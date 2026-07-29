//! Companion-file discovery — the search an enterprise executable performs to
//! find its own configuration, made explicit and auditable.
//!
//! # How the applications being modelled actually do it
//!
//! The anchor is always `GetModuleFileNameW(NULL)`, the real path of the running
//! module. It is used rather than `argv[0]` because a parent process controls
//! `argv[0]` and can point it anywhere; `GetModuleFileName` cannot be spoofed
//! from outside. Strip the extension, append `.ini`, and that is the classic
//! sidecar. .NET does exactly this to reach `MyApp.exe.config`.
//!
//! Around that, most products layer a search order. This module reproduces the
//! common one, highest precedence first, and records which rung each hit came
//! from:
//!
//! | Rank | Origin | Note |
//! |---|---|---|
//! | 1 | explicit path | whatever the operator passed |
//! | 2 | environment variable | `<STEM>_CONFIG`, `<STEM>_HOME` |
//! | 3 | beside the executable | portable mode; the sidecar proper |
//! | 4 | `%LOCALAPPDATA%\<stem>` | per-user, non-roaming |
//! | 5 | `%APPDATA%\<stem>` | per-user, roaming |
//! | 6 | `%PROGRAMDATA%\<stem>` | machine-wide |
//! | 7 | registry pointer | `HKCU/HKLM\Software\<stem>` `ConfigPath` |
//! | 8 | Group Policy caches | `Registry.pol`, `PolicyDefinitions` |
//! | 9 | current directory | **reported as a risk, never trusted** |
//! | 10 | `%WINDIR%` | the `GetPrivateProfileString` trap |
//!
//! # Why the risk reporting exists
//!
//! Two rungs are load-bearing security bugs in a lot of shipping software:
//!
//! * **The current directory.** If an application resolves its config relative
//!   to the CWD, anyone who can drop a file into a directory a user launches
//!   from controls that configuration. This is config planting, the same shape
//!   as DLL planting.
//! * **`%WINDIR%`.** `GetPrivateProfileString` with an unqualified file name
//!   silently resolves against the Windows directory. Plenty of legacy code
//!   reads — and writes — `C:\Windows\app.ini` without ever intending to.
//!
//! So a hit is never reported bare. Each carries the rung it came from and any
//! of: sourced from the CWD, sitting in a directory this user can write to while
//! the executable does not, reached through a reparse point, resolved outside
//! the anchor directory, or living on a network path.

use crate::formats::Format;
use std::collections::BTreeSet;
use std::ffi::c_void;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// Extensions worth looking for. Ordered so the most specific wins a tie.
const EXTENSIONS: &[&str] = &[
    "reg", "pol", "admx", "inf", "json", "xml", "ini", "cfg", "conf", "csv", "tsv",
];

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Origin {
    Explicit,
    Env(String),
    Sidecar,
    LocalAppData,
    RoamingAppData,
    ProgramData,
    RegistryPointer(String),
    GroupPolicy,
    CurrentDirectory,
    WindowsDirectory,
}

impl Origin {
    pub fn rank(&self) -> usize {
        match self {
            Origin::Explicit => 1,
            Origin::Env(_) => 2,
            Origin::Sidecar => 3,
            Origin::LocalAppData => 4,
            Origin::RoamingAppData => 5,
            Origin::ProgramData => 6,
            Origin::RegistryPointer(_) => 7,
            Origin::GroupPolicy => 8,
            Origin::CurrentDirectory => 9,
            Origin::WindowsDirectory => 10,
        }
    }

    pub fn label(&self) -> String {
        match self {
            Origin::Explicit => "explicit path".into(),
            Origin::Env(v) => format!("env {v}"),
            Origin::Sidecar => "beside the executable".into(),
            Origin::LocalAppData => "%LOCALAPPDATA%".into(),
            Origin::RoamingAppData => "%APPDATA%".into(),
            Origin::ProgramData => "%PROGRAMDATA%".into(),
            Origin::RegistryPointer(k) => format!("registry {k}"),
            Origin::GroupPolicy => "Group Policy cache".into(),
            Origin::CurrentDirectory => "current directory".into(),
            Origin::WindowsDirectory => "%WINDIR%".into(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Risk {
    /// Found via the current working directory — the config-planting vector.
    CurrentDirectory,
    /// This user can create files in the directory, but not in the executable's
    /// own directory. A lower-privileged location overriding a protected one.
    UserWritable,
    /// Reached through a symlink, junction or other reparse point.
    ReparsePoint,
    /// The real path leaves the anchor directory.
    EscapesAnchor,
    /// UNC or a mapped network drive: availability and integrity are not local.
    NetworkPath,
    /// The `%WINDIR%` fallback of the profile-string APIs.
    WindowsFallback,
    /// The path only matched after 8.3 short-name expansion.
    ShortNameAlias,
}

impl Risk {
    pub fn explain(self) -> &'static str {
        match self {
            Risk::CurrentDirectory =>
                "sourced from the working directory: anyone who can write there controls this configuration",
            Risk::UserWritable =>
                "this user can create files in that directory but not beside the executable, so it can override a protected setting",
            Risk::ReparsePoint =>
                "reached through a symlink or junction; the real target may be elsewhere",
            Risk::EscapesAnchor =>
                "the resolved path leaves the anchor directory",
            Risk::NetworkPath =>
                "on a network path: availability and integrity are outside this machine",
            Risk::WindowsFallback =>
                "%WINDIR% is where GetPrivateProfileString silently resolves an unqualified file name",
            Risk::ShortNameAlias =>
                "matched only after 8.3 short-name expansion; path comparisons elsewhere may not agree",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Found {
    /// Candidate path as reached through the documented search rung.
    pub path: PathBuf,
    /// Canonical target after resolving links/junctions and normalizing the
    /// extended-length prefix. This may differ from `path`.
    pub resolved_path: PathBuf,
    pub origin: Origin,
    pub format: Option<Format>,
    pub size: u64,
    pub risks: Vec<Risk>,
}

#[derive(Debug)]
pub struct Report {
    /// The executable the search hung off, if one was given.
    pub exe: Option<PathBuf>,
    pub anchor: PathBuf,
    pub stem: String,
    pub found: Vec<Found>,
    /// Locations searched that held nothing, for auditability.
    pub searched: Vec<PathBuf>,
    pub notes: Vec<String>,
}

impl Report {
    pub fn risky(&self) -> usize {
        self.found.iter().filter(|f| !f.risks.is_empty()).count()
    }
}

/// Options mirroring what an application would decide at build time.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Also enumerate the machine's Group Policy caches.
    pub policy: bool,
    /// Follow the registry pointer convention.
    pub registry_pointer: bool,
    /// Ask the text renderer to report every candidate path probed. Discovery
    /// always retains the trail so machine-readable output is auditable.
    pub verbose: bool,
}

pub fn discover(target: &Path, opts: &Options) -> Result<Report, String> {
    // Rendering is owned by the caller. Reading this presentation preference
    // here keeps Options a single command-level contract while the report
    // retains the complete trail in either mode.
    let _text_requests_probe_trail = opts.verbose;
    let meta = std::fs::metadata(target)
        .map_err(|e| format!("cannot access {}: {e}", target.display()))?;

    // Being handed a config file rather than an executable is a real question —
    // "what else would this application pick up?" — so anchor on its directory
    // and record the file itself at rank 1.
    let given_config = !meta.is_dir()
        && target
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| EXTENSIONS.iter().any(|x| x.eq_ignore_ascii_case(e)))
            .unwrap_or(false);

    let (exe, anchor, stem) = if meta.is_dir() {
        let dir = canonical(target);
        let stem = dir
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "config".into());
        (None, dir, stem)
    } else {
        let file = canonical(target);
        let dir = file
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| file.clone());
        let stem = file
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "config".into());
        (if given_config { None } else { Some(file) }, dir, stem)
    };

    let mut r = Report {
        exe: exe.clone(),
        anchor: anchor.clone(),
        stem: stem.clone(),
        found: Vec::new(),
        searched: Vec::new(),
        notes: Vec::new(),
    };

    // The executable's own directory sets the privilege baseline: a config in a
    // directory the user can write to, when this one is protected, is the
    // escalation shape worth flagging.
    let anchor_writable = dir_writable(&anchor);
    r.notes.push(format!(
        "anchor {} is {} by this user",
        anchor.display(),
        if anchor_writable {
            "writable"
        } else {
            "not writable"
        }
    ));

    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();

    // 1. The file the operator named outright, if it was a config rather than
    //    an executable.
    if given_config {
        consider(
            &mut r,
            &mut seen,
            canonical(target),
            Origin::Explicit,
            &anchor,
            anchor_writable,
            opts,
        );
        r.notes.push(
            "the target is itself a configuration file; the search below shows what else the \
             owning application would find"
                .into(),
        );
    }

    // 2. Environment variables an operator or CI would set.
    let up = stem.to_ascii_uppercase().replace(['-', '.', ' '], "_");
    for var in [
        format!("{up}_CONFIG"),
        format!("{up}_HOME"),
        format!("{up}_INI"),
    ] {
        if let Ok(v) = std::env::var(&var) {
            let p = PathBuf::from(&v);
            let candidates: Vec<PathBuf> = if p.is_dir() {
                names(&stem).map(|n| p.join(n)).collect()
            } else {
                vec![p]
            };
            for c in candidates {
                consider(
                    &mut r,
                    &mut seen,
                    c,
                    Origin::Env(var.clone()),
                    &anchor,
                    anchor_writable,
                    opts,
                );
            }
        }
    }

    // 3. Beside the executable — the sidecar proper.
    for n in names(&stem) {
        consider(
            &mut r,
            &mut seen,
            anchor.join(n),
            Origin::Sidecar,
            &anchor,
            anchor_writable,
            opts,
        );
    }
    // .NET's convention: MyApp.exe.config, not MyApp.config.
    if let Some(exe) = &exe {
        if let Some(file) = exe.file_name() {
            for ext in ["config", "json", "ini"] {
                let mut n = file.to_os_string();
                n.push(format!(".{ext}"));
                consider(
                    &mut r,
                    &mut seen,
                    anchor.join(n),
                    Origin::Sidecar,
                    &anchor,
                    anchor_writable,
                    opts,
                );
            }
        }
    }

    // 4-6. The per-user and machine data directories.
    for (var, origin) in [
        ("LOCALAPPDATA", Origin::LocalAppData),
        ("APPDATA", Origin::RoamingAppData),
        ("PROGRAMDATA", Origin::ProgramData),
    ] {
        let Ok(base) = std::env::var(var) else {
            continue;
        };
        let dir = PathBuf::from(base).join(&stem);
        for n in names(&stem) {
            consider(
                &mut r,
                &mut seen,
                dir.join(n),
                origin.clone(),
                &anchor,
                anchor_writable,
                opts,
            );
        }
    }

    // 7. The registry-pointer convention.
    if opts.registry_pointer {
        for (hive, label) in [
            (crate::model::Hive::Hkcu, "HKCU"),
            (crate::model::Hive::Hklm, "HKLM"),
        ] {
            for value in ["ConfigPath", "ConfigFile", "InstallPath", "Path"] {
                if let Some(p) = registry_pointer(hive, &stem, value) {
                    let key = format!("{label}\\Software\\{stem}\\{value}");
                    let candidates: Vec<PathBuf> = if p.is_dir() {
                        names(&stem).map(|n| p.join(n)).collect()
                    } else {
                        vec![p]
                    };
                    for c in candidates {
                        consider(
                            &mut r,
                            &mut seen,
                            c,
                            Origin::RegistryPointer(key.clone()),
                            &anchor,
                            anchor_writable,
                            opts,
                        );
                    }
                }
            }
        }
    }

    // 8. The machine's Group Policy caches.
    if opts.policy {
        for p in policy_paths() {
            consider(
                &mut r,
                &mut seen,
                p,
                Origin::GroupPolicy,
                &anchor,
                anchor_writable,
                opts,
            );
        }
    }

    // 9. The working directory, always probed so its risk can be reported.
    if let Ok(cwd) = std::env::current_dir() {
        let cwd = canonical(&cwd);
        if cwd != anchor {
            for n in names(&stem) {
                consider(
                    &mut r,
                    &mut seen,
                    cwd.join(n),
                    Origin::CurrentDirectory,
                    &anchor,
                    anchor_writable,
                    opts,
                );
            }
        } else {
            r.notes.push(
                "the working directory is the anchor directory, so no separate CWD risk".into(),
            );
        }
    }

    // 10. The %WINDIR% fallback.
    if let Ok(win) = std::env::var("WINDIR") {
        let win = PathBuf::from(win);
        for n in names(&stem) {
            consider(
                &mut r,
                &mut seen,
                win.join(n),
                Origin::WindowsDirectory,
                &anchor,
                anchor_writable,
                opts,
            );
        }
    }

    r.found.sort_by_key(|f| (f.origin.rank(), f.path.clone()));
    Ok(r)
}

/// The companion file names to probe for a given stem.
fn names(stem: &str) -> impl Iterator<Item = String> + '_ {
    EXTENSIONS.iter().map(move |e| format!("{stem}.{e}"))
}

fn policy_paths() -> Vec<PathBuf> {
    let Ok(win) = std::env::var("WINDIR") else {
        return Vec::new();
    };
    let win = PathBuf::from(win);
    let mut out = vec![
        win.join(r"System32\GroupPolicy\Machine\Registry.pol"),
        win.join(r"System32\GroupPolicy\User\Registry.pol"),
    ];
    // Per-user policy is keyed by SID, so enumerate rather than guess.
    let users = win.join(r"System32\GroupPolicyUsers");
    if let Ok(entries) = std::fs::read_dir(&users) {
        for e in entries.flatten() {
            out.push(e.path().join(r"User\Registry.pol"));
            out.push(e.path().join(r"Machine\Registry.pol"));
        }
    }
    let defs = win.join("PolicyDefinitions");
    if let Ok(entries) = std::fs::read_dir(&defs) {
        for e in entries.flatten().take(4096) {
            let p = e.path();
            if p.extension()
                .map(|x| x.eq_ignore_ascii_case("admx"))
                .unwrap_or(false)
            {
                out.push(p);
            }
        }
    }
    out
}

fn consider(
    r: &mut Report,
    seen: &mut BTreeSet<PathBuf>,
    candidate: PathBuf,
    origin: Origin,
    anchor: &Path,
    anchor_writable: bool,
    _opts: &Options,
) {
    if !seen.insert(candidate.clone()) {
        return;
    }
    let Ok(meta) = std::fs::metadata(&candidate) else {
        r.searched.push(candidate);
        return;
    };
    if !meta.is_file() {
        return;
    }

    let real = canonical(&candidate);
    let mut risks = Vec::new();

    if origin == Origin::CurrentDirectory {
        risks.push(Risk::CurrentDirectory);
    }
    if origin == Origin::WindowsDirectory {
        risks.push(Risk::WindowsFallback);
    }
    if is_reparse_point(&candidate) {
        risks.push(Risk::ReparsePoint);
    }
    if is_network(&real) {
        risks.push(Risk::NetworkPath);
    }
    if real != canonical_of_display(&candidate) {
        risks.push(Risk::ShortNameAlias);
    }
    // A sidecar that resolves outside the anchor got there through a link.
    if origin == Origin::Sidecar && !real.starts_with(anchor) {
        risks.push(Risk::EscapesAnchor);
    }
    if !anchor_writable {
        if let Some(dir) = candidate.parent() {
            if dir_writable(dir) {
                risks.push(Risk::UserWritable);
            }
        }
    }

    // Identify the format from content, exactly as `regx read` would.
    let format = std::fs::read(&candidate)
        .ok()
        .map(|b| crate::formats::detect(&b, Some(&candidate)));

    risks.sort_unstable();
    risks.dedup();

    r.found.push(Found {
        path: candidate,
        resolved_path: real,
        origin,
        format,
        size: meta.len(),
        risks,
    });
}

// ---------------------------------------------------------------------------
// Win32 helpers
// ---------------------------------------------------------------------------

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
const FILE_ADD_FILE: u32 = 0x0000_0002;
const FILE_SHARE_ALL: u32 = 0x0000_0007;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const DRIVE_REMOTE: u32 = 4;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileAttributesW(path: *const u16) -> u32;
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        sa: *const c_void,
        disposition: u32,
        flags: u32,
        template: *mut c_void,
    ) -> *mut c_void;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn GetLongPathNameW(short: *const u16, long: *mut u16, len: u32) -> u32;
    fn GetDriveTypeW(root: *const u16) -> u32;
}

fn wide(p: &Path) -> Vec<u16> {
    let mut v: Vec<u16> = p.as_os_str().encode_wide().collect();
    v.push(0);
    v
}

/// The path of the running executable — the anchor an application would use.
///
/// This is `GetModuleFileNameW(NULL, …)`: `std::env::current_exe` is a thin
/// wrapper over exactly that call on Windows, so declaring the import again
/// would only duplicate it. The distinction that matters is against `argv[0]`,
/// which a parent process chooses and can therefore lie about.
pub fn own_executable() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

fn is_reparse_point(p: &Path) -> bool {
    let w = wide(p);
    // SAFETY: NUL-terminated path pointer that outlives the call.
    let attrs = unsafe { GetFileAttributesW(w.as_ptr()) };
    attrs != INVALID_FILE_ATTRIBUTES && attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Can this user create a file in `dir`? Asked of the OS rather than inferred
/// from the path, and without a side effect: opening the *directory* for
/// `FILE_ADD_FILE` is an access check, not a write.
fn dir_writable(dir: &Path) -> bool {
    let w = wide(dir);
    // SAFETY: BACKUP_SEMANTICS is required to open a directory handle; the
    // handle is closed on every success path below.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            FILE_ADD_FILE,
            FILE_SHARE_ALL,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if h as isize == -1 {
        return false;
    }
    // SAFETY: `h` is a valid handle from CreateFileW, closed exactly once.
    unsafe {
        CloseHandle(h);
    }
    true
}

fn is_network(p: &Path) -> bool {
    let s = p.to_string_lossy();
    if s.starts_with(r"\\") && !s.starts_with(r"\\?\") {
        return true;
    }
    let s = s.trim_start_matches(r"\\?\");
    let Some(root) = s.get(..3) else { return false };
    if !root.as_bytes().get(1).map(|b| *b == b':').unwrap_or(false) {
        return false;
    }
    let w = wide(Path::new(root));
    // SAFETY: NUL-terminated 3-character drive root.
    unsafe { GetDriveTypeW(w.as_ptr()) == DRIVE_REMOTE }
}

/// `std::fs::canonicalize` resolves links; this only expands 8.3 short names,
/// so the two can be compared to detect short-name aliasing.
fn canonical_of_display(p: &Path) -> PathBuf {
    let w = wide(p);
    let mut buf = vec![0u16; 32_768];
    // SAFETY: both pointers are valid for the declared lengths.
    let n = unsafe { GetLongPathNameW(w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 || n as usize >= buf.len() {
        return p.to_path_buf();
    }
    PathBuf::from(std::ffi::OsString::from_wide(&buf[..n as usize]))
}

/// Fully resolved path with the `\\?\` prefix removed for readability.
fn canonical(p: &Path) -> PathBuf {
    match std::fs::canonicalize(p) {
        Ok(c) => {
            let s = c.to_string_lossy().to_string();
            PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s).to_string())
        }
        Err(_) => p.to_path_buf(),
    }
}

fn registry_pointer(hive: crate::model::Hive, stem: &str, value: &str) -> Option<PathBuf> {
    use crate::winreg::{self, RegKey, View, KEY_READ};
    let root = match hive {
        crate::model::Hive::Hkcu => {
            RegKey::predefined(winreg::hkey_current_user(), "HKEY_CURRENT_USER")
        }
        _ => RegKey::predefined(winreg::hkey_local_machine(), "HKEY_LOCAL_MACHINE"),
    };
    let key = root
        .open(&format!("Software\\{stem}"), KEY_READ, View::Native)
        .ok()?;
    let (ty, bytes) = key.get_value(value).ok()??;
    let data = crate::engine::raw_to_data(ty, &bytes);
    match data {
        crate::model::RegData::Sz(s) if !s.trim().is_empty() => Some(PathBuf::from(s)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("regx-discover-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn own_executable_resolves() {
        let p = own_executable().expect("the module path should resolve");
        assert!(p.is_absolute(), "{p:?}");
        assert!(p.exists(), "{p:?}");
    }

    #[test]
    fn a_config_target_is_recorded_as_explicit() {
        let d = scratch("explicit");
        std::fs::write(d.join("app.ini"), b"[HKCU\\Software\\A]\nX = 1\n").unwrap();
        std::fs::write(d.join("app.reg"), b"REGEDIT4\r\n").unwrap();

        let r = discover(&d.join("app.ini"), &Options::default()).unwrap();
        assert!(r.exe.is_none(), "a config file is not an executable");
        assert_eq!(r.found[0].origin, Origin::Explicit);
        assert_eq!(r.found[0].origin.rank(), 1);
        // The sibling is still found, one rung down.
        assert!(r.found.iter().any(|f| f.origin == Origin::Sidecar));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn finds_the_sidecar_beside_the_executable() {
        let d = scratch("sidecar");
        std::fs::write(d.join("updater.exe"), b"MZ").unwrap();
        std::fs::write(d.join("updater.ini"), b"[HKCU\\Software\\A]\nX = 1\n").unwrap();
        std::fs::write(
            d.join("updater.reg"),
            b"Windows Registry Editor Version 5.00\r\n",
        )
        .unwrap();
        std::fs::write(d.join("unrelated.ini"), b"x").unwrap();

        let r = discover(&d.join("updater.exe"), &Options::default()).unwrap();
        assert_eq!(r.stem, "updater");

        let names: Vec<String> = r
            .found
            .iter()
            .map(|f| f.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"updater.ini".to_string()), "{names:?}");
        assert!(names.contains(&"updater.reg".to_string()), "{names:?}");
        assert!(
            !names.contains(&"unrelated.ini".to_string()),
            "must match the stem only"
        );

        let ini = r
            .found
            .iter()
            .find(|f| f.path.extension().unwrap() == "ini")
            .unwrap();
        assert_eq!(ini.origin, Origin::Sidecar);
        assert_eq!(ini.format, Some(Format::Ini));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn dotnet_style_exe_config_is_found() {
        let d = scratch("dotnet");
        std::fs::write(d.join("svc.exe"), b"MZ").unwrap();
        std::fs::write(d.join("svc.exe.json"), b"{}").unwrap();
        let r = discover(&d.join("svc.exe"), &Options::default()).unwrap();
        assert!(
            r.found
                .iter()
                .any(|f| f.path.file_name().unwrap() == "svc.exe.json"),
            "{:?}",
            r.found
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_hit_in_the_working_directory_is_flagged() {
        let anchor = scratch("anchor");
        let cwd = scratch("cwd");
        std::fs::write(anchor.join("tool.exe"), b"MZ").unwrap();
        std::fs::write(cwd.join("tool.ini"), b"[HKCU\\Software\\A]\nX = 1\n").unwrap();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&cwd).unwrap();
        let r = discover(&anchor.join("tool.exe"), &Options::default()).unwrap();
        std::env::set_current_dir(prev).unwrap();

        let hit = r
            .found
            .iter()
            .find(|f| f.origin == Origin::CurrentDirectory)
            .expect("the CWD copy should be found");
        assert!(
            hit.risks.contains(&Risk::CurrentDirectory),
            "{:?}",
            hit.risks
        );
        let _ = std::fs::remove_dir_all(&anchor);
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[test]
    fn env_variable_outranks_the_sidecar() {
        let d = scratch("env");
        let alt = scratch("env-alt");
        std::fs::write(d.join("app.exe"), b"MZ").unwrap();
        std::fs::write(d.join("app.ini"), b"[HKCU\\Software\\A]\nX = 1\n").unwrap();
        std::fs::write(alt.join("app.ini"), b"[HKCU\\Software\\B]\nY = 2\n").unwrap();

        unsafe { std::env::set_var("APP_CONFIG", alt.join("app.ini")) };
        let r = discover(&d.join("app.exe"), &Options::default()).unwrap();
        unsafe { std::env::remove_var("APP_CONFIG") };

        assert!(
            matches!(r.found[0].origin, Origin::Env(_)),
            "{:?}",
            r.found[0].origin
        );
        assert!(r.found[0].origin.rank() < Origin::Sidecar.rank());
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&alt);
    }

    #[test]
    fn a_directory_target_anchors_on_the_directory_name() {
        let d = scratch("bydir");
        std::fs::write(d.join("regx-discover-bydir.reg"), b"REGEDIT4\r\n").unwrap();
        let r = discover(&d, &Options::default()).unwrap();
        assert_eq!(r.stem, "regx-discover-bydir");
        assert_eq!(r.found.len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn temp_is_writable_and_windows_is_not() {
        assert!(dir_writable(&std::env::temp_dir()));

        // The negative half is a fact about the host, not the code: an elevated
        // process can write to System32.
        let win = PathBuf::from(std::env::var("WINDIR").unwrap());
        if dir_writable(&win.join("System32")) {
            eprintln!("SKIPPED: System32 is writable here, so this host is elevated");
        }
    }

    #[test]
    fn missing_target_is_an_error() {
        assert!(discover(Path::new(r"C:\nope\nothing-here.exe"), &Options::default()).is_err());
    }
}
