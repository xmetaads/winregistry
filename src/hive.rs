//! Offline Hive Direct Engine - `RegLoadAppKey` without administrator rights.
//!
//! # Why this is different from `reg load`
//!
//! `RegLoadKey` (what `reg load` and regedit's "Load Hive" call) requires
//! `SeRestorePrivilege`, which a standard user's token does not hold and cannot
//! obtain without elevation. `RegLoadAppKeyW` deliberately does not: it mounts
//! the hive into a private, unnamed slot that only the calling process can see.
//! That is precisely why it needs no privilege - there is no global namespace
//! entry to protect.
//!
//! # The constraint that shapes the CLI
//!
//! The returned handle is **process-scoped**. Closing it - including at process
//! exit - unloads the hive. So this sequence *cannot* work:
//!
//! ```text
//! regx hive mount NTUSER.DAT --as my_hive   # process 1 exits -> hive unloaded
//! regx hive set my_hive\Software\App ...    # process 2: nothing is mounted
//! regx hive unmount my_hive                 # process 3: nothing to unmount
//! ```
//!
//! There is no supported way around it: the handle cannot be published to the
//! registry namespace (that is what the privilege check guards) and inheriting it
//! into another process would require the mounting process to stay alive, i.e. a
//! daemon - which defeats "portable, no install".
//!
//! So mount/operate/unmount happens **within one process**:
//!   * `regx hive <FILE> <op>` - mount, run one operation, unmount. Self-contained.
//!   * `regx hive <FILE> exec -c "..." -c "..."` - many operations, one mount.
//!     This is the literal replacement for the mount/set/unmount script above.
//!
//! # What a standard user can realistically open
//!
//! Write access to the *file* is still required, and a hive already mounted by
//! the OS is held exclusively. In practice that means: your own logged-off
//! secondary profile, a copy of a hive, an application's private hive, or a hive
//! from a backup / mounted VHD. A currently logged-on user's `NTUSER.DAT` fails
//! with `ERROR_SHARING_VIOLATION`, by design.

use crate::engine::Roots;
use crate::winreg::{self, RegKey, KEY_READ, KEY_WRITE};
use std::path::{Path, PathBuf};

pub struct Session {
    pub roots: Roots,
    pub path: PathBuf,
    pub writable: bool,
    pub created: bool,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Session({}, writable={})",
            self.path.display(),
            self.writable
        )
    }
}

#[derive(Debug)]
pub enum OpenError {
    Missing(PathBuf),
    NotAHive(PathBuf),
    Io(PathBuf, String),
    Api(winreg::Error, &'static str),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Missing(p) => write!(
                f,
                "{} does not exist (pass --create to start a new hive file)",
                p.display()
            ),
            OpenError::NotAHive(p) => write!(
                f,
                "{} is not a registry hive: missing the 'regf' signature. \
                 A .reg text file is not a hive - use `regx import` for those.",
                p.display()
            ),
            OpenError::Io(p, e) => write!(f, "cannot access {}: {e}", p.display()),
            OpenError::Api(e, hint) => {
                if hint.is_empty() {
                    write!(f, "{e}")
                } else {
                    write!(f, "{e}\n  hint: {hint}")
                }
            }
        }
    }
}

impl std::error::Error for OpenError {}

/// Mount `path` as an app hive for the lifetime of the returned `Session`.
pub fn open(
    path: &Path,
    writable: bool,
    create: bool,
    exclusive: bool,
) -> Result<Session, OpenError> {
    let exists = path.exists();

    if !exists && !create {
        return Err(OpenError::Missing(path.to_path_buf()));
    }
    if exists {
        match winreg::looks_like_hive(path) {
            Ok(true) => {}
            Ok(false) => return Err(OpenError::NotAHive(path.to_path_buf())),
            Err(e) => return Err(OpenError::Io(path.to_path_buf(), e.to_string())),
        }
    }

    let sam = if writable {
        KEY_READ | KEY_WRITE
    } else {
        KEY_READ
    };

    let key = winreg::load_app_key(path, sam, exclusive).map_err(|e| {
        let hint: &'static str = match e.code {
            winreg::ERROR_SHARING_VIOLATION => {
                "the hive is already loaded - a logged-on user's NTUSER.DAT is held by the OS. \
                 Work on a logged-off profile, or copy the file first."
            }
            winreg::ERROR_ACCESS_DENIED => {
                "no NTFS access to the hive file. Another user's profile directory is \
                 normally readable only by that user and administrators."
            }
            winreg::ERROR_BADDB => "the hive file is corrupt or was not cleanly unloaded",
            _ => "",
        };
        OpenError::Api(e, hint)
    })?;

    Ok(Session {
        roots: Roots::Mounted(key),
        path: path.to_path_buf(),
        writable,
        created: !exists,
    })
}

impl Session {
    pub fn key(&self) -> &RegKey {
        match &self.roots {
            Roots::Mounted(k) => k,
            Roots::Live(_) => unreachable!("hive session is always mounted"),
        }
    }

    /// Flush pending writes. Dropping the key unloads the hive, which also
    /// flushes, but doing it explicitly means a later failure is still reported.
    pub fn flush(&self) -> winreg::Result<()> {
        self.key().flush()
    }
}

/// Report what we can learn about a hive file without committing to a write.
pub struct Info {
    pub path: PathBuf,
    pub size: u64,
    pub signature_ok: bool,
    pub readable: bool,
    pub writable: bool,
    pub detail: String,
    pub root_subkeys: Vec<String>,
}

pub fn info(path: &Path) -> Info {
    let mut i = Info {
        path: path.to_path_buf(),
        size: 0,
        signature_ok: false,
        readable: false,
        writable: false,
        detail: String::new(),
        root_subkeys: Vec::new(),
    };

    match std::fs::metadata(path) {
        Ok(m) => i.size = m.len(),
        Err(e) => {
            i.detail = e.to_string();
            return i;
        }
    }
    i.signature_ok = winreg::looks_like_hive(path).unwrap_or(false);
    if !i.signature_ok {
        i.detail = "missing 'regf' signature".into();
        return i;
    }

    // Probe read-only first: a successful read mount proves the file is not
    // already loaded elsewhere, without risking a write.
    match open(path, false, false, false) {
        Ok(s) => {
            i.readable = true;
            i.root_subkeys = s.key().subkeys().unwrap_or_default();
        }
        Err(e) => {
            i.detail = e.to_string();
            return i;
        }
    }
    match open(path, true, false, false) {
        Ok(_) => i.writable = true,
        Err(e) => i.detail = format!("read-only: {e}"),
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{self, apply};
    use crate::model::*;
    use crate::winreg::View;

    fn scratch(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("regx-hive-test-{name}.dat"));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn rejects_a_text_file_before_calling_the_api() {
        let p = scratch("text");
        std::fs::write(&p, b"Windows Registry Editor Version 5.00\r\n").unwrap();
        let e = open(&p, false, false, false).unwrap_err();
        assert!(matches!(e, OpenError::NotAHive(_)), "{e}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn missing_file_without_create_is_reported_clearly() {
        let p = scratch("absent");
        let e = open(&p, true, false, false).unwrap_err();
        assert!(matches!(e, OpenError::Missing(_)), "{e}");
    }

    /// The headline claim, executed end to end: create a hive, write into it,
    /// unmount, remount in a fresh mount and read the data back - all without
    /// any elevation. If `RegLoadAppKey` needed admin this test would fail.
    #[test]
    fn creates_writes_and_reopens_a_hive_without_admin() {
        let p = scratch("roundtrip");

        let file = RegFile {
            format: RegFormat::V5,
            encoding: crate::encoding::SourceEncoding::Utf16Le,
            keys: vec![KeyBlock {
                // The hive component is ignored for a mounted session.
                path: RegPath::parse("HKEY_CURRENT_USER\\Software\\MyApp").unwrap(),
                delete: false,
                values: vec![
                    ValueEntry {
                        name: ValueName::Named("License".into()),
                        data: RegData::Sz("OK".into()),
                        line: 0,
                    },
                    ValueEntry {
                        name: ValueName::Named("Seats".into()),
                        data: RegData::Dword(5),
                        line: 0,
                    },
                ],
                line: 0,
            }],
        };

        {
            let s = open(&p, true, true, false).expect("create hive");
            assert!(s.created);
            let r = apply(&s.roots, &file, View::Native, false);
            assert!(r.failures.is_empty(), "{:?}", r.failures);
            assert_eq!(r.values_set, 2);
            s.flush().unwrap();
        } // hive unloaded here

        assert!(p.exists(), "hive file should persist after unmount");
        assert!(winreg::looks_like_hive(&p).unwrap());

        {
            let s = open(&p, false, false, false).expect("reopen hive");
            let path = RegPath::parse("HKEY_CURRENT_USER\\Software\\MyApp").unwrap();
            let (blocks, rep) = engine::export(&s.roots, &path, View::Native, true).unwrap();
            assert!(rep.skipped.is_empty());
            assert_eq!(blocks.len(), 1);
            assert_eq!(blocks[0].values.len(), 2);
            let lic = blocks[0]
                .values
                .iter()
                .find(|v| matches!(&v.name, ValueName::Named(n) if n == "License"))
                .unwrap();
            assert_eq!(lic.data, RegData::Sz("OK".into()));
        }

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn info_reports_a_freshly_created_hive_as_readable_and_writable() {
        let p = scratch("info");
        {
            let _s = open(&p, true, true, false).expect("create hive");
        }
        let i = info(&p);
        assert!(i.signature_ok, "{}", i.detail);
        assert!(i.readable, "{}", i.detail);
        assert!(i.writable, "{}", i.detail);
        assert!(i.size > 0);
        let _ = std::fs::remove_file(&p);
    }
}
