//! `--self-check`: what this environment does to a portable, non-admin binary.
//!
//! UAC is not the real obstacle in a locked-down enterprise - application
//! control is. An unsigned `.exe` under `%TEMP%`, `Downloads` or `%APPDATA%` is
//! exactly the shape AppLocker's and SRP's default rule sets are written to
//! block, and WDAC blocks it regardless of location. All three are configured
//! through registry keys a standard user *can read*, so we can tell the user
//! why the tool will or will not run before they hit a silent failure.
//!
//! Mitigation, in the order that actually works:
//!   1. Sign the executable (EV certificate, or the organisation's internal CA).
//!      A publisher rule survives being copied anywhere; a path rule does not.
//!   2. Failing that, run from a path the policy already allows - typically
//!      `%ProgramFiles%` or an IT-managed share - not from Downloads.
//!   3. Strip the Mark-of-the-Web from the downloaded file, which is what
//!      triggers SmartScreen's "unrecognised app" interstitial.

use crate::winreg::{self, RegKey, View, KEY_READ};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    Note,
    Warn,
}

#[derive(Debug)]
pub struct Finding {
    pub area: &'static str,
    pub verdict: Verdict,
    pub detail: String,
}

pub fn run() -> Vec<Finding> {
    let mut f = Vec::new();
    f.push(process_identity());
    f.push(elevation());
    f.extend(wow64());
    f.push(image_location());
    f.push(mark_of_the_web());
    f.push(applocker());
    f.push(srp());
    f.push(wdac());
    f.push(hkcu_writable());
    f
}

fn hklm() -> RegKey {
    RegKey::predefined(winreg::hkey_local_machine(), "HKEY_LOCAL_MACHINE")
}

fn read_dword(root: &RegKey, path: &str, name: &str) -> Option<u32> {
    let k = root.open(path, KEY_READ, View::Bits64).ok()?;
    let (ty, bytes) = k.get_value(name).ok()??;
    if ty != 4 || bytes.len() != 4 {
        return None;
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(&bytes);
    Some(u32::from_le_bytes(a))
}

fn process_identity() -> Finding {
    let arch = if cfg!(target_pointer_width = "64") {
        "64-bit"
    } else {
        "32-bit"
    };
    Finding {
        area: "process",
        verdict: if cfg!(target_pointer_width = "64") {
            Verdict::Ok
        } else {
            Verdict::Warn
        },
        detail: format!(
            "{arch} process. {}",
            if cfg!(target_pointer_width = "64") {
                "HKLM\\SOFTWARE resolves to the 64-bit view."
            } else {
                "A 32-bit build is silently redirected to SOFTWARE\\WOW6432Node; \
                 ship an x64/arm64 binary or always pass --view."
            }
        ),
    }
}

fn elevation() -> Finding {
    match token_elevation() {
        Some(true) => Finding {
            area: "elevation",
            verdict: Verdict::Warn,
            detail: "running ELEVATED. regx is designed for the standard-user path; \
                     writes will succeed here that fail for real users, so test unelevated."
                .into(),
        },
        Some(false) => Finding {
            area: "elevation",
            verdict: Verdict::Ok,
            detail: format!(
                "not elevated ({}), as intended - the manifest is asInvoker and never prompts.",
                integrity_label()
            ),
        },
        None => Finding {
            area: "elevation",
            verdict: Verdict::Note,
            detail: "could not query the process token".into(),
        },
    }
}

fn wow64() -> Vec<Finding> {
    let root = hklm();
    let mut out = Vec::new();
    let probe = |view: View| root.open("SOFTWARE\\Microsoft", KEY_READ, view).is_ok();
    out.push(Finding {
        area: "wow64",
        verdict: Verdict::Ok,
        detail: format!(
            "registry views reachable: 64-bit={}, 32-bit={}",
            probe(View::Bits64),
            probe(View::Bits32)
        ),
    });
    out
}

fn image_location() -> Finding {
    let exe = crate::discover::own_executable().unwrap_or_else(|| PathBuf::from("<unknown>"));
    let lower = exe.to_string_lossy().to_lowercase();
    let risky = [
        "\\temp\\",
        "\\downloads\\",
        "\\appdata\\",
        "\\users\\public\\",
    ];
    let hit = risky.iter().find(|p| lower.contains(**p));
    match hit {
        Some(p) => Finding {
            area: "image path",
            verdict: Verdict::Warn,
            detail: format!(
                "{} sits under {p} - the location AppLocker's and SRP's default rules \
                 deny for standard users. Sign the binary, or run it from an allowed path.",
                exe.display()
            ),
        },
        None => Finding {
            area: "image path",
            verdict: Verdict::Ok,
            detail: format!("{} is not in a commonly denied location", exe.display()),
        },
    }
}

/// Mark-of-the-Web lives in the `Zone.Identifier` alternate data stream; NTFS
/// exposes it as a normal file path, so no special API is needed.
fn mark_of_the_web() -> Finding {
    let Some(exe) = crate::discover::own_executable() else {
        return Finding {
            area: "mark-of-the-web",
            verdict: Verdict::Note,
            detail: "could not resolve the executable path".into(),
        };
    };
    let ads = format!("{}:Zone.Identifier", exe.display());
    match std::fs::read_to_string(&ads) {
        Ok(s) => {
            let zone = s
                .lines()
                .find_map(|l| l.trim().strip_prefix("ZoneId="))
                .unwrap_or("?")
                .to_string();
            Finding {
                area: "mark-of-the-web",
                verdict: if zone == "3" || zone == "4" {
                    Verdict::Warn
                } else {
                    Verdict::Note
                },
                detail: format!(
                    "the binary carries ZoneId={zone} (3 = internet, 4 = untrusted). \
                     SmartScreen and some AppLocker rules key off this; \
                     clear it with `Unblock-File`."
                ),
            }
        }
        Err(_) => Finding {
            area: "mark-of-the-web",
            verdict: Verdict::Ok,
            detail: "no Zone.Identifier stream on the binary".into(),
        },
    }
}

fn applocker() -> Finding {
    let root = hklm();
    let base = "SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2";
    let mut modes = Vec::new();
    for coll in ["Exe", "Dll", "Msi", "Script", "Appx"] {
        if let Some(m) = read_dword(&root, &format!("{base}\\{coll}"), "EnforcementMode") {
            modes.push(format!(
                "{coll}={}",
                match m {
                    0 => "audit",
                    1 => "enforce",
                    _ => "?",
                }
            ));
        }
    }
    let svc = read_dword(&root, "SYSTEM\\CurrentControlSet\\Services\\AppID", "Start");
    let svc_txt = match svc {
        Some(2) => "AppIDSvc=automatic",
        Some(3) => "AppIDSvc=manual",
        Some(4) => "AppIDSvc=disabled",
        _ => "AppIDSvc=unknown",
    };

    if modes.is_empty() {
        return Finding {
            area: "applocker",
            verdict: Verdict::Ok,
            detail: format!("no AppLocker policy configured ({svc_txt})"),
        };
    }
    let enforcing = modes.iter().any(|m| m.ends_with("enforce"));
    Finding {
        area: "applocker",
        verdict: if enforcing {
            Verdict::Warn
        } else {
            Verdict::Note
        },
        detail: format!(
            "AppLocker policy present: {} ({svc_txt}). {}",
            modes.join(", "),
            if enforcing {
                "Enforcement is on - an unsigned binary outside an allowed path will be blocked."
            } else {
                "Audit only for now, but the policy can be flipped to enforce centrally."
            }
        ),
    }
}

fn srp() -> Finding {
    let root = hklm();
    let base = "SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers";
    match read_dword(&root, base, "DefaultLevel") {
        // 0x00000000 Disallowed, 0x00001000 Basic User, 0x00040000 Unrestricted.
        Some(0) => Finding {
            area: "srp",
            verdict: Verdict::Warn,
            detail: "Software Restriction Policies default to Disallowed (whitelist mode); \
                     only explicitly allowed paths or publishers may execute."
                .into(),
        },
        Some(0x1000) => Finding {
            area: "srp",
            verdict: Verdict::Warn,
            detail: "SRP default level is Basic User - the process runs with a stripped token."
                .into(),
        },
        Some(0x40000) => Finding {
            area: "srp",
            verdict: Verdict::Ok,
            detail: "SRP present but default level is Unrestricted".into(),
        },
        Some(other) => Finding {
            area: "srp",
            verdict: Verdict::Note,
            detail: format!("SRP DefaultLevel = 0x{other:08x}"),
        },
        None => Finding {
            area: "srp",
            verdict: Verdict::Ok,
            detail: "no Software Restriction Policy configured".into(),
        },
    }
}

fn wdac() -> Finding {
    let root = hklm();
    let dg = "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard";
    let vbs = read_dword(&root, dg, "EnableVirtualizationBasedSecurity");
    let ci = read_dword(&root, dg, "HypervisorEnforcedCodeIntegrity");

    let active = std::env::var("SystemRoot")
        .map(|r| PathBuf::from(r).join("System32\\CodeIntegrity\\CiPolicies\\Active"))
        .ok()
        .and_then(|p| std::fs::read_dir(p).ok())
        .map(|d| d.filter_map(|e| e.ok()).count())
        .unwrap_or(0);

    // Only *user-mode* code integrity blocks an application. HVCI protects
    // kernel mode. And stock Windows 11 ships several policies in CiPolicies
    // \Active by default (Microsoft's vulnerable-driver blocklist among them),
    // so their mere presence is not evidence of an app-control policy - warning
    // on the count alone would cry wolf on almost every machine.
    if ci == Some(1) {
        return Finding {
            area: "wdac",
            verdict: Verdict::Warn,
            detail: format!(
                "hypervisor-enforced code integrity is ON (VBS={vbs:?}, {active} active policy file(s)). \
                 If the deployed policy includes user-mode rules, file location is irrelevant - \
                 only a signature or an explicit hash rule lets an unsigned binary run."
            ),
        };
    }
    Finding {
        area: "wdac",
        verdict: Verdict::Note,
        detail: format!(
            "{active} code-integrity policy file(s) deployed, HVCI off (VBS={vbs:?}). \
             Windows ships driver-blocklist policies here by default; this is not by itself \
             an application-control policy. Verify with `Get-CIPolicyInfo` if it matters."
        ),
    }
}

fn hkcu_writable() -> Finding {
    let root = RegKey::predefined(winreg::hkey_current_user(), "HKEY_CURRENT_USER");
    match root.open("Software", winreg::KEY_WRITE, View::Native) {
        Ok(_) => Finding {
            area: "hkcu",
            verdict: Verdict::Ok,
            detail: "HKCU\\Software is writable - the redirection target is usable".into(),
        },
        Err(e) => Finding {
            area: "hkcu",
            verdict: Verdict::Warn,
            detail: format!("HKCU\\Software is NOT writable: {e}"),
        },
    }
}

// ---------------------------------------------------------------------------
// Token queries
// ---------------------------------------------------------------------------

const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ELEVATION: u32 = 20;
const TOKEN_INTEGRITY_LEVEL: u32 = 25;

#[link(name = "kernel32")]
unsafe extern "system" {
    safe fn GetCurrentProcess() -> *mut std::ffi::c_void;
    fn CloseHandle(h: *mut std::ffi::c_void) -> i32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(
        process: *mut std::ffi::c_void,
        access: u32,
        token: *mut *mut std::ffi::c_void,
    ) -> i32;
    fn GetTokenInformation(
        token: *mut std::ffi::c_void,
        class: u32,
        info: *mut u8,
        len: u32,
        ret: *mut u32,
    ) -> i32;
    fn GetSidSubAuthorityCount(sid: *mut u8) -> *mut u8;
    fn GetSidSubAuthority(sid: *mut u8, index: u32) -> *mut u32;
}

struct Token(*mut std::ffi::c_void);

impl Token {
    fn open() -> Option<Token> {
        let mut h: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: `h` is a valid out-slot; the pseudo-handle from
        // GetCurrentProcess needs no cleanup.
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h) };
        if ok == 0 || h.is_null() {
            None
        } else {
            Some(Token(h))
        }
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: handle came from OpenProcessToken and is closed once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn token_elevation() -> Option<bool> {
    let t = Token::open()?;
    let mut val: u32 = 0;
    let mut ret: u32 = 0;
    // SAFETY: TOKEN_ELEVATION is a single DWORD; the buffer matches its size.
    let ok = unsafe {
        GetTokenInformation(
            t.0,
            TOKEN_ELEVATION,
            &mut val as *mut u32 as *mut u8,
            4,
            &mut ret,
        )
    };
    if ok == 0 {
        None
    } else {
        Some(val != 0)
    }
}

/// Integrity level from the RID of the mandatory-label SID.
fn integrity_label() -> &'static str {
    let Some(t) = Token::open() else {
        return "integrity unknown";
    };
    let mut len: u32 = 0;
    // SAFETY: probe call - a null buffer with zero length returns the size needed.
    unsafe {
        GetTokenInformation(
            t.0,
            TOKEN_INTEGRITY_LEVEL,
            std::ptr::null_mut(),
            0,
            &mut len,
        );
    }
    if len == 0 {
        return "integrity unknown";
    }
    let mut buf = vec![0u8; len as usize];
    // SAFETY: `buf` has `len` writable bytes, the size the probe asked for.
    let ok =
        unsafe { GetTokenInformation(t.0, TOKEN_INTEGRITY_LEVEL, buf.as_mut_ptr(), len, &mut len) };
    if ok == 0 {
        return "integrity unknown";
    }
    // TOKEN_MANDATORY_LABEL is a SID_AND_ATTRIBUTES: the SID pointer comes first.
    let sid = unsafe { *(buf.as_ptr() as *const *mut u8) };
    if sid.is_null() {
        return "integrity unknown";
    }
    // SAFETY: `sid` is a valid SID owned by `buf` for the rest of this function.
    let rid = unsafe {
        let count = *GetSidSubAuthorityCount(sid);
        if count == 0 {
            return "integrity unknown";
        }
        *GetSidSubAuthority(sid, (count - 1) as u32)
    };
    match rid {
        0x0000 => "untrusted integrity",
        0x1000 => "low integrity",
        0x2000 => "medium integrity",
        0x2100 => "medium-plus integrity",
        0x3000 => "high integrity",
        0x4000 => "system integrity",
        _ => "custom integrity",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_check_reports_every_area_without_panicking() {
        let f = run();
        for area in [
            "process",
            "elevation",
            "wow64",
            "image path",
            "mark-of-the-web",
            "applocker",
            "srp",
            "wdac",
            "hkcu",
        ] {
            assert!(f.iter().any(|x| x.area == area), "missing area {area}");
        }
    }

    #[test]
    fn token_queries_return_something_sane() {
        assert!(token_elevation().is_some());
        assert_ne!(integrity_label(), "integrity unknown");
    }
}
