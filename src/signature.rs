//! Authenticode verification of the running binary, via `WinVerifyTrust`.
//!
//! Code signing is the single largest barrier to deploying a portable tool into
//! a managed environment: AppLocker judges a publisher, WDAC ignores file
//! location entirely, and SmartScreen warns on anything without reputation. So
//! the first question an administrator has is "is this signed, and by whom?" —
//! and the answer should come from the tool itself rather than from a README
//! that could have been edited.
//!
//! This asks Windows the same question Explorer's Digital Signatures tab asks,
//! against the same trust store, so the answer matches what AppLocker will
//! conclude. It deliberately does **not** contact a revocation endpoint:
//! `--self-check` runs on locked-down machines with no outbound access, and a
//! check that hangs for thirty seconds is worse than one that says plainly that
//! revocation was not consulted.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Signed, and the chain validates against this machine's trust store.
    Trusted { signer: String },
    /// Signed, but the chain does not validate here. Carries the reason.
    Untrusted {
        reason: &'static str,
        signer: Option<String>,
    },
    /// No signature at all.
    Unsigned,
    /// The check itself could not be performed.
    Unknown(String),
}

impl Status {
    pub fn label(&self) -> &'static str {
        match self {
            Status::Trusted { .. } => "trusted",
            Status::Untrusted { .. } => "untrusted",
            Status::Unsigned => "unsigned",
            Status::Unknown(_) => "unknown",
        }
    }

    /// What this means for getting the binary to run in a managed environment.
    pub fn consequence(&self) -> &'static str {
        match self {
            Status::Trusted { .. } => {
                "an AppLocker publisher rule can allow this binary anywhere it is copied"
            }
            Status::Untrusted { .. } => {
                "the signature will not satisfy a publisher rule on this machine; \
                 the issuing CA has to be trusted here first"
            }
            Status::Unsigned => {
                "AppLocker and WDAC have no publisher to judge, so only a path or hash rule \
                 can allow it, and SmartScreen will warn on a downloaded copy"
            }
            Status::Unknown(_) => "signature state could not be determined",
        }
    }
}

// ---------------------------------------------------------------------------
// Win32
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

/// WINTRUST_ACTION_GENERIC_VERIFY_V2 — the same action Explorer uses.
const ACTION_GENERIC_VERIFY_V2: Guid = Guid {
    data1: 0x00AA_C56B,
    data2: 0xCD44,
    data3: 0x11D0,
    data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};

#[repr(C)]
struct WintrustFileInfo {
    cb_struct: u32,
    file_path: *const u16,
    file_handle: *mut core::ffi::c_void,
    known_subject: *const Guid,
}

#[repr(C)]
struct WintrustData {
    cb_struct: u32,
    policy_callback_data: *mut core::ffi::c_void,
    sip_client_data: *mut core::ffi::c_void,
    ui_choice: u32,
    revocation_checks: u32,
    union_choice: u32,
    // The union: only the file variant is used, which is a pointer either way.
    file_info: *const WintrustFileInfo,
    state_action: u32,
    state_data: *mut core::ffi::c_void,
    url_reference: *mut u16,
    prov_flags: u32,
    ui_context: u32,
    signature_settings: *mut core::ffi::c_void,
}

const WTD_UI_NONE: u32 = 2;
const WTD_REVOKE_NONE: u32 = 0;
const WTD_CHOICE_FILE: u32 = 1;
const WTD_STATEACTION_VERIFY: u32 = 1;
const WTD_STATEACTION_CLOSE: u32 = 2;
/// Behave as the shell does, rather than applying driver-signing policy.
const WTD_SAFER_FLAG: u32 = 0x100;

// The subset of HRESULTs worth naming. Anything else is reported numerically
// rather than guessed at.
const TRUST_E_NOSIGNATURE: i32 = -2_146_762_496; // 0x800B0100
const TRUST_E_BAD_DIGEST: i32 = -2_146_869_232; // 0x80096010
const TRUST_E_EXPLICIT_DISTRUST: i32 = -2_146_762_479; // 0x800B0111
const CERT_E_UNTRUSTEDROOT: i32 = -2_146_762_487; // 0x800B0109
const CERT_E_EXPIRED: i32 = -2_146_762_495; // 0x800B0101
const CERT_E_CHAINING: i32 = -2_146_762_486; // 0x800B010A

#[link(name = "wintrust")]
unsafe extern "system" {
    fn WinVerifyTrust(
        hwnd: *mut core::ffi::c_void,
        action: *const Guid,
        data: *mut WintrustData,
    ) -> i32;
}

fn wide(p: &Path) -> Vec<u16> {
    let mut v: Vec<u16> = p.as_os_str().encode_wide().collect();
    v.push(0);
    v
}

/// Verify `path` against this machine's trust store.
pub fn verify(path: &Path) -> Status {
    if !path.exists() {
        return Status::Unknown(format!("{} does not exist", path.display()));
    }

    let w = wide(path);
    let file = WintrustFileInfo {
        cb_struct: std::mem::size_of::<WintrustFileInfo>() as u32,
        file_path: w.as_ptr(),
        file_handle: std::ptr::null_mut(),
        known_subject: std::ptr::null(),
    };

    let mut data = WintrustData {
        cb_struct: std::mem::size_of::<WintrustData>() as u32,
        policy_callback_data: std::ptr::null_mut(),
        sip_client_data: std::ptr::null_mut(),
        ui_choice: WTD_UI_NONE,
        // Revocation is deliberately not checked: this runs on machines with no
        // outbound access, where the lookup would stall rather than answer.
        revocation_checks: WTD_REVOKE_NONE,
        union_choice: WTD_CHOICE_FILE,
        file_info: &file,
        state_action: WTD_STATEACTION_VERIFY,
        state_data: std::ptr::null_mut(),
        url_reference: std::ptr::null_mut(),
        prov_flags: WTD_SAFER_FLAG,
        ui_context: 0,
        signature_settings: std::ptr::null_mut(),
    };

    // SAFETY: both structs are laid out per the SDK and live for the call;
    // `w` outlives `file`, which outlives `data`.
    let rc = unsafe { WinVerifyTrust(std::ptr::null_mut(), &ACTION_GENERIC_VERIFY_V2, &mut data) };

    // The verify call allocates state that must be released with a second call,
    // whatever the result.
    data.state_action = WTD_STATEACTION_CLOSE;
    // SAFETY: same structs, now asking the provider to free what it allocated.
    unsafe {
        WinVerifyTrust(std::ptr::null_mut(), &ACTION_GENERIC_VERIFY_V2, &mut data);
    }

    match rc {
        0 => Status::Trusted {
            signer: "see `Get-AuthenticodeSignature` for the certificate subject".into(),
        },
        TRUST_E_NOSIGNATURE => Status::Unsigned,
        CERT_E_UNTRUSTEDROOT => Status::Untrusted {
            reason: "the certificate chains to a root this machine does not trust",
            signer: None,
        },
        CERT_E_EXPIRED => Status::Untrusted {
            reason: "the certificate has expired and the signature was not timestamped",
            signer: None,
        },
        CERT_E_CHAINING => Status::Untrusted {
            reason: "the certificate chain is incomplete on this machine",
            signer: None,
        },
        TRUST_E_BAD_DIGEST => Status::Untrusted {
            reason: "the file has been modified since it was signed",
            signer: None,
        },
        TRUST_E_EXPLICIT_DISTRUST => Status::Untrusted {
            reason: "the signature is explicitly distrusted on this machine",
            signer: None,
        },
        other => Status::Unknown(format!("WinVerifyTrust returned 0x{:08X}", other as u32)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unsigned_binary_reports_unsigned_not_unknown() {
        // The test binary itself is unsigned, which is the case that matters:
        // it must be distinguishable from "could not check".
        let exe = std::env::current_exe().unwrap();
        let s = verify(&exe);
        assert!(
            matches!(s, Status::Unsigned | Status::Trusted { .. }),
            "unexpected status for the test binary: {s:?}"
        );
        assert!(!s.consequence().is_empty());
    }

    #[test]
    fn a_non_executable_is_reported_without_panicking() {
        let p = std::env::temp_dir().join("regx-sig-test.txt");
        std::fs::write(&p, b"not a PE file").unwrap();
        let s = verify(&p);
        // Windows reports "no signature" for a file with no signable structure;
        // either that or an explicit error is fine, a panic is not.
        assert!(
            matches!(
                s,
                Status::Unsigned | Status::Unknown(_) | Status::Untrusted { .. }
            ),
            "{s:?}"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_missing_file_is_unknown_not_unsigned() {
        let s = verify(Path::new(r"C:\nope\regx-does-not-exist.exe"));
        assert!(matches!(s, Status::Unknown(_)), "{s:?}");
    }

    #[test]
    fn every_status_explains_its_consequence() {
        for s in [
            Status::Trusted { signer: "x".into() },
            Status::Untrusted {
                reason: "y",
                signer: None,
            },
            Status::Unsigned,
            Status::Unknown("z".into()),
        ] {
            assert!(!s.label().is_empty());
            assert!(
                s.consequence().len() > 20,
                "{s:?} has no useful consequence"
            );
        }
    }
}
