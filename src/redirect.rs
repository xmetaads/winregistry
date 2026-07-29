//! Smart Redirection: HKLM/HKCR -> HKCU mapping with an honest confidence signal.
//!
//! The product risk here is *false success*: a naive `HKLM` -> `HKCU` string
//! replace always "works", writes cleanly, and changes nothing. So every mapping
//! carries a `Confidence` plus the reason, and the CLI refuses to silently apply
//! anything below `--min-confidence`.

use crate::model::{Hive, RegPath};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Confidence {
    /// Cannot be mapped at all; applying it would be meaningless or harmful.
    Refuse,
    /// Mapping is syntactically valid but very unlikely to take effect.
    Low,
    /// Works if the consuming application checks HKCU (many do not).
    Medium,
    /// Documented per-user equivalent; Windows itself reads the HKCU copy.
    High,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Refuse => "refuse",
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Mapping {
    pub to: Option<RegPath>,
    pub confidence: Confidence,
    pub reason: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Policy {
    /// Leave every path untouched.
    Off,
    /// Map everything we can, subject to `min_confidence`.
    Auto,
    /// Only the genuinely reliable HKCR/Classes case.
    ClassesOnly,
}

pub fn map(path: &RegPath, policy: Policy) -> Mapping {
    let keep = |reason: &'static str| Mapping {
        to: None,
        confidence: Confidence::High,
        reason,
    };

    match path.hive {
        // Already per-user - nothing to do.
        Hive::Hkcu => return keep("already under HKEY_CURRENT_USER"),
        Hive::Hkcc => {
            return Mapping {
                to: None,
                confidence: Confidence::Refuse,
                reason:
                    "HKCC is a live view of the hardware profile; it has no per-user equivalent",
            }
        }
        Hive::Hku => return Mapping {
            to: None,
            confidence: Confidence::Low,
            reason:
                "HKEY_USERS targets a specific SID; resolve it explicitly instead of redirecting",
        },
        _ => {}
    }

    if policy == Policy::Off {
        return keep("redirection disabled");
    }

    // HKCR is a merged view of HKLM\Software\Classes and HKCU\Software\Classes,
    // and since Vista a write to HKCR already lands in the per-user copy.
    // This is the one mapping that is reliable by design.
    if path.hive == Hive::Hkcr {
        let m = Mapping {
            to: Some(RegPath {
                hive: Hive::Hkcu,
                sub: join("SOFTWARE\\Classes", &path.sub),
            }),
            confidence: Confidence::High,
            reason: "HKCR is a merged view; the per-user branch takes precedence",
        };
        return maybe_userchoice(m, &path.sub);
    }

    // From here on: HKLM.
    // Normalise the WOW64 alias first, otherwise the classification below misses.
    let sub = strip_wow6432(&path.sub);
    let upper = sub.to_ascii_uppercase();

    let hkcu = |s: &str, confidence: Confidence, reason: &'static str| Mapping {
        to: Some(RegPath {
            hive: Hive::Hkcu,
            sub: s.to_string(),
        }),
        confidence,
        reason,
    };

    if upper.starts_with("SYSTEM")
        || upper.starts_with("HARDWARE")
        || upper.starts_with("SAM")
        || upper.starts_with("SECURITY")
        || upper.starts_with("BCD")
    {
        return Mapping {
            to: None,
            confidence: Confidence::Refuse,
            reason: "machine-only hive (services, drivers, SAM); no per-user equivalent exists",
        };
    }

    if let Some(rest) = strip_ci(&sub, "SOFTWARE\\Classes") {
        let m = hkcu(
            &join("SOFTWARE\\Classes", rest),
            Confidence::High,
            "class registration resolves per-user first",
        );
        return maybe_userchoice(m, rest);
    }

    if policy == Policy::ClassesOnly {
        return Mapping {
            to: None,
            confidence: Confidence::Refuse,
            reason: "--redirect classes-only: nothing outside Software\\Classes is mapped",
        };
    }

    if let Some(rest) = strip_ci(&sub, "SOFTWARE\\Policies") {
        return hkcu(
            &join("SOFTWARE\\Policies", rest),
            Confidence::Low,
            "machine-scoped policies are read from HKLM by SYSTEM services, and Group Policy refresh wipes the HKCU\\Software\\Policies subtree",
        );
    }

    if strip_ci(
        &sub,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
    )
    .is_some()
    {
        return hkcu(
            &sub,
            Confidence::Low,
            "the HKCU copy exists but is commonly locked down by Group Policy ACLs",
        );
    }

    // These are Windows mechanisms, not ordinary application preferences.
    // Their HKLM and HKCU branches have different semantics, so copying the
    // same path into HKCU would report success without preserving behaviour.
    if strip_ci(
        &sub,
        "SOFTWARE\\Microsoft\\Active Setup\\Installed Components",
    )
    .is_some()
    {
        return Mapping {
            to: None,
            confidence: Confidence::Refuse,
            reason: "Active Setup HKLM entries register components, while HKCU entries record per-user completion; they are not interchangeable",
        };
    }

    if strip_ci(
        &sub,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    )
    .is_some()
        || strip_ci(
            &sub,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        )
        .is_some()
    {
        return Mapping {
            to: None,
            confidence: Confidence::Refuse,
            reason: "User Shell Folders must be set in the existing HKCU profile (prefer the Windows Known Folder API); machine and user value sets are not interchangeable",
        };
    }

    if strip_ci(
        &sub,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    )
    .is_some()
    {
        return Mapping {
            to: None,
            confidence: Confidence::Refuse,
            reason: "Winlogon Shell/Userinit are machine logon settings; redirecting them can break sign-in and has no safe per-user equivalent",
        };
    }

    for run in [
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
    ] {
        if strip_ci(&sub, run).is_some() {
            return hkcu(
                &sub,
                Confidence::High,
                "Windows reads the per-user copy of this key in addition to the machine copy",
            );
        }
    }

    if upper.starts_with("SOFTWARE") {
        return hkcu(
            &sub,
            Confidence::Medium,
            "per-user equivalent is valid only if the application falls back to HKCU",
        );
    }

    Mapping {
        to: None,
        confidence: Confidence::Refuse,
        reason: "unrecognised HKLM subtree; refusing to guess a per-user location",
    }
}

/// `UserChoice` is protected by a SID-salted hash since Windows 8; writing it
/// from a .reg file is rejected by Explorer and the association silently resets.
fn maybe_userchoice(mut m: Mapping, sub: &str) -> Mapping {
    if sub.to_ascii_uppercase().contains("\\USERCHOICE") {
        m.confidence = Confidence::Refuse;
        m.to = None;
        m.reason =
            "UserChoice is protected by a per-SID hash; file associations cannot be set via .reg";
    }
    m
}

/// On 64-bit Windows a 32-bit caller sees `SOFTWARE\WOW6432Node\X` as `SOFTWARE\X`.
/// Normalise so classification does not depend on which view produced the file.
pub fn strip_wow6432(sub: &str) -> String {
    match strip_ci(sub, "SOFTWARE\\WOW6432Node") {
        Some(rest) => join("SOFTWARE", rest),
        None => sub.to_string(),
    }
}

/// Case-insensitive prefix strip on whole path components.
/// Returns the remainder with no leading backslash, or `None` if no match.
fn strip_ci<'a>(sub: &'a str, prefix: &str) -> Option<&'a str> {
    if sub.len() < prefix.len() {
        return None;
    }
    if !sub[..prefix.len()].eq_ignore_ascii_case(prefix) {
        return None;
    }
    match sub.as_bytes().get(prefix.len()) {
        None => Some(""),
        Some(b'\\') => Some(sub[prefix.len() + 1..].trim_start_matches('\\')),
        Some(_) => None, // partial component match, e.g. "SOFTWAREX"
    }
}

fn join(base: &str, rest: &str) -> String {
    if rest.is_empty() {
        base.to_string()
    } else {
        format!("{base}\\{rest}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> RegPath {
        RegPath::parse(s).unwrap()
    }

    #[test]
    fn classes_map_with_high_confidence() {
        let m = map(
            &p("HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\.txt"),
            Policy::Auto,
        );
        assert_eq!(m.confidence, Confidence::High);
        assert_eq!(
            m.to.unwrap().to_string(),
            "HKEY_CURRENT_USER\\SOFTWARE\\Classes\\.txt"
        );
    }

    #[test]
    fn system_hive_is_refused() {
        let m = map(
            &p("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Foo"),
            Policy::Auto,
        );
        assert_eq!(m.confidence, Confidence::Refuse);
        assert!(m.to.is_none());
    }

    #[test]
    fn machine_policy_is_low_confidence() {
        let m = map(
            &p("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"),
            Policy::Auto,
        );
        assert_eq!(m.confidence, Confidence::Low);
    }

    #[test]
    fn wow6432node_is_normalised() {
        let m = map(&p("HKLM\\SOFTWARE\\WOW6432Node\\Acme\\App"), Policy::Auto);
        assert_eq!(m.to.unwrap().sub, "SOFTWARE\\Acme\\App");
    }

    #[test]
    fn userchoice_is_refused() {
        let m = map(&p("HKEY_CLASSES_ROOT\\.pdf\\UserChoice"), Policy::Auto);
        assert_eq!(m.confidence, Confidence::Refuse);
    }

    #[test]
    fn active_setup_is_recognised_and_refused() {
        let m = map(
            &p("HKLM\\Software\\Microsoft\\Active Setup\\Installed Components\\{ABC}"),
            Policy::Auto,
        );
        assert_eq!(m.confidence, Confidence::Refuse);
        assert!(m.to.is_none());
        assert!(m.reason.contains("Active Setup"));
    }

    #[test]
    fn active_setup_wow6432_alias_is_recognised() {
        let m = map(
            &p("HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Active Setup\\Installed Components\\{ABC}"),
            Policy::Auto,
        );
        assert_eq!(m.confidence, Confidence::Refuse);
        assert!(m.reason.contains("Active Setup"));
    }

    #[test]
    fn user_shell_folders_are_recognised_and_refused() {
        let m = map(
            &p("HKLM\\software\\microsoft\\windows\\currentversion\\explorer\\user shell folders"),
            Policy::Auto,
        );
        assert_eq!(m.confidence, Confidence::Refuse);
        assert!(m.to.is_none());
        assert!(m.reason.contains("Known Folder"));
    }

    #[test]
    fn winlogon_is_recognised_and_refused() {
        let m = map(
            &p("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
            Policy::Auto,
        );
        assert_eq!(m.confidence, Confidence::Refuse);
        assert!(m.to.is_none());
        assert!(m.reason.contains("Winlogon"));
    }

    #[test]
    fn unrelated_explorer_key_is_not_overstated_as_high_confidence() {
        let m = map(
            &p("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"),
            Policy::Auto,
        );
        assert_eq!(m.confidence, Confidence::Medium);
    }

    #[test]
    fn partial_component_does_not_match() {
        assert_eq!(strip_ci("SOFTWAREX\\A", "SOFTWARE"), None);
        assert_eq!(strip_ci("SOFTWARE\\A", "SOFTWARE"), Some("A"));
        assert_eq!(strip_ci("software", "SOFTWARE"), Some(""));
    }
}
