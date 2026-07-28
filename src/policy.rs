//! Administrative policy over `regx` itself.
//!
//! A security team's objection to deploying a registry editor is not that it
//! might be unsigned — that is solvable with a certificate. It is that they
//! cannot govern what it does once it is on the machine. This is the answer:
//! a policy surface an administrator sets, a standard user cannot alter, and
//! the tool enforces on itself.
//!
//! # Why only HKLM
//!
//! Policy is read from `HKLM\SOFTWARE\Policies\regx` and **nowhere else**.
//! That is the whole point. A standard user can write freely to HKCU, so
//! honouring a per-user copy would let the person being restricted lift their
//! own restrictions — the exact inversion of what a policy is for. HKCU is not
//! consulted, even as a fallback, even to make something *more* strict, because
//! a setting that is sometimes authoritative and sometimes not is worse than
//! one that never is.
//!
//! By the same reasoning a `regx` command-line flag can make policy stricter
//! but never looser: `--audit-log` may add a second log, `--min-confidence high`
//! may exceed the floor, and neither can go the other way.
//!
//! # Settings
//!
//! | Value | Type | Effect |
//! |---|---|---|
//! | `AuditLog` | `REG_SZ` | Every mutation is logged here, whether or not `--audit-log` was passed |
//! | `AuditRedact` | `REG_DWORD` | Force `--audit-redact` on |
//! | `MinConfidence` | `REG_SZ` | Floor for Smart Redirection: `high`, `medium` or `low` |
//! | `DenyKeys` | `REG_MULTI_SZ` | Key prefixes `regx` must refuse to write to |
//! | `DisableHive` | `REG_DWORD` | Forbid the offline hive engine entirely |
//! | `RequireConfirm` | `REG_DWORD` | Ignore `-y`; a human must confirm each write |
//!
//! An ADMX template is shipped in `policy/` so this is configurable through
//! Group Policy rather than by hand — and `regx inspect policy/regx.admx`
//! reads it, which is a reasonable way to check what it declares.

use crate::model::{fold_str, RegData, RegPath};
use crate::winreg::{self, RegKey, View, KEY_READ};
use std::path::PathBuf;

/// Where policy lives. Not configurable, by design.
const POLICY_KEY: &str = r"SOFTWARE\Policies\regx";

#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// A log path the administrator requires, in addition to any `--audit-log`.
    pub audit_log: Option<PathBuf>,
    pub audit_redact: bool,
    /// `high`, `medium` or `low`; redirection may not go below this.
    pub min_confidence: Option<String>,
    /// Key path prefixes that must not be written to.
    pub deny_keys: Vec<String>,
    pub disable_hive: bool,
    pub require_confirm: bool,
    /// Present so `--self-check` can say "no policy is applied" with confidence
    /// rather than by inferring it from empty fields.
    pub configured: bool,
}

impl Policy {
    /// Read the machine policy. A machine with none configured yields a
    /// `Policy` that constrains nothing.
    pub fn load() -> Policy {
        let hklm = RegKey::predefined(winreg::hkey_local_machine(), "HKEY_LOCAL_MACHINE");

        // The 64-bit view explicitly: a 32-bit build must not read a different
        // policy than a 64-bit one, or the restriction depends on which binary
        // the user happened to run.
        let Ok(key) = hklm.open(POLICY_KEY, KEY_READ, View::Bits64) else {
            return Policy::default();
        };

        let string = |name: &str| -> Option<String> {
            let (ty, bytes) = key.get_value(name).ok()??;
            match crate::engine::raw_to_data(ty, &bytes) {
                RegData::Sz(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
                _ => None,
            }
        };
        let flag = |name: &str| -> bool {
            matches!(
                key.get_value(name).ok().flatten(),
                Some((ty, bytes))
                    if matches!(crate::engine::raw_to_data(ty, &bytes), RegData::Dword(v) if v != 0)
            )
        };
        let multi = |name: &str| -> Vec<String> {
            match key.get_value(name).ok().flatten() {
                Some((_, bytes)) => crate::model::utf16_from_bytes(&bytes)
                    .into_iter()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                None => Vec::new(),
            }
        };

        Policy {
            audit_log: string("AuditLog").map(PathBuf::from),
            audit_redact: flag("AuditRedact"),
            min_confidence: string("MinConfidence").map(|s| s.to_ascii_lowercase()),
            deny_keys: multi("DenyKeys"),
            disable_hive: flag("DisableHive"),
            require_confirm: flag("RequireConfirm"),
            configured: true,
        }
    }

    pub fn constrains_anything(&self) -> bool {
        self.audit_log.is_some()
            || self.audit_redact
            || self.min_confidence.is_some()
            || !self.deny_keys.is_empty()
            || self.disable_hive
            || self.require_confirm
    }

    /// Is writing to `path` forbidden? Returns the rule that forbids it.
    ///
    /// Matching is on whole path components, case-insensitively. A prefix of
    /// `HKCU\Software\Acme` denies `HKCU\Software\Acme\Sub` but not
    /// `HKCU\Software\AcmeOther` — otherwise a rule aimed at one product would
    /// silently cover every product whose name starts the same way.
    pub fn denies(&self, path: &RegPath) -> Option<&str> {
        let target = fold_str(&path.to_string());
        self.deny_keys.iter().find_map(|rule| {
            let r = fold_str(rule.trim_end_matches('\\'));
            if target == r || target.starts_with(&format!("{r}\\")) {
                Some(rule.as_str())
            } else {
                None
            }
        })
    }

    /// Lines for `--self-check`, describing what is in force.
    pub fn describe(&self) -> Vec<String> {
        if !self.configured {
            return vec![format!(
                "no administrative policy: HKLM\\{POLICY_KEY} does not exist"
            )];
        }
        if !self.constrains_anything() {
            return vec![format!("HKLM\\{POLICY_KEY} exists but sets nothing")];
        }
        let mut out = Vec::new();
        if let Some(p) = &self.audit_log {
            out.push(format!("audit log required at {}", p.display()));
        }
        if self.audit_redact {
            out.push("audit values are redacted to digests".into());
        }
        if let Some(c) = &self.min_confidence {
            out.push(format!("redirection floor: {c}"));
        }
        if !self.deny_keys.is_empty() {
            out.push(format!(
                "{} denied key prefix(es): {}",
                self.deny_keys.len(),
                self.deny_keys.join(", ")
            ));
        }
        if self.disable_hive {
            out.push("the offline hive engine is disabled".into());
        }
        if self.require_confirm {
            out.push("-y is ignored; every write needs confirmation".into());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RegPath;

    fn policy_with(deny: &[&str]) -> Policy {
        Policy {
            deny_keys: deny.iter().map(|s| s.to_string()).collect(),
            configured: true,
            ..Policy::default()
        }
    }

    #[test]
    fn a_deny_rule_covers_the_key_and_its_subtree() {
        let p = policy_with(&["HKEY_CURRENT_USER\\Software\\Acme"]);
        let denied = |s: &str| p.denies(&RegPath::parse(s).unwrap()).is_some();

        assert!(denied("HKCU\\Software\\Acme"));
        assert!(denied("HKCU\\Software\\Acme\\Sub\\Deeper"));
    }

    #[test]
    fn a_deny_rule_does_not_leak_onto_a_similarly_named_key() {
        // Matching on the raw string prefix would make a rule for one product
        // quietly cover every product whose name starts the same way.
        let p = policy_with(&["HKEY_CURRENT_USER\\Software\\Acme"]);
        assert!(p
            .denies(&RegPath::parse("HKCU\\Software\\AcmeOther").unwrap())
            .is_none());
        assert!(p
            .denies(&RegPath::parse("HKCU\\Software\\Acme2").unwrap())
            .is_none());
    }

    #[test]
    fn deny_matching_is_case_insensitive_like_the_registry() {
        let p = policy_with(&["hkey_current_user\\software\\ACME"]);
        assert!(p
            .denies(&RegPath::parse("HKCU\\Software\\Acme\\Child").unwrap())
            .is_some());
    }

    #[test]
    fn a_trailing_backslash_in_a_rule_is_tolerated() {
        let p = policy_with(&["HKEY_CURRENT_USER\\Software\\Acme\\"]);
        assert!(p
            .denies(&RegPath::parse("HKCU\\Software\\Acme\\X").unwrap())
            .is_some());
    }

    #[test]
    fn an_unconfigured_policy_constrains_nothing_and_says_so() {
        let p = Policy::default();
        assert!(!p.constrains_anything());
        assert!(p
            .denies(&RegPath::parse("HKCU\\Software\\Anything").unwrap())
            .is_none());
        assert!(p.describe()[0].contains("no administrative policy"));
    }

    #[test]
    fn loading_on_an_unconfigured_machine_does_not_fail() {
        // Most machines have no policy key; that must read as "no constraints",
        // never as an error or a partially-applied policy.
        let p = Policy::load();
        if !p.configured {
            assert!(!p.constrains_anything());
        }
    }

    #[test]
    fn describe_lists_every_active_constraint() {
        let p = Policy {
            audit_log: Some(PathBuf::from("C:\\logs\\regx.jsonl")),
            audit_redact: true,
            min_confidence: Some("high".into()),
            deny_keys: vec!["HKCU\\Software\\Finance".into()],
            disable_hive: true,
            require_confirm: true,
            configured: true,
        };
        let lines = p.describe().join("\n");
        for expected in [
            "audit log required",
            "redacted",
            "high",
            "denied key prefix",
            "hive engine is disabled",
            "-y is ignored",
        ] {
            assert!(
                lines.contains(expected),
                "missing {expected:?} in:\n{lines}"
            );
        }
    }
}
