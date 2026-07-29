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

    /// Is writing to `sub` inside a mounted hive forbidden?
    ///
    /// A mounted hive has no hive component — `HKCU` and `HKLM` are meaningless
    /// for a file — so a rule is matched on its subkey path alone. A rule
    /// protecting `HKCU\Software\Finance` therefore also protects
    /// `Software\Finance` inside somebody's `NTUSER.DAT`, which is the point:
    /// an administrator forbidding a setting means the setting, not one
    /// particular route to it. Without this the offline hive engine was a
    /// straight bypass of the deny list.
    pub fn denies_hive_subkey(&self, sub: &str) -> Option<&str> {
        let target = fold_str(sub.trim_matches('\\'));
        self.deny_keys.iter().find_map(|rule| {
            // Drop the rule's hive component; what remains is the subkey path.
            let without_hive = match RegPath::parse(rule) {
                Some(p) => p.sub,
                None => rule.trim_matches('\\').to_string(),
            };
            let r = fold_str(without_hive.trim_matches('\\'));
            if r.is_empty() {
                return None;
            }
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
    fn a_deny_rule_reaches_inside_a_mounted_hive() {
        // The offline hive engine was a straight bypass: a rule protecting a
        // key in the live registry did nothing about the same key inside
        // somebody's NTUSER.DAT.
        let p = policy_with(&["HKEY_CURRENT_USER\\Software\\Finance"]);
        assert!(p.denies_hive_subkey("Software\\Finance").is_some());
        assert!(p.denies_hive_subkey("Software\\Finance\\Payroll").is_some());
        assert!(p.denies_hive_subkey("\\Software\\Finance\\").is_some());

        // The rule's own hive is irrelevant for a file, so an HKLM rule still
        // protects the same subkey path.
        let p = policy_with(&["HKLM\\Software\\Finance"]);
        assert!(p.denies_hive_subkey("Software\\Finance").is_some());

        // And it still must not leak onto a neighbour.
        assert!(p.denies_hive_subkey("Software\\FinanceOther").is_none());
        assert!(p.denies_hive_subkey("Software\\Other").is_none());
    }

    #[test]
    fn a_hive_deny_rule_naming_only_a_root_matches_nothing() {
        // A rule of "HKCU" alone has an empty subkey path; treating that as a
        // prefix would deny every hive write on the machine.
        let p = policy_with(&["HKEY_CURRENT_USER"]);
        assert!(p.denies_hive_subkey("Software\\Anything").is_none());
    }

    #[test]
    fn every_registry_write_path_is_guarded() {
        // A structural check rather than a behavioural one: the deny list is
        // only as good as the number of places that consult it, and the hive
        // engine was missed the first time round. If a new write path appears,
        // this fails until it is wired in.
        let main = include_str!("main.rs");

        // The ordinary live paths: import/sync, undo, set, delete.
        assert_eq!(
            main.matches("enforce_denies(policy, &file)?").count(),
            4,
            "expected import/sync preflight, undo, set and delete checks"
        );
        assert_eq!(
            main.matches("enforce_denies(policy, &per_view)?").count(),
            1,
            "expected generated per-view reconciliation deletes to be rechecked"
        );
        assert_eq!(
            main.matches("enforce_denies(policy, &combined)?").count(),
            5,
            "expected subtree/value copy-move and both saved-plan apply paths to check the complete two-phase mutation"
        );
        assert_eq!(
            main.matches("enforce_denies(policy, &restore_file)?")
                .count(),
            2,
            "expected single- and dual-view application-hive restore to check every live destination"
        );
        // The offline hive paths: set, delete, import, undo, plus sync before
        // and after it generates reconciliation deletes.
        assert_eq!(
            main.matches("enforce_hive_denies(policy, &file)?").count(),
            6,
            "expected set/delete/import/undo guards and both hive-sync policy boundaries"
        );
        assert_eq!(
            main.matches("enforce_hive_denies(policy, &combined)?")
                .count(),
            2,
            "expected offline subtree and value copy/move to check their complete two-phase mutations"
        );

        // The check must also come before anything the refusal would have to
        // walk back — a written undo file, or a prompt already answered. Both
        // orderings were wrong when first written, one function apart, so the
        // relative positions are pinned rather than trusted.
        for (func, after) in [
            ("fn cmd_import(", "capture_prepared_view_snapshots"),
            ("fn cmd_import(", "add_prune_deletes"),
            ("fn cmd_import(", "if !confirm("),
            ("fn cmd_delete(", "if !confirm("),
        ] {
            // Bounded to this function. Searching on to end-of-file would let
            // a check deleted from one function be satisfied by the next one
            // down, and a guard that can pass for the wrong reason is not a
            // guard. `unwrap_or(usize::MAX)` had the same shape of flaw: a
            // missing prompt would read as "the deny check comes first".
            let start = main
                .find(func)
                .unwrap_or_else(|| panic!("{func} not found"));
            let rest = &main[start + func.len()..];
            let body = &rest[..rest.find("\nfn ").unwrap_or(rest.len())];

            let deny = body
                .find("enforce_denies(policy, &file)?")
                .unwrap_or_else(|| panic!("{func} has no deny check"));
            let later = body
                .find(after)
                .unwrap_or_else(|| panic!("{func} no longer contains {after:?}"));
            assert!(
                deny < later,
                "{func}: the deny check must precede {after:?}"
            );
        }
        {
            let func = "fn cmd_copy_move(";
            let start = main
                .find(func)
                .unwrap_or_else(|| panic!("{func} not found"));
            let rest = &main[start + func.len()..];
            let body = &rest[..rest.find("\nfn ").unwrap_or(rest.len())];
            let deny = body
                .find("enforce_denies(policy, &combined)?")
                .expect("copy/move has no combined deny check");
            for after in ["undo::snapshot", "if !confirm(", "apply_copy_move_atomic("] {
                let later = body
                    .find(after)
                    .unwrap_or_else(|| panic!("{func} no longer contains {after:?}"));
                assert!(
                    deny < later,
                    "{func}: the combined deny check must precede {after:?}"
                );
            }
        }

        // And every apply in the shipped binary must be the audited one. The
        // unaudited entry point is #[cfg(test)] precisely so this holds.
        assert_eq!(
            main.matches("engine::apply(").count(),
            0,
            "a write path is bypassing the audit log"
        );
        assert_eq!(
            main.matches("engine::apply_audited(").count(),
            18,
            "expected the audited write sites including offline-hive batch apply and rollback"
        );

        // A declined confirmation is a no-side-effect result. Snapshot reads
        // happen before the question, but the final undo-artifact write in
        // every artifact-producing mutation function must happen afterwards.
        for func in [
            "fn cmd_import(",
            "fn cmd_undo(",
            "fn cmd_apply_plan(",
            "fn cmd_batch(",
            "fn cmd_copy_move_value(",
            "fn cmd_restore(",
            "fn cmd_restore_both(",
            "fn cmd_copy_move(",
            "fn cmd_copy_move_both(",
            "fn cmd_apply_copy_plan(",
            "fn cmd_apply_copy_plan_both(",
        ] {
            let start = main
                .find(func)
                .unwrap_or_else(|| panic!("{func} not found"));
            let rest = &main[start + func.len()..];
            let body = &rest[..rest.find("\nfn ").unwrap_or(rest.len())];
            let confirmation = body
                .rfind("if !confirm(")
                .unwrap_or_else(|| panic!("{func} has no confirmation"));
            let artifact = body
                .rfind("write_reg(")
                .unwrap_or_else(|| panic!("{func} has no undo artifact"));
            assert!(
                confirmation < artifact,
                "{func}: undo artifact is written before confirmation"
            );
        }
        // Set/delete share one artifact writer. Each caller must confirm before
        // invoking it, and the helper itself is the only place that persists
        // these direct-mutation snapshots.
        for func in ["fn cmd_set(", "fn cmd_delete("] {
            let start = main
                .find(func)
                .unwrap_or_else(|| panic!("{func} not found"));
            let rest = &main[start + func.len()..];
            let body = &rest[..rest.find("\nfn ").unwrap_or(rest.len())];
            let confirmation = body
                .find("if !confirm(")
                .unwrap_or_else(|| panic!("{func} has no confirmation"));
            let artifact = body
                .find("write_direct_mutation_undo(")
                .unwrap_or_else(|| panic!("{func} does not persist its undo"));
            assert!(
                confirmation < artifact,
                "{func}: shared undo writer is called before confirmation"
            );
        }
        {
            let func = "fn write_direct_mutation_undo(";
            let start = main.find(func).expect("direct undo writer not found");
            let rest = &main[start + func.len()..];
            let body = &rest[..rest.find("\nfn ").unwrap_or(rest.len())];
            assert!(
                body.contains("write_reg("),
                "direct mutation undo helper no longer writes the snapshot"
            );
        }
        let hive_ops = main
            .split_once("fn run_hive_op(")
            .map(|(_, body)| body)
            .expect("run_hive_op not found");
        let hive_batch = hive_ops
            .split_once("HiveOp::Batch {")
            .map(|(_, rest)| {
                rest.split_once("HiveOp::Export {")
                    .map(|(body, _)| body)
                    .expect("hive batch no longer precedes export")
            })
            .expect("HiveOp::Batch not found");
        assert!(
            hive_batch
                .find("if !confirm(")
                .expect("hive batch confirmation")
                < hive_batch
                    .find("write_reg(")
                    .expect("hive batch undo artifact"),
            "offline-hive batch writes its undo artifact before confirmation"
        );
        for (start_marker, end_marker, label) in [
            ("HiveOp::Set {", "HiveOp::Delete {", "hive set"),
            ("HiveOp::Delete {", "HiveOp::Copy {", "hive delete"),
            ("HiveOp::Copy {", "HiveOp::CopyValue {", "hive copy/move"),
            (
                "HiveOp::CopyValue {",
                "HiveOp::Import {",
                "hive value copy/move",
            ),
            ("HiveOp::Import {", "HiveOp::Sync {", "hive import"),
            ("HiveOp::Sync {", "HiveOp::Batch {", "hive sync"),
        ] {
            let body = hive_ops
                .split_once(start_marker)
                .and_then(|(_, rest)| rest.split_once(end_marker).map(|(body, _)| body))
                .unwrap_or_else(|| panic!("{label} branch not found"));
            let confirmation = body
                .rfind("if !confirm(")
                .unwrap_or_else(|| panic!("{label} confirmation not found"));
            let artifact = body
                .rfind("write_hive_undo(")
                .unwrap_or_else(|| panic!("{label} undo write not found"));
            assert!(
                confirmation < artifact,
                "{label} writes its undo artifact before confirmation"
            );
        }
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
