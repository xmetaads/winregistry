//! Tamper-evident audit log.
//!
//! An enterprise cannot deploy a tool that changes the registry and leaves no
//! attributable record of what it changed. This writes one JSON object per line
//! — timestamp, actor, operation, before and after — to a file the operator
//! nominates, appending so that concurrent runs accumulate rather than clobber.
//!
//! # Why the records are chained
//!
//! A log an attacker can quietly edit is not evidence. Every record carries the
//! SHA-256 of the previous record's serialised form, so removing or altering a
//! line breaks the chain from that point on and `regx audit verify` says exactly
//! where. This does not stop someone truncating the tail or rewriting the whole
//! file — nothing local can, without a key the operator does not hold — but it
//! does turn silent tampering into a detectable event, which is the property
//! auditors actually ask for. Ship the file somewhere append-only for the rest.
//!
//! # Why values can be redacted
//!
//! Registry values hold licence keys, tokens and connection strings. A log that
//! faithfully records every byte written is itself a secret. `--audit-redact`
//! records the SHA-256 of the data and its length instead of the data, which
//! still proves *that* a specific value was written and lets two runs be
//! compared, without the log becoming something that needs a vault of its own.

use crate::model::{RegData, RegPath, ValueName};
use crate::sha256::{hash_hex, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    Applied,
    /// `--dry-run`: the operation was resolved but deliberately not performed.
    Simulated,
    Failed,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Outcome::Applied => "applied",
            Outcome::Simulated => "simulated",
            Outcome::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    KeyCreate,
    KeyDelete,
    ValueSet,
    ValueDelete,
}

impl Op {
    fn as_str(self) -> &'static str {
        match self {
            Op::KeyCreate => "key.create",
            Op::KeyDelete => "key.delete",
            Op::ValueSet => "value.set",
            Op::ValueDelete => "value.delete",
        }
    }
}

/// One recordable operation.
///
/// A struct rather than seven positional arguments: at the call sites in the
/// apply engine, `Some(&v.name), before.as_ref(), Some(other)` in a row is
/// three `Option`s of two different types that are trivial to transpose, and
/// nothing would catch it.
pub struct Event<'a> {
    pub op: Op,
    pub path: &'a RegPath,
    pub name: Option<&'a ValueName>,
    /// What was there before the write, when a log is attached.
    pub before: Option<&'a RegData>,
    /// What was written. `None` for a delete.
    pub after: Option<&'a RegData>,
    pub outcome: Outcome,
    /// Error text when the outcome is `Failed`.
    pub detail: Option<&'a str>,
}

pub struct Logger {
    path: PathBuf,
    redact: bool,
    /// Hash of the previous record, carried forward to chain the next.
    prev: String,
    session: String,
    seq: u64,
}

impl Logger {
    /// Open (creating if needed) and write the session header.
    ///
    /// The chain continues from whatever is already in the file, so appending
    /// to an existing log keeps it verifiable end to end.
    pub fn open(path: &Path, redact: bool, command: &str) -> std::io::Result<Logger> {
        let prev = last_hash(path).unwrap_or_else(|| "genesis".to_string());

        // Distinguishes interleaved records when several runs append together.
        let session =
            hash_hex(format!("{}|{}|{}", command, now_iso8601(), std::process::id()).as_bytes())
                [..16]
                .to_string();

        let mut l = Logger {
            path: path.to_path_buf(),
            redact,
            prev,
            session,
            seq: 0,
        };

        let fields = vec![
            ("event".into(), jstr("session.start")),
            ("version".into(), jstr(env!("CARGO_PKG_VERSION"))),
            ("command".into(), jstr(&redact_command(command, redact))),
            ("actor".into(), jstr(&actor())),
            ("pid".into(), std::process::id().to_string()),
            ("redacted".into(), redact.to_string()),
        ];
        l.write(fields)?;
        Ok(l)
    }

    /// Record one registry operation.
    pub fn record(&mut self, e: Event<'_>) {
        let mut fields = vec![
            ("event".to_string(), jstr(e.op.as_str())),
            ("key".to_string(), jstr(&e.path.to_string())),
            ("outcome".to_string(), jstr(e.outcome.as_str())),
        ];
        if let Some(n) = e.name {
            fields.push(("value".into(), jstr(&n.to_string())));
        }
        if let Some(b) = e.before {
            fields.push(("before".into(), self.render(b)));
        }
        if let Some(a) = e.after {
            fields.push(("after".into(), self.render(a)));
        }
        if let Some(d) = e.detail {
            fields.push(("detail".into(), jstr(d)));
        }
        // A logging failure must never take down the operation being logged,
        // but it must not pass unnoticed either.
        if let Err(e) = self.write(fields) {
            eprintln!("regx: audit log write failed: {e}");
        }
    }

    /// Data as JSON, or its digest when redacting.
    fn render(&self, d: &RegData) -> String {
        let ty = jstr(d.type_name());
        if !self.redact {
            return format!("{{\"type\": {ty}, \"data\": {}}}", jstr(&d.preview()));
        }
        match crate::engine::data_to_raw(d) {
            Some((_, bytes)) => format!(
                "{{\"type\": {ty}, \"sha256\": {}, \"bytes\": {}}}",
                jstr(&hash_hex(&bytes)),
                bytes.len()
            ),
            None => format!("{{\"type\": {ty}}}"),
        }
    }

    fn write(&mut self, mut fields: Vec<(String, String)>) -> std::io::Result<()> {
        self.seq += 1;
        let mut head = vec![
            ("ts".to_string(), jstr(&now_iso8601())),
            ("session".to_string(), jstr(&self.session)),
            ("seq".to_string(), self.seq.to_string()),
        ];
        head.append(&mut fields);
        head.push(("prev".to_string(), jstr(&self.prev)));

        let body = head
            .iter()
            .map(|(k, v)| format!("{}: {v}", jstr(k)))
            .collect::<Vec<_>>()
            .join(", ");

        // The record's own hash covers the body including `prev`, which is what
        // links it to everything before it.
        let hash = hash_hex(body.as_bytes());
        let line = format!("{{{body}, \"hash\": {}}}\n", jstr(&hash));
        self.prev = hash;

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(line.as_bytes())
    }
}

#[derive(Debug)]
pub struct Verification {
    pub records: usize,
    pub sessions: usize,
    /// 1-based line numbers where the chain does not hold.
    pub broken: Vec<(usize, String)>,
}

impl Verification {
    pub fn is_intact(&self) -> bool {
        self.broken.is_empty()
    }
}

/// Re-hash every record and confirm each one names its predecessor.
pub fn verify(path: &Path) -> std::io::Result<Verification> {
    let text = std::fs::read_to_string(path)?;
    let mut v = Verification {
        records: 0,
        sessions: 0,
        broken: Vec::new(),
    };
    let mut expected_prev = "genesis".to_string();
    let mut seen_sessions: Vec<String> = Vec::new();

    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        v.records += 1;
        let lineno = i + 1;

        let Some((body, stated)) = split_hash(line) else {
            v.broken.push((lineno, "record has no hash field".into()));
            continue;
        };

        let actual = hash_hex(body.as_bytes());
        if actual != stated {
            v.broken.push((
                lineno,
                format!("content does not match its hash (recorded {stated}, actual {actual})"),
            ));
            // Continue from what the record claims, so one edited line reports
            // once rather than invalidating everything after it.
            expected_prev = stated.to_string();
            continue;
        }

        match field(body, "prev") {
            Some(p) if p == expected_prev => {}
            Some(p) => v.broken.push((
                lineno,
                format!("chain break: names {p} as previous, expected {expected_prev}"),
            )),
            None => v.broken.push((lineno, "record has no prev field".into())),
        }
        expected_prev = stated.to_string();

        if let Some(s) = field(body, "session") {
            if !seen_sessions.contains(&s.to_string()) {
                seen_sessions.push(s.to_string());
            }
        }
    }

    v.sessions = seen_sessions.len();
    Ok(v)
}

/// Split a record into the body that was hashed and the hash it states.
///
/// The opening brace is located rather than assumed at index 0: a log that has
/// been through a Windows editor or a PowerShell redirect often gains a UTF-8
/// BOM, and reporting that as tampering would be a false accusation about the
/// one thing this file exists to answer truthfully.
fn split_hash(line: &str) -> Option<(&str, &str)> {
    let open = line.find('{')?;
    let marker = ", \"hash\": \"";
    let at = line.rfind(marker)?;
    let body = line.get(open + 1..at)?;
    let rest = &line[at + marker.len()..];
    let end = rest.find('"')?;
    Some((body, &rest[..end]))
}

/// Pull a string field out of a record body without a JSON parser. The writer
/// controls the format, so this only has to understand what the writer emits.
fn field<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("\"{name}\": \"");
    let at = body.find(&needle)? + needle.len();
    let rest = &body[at..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Strip value data out of the recorded command line when redacting.
///
/// Redaction was originally applied only to the values written, which left the
/// obvious hole wide open: `regx set … -d SECRET` puts the secret straight into
/// the `session.start` record. A redacted log that still contains the secret is
/// worse than no redaction, because the operator believes it is safe to keep.
///
/// The argument after `-d`/`--data`, and the `--data=VALUE` form, become a
/// digest — still enough to tell two runs apart, or to confirm a specific value
/// was written, without holding the value itself.
///
/// This covers data supplied on the command line. Data read from a file never
/// appears here, and is redacted where it is written.
fn redact_command(command: &str, redact: bool) -> String {
    if !redact {
        return command.to_string();
    }
    let mut out: Vec<String> = Vec::new();
    let mut elide_next = false;

    for token in command.split_whitespace() {
        if elide_next {
            out.push(digest_placeholder(token));
            elide_next = false;
            continue;
        }
        if token == "-d" || token == "--data" {
            out.push(token.to_string());
            elide_next = true;
            continue;
        }
        if let Some(v) = token
            .strip_prefix("--data=")
            .or_else(|| token.strip_prefix("-d="))
        {
            let flag = if token.starts_with("--") {
                "--data"
            } else {
                "-d"
            };
            out.push(format!("{flag}={}", digest_placeholder(v)));
            continue;
        }
        out.push(token.to_string());
    }
    out.join(" ")
}

fn digest_placeholder(value: &str) -> String {
    format!("<redacted:{}>", &hash_hex(value.as_bytes())[..16])
}

/// Digest of a file, for release checksums and for `audit verify` to record
/// which binary produced a log.
pub fn file_digest(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(crate::sha256::hex(&h.finish()))
}

fn last_hash(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let last = text.lines().rev().find(|l| !l.trim().is_empty())?;
    split_hash(last.trim()).map(|(_, h)| h.to_string())
}

/// `DOMAIN\user (S-1-5-21-...)`, so a record is attributable to an account
/// rather than just a session.
fn actor() -> String {
    let name = std::env::var("USERNAME").unwrap_or_else(|_| "?".into());
    let domain = std::env::var("USERDOMAIN").unwrap_or_else(|_| "?".into());
    match crate::selfcheck::current_user_sid() {
        Some(sid) => format!("{domain}\\{name} ({sid})"),
        None => format!("{domain}\\{name}"),
    }
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// UTC in RFC 3339 form. Implemented here rather than pulling in a date crate:
/// the civil-from-days algorithm is a dozen lines and this is the only place a
/// calendar is needed.
pub fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's `civil_from_days`, shifting the era to start in March so
/// the leap day falls at the end of a year and needs no special case.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn jstr(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("regx-audit-{name}.jsonl"));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn path() -> RegPath {
        RegPath::parse("HKCU\\Software\\Acme").unwrap()
    }

    #[test]
    fn civil_calendar_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        // 2024 is a leap year: day 59 of the year is 29 February.
        assert_eq!(civil_from_days(19_723 + 59), (2024, 2, 29));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn timestamp_is_rfc3339_utc() {
        let ts = now_iso8601();
        assert_eq!(ts.len(), 20, "{ts}");
        assert!(ts.ends_with('Z'), "{ts}");
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn a_written_log_verifies() {
        let p = scratch("intact");
        let mut l = Logger::open(&p, false, "regx set ...").unwrap();
        l.record(Event {
            op: Op::ValueSet,
            path: &path(),
            name: Some(&ValueName::Named("Channel".into())),
            before: Some(&RegData::Sz("stable".into())),
            after: Some(&RegData::Sz("beta".into())),
            outcome: Outcome::Applied,
            detail: None,
        });
        l.record(Event {
            op: Op::ValueDelete,
            path: &path(),
            name: Some(&ValueName::Named("Legacy".into())),
            before: Some(&RegData::Dword(1)),
            after: None,
            outcome: Outcome::Applied,
            detail: None,
        });
        drop(l);

        let v = verify(&p).unwrap();
        assert!(v.is_intact(), "{:?}", v.broken);
        assert_eq!(v.records, 3, "session header plus two operations");
        assert_eq!(v.sessions, 1);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_utf8_bom_is_not_mistaken_for_tampering() {
        let p = scratch("bom");
        let mut l = Logger::open(&p, false, "regx set ...").unwrap();
        l.record(Event {
            op: Op::KeyCreate,
            path: &path(),
            name: None,
            before: None,
            after: None,
            outcome: Outcome::Applied,
            detail: None,
        });
        drop(l);

        // What a PowerShell redirect or a Windows editor does to the file.
        let body = std::fs::read(&p).unwrap();
        let mut with_bom = vec![0xEF, 0xBB, 0xBF];
        with_bom.extend_from_slice(&body);
        std::fs::write(&p, with_bom).unwrap();

        let v = verify(&p).unwrap();
        assert!(
            v.is_intact(),
            "a BOM must not read as tampering: {:?}",
            v.broken
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn editing_a_record_is_detected() {
        let p = scratch("edited");
        let mut l = Logger::open(&p, false, "regx set ...").unwrap();
        l.record(Event {
            op: Op::ValueSet,
            path: &path(),
            name: Some(&ValueName::Named("Channel".into())),
            before: None,
            after: Some(&RegData::Sz("beta".into())),
            outcome: Outcome::Applied,
            detail: None,
        });
        drop(l);

        let text = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, text.replace("beta", "prod")).unwrap();

        let v = verify(&p).unwrap();
        assert!(!v.is_intact(), "an edited value must break the record hash");
        assert!(v.broken[0].1.contains("does not match"), "{:?}", v.broken);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn deleting_a_record_breaks_the_chain() {
        let p = scratch("deleted");
        let mut l = Logger::open(&p, false, "regx import ...").unwrap();
        for i in 0..3 {
            l.record(Event {
                op: Op::ValueSet,
                path: &path(),
                name: Some(&ValueName::Named(format!("v{i}"))),
                before: None,
                after: Some(&RegData::Dword(i)),
                outcome: Outcome::Applied,
                detail: None,
            });
        }
        drop(l);

        let lines: Vec<String> = std::fs::read_to_string(&p)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        assert_eq!(lines.len(), 4);
        // Remove a record from the middle; every hash still self-verifies, so
        // only the chain link can reveal it.
        let mut kept = lines.clone();
        kept.remove(2);
        std::fs::write(&p, kept.join("\n") + "\n").unwrap();

        let v = verify(&p).unwrap();
        assert!(!v.is_intact());
        assert!(v.broken[0].1.contains("chain break"), "{:?}", v.broken);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn appending_a_second_session_continues_the_chain() {
        let p = scratch("append");
        let mut a = Logger::open(&p, false, "first").unwrap();
        a.record(Event {
            op: Op::KeyCreate,
            path: &path(),
            name: None,
            before: None,
            after: None,
            outcome: Outcome::Applied,
            detail: None,
        });
        drop(a);

        let mut b = Logger::open(&p, false, "second").unwrap();
        b.record(Event {
            op: Op::KeyDelete,
            path: &path(),
            name: None,
            before: None,
            after: None,
            outcome: Outcome::Applied,
            detail: None,
        });
        drop(b);

        let v = verify(&p).unwrap();
        assert!(v.is_intact(), "{:?}", v.broken);
        assert_eq!(v.sessions, 2);
        assert_eq!(v.records, 4);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn redaction_records_a_digest_not_the_secret() {
        let p = scratch("redact");
        let secret = "licence-key-do-not-log";
        let mut l = Logger::open(&p, true, "regx set ...").unwrap();
        l.record(Event {
            op: Op::ValueSet,
            path: &path(),
            name: Some(&ValueName::Named("Licence".into())),
            before: None,
            after: Some(&RegData::Sz(secret.into())),
            outcome: Outcome::Applied,
            detail: None,
        });
        drop(l);

        let text = std::fs::read_to_string(&p).unwrap();
        assert!(!text.contains(secret), "the secret was written to the log");
        assert!(text.contains("sha256"), "no digest recorded: {text}");
        assert!(verify(&p).unwrap().is_intact());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn redaction_covers_the_command_line_too() {
        // The first version of this redacted the written values but recorded
        // the command line verbatim, so `regx set ... -d SECRET` leaked the
        // secret into the session header. A redacted log that still contains
        // the secret is worse than none, because it is trusted.
        let p = scratch("redact-cmd");
        let secret = "SECRET-KEY-1234";
        let mut l = Logger::open(
            &p,
            true,
            &format!("regx set HKCU\\Software\\A -v Licence -d {secret} -y"),
        )
        .unwrap();
        l.record(Event {
            op: Op::ValueSet,
            path: &path(),
            name: Some(&ValueName::Named("Licence".into())),
            before: None,
            after: Some(&RegData::Sz(secret.into())),
            outcome: Outcome::Applied,
            detail: None,
        });
        drop(l);

        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            !text.contains(secret),
            "the secret leaked into the log:\n{text}"
        );
        assert!(
            text.contains("<redacted:"),
            "no placeholder recorded: {text}"
        );
        // The key and value name are still there: redaction must not destroy
        // the audit value of the record.
        assert!(text.contains("Licence"), "{text}");
        assert!(verify(&p).unwrap().is_intact());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn redaction_handles_both_flag_spellings_and_leaves_other_tokens_alone() {
        assert_eq!(
            redact_command("regx set K -v N -d hunter2 -y", true),
            format!("regx set K -v N -d {} -y", digest_placeholder("hunter2"))
        );
        assert_eq!(
            redact_command("regx set K --data=hunter2", true),
            format!("regx set K --data={}", digest_placeholder("hunter2"))
        );
        // Without redaction the command is recorded as given.
        assert_eq!(
            redact_command("regx set K -d hunter2", false),
            "regx set K -d hunter2"
        );
        // The same input always yields the same placeholder, so two runs can
        // still be compared.
        assert_eq!(digest_placeholder("x"), digest_placeholder("x"));
        assert_ne!(digest_placeholder("x"), digest_placeholder("y"));
    }

    #[test]
    fn a_dry_run_is_recorded_as_simulated() {
        let p = scratch("dryrun");
        let mut l = Logger::open(&p, false, "regx set --dry-run").unwrap();
        l.record(Event {
            op: Op::ValueSet,
            path: &path(),
            name: Some(&ValueName::Named("x".into())),
            before: None,
            after: Some(&RegData::Dword(1)),
            outcome: Outcome::Simulated,
            detail: None,
        });
        drop(l);
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("\"outcome\": \"simulated\""), "{text}");
        let _ = std::fs::remove_file(&p);
    }
}
