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
use crate::sha256::{constant_time_eq, hash_hex, hmac_hex, Sha256};
use std::fs::OpenOptions;
use std::io::{Seek, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    fn GetLastError() -> u32;
}

const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArtifactOp {
    ShortcutCreate,
    ShortcutDelete,
}

impl ArtifactOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::ShortcutCreate => "shortcut.create",
            Self::ShortcutDelete => "shortcut.delete",
        }
    }
}

pub struct ArtifactEvent<'a> {
    pub op: ArtifactOp,
    pub path: &'a Path,
    pub before_sha256: Option<&'a str>,
    pub after_sha256: Option<&'a str>,
    pub outcome: Outcome,
    pub detail: Option<&'a str>,
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

    /// Record a filesystem artifact mutation without placing its contents in
    /// the audit log. Exact before/after SHA-256 values keep the operation
    /// independently verifiable.
    pub fn record_artifact(&mut self, e: ArtifactEvent<'_>) {
        let mut fields = vec![
            ("event".to_string(), jstr(e.op.as_str())),
            ("path".to_string(), jstr(&e.path.display().to_string())),
            ("outcome".to_string(), jstr(e.outcome.as_str())),
        ];
        if let Some(digest) = e.before_sha256 {
            fields.push(("beforeSha256".into(), jstr(digest)));
        }
        if let Some(digest) = e.after_sha256 {
            fields.push(("afterSha256".into(), jstr(digest)));
        }
        if let Some(detail) = e.detail {
            fields.push(("detail".into(), jstr(detail)));
        }
        if let Err(error) = self.write(fields) {
            eprintln!("regx: audit log write failed: {error}");
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

#[derive(Debug)]
pub struct ChainVerification {
    pub files: usize,
    pub records: usize,
    pub sessions: usize,
    pub broken: Vec<(usize, String)>,
}

impl ChainVerification {
    pub fn is_intact(&self) -> bool {
        self.broken.is_empty()
    }
}

#[derive(Debug)]
pub struct Rotation {
    pub archived_records: usize,
    pub archived_hash: String,
    pub archived_sha256: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Anchor {
    pub sha256: String,
    pub tail_hash: String,
    pub records: usize,
}

impl Anchor {
    pub fn matches(&self, other: &Anchor) -> bool {
        self == other
    }
}

impl Verification {
    pub fn is_intact(&self) -> bool {
        self.broken.is_empty()
    }
}

/// Persist a detached checkpoint. Keeping this small, text-only artifact on a
/// different trust boundary (append-only storage, another host, or a signed
/// ticket) makes a coordinated rewrite of the entire local log detectable.
#[cfg(test)]
pub fn write_anchor(log: &Path, destination: &Path) -> std::io::Result<Anchor> {
    write_anchor_with_key(log, destination, None).map(|(anchor, _)| anchor)
}

/// Write an unsigned v1 anchor or an HMAC-authenticated v2 anchor.
pub fn write_anchor_with_key(
    log: &Path,
    destination: &Path,
    key: Option<&[u8]>,
) -> std::io::Result<(Anchor, bool)> {
    if let Some(key) = key {
        validate_anchor_key(key)?;
    }
    if log == destination
        || (destination.exists()
            && std::fs::canonicalize(log).ok() == std::fs::canonicalize(destination).ok())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "audit log and detached anchor must be different files",
        ));
    }
    let before = file_digest(log)?;
    let verification = verify(log)?;
    if !verification.is_intact() || verification.records == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "refusing to anchor an empty or broken audit log",
        ));
    }
    let anchor = current_anchor(log, verification.records)?;
    if anchor.sha256 != before || file_digest(log)? != before {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "audit log changed while its anchor was being created",
        ));
    }
    let (text, signed) = match key {
        None => (
            format!(
                "regx-audit-anchor-v1\nsha256 {}\ntail {}\nrecords {}\n",
                anchor.sha256, anchor.tail_hash, anchor.records
            ),
            false,
        ),
        Some(key) => {
            let authenticated = format!(
                "regx-audit-anchor-v2\nsha256 {}\ntail {}\nrecords {}\nalgorithm hmac-sha256\n",
                anchor.sha256, anchor.tail_hash, anchor.records
            );
            let signature = hmac_hex(key, authenticated.as_bytes());
            (format!("{authenticated}signature {signature}\n"), true)
        }
    };
    crate::file_io::atomic_write(destination, text.as_bytes())?;
    if file_digest(log)? != anchor.sha256 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "audit log changed before its detached anchor was committed",
        ));
    }
    Ok((anchor, signed))
}

#[cfg(test)]
pub fn verify_anchor(log: &Path, anchor_path: &Path) -> std::io::Result<(Anchor, Anchor)> {
    verify_anchor_with_key(log, anchor_path, None).map(|(expected, actual, _)| (expected, actual))
}

/// Verify the anchor authentication before comparing it with the live log.
///
/// Supplying a key for an unsigned anchor is rejected to prevent an attacker
/// from downgrading a signed checkpoint to v1.
pub fn verify_anchor_with_key(
    log: &Path,
    anchor_path: &Path,
    key: Option<&[u8]>,
) -> std::io::Result<(Anchor, Anchor, bool)> {
    if let Some(key) = key {
        validate_anchor_key(key)?;
    }
    let verification = verify(log)?;
    let actual = current_anchor(log, verification.records)?;
    let (expected, signed) = read_anchor(anchor_path, key)?;
    Ok((expected, actual, signed))
}

fn validate_anchor_key(key: &[u8]) -> std::io::Result<()> {
    if !(32..=64 * 1024).contains(&key.len()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "audit anchor key must contain 32 to 65536 raw bytes",
        ));
    }
    Ok(())
}

fn current_anchor(log: &Path, records: usize) -> std::io::Result<Anchor> {
    let tail_hash = last_hash(log).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "audit log has no tail hash",
        )
    })?;
    Ok(Anchor {
        sha256: file_digest(log)?,
        tail_hash,
        records,
    })
}

fn read_anchor(path: &Path, key: Option<&[u8]>) -> std::io::Result<(Anchor, bool)> {
    let text = std::fs::read_to_string(path)?;
    let mut lines = text.lines();
    let header = lines.next();
    if header != Some("regx-audit-anchor-v1") && header != Some("regx-audit-anchor-v2") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported audit anchor header",
        ));
    }
    let sha256 = anchor_field(lines.next(), "sha256")?;
    let tail_hash = anchor_field(lines.next(), "tail")?;
    let records = anchor_field(lines.next(), "records")?
        .parse::<usize>()
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid anchor record count",
            )
        })?;
    let signed = header == Some("regx-audit-anchor-v2");
    if signed {
        if anchor_field(lines.next(), "algorithm")? != "hmac-sha256" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported audit anchor authentication algorithm",
            ));
        }
        let signature = anchor_field(lines.next(), "signature")?;
        if signature.len() != 64 || !signature.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed audit anchor signature",
            ));
        }
        let key = key.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "signed audit anchor requires an authentication key",
            )
        })?;
        let authenticated = format!(
            "regx-audit-anchor-v2\nsha256 {sha256}\ntail {tail_hash}\nrecords {records}\nalgorithm hmac-sha256\n"
        );
        let expected_signature = hmac_hex(key, authenticated.as_bytes());
        if !constant_time_eq(signature.as_bytes(), expected_signature.as_bytes()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "audit anchor signature does not match the supplied key",
            ));
        }
    } else if key.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "refusing unsigned audit anchor while an authentication key is required",
        ));
    }
    if lines.any(|line| !line.trim().is_empty())
        || sha256.len() != 64
        || tail_hash.len() != 64
        || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !tail_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed audit anchor",
        ));
    }
    Ok((
        Anchor {
            sha256,
            tail_hash,
            records,
        },
        signed,
    ))
}

fn anchor_field(line: Option<&str>, name: &str) -> std::io::Result<String> {
    line.and_then(|line| line.strip_prefix(name))
        .and_then(|value| value.strip_prefix(' '))
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("audit anchor is missing {name}"),
            )
        })
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

/// Verify independently hashed segments and the marker linking each segment to
/// the exact bytes and tail record of its predecessor.
pub fn verify_chain(paths: &[PathBuf]) -> std::io::Result<ChainVerification> {
    let mut result = ChainVerification {
        files: paths.len(),
        records: 0,
        sessions: 0,
        broken: Vec::new(),
    };
    if paths.is_empty() {
        result
            .broken
            .push((0, "audit chain contains no files".into()));
        return Ok(result);
    }

    let mut previous_tail: Option<String> = None;
    let mut previous_digest: Option<String> = None;
    for (index, path) in paths.iter().enumerate() {
        let verification = verify(path)?;
        result.records += verification.records;
        result.sessions += verification.sessions;
        for (line, problem) in verification.broken {
            result
                .broken
                .push((index, format!("{} line {line}: {problem}", path.display())));
        }

        if index > 0 {
            let first = first_body(path)?;
            let expected_tail = previous_tail.as_deref().unwrap_or("");
            let expected_digest = previous_digest.as_deref().unwrap_or("");
            if field(&first, "event") != Some("segment.start") {
                result.broken.push((
                    index,
                    format!("{} does not begin with segment.start", path.display()),
                ));
            }
            if field(&first, "previousHash") != Some(expected_tail) {
                result.broken.push((
                    index,
                    format!(
                        "{} does not link to the previous segment tail",
                        path.display()
                    ),
                ));
            }
            if field(&first, "previousSha256") != Some(expected_digest) {
                result.broken.push((
                    index,
                    format!(
                        "{} does not bind the previous segment bytes",
                        path.display()
                    ),
                ));
            }
        }
        previous_tail = last_hash(path);
        previous_digest = Some(file_digest(path)?);
    }
    Ok(result)
}

/// Archive an intact active log and replace it with a genesis segment marker
/// that cryptographically binds the archived bytes and tail record.
pub fn rotate(active: &Path, archive: &Path) -> std::io::Result<Rotation> {
    if archive.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} already exists", archive.display()),
        ));
    }
    let mut source = std::fs::File::open(active)?;
    let verification = verify(active)?;
    if !verification.is_intact() || verification.records == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "refusing to rotate an empty or broken audit log",
        ));
    }
    let before = file_digest(active)?;
    let tail = last_hash(active).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "audit log has no tail hash",
        )
    })?;

    source.seek(std::io::SeekFrom::Start(0))?;
    let mut destination = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(archive)?;
    if let Err(error) = std::io::copy(&mut source, &mut destination) {
        drop(destination);
        let _ = std::fs::remove_file(archive);
        return Err(error);
    }
    if let Err(error) = destination.sync_all() {
        drop(destination);
        let _ = std::fs::remove_file(archive);
        return Err(error);
    }
    drop(destination);
    let archived_digest = file_digest(archive)?;
    let after = file_digest(active)?;
    if archived_digest != before || after != before {
        let _ = std::fs::remove_file(archive);
        return Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "active audit log changed while it was being rotated",
        ));
    }

    let marker = segment_start_line(&tail, &archived_digest);
    replace_active_segment(active, marker.as_bytes())?;
    Ok(Rotation {
        archived_records: verification.records,
        archived_hash: tail,
        archived_sha256: archived_digest,
    })
}

fn replace_active_segment(active: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let stem = active
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("audit");
    let temp = active.with_file_name(format!(
        ".{stem}.rotate-{}-{}.tmp",
        std::process::id(),
        now_iso8601().replace([':', '-'], "")
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    drop(file);
    let old = wide_path(active);
    let new = wide_path(&temp);
    // SAFETY: both paths are NUL-terminated and remain alive for the call.
    let ok = unsafe {
        MoveFileExW(
            new.as_ptr(),
            old.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        // Some managed sandboxes and hardened volumes deny replace semantics
        // even though the existing file is writable. The archive is already
        // durably synced, so an in-place rewrite cannot lose the old segment;
        // it only forfeits atomic visibility of the new marker.
        if code == 5 {
            let result = std::fs::write(active, bytes);
            let _ = std::fs::remove_file(&temp);
            return result;
        }
        let _ = std::fs::remove_file(&temp);
        return Err(std::io::Error::from_raw_os_error(code as i32));
    }
    Ok(())
}

fn wide_path(path: &Path) -> Vec<u16> {
    let mut value = path.as_os_str().encode_wide().collect::<Vec<_>>();
    value.push(0);
    value
}

fn first_body(path: &Path) -> std::io::Result<String> {
    let text = std::fs::read_to_string(path)?;
    let first = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "empty segment"))?;
    let (body, _) = split_hash(first.trim()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "first segment record has no hash",
        )
    })?;
    Ok(body.to_string())
}

fn segment_start_line(previous_hash: &str, previous_sha256: &str) -> String {
    let session = hash_hex(format!("rotate|{}|{}", now_iso8601(), std::process::id()).as_bytes())
        [..16]
        .to_string();
    let fields = [
        ("ts", jstr(&now_iso8601())),
        ("session", jstr(&session)),
        ("seq", "1".into()),
        ("event", jstr("segment.start")),
        ("previousHash", jstr(previous_hash)),
        ("previousSha256", jstr(previous_sha256)),
        ("prev", jstr("genesis")),
    ];
    let body = fields
        .iter()
        .map(|(key, value)| format!("{}: {value}", jstr(key)))
        .collect::<Vec<_>>()
        .join(", ");
    let hash = hash_hex(body.as_bytes());
    format!("{{{body}, \"hash\": {}}}\n", jstr(&hash))
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
        if token == "-d" || token == "--data" || token == "--args" {
            out.push(token.to_string());
            elide_next = true;
            continue;
        }
        if let Some(v) = token
            .strip_prefix("--data=")
            .or_else(|| token.strip_prefix("-d="))
            .or_else(|| token.strip_prefix("--args="))
        {
            let flag = if token.starts_with("--args") {
                "--args"
            } else if token.starts_with("--") {
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

pub fn last_hash(path: &Path) -> Option<String> {
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
    fn detached_anchor_detects_a_complete_valid_rewrite() {
        let p = scratch("anchor-log");
        let anchor_path = scratch("anchor-checkpoint");
        let mut logger = Logger::open(&p, true, "regx set ...").unwrap();
        logger.record(Event {
            op: Op::ValueSet,
            path: &path(),
            name: Some(&ValueName::Named("Channel".into())),
            before: None,
            after: Some(&RegData::Sz("stable".into())),
            outcome: Outcome::Applied,
            detail: None,
        });
        drop(logger);

        let original = std::fs::read(&p).unwrap();
        assert_eq!(
            write_anchor(&p, &p).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(std::fs::read(&p).unwrap(), original);

        let written = write_anchor(&p, &anchor_path).unwrap();
        let (expected, actual) = verify_anchor(&p, &anchor_path).unwrap();
        assert_eq!(written, expected);
        assert!(expected.matches(&actual));

        // Append a perfectly valid new session. The internal chain remains
        // intact, but the detached checkpoint must no longer match.
        drop(Logger::open(&p, true, "regx delete ...").unwrap());
        assert!(verify(&p).unwrap().is_intact());
        let (expected, actual) = verify_anchor(&p, &anchor_path).unwrap();
        assert!(!expected.matches(&actual));

        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&anchor_path);
    }

    #[test]
    fn signed_anchor_rejects_wrong_key_tampering_and_downgrade() {
        let log = scratch("signed-anchor-log");
        let signed_path = scratch("signed-anchor-checkpoint");
        let unsigned_path = scratch("unsigned-anchor-checkpoint");
        let mut logger = Logger::open(&log, true, "regx set ...").unwrap();
        logger.record(Event {
            op: Op::ValueSet,
            path: &path(),
            name: Some(&ValueName::Named("Channel".into())),
            before: None,
            after: Some(&RegData::Sz("stable".into())),
            outcome: Outcome::Applied,
            detail: None,
        });
        drop(logger);
        let key = [0x41u8; 32];
        let wrong = [0x42u8; 32];

        let (_, signed) = write_anchor_with_key(&log, &signed_path, Some(&key)).unwrap();
        assert!(signed);
        assert!(
            verify_anchor_with_key(&log, &signed_path, Some(&key))
                .unwrap()
                .2
        );
        assert!(verify_anchor_with_key(&log, &signed_path, Some(&wrong))
            .unwrap_err()
            .to_string()
            .contains("signature does not match"));
        assert!(verify_anchor_with_key(&log, &signed_path, None)
            .unwrap_err()
            .to_string()
            .contains("requires an authentication key"));

        let text = std::fs::read_to_string(&signed_path).unwrap();
        std::fs::write(&signed_path, text.replace("sha256 ", "sha256 0")).unwrap();
        assert!(verify_anchor_with_key(&log, &signed_path, Some(&key)).is_err());

        write_anchor(&log, &unsigned_path).unwrap();
        assert!(verify_anchor_with_key(&log, &unsigned_path, Some(&key))
            .unwrap_err()
            .to_string()
            .contains("refusing unsigned"));
        let _ = std::fs::remove_file(log);
        let _ = std::fs::remove_file(signed_path);
        let _ = std::fs::remove_file(unsigned_path);
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
    fn rotated_segments_preserve_a_verifiable_cross_file_chain() {
        let active = scratch("rotate-active");
        let archive = scratch("rotate-archive");
        let mut first = Logger::open(&active, false, "first").unwrap();
        first.record(Event {
            op: Op::KeyCreate,
            path: &path(),
            name: None,
            before: None,
            after: None,
            outcome: Outcome::Applied,
            detail: None,
        });
        drop(first);

        let rotation = rotate(&active, &archive).unwrap();
        assert_eq!(rotation.archived_records, 2);
        let mut second = Logger::open(&active, false, "second").unwrap();
        second.record(Event {
            op: Op::KeyDelete,
            path: &path(),
            name: None,
            before: None,
            after: None,
            outcome: Outcome::Applied,
            detail: None,
        });
        drop(second);

        let files = vec![archive.clone(), active.clone()];
        let chain = verify_chain(&files).unwrap();
        assert!(chain.is_intact(), "{:?}", chain.broken);
        assert_eq!(chain.files, 2);
        assert_eq!(chain.records, 5);

        let reversed = verify_chain(&[active.clone(), archive.clone()]).unwrap();
        assert!(!reversed.is_intact(), "segment reordering must be detected");
        let _ = std::fs::remove_file(active);
        let _ = std::fs::remove_file(archive);
    }

    #[test]
    fn rotated_chain_detects_an_edited_archive() {
        let active = scratch("rotate-edit-active");
        let archive = scratch("rotate-edit-archive");
        let mut logger = Logger::open(&active, false, "first").unwrap();
        logger.record(Event {
            op: Op::ValueSet,
            path: &path(),
            name: Some(&ValueName::Named("Mode".into())),
            before: None,
            after: Some(&RegData::Sz("before".into())),
            outcome: Outcome::Applied,
            detail: None,
        });
        drop(logger);
        rotate(&active, &archive).unwrap();

        let text = std::fs::read_to_string(&archive).unwrap();
        std::fs::write(&archive, text.replace("before", "after")).unwrap();
        let chain = verify_chain(&[archive.clone(), active.clone()]).unwrap();
        assert!(!chain.is_intact());
        assert!(
            chain
                .broken
                .iter()
                .any(|(_, problem)| problem.contains("does not match")),
            "{:?}",
            chain.broken
        );
        let _ = std::fs::remove_file(active);
        let _ = std::fs::remove_file(archive);
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
        let shortcut = redact_command("regx lnk create --args secret-token --output a.lnk", true);
        assert!(!shortcut.contains("secret-token"));
        assert!(shortcut.contains("--args <redacted:"));
        let shortcut_equals = redact_command("regx lnk create --args=secret-token", true);
        assert!(!shortcut_equals.contains("secret-token"));
        assert!(shortcut_equals.contains("--args=<redacted:"));
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
