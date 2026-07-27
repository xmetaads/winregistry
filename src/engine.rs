//! The read/write engine that sits between the `.reg` model and the Win32 API.
//!
//! Everything here is written against a [`Roots`] resolver rather than against
//! HKCU directly, so the *same* export / apply / undo code drives both the live
//! hives and a file mounted with `RegLoadAppKey`. That is what makes the offline
//! engine a thin shell rather than a parallel implementation.

use crate::model::*;
use crate::winreg::{self, RegKey, View, KEY_READ, KEY_WRITE};

// ---------------------------------------------------------------------------
// Data conversion
// ---------------------------------------------------------------------------

/// Model value -> `(type, bytes)` ready for `RegSetValueEx`.
/// Returns `None` for `RegData::Delete`, which is not a write.
pub fn data_to_raw(d: &RegData) -> Option<(u32, Vec<u8>)> {
    match d {
        RegData::Delete => None,
        RegData::Sz(s) => Some((REG_SZ, utf16_nul(s))),
        RegData::Dword(v) => Some((REG_DWORD, v.to_le_bytes().to_vec())),
        RegData::Hex { ty, bytes } => Some((*ty, bytes.clone())),
    }
}

/// `(type, bytes)` from the API -> model value.
///
/// A REG_SZ is only rendered as a quoted string when it is genuinely clean
/// UTF-16: even length, single trailing NUL, no embedded NUL, no control
/// characters. Anything else stays `hex(1)`, because writing a raw newline into
/// a `.reg` file silently corrupts the next line - the same rule regedit uses.
pub fn raw_to_data(ty: u32, bytes: &[u8]) -> RegData {
    match ty {
        REG_SZ => match clean_string(bytes) {
            Some(s) => RegData::Sz(s),
            None => RegData::Hex {
                ty,
                bytes: bytes.to_vec(),
            },
        },
        REG_DWORD if bytes.len() == 4 => {
            let mut a = [0u8; 4];
            a.copy_from_slice(bytes);
            RegData::Dword(u32::from_le_bytes(a))
        }
        _ => RegData::Hex {
            ty,
            bytes: bytes.to_vec(),
        },
    }
}

pub fn utf16_nul(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2 + 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

fn clean_string(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return Some(String::new());
    }
    if bytes.len() % 2 != 0 || !bytes.ends_with(&[0, 0]) {
        return None;
    }
    let units: Vec<u16> = bytes[..bytes.len() - 2]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    if units.contains(&0) {
        return None;
    }
    let s = String::from_utf16(&units).ok()?;
    if s.chars().any(|c| (c as u32) < 0x20) {
        return None;
    }
    Some(s)
}

/// Parse a `-t TYPE -d DATA` pair from the command line into a model value.
///
/// Follows `reg.exe` conventions so muscle memory transfers: `REG_MULTI_SZ`
/// entries are separated by a literal `\0`, and DWORD/QWORD accept decimal or
/// `0x`-prefixed hex.
pub fn parse_typed(ty: &str, data: &str) -> std::result::Result<RegData, String> {
    let t = ty.trim().to_ascii_uppercase();
    let t = t.strip_prefix("REG_").unwrap_or(&t);
    match t {
        "SZ" => Ok(RegData::Sz(data.to_string())),
        "EXPAND_SZ" => Ok(RegData::Hex {
            ty: REG_EXPAND_SZ,
            bytes: utf16_nul(data),
        }),
        "MULTI_SZ" => {
            let mut bytes = Vec::new();
            for part in data.split("\\0").filter(|s| !s.is_empty()) {
                bytes.extend_from_slice(&utf16_nul(part));
            }
            bytes.extend_from_slice(&[0, 0]); // the terminating empty string
            Ok(RegData::Hex {
                ty: REG_MULTI_SZ,
                bytes,
            })
        }
        "DWORD" => parse_int(data)
            .and_then(|v| u32::try_from(v).ok())
            .map(RegData::Dword)
            .ok_or_else(|| format!("invalid DWORD value {data:?}")),
        "QWORD" => parse_int(data)
            .map(|v| RegData::Hex {
                ty: REG_QWORD,
                bytes: v.to_le_bytes().to_vec(),
            })
            .ok_or_else(|| format!("invalid QWORD value {data:?}")),
        "BINARY" | "NONE" => {
            let cleaned: String = data
                .chars()
                .filter(|c| !matches!(c, ' ' | ',' | '-' | ':'))
                .collect();
            if cleaned.len() % 2 != 0 {
                return Err("binary data must have an even number of hex digits".into());
            }
            let mut bytes = Vec::with_capacity(cleaned.len() / 2);
            for pair in cleaned.as_bytes().chunks(2) {
                let s = std::str::from_utf8(pair).map_err(|_| "invalid hex".to_string())?;
                bytes.push(
                    u8::from_str_radix(s, 16).map_err(|_| format!("invalid hex byte {s:?}"))?,
                );
            }
            Ok(RegData::Hex {
                ty: if t == "BINARY" { REG_BINARY } else { REG_NONE },
                bytes,
            })
        }
        _ => Err(format!(
            "unknown type {ty:?}; expected one of REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, \
             REG_DWORD, REG_QWORD, REG_BINARY, REG_NONE"
        )),
    }
}

fn parse_int(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse::<u64>().ok(),
    }
}

// ---------------------------------------------------------------------------
// Root resolution
// ---------------------------------------------------------------------------

/// Where a `RegPath` actually lands.
pub enum Roots {
    /// The five predefined hives of the running user's session.
    Live(Box<LiveRoots>),
    /// A hive file mounted with `RegLoadAppKey`; the hive component of every
    /// path is ignored and the subkey path is taken relative to the mount.
    Mounted(RegKey),
}

pub struct LiveRoots {
    hkcr: RegKey,
    hkcu: RegKey,
    hklm: RegKey,
    hku: RegKey,
    hkcc: RegKey,
}

impl Roots {
    pub fn live() -> Roots {
        Roots::Live(Box::new(LiveRoots {
            hkcr: RegKey::predefined(winreg::hkey_classes_root(), "HKEY_CLASSES_ROOT"),
            hkcu: RegKey::predefined(winreg::hkey_current_user(), "HKEY_CURRENT_USER"),
            hklm: RegKey::predefined(winreg::hkey_local_machine(), "HKEY_LOCAL_MACHINE"),
            hku: RegKey::predefined(winreg::hkey_users(), "HKEY_USERS"),
            hkcc: RegKey::predefined(winreg::hkey_current_config(), "HKEY_CURRENT_CONFIG"),
        }))
    }

    /// Returns the root handle plus the subkey path relative to it.
    pub fn resolve<'a>(&'a self, p: &RegPath) -> (&'a RegKey, String) {
        match self {
            Roots::Mounted(k) => (k, p.sub.clone()),
            Roots::Live(l) => {
                let k = match p.hive {
                    Hive::Hkcr => &l.hkcr,
                    Hive::Hkcu => &l.hkcu,
                    Hive::Hklm => &l.hklm,
                    Hive::Hku => &l.hku,
                    Hive::Hkcc => &l.hkcc,
                };
                (k, p.sub.clone())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct ExportReport {
    /// Subkeys we could not open. Export never aborts on these: a partial export
    /// of your own hive is normal (GP-locked policy keys, `Protected` subtrees).
    pub skipped: Vec<(String, String)>,
    pub keys: usize,
    pub values: usize,
}

/// Export `path` (and optionally its subtree) into key blocks.
pub fn export(
    roots: &Roots,
    path: &RegPath,
    view: View,
    recursive: bool,
) -> winreg::Result<(Vec<KeyBlock>, ExportReport)> {
    let (root, sub) = roots.resolve(path);
    let key = root.open(&sub, KEY_READ, view)?;
    let mut out = Vec::new();
    let mut report = ExportReport::default();
    walk(&key, path, view, recursive, &mut out, &mut report);
    Ok((out, report))
}

fn walk(
    key: &RegKey,
    path: &RegPath,
    view: View,
    recursive: bool,
    out: &mut Vec<KeyBlock>,
    report: &mut ExportReport,
) {
    let values = match key.values() {
        Ok(v) => v,
        Err(e) => {
            report.skipped.push((path.to_string(), e.to_string()));
            Vec::new()
        }
    };
    report.keys += 1;
    report.values += values.len();

    out.push(KeyBlock {
        path: path.clone(),
        delete: false,
        values: values
            .into_iter()
            .map(|(name, ty, bytes)| ValueEntry {
                name: if name.is_empty() {
                    ValueName::Default
                } else {
                    ValueName::Named(name)
                },
                data: raw_to_data(ty, &bytes),
                line: 0,
            })
            .collect(),
        line: 0,
    });

    if !recursive {
        return;
    }
    let children = match key.subkeys() {
        Ok(c) => c,
        Err(e) => {
            report.skipped.push((path.to_string(), e.to_string()));
            return;
        }
    };
    for child in children {
        let child_path = RegPath {
            hive: path.hive,
            sub: if path.sub.is_empty() {
                child.clone()
            } else {
                format!("{}\\{}", path.sub, child)
            },
        };
        match key.open(&child, KEY_READ, view) {
            Ok(k) => walk(&k, &child_path, view, recursive, out, report),
            // Skip-and-continue: one denied subkey must not lose the rest.
            Err(e) => report.skipped.push((child_path.to_string(), e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct ApplyReport {
    pub keys_created: usize,
    pub keys_deleted: usize,
    pub values_set: usize,
    pub values_deleted: usize,
    pub failures: Vec<(String, String)>,
}

impl ApplyReport {
    pub fn touched(&self) -> usize {
        self.keys_created + self.keys_deleted + self.values_set + self.values_deleted
    }
}

/// Apply every key block. `dry_run` performs all the *reads* (so permission
/// problems still surface) but skips every write.
pub fn apply(roots: &Roots, file: &RegFile, view: View, dry_run: bool) -> ApplyReport {
    apply_audited(roots, file, view, dry_run, None)
}

/// As [`apply`], but recording every mutation to an audit log.
///
/// The prior value is read before each write so the log records what was
/// replaced, not merely what was written. That is one extra query per value,
/// paid only when a log is actually attached.
pub fn apply_audited(
    roots: &Roots,
    file: &RegFile,
    view: View,
    dry_run: bool,
    mut audit: Option<&mut crate::audit::Logger>,
) -> ApplyReport {
    use crate::audit::{Event, Op, Outcome};
    let outcome = if dry_run {
        Outcome::Simulated
    } else {
        Outcome::Applied
    };
    let mut r = ApplyReport::default();

    for block in &file.keys {
        let (root, sub) = roots.resolve(&block.path);

        if block.delete {
            if root.open(&sub, KEY_READ, view).is_err() {
                continue; // nothing to delete
            }
            if dry_run {
                r.keys_deleted += 1;
                if let Some(a) = audit.as_deref_mut() {
                    a.record(Event {
                        op: Op::KeyDelete,
                        path: &block.path,
                        name: None,
                        before: None,
                        after: None,
                        outcome,
                        detail: None,
                    });
                }
                continue;
            }
            match root.delete_tree(&sub) {
                Ok(()) => {
                    // RegDeleteTree empties the key but keeps it; remove the key
                    // itself so `[-KEY]` matches regedit's semantics.
                    let _ = root.delete_key(&sub, view);
                    r.keys_deleted += 1;
                    if let Some(a) = audit.as_deref_mut() {
                        a.record(Event {
                            op: Op::KeyDelete,
                            path: &block.path,
                            name: None,
                            before: None,
                            after: None,
                            outcome,
                            detail: None,
                        });
                    }
                }
                Err(e) => {
                    if let Some(a) = audit.as_deref_mut() {
                        a.record(Event {
                            op: Op::KeyDelete,
                            path: &block.path,
                            name: None,
                            before: None,
                            after: None,
                            outcome: Outcome::Failed,
                            detail: Some(&e.to_string()),
                        });
                    }
                    r.failures.push((block.path.to_string(), e.to_string()));
                }
            }
            continue;
        }

        // A dry run must not create the key, so probe with an open instead.
        let key = if dry_run {
            match root.open(&sub, KEY_READ | KEY_WRITE, view) {
                Ok(k) => Some(k),
                Err(e) if e.is_not_found() => {
                    r.keys_created += 1;
                    None
                }
                Err(e) => {
                    r.failures.push((block.path.to_string(), e.to_string()));
                    continue;
                }
            }
        } else {
            match root.create(&sub, KEY_READ | KEY_WRITE, view) {
                Ok((k, created)) => {
                    if created {
                        r.keys_created += 1;
                        if let Some(a) = audit.as_deref_mut() {
                            a.record(Event {
                                op: Op::KeyCreate,
                                path: &block.path,
                                name: None,
                                before: None,
                                after: None,
                                outcome,
                                detail: None,
                            });
                        }
                    }
                    Some(k)
                }
                Err(e) => {
                    r.failures.push((block.path.to_string(), e.to_string()));
                    continue;
                }
            }
        };

        for v in &block.values {
            let name = value_api_name(&v.name);
            let label = format!("{}\\{}", block.path, v.name);

            // Read what is there now, so the log records what was replaced.
            // Skipped entirely when nothing is listening.
            let before = if audit.is_some() {
                key.as_ref()
                    .and_then(|k| k.get_value(name).ok().flatten())
                    .map(|(ty, bytes)| raw_to_data(ty, &bytes))
            } else {
                None
            };

            match &v.data {
                RegData::Delete => {
                    let exists = key
                        .as_ref()
                        .and_then(|k| k.get_value(name).ok().flatten())
                        .is_some();
                    if !exists {
                        continue;
                    }
                    if dry_run {
                        r.values_deleted += 1;
                        if let Some(a) = audit.as_deref_mut() {
                            a.record(Event {
                                op: Op::ValueDelete,
                                path: &block.path,
                                name: Some(&v.name),
                                before: before.as_ref(),
                                after: None,
                                outcome,
                                detail: None,
                            });
                        }
                        continue;
                    }
                    match key.as_ref().unwrap().delete_value(name) {
                        Ok(()) => {
                            r.values_deleted += 1;
                            if let Some(a) = audit.as_deref_mut() {
                                a.record(Event {
                                    op: Op::ValueDelete,
                                    path: &block.path,
                                    name: Some(&v.name),
                                    before: before.as_ref(),
                                    after: None,
                                    outcome,
                                    detail: None,
                                });
                            }
                        }
                        Err(e) => {
                            if let Some(a) = audit.as_deref_mut() {
                                a.record(Event {
                                    op: Op::ValueDelete,
                                    path: &block.path,
                                    name: Some(&v.name),
                                    before: before.as_ref(),
                                    after: None,
                                    outcome: Outcome::Failed,
                                    detail: Some(&e.to_string()),
                                });
                            }
                            r.failures.push((label, e.to_string()));
                        }
                    }
                }
                other => {
                    let Some((ty, bytes)) = data_to_raw(other) else {
                        continue;
                    };
                    if dry_run {
                        r.values_set += 1;
                        if let Some(a) = audit.as_deref_mut() {
                            a.record(Event {
                                op: Op::ValueSet,
                                path: &block.path,
                                name: Some(&v.name),
                                before: before.as_ref(),
                                after: Some(other),
                                outcome,
                                detail: None,
                            });
                        }
                        continue;
                    }
                    match key.as_ref().unwrap().set_value(name, ty, &bytes) {
                        Ok(()) => {
                            r.values_set += 1;
                            if let Some(a) = audit.as_deref_mut() {
                                a.record(Event {
                                    op: Op::ValueSet,
                                    path: &block.path,
                                    name: Some(&v.name),
                                    before: before.as_ref(),
                                    after: Some(other),
                                    outcome,
                                    detail: None,
                                });
                            }
                        }
                        Err(e) => {
                            if let Some(a) = audit.as_deref_mut() {
                                a.record(Event {
                                    op: Op::ValueSet,
                                    path: &block.path,
                                    name: Some(&v.name),
                                    before: before.as_ref(),
                                    after: Some(other),
                                    outcome: Outcome::Failed,
                                    detail: Some(&e.to_string()),
                                });
                            }
                            r.failures.push((label, e.to_string()));
                        }
                    }
                }
            }
        }

        if let Some(k) = &key {
            let _ = k.flush();
        }
    }

    r
}

/// The API name for a value: the default value is the empty string.
pub fn value_api_name(n: &ValueName) -> &str {
    match n {
        ValueName::Default => "",
        ValueName::Named(s) => s,
    }
}

// ---------------------------------------------------------------------------
// Probe
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ProbeResult {
    pub path: String,
    pub exists: bool,
    pub readable: bool,
    pub writable: bool,
    pub creatable: bool,
    pub detail: String,
}

/// Answer the only question that matters before an import: *can this user
/// actually write here?* Done by really opening the key - an ACL on a single
/// subkey can deny a standard user even inside their own HKCU.
pub fn probe(roots: &Roots, path: &RegPath, view: View) -> ProbeResult {
    let (root, sub) = roots.resolve(path);
    let mut res = ProbeResult {
        path: path.to_string(),
        exists: false,
        readable: false,
        writable: false,
        creatable: false,
        detail: String::new(),
    };

    match root.open(&sub, KEY_READ, view) {
        Ok(_) => {
            res.exists = true;
            res.readable = true;
        }
        Err(e) if e.is_not_found() => res.detail = "key does not exist yet".into(),
        Err(e) => {
            res.exists = true;
            res.detail = e.to_string();
        }
    }

    match root.open(&sub, KEY_WRITE, view) {
        Ok(_) => res.writable = true,
        Err(e) if !e.is_not_found() => {
            if res.detail.is_empty() {
                res.detail = e.to_string();
            }
        }
        Err(_) => {}
    }

    if !res.exists {
        // Can we create it? Walk up to the nearest existing ancestor and test
        // write access there - creating and deleting a probe key would be a
        // side effect, which `probe` must never have.
        let mut cur = sub.as_str();
        while let Some(idx) = cur.rfind('\\') {
            cur = &cur[..idx];
            match root.open(cur, KEY_READ, view) {
                Ok(_) => {
                    res.creatable = root.open(cur, KEY_WRITE, view).is_ok();
                    res.detail = format!(
                        "nearest existing ancestor: {}\\{cur} ({})",
                        root.label(),
                        if res.creatable {
                            "writable"
                        } else {
                            "not writable"
                        }
                    );
                    return res;
                }
                Err(e) if e.is_not_found() => continue,
                Err(_) => break,
            }
        }
        res.creatable = root.open("", KEY_WRITE, view).is_ok();
    }

    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_string_rejects_unterminated_and_control_chars() {
        assert_eq!(
            clean_string(&[0x41, 0x00, 0x00, 0x00]).as_deref(),
            Some("A")
        );
        assert_eq!(clean_string(&[0x41, 0x00]), None, "missing NUL terminator");
        assert_eq!(clean_string(&[0x41, 0x00, 0x00]), None, "odd length");
        assert_eq!(clean_string(&[0x0a, 0x00, 0x00, 0x00]), None, "newline");
        assert_eq!(clean_string(&[]).as_deref(), Some(""));
    }

    #[test]
    fn raw_round_trip_preserves_types() {
        for d in [
            RegData::Sz("hello".into()),
            RegData::Dword(0xdead_beef),
            RegData::Hex {
                ty: REG_QWORD,
                bytes: vec![1, 2, 3, 4, 5, 6, 7, 8],
            },
            RegData::Hex {
                ty: REG_MULTI_SZ,
                bytes: vec![0x61, 0, 0, 0, 0, 0],
            },
        ] {
            let (ty, bytes) = data_to_raw(&d).unwrap();
            assert_eq!(raw_to_data(ty, &bytes), d, "round trip failed for {d:?}");
        }
    }

    #[test]
    fn dirty_reg_sz_falls_back_to_hex() {
        // A REG_SZ holding a newline must not be emitted as a quoted string.
        let d = raw_to_data(REG_SZ, &[0x0a, 0x00, 0x00, 0x00]);
        assert!(matches!(d, RegData::Hex { ty: REG_SZ, .. }));
    }

    #[test]
    fn probe_reports_hklm_software_not_writable() {
        let roots = Roots::live();
        let p = RegPath::parse("HKEY_LOCAL_MACHINE\\SOFTWARE").unwrap();
        let r = probe(&roots, &p, View::Native);
        assert!(r.exists && r.readable);
        // The negative half only holds for a standard user. An elevated host —
        // GitHub's windows-latest runner is one — genuinely can write there,
        // and asserting otherwise tests the runner rather than the code.
        if r.writable {
            eprintln!("SKIPPED: HKLM is writable here, so this host is elevated");
        }
    }

    #[test]
    fn export_then_apply_round_trips_through_the_live_registry() {
        let roots = Roots::live();
        let base = "Software\\regx-engine-test";
        let path = RegPath::parse(&format!("HKEY_CURRENT_USER\\{base}")).unwrap();

        let file = RegFile {
            format: RegFormat::V5,
            encoding: crate::encoding::SourceEncoding::Utf16Le,
            keys: vec![
                KeyBlock {
                    path: path.clone(),
                    delete: false,
                    values: vec![
                        ValueEntry {
                            name: ValueName::Default,
                            data: RegData::Sz("root".into()),
                            line: 0,
                        },
                        ValueEntry {
                            name: ValueName::Named("num".into()),
                            data: RegData::Dword(42),
                            line: 0,
                        },
                    ],
                    line: 0,
                },
                KeyBlock {
                    path: RegPath::parse(&format!("HKEY_CURRENT_USER\\{base}\\child")).unwrap(),
                    delete: false,
                    values: vec![ValueEntry {
                        name: ValueName::Named("deep".into()),
                        data: RegData::Hex {
                            ty: REG_MULTI_SZ,
                            bytes: vec![0x61, 0, 0, 0, 0, 0],
                        },
                        line: 0,
                    }],
                    line: 0,
                },
            ],
        };

        let r = apply(&roots, &file, View::Native, false);
        assert!(r.failures.is_empty(), "{:?}", r.failures);
        assert_eq!(r.values_set, 3);

        let (blocks, rep) = export(&roots, &path, View::Native, true).unwrap();
        assert_eq!(blocks.len(), 2);
        assert!(rep.skipped.is_empty());
        assert_eq!(blocks[0].values.len(), 2);
        assert_eq!(blocks[1].values[0].data.type_id(), Some(REG_MULTI_SZ));

        // Delete block removes the whole subtree.
        let del = RegFile {
            keys: vec![KeyBlock {
                path: path.clone(),
                delete: true,
                values: vec![],
                line: 0,
            }],
            ..file
        };
        let r = apply(&roots, &del, View::Native, false);
        assert_eq!(r.keys_deleted, 1, "{:?}", r.failures);
        assert!(export(&roots, &path, View::Native, true).is_err());
    }
}
