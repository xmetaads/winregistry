//! `Registry.pol` — the Group Policy "PReg" binary format.
//!
//! This is the file a domain controller pushes down and the Group Policy engine
//! replays into the registry. Being able to read it matters for a non-admin
//! tool: the cached copies under `%WINDIR%\System32\GroupPolicy` and
//! `...\GroupPolicyUsers` are readable by ordinary users, so `regx` can show
//! exactly which registry writes a policy performs — and, with Smart
//! Redirection, apply the per-user-meaningful subset without any elevation.
//!
//! # Layout
//!
//! ```text
//! "PReg"  u32 version(=1)          8-byte header, ASCII signature
//! then a sequence of records, each:
//!   '['  key\0  ';'  value\0  ';'  u32 type  ';'  u32 size  ';'  data[size]  ']'
//! ```
//!
//! Every character shown in quotes — the brackets and semicolons — and both
//! strings are UTF-16LE. `size` counts bytes, not characters.
//!
//! # Directives
//!
//! A value name beginning with `**` is an instruction rather than data:
//!
//! | Directive | Meaning |
//! |---|---|
//! | `**del.Name` | delete the value `Name` |
//! | `**delvals.` | delete every value in the key |
//! | `**DeleteValues` | data is a `;`-separated list of values to delete |
//! | `**DeleteKeys` | data is a `;`-separated list of subkeys to delete |
//! | `**soft.Name` | write `Name` only if it does not already exist |
//! | `**SecureKey`, `**ListElement` | ACL / UI hints, no registry effect |

use crate::model::*;
use std::path::Path;

const HEADER: &[u8] = b"PReg";

pub fn read(
    bytes: &[u8],
    root: Hive,
    path: Option<&Path>,
) -> Result<(Vec<KeyBlock>, Vec<String>), String> {
    if bytes.len() < 8 || &bytes[..4] != HEADER {
        return Err("not a Registry.pol file: missing the 'PReg' signature".into());
    }
    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != 1 {
        return Err(format!(
            "unsupported Registry.pol version {version}; only version 1 is defined"
        ));
    }

    // A .pol records no hive: identical bytes mean HKLM under Machine\ and
    // HKCU under User\. Infer from the path when we can, so the common case
    // needs no flag.
    let (root, inferred) = infer_root(root, path);
    let mut notes = Vec::new();
    notes.push(match inferred {
        Some(why) => format!("policy paths rooted at {} ({why})", root.long_name()),
        None => format!(
            "policy paths rooted at {} (a .pol stores no hive; override with --pol-root)",
            root.long_name()
        ),
    });

    let mut p = Cursor { b: bytes, i: 8 };
    let mut blocks: Vec<KeyBlock> = Vec::new();
    let mut record = 0usize;

    while p.i < bytes.len() {
        p.skip_padding();
        if p.i >= bytes.len() {
            break;
        }
        record += 1;

        p.expect('[', record)?;
        let key = p.utf16z(record, "key")?;
        p.expect(';', record)?;
        let name = p.utf16z(record, "value name")?;
        p.expect(';', record)?;
        let ty = p.u32(record, "type")?;
        p.expect(';', record)?;
        let size = p.u32(record, "size")? as usize;
        p.expect(';', record)?;
        let data = p.take(size, record)?;
        p.expect(']', record)?;

        let path = RegPath {
            hive: root,
            sub: key.trim_matches('\\').to_string(),
        };

        apply_record(&mut blocks, path, &name, ty, data, record, &mut notes);
    }

    notes.insert(0, format!("{record} policy record(s)"));
    Ok((blocks, notes))
}

fn infer_root(fallback: Hive, path: Option<&Path>) -> (Hive, Option<&'static str>) {
    let Some(p) = path else {
        return (fallback, None);
    };
    let s = p.to_string_lossy().to_ascii_lowercase().replace('/', "\\");
    if s.contains("\\user\\") || s.contains("grouppolicyusers") {
        return (Hive::Hkcu, Some("path contains a User policy directory"));
    }
    if s.contains("\\machine\\") {
        return (Hive::Hklm, Some("path contains a Machine policy directory"));
    }
    (fallback, None)
}

fn apply_record(
    blocks: &mut Vec<KeyBlock>,
    path: RegPath,
    name: &str,
    ty: u32,
    data: &[u8],
    record: usize,
    notes: &mut Vec<String>,
) {
    // Directives are case-insensitive in practice.
    let lower = name.to_ascii_lowercase();

    if let Some(target) = lower.strip_prefix("**del.") {
        // Preserve the original spelling of the value name.
        let original = &name[name.len() - target.len()..];
        push_value(
            blocks,
            path,
            ValueName::Named(original.to_string()),
            RegData::Delete,
            record,
        );
        return;
    }

    if lower.starts_with("**delvals.") || lower == "**delvals" {
        // Whole-key value wipe. A .reg file has no syntax for "delete every
        // value but keep the key", so record it as a key delete and say so.
        let b = block_for(blocks, path.clone(), record);
        b.delete = true;
        notes.push(format!(
            "record {record}: **delvals on {path} deletes every value; expressed as a key delete, \
             which also removes subkeys"
        ));
        return;
    }

    if lower == "**deletevalues" {
        for v in split_list(data) {
            push_value(
                blocks,
                path.clone(),
                ValueName::Named(v),
                RegData::Delete,
                record,
            );
        }
        return;
    }

    if lower == "**deletekeys" {
        for k in split_list(data) {
            let child = RegPath {
                hive: path.hive,
                sub: if path.sub.is_empty() {
                    k.clone()
                } else {
                    format!("{}\\{}", path.sub, k)
                },
            };
            let b = block_for(blocks, child, record);
            b.delete = true;
        }
        return;
    }

    if let Some(target) = lower.strip_prefix("**soft.") {
        let original = &name[name.len() - target.len()..];
        notes.push(format!(
            "record {record}: **soft.{original} means \"write only if absent\"; \
             applied unconditionally because .reg has no equivalent"
        ));
        push_value(
            blocks,
            path,
            ValueName::Named(original.to_string()),
            decode(ty, data),
            record,
        );
        return;
    }

    if lower.starts_with("**") {
        notes.push(format!(
            "record {record}: ignoring directive {name:?} (no registry effect)"
        ));
        // Still make sure the key itself exists.
        block_for(blocks, path, record);
        return;
    }

    push_value(
        blocks,
        path,
        crate::formats::value_name(name),
        decode(ty, data),
        record,
    );
}

/// Directive payloads are a UTF-16LE, `;`-separated, NUL-terminated list.
fn split_list(data: &[u8]) -> Vec<String> {
    let s = utf16(data);
    s.split(';')
        .map(|x| x.trim_end_matches('\0').trim())
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

fn decode(ty: u32, data: &[u8]) -> RegData {
    match ty {
        REG_DWORD if data.len() == 4 => {
            RegData::Dword(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        }
        REG_SZ => {
            // Prefer the readable form when the payload is well-formed.
            let s = utf16(data);
            if !s.contains('\0') && !s.chars().any(|c| (c as u32) < 0x20) {
                RegData::Sz(s)
            } else {
                RegData::Hex {
                    ty,
                    bytes: data.to_vec(),
                }
            }
        }
        _ => RegData::Hex {
            ty,
            bytes: data.to_vec(),
        },
    }
}

fn utf16(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

fn block_for(blocks: &mut Vec<KeyBlock>, path: RegPath, line: usize) -> &mut KeyBlock {
    let fold = path.fold();
    if let Some(idx) = blocks.iter().position(|b| b.path.fold() == fold) {
        return &mut blocks[idx];
    }
    blocks.push(KeyBlock {
        path,
        delete: false,
        values: Vec::new(),
        line,
    });
    blocks.last_mut().unwrap()
}

fn push_value(
    blocks: &mut Vec<KeyBlock>,
    path: RegPath,
    name: ValueName,
    data: RegData,
    line: usize,
) {
    block_for(blocks, path, line)
        .values
        .push(ValueEntry { name, data, line });
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    /// Some writers pad between records with NUL or CR/LF; skip it rather than
    /// failing on a file that Windows itself accepts.
    fn skip_padding(&mut self) {
        while self.i + 1 < self.b.len() {
            let u = u16::from_le_bytes([self.b[self.i], self.b[self.i + 1]]);
            if u == 0 || u == 0x0d || u == 0x0a || u == 0x20 {
                self.i += 2;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, ch: char, record: usize) -> Result<(), String> {
        if self.i + 2 > self.b.len() {
            return Err(format!(
                "record {record}: file ends where {ch:?} was expected"
            ));
        }
        let got = u16::from_le_bytes([self.b[self.i], self.b[self.i + 1]]);
        if got != ch as u16 {
            return Err(format!(
                "record {record}: expected {ch:?} at byte {}, found U+{got:04X}",
                self.i
            ));
        }
        self.i += 2;
        Ok(())
    }

    fn utf16z(&mut self, record: usize, what: &str) -> Result<String, String> {
        let start = self.i;
        while self.i + 1 < self.b.len() {
            let u = u16::from_le_bytes([self.b[self.i], self.b[self.i + 1]]);
            self.i += 2;
            if u == 0 {
                let units: Vec<u16> = self.b[start..self.i - 2]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                return Ok(String::from_utf16_lossy(&units));
            }
        }
        Err(format!("record {record}: unterminated {what} string"))
    }

    fn u32(&mut self, record: usize, what: &str) -> Result<u32, String> {
        if self.i + 4 > self.b.len() {
            return Err(format!(
                "record {record}: file ends inside the {what} field"
            ));
        }
        let v = u32::from_le_bytes([
            self.b[self.i],
            self.b[self.i + 1],
            self.b[self.i + 2],
            self.b[self.i + 3],
        ]);
        self.i += 4;
        Ok(v)
    }

    fn take(&mut self, n: usize, record: usize) -> Result<&'a [u8], String> {
        if self.i + n > self.b.len() {
            return Err(format!(
                "record {record}: declares {n} bytes of data but only {} remain",
                self.b.len() - self.i
            ));
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u8> {
        let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        v.extend_from_slice(&[0, 0]);
        v
    }

    fn record(key: &str, name: &str, ty: u32, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&('[' as u16).to_le_bytes());
        v.extend_from_slice(&w(key));
        v.extend_from_slice(&(';' as u16).to_le_bytes());
        v.extend_from_slice(&w(name));
        v.extend_from_slice(&(';' as u16).to_le_bytes());
        v.extend_from_slice(&ty.to_le_bytes());
        v.extend_from_slice(&(';' as u16).to_le_bytes());
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(&(';' as u16).to_le_bytes());
        v.extend_from_slice(data);
        v.extend_from_slice(&(']' as u16).to_le_bytes());
        v
    }

    fn pol(records: &[Vec<u8>]) -> Vec<u8> {
        let mut v = b"PReg".to_vec();
        v.extend_from_slice(&1u32.to_le_bytes());
        for r in records {
            v.extend_from_slice(r);
        }
        v
    }

    #[test]
    fn reads_dword_and_string_records() {
        let bytes = pol(&[
            record(
                "Software\\Policies\\Acme",
                "Enabled",
                REG_DWORD,
                &1u32.to_le_bytes(),
            ),
            record(
                "Software\\Policies\\Acme",
                "Server",
                REG_SZ,
                &w("https://acme.test"),
            ),
        ]);
        let (blocks, notes) = read(&bytes, Hive::Hklm, None).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            blocks[0].path.to_string(),
            "HKEY_LOCAL_MACHINE\\Software\\Policies\\Acme"
        );
        assert_eq!(blocks[0].values[0].data, RegData::Dword(1));
        assert_eq!(
            blocks[0].values[1].data,
            RegData::Sz("https://acme.test".into())
        );
        assert!(notes[0].starts_with("2 policy record"));
    }

    #[test]
    fn del_directive_becomes_a_value_delete() {
        let bytes = pol(&[record("Software\\Acme", "**del.Legacy", REG_SZ, &w(" "))]);
        let (blocks, _) = read(&bytes, Hive::Hkcu, None).unwrap();
        assert_eq!(blocks[0].values[0].name, ValueName::Named("Legacy".into()));
        assert_eq!(blocks[0].values[0].data, RegData::Delete);
    }

    #[test]
    fn delete_values_list_expands() {
        let bytes = pol(&[record(
            "Software\\Acme",
            "**DeleteValues",
            REG_SZ,
            &w("A;B;C"),
        )]);
        let (blocks, _) = read(&bytes, Hive::Hkcu, None).unwrap();
        assert_eq!(blocks[0].values.len(), 3);
        assert!(blocks[0].values.iter().all(|v| v.data == RegData::Delete));
    }

    #[test]
    fn delete_keys_list_makes_child_delete_blocks() {
        let bytes = pol(&[record(
            "Software\\Acme",
            "**DeleteKeys",
            REG_SZ,
            &w("Old;Older"),
        )]);
        let (blocks, _) = read(&bytes, Hive::Hkcu, None).unwrap();
        assert_eq!(blocks.len(), 2);
        assert!(blocks.iter().all(|b| b.delete));
        assert_eq!(blocks[0].path.sub, "Software\\Acme\\Old");
    }

    #[test]
    fn root_is_inferred_from_the_policy_directory() {
        let bytes = pol(&[record(
            "Software\\Acme",
            "X",
            REG_DWORD,
            &0u32.to_le_bytes(),
        )]);
        let p = Path::new(r"C:\Windows\System32\GroupPolicy\User\Registry.pol");
        let (blocks, notes) = read(&bytes, Hive::Hklm, Some(p)).unwrap();
        assert_eq!(
            blocks[0].path.hive,
            Hive::Hkcu,
            "User\\ should override the fallback"
        );
        assert!(notes.iter().any(|n| n.contains("User policy directory")));
    }

    #[test]
    fn rejects_bad_signature_and_truncation() {
        assert!(read(b"NOPE\x01\x00\x00\x00", Hive::Hklm, None).is_err());
        let mut bytes = pol(&[record("A", "B", REG_DWORD, &0u32.to_le_bytes())]);
        bytes.truncate(bytes.len() - 6);
        let e = read(&bytes, Hive::Hklm, None).unwrap_err();
        assert!(e.contains("record 1"), "{e}");
    }
}
