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
use std::collections::HashMap;
use std::path::Path;

const HEADER: &[u8] = b"PReg";

/// Serialize registry data as a version-1 `Registry.pol`.
///
/// A policy file carries no hive field, so every block must belong to one
/// HKCU/HKLM root. Constructs the format cannot express exactly are rejected
/// rather than widened into a more destructive operation.
pub fn write(file: &RegFile) -> Result<(Vec<u8>, Hive), String> {
    let root = file
        .keys
        .first()
        .map(|block| block.path.hive)
        .ok_or_else(|| "cannot write an empty Registry.pol".to_string())?;
    if !matches!(root, Hive::Hkcu | Hive::Hklm) {
        return Err(format!(
            "Registry.pol supports only HKCU or HKLM, not {}",
            root.long_name()
        ));
    }
    let mut out = Vec::from(HEADER);
    out.extend_from_slice(&1u32.to_le_bytes());
    for block in &file.keys {
        if block.path.hive != root {
            return Err(format!(
                "Registry.pol has one implicit root; found both {} and {}",
                root.long_name(),
                block.path.hive.long_name()
            ));
        }
        if block.path.sub.is_empty() {
            return Err("Registry.pol cannot address its implicit root as a record key".into());
        }
        validate_pol_key(&block.path.sub)?;
        if block.delete {
            let (parent, child) = block
                .path
                .sub
                .rsplit_once('\\')
                .unwrap_or(("", block.path.sub.as_str()));
            if parent.is_empty() || child.is_empty() {
                return Err(
                    "Registry.pol cannot encode deletion of a top-level key exactly".into(),
                );
            }
            let mut data = utf16_bytes(child, true);
            write_record(&mut out, parent, "**DeleteKeys", REG_SZ, &mut data)?;
            continue;
        }
        if block.values.is_empty() {
            write_record(&mut out, &block.path.sub, "", REG_NONE, &mut Vec::new())?;
            continue;
        }
        for value in &block.values {
            let name = match &value.name {
                ValueName::Default => {
                    return Err(format!(
                        "Registry.pol does not define default-value mutation at {}",
                        block.path
                    ));
                }
                ValueName::Named(name) => name,
            };
            validate_pol_value_name(name)?;
            let (record_name, ty, mut data) = match &value.data {
                RegData::Delete => {
                    if format!("**del.{name}").len() > 259 {
                        return Err(format!(
                            "Registry.pol cannot encode deletion of value {name:?} within the 259-character directive limit"
                        ));
                    }
                    (format!("**del.{name}"), REG_SZ, utf16_bytes(" ", true))
                }
                RegData::Sz(text) => {
                    if text.contains('\0') {
                        return Err(format!(
                            "{} contains a NUL that Registry.pol cannot encode as REG_SZ",
                            block.path
                        ));
                    }
                    (name.to_string(), REG_SZ, utf16_bytes(text, true))
                }
                RegData::Dword(number) => {
                    (name.to_string(), REG_DWORD, number.to_le_bytes().to_vec())
                }
                RegData::Hex { ty, bytes } => {
                    if !matches!(
                        *ty,
                        REG_SZ
                            | REG_EXPAND_SZ
                            | REG_BINARY
                            | REG_DWORD
                            | REG_DWORD_BIG_ENDIAN
                            | REG_MULTI_SZ
                            | REG_QWORD
                    ) {
                        return Err(format!(
                            "Registry.pol does not define registry type {ty} at {}",
                            block.path
                        ));
                    }
                    (name.to_string(), *ty, bytes.clone())
                }
            };
            write_record(&mut out, &block.path.sub, &record_name, ty, &mut data)?;
        }
    }
    Ok((out, root))
}

fn validate_pol_key(key: &str) -> Result<(), String> {
    if key.split('\\').any(|component| {
        component.is_empty()
            || !component
                .chars()
                .all(|ch| matches!(ch as u32, 0x20..=0x5b | 0x5d..=0x7e))
    }) {
        return Err(format!(
            "Registry.pol key path {key:?} is outside the ASCII MS-GPREG grammar"
        ));
    }
    Ok(())
}

fn validate_pol_value_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 259
        || !name.chars().all(|ch| matches!(ch as u32, 0x20..=0x7e))
    {
        return Err(format!(
            "Registry.pol value name {name:?} must be 1-259 printable ASCII characters"
        ));
    }
    if name.starts_with("**") {
        return Err(format!(
            "Registry.pol value name {name:?} collides with a policy directive"
        ));
    }
    Ok(())
}

fn write_record(
    out: &mut Vec<u8>,
    key: &str,
    name: &str,
    ty: u32,
    data: &mut Vec<u8>,
) -> Result<(), String> {
    if data.len() > u16::MAX as usize {
        return Err(format!(
            "Registry.pol record data is {} bytes; MS-GPREG limits it to 65535",
            data.len()
        ));
    }
    let size = data.len() as u32;
    push_char(out, '[');
    push_utf16z(out, key);
    push_char(out, ';');
    push_utf16z(out, name);
    push_char(out, ';');
    out.extend_from_slice(&ty.to_le_bytes());
    push_char(out, ';');
    out.extend_from_slice(&size.to_le_bytes());
    push_char(out, ';');
    out.append(data);
    push_char(out, ']');
    Ok(())
}

fn push_char(out: &mut Vec<u8>, ch: char) {
    out.extend_from_slice(&(ch as u16).to_le_bytes());
}

fn push_utf16z(out: &mut Vec<u8>, text: &str) {
    out.extend(utf16_bytes(text, true));
}

fn utf16_bytes(text: &str, nul: bool) -> Vec<u8> {
    text.encode_utf16()
        .chain(nul.then_some(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

pub fn read(bytes: &[u8], root: Hive, path: Option<&Path>) -> Result<super::ReaderResult, String> {
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
    let mut losses = Vec::new();
    notes.push(match inferred {
        Some(why) => format!("policy paths rooted at {} ({why})", root.long_name()),
        None => format!(
            "policy paths rooted at {} (a .pol stores no hive; override with --pol-root)",
            root.long_name()
        ),
    });

    let mut p = Cursor { b: bytes, i: 8 };
    let mut blocks = BlockBuilder::default();
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

        // Microsoft's key-only form leaves value, type, size, and data empty.
        // It must not become a synthetic default REG_NONE value.
        if name.is_empty() && ty == REG_NONE && data.is_empty() {
            blocks.block_for(path, record);
            continue;
        }

        apply_record(&mut blocks, path, &name, ty, data, record, &mut losses);
    }

    notes.insert(0, format!("{record} policy record(s)"));
    Ok((blocks.blocks, notes, losses))
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
    blocks: &mut BlockBuilder,
    path: RegPath,
    name: &str,
    ty: u32,
    data: &[u8],
    record: usize,
    losses: &mut Vec<String>,
) {
    // Directives are case-insensitive in practice.
    let lower = name.to_ascii_lowercase();

    if let Some(target) = lower.strip_prefix("**del.") {
        // Preserve the original spelling of the value name.
        let original = &name[name.len() - target.len()..];
        push_value(
            blocks,
            path,
            crate::formats::value_name(original),
            RegData::Delete,
            record,
        );
        return;
    }

    if lower.starts_with("**delvals.") || lower == "**delvals" {
        // A key delete would be wider and more destructive: it also removes
        // subkeys. Keep the key visible for inspection, omit the unrepresentable
        // mutation, and let every write/convert caller fail closed on `losses`.
        blocks.block_for(path.clone(), record);
        losses.push(format!(
            "record {record}: **delvals on {path} deletes every value while preserving subkeys"
        ));
        return;
    }

    if lower == "**deletevalues" {
        let Some(items) = split_list(data) else {
            losses.push(format!(
                "record {record}: **DeleteValues on {path} has a malformed UTF-16LE payload"
            ));
            return;
        };
        for v in items {
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
        let Some(items) = split_list(data) else {
            losses.push(format!(
                "record {record}: **DeleteKeys on {path} has a malformed UTF-16LE payload"
            ));
            return;
        };
        for k in items {
            let child = RegPath {
                hive: path.hive,
                sub: if path.sub.is_empty() {
                    k.clone()
                } else {
                    format!("{}\\{}", path.sub, k)
                },
            };
            let b = blocks.block_for(child, record);
            b.delete = true;
        }
        return;
    }

    if let Some(target) = lower.strip_prefix("**soft.") {
        let original = &name[name.len() - target.len()..];
        blocks.block_for(path.clone(), record);
        losses.push(format!(
            "record {record}: **soft.{original} on {path} writes only when the value is absent"
        ));
        return;
    }

    if lower.starts_with("**") {
        losses.push(format!(
            "record {record}: directive {name:?} on {path} is not representable"
        ));
        blocks.block_for(path, record);
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
fn split_list(data: &[u8]) -> Option<Vec<String>> {
    if !data.len().is_multiple_of(2) {
        return None;
    }
    let units = data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let s = String::from_utf16(&units).ok()?;
    let s = s.trim_end_matches('\0');
    Some(
        s.split(';')
            .filter(|x| !x.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

fn decode(ty: u32, data: &[u8]) -> RegData {
    match ty {
        REG_DWORD if data.len() == 4 => {
            RegData::Dword(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        }
        REG_SZ => {
            // Prefer the readable form only when every input byte is represented.
            // Malformed UTF-16 or data hidden after a terminator must remain raw.
            if let Some(s) = utf16_string(data) {
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

fn utf16_string(data: &[u8]) -> Option<String> {
    if !data.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let content = match units.split_last() {
        Some((0, content)) => content,
        _ => units.as_slice(),
    };
    if content.contains(&0) {
        return None;
    }
    let text = String::from_utf16(content).ok()?;
    (!text.chars().any(|character| (character as u32) < 0x20)).then_some(text)
}

#[derive(Default)]
struct BlockBuilder {
    blocks: Vec<KeyBlock>,
    index: HashMap<String, usize>,
}

impl BlockBuilder {
    fn block_for(&mut self, path: RegPath, line: usize) -> &mut KeyBlock {
        let fold = path.fold();
        let index = match self.index.get(&fold) {
            Some(index) => *index,
            None => {
                let index = self.blocks.len();
                self.blocks.push(KeyBlock {
                    path,
                    delete: false,
                    values: Vec::new(),
                    line,
                });
                self.index.insert(fold, index);
                index
            }
        };
        &mut self.blocks[index]
    }
}

fn push_value(
    blocks: &mut BlockBuilder,
    path: RegPath,
    name: ValueName,
    data: RegData,
    line: usize,
) {
    blocks
        .block_for(path, line)
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
                return String::from_utf16(&units)
                    .map_err(|_| format!("record {record}: {what} contains malformed UTF-16"));
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
        let (blocks, notes, losses) = read(&bytes, Hive::Hklm, None).unwrap();
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
        assert!(losses.is_empty());
    }

    #[test]
    fn conditional_or_wider_directives_are_reported_without_widening() {
        let bytes = pol(&[
            record("Software\\Policies\\Acme", "**delvals.", REG_SZ, &w(" ")),
            record(
                "Software\\Policies\\Acme",
                "**soft.Existing",
                REG_DWORD,
                &1u32.to_le_bytes(),
            ),
            record(
                "Software\\Policies\\Acme",
                "**SecureKey",
                REG_DWORD,
                &1u32.to_le_bytes(),
            ),
        ]);
        let (blocks, _, losses) = read(&bytes, Hive::Hklm, None).unwrap();
        assert_eq!(blocks.len(), 1);
        assert!(!blocks[0].delete);
        assert!(blocks[0].values.is_empty());
        assert_eq!(losses.len(), 3);
        assert!(losses[0].contains("preserving subkeys"));
        assert!(losses[1].contains("only when the value is absent"));
        assert!(losses[2].contains("not representable"));
    }

    #[test]
    fn writer_round_trips_values_deletes_and_raw_types() {
        let file = RegFile {
            format: RegFormat::V5,
            encoding: crate::encoding::SourceEncoding::Utf8,
            keys: vec![
                KeyBlock {
                    path: RegPath {
                        hive: Hive::Hkcu,
                        sub: "Software\\Policies\\Acme".into(),
                    },
                    delete: false,
                    values: vec![
                        ValueEntry {
                            name: ValueName::Named("Gone".into()),
                            data: RegData::Delete,
                            line: 1,
                        },
                        ValueEntry {
                            name: ValueName::Named("Server".into()),
                            data: RegData::Sz("https://例.example".into()),
                            line: 2,
                        },
                        ValueEntry {
                            name: ValueName::Named("Enabled".into()),
                            data: RegData::Dword(1),
                            line: 3,
                        },
                        ValueEntry {
                            name: ValueName::Named("Raw".into()),
                            data: RegData::Hex {
                                ty: REG_BINARY,
                                bytes: vec![0, 1, 2, 255],
                            },
                            line: 4,
                        },
                    ],
                    line: 1,
                },
                KeyBlock {
                    path: RegPath {
                        hive: Hive::Hkcu,
                        sub: "Software\\Policies\\Acme\\Obsolete".into(),
                    },
                    delete: true,
                    values: Vec::new(),
                    line: 5,
                },
            ],
        };
        let (bytes, root) = write(&file).unwrap();
        assert_eq!(root, Hive::Hkcu);
        let (blocks, _, losses) = read(&bytes, root, None).unwrap();
        assert!(losses.is_empty());
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].values.len(), 4);
        assert_eq!(blocks[0].values[0].name, ValueName::Named("Gone".into()));
        assert_eq!(blocks[0].values[0].data, RegData::Delete);
        assert_eq!(
            blocks[0].values[1].data,
            RegData::Sz("https://例.example".into())
        );
        assert_eq!(blocks[0].values[2].data, RegData::Dword(1));
        assert_eq!(
            blocks[0].values[3].data,
            RegData::Hex {
                ty: REG_BINARY,
                bytes: vec![0, 1, 2, 255]
            }
        );
        assert!(blocks[1].delete);
        assert_eq!(blocks[1].path.sub, "Software\\Policies\\Acme\\Obsolete");
    }

    #[test]
    fn writer_refuses_states_the_format_cannot_represent_exactly() {
        let block = |hive, sub: &str, delete| KeyBlock {
            path: RegPath {
                hive,
                sub: sub.into(),
            },
            delete,
            values: Vec::new(),
            line: 1,
        };
        let file = |keys| RegFile {
            format: RegFormat::V5,
            encoding: crate::encoding::SourceEncoding::Utf8,
            keys,
        };
        let (empty, _) = write(&file(vec![block(Hive::Hkcu, "Software\\Empty", false)])).unwrap();
        let (empty_blocks, _, losses) = read(&empty, Hive::Hkcu, None).unwrap();
        assert!(losses.is_empty());
        assert_eq!(empty_blocks.len(), 1);
        assert!(empty_blocks[0].values.is_empty());
        assert!(write(&file(vec![block(Hive::Hkcu, "", true)]))
            .unwrap_err()
            .contains("implicit root"));
        assert!(write(&file(vec![
            block(Hive::Hkcu, "Software\\A", true),
            block(Hive::Hklm, "Software\\B", true),
        ]))
        .unwrap_err()
        .contains("one implicit root"));
        let unsupported = RegFile {
            format: RegFormat::V5,
            encoding: crate::encoding::SourceEncoding::Utf8,
            keys: vec![KeyBlock {
                path: RegPath {
                    hive: Hive::Hkcu,
                    sub: "Software\\A".into(),
                },
                delete: false,
                values: vec![ValueEntry {
                    name: ValueName::Named("Custom".into()),
                    data: RegData::Hex {
                        ty: 0x1234,
                        bytes: vec![1],
                    },
                    line: 1,
                }],
                line: 1,
            }],
        };
        assert!(write(&unsupported)
            .unwrap_err()
            .contains("does not define registry type"));
        let oversized = RegFile {
            format: RegFormat::V5,
            encoding: crate::encoding::SourceEncoding::Utf8,
            keys: vec![KeyBlock {
                path: RegPath {
                    hive: Hive::Hkcu,
                    sub: "Software\\A".into(),
                },
                delete: false,
                values: vec![ValueEntry {
                    name: ValueName::Named("Large".into()),
                    data: RegData::Hex {
                        ty: REG_BINARY,
                        bytes: vec![0; u16::MAX as usize + 1],
                    },
                    line: 1,
                }],
                line: 1,
            }],
        };
        assert!(write(&oversized).unwrap_err().contains("65535"));

        let invalid_key = file(vec![block(Hive::Hkcu, "Software\\Café", false)]);
        assert!(write(&invalid_key).unwrap_err().contains("ASCII MS-GPREG"));
        let top_level_delete = file(vec![block(Hive::Hkcu, "Software", true)]);
        assert!(write(&top_level_delete)
            .unwrap_err()
            .contains("top-level key"));

        let invalid_name = RegFile {
            format: RegFormat::V5,
            encoding: crate::encoding::SourceEncoding::Utf8,
            keys: vec![KeyBlock {
                path: RegPath {
                    hive: Hive::Hkcu,
                    sub: "Software\\A".into(),
                },
                delete: false,
                values: vec![ValueEntry {
                    name: ValueName::Named("Café".into()),
                    data: RegData::Dword(1),
                    line: 1,
                }],
                line: 1,
            }],
        };
        assert!(write(&invalid_name)
            .unwrap_err()
            .contains("printable ASCII"));
    }

    #[test]
    fn writer_uses_the_windows_delete_directive_payload() {
        let file = RegFile {
            format: RegFormat::V5,
            encoding: crate::encoding::SourceEncoding::Utf8,
            keys: vec![KeyBlock {
                path: RegPath {
                    hive: Hive::Hkcu,
                    sub: "Software\\Policies\\Acme".into(),
                },
                delete: false,
                values: vec![ValueEntry {
                    name: ValueName::Named("Gone".into()),
                    data: RegData::Delete,
                    line: 1,
                }],
                line: 1,
            }],
        };
        let (bytes, _) = write(&file).unwrap();
        assert_eq!(
            bytes,
            pol(&[record(
                "Software\\Policies\\Acme",
                "**del.Gone",
                REG_SZ,
                &w(" ")
            )])
        );
    }

    #[test]
    fn malformed_or_hidden_string_bytes_remain_lossless_hex() {
        let payloads = [
            vec![0x41],
            vec![0x00, 0xd8, 0x00, 0x00],
            vec![0x41, 0x00, 0x00, 0x00, 0x42, 0x00],
        ];
        let records = payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| {
                record(
                    "Software\\Policies\\Acme",
                    &format!("Raw{index}"),
                    REG_SZ,
                    payload,
                )
            })
            .collect::<Vec<_>>();
        let (blocks, _, _) = read(&pol(&records), Hive::Hklm, None).unwrap();

        for (entry, payload) in blocks[0].values.iter().zip(payloads) {
            assert_eq!(
                entry.data,
                RegData::Hex {
                    ty: REG_SZ,
                    bytes: payload
                }
            );
        }
    }

    #[test]
    fn malformed_utf16_in_policy_names_is_rejected_not_replaced() {
        let mut item = record(
            "Software\\Policies\\Acme",
            "Enabled",
            REG_DWORD,
            &1u32.to_le_bytes(),
        );
        // The first key-name code unit follows the opening '[' code unit.
        item[2..4].copy_from_slice(&0xd800u16.to_le_bytes());
        let error = read(&pol(&[item]), Hive::Hklm, None).unwrap_err();
        assert!(error.contains("record 1: key contains malformed UTF-16"));
        assert!(!error.contains('\u{fffd}'));
    }

    #[test]
    fn thousands_of_distinct_policy_keys_keep_their_order_and_values() {
        let records: Vec<Vec<u8>> = (0..5_000)
            .map(|index| {
                record(
                    &format!("Software\\Policies\\Bench\\K{index:06}"),
                    "Enabled",
                    REG_DWORD,
                    &(index as u32).to_le_bytes(),
                )
            })
            .collect();
        let (blocks, _, _) = read(&pol(&records), Hive::Hklm, None).unwrap();
        assert_eq!(blocks.len(), records.len());
        assert_eq!(blocks[0].path.sub, "Software\\Policies\\Bench\\K000000");
        assert_eq!(
            blocks.last().unwrap().path.sub,
            "Software\\Policies\\Bench\\K004999"
        );
        assert_eq!(blocks.last().unwrap().values.len(), 1);
    }

    #[test]
    fn del_directive_becomes_a_value_delete() {
        let bytes = pol(&[record("Software\\Acme", "**del.Legacy", REG_SZ, &w(" "))]);
        let (blocks, _, _) = read(&bytes, Hive::Hkcu, None).unwrap();
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
        let (blocks, _, _) = read(&bytes, Hive::Hkcu, None).unwrap();
        assert_eq!(blocks[0].values.len(), 3);
        assert!(blocks[0].values.iter().all(|v| v.data == RegData::Delete));
    }

    #[test]
    fn delete_lists_preserve_spaces_and_malformed_lists_are_losses() {
        let bytes = pol(&[record(
            "Software\\Acme",
            "**DeleteValues",
            REG_SZ,
            &w(" Leading;Trailing ; Both "),
        )]);
        let (blocks, _, losses) = read(&bytes, Hive::Hkcu, None).unwrap();
        let names = blocks[0]
            .values
            .iter()
            .map(|value| match &value.name {
                ValueName::Named(name) => name.as_str(),
                ValueName::Default => "@",
            })
            .collect::<Vec<_>>();
        assert_eq!(names, [" Leading", "Trailing ", " Both "]);
        assert!(losses.is_empty());

        let malformed = pol(&[record("Software\\Acme", "**DeleteKeys", REG_SZ, &[0x00])]);
        let (blocks, _, losses) = read(&malformed, Hive::Hkcu, None).unwrap();
        assert!(blocks.is_empty());
        assert_eq!(losses.len(), 1);
        assert!(losses[0].contains("malformed UTF-16LE"));
    }

    #[test]
    fn delete_keys_list_makes_child_delete_blocks() {
        let bytes = pol(&[record(
            "Software\\Acme",
            "**DeleteKeys",
            REG_SZ,
            &w("Old;Older"),
        )]);
        let (blocks, _, _) = read(&bytes, Hive::Hkcu, None).unwrap();
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
        let (blocks, notes, _) = read(&bytes, Hive::Hklm, Some(p)).unwrap();
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
