//! Setup information (`.inf`) files — the `[AddReg]` and `[DelReg]` sections.
//!
//! INF is how Windows itself has installed registry settings since NT: driver
//! packages, `rundll32 setupapi,InstallHinfSection`, and a great many "run this
//! to fix X" downloads. The registry lines are plain text, so they can be read
//! and redirected without any of the privilege the actual installer would need.
//!
//! ```text
//! [Version]
//! Signature = "$WINDOWS NT$"
//!
//! [DefaultInstall]
//! AddReg = Acme.Add
//! DelReg = Acme.Del
//!
//! [Acme.Add]
//! HKCU,"Software\Acme","Server",0x00000000,"%SERVER%"
//! HKCU,"Software\Acme","Port",0x00010001,8080
//!
//! [Strings]
//! SERVER = "acme.test"
//! ```
//!
//! The flags field is a bitmask; the type lives in bits 16-17 plus bit 0.

use crate::model::*;
use std::collections::HashMap;

// FLG_ADDREG_TYPE_* from setupapi.
const TYPE_MASK: u32 = 0xFFFF_0001;
const T_SZ: u32 = 0x0000_0000;
const T_BINARY: u32 = 0x0000_0001;
const T_MULTI_SZ: u32 = 0x0001_0000;
const T_DWORD: u32 = 0x0001_0001;
const T_EXPAND_SZ: u32 = 0x0002_0000;
const T_NONE: u32 = 0x0002_0001;
const T_QWORD: u32 = 0x0003_0000;

const FLG_DELREG_VALUE: u32 = 0x0000_0004;

pub fn read(
    bytes: &[u8],
    only_section: Option<&str>,
) -> Result<(Vec<KeyBlock>, Vec<String>), String> {
    let (text, _) = crate::encoding::decode(bytes);
    let sections = split_sections(&text);
    let mut notes = Vec::new();

    let strings = sections
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("Strings"))
        .map(|(_, lines)| parse_strings(lines))
        .unwrap_or_default();

    // Collect the section names referenced by AddReg=/DelReg= directives.
    let mut add: Vec<String> = Vec::new();
    let mut del: Vec<String> = Vec::new();
    for (_, lines) in &sections {
        for (_, line) in lines {
            let Some((lhs, rhs)) = line.split_once('=') else {
                continue;
            };
            let key = lhs.trim();
            let targets = rhs
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            if key.eq_ignore_ascii_case("AddReg") {
                add.extend(targets);
            } else if key.eq_ignore_ascii_case("DelReg") {
                del.extend(targets);
            }
        }
    }

    // A hand-written INF fragment often has no [DefaultInstall]; fall back to
    // any section that literally looks like a register list.
    if add.is_empty() && del.is_empty() {
        for (name, _) in &sections {
            let l = name.to_ascii_lowercase();
            if l.contains("addreg") {
                add.push(name.clone());
            } else if l.contains("delreg") {
                del.push(name.clone());
            }
        }
        if !add.is_empty() || !del.is_empty() {
            notes.push(
                "no AddReg=/DelReg= directive found; used sections named *AddReg*/*DelReg*".into(),
            );
        }
    }

    if let Some(want) = only_section {
        add.retain(|s| s.eq_ignore_ascii_case(want));
        del.retain(|s| s.eq_ignore_ascii_case(want));
        if add.is_empty() && del.is_empty() {
            return Err(format!(
                "no AddReg/DelReg section named {want:?} in this INF"
            ));
        }
    }

    if add.is_empty() && del.is_empty() {
        return Err("this INF contains no [AddReg] or [DelReg] section".into());
    }

    let find = |want: &str| -> Option<&Vec<(usize, String)>> {
        sections
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(want))
            .map(|(_, l)| l)
    };

    let mut blocks: Vec<KeyBlock> = Vec::new();
    let mut used = Vec::new();

    for name in &add {
        let Some(lines) = find(name) else {
            notes.push(format!(
                "AddReg references [{name}], which this file does not define"
            ));
            continue;
        };
        used.push(name.clone());
        for (no, line) in lines {
            match add_line(line, &strings) {
                Ok(Some((path, Some(entry)))) => push(&mut blocks, path, entry, *no),
                // Key-only line: creating the block is the whole effect.
                Ok(Some((path, None))) => {
                    block_for(&mut blocks, path, *no);
                }
                Ok(None) => {}
                Err(e) => notes.push(format!("[{name}] line {no}: {e}")),
            }
        }
    }

    for name in &del {
        let Some(lines) = find(name) else {
            notes.push(format!(
                "DelReg references [{name}], which this file does not define"
            ));
            continue;
        };
        used.push(name.clone());
        for (no, line) in lines {
            match del_line(line, &strings) {
                Ok(Some((path, Some(entry)))) => push(&mut blocks, path, entry, *no),
                Ok(Some((path, None))) => {
                    let b = block_for(&mut blocks, path, *no);
                    b.delete = true;
                }
                Ok(None) => {}
                Err(e) => notes.push(format!("[{name}] line {no}: {e}")),
            }
        }
    }

    notes.insert(0, format!("sections read: {}", used.join(", ")));
    if !strings.is_empty() {
        notes.push(format!("{} [Strings] token(s) substituted", strings.len()));
    }
    Ok((blocks, notes))
}

/// `root, subkey, value, flags, data...`
///
/// A returned `None` entry means the line only names a key, which AddReg treats
/// as "create it"; the key block alone expresses that.
fn add_line(
    line: &str,
    strings: &HashMap<String, String>,
) -> Result<Option<(RegPath, Option<ValueEntry>)>, String> {
    let f = fields(line);
    if f.is_empty() {
        return Ok(None);
    }
    if f.len() < 2 {
        return Err(format!("expected at least root,subkey — got {line:?}"));
    }

    let hive = root(&f[0])?;
    let sub = expand(&f[1], strings);
    let path = RegPath {
        hive,
        sub: sub.trim_matches('\\').to_string(),
    };

    if f.len() < 3 || f[2..].iter().all(|x| x.is_empty()) {
        return Ok(Some((path, None)));
    }

    let name = crate::formats::value_name(&expand(&f[2], strings));
    let flags = if f.len() > 3 {
        number(&f[3]).unwrap_or(0) as u32
    } else {
        0
    };
    let raw: Vec<String> = f[4..].iter().map(|x| expand(x, strings)).collect();

    let data = match flags & TYPE_MASK {
        T_SZ => RegData::Sz(raw.join(",")),
        T_EXPAND_SZ => RegData::Hex {
            ty: REG_EXPAND_SZ,
            bytes: crate::engine::utf16_nul(&raw.join(",")),
        },
        T_MULTI_SZ => {
            let mut bytes = Vec::new();
            for s in raw.iter().filter(|s| !s.is_empty()) {
                bytes.extend_from_slice(&crate::engine::utf16_nul(s));
            }
            bytes.extend_from_slice(&[0, 0]);
            RegData::Hex {
                ty: REG_MULTI_SZ,
                bytes,
            }
        }
        T_DWORD => {
            let v = raw
                .first()
                .and_then(|s| number(s))
                .ok_or_else(|| format!("invalid DWORD data {:?}", raw.join(",")))?;
            RegData::Dword(v as u32)
        }
        T_QWORD => {
            let v = raw
                .first()
                .and_then(|s| number(s))
                .ok_or_else(|| format!("invalid QWORD data {:?}", raw.join(",")))?;
            RegData::Hex {
                ty: REG_QWORD,
                bytes: v.to_le_bytes().to_vec(),
            }
        }
        T_BINARY | T_NONE => {
            let mut bytes = Vec::with_capacity(raw.len());
            for tok in raw.iter().filter(|t| !t.is_empty()) {
                bytes.push(
                    u8::from_str_radix(tok.trim().trim_start_matches("0x"), 16)
                        .map_err(|_| format!("invalid binary byte {tok:?}"))?,
                );
            }
            let ty = if flags & TYPE_MASK == T_NONE {
                REG_NONE
            } else {
                REG_BINARY
            };
            RegData::Hex { ty, bytes }
        }
        other => return Err(format!("unsupported AddReg type flag 0x{other:08x}")),
    };

    Ok(Some((
        path,
        Some(ValueEntry {
            name,
            data,
            line: 0,
        }),
    )))
}

/// `root, subkey [, value [, flags]]` — no value name deletes the whole key.
fn del_line(
    line: &str,
    strings: &HashMap<String, String>,
) -> Result<Option<(RegPath, Option<ValueEntry>)>, String> {
    let f = fields(line);
    if f.is_empty() {
        return Ok(None);
    }
    if f.len() < 2 {
        return Err(format!("expected at least root,subkey — got {line:?}"));
    }
    let path = RegPath {
        hive: root(&f[0])?,
        sub: expand(&f[1], strings).trim_matches('\\').to_string(),
    };

    let has_value = f.len() > 2 && !f[2].is_empty();
    let flags = if f.len() > 3 {
        number(&f[3]).unwrap_or(0) as u32
    } else {
        0
    };

    if has_value || flags & FLG_DELREG_VALUE != 0 {
        let name = crate::formats::value_name(&expand(&f[2], strings));
        return Ok(Some((
            path,
            Some(ValueEntry {
                name,
                data: RegData::Delete,
                line: 0,
            }),
        )));
    }
    Ok(Some((path, None)))
}

fn root(s: &str) -> Result<Hive, String> {
    match s.trim().to_ascii_uppercase().as_str() {
        "HKCR" | "HKEY_CLASSES_ROOT" => Ok(Hive::Hkcr),
        "HKCU" | "HKEY_CURRENT_USER" => Ok(Hive::Hkcu),
        "HKLM" | "HKEY_LOCAL_MACHINE" => Ok(Hive::Hklm),
        "HKU" | "HKEY_USERS" => Ok(Hive::Hku),
        // HKR is relative to the driver's own INF install context, which only
        // exists inside SetupAPI. Guessing a path would be worse than skipping.
        "HKR" => Err("HKR is relative to a driver install context and has no fixed path".into()),
        other => Err(format!("unknown INF root {other:?}")),
    }
}

/// Split an INF line on commas, honouring double quotes. `""` is an escaped quote.
fn fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur).trim().to_string()),
            ';' if !quoted => break, // trailing comment
            _ => cur.push(c),
        }
    }
    out.push(cur.trim().to_string());
    while out.last().map(|s| s.is_empty()).unwrap_or(false) && out.len() > 2 {
        out.pop();
    }
    if out.iter().all(|s| s.is_empty()) {
        return Vec::new();
    }
    out
}

/// Replace `%Token%` from the `[Strings]` section. `%%` is a literal percent.
fn expand(s: &str, strings: &HashMap<String, String>) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(tail) = after.strip_prefix('%') {
            out.push('%');
            rest = tail;
            continue;
        }
        match after.find('%') {
            Some(end) => {
                let token = &after[..end];
                match strings.get(&token.to_ascii_lowercase()) {
                    Some(v) => out.push_str(v),
                    // Unknown token: keep it verbatim rather than silently
                    // producing an empty string an installer never intended.
                    None => {
                        out.push('%');
                        out.push_str(token);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push('%');
                out.push_str(after);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn parse_strings(lines: &[(usize, String)]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for (_, line) in lines {
        if let Some((k, v)) = line.split_once('=') {
            m.insert(
                k.trim().to_ascii_lowercase(),
                v.trim().trim_matches('"').to_string(),
            );
        }
    }
    m
}

fn number(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s.strip_suffix(&['h', 'H'][..]).unwrap_or(s);
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok().or_else(|| u64::from_str_radix(s, 16).ok()),
    }
}

/// `[Name]` headers to their non-empty, non-comment lines, with line numbers.
fn split_sections(text: &str) -> Vec<(String, Vec<(usize, String)>)> {
    let mut out: Vec<(String, Vec<(usize, String)>)> = Vec::new();
    for (i, raw) in text.split('\n').enumerate() {
        let line = raw.trim_end_matches('\r').trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            if let Some(end) = line.rfind(']') {
                out.push((line[1..end].trim().to_string(), Vec::new()));
                continue;
            }
        }
        if let Some(last) = out.last_mut() {
            last.1.push((i + 1, line.to_string()));
        }
    }
    out
}

fn block_for(blocks: &mut Vec<KeyBlock>, path: RegPath, line: usize) -> &mut KeyBlock {
    let fold = path.fold();
    if let Some(i) = blocks.iter().position(|b| b.path.fold() == fold) {
        return &mut blocks[i];
    }
    blocks.push(KeyBlock {
        path,
        delete: false,
        values: Vec::new(),
        line,
    });
    blocks.last_mut().unwrap()
}

fn push(blocks: &mut Vec<KeyBlock>, path: RegPath, mut entry: ValueEntry, line: usize) {
    entry.line = line;
    block_for(blocks, path, line).values.push(entry);
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[Version]
Signature = "$WINDOWS NT$"

[DefaultInstall]
AddReg = Acme.Add
DelReg = Acme.Del

[Acme.Add]
HKCU,"Software\Acme","Server",0x00000000,"%SERVER%"
HKCU,"Software\Acme","Port",0x00010001,8080
HKCU,"Software\Acme","Path",0x00020000,"%%SystemRoot%%\acme"
HKCU,"Software\Acme","List",0x00010000,"a","b"
HKLM,"Software\Acme","Blob",0x00000001,01,02,ff

[Acme.Del]
HKCU,"Software\Acme","Legacy"
HKCU,"Software\AcmeOld"

[Strings]
SERVER = "acme.test"
"#;

    #[test]
    fn reads_every_addreg_type() {
        let (blocks, notes) = read(SAMPLE.as_bytes(), None).unwrap();
        let hkcu = blocks
            .iter()
            .find(|b| b.path.sub == "Software\\Acme" && b.path.hive == Hive::Hkcu)
            .unwrap();

        let get = |n: &str| {
            hkcu.values
                .iter()
                .find(|v| matches!(&v.name, ValueName::Named(x) if x == n))
                .unwrap()
        };
        assert_eq!(
            get("Server").data,
            RegData::Sz("acme.test".into()),
            "[Strings] token"
        );
        assert_eq!(get("Port").data, RegData::Dword(8080));
        assert_eq!(get("Path").data.type_id(), Some(REG_EXPAND_SZ));
        assert_eq!(get("List").data.type_id(), Some(REG_MULTI_SZ));
        assert!(notes.iter().any(|n| n.contains("Acme.Add")));

        let hklm = blocks.iter().find(|b| b.path.hive == Hive::Hklm).unwrap();
        assert_eq!(
            hklm.values[0].data,
            RegData::Hex {
                ty: REG_BINARY,
                bytes: vec![1, 2, 255]
            }
        );
    }

    #[test]
    fn delreg_distinguishes_value_from_key() {
        let (blocks, _) = read(SAMPLE.as_bytes(), None).unwrap();
        let acme = blocks
            .iter()
            .find(|b| b.path.sub == "Software\\Acme" && b.path.hive == Hive::Hkcu)
            .unwrap();
        assert!(acme.values.iter().any(|v| v.data == RegData::Delete));
        let old = blocks
            .iter()
            .find(|b| b.path.sub == "Software\\AcmeOld")
            .unwrap();
        assert!(
            old.delete,
            "a DelReg line with no value name deletes the key"
        );
    }

    #[test]
    fn escaped_percent_survives_expansion() {
        let m = HashMap::from([("server".to_string(), "acme.test".to_string())]);
        assert_eq!(expand("%%SystemRoot%%\\x", &m), "%SystemRoot%\\x");
        assert_eq!(expand("%SERVER%", &m), "acme.test");
        assert_eq!(
            expand("%unknown%", &m),
            "%unknown%",
            "unknown tokens stay verbatim"
        );
    }

    #[test]
    fn quoted_commas_do_not_split_fields() {
        let f = fields(r#"HKCU,"Software\A,B","Name",0x0,"x,y""#);
        assert_eq!(f[1], "Software\\A,B");
        assert_eq!(f[4], "x,y");
    }

    #[test]
    fn hkr_is_reported_not_guessed() {
        let inf =
            "[Version]\nSignature=\"$WINDOWS NT$\"\n[X]\nAddReg=R\n[R]\nHKR,,\"V\",0x0,\"d\"\n";
        let (blocks, notes) = read(inf.as_bytes(), None).unwrap();
        assert!(blocks.is_empty());
        assert!(notes.iter().any(|n| n.contains("HKR")), "{notes:?}");
    }

    #[test]
    fn missing_section_is_an_error_not_silence() {
        let inf = "[Version]\nSignature=\"x\"\n[X]\nAddReg=R\n[R]\nHKCU,\"S\",\"V\",0x0,\"d\"\n";
        assert!(read(inf.as_bytes(), Some("Nope")).is_err());
    }
}
