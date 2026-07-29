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

use super::OrderedBlocks;
use crate::model::*;
use std::collections::HashMap;

type InfLine = (usize, String);
type Sections = Vec<(String, Vec<InfLine>)>;

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
const FLG_NOCLOBBER: u32 = 0x0000_0002;
const FLG_APPEND: u32 = 0x0000_0008;
const FLG_KEYONLY: u32 = 0x0000_0010;
const FLG_OVERWRITEONLY: u32 = 0x0000_0020;
const FLG_64BITKEY: u32 = 0x0000_1000;
const FLG_KEYONLY_COMMON: u32 = 0x0000_2000;
const FLG_32BITKEY: u32 = 0x0000_4000;
const BEHAVIOR_MASK: u32 = FLG_NOCLOBBER
    | FLG_DELREG_VALUE
    | FLG_APPEND
    | FLG_KEYONLY
    | FLG_OVERWRITEONLY
    | FLG_64BITKEY
    | FLG_KEYONLY_COMMON
    | FLG_32BITKEY;

pub fn read(
    bytes: &[u8],
    only_section: Option<&str>,
    language: Option<u16>,
) -> Result<super::ReaderResult, String> {
    let (text, _) = crate::encoding::decode_strict(bytes)?;
    let mut notes = Vec::new();
    let mut losses = Vec::new();
    let (sections, line_losses) = split_sections(&text);
    losses.extend(line_losses);

    let (strings, string_note, string_losses) = select_strings(&sections, language);
    losses.extend(string_losses);
    if let Some(note) = string_note {
        notes.push(note);
    }

    // Collect the section names referenced by AddReg=/DelReg= directives.
    let mut add: Vec<String> = Vec::new();
    let mut del: Vec<String> = Vec::new();
    for (section_name, lines) in &sections {
        if section_name.eq_ignore_ascii_case("Strings")
            || section_name
                .get(.."Strings.".len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Strings."))
        {
            continue;
        }
        for (no, line) in lines {
            let Some((lhs, rhs)) = line.split_once('=') else {
                continue;
            };
            let key = lhs.trim();
            if key.eq_ignore_ascii_case("AddReg") || key.eq_ignore_ascii_case("DelReg") {
                for target in rhs.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    match expand(target, &strings) {
                        Ok(target) if key.eq_ignore_ascii_case("AddReg") => add.push(target),
                        Ok(target) => del.push(target),
                        Err(error) => losses.push(format!(
                            "line {no}: {key} section reference {target:?}: {error}"
                        )),
                    }
                }
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

    let mut blocks = OrderedBlocks::new();
    let mut used = Vec::new();

    for name in &add {
        let Some(lines) = find(name) else {
            losses.push(format!(
                "AddReg references [{name}], which this file does not define"
            ));
            continue;
        };
        let security_section = format!("{name}.security");
        if find(&security_section).is_some_and(|lines| !lines.is_empty()) {
            losses.push(format!(
                "[{security_section}] applies a security descriptor that the registry-data model cannot preserve"
            ));
        }
        used.push(name.clone());
        for (no, line) in lines {
            match add_line(line, &strings) {
                Ok(Some(LineOp::Value(path, entry))) => blocks.push(path, entry, *no),
                Ok(Some(LineOp::CreateKey(path))) => {
                    blocks.block_for(path, *no);
                }
                Ok(Some(LineOp::DeleteKey(path))) => {
                    blocks.block_for(path, *no).delete = true;
                }
                Ok(None) => {}
                Err(e) => losses.push(format!("[{name}] line {no}: {e}")),
            }
        }
    }

    for name in &del {
        let Some(lines) = find(name) else {
            losses.push(format!(
                "DelReg references [{name}], which this file does not define"
            ));
            continue;
        };
        used.push(name.clone());
        for (no, line) in lines {
            match del_line(line, &strings) {
                Ok(Some((path, Some(entry)))) => blocks.push(path, entry, *no),
                Ok(Some((path, None))) => {
                    let b = blocks.block_for(path, *no);
                    b.delete = true;
                }
                Ok(None) => {}
                Err(e) => losses.push(format!("[{name}] line {no}: {e}")),
            }
        }
    }

    notes.insert(0, format!("sections read: {}", used.join(", ")));
    Ok((blocks.into_vec(), notes, losses))
}

enum LineOp {
    CreateKey(RegPath),
    DeleteKey(RegPath),
    Value(RegPath, ValueEntry),
}

/// `root, subkey, value, flags, data...`
fn add_line(line: &str, strings: &HashMap<String, String>) -> Result<Option<LineOp>, String> {
    let f = fields(line)?;
    if f.is_empty() {
        return Ok(None);
    }
    if f.len() < 2 {
        return Err(format!("expected at least root,subkey — got {line:?}"));
    }

    let hive = root(&f[0])?;
    let sub = expand(&f[1], strings)?;
    let path = RegPath {
        hive,
        sub: sub.trim_matches('\\').to_string(),
    };

    if f.len() < 3 || f[2..].iter().all(|x| x.is_empty()) {
        return Ok(Some(LineOp::CreateKey(path)));
    }

    let name = crate::formats::value_name(&expand(&f[2], strings)?);
    let flags = if f.len() > 3 {
        number(&f[3]).ok_or_else(|| format!("invalid AddReg flags {:?}", f[3]))? as u32
    } else {
        0
    };
    if flags & (FLG_32BITKEY | FLG_64BITKEY) != 0 {
        return Err(format!(
            "per-line registry-view flag 0x{:08x} cannot be preserved by one common model",
            flags & (FLG_32BITKEY | FLG_64BITKEY)
        ));
    }
    if flags & (FLG_NOCLOBBER | FLG_APPEND | FLG_OVERWRITEONLY) != 0 {
        return Err(format!(
            "conditional/append AddReg flags 0x{:08x} require current registry state",
            flags & (FLG_NOCLOBBER | FLG_APPEND | FLG_OVERWRITEONLY)
        ));
    }
    let unknown_low = flags & 0x0000_ffff & !BEHAVIOR_MASK & !T_BINARY;
    if unknown_low != 0 {
        return Err(format!(
            "unsupported AddReg behavior flags 0x{unknown_low:08x}"
        ));
    }
    if flags & (FLG_KEYONLY | FLG_KEYONLY_COMMON) != 0 {
        return Ok(Some(LineOp::CreateKey(path)));
    }
    if flags & FLG_DELREG_VALUE != 0 {
        if matches!(name, ValueName::Default) {
            return Ok(Some(LineOp::DeleteKey(path)));
        }
        return Ok(Some(LineOp::Value(
            path,
            ValueEntry {
                name,
                data: RegData::Delete,
                line: 0,
            },
        )));
    }
    let raw: Vec<String> = f[4..]
        .iter()
        .map(|value| expand(value, strings))
        .collect::<Result<_, _>>()?;

    let data = match flags & TYPE_MASK {
        T_SZ => RegData::Sz(raw.join(",")),
        T_EXPAND_SZ => RegData::Hex {
            ty: REG_EXPAND_SZ,
            bytes: crate::value::utf16_nul(&raw.join(",")),
        },
        T_MULTI_SZ => {
            let mut bytes = Vec::new();
            for s in raw.iter().filter(|s| !s.is_empty()) {
                bytes.extend_from_slice(&crate::value::utf16_nul(s));
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
        other if other & T_BINARY != 0 => {
            let mut bytes = Vec::with_capacity(raw.len());
            for tok in raw.iter().filter(|token| !token.is_empty()) {
                bytes.push(
                    u8::from_str_radix(tok.trim().trim_start_matches("0x"), 16)
                        .map_err(|_| format!("invalid binary byte {tok:?}"))?,
                );
            }
            RegData::Hex {
                ty: other >> 16,
                bytes,
            }
        }
        other => return Err(format!("unsupported AddReg type flag 0x{other:08x}")),
    };

    Ok(Some(LineOp::Value(
        path,
        ValueEntry {
            name,
            data,
            line: 0,
        },
    )))
}

/// `root, subkey [, value [, flags]]` — no value name deletes the whole key.
fn del_line(
    line: &str,
    strings: &HashMap<String, String>,
) -> Result<Option<(RegPath, Option<ValueEntry>)>, String> {
    let f = fields(line)?;
    if f.is_empty() {
        return Ok(None);
    }
    if f.len() < 2 {
        return Err(format!("expected at least root,subkey — got {line:?}"));
    }
    let path = RegPath {
        hive: root(&f[0])?,
        sub: expand(&f[1], strings)?.trim_matches('\\').to_string(),
    };

    let has_value = f.len() > 2 && !f[2].is_empty();
    let flags = if f.len() > 3 {
        number(&f[3]).ok_or_else(|| format!("invalid DelReg flags {:?}", f[3]))? as u32
    } else {
        0
    };
    if flags & (FLG_32BITKEY | FLG_64BITKEY) != 0 {
        return Err(format!(
            "per-line registry-view flag 0x{:08x} cannot be preserved by one common model",
            flags & (FLG_32BITKEY | FLG_64BITKEY)
        ));
    }
    if flags & FLG_KEYONLY_COMMON != 0 {
        return Ok(Some((path, None)));
    }

    if has_value || flags & FLG_DELREG_VALUE != 0 {
        let name = crate::formats::value_name(&expand(&f[2], strings)?);
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
fn fields(line: &str) -> Result<Vec<String>, String> {
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
    if quoted {
        return Err(format!("unterminated quoted field in {line:?}"));
    }
    out.push(cur.trim().to_string());
    while out.last().map(|s| s.is_empty()).unwrap_or(false) && out.len() > 2 {
        out.pop();
    }
    if out.iter().all(|s| s.is_empty()) {
        return Ok(Vec::new());
    }
    Ok(out)
}

/// Replace `%Token%` from the `[Strings]` section. `%%` is a literal percent.
///
/// SetupAPI requires every token to be defined. Keeping an unresolved token
/// verbatim would turn malformed INF syntax into registry data that Windows
/// would never have installed.
fn expand(s: &str, strings: &HashMap<String, String>) -> Result<String, String> {
    if !s.contains('%') {
        return Ok(s.to_string());
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
                    None => return Err(format!("undefined [Strings] token %{token}%")),
                }
                rest = &after[end + 1..];
            }
            None => return Err(format!("unterminated [Strings] token in {s:?}")),
        }
    }
    out.push_str(rest);
    Ok(out)
}

fn select_strings(
    sections: &[(String, Vec<InfLine>)],
    requested: Option<u16>,
) -> (HashMap<String, String>, Option<String>, Vec<String>) {
    let mut base = None;
    let mut localized = Vec::new();
    let mut losses = Vec::new();

    for (name, lines) in sections {
        if name.eq_ignore_ascii_case("Strings") {
            if base.replace(lines).is_some() {
                losses.push("INF defines more than one [Strings] section".into());
            }
            continue;
        }
        let Some((prefix, suffix)) = name.split_once('.') else {
            continue;
        };
        if !prefix.eq_ignore_ascii_case("Strings") {
            continue;
        }
        if suffix.len() != 4 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            losses.push(format!(
                "[{name}] has an invalid LanguageID; expected four hexadecimal digits"
            ));
            continue;
        }
        let id = u16::from_str_radix(suffix, 16).expect("validated hexadecimal LANGID");
        if localized.iter().any(|(candidate, _)| *candidate == id) {
            losses.push(format!(
                "INF defines more than one [Strings.{id:04X}] section"
            ));
            continue;
        }
        localized.push((id, lines));
    }

    let selected = match requested {
        None => base.map(|lines| (None, lines)),
        Some(id) => localized
            .iter()
            .find(|(candidate, _)| *candidate == id)
            .map(|(candidate, lines)| (Some(*candidate), *lines))
            .or_else(|| {
                let neutral = id & 0x03ff;
                localized
                    .iter()
                    .find(|(candidate, _)| *candidate == neutral)
                    .map(|(candidate, lines)| (Some(*candidate), *lines))
            })
            .or_else(|| {
                let primary = id & 0x03ff;
                localized
                    .iter()
                    .find(|(candidate, _)| *candidate & 0x03ff == primary)
                    .map(|(candidate, lines)| (Some(*candidate), *lines))
            })
            .or_else(|| base.map(|lines| (None, lines))),
    };

    let Some((selected_id, lines)) = selected else {
        let note = requested.map(|id| {
            format!("no [Strings.{id:04X}] family or undecorated [Strings] section was available")
        });
        return (HashMap::new(), note, losses);
    };
    let (strings, parse_losses) = parse_strings(lines);
    losses.extend(parse_losses);
    let note = match (requested, selected_id) {
        (Some(requested), Some(selected)) => format!(
            "{} [Strings.{selected:04X}] token(s) selected for LANGID {requested:04X}",
            strings.len()
        ),
        (Some(requested), None) => format!(
            "{} undecorated [Strings] token(s) selected as fallback for LANGID {requested:04X}",
            strings.len()
        ),
        (None, _) if !localized.is_empty() => format!(
            "{} undecorated [Strings] token(s) selected; {} locale section(s) available (--inf-language LANGID selects one)",
            strings.len(),
            localized.len()
        ),
        (None, _) => format!("{} [Strings] token(s) substituted", strings.len()),
    };
    (strings, Some(note), losses)
}

fn parse_strings(lines: &[(usize, String)]) -> (HashMap<String, String>, Vec<String>) {
    let mut m = HashMap::new();
    let mut losses = Vec::new();
    for (no, line) in lines {
        let Some((key, raw_value)) = line.split_once('=') else {
            losses.push(format!("[Strings] line {no}: expected key=value"));
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            losses.push(format!("[Strings] line {no}: token name is empty"));
            continue;
        }
        let value = match inf_string(raw_value) {
            Ok(value) => value,
            Err(error) => {
                losses.push(format!("[Strings] line {no}: {error}"));
                continue;
            }
        };
        let normalized = key.to_ascii_lowercase();
        match m.entry(normalized) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(value);
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                losses.push(format!(
                    "[Strings] line {no}: duplicate token {key:?} (names are case-insensitive)"
                ));
            }
        }
    }
    (m, losses)
}

fn inf_string(raw: &str) -> Result<String, String> {
    let value = raw.trim_start();
    if !value.starts_with('"') {
        let value = value.split_once(';').map_or(value, |(head, _)| head).trim();
        if value.contains('"') {
            return Err("unquoted token data contains a double quote".into());
        }
        return Ok(value.to_string());
    }

    let mut out = String::new();
    let mut chars = value[1..].chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '"' {
            out.push(ch);
            continue;
        }
        if chars.peek() == Some(&'"') {
            chars.next();
            out.push('"');
            continue;
        }
        let tail: String = chars.collect();
        let tail = tail.trim_start();
        if !tail.is_empty() && !tail.starts_with(';') {
            return Err(format!("unexpected text after closing quote: {tail:?}"));
        }
        return Ok(out);
    }
    Err("unterminated quoted token data".into())
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
fn split_sections(text: &str) -> (Sections, Vec<String>) {
    let mut out = Sections::new();
    let mut losses = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    let mut logical = Vec::new();

    for (i, raw) in text.split('\n').enumerate() {
        let physical = raw.trim_end_matches('\r');
        let (start, mut line) = match pending.take() {
            Some((start, mut previous)) => {
                previous.push_str(physical.trim_start());
                (start, previous)
            }
            None => (i + 1, physical.to_string()),
        };
        if let Some(slash) = continuation_at(&line) {
            line.truncate(slash);
            pending = Some((start, line));
            continue;
        }
        logical.push((start, line));
    }
    if let Some((start, line)) = pending {
        losses.push(format!("line {start}: unterminated INF line continuation"));
        logical.push((start, line));
    }

    for (line_no, raw) in logical {
        let line = raw.trim();
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
            last.1.push((line_no, line.to_string()));
        }
    }
    (out, losses)
}

fn continuation_at(line: &str) -> Option<usize> {
    let mut quoted = false;
    let mut end = line.len();
    let mut chars = line.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        if ch == '"' {
            if quoted && chars.peek().is_some_and(|(_, next)| *next == '"') {
                chars.next();
            } else {
                quoted = !quoted;
            }
        } else if ch == ';' && !quoted {
            end = index;
            break;
        }
    }
    let content = line[..end].trim_end();
    content.ends_with('\\').then(|| content.len() - 1)
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
        let (blocks, notes, losses) = read(SAMPLE.as_bytes(), None, None).unwrap();
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
        assert!(losses.is_empty());

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
    fn custom_raw_types_round_trip_but_section_security_is_a_loss() {
        let inf = r#"[Version]
Signature="$WINDOWS NT$"
[DefaultInstall]
AddReg=Raw
[Raw]
HKCU,"Software\Acme","Custom",0x00380001,00,7f,ff
[Raw.security]
"D:P(A;;GA;;;SY)(A;;GA;;;BA)"
"#;
        let (blocks, _, losses) = read(inf.as_bytes(), None, None).unwrap();
        assert_eq!(
            blocks[0].values[0].data,
            RegData::Hex {
                ty: 0x38,
                bytes: vec![0, 0x7f, 0xff],
            }
        );
        assert_eq!(losses.len(), 1);
        assert!(losses[0].contains("security descriptor"));
    }

    #[test]
    fn delreg_distinguishes_value_from_key() {
        let (blocks, _, _) = read(SAMPLE.as_bytes(), None, None).unwrap();
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
        assert_eq!(expand("%%SystemRoot%%\\x", &m).unwrap(), "%SystemRoot%\\x");
        assert_eq!(expand("%SERVER%", &m).unwrap(), "acme.test");
        assert!(expand("%unknown%", &m).unwrap_err().contains("undefined"));
        assert!(expand("100%", &m).unwrap_err().contains("unterminated"));

        let inf = r#"[Version]
Signature="$WINDOWS NT$"
[DefaultInstall]
AddReg=%MISSING_SECTION%
[Fallback.AddReg]
HKCU,"Software\%MISSING_KEY%","%MISSING_NAME%",0,"%MISSING_DATA%"
"#;
        let (blocks, _, losses) = read(inf.as_bytes(), None, None).unwrap();
        assert!(blocks.is_empty());
        assert!(
            losses.iter().any(|loss| loss.contains("%MISSING_SECTION%")),
            "{losses:?}"
        );

        let token_named_like_directive = br#"[Version]
Signature="$WINDOWS NT$"
[DefaultInstall]
AddReg=Real
[Real]
HKCU,"Software\Acme","Value",0,"%AddReg%"
[Strings]
AddReg="ordinary token data"
"#;
        let (blocks, _, losses) = read(token_named_like_directive, None, None).unwrap();
        assert!(losses.is_empty(), "{losses:?}");
        assert_eq!(
            blocks[0].values[0].data,
            RegData::Sz("ordinary token data".into())
        );

        let localized = br#"[Version]
Signature="$WINDOWS NT$"
[DefaultInstall]
AddReg=Real
[Real]
HKCU,"Software\Acme","Greeting",0,"%Greeting%"
[Strings]
Greeting="default"
[Strings.0009]
Greeting="neutral English"
[Strings.0409]
Greeting="US English"
[Strings.0407]
Greeting="German"
"#;
        let value_for = |language| {
            let (blocks, notes, losses) = read(localized, None, language).unwrap();
            assert!(losses.is_empty(), "{losses:?}");
            let RegData::Sz(value) = &blocks[0].values[0].data else {
                panic!("localized token was not a string")
            };
            (value.clone(), notes)
        };
        assert_eq!(value_for(None).0, "default");
        assert_eq!(value_for(Some(0x0409)).0, "US English");
        assert_eq!(value_for(Some(0x0c09)).0, "neutral English");
        assert_eq!(value_for(Some(0x0807)).0, "German");
        let (fallback, notes) = value_for(Some(0x0411));
        assert_eq!(fallback, "default");
        assert!(notes.iter().any(|note| note.contains("fallback")));

        let physical_syntax = br#"[Version]
Signature="$WINDOWS NT$"
[DefaultInstall]
AddReg=R
[R]
HKCU,"Software\Acme","Semicolon",0,\
  "%Semicolon%"
HKCU,"Software\Acme","Quoted",0,"%Quoted%"
[Strings]
Semicolon="inside;not a comment" ; this is a comment
Quoted="""quoted value"""
Ignored="separate" ; a backslash in this comment does not continue \
After="next definition"
"#;
        let (blocks, _, losses) = read(physical_syntax, None, None).unwrap();
        assert!(losses.is_empty(), "{losses:?}");
        let values = &blocks[0].values;
        assert!(values.iter().any(|value| {
            value.name == ValueName::Named("Semicolon".into())
                && value.data == RegData::Sz("inside;not a comment".into())
        }));
        assert!(values.iter().any(|value| {
            value.name == ValueName::Named("Quoted".into())
                && value.data == RegData::Sz("\"quoted value\"".into())
        }));

        let ambiguous = br#"[Version]
Signature="$WINDOWS NT$"
[DefaultInstall]
AddReg=R
[R]
HKCU,"Software\Acme","Value",0,"%Name%"
[Strings]
Name="first"
name="second"
Broken="unterminated
"#;
        let (blocks, _, losses) = read(ambiguous, None, None).unwrap();
        assert_eq!(blocks[0].values[0].data, RegData::Sz("first".into()));
        assert!(losses.iter().any(|loss| loss.contains("duplicate token")));
        assert!(losses
            .iter()
            .any(|loss| loss.contains("unterminated quoted")));

        let (_, _, losses) = read(
            b"[Version]\nSignature=\"x\"\n[X]\nAddReg=R\n[R]\nHKCU,\\",
            None,
            None,
        )
        .unwrap();
        assert!(
            losses
                .iter()
                .any(|loss| loss.contains("unterminated INF line continuation")),
            "{losses:?}"
        );
    }

    #[test]
    fn quoted_commas_do_not_split_fields() {
        let f = fields(r#"HKCU,"Software\A,B","Name",0x0,"x,y""#).unwrap();
        assert_eq!(f[1], "Software\\A,B");
        assert_eq!(f[4], "x,y");
        assert!(fields(r#"HKCU,"Software\A","Name",0,"unterminated"#)
            .unwrap_err()
            .contains("unterminated quoted field"));
    }

    #[test]
    fn hkr_is_reported_not_guessed() {
        let inf =
            "[Version]\nSignature=\"$WINDOWS NT$\"\n[X]\nAddReg=R\n[R]\nHKR,,\"V\",0x0,\"d\"\n";
        let (blocks, _, losses) = read(inf.as_bytes(), None, None).unwrap();
        assert!(blocks.is_empty());
        assert!(losses.iter().any(|loss| loss.contains("HKR")), "{losses:?}");
    }

    #[test]
    fn behavioral_and_view_flags_are_not_flattened_into_unconditional_writes() {
        let inf = r#"[Version]
Signature="$WINDOWS NT$"
[DefaultInstall]
AddReg=Flags
[Flags]
HKCU,"Software\Acme","CreateOnly",0x00000002,"x"
HKCU,"Software\Acme","Append",0x00010008,"x"
HKCU,"Software\Acme","View",0x00004000,"x"
HKCU,"Software\Acme","Gone",0x00000004
HKCU,"Software\Acme","Ignored",0x00000010,"x"
HKCU,"Software\Acme\Old",,0x00000004
"#;
        let (blocks, _, losses) = read(inf.as_bytes(), None, None).unwrap();
        assert_eq!(losses.len(), 3);
        assert!(losses
            .iter()
            .any(|loss| loss.contains("current registry state")));
        assert!(losses.iter().any(|loss| loss.contains("registry-view")));
        let block = &blocks[0];
        assert!(block.values.iter().any(|value| {
            value.name == ValueName::Named("Gone".into()) && value.data == RegData::Delete
        }));
        assert!(!block
            .values
            .iter()
            .any(|value| matches!(&value.name, ValueName::Named(name) if name == "Ignored")));
        assert!(blocks
            .iter()
            .any(|candidate| candidate.path.sub.ends_with("\\Old") && candidate.delete));
    }

    #[test]
    fn missing_section_is_an_error_not_silence() {
        let inf = "[Version]\nSignature=\"x\"\n[X]\nAddReg=R\n[R]\nHKCU,\"S\",\"V\",0x0,\"d\"\n";
        assert!(read(inf.as_bytes(), Some("Nope"), None).is_err());
    }
}
