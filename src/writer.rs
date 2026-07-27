//! Serialise the model back to `.reg` text, byte-compatible with regedit.exe
//! output so that diffing our export against a regedit export is meaningful.

use crate::model::*;

/// regedit wraps hex payloads at column 80 and indents continuations by 2 spaces.
const WRAP_COL: usize = 80;

pub fn to_string(file: &RegFile) -> String {
    to_string_rooted(file, None, &[])
}

/// `root_label` replaces the hive name on every key, which is how a mounted
/// hive gets written out: the `.reg` format has no syntax for "app hive", so an
/// offline export must be re-rooted under some `HKEY_*` mount point to be
/// importable at all. `banner` lines are emitted as `;` comments above the header.
pub fn to_string_rooted(file: &RegFile, root_label: Option<&str>, banner: &[String]) -> String {
    let mut out = String::new();
    for line in banner {
        out.push_str("; ");
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !banner.is_empty() {
        out.push_str("\r\n");
    }
    out.push_str(file.format.header());
    out.push_str("\r\n");

    let render = |p: &RegPath| match root_label {
        None => p.to_string(),
        Some(r) if p.sub.is_empty() => r.to_string(),
        Some(r) => format!("{r}\\{}", p.sub),
    };

    for key in &file.keys {
        out.push_str("\r\n");
        if key.delete {
            out.push_str(&format!("[-{}]\r\n", render(&key.path)));
            continue;
        }
        out.push_str(&format!("[{}]\r\n", render(&key.path)));
        for v in &key.values {
            out.push_str(&value_line(v));
            out.push_str("\r\n");
        }
    }
    out
}

fn value_line(v: &ValueEntry) -> String {
    let name = match &v.name {
        ValueName::Default => "@".to_string(),
        ValueName::Named(n) => format!("\"{}\"", escape(n)),
    };
    format!("{name}={}", data_literal(&name, &v.data))
}

fn data_literal(name_prefix: &str, data: &RegData) -> String {
    match data {
        RegData::Delete => "-".to_string(),
        RegData::Sz(s) => format!("\"{}\"", escape(s)),
        RegData::Dword(v) => format!("dword:{v:08x}"),
        RegData::Hex { ty, bytes } => {
            let head = if *ty == REG_BINARY {
                "hex:".to_string()
            } else {
                format!("hex({ty:x}):")
            };
            // +1 for the '=' between name and data.
            let first_indent = name_prefix.chars().count() + 1 + head.chars().count();
            head + &wrap_hex(bytes, first_indent)
        }
    }
}

/// Only `\` and `"` are escaped - matching the parser, and matching regedit.
/// Notably a newline inside a REG_SZ is written literally, which is exactly why
/// regedit prefers `hex(1)` for such values.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out
}

fn wrap_hex(bytes: &[u8], first_indent: usize) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    let mut col = first_indent;
    for (i, b) in bytes.iter().enumerate() {
        let last = i + 1 == bytes.len();
        let tok = if last {
            format!("{b:02x}")
        } else {
            format!("{b:02x},")
        };
        // Reserve one column for the trailing `\` continuation marker.
        if col + tok.len() > WRAP_COL - 1 && i > 0 {
            out.push_str("\\\r\n  ");
            col = 2;
        }
        col += tok.len();
        out.push_str(&tok);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::SourceEncoding;
    use crate::parser::parse_str;

    #[test]
    fn round_trips_escapes_and_hex() {
        let src = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\A]\r\n\"p\"=\"C:\\\\Tmp\\\\\"\r\n\"say\"=\"he said \\\"hi\\\"\"\r\n\"d\"=dword:0000002a\r\n\"b\"=hex:00,01,02\r\n";
        let a = parse_str(src, SourceEncoding::Utf16Le);
        assert!(!a.has_errors(), "{:?}", a.diagnostics);
        let text = to_string(&a.file);
        let b = parse_str(&text, SourceEncoding::Utf16Le);
        assert!(!b.has_errors(), "{:?}", b.diagnostics);
        assert_eq!(a.file.keys[0].values.len(), b.file.keys[0].values.len());
        for (x, y) in a.file.keys[0].values.iter().zip(&b.file.keys[0].values) {
            assert_eq!(x.name, y.name);
            assert_eq!(x.data, y.data);
        }
    }

    #[test]
    fn long_hex_wraps_and_reparses() {
        let bytes: Vec<u8> = (0u8..200).collect();
        let file = RegFile {
            format: RegFormat::V5,
            encoding: SourceEncoding::Utf16Le,
            keys: vec![KeyBlock {
                path: RegPath::parse("HKCU\\A").unwrap(),
                delete: false,
                values: vec![ValueEntry {
                    name: ValueName::Named("big".into()),
                    data: RegData::Hex { ty: REG_BINARY, bytes: bytes.clone() },
                    line: 0,
                }],
                line: 0,
            }],
        };
        let text = to_string(&file);
        assert!(text.lines().all(|l| l.len() <= WRAP_COL));
        let back = parse_str(&text, SourceEncoding::Utf16Le);
        assert!(!back.has_errors(), "{:?}", back.diagnostics);
        assert_eq!(
            back.file.keys[0].values[0].data,
            RegData::Hex { ty: REG_BINARY, bytes }
        );
    }
}
