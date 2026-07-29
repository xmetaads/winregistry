//! Serialise the model back to `.reg` text, byte-compatible with regedit.exe
//! output so that diffing our export against a regedit export is meaningful.

use crate::model::*;

/// regedit wraps hex payloads at column 80 and indents continuations by 2 spaces.
const WRAP_COL: usize = 80;

/// Names in a `.reg` file occupy physical lines and have no escape for control
/// characters. Refuse an unrepresentable model instead of emitting a file that
/// regedit parses as different keys or values.
pub fn validate_reg_names(file: &RegFile) -> Result<(), String> {
    for key in &file.keys {
        let path = key.path.to_string();
        if key.path.sub.chars().any(forbidden_name_control) {
            return Err(format!("key path contains a control character: {path:?}"));
        }
        if key.path.sub.contains("\\\\") {
            return Err(format!("key path contains an empty component: {path:?}"));
        }
        if key
            .path
            .sub
            .split('\\')
            .any(|component| component.encode_utf16().count() > 255)
        {
            return Err(format!(
                "key path component exceeds 255 UTF-16 code units: {path:?}"
            ));
        }
        for value in &key.values {
            let ValueName::Named(name) = &value.name else {
                continue;
            };
            if name.chars().any(forbidden_name_control) {
                return Err(format!(
                    "value name contains a control character under {path:?}"
                ));
            }
            if name.encode_utf16().count() > 16_383 {
                return Err(format!(
                    "value name exceeds 16,383 UTF-16 code units under {path:?}"
                ));
            }
        }
    }
    Ok(())
}

fn forbidden_name_control(character: char) -> bool {
    let code = character as u32;
    code < 0x20 || code == 0x7f
}

pub fn to_string(file: &RegFile) -> String {
    to_string_rooted(file, None, &[])
}

/// Serialize the explicit JSON form accepted by `formats::json`.
///
/// Hex-backed values carry both the numeric type id and raw bytes. Rendering
/// them as preview text would corrupt malformed strings and unknown registry
/// types on a JSON -> model -> JSON round trip.
pub fn to_json(file: &RegFile) -> String {
    let mut out = String::from("{\n  \"keys\": [\n");
    for (i, key) in file.keys.iter().enumerate() {
        out.push_str(&format!(
            "    {{\"path\": {}, \"delete\": {}, \"values\": [",
            json_string(&key.path.to_string()),
            key.delete
        ));
        for (j, value) in key.values.iter().enumerate() {
            if j > 0 {
                out.push_str(", ");
            }
            out.push_str(&value_to_json(value));
        }
        out.push_str("]}");
        if i + 1 < file.keys.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]\n}\n");
    out
}

/// Serialize one value in the exact registry-data JSON shape.
///
/// Query output embeds this alongside its human preview so callers can retain
/// numeric type ids and raw bytes without re-parsing display text.
pub fn value_to_json(value: &ValueEntry) -> String {
    let name = match &value.name {
        ValueName::Default => "",
        ValueName::Named(name) => name,
    };
    let mut out = format!("{{\"name\": {}", json_string(name));
    match &value.data {
        RegData::Delete => out.push_str(", \"data\": null"),
        RegData::Sz(text) => out.push_str(&format!(
            ", \"type\": \"REG_SZ\", \"data\": {}",
            json_string(text)
        )),
        RegData::Dword(number) => {
            out.push_str(&format!(", \"type\": \"REG_DWORD\", \"data\": {number}"))
        }
        RegData::Hex { ty, bytes } => out.push_str(&format!(
            ", \"typeId\": {ty}, \"raw\": {}",
            json_string(&hex_bytes(bytes))
        )),
    }
    out.push('}');
    out
}

/// Serialize rows accepted by `formats::csv`.
///
/// Raw values use `.reg`'s `hex(type-id)` spelling so every numeric registry
/// type, including unknown ones, survives a CSV round trip.
pub fn to_csv(file: &RegFile) -> String {
    let mut out = String::from("key,name,type,data\r\n");
    for key in &file.keys {
        if key.delete {
            csv_row(&mut out, &[&key.path.to_string(), "", "", "DELETE_KEY"]);
            continue;
        }
        // An empty key has no value row to carry it in CSV. Emit an explicit
        // marker understood by the reader rather than silently dropping it.
        if key.values.is_empty() {
            csv_row(&mut out, &[&key.path.to_string(), "", "", "CREATE_KEY"]);
            continue;
        }
        for value in &key.values {
            let name = match &value.name {
                ValueName::Default => "",
                ValueName::Named(name) => name,
            };
            let (ty, data) = match &value.data {
                RegData::Delete => (String::new(), String::new()),
                RegData::Sz(text) => ("REG_SZ".to_string(), text.clone()),
                RegData::Dword(number) => ("REG_DWORD".to_string(), number.to_string()),
                RegData::Hex { ty, bytes } => (format!("hex({ty:x})"), hex_bytes(bytes)),
            };
            csv_row(
                &mut out,
                &[&key.path.to_string(), name, ty.as_str(), data.as_str()],
            );
        }
    }
    out
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
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

fn csv_row(out: &mut String, fields: &[&str]) {
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&field.replace('"', "\"\""));
        out.push('"');
    }
    out.push_str("\r\n");
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
        RegData::Sz(s) if !s.chars().any(quoted_string_control) => {
            format!("\"{}\"", escape(s))
        }
        RegData::Sz(s) => hex_literal(name_prefix, REG_SZ, &crate::value::utf16_nul(s)),
        RegData::Dword(v) => format!("dword:{v:08x}"),
        RegData::Hex { ty, bytes } => hex_literal(name_prefix, *ty, bytes),
    }
}

fn quoted_string_control(character: char) -> bool {
    (character as u32) < 0x20
}

fn hex_literal(name_prefix: &str, ty: u32, bytes: &[u8]) -> String {
    let head = if ty == REG_BINARY {
        "hex:".to_string()
    } else {
        format!("hex({ty:x}):")
    };
    // +1 for the '=' between name and data.
    let first_indent = name_prefix.chars().count() + 1 + head.chars().count();
    head + &wrap_hex(bytes, first_indent)
}

/// Only `\` and `"` are escaped - matching the parser, and matching regedit.
/// Callers route strings containing control characters through `hex(1)` because
/// quoted `.reg` strings have no escape for them.
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

    fn structured_sample() -> RegFile {
        RegFile {
            format: RegFormat::V5,
            encoding: SourceEncoding::Utf8,
            keys: vec![
                KeyBlock {
                    path: RegPath::parse("HKCU\\Software\\A,\"B\"").unwrap(),
                    delete: false,
                    values: vec![
                        ValueEntry {
                            name: ValueName::Default,
                            data: RegData::Sz("line 1\nline 2".into()),
                            line: 0,
                        },
                        ValueEntry {
                            name: ValueName::Named("Count".into()),
                            data: RegData::Dword(42),
                            line: 0,
                        },
                        ValueEntry {
                            name: ValueName::Named("Raw".into()),
                            data: RegData::Hex {
                                ty: 0x1234,
                                bytes: vec![0, 1, 0xfe, 0xff, 7],
                            },
                            line: 0,
                        },
                        ValueEntry {
                            name: ValueName::Named("Gone".into()),
                            data: RegData::Delete,
                            line: 0,
                        },
                    ],
                    line: 0,
                },
                KeyBlock {
                    path: RegPath::parse("HKCU\\Software\\Empty").unwrap(),
                    delete: false,
                    values: vec![],
                    line: 0,
                },
                KeyBlock {
                    path: RegPath::parse("HKCU\\Software\\Deleted").unwrap(),
                    delete: true,
                    values: vec![],
                    line: 0,
                },
            ],
        }
    }

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
                    data: RegData::Hex {
                        ty: REG_BINARY,
                        bytes: bytes.clone(),
                    },
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
            RegData::Hex {
                ty: REG_BINARY,
                bytes
            }
        );
    }

    #[test]
    fn reg_output_rejects_names_it_cannot_represent_on_one_line() {
        let mut file = structured_sample();
        file.keys[0].path.sub = "Software\\Visible\nHidden".into();
        assert!(validate_reg_names(&file)
            .unwrap_err()
            .contains("control character"));

        file.keys[0].path.sub = "Software\\Safe".into();
        file.keys[0].values[1].name = ValueName::Named("Visible\tHidden".into());
        assert!(validate_reg_names(&file)
            .unwrap_err()
            .contains("control character"));
    }

    #[test]
    fn reg_output_uses_hex_one_for_unquotable_sz_without_losing_bytes() {
        let mut file = structured_sample();
        file.keys[0].values = vec![ValueEntry {
            name: ValueName::Named("Multiline".into()),
            data: RegData::Sz("first\nsecond\0tail".into()),
            line: 0,
        }];
        let expected = crate::value::data_to_raw(&file.keys[0].values[0].data).unwrap();
        let text = to_string(&file);
        assert!(text.contains("\"Multiline\"=hex(1):"), "{text}");

        let parsed = parse_str(&text, SourceEncoding::Utf16Le);
        assert!(!parsed.has_errors(), "{:?}", parsed.diagnostics);
        let actual = crate::value::data_to_raw(&parsed.file.keys[0].values[0].data).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn json_output_round_trips_every_model_shape() {
        let original = structured_sample();
        let text = to_json(&original);
        let (keys, _) = crate::formats::json::read(text.as_bytes()).unwrap();
        assert_eq!(keys.len(), original.keys.len());
        for (actual, expected) in keys.iter().zip(&original.keys) {
            assert_eq!(actual.path.fold(), expected.path.fold());
            assert_eq!(actual.delete, expected.delete);
            assert_eq!(actual.values.len(), expected.values.len());
            for (actual, expected) in actual.values.iter().zip(&expected.values) {
                assert_eq!(actual.name, expected.name);
                assert_eq!(actual.data, expected.data);
            }
        }
    }

    #[test]
    fn csv_output_round_trips_every_model_shape() {
        let original = structured_sample();
        let text = to_csv(&original);
        let (keys, _) = crate::formats::csv::read(text.as_bytes()).unwrap();
        assert_eq!(keys.len(), original.keys.len());
        for (actual, expected) in keys.iter().zip(&original.keys) {
            assert_eq!(actual.path.fold(), expected.path.fold());
            assert_eq!(actual.delete, expected.delete);
            assert_eq!(actual.values.len(), expected.values.len());
            for (actual, expected) in actual.values.iter().zip(&expected.values) {
                assert_eq!(actual.name, expected.name);
                assert_eq!(actual.data, expected.data);
            }
        }
    }
}
