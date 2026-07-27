//! INI input — the shape most Windows configuration already has.
//!
//! ```ini
//! [HKEY_CURRENT_USER\Software\Acme]
//! Server = acme.test
//! Port:dword = 8080
//! Path:expand_sz = %USERPROFILE%\acme
//! Recent:multi_sz = a.txt|b.txt
//! Blob:binary = 01 02 ff
//! Legacy =                       ; empty value deletes it
//! @ = default value
//!
//! [-HKEY_CURRENT_USER\Software\Old]
//! ```
//!
//! A section header is a full registry path, and `[-Path]` deletes the key —
//! both borrowed from `.reg` so the two formats read the same way. The optional
//! `:type` suffix on a name is the only addition; without it a value is
//! `REG_SZ`, which is what an ordinary INI means anyway.

use crate::model::*;

pub fn read(bytes: &[u8]) -> Result<(Vec<KeyBlock>, Vec<String>), String> {
    let (text, _) = crate::encoding::decode(bytes);
    let mut blocks: Vec<KeyBlock> = Vec::new();
    let mut notes = Vec::new();
    let mut current: Option<usize> = None;

    for (i, raw) in text.split('\n').enumerate() {
        let line_no = i + 1;
        let line = raw.trim_end_matches('\r').trim();

        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') {
            let end = line
                .rfind(']')
                .ok_or_else(|| format!("line {line_no}: unterminated section header"))?;
            let inner = &line[1..end];
            let (delete, path) = match inner.strip_prefix('-') {
                Some(rest) => (true, rest.trim()),
                None => (false, inner.trim()),
            };
            let mut block = crate::formats::block(path, line_no)?;
            block.delete = delete;
            blocks.push(block);
            current = Some(blocks.len() - 1);
            continue;
        }

        let Some(idx) = current else {
            return Err(format!(
                "line {line_no}: {line:?} appears before any [section]; \
                 an INI read as registry data needs every value under a key path"
            ));
        };

        let Some((lhs, rhs)) = line.split_once('=') else {
            return Err(format!(
                "line {line_no}: expected NAME = VALUE, found {line:?}"
            ));
        };

        // Strip an unquoted trailing comment, then unwrap surrounding quotes.
        let mut data = rhs.trim();
        if !data.starts_with('"') {
            if let Some(pos) = data.find(" ;") {
                data = data[..pos].trim_end();
            }
        }
        let data = data.trim().trim_matches('"');

        let (name, ty) = match lhs.trim().rsplit_once(':') {
            Some((n, t)) if !t.trim().is_empty() && !t.contains('\\') => (n.trim(), Some(t.trim())),
            _ => (lhs.trim(), None),
        };

        let value = match ty {
            None if data.is_empty() => RegData::Delete,
            None => RegData::Sz(data.to_string()),
            Some(t) => {
                // The `|` separator reads better in an INI than reg.exe's `\0`.
                let normalised = if t.eq_ignore_ascii_case("multi_sz")
                    || t.eq_ignore_ascii_case("reg_multi_sz")
                {
                    data.replace('|', "\\0")
                } else {
                    data.to_string()
                };
                crate::engine::parse_typed(t, &normalised)
                    .map_err(|e| format!("line {line_no}: {e}"))?
            }
        };

        if blocks[idx].delete {
            notes.push(format!(
                "line {line_no}: {name:?} sits under a [-{}] delete section and is ignored",
                blocks[idx].path
            ));
            continue;
        }

        blocks[idx].values.push(ValueEntry {
            name: crate::formats::value_name(name),
            data: value,
            line: line_no,
        });
    }

    if blocks.is_empty() {
        return Err("no [SECTION] headers found; an INI needs a registry path per section".into());
    }
    notes.insert(0, format!("{} section(s) read", blocks.len()));
    Ok((blocks, notes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
; Acme configuration
[HKEY_CURRENT_USER\Software\Acme]
Server = acme.test
Port:dword = 8080
Path:expand_sz = %USERPROFILE%\acme
Recent:multi_sz = a.txt|b.txt
Blob:binary = 01 02 ff
Legacy =
@ = default value

[-HKEY_CURRENT_USER\Software\Old]
"#;

    fn val(b: &KeyBlock, n: &str) -> RegData {
        b.values
            .iter()
            .find(|v| matches!(&v.name, ValueName::Named(x) if x == n))
            .unwrap()
            .data
            .clone()
    }

    #[test]
    fn reads_typed_entries() {
        let (blocks, _) = read(SAMPLE.as_bytes()).unwrap();
        let acme = &blocks[0];
        assert_eq!(val(acme, "Server"), RegData::Sz("acme.test".into()));
        assert_eq!(val(acme, "Port"), RegData::Dword(8080));
        assert_eq!(val(acme, "Path").type_id(), Some(REG_EXPAND_SZ));
        assert_eq!(val(acme, "Recent").type_id(), Some(REG_MULTI_SZ));
        assert_eq!(
            val(acme, "Blob"),
            RegData::Hex {
                ty: REG_BINARY,
                bytes: vec![1, 2, 255]
            }
        );
        assert_eq!(val(acme, "Legacy"), RegData::Delete, "empty value deletes");
    }

    #[test]
    fn at_sign_is_the_default_value() {
        let (blocks, _) = read(SAMPLE.as_bytes()).unwrap();
        let d = blocks[0]
            .values
            .iter()
            .find(|v| v.name == ValueName::Default)
            .unwrap();
        assert_eq!(d.data, RegData::Sz("default value".into()));
    }

    #[test]
    fn minus_prefix_deletes_the_key() {
        let (blocks, _) = read(SAMPLE.as_bytes()).unwrap();
        assert!(blocks[1].delete);
        assert_eq!(blocks[1].path.sub, "Software\\Old");
    }

    #[test]
    fn multi_sz_uses_pipe_separators() {
        let (blocks, _) = read(SAMPLE.as_bytes()).unwrap();
        let RegData::Hex { bytes, .. } = val(&blocks[0], "Recent") else {
            panic!()
        };
        assert_eq!(
            crate::model::utf16_from_bytes(&bytes),
            vec!["a.txt", "b.txt"]
        );
    }

    #[test]
    fn a_path_with_a_colon_is_not_mistaken_for_a_type() {
        let src = "[HKCU\\Software\\A]\nC:\\Tools = x\n";
        let (blocks, _) = read(src.as_bytes()).unwrap();
        assert_eq!(
            blocks[0].values[0].name,
            ValueName::Named("C:\\Tools".into())
        );
    }

    #[test]
    fn value_before_a_section_is_an_error() {
        assert!(read(b"Name = x\n").is_err());
        assert!(read(b"; only a comment\n").is_err());
    }
}
