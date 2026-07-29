//! `.reg` parser.
//!
//! Deliberately hand-written rather than regex-driven, because the format's real
//! edge cases are all about *state*:
//!   * `\` at end-of-line continues a value, but only inside a `hex` payload.
//!     A quoted string ending in `"C:\\"` must not be treated as a continuation.
//!   * `;` starts a comment only at the start of a *physical* line, and only when
//!     we are not in the middle of a hex continuation (regedit is inconsistent
//!     here, so we warn instead of guessing).
//!   * Inside quoted strings the only escapes are `\\` and `\"`.
//!     There is NO `\n`, `\t`, or `\0` - writing one produces a literal backslash.
//!   * A key name may itself contain `]`, so the terminator is the LAST `]`.

use crate::encoding::{decode_strict, source_encoding, SourceEncoding};
use crate::model::*;

#[derive(Debug)]
pub struct Diagnostic {
    pub line: usize,
    pub severity: Severity,
    pub message: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    Warning,
    Error,
}

#[derive(Debug)]
pub struct ParseOutcome {
    pub file: RegFile,
    pub diagnostics: Vec<Diagnostic>,
}

impl ParseOutcome {
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == Severity::Error)
    }
}

pub fn parse_bytes(bytes: &[u8]) -> ParseOutcome {
    match decode_strict(bytes) {
        Ok((text, encoding)) => parse_str(&text, encoding),
        Err(message) => ParseOutcome {
            file: RegFile {
                format: RegFormat::V5,
                encoding: source_encoding(bytes),
                keys: Vec::new(),
            },
            diagnostics: vec![Diagnostic {
                line: 0,
                severity: Severity::Error,
                message,
            }],
        },
    }
}

pub fn parse_str(text: &str, encoding: SourceEncoding) -> ParseOutcome {
    let mut p = Parser {
        diags: Vec::new(),
        keys: Vec::new(),
        current: None,
    };
    let format = p.run(text);
    ParseOutcome {
        file: RegFile {
            format,
            encoding,
            keys: p.keys,
        },
        diagnostics: p.diags,
    }
}

struct Parser {
    diags: Vec<Diagnostic>,
    keys: Vec<KeyBlock>,
    current: Option<KeyBlock>,
}

impl Parser {
    fn warn(&mut self, line: usize, msg: impl Into<String>) {
        self.diags.push(Diagnostic {
            line,
            severity: Severity::Warning,
            message: msg.into(),
        });
    }

    fn error(&mut self, line: usize, msg: impl Into<String>) {
        self.diags.push(Diagnostic {
            line,
            severity: Severity::Error,
            message: msg.into(),
        });
    }

    fn flush_key(&mut self) {
        if let Some(k) = self.current.take() {
            self.keys.push(k);
        }
    }

    fn run(&mut self, text: &str) -> RegFormat {
        let lines: Vec<&str> = text.split('\n').map(|l| l.trim_end_matches('\r')).collect();

        let mut format = RegFormat::V5;
        let mut idx = 0usize;

        // Header: first line that is neither blank nor a comment. Undo files we
        // generate carry a comment banner above the header, so this must skip
        // leading `;` lines rather than choking on them.
        while idx < lines.len() {
            let t = lines[idx].trim();
            if t.is_empty() || t.starts_with(';') {
                idx += 1;
            } else {
                break;
            }
        }
        match lines.get(idx).map(|l| l.trim()) {
            Some(h) if h.eq_ignore_ascii_case("REGEDIT4") => {
                format = RegFormat::V4;
                idx += 1;
            }
            Some(h)
                if h.to_ascii_lowercase()
                    .starts_with("windows registry editor version 5") =>
            {
                format = RegFormat::V5;
                idx += 1;
            }
            _ => {
                self.error(
                    idx + 1,
                    "missing .reg header (expected \"Windows Registry Editor Version 5.00\" or \"REGEDIT4\")",
                );
            }
        }

        // Fold physical lines into logical lines, honouring hex continuations.
        let mut pending: Option<(usize, String)> = None; // (start line, accumulated)
        while idx < lines.len() {
            let lineno = idx + 1;
            let raw = lines[idx];
            idx += 1;

            if let Some((start, mut acc)) = pending.take() {
                let t = raw.trim();
                if t.starts_with(';') {
                    self.warn(
                        lineno,
                        "comment inside a hex continuation - regedit.exe handles this inconsistently; the line is ignored",
                    );
                    pending = Some((start, acc));
                    continue;
                }
                let more = t.ends_with('\\');
                acc.push_str(if more {
                    t.trim_end_matches('\\').trim_end()
                } else {
                    t
                });
                if more {
                    pending = Some((start, acc));
                } else {
                    self.logical(start, &acc);
                }
                continue;
            }

            let t = raw.trim();
            if t.is_empty() || t.starts_with(';') {
                continue;
            }
            if is_hex_continuation(t) {
                pending = Some((lineno, t.trim_end_matches('\\').trim_end().to_string()));
                continue;
            }
            self.logical(lineno, t);
        }

        if let Some((start, acc)) = pending {
            self.warn(start, "file ends with a dangling `\\` continuation");
            self.logical(start, &acc);
        }

        self.flush_key();
        format
    }

    fn logical(&mut self, line: usize, s: &str) {
        if s.starts_with('[') {
            self.key_line(line, s);
        } else {
            self.value_line(line, s);
        }
    }

    fn key_line(&mut self, line: usize, s: &str) {
        let Some(close) = s.rfind(']') else {
            self.error(line, "unterminated key header (missing `]`)");
            return;
        };
        let inner = &s[1..close];
        let trailing = s[close + 1..].trim();
        if !trailing.is_empty() && !trailing.starts_with(';') {
            self.warn(line, format!("ignoring text after `]`: {trailing:?}"));
        }

        let (delete, path_str) = match inner.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, inner),
        };

        let Some(path) = RegPath::parse(path_str) else {
            self.error(line, format!("unknown root hive in key path {path_str:?}"));
            return;
        };

        // Real limit enforced by the API; catching it here beats a cryptic
        // ERROR_INVALID_PARAMETER at write time.
        if path
            .sub
            .split('\\')
            .any(|component| component.encode_utf16().count() > 255)
        {
            self.warn(line, "a key name component exceeds 255 UTF-16 code units");
        }

        self.flush_key();
        self.current = Some(KeyBlock {
            path,
            delete,
            values: Vec::new(),
            line,
        });
    }

    fn value_line(&mut self, line: usize, s: &str) {
        let (name, rest) = match parse_value_name(s) {
            Ok(v) => v,
            Err(e) => {
                self.error(line, e);
                return;
            }
        };

        let Some(rhs) = rest.strip_prefix('=') else {
            self.error(line, "expected `=` after value name");
            return;
        };
        let rhs = rhs.trim();

        let data = match self.parse_data(line, rhs) {
            Some(d) => d,
            None => return,
        };

        let Some(k) = self.current.as_mut() else {
            self.error(line, "value appears before any [key] header");
            return;
        };
        let in_delete_block = k.delete;
        k.values.push(ValueEntry { name, data, line });
        if in_delete_block {
            self.warn(line, "values under a `[-KEY]` delete block are ignored");
        }
    }

    fn parse_data(&mut self, line: usize, rhs: &str) -> Option<RegData> {
        if rhs == "-" {
            return Some(RegData::Delete);
        }
        if rhs.starts_with('"') {
            return match unquote(rhs) {
                Ok((s, tail)) => {
                    if !tail.trim().is_empty() {
                        self.warn(
                            line,
                            format!("ignoring text after string: {:?}", tail.trim()),
                        );
                    }
                    Some(RegData::Sz(s))
                }
                Err(e) => {
                    self.error(line, e);
                    None
                }
            };
        }
        let lower = rhs.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("dword:") {
            return match u32::from_str_radix(v.trim(), 16) {
                Ok(n) => Some(RegData::Dword(n)),
                Err(_) => {
                    self.error(line, format!("invalid dword literal {:?}", v.trim()));
                    None
                }
            };
        }
        if let Some(rest) = lower.strip_prefix("hex") {
            let (ty, payload) = if let Some(rest) = rest.strip_prefix('(') {
                let Some(close) = rest.find(')') else {
                    self.error(line, "unterminated `hex(` type specifier");
                    return None;
                };
                let Ok(ty) = u32::from_str_radix(rest[..close].trim(), 16) else {
                    self.error(line, format!("invalid hex type {:?}", &rest[..close]));
                    return None;
                };
                let Some(p) = rest[close + 1..].strip_prefix(':') else {
                    self.error(line, "expected `:` after `hex(N)`");
                    return None;
                };
                (ty, p)
            } else {
                let Some(p) = rest.strip_prefix(':') else {
                    self.error(line, format!("unrecognised data literal {rhs:?}"));
                    return None;
                };
                (REG_BINARY, p)
            };

            let mut bytes = Vec::new();
            for tok in payload.split(',') {
                let tok = tok.trim();
                if tok.is_empty() {
                    continue;
                }
                match u8::from_str_radix(tok, 16) {
                    Ok(b) => bytes.push(b),
                    Err(_) => {
                        self.error(line, format!("invalid hex byte {tok:?}"));
                        return None;
                    }
                }
            }
            self.check_hex_shape(line, ty, &bytes);
            return Some(RegData::Hex { ty, bytes });
        }

        self.error(line, format!("unrecognised data literal {rhs:?}"));
        None
    }

    /// Structural sanity checks that regedit will not give you, but that cause
    /// real "the app reads garbage" bugs downstream.
    fn check_hex_shape(&mut self, line: usize, ty: u32, bytes: &[u8]) {
        match ty {
            REG_SZ | REG_EXPAND_SZ | REG_LINK => {
                if !bytes.len().is_multiple_of(2) {
                    self.warn(
                        line,
                        "string payload has an odd byte count (not valid UTF-16LE)",
                    );
                } else if !bytes.ends_with(&[0, 0]) {
                    self.warn(
                        line,
                        "string payload is not NUL-terminated - consumers will read past the value",
                    );
                }
            }
            REG_MULTI_SZ => {
                if !bytes.len().is_multiple_of(2) {
                    self.warn(line, "REG_MULTI_SZ payload has an odd byte count");
                } else if !bytes.ends_with(&[0, 0, 0, 0]) && !bytes.is_empty() {
                    self.warn(
                        line,
                        "REG_MULTI_SZ must end with a double NUL (00,00,00,00)",
                    );
                }
            }
            REG_DWORD | REG_DWORD_BIG_ENDIAN => {
                if bytes.len() != 4 {
                    self.warn(
                        line,
                        format!("DWORD payload is {} bytes, expected 4", bytes.len()),
                    );
                }
            }
            REG_QWORD => {
                if bytes.len() != 8 {
                    self.warn(
                        line,
                        format!("QWORD payload is {} bytes, expected 8", bytes.len()),
                    );
                }
            }
            _ => {}
        }
        if bytes.len() > 1_048_576 {
            self.warn(
                line,
                "value exceeds 1 MB - Microsoft recommends a file reference instead",
            );
        }
    }
}

/// A physical line continues only if it is (or is inside) a hex payload.
/// `"p"="C:\\"` ends with `"`, so it never matches; `hex:01,02,\` does.
fn is_hex_continuation(t: &str) -> bool {
    if !t.ends_with('\\') {
        return false;
    }
    match t.split_once('=') {
        Some((_, rhs)) => rhs.trim_start().to_ascii_lowercase().starts_with("hex"),
        None => false,
    }
}

/// Split `"name"=...` or `@=...` into (name, remainder-starting-at-`=`).
fn parse_value_name(s: &str) -> Result<(ValueName, &str), String> {
    if let Some(rest) = s.strip_prefix('@') {
        return Ok((ValueName::Default, rest.trim_start()));
    }
    if s.starts_with('"') {
        let (name, tail) = unquote(s)?;
        if name.contains('\0') {
            return Err("value name contains an embedded NUL".into());
        }
        if name.encode_utf16().count() > 16_383 {
            return Err("value name exceeds the 16,383 UTF-16 code-unit limit".into());
        }
        return Ok((ValueName::Named(name), tail.trim_start()));
    }
    Err(format!("expected a quoted value name or `@`, found {s:?}"))
}

/// Consume a `.reg` quoted string starting at `s[0] == '"'`.
/// Returns the decoded content and the remaining input after the closing quote.
fn unquote(s: &str) -> Result<(String, &str), String> {
    let bytes = s.as_bytes();
    debug_assert_eq!(bytes[0], b'"');
    let mut out = String::new();
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return Ok((out, &s[i + 1..])),
            b'\\' => {
                // Only `\\` and `\"` are escapes. Anything else is a literal
                // backslash followed by that character - `\n` is NOT a newline.
                match bytes.get(i + 1) {
                    Some(b'\\') => {
                        out.push('\\');
                        i += 2;
                    }
                    Some(b'"') => {
                        out.push('"');
                        i += 2;
                    }
                    Some(_) => {
                        out.push('\\');
                        i += 1;
                    }
                    None => return Err("string ends with a lone backslash".into()),
                }
            }
            _ => {
                let ch = s[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    Err("unterminated string literal".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> ParseOutcome {
        parse_str(s, SourceEncoding::Utf16Le)
    }

    #[test]
    fn backslash_in_string_is_not_a_continuation() {
        let out = parse("Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\A]\r\n\"p\"=\"C:\\\\Temp\\\\\"\r\n");
        assert!(!out.has_errors(), "{:?}", out.diagnostics);
        let v = &out.file.keys[0].values[0];
        assert_eq!(v.data, RegData::Sz("C:\\Temp\\".into()));
    }

    #[test]
    fn hex_continuation_is_folded() {
        let out = parse(
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\A]\r\n\"b\"=hex:01,02,\\\r\n  03,04\r\n",
        );
        assert!(!out.has_errors(), "{:?}", out.diagnostics);
        assert_eq!(
            out.file.keys[0].values[0].data,
            RegData::Hex {
                ty: REG_BINARY,
                bytes: vec![1, 2, 3, 4]
            }
        );
    }

    #[test]
    fn typed_hex_and_delete_forms() {
        let out = parse(
            "REGEDIT4\r\n[-HKEY_CURRENT_USER\\Gone]\r\n[HKEY_CURRENT_USER\\A]\r\n@=\"def\"\r\n\"q\"=hex(b):01,00,00,00,00,00,00,00\r\n\"drop\"=-\r\n",
        );
        assert!(!out.has_errors(), "{:?}", out.diagnostics);
        assert_eq!(out.file.format, RegFormat::V4);
        assert!(out.file.keys[0].delete);
        let a = &out.file.keys[1];
        assert_eq!(a.values[0].name, ValueName::Default);
        assert_eq!(a.values[1].data.type_id(), Some(REG_QWORD));
        assert_eq!(a.values[2].data, RegData::Delete);
    }

    #[test]
    fn missing_multi_sz_terminator_warns() {
        let out = parse(
            "Windows Registry Editor Version 5.00\r\n[HKEY_CURRENT_USER\\A]\r\n\"m\"=hex(7):61,00\r\n",
        );
        assert!(!out.has_errors());
        assert!(out
            .diagnostics
            .iter()
            .any(|d| d.message.contains("double NUL")));
    }

    #[test]
    fn rejects_embedded_nul_and_counts_win32_utf16_limits() {
        let key = parse(
            "Windows Registry Editor Version 5.00\r\n\
             [HKEY_CURRENT_USER\\Visible\0Hidden]\r\n",
        );
        assert!(key.has_errors());
        assert!(key.file.keys.is_empty());

        let value = parse(
            "Windows Registry Editor Version 5.00\r\n\
             [HKEY_CURRENT_USER\\A]\r\n\
             \"Visible\0Hidden\"=\"x\"\r\n",
        );
        assert!(value.has_errors());
        assert!(value.file.keys[0].values.is_empty());

        let too_long = "😀".repeat(8_192); // 16,384 UTF-16 code units.
        let value = parse(&format!(
            "Windows Registry Editor Version 5.00\r\n\
             [HKEY_CURRENT_USER\\A]\r\n\
             \"{too_long}\"=\"x\"\r\n"
        ));
        assert!(value.has_errors());
        assert!(value
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("16,383 UTF-16")));
    }
}
