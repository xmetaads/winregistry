//! Auto-repair for `.reg` files found in the wild.
//!
//! Files copied out of forum posts, blog code blocks and chat clients arrive
//! damaged in a small number of very predictable ways. Each repair below is
//! either **safe** (the result is unambiguously what the author meant) or
//! **lossy** (bytes change). Lossy repairs are still applied - the file is
//! already broken - but they are reported separately so the user can judge.

use crate::model::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Safe,
    Lossy,
}

#[derive(Debug)]
pub struct Fix {
    pub line: usize,
    pub class: Class,
    pub what: String,
}

#[derive(Debug, Default)]
pub struct FixReport {
    pub fixes: Vec<Fix>,
    /// Problems detected but deliberately not touched.
    pub unfixable: Vec<(usize, String)>,
}

impl FixReport {
    pub fn lossy_count(&self) -> usize {
        self.fixes
            .iter()
            .filter(|f| f.class == Class::Lossy)
            .count()
    }
}

/// Scan the *raw text* for damage the parser silently absorbs, so `--fix` can
/// report it even though re-emitting the model already normalises it.
pub fn scan_raw(text: &str) -> Vec<Fix> {
    let mut out = Vec::new();
    for (i, line) in text.split('\n').enumerate() {
        let line = line.trim_end_matches('\r');
        let trimmed = line.trim_end();
        // A continuation marker followed by trailing blanks: regedit stops folding
        // the value and the rest of the payload is lost.
        if trimmed.ends_with('\\') && line.len() != trimmed.len() {
            out.push(Fix {
                line: i + 1,
                class: Class::Safe,
                what: format!(
                    "removed {} trailing space(s) after the `\\` continuation marker",
                    line.len() - trimmed.len()
                ),
            });
        }
        if line.contains('\t') && line.trim_start().starts_with('"') {
            out.push(Fix {
                line: i + 1,
                class: Class::Safe,
                what: "normalised a literal tab in a value line".into(),
            });
        }
    }
    out
}

/// Repair the parsed model in place.
pub fn repair(file: &mut RegFile) -> FixReport {
    let mut r = FixReport::default();

    for key in &mut file.keys {
        // --- Control characters in the key path -----------------------------
        // These cannot be created through the API and usually come from a copy
        // that swallowed a line break inside a long path.
        if key.path.sub.chars().any(is_control) {
            let before = key.path.sub.clone();
            key.path.sub = key.path.sub.chars().filter(|c| !is_control(*c)).collect();
            r.fixes.push(Fix {
                line: key.line,
                class: Class::Safe,
                what: format!(
                    "stripped control character(s) from key path {before:?} -> {:?}",
                    key.path.sub
                ),
            });
        }
        // Empty path components (`A\\\\B`) are equally impossible.
        if key.path.sub.contains("\\\\") {
            key.path.sub = key
                .path
                .sub
                .split('\\')
                .filter(|c| !c.is_empty())
                .collect::<Vec<_>>()
                .join("\\");
            r.fixes.push(Fix {
                line: key.line,
                class: Class::Safe,
                what: "collapsed empty components in the key path".into(),
            });
        }

        for v in &mut key.values {
            if let ValueName::Named(n) = &v.name {
                if n.chars().any(is_control) {
                    let cleaned: String = n.chars().filter(|c| !is_control(*c)).collect();
                    r.fixes.push(Fix {
                        line: v.line,
                        class: Class::Safe,
                        what: format!("stripped control character(s) from value name {n:?}"),
                    });
                    v.name = ValueName::Named(cleaned);
                }
            }

            let RegData::Hex { ty, bytes } = &mut v.data else {
                continue;
            };
            let ty = *ty;

            match ty {
                REG_SZ | REG_EXPAND_SZ | REG_LINK => {
                    if bytes.len() % 2 != 0 {
                        bytes.push(0);
                        r.fixes.push(Fix {
                            line: v.line,
                            class: Class::Lossy,
                            what: "padded an odd-length UTF-16 payload with one NUL byte".into(),
                        });
                    }
                    if !bytes.is_empty() && !bytes.ends_with(&[0, 0]) {
                        bytes.extend_from_slice(&[0, 0]);
                        r.fixes.push(Fix {
                            line: v.line,
                            class: Class::Safe,
                            what: format!(
                                "appended the missing NUL terminator to a {} payload",
                                type_label(ty)
                            ),
                        });
                    }
                }
                REG_MULTI_SZ => {
                    if bytes.len() % 2 != 0 {
                        bytes.push(0);
                        r.fixes.push(Fix {
                            line: v.line,
                            class: Class::Lossy,
                            what: "padded an odd-length REG_MULTI_SZ payload with one NUL byte"
                                .into(),
                        });
                    }
                    if !bytes.is_empty() && !bytes.ends_with(&[0, 0, 0, 0]) {
                        // Each string is NUL-terminated and the list ends with an
                        // extra empty string, i.e. a trailing double NUL.
                        let before = bytes.len();
                        while !bytes.ends_with(&[0, 0, 0, 0]) {
                            bytes.extend_from_slice(&[0, 0]);
                        }
                        r.fixes.push(Fix {
                            line: v.line,
                            class: Class::Safe,
                            what: format!(
                                "appended {} byte(s) to terminate a REG_MULTI_SZ list",
                                bytes.len() - before
                            ),
                        });
                    }
                }
                REG_DWORD | REG_DWORD_BIG_ENDIAN => {
                    if bytes.len() != 4 {
                        r.unfixable.push((
                            v.line,
                            format!(
                                "DWORD payload is {} bytes; refusing to guess the intended value",
                                bytes.len()
                            ),
                        ));
                    }
                }
                REG_QWORD => {
                    if bytes.len() != 8 {
                        r.unfixable.push((
                            v.line,
                            format!("QWORD payload is {} bytes; refusing to guess", bytes.len()),
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    // Duplicate key blocks are a defect in a hand-edited file just as much as a
    // redirection artefact - fold them with the same last-write-wins rule.
    let keys = std::mem::take(&mut file.keys);
    let (merged, report) = crate::coalesce::coalesce(keys);
    if report.blocks_merged > 0 {
        r.fixes.push(Fix {
            line: 0,
            class: if report.conflicts.is_empty() {
                Class::Safe
            } else {
                Class::Lossy
            },
            what: format!(
                "merged {} duplicate key block(s); {} value conflict(s) resolved last-write-wins",
                report.blocks_merged,
                report.conflicts.len()
            ),
        });
    }
    file.keys = merged;

    r
}

fn type_label(ty: u32) -> &'static str {
    match ty {
        REG_SZ => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        REG_LINK => "REG_LINK",
        REG_MULTI_SZ => "REG_MULTI_SZ",
        _ => "string",
    }
}

fn is_control(c: char) -> bool {
    let u = c as u32;
    u < 0x20 || u == 0x7f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::SourceEncoding;
    use crate::parser::parse_str;

    fn parse(s: &str) -> RegFile {
        let o = parse_str(s, SourceEncoding::Utf16Le);
        assert!(!o.has_errors(), "{:?}", o.diagnostics);
        o.file
    }

    #[test]
    fn appends_missing_string_terminator() {
        let mut f = parse(
            "Windows Registry Editor Version 5.00\r\n[HKEY_CURRENT_USER\\A]\r\n\"s\"=hex(2):25,00,50,00,41,00,54,00,48,00\r\n",
        );
        let r = repair(&mut f);
        assert_eq!(r.lossy_count(), 0);
        assert!(r.fixes.iter().any(|x| x.what.contains("NUL terminator")));
        let RegData::Hex { bytes, .. } = &f.keys[0].values[0].data else {
            panic!()
        };
        assert!(bytes.ends_with(&[0, 0]));
    }

    #[test]
    fn repairs_multi_sz_double_nul() {
        let mut f = parse(
            "Windows Registry Editor Version 5.00\r\n[HKEY_CURRENT_USER\\A]\r\n\"m\"=hex(7):61,00\r\n",
        );
        let r = repair(&mut f);
        let RegData::Hex { bytes, .. } = &f.keys[0].values[0].data else {
            panic!()
        };
        assert!(bytes.ends_with(&[0, 0, 0, 0]), "{bytes:?}");
        assert!(r.unfixable.is_empty(), "{:?}", r.unfixable);
    }

    #[test]
    fn strips_control_characters_from_paths() {
        let mut f = parse(
            "Windows Registry Editor Version 5.00\r\n[HKEY_CURRENT_USER\\So\u{1}ftware\\A]\r\n\"x\"=dword:00000001\r\n",
        );
        let r = repair(&mut f);
        assert_eq!(f.keys[0].path.sub, "Software\\A");
        assert!(r.fixes.iter().any(|x| x.what.contains("control character")));
    }

    #[test]
    fn odd_length_payload_is_flagged_lossy() {
        let mut f = parse(
            "Windows Registry Editor Version 5.00\r\n[HKEY_CURRENT_USER\\A]\r\n\"s\"=hex(1):41,00,42\r\n",
        );
        let r = repair(&mut f);
        assert_eq!(r.lossy_count(), 1, "{:?}", r.fixes);
    }

    #[test]
    fn dword_of_wrong_length_is_not_guessed() {
        let mut f = parse(
            "Windows Registry Editor Version 5.00\r\n[HKEY_CURRENT_USER\\A]\r\n\"d\"=hex(4):01,02\r\n",
        );
        let r = repair(&mut f);
        assert_eq!(r.unfixable.len(), 1);
        assert!(r.fixes.iter().all(|f| !f.what.contains("DWORD")));
    }

    #[test]
    fn scan_raw_finds_whitespace_after_continuation() {
        let fixes = scan_raw("\"b\"=hex:01,\\   \r\n  02\r\n");
        assert_eq!(fixes.len(), 1);
        assert!(fixes[0].what.contains("trailing space"));
    }
}
