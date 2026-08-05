//! Parser for declarative shortcut manifests.
//!
//! The format is intentionally small and explicit:
//!
//! ```text
//! [SHORTCUT]
//! Target=C:\Program Files\Acme\Acme.exe
//! Output=shell:Startup\Acme.lnk
//! Arguments=--background
//! Style=hidden
//!
//! [DELETE_SHORTCUT]
//! Path=shell:Startup\Old Acme.lnk
//! ```

use crate::shortcut::{self, CreateOptions, ShowStyle};
use std::collections::BTreeMap;
use std::path::PathBuf;

const MAX_ACTIONS: usize = 1_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Create(CreateOptions),
    Delete(PathBuf),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub actions: Vec<Action>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockKind {
    Create,
    Delete,
}

pub fn parse(text: &str) -> Result<Manifest, String> {
    let mut actions = Vec::new();
    let mut current: Option<(BlockKind, usize, BTreeMap<String, String>)> = None;

    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(format!("line {line_number}: unterminated manifest block"));
            }
            if let Some(block) = current.take() {
                push_block(&mut actions, block)?;
            }
            let name = line[1..line.len() - 1].trim();
            let kind = if name.eq_ignore_ascii_case("SHORTCUT") {
                BlockKind::Create
            } else if name.eq_ignore_ascii_case("DELETE_SHORTCUT") {
                BlockKind::Delete
            } else {
                return Err(format!(
                    "line {line_number}: unsupported block [{name}]; expected [SHORTCUT] or [DELETE_SHORTCUT]"
                ));
            };
            current = Some((kind, line_number, BTreeMap::new()));
            continue;
        }

        let Some((_, _, fields)) = current.as_mut() else {
            return Err(format!(
                "line {line_number}: field appears before a [SHORTCUT] or [DELETE_SHORTCUT] block"
            ));
        };
        let Some((name, value)) = line.split_once('=') else {
            return Err(format!("line {line_number}: expected Name=Value"));
        };
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return Err(format!("line {line_number}: field name is empty"));
        }
        let value = unquote(value.trim(), line_number)?;
        if fields.insert(name.clone(), value).is_some() {
            return Err(format!("line {line_number}: duplicate field {name:?}"));
        }
    }
    if let Some(block) = current.take() {
        push_block(&mut actions, block)?;
    }
    if actions.is_empty() {
        return Err("shortcut manifest contains no actions".into());
    }
    if actions.len() > MAX_ACTIONS {
        return Err(format!(
            "shortcut manifest exceeds the {MAX_ACTIONS}-action limit"
        ));
    }
    Ok(Manifest { actions })
}

fn push_block(
    actions: &mut Vec<Action>,
    (kind, line, mut fields): (BlockKind, usize, BTreeMap<String, String>),
) -> Result<(), String> {
    match kind {
        BlockKind::Create => {
            reject_unknown(
                &fields,
                &[
                    "target",
                    "output",
                    "workdir",
                    "workingdirectory",
                    "args",
                    "arguments",
                    "description",
                    "icon",
                    "style",
                ],
                line,
            )?;
            reject_alias_pair(&fields, "workdir", "workingdirectory", line)?;
            reject_alias_pair(&fields, "args", "arguments", line)?;
            let target = required(&mut fields, "target", line)?;
            let output = required(&mut fields, "output", line)?;
            let working_directory = fields
                .remove("workdir")
                .or_else(|| fields.remove("workingdirectory"))
                .map(PathBuf::from);
            let arguments = fields.remove("args").or_else(|| fields.remove("arguments"));
            let description = fields.remove("description");
            let (icon_path, icon_index) = match fields.remove("icon") {
                Some(spec) => {
                    let (path, index) = shortcut::parse_icon_spec(&spec)
                        .map_err(|error| format!("block at line {line}: {error}"))?;
                    (Some(path), index)
                }
                None => (None, 0),
            };
            let style = match fields
                .remove("style")
                .unwrap_or_else(|| "normal".into())
                .to_ascii_lowercase()
                .as_str()
            {
                "normal" => ShowStyle::Normal,
                "hidden" => ShowStyle::Hidden,
                "minimized" => ShowStyle::Minimized,
                value => {
                    return Err(format!(
                        "block at line {line}: unsupported Style={value:?}; expected normal, hidden, or minimized"
                    ));
                }
            };
            actions.push(Action::Create(CreateOptions {
                target: PathBuf::from(target),
                output: PathBuf::from(output),
                working_directory,
                arguments,
                description,
                icon_path,
                icon_index,
                style,
            }));
        }
        BlockKind::Delete => {
            reject_unknown(&fields, &["path", "output"], line)?;
            reject_alias_pair(&fields, "path", "output", line)?;
            let path = fields
                .remove("path")
                .or_else(|| fields.remove("output"))
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("block at line {line}: [DELETE_SHORTCUT] requires Path"))?;
            actions.push(Action::Delete(PathBuf::from(path)));
        }
    }
    Ok(())
}

fn required(
    fields: &mut BTreeMap<String, String>,
    name: &str,
    line: usize,
) -> Result<String, String> {
    fields
        .remove(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("block at line {line}: [SHORTCUT] requires {name}"))
}

fn reject_unknown(
    fields: &BTreeMap<String, String>,
    allowed: &[&str],
    line: usize,
) -> Result<(), String> {
    if let Some(name) = fields.keys().find(|name| !allowed.contains(&name.as_str())) {
        return Err(format!("block at line {line}: unknown field {name:?}"));
    }
    Ok(())
}

fn reject_alias_pair(
    fields: &BTreeMap<String, String>,
    left: &str,
    right: &str,
    line: usize,
) -> Result<(), String> {
    if fields.contains_key(left) && fields.contains_key(right) {
        return Err(format!(
            "block at line {line}: {left} and {right} are aliases; specify only one"
        ));
    }
    Ok(())
}

fn unquote(value: &str, line: usize) -> Result<String, String> {
    if let Some(rest) = value.strip_prefix('"') {
        let Some(inner) = rest.strip_suffix('"') else {
            return Err(format!("line {line}: unterminated quoted value"));
        };
        if inner.contains('"') {
            return Err(format!(
                "line {line}: embedded quote is not supported in a quoted manifest value"
            ));
        }
        Ok(inner.to_string())
    } else {
        if value.ends_with('"') {
            return Err(format!("line {line}: unmatched quote in manifest value"));
        }
        Ok(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_repeated_create_and_delete_blocks() {
        let manifest = parse(
            r#"
            [SHORTCUT]
            Target="C:\Program Files\Acme\Acme.exe"
            Output=shell:Startup\Acme.lnk
            Arguments=--background
            Style=hidden

            [DELETE_SHORTCUT]
            Path=shell:Desktop\Old.lnk
            "#,
        )
        .unwrap();
        assert_eq!(manifest.actions.len(), 2);
        let Action::Create(create) = &manifest.actions[0] else {
            panic!("first action is not create")
        };
        assert_eq!(create.style, ShowStyle::Hidden);
        assert_eq!(create.arguments.as_deref(), Some("--background"));
    }

    #[test]
    fn rejects_unknown_duplicate_and_incomplete_fields() {
        assert!(parse("[SHORTCUT]\nTarget=x\nMystery=y\nOutput=z.lnk")
            .unwrap_err()
            .contains("unknown field"));
        assert!(parse("[SHORTCUT]\nTarget=x\nTarget=y\nOutput=z.lnk")
            .unwrap_err()
            .contains("duplicate field"));
        assert!(parse("[DELETE_SHORTCUT]\n")
            .unwrap_err()
            .contains("requires Path"));
    }
}
