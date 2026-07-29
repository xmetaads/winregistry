//! Search the common registry-data model.
//!
//! Keeping this independent of live Win32 access means one implementation
//! searches files, policy formats, stdin, live keys, and eventually hives.

use crate::model::{self, KeyBlock, RegData, RegPath, ValueEntry, ValueName};
use regex::{Regex, RegexBuilder};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Field {
    Key,
    Name,
    Type,
    Data,
}

#[derive(Clone, Debug)]
pub struct Match {
    pub field: Field,
    pub path: RegPath,
    pub name: Option<ValueName>,
    pub type_name: Option<&'static str>,
    pub data: Option<String>,
    pub exact: Option<ValueEntry>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Substring,
    Glob,
    Regex,
}

pub enum Matcher {
    Substring { needle: String, exact_case: bool },
    Pattern(Regex),
}

impl Matcher {
    pub fn compile(pattern: &str, mode: Mode, case_sensitive: bool) -> Result<Self, String> {
        if mode == Mode::Substring {
            return Ok(Self::Substring {
                needle: if case_sensitive {
                    pattern.to_string()
                } else {
                    model::fold_str(pattern)
                },
                exact_case: case_sensitive,
            });
        }
        let expression = if mode == Mode::Glob {
            glob_regex(pattern)
        } else {
            pattern.to_string()
        };
        RegexBuilder::new(&expression)
            .case_insensitive(!case_sensitive)
            // User input must not compile an arbitrarily large automaton or
            // deeply nested expression in an interactive administration tool.
            .size_limit(2 * 1024 * 1024)
            .dfa_size_limit(2 * 1024 * 1024)
            .nest_limit(128)
            .build()
            .map(Self::Pattern)
            .map_err(|error| error.to_string())
    }

    fn is_match(&self, text: &str) -> bool {
        match self {
            Self::Substring { needle, exact_case } => {
                if *exact_case {
                    text.contains(needle)
                } else {
                    model::fold_str(text).contains(needle)
                }
            }
            Self::Pattern(regex) => regex.is_match(text),
        }
    }
}

fn expand_root_alias(pattern: &str) -> String {
    let (root, rest) = pattern
        .split_once('\\')
        .map_or((pattern, ""), |(root, rest)| (root, rest));
    let canonical = match root.to_ascii_uppercase().as_str() {
        "HKCU" => "HKEY_CURRENT_USER",
        "HKLM" => "HKEY_LOCAL_MACHINE",
        "HKCR" => "HKEY_CLASSES_ROOT",
        "HKU" => "HKEY_USERS",
        "HKCC" => "HKEY_CURRENT_CONFIG",
        _ => return pattern.to_string(),
    };
    if rest.is_empty() {
        canonical.to_string()
    } else {
        format!("{canonical}\\{rest}")
    }
}

fn glob_regex(glob: &str) -> String {
    let mut out = String::from("^");
    let mut chars = glob.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                out.push_str(".*");
            }
            '*' => out.push_str(r"[^\\]*"),
            '?' => out.push_str(r"[^\\]"),
            // Backslash is the registry path separator, not an escape token.
            '\\' => out.push_str(r"\\"),
            '[' | ']' | '(' | ')' | '{' | '}' | '.' | '+' | '^' | '$' | '|' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out.push('$');
    out
}

pub struct Filters {
    pub include: Vec<Matcher>,
    pub exclude: Vec<Matcher>,
}

impl Filters {
    pub fn compile_globs(
        include: &[String],
        exclude: &[String],
        case_sensitive: bool,
    ) -> Result<Self, String> {
        let compile = |patterns: &[String], kind: &str| {
            patterns
                .iter()
                .map(|pattern| {
                    Matcher::compile(&expand_root_alias(pattern), Mode::Glob, case_sensitive)
                        .map_err(|error| format!("invalid {kind} pattern {pattern:?}: {error}"))
                })
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(Self {
            include: compile(include, "include")?,
            exclude: compile(exclude, "exclude")?,
        })
    }

    pub fn allows(&self, path: &str) -> bool {
        (self.include.is_empty() || self.include.iter().any(|item| item.is_match(path)))
            && !self.exclude.iter().any(|item| item.is_match(path))
    }
}

pub struct ValueFilters {
    pub include: Vec<Matcher>,
    pub exclude: Vec<Matcher>,
}

impl ValueFilters {
    pub fn compile_globs(include: &[String], exclude: &[String]) -> Result<Self, String> {
        let compile = |patterns: &[String], kind: &str| {
            glob_matchers(patterns, false)
                .map_err(|error| format!("invalid {kind} value pattern: {error}"))
        };
        Ok(Self {
            include: compile(include, "include")?,
            exclude: compile(exclude, "exclude")?,
        })
    }

    pub fn is_active(&self) -> bool {
        !self.include.is_empty() || !self.exclude.is_empty()
    }

    pub fn allows(&self, name: &ValueName) -> bool {
        let name = match name {
            ValueName::Default => "@",
            ValueName::Named(name) => name,
        };
        (self.include.is_empty() || self.include.iter().any(|item| item.is_match(name)))
            && !self.exclude.iter().any(|item| item.is_match(name))
    }
}

pub fn glob_matchers(patterns: &[String], case_sensitive: bool) -> Result<Vec<Matcher>, String> {
    patterns
        .iter()
        .map(|pattern| Matcher::compile(pattern, Mode::Glob, case_sensitive))
        .collect()
}

impl Matcher {
    pub fn matches(&self, text: &str) -> bool {
        self.is_match(text)
    }
}

pub fn find(
    keys: &[KeyBlock],
    query: &Matcher,
    fields: &[Field],
    filters: &Filters,
    value_filters: &ValueFilters,
    limit: usize,
) -> Vec<Match> {
    let wanted = |field| fields.is_empty() || fields.contains(&field);
    let mut found = Vec::new();

    for key in keys {
        let path = key.path.to_string();
        if !filters.allows(&path) {
            continue;
        }
        if !value_filters.is_active() && wanted(Field::Key) && query.is_match(&path) {
            found.push(Match {
                field: Field::Key,
                path: key.path.clone(),
                name: None,
                type_name: None,
                data: None,
                exact: None,
            });
            if found.len() >= limit {
                break;
            }
        }

        for value in &key.values {
            if !value_filters.allows(&value.name) {
                continue;
            }
            let name = match &value.name {
                ValueName::Default => "",
                ValueName::Named(name) => name,
            };
            if wanted(Field::Name) && query.is_match(name) {
                found.push(value_match(Field::Name, key, value));
            }
            if found.len() >= limit {
                break;
            }

            let type_text = match value.data.type_id() {
                Some(id) => format!("{} {id} 0x{id:x}", value.data.type_name()),
                None => value.data.type_name().to_string(),
            };
            if wanted(Field::Type) && query.is_match(&type_text) {
                found.push(value_match(Field::Type, key, value));
            }
            if found.len() >= limit {
                break;
            }

            if wanted(Field::Data)
                && searchable_data(&value.data)
                    .iter()
                    .any(|text| query.is_match(text))
            {
                found.push(value_match(Field::Data, key, value));
            }
            if found.len() >= limit {
                break;
            }
        }
        if found.len() >= limit {
            break;
        }
    }
    found
}

fn value_match(field: Field, key: &KeyBlock, value: &crate::model::ValueEntry) -> Match {
    Match {
        field,
        path: key.path.clone(),
        name: Some(value.name.clone()),
        type_name: Some(value.data.type_name()),
        data: Some(value.data.preview()),
        exact: Some(value.clone()),
    }
}

fn searchable_data(data: &RegData) -> Vec<String> {
    match data {
        RegData::Delete => vec!["delete".into()],
        RegData::Sz(text) => vec![text.clone()],
        RegData::Dword(number) => {
            vec![number.to_string(), format!("0x{number:08x}")]
        }
        RegData::Hex { bytes, .. } => {
            let hex = bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let mut forms = vec![hex];
            if bytes.len() % 2 == 0 {
                forms.extend(model::utf16_from_bytes(bytes));
            }
            forms
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Hive, ValueEntry, REG_BINARY};

    fn sample() -> Vec<KeyBlock> {
        vec![KeyBlock {
            path: RegPath {
                hive: Hive::Hkcu,
                sub: "Software\\Tools".into(),
            },
            delete: false,
            values: vec![
                ValueEntry {
                    name: ValueName::Named("ServerName".into()),
                    data: RegData::Sz("example.test".into()),
                    line: 0,
                },
                ValueEntry {
                    name: ValueName::Named("Blob".into()),
                    data: RegData::Hex {
                        ty: REG_BINARY,
                        bytes: vec![0xde, 0xad, 0xbe, 0xef],
                    },
                    line: 0,
                },
            ],
            line: 0,
        }]
    }

    fn no_filters() -> Filters {
        Filters {
            include: vec![],
            exclude: vec![],
        }
    }

    fn no_value_filters() -> ValueFilters {
        ValueFilters {
            include: vec![],
            exclude: vec![],
        }
    }

    #[test]
    fn searches_each_field_case_insensitively() {
        let keys = sample();
        for (query, field) in [
            ("TOOLS", Field::Key),
            ("servername", Field::Name),
            ("reg_binary", Field::Type),
            ("ad be", Field::Data),
            ("example.TEST", Field::Data),
        ] {
            let matcher = Matcher::compile(query, Mode::Substring, false).unwrap();
            assert_eq!(
                find(
                    &keys,
                    &matcher,
                    &[field],
                    &no_filters(),
                    &no_value_filters(),
                    10
                )
                .len(),
                1
            );
        }
    }

    #[test]
    fn limit_applies_across_fields() {
        let keys = sample();
        let matcher = Matcher::compile("e", Mode::Substring, false).unwrap();
        assert_eq!(
            find(&keys, &matcher, &[], &no_filters(), &no_value_filters(), 2).len(),
            2
        );
    }

    #[test]
    fn glob_regex_and_path_filters_are_composed() {
        let keys = sample();
        let glob = Matcher::compile("Server*", Mode::Glob, false).unwrap();
        let filters = Filters::compile_globs(&["HKCU\\Software\\**".into()], &[], false).unwrap();
        assert_eq!(
            find(
                &keys,
                &glob,
                &[Field::Name],
                &filters,
                &no_value_filters(),
                10
            )
            .len(),
            1
        );

        let regex = Matcher::compile(r"^example\.(test|invalid)$", Mode::Regex, false).unwrap();
        assert_eq!(
            find(
                &keys,
                &regex,
                &[Field::Data],
                &filters,
                &no_value_filters(),
                10
            )
            .len(),
            1
        );

        let excluded = Filters {
            include: vec![],
            exclude: vec![Matcher::compile("**\\Tools", Mode::Glob, false).unwrap()],
        };
        assert!(find(
            &keys,
            &glob,
            &[Field::Name],
            &excluded,
            &no_value_filters(),
            10
        )
        .is_empty());
    }

    #[test]
    fn value_filters_scope_matches_and_suppress_key_only_results() {
        let keys = sample();
        let query = Matcher::compile("*", Mode::Glob, false).unwrap();
        let only_blob = ValueFilters::compile_globs(&["blob".into()], &[]).unwrap();
        let matches = find(&keys, &query, &[], &no_filters(), &only_blob, 10);
        assert_eq!(matches.len(), 3);
        assert!(matches.iter().all(|item| {
            item.field != Field::Key && item.name == Some(ValueName::Named("Blob".into()))
        }));

        let excluded = ValueFilters::compile_globs(&[], &["Server*".into()]).unwrap();
        let matches = find(&keys, &query, &[Field::Name], &no_filters(), &excluded, 10);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, Some(ValueName::Named("Blob".into())));
    }

    #[test]
    fn invalid_regex_is_reported() {
        assert!(Matcher::compile("(", Mode::Regex, false).is_err());
    }

    #[test]
    fn malformed_utf16_is_searchable_as_bytes_not_fabricated_text() {
        let data = RegData::Hex {
            ty: crate::model::REG_EXPAND_SZ,
            bytes: vec![0x00, 0xd8, 0x00, 0x00],
        };
        let forms = searchable_data(&data);
        assert_eq!(forms, vec!["00 d8 00 00"]);
        assert!(!forms.iter().any(|form| form.contains('\u{fffd}')));
    }
}
