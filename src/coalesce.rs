//! Key-block coalescing.
//!
//! A `.reg` file may legally mention the same key more than once, and Smart
//! Redirection makes collisions *routine*: `SOFTWARE\Acme` and
//! `SOFTWARE\WOW6432Node\Acme` both land on `HKCU\SOFTWARE\Acme`. Registry paths
//! are case-insensitive but case-preserving, so the grouping key is
//! `RegPath::fold()` while the emitted path keeps the first spelling seen.
//!
//! Semantics match regedit's own merge order: **last write wins**, and a
//! `[-KEY]` delete block resets everything declared for that key before it.

use crate::model::*;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Conflict {
    pub path: String,
    pub value: String,
    pub first_line: usize,
    pub last_line: usize,
    pub old: String,
    pub new: String,
}

#[derive(Debug, Default)]
pub struct CoalesceReport {
    pub blocks_merged: usize,
    pub conflicts: Vec<Conflict>,
}

/// Collapse duplicate key blocks in `keys`, preserving first-appearance order.
pub fn coalesce(keys: Vec<KeyBlock>) -> (Vec<KeyBlock>, CoalesceReport) {
    let mut order: Vec<String> = Vec::new();
    let mut slots: HashMap<String, KeyBlock> = HashMap::new();
    let mut report = CoalesceReport::default();

    for block in keys {
        let fold = block.path.fold();
        let Some(existing) = slots.get_mut(&fold) else {
            order.push(fold.clone());
            slots.insert(fold, block);
            continue;
        };
        report.blocks_merged += 1;

        if block.delete {
            // `[-KEY]` after value writes: the delete wins and discards them,
            // exactly as regedit applies the file top-to-bottom.
            existing.delete = true;
            existing.values.clear();
            continue;
        }
        if existing.delete {
            // Re-created after a delete: the key is dropped then repopulated.
            existing.delete = false;
            existing.values.clear();
        }

        for v in block.values {
            match existing
                .values
                .iter_mut()
                .find(|e| same_value(&e.name, &v.name))
            {
                Some(prev) => {
                    if prev.data != v.data {
                        report.conflicts.push(Conflict {
                            path: existing.path.to_string(),
                            value: v.name.to_string(),
                            first_line: prev.line,
                            last_line: v.line,
                            old: prev.data.preview(),
                            new: v.data.preview(),
                        });
                    }
                    *prev = v;
                }
                None => existing.values.push(v),
            }
        }
    }

    let out = order.into_iter().filter_map(|k| slots.remove(&k)).collect();
    (out, report)
}

/// Value names are case-insensitive too, and `@` is distinct from `""`
/// only in syntax - both address the key's default value.
fn same_value(a: &ValueName, b: &ValueName) -> bool {
    match (a, b) {
        (ValueName::Default, ValueName::Default) => true,
        (ValueName::Default, ValueName::Named(n)) | (ValueName::Named(n), ValueName::Default) => {
            n.is_empty()
        }
        (ValueName::Named(x), ValueName::Named(y)) => fold_str(x) == fold_str(y),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(path: &str, values: &[(&str, u32)]) -> KeyBlock {
        KeyBlock {
            path: RegPath::parse(path).unwrap(),
            delete: false,
            values: values
                .iter()
                .map(|(n, d)| ValueEntry {
                    name: ValueName::Named((*n).into()),
                    data: RegData::Dword(*d),
                    line: 0,
                })
                .collect(),
            line: 0,
        }
    }

    #[test]
    fn merges_case_insensitively_last_write_wins() {
        let (out, rep) = coalesce(vec![
            key("HKCU\\SOFTWARE\\Acme", &[("a", 1), ("b", 2)]),
            key("HKCU\\Software\\acme", &[("A", 9), ("c", 3)]),
        ]);
        assert_eq!(out.len(), 1);
        // First spelling is preserved.
        assert_eq!(out[0].path.sub, "SOFTWARE\\Acme");
        assert_eq!(out[0].values.len(), 3);
        assert_eq!(out[0].values[0].data, RegData::Dword(9));
        assert_eq!(rep.blocks_merged, 1);
        assert_eq!(rep.conflicts.len(), 1);
    }

    #[test]
    fn keys_windows_keeps_distinct_are_not_merged() {
        // `str::to_uppercase` maps ß to SS, so folding with it made these two
        // paths compare equal and merged them, discarding one key's values.
        // Windows uppercases per character and keeps them apart — verified
        // against the live registry, which creates two subkeys for these names.
        let (out, rep) = coalesce(vec![
            key("HKCU\\Software\\straße", &[("mark", 1)]),
            key("HKCU\\Software\\STRASSE", &[("mark", 2)]),
        ]);
        assert_eq!(out.len(), 2, "two distinct keys were merged: {out:?}");
        assert_eq!(rep.blocks_merged, 0);

        // The ligature has the same shape: ﬁ uppercases to FI.
        let (out, _) = coalesce(vec![
            key("HKCU\\Software\\ﬁle", &[("a", 1)]),
            key("HKCU\\Software\\FILE", &[("a", 2)]),
        ]);
        assert_eq!(out.len(), 2, "{out:?}");

        // Ordinary case folding must still work, in ASCII and beyond.
        let (out, rep) = coalesce(vec![
            key("HKCU\\Software\\Программа", &[("a", 1)]),
            key("HKCU\\Software\\ПРОГРАММА", &[("a", 2)]),
        ]);
        assert_eq!(out.len(), 1, "case-only differences must still merge");
        assert_eq!(rep.blocks_merged, 1);
    }

    #[test]
    fn identical_rewrite_is_not_a_conflict() {
        let (_, rep) = coalesce(vec![
            key("HKCU\\A", &[("x", 1)]),
            key("HKCU\\A", &[("x", 1)]),
        ]);
        assert!(rep.conflicts.is_empty());
    }

    #[test]
    fn delete_block_resets_earlier_values() {
        let mut del = key("HKCU\\A", &[]);
        del.delete = true;
        let (out, _) = coalesce(vec![key("HKCU\\A", &[("x", 1)]), del]);
        assert_eq!(out.len(), 1);
        assert!(out[0].delete);
        assert!(out[0].values.is_empty());
    }

    #[test]
    fn recreate_after_delete_clears_the_delete() {
        let mut del = key("HKCU\\A", &[]);
        del.delete = true;
        let (out, _) = coalesce(vec![del, key("HKCU\\A", &[("x", 1)])]);
        assert!(!out[0].delete);
        assert_eq!(out[0].values.len(), 1);
    }

    #[test]
    fn default_value_aliases_empty_name() {
        let a = KeyBlock {
            path: RegPath::parse("HKCU\\A").unwrap(),
            delete: false,
            values: vec![ValueEntry {
                name: ValueName::Default,
                data: RegData::Sz("one".into()),
                line: 1,
            }],
            line: 0,
        };
        let b = KeyBlock {
            path: RegPath::parse("HKCU\\A").unwrap(),
            delete: false,
            values: vec![ValueEntry {
                name: ValueName::Named(String::new()),
                data: RegData::Sz("two".into()),
                line: 2,
            }],
            line: 0,
        };
        let (out, rep) = coalesce(vec![a, b]);
        assert_eq!(out[0].values.len(), 1);
        assert_eq!(rep.conflicts.len(), 1);
    }
}
