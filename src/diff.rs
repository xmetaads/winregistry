//! Three-way capable comparison between any two sources of registry data.
//!
//! Either side may be a file in any supported format or a live registry key, so
//! the useful questions all reduce to one command:
//!
//! * `file` vs `file` — what changed between two exports?
//! * `file` vs `live` — has this machine drifted from the baseline?
//! * `live` vs `file` — what would importing this file actually change?
//! * `live` vs `live` — how do two branches of the registry differ?
//!
//! The output is a real `.reg` patch: applying it to the *left* side produces
//! the *right* side. That means a drift report is also the fix, and the inverse
//! patch is the rollback.
//!
//! Comparison is case-insensitive on key paths and value names, because the
//! registry is, but byte-exact on data — a `REG_SZ` and a `REG_EXPAND_SZ`
//! holding the same characters are a difference, not a match, since the
//! consuming application expands one and not the other.

use crate::model::*;
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Change {
    /// Present on the right, absent on the left.
    Added,
    /// Present on both, different data or type.
    Modified,
    /// Present on the left, absent on the right.
    Removed,
}

impl Change {
    pub fn sigil(self) -> char {
        match self {
            Change::Added => '+',
            Change::Modified => '~',
            Change::Removed => '-',
        }
    }
}

#[derive(Clone, Debug)]
pub struct ValueDiff {
    pub path: RegPath,
    pub name: ValueName,
    pub change: Change,
    pub left: Option<RegData>,
    pub right: Option<RegData>,
}

#[derive(Clone, Debug)]
pub struct KeyDiff {
    pub path: RegPath,
    pub change: Change,
}

#[derive(Debug, Default)]
pub struct Diff {
    pub keys: Vec<KeyDiff>,
    pub values: Vec<ValueDiff>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.values.is_empty()
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let count = |c: Change| {
            self.keys.iter().filter(|k| k.change == c).count()
                + self.values.iter().filter(|v| v.change == c).count()
        };
        (
            count(Change::Added),
            count(Change::Modified),
            count(Change::Removed),
        )
    }

    /// The patch that turns the left side into the right side.
    ///
    /// Ordering matters: removals are emitted last so a `[-KEY]` never deletes a
    /// key that an earlier block in the same file just populated.
    pub fn to_patch(&self) -> RegFile {
        let mut writes: BTreeMap<String, KeyBlock> = BTreeMap::new();
        let mut order: Vec<String> = Vec::new();

        let slot =
            |map: &mut BTreeMap<String, KeyBlock>, order: &mut Vec<String>, path: &RegPath| {
                let fold = path.fold();
                if !map.contains_key(&fold) {
                    order.push(fold.clone());
                    map.insert(
                        fold.clone(),
                        KeyBlock {
                            path: path.clone(),
                            delete: false,
                            values: Vec::new(),
                            line: 0,
                        },
                    );
                }
                fold
            };

        // Keys that exist only on the right must be created even when they hold
        // no values, or the patch silently loses them.
        for k in self.keys.iter().filter(|k| k.change == Change::Added) {
            slot(&mut writes, &mut order, &k.path);
        }

        for v in &self.values {
            match v.change {
                Change::Added | Change::Modified => {
                    let Some(data) = v.right.clone() else {
                        continue;
                    };
                    let fold = slot(&mut writes, &mut order, &v.path);
                    writes.get_mut(&fold).unwrap().values.push(ValueEntry {
                        name: v.name.clone(),
                        data,
                        line: 0,
                    });
                }
                Change::Removed => {
                    let fold = slot(&mut writes, &mut order, &v.path);
                    writes.get_mut(&fold).unwrap().values.push(ValueEntry {
                        name: v.name.clone(),
                        data: RegData::Delete,
                        line: 0,
                    });
                }
            }
        }

        let mut keys: Vec<KeyBlock> = order
            .into_iter()
            .filter_map(|f| writes.remove(&f))
            .filter(|b| {
                !b.values.is_empty()
                    || self
                        .keys
                        .iter()
                        .any(|k| k.change == Change::Added && k.path.fold() == b.path.fold())
            })
            .collect();

        // Deleted keys last, and deduplicated to their topmost ancestor so a
        // parent delete does not leave a redundant child delete behind it.
        let mut removed: Vec<&KeyDiff> = self
            .keys
            .iter()
            .filter(|k| k.change == Change::Removed)
            .collect();
        removed.sort_by_key(|k| k.path.fold());
        let mut kept: Vec<RegPath> = Vec::new();
        for k in removed {
            let f = k.path.fold();
            if kept.iter().any(|p| {
                let pf = p.fold();
                f == pf || f.starts_with(&format!("{pf}\\"))
            }) {
                continue;
            }
            kept.push(k.path.clone());
        }
        for path in kept {
            // A key being deleted makes any value writes into it pointless.
            keys.retain(|b| {
                let bf = b.path.fold();
                let pf = path.fold();
                bf != pf && !bf.starts_with(&format!("{pf}\\"))
            });
            keys.push(KeyBlock {
                path,
                delete: true,
                values: Vec::new(),
                line: 0,
            });
        }

        RegFile {
            format: RegFormat::V5,
            encoding: crate::encoding::SourceEncoding::Utf16Le,
            keys,
        }
    }
}

/// Compare two sets of key blocks.
pub fn compare(left: &[KeyBlock], right: &[KeyBlock]) -> Diff {
    let l = index(left);
    let r = index(right);
    let mut d = Diff::default();

    // Keys.
    for (fold, (path, _)) in &r {
        if !l.contains_key(fold) {
            d.keys.push(KeyDiff {
                path: path.clone(),
                change: Change::Added,
            });
        }
    }
    for (fold, (path, _)) in &l {
        if !r.contains_key(fold) {
            d.keys.push(KeyDiff {
                path: path.clone(),
                change: Change::Removed,
            });
        }
    }

    // Values.
    for (fold, (path, rvals)) in &r {
        let lvals = l.get(fold).map(|(_, v)| v);
        for (vfold, (name, rdata)) in rvals {
            match lvals.and_then(|m| m.get(vfold)) {
                None => d.values.push(ValueDiff {
                    path: path.clone(),
                    name: name.clone(),
                    change: Change::Added,
                    left: None,
                    right: Some(rdata.clone()),
                }),
                Some((_, ldata)) if ldata != rdata => d.values.push(ValueDiff {
                    path: path.clone(),
                    name: name.clone(),
                    change: Change::Modified,
                    left: Some(ldata.clone()),
                    right: Some(rdata.clone()),
                }),
                Some(_) => {}
            }
        }
    }
    for (fold, (path, lvals)) in &l {
        // Values under a key that no longer exists are covered by the key
        // removal; listing them again would double-count the change.
        if !r.contains_key(fold) {
            continue;
        }
        let rvals = r.get(fold).map(|(_, v)| v);
        for (vfold, (name, ldata)) in lvals {
            if rvals.map(|m| m.contains_key(vfold)).unwrap_or(false) {
                continue;
            }
            d.values.push(ValueDiff {
                path: path.clone(),
                name: name.clone(),
                change: Change::Removed,
                left: Some(ldata.clone()),
                right: None,
            });
        }
    }

    d.keys.sort_by(|a, b| a.path.fold().cmp(&b.path.fold()));
    d.values.sort_by(|a, b| {
        a.path
            .fold()
            .cmp(&b.path.fold())
            .then_with(|| fold_str(&a.name.to_string()).cmp(&fold_str(&b.name.to_string())))
    });
    d
}

/// Compare values without structural key changes.
///
/// Unlike [`compare`], removals under a key absent on the right remain
/// explicit value deletions. This is required for a scoped value-only patch:
/// deleting the whole key would also remove values outside the requested
/// selection.
pub fn compare_values(left: &[KeyBlock], right: &[KeyBlock]) -> Vec<ValueDiff> {
    let l = index(left);
    let r = index(right);
    let mut values = Vec::new();
    for (fold, (path, rvals)) in &r {
        let lvals = l.get(fold).map(|(_, values)| values);
        for (vfold, (name, rdata)) in rvals {
            match lvals.and_then(|items| items.get(vfold)) {
                None => values.push(ValueDiff {
                    path: path.clone(),
                    name: name.clone(),
                    change: Change::Added,
                    left: None,
                    right: Some(rdata.clone()),
                }),
                Some((_, ldata)) if ldata != rdata => values.push(ValueDiff {
                    path: path.clone(),
                    name: name.clone(),
                    change: Change::Modified,
                    left: Some(ldata.clone()),
                    right: Some(rdata.clone()),
                }),
                Some(_) => {}
            }
        }
    }
    for (fold, (path, lvals)) in &l {
        let rvals = r.get(fold).map(|(_, values)| values);
        for (vfold, (name, ldata)) in lvals {
            if rvals.is_some_and(|items| items.contains_key(vfold)) {
                continue;
            }
            values.push(ValueDiff {
                path: path.clone(),
                name: name.clone(),
                change: Change::Removed,
                left: Some(ldata.clone()),
                right: None,
            });
        }
    }
    values.sort_by(|a, b| {
        a.path
            .fold()
            .cmp(&b.path.fold())
            .then_with(|| fold_str(&a.name.to_string()).cmp(&fold_str(&b.name.to_string())))
    });
    values
}

type ValueIndex = BTreeMap<String, (ValueName, RegData)>;

/// Fold to a case-insensitive index. A `[-KEY]` block on either side means the
/// key is absent there, which is exactly how it should compare.
fn index(blocks: &[KeyBlock]) -> BTreeMap<String, (RegPath, ValueIndex)> {
    let mut out: BTreeMap<String, (RegPath, ValueIndex)> = BTreeMap::new();
    for b in blocks {
        let fold = b.path.fold();
        if b.delete {
            out.remove(&fold);
            continue;
        }
        let entry = out
            .entry(fold)
            .or_insert_with(|| (b.path.clone(), BTreeMap::new()));
        for v in &b.values {
            let key = fold_str(crate::engine::value_api_name(&v.name));
            if v.data == RegData::Delete {
                entry.1.remove(&key);
            } else {
                entry.1.insert(key, (v.name.clone(), v.data.clone()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(path: &str, values: &[(&str, RegData)]) -> KeyBlock {
        KeyBlock {
            path: RegPath::parse(path).unwrap(),
            delete: false,
            values: values
                .iter()
                .map(|(n, d)| ValueEntry {
                    name: crate::formats::value_name(n),
                    data: d.clone(),
                    line: 0,
                })
                .collect(),
            line: 0,
        }
    }

    #[test]
    fn detects_added_modified_and_removed() {
        let left = vec![block(
            "HKCU\\Software\\A",
            &[
                ("keep", RegData::Dword(1)),
                ("change", RegData::Sz("old".into())),
                ("gone", RegData::Dword(9)),
            ],
        )];
        let right = vec![block(
            "HKCU\\Software\\A",
            &[
                ("keep", RegData::Dword(1)),
                ("change", RegData::Sz("new".into())),
                ("added", RegData::Dword(2)),
            ],
        )];

        let d = compare(&left, &right);
        assert_eq!(d.counts(), (1, 1, 1));
        let by = |n: &str| d.values.iter().find(|v| v.name.to_string() == n).unwrap();
        assert_eq!(by("added").change, Change::Added);
        assert_eq!(by("change").change, Change::Modified);
        assert_eq!(by("gone").change, Change::Removed);
        assert!(d.values.iter().all(|v| v.name.to_string() != "keep"));
    }

    #[test]
    fn key_paths_and_value_names_compare_case_insensitively() {
        let left = vec![block("HKCU\\Software\\A", &[("Name", RegData::Dword(1))])];
        let right = vec![block("HKCU\\SOFTWARE\\a", &[("NAME", RegData::Dword(1))])];
        assert!(
            compare(&left, &right).is_empty(),
            "the registry is case-insensitive"
        );
    }

    #[test]
    fn same_text_in_a_different_type_is_a_difference() {
        let left = vec![block("HKCU\\A", &[("p", RegData::Sz("%TMP%".into()))])];
        let right = vec![block(
            "HKCU\\A",
            &[(
                "p",
                RegData::Hex {
                    ty: REG_EXPAND_SZ,
                    bytes: crate::value::utf16_nul("%TMP%"),
                },
            )],
        )];
        let d = compare(&left, &right);
        assert_eq!(d.counts(), (0, 1, 0), "one expands, the other does not");
    }

    #[test]
    fn patch_applied_to_left_yields_right() {
        let left = vec![block(
            "HKCU\\A",
            &[("x", RegData::Dword(1)), ("drop", RegData::Dword(5))],
        )];
        let right = vec![
            block("HKCU\\A", &[("x", RegData::Dword(2))]),
            block("HKCU\\B", &[("y", RegData::Sz("new".into()))]),
        ];

        let patch = compare(&left, &right).to_patch();
        // Replay the patch over the left side and re-compare.
        let mut merged = left.clone();
        merged.extend(patch.keys.clone());
        let (folded, _) = crate::coalesce::coalesce(merged);
        assert!(
            compare(&folded, &right).is_empty(),
            "patch did not reproduce the right side"
        );
    }

    #[test]
    fn a_removed_key_becomes_a_single_topmost_delete() {
        let left = vec![
            block("HKCU\\A", &[("x", RegData::Dword(1))]),
            block("HKCU\\A\\Child", &[("y", RegData::Dword(1))]),
        ];
        let patch = compare(&left, &[]).to_patch();
        let deletes: Vec<&KeyBlock> = patch.keys.iter().filter(|k| k.delete).collect();
        assert_eq!(
            deletes.len(),
            1,
            "the child delete is redundant: {:?}",
            patch.keys
        );
        assert_eq!(deletes[0].path.sub, "A");
    }

    #[test]
    fn an_empty_key_added_on_the_right_survives_the_patch() {
        let right = vec![block("HKCU\\Software\\Empty", &[])];
        let patch = compare(&[], &right).to_patch();
        assert_eq!(patch.keys.len(), 1);
        assert!(!patch.keys[0].delete);
    }

    #[test]
    fn a_delete_block_means_absent_on_that_side() {
        let mut del = block("HKCU\\A", &[]);
        del.delete = true;
        let left = vec![block("HKCU\\A", &[("x", RegData::Dword(1))]), del];
        let right = vec![block("HKCU\\A", &[("x", RegData::Dword(1))])];

        let d = compare(&left, &right);
        // The trailing [-KEY] wipes the key on the left, so both the key and
        // the value it carries are additions. Additions are counted at both
        // levels deliberately: the patch has to emit the value writes, so they
        // are real entries. Removals are not symmetric — a single [-KEY]
        // subsumes the values under it, so those are omitted rather than
        // double-counted.
        assert_eq!(d.counts(), (2, 0, 0));
        assert_eq!(d.keys.len(), 1);
        assert_eq!(d.keys[0].change, Change::Added);
        assert_eq!(d.values.len(), 1);

        // The important guarantee is still that the patch reconstructs `right`.
        let patch = compare(&left, &right).to_patch();
        let mut merged = left.clone();
        merged.extend(patch.keys);
        let (folded, _) = crate::coalesce::coalesce(merged);
        assert!(compare(&folded, &right).is_empty());
    }

    #[test]
    fn identical_inputs_produce_no_diff_and_an_empty_patch() {
        let a = vec![block("HKCU\\A", &[("x", RegData::Dword(1))])];
        let d = compare(&a, &a);
        assert!(d.is_empty());
        assert!(d.to_patch().keys.is_empty());
    }

    #[test]
    fn value_only_comparison_keeps_deletes_when_the_right_key_is_absent() {
        let left = vec![block(
            "HKCU\\A",
            &[
                ("selected", RegData::Dword(1)),
                ("untouched", RegData::Dword(2)),
            ],
        )];
        let values = compare_values(&left, &[]);
        assert_eq!(values.len(), 2);
        assert!(values.iter().all(|value| value.change == Change::Removed));

        let patch = Diff {
            keys: Vec::new(),
            values: values
                .into_iter()
                .filter(|value| value.name.to_string() == "selected")
                .collect(),
        }
        .to_patch();
        assert_eq!(patch.keys.len(), 1);
        assert!(!patch.keys[0].delete);
        assert_eq!(patch.keys[0].values.len(), 1);
        assert_eq!(patch.keys[0].values[0].data, RegData::Delete);
    }
}
