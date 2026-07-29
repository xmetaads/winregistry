//! Undo snapshots.
//!
//! The registry gives us no transaction (KTM is deprecated and admin-adjacent),
//! so a failed merge leaves half-applied state. The compensation is to compute
//! the *inverse* of the pending change before touching anything, and write it as
//! an ordinary `.reg` file the user can double-click or feed back to `regx`.
//!
//! Inverse rules, per declared key:
//!   * `[-KEY]` that exists -> export the whole subtree, so undo recreates it.
//!   * key exists, value exists -> record the current data.
//!   * key exists, value absent -> record `"name"=-`.
//!   * key does not exist -> record `[-TOPMOST_MISSING_ANCESTOR]`, not `[-KEY]`.
//!     Deleting only the leaf would leave the intermediate keys we are about to
//!     create behind as empty shells.
//!
//! Ordering: restores first, removals last, so a restore never writes into a key
//! that an earlier removal just deleted.

use crate::engine::{self, Roots};
use crate::model::*;
use crate::winreg::{View, KEY_READ};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_UNDO_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub struct Snapshot {
    pub file: RegFile,
    /// Keys that will be created from scratch, deduplicated to their topmost
    /// missing ancestor.
    pub new_keys: Vec<String>,
    pub restored_values: usize,
    /// Keys we could not read; their prior state is NOT in the undo file.
    pub unreadable: Vec<(String, String)>,
}

impl Snapshot {
    pub fn is_complete(&self) -> bool {
        self.unreadable.is_empty()
    }
}

pub fn snapshot(roots: &Roots, file: &RegFile, view: View) -> Snapshot {
    let mut restores: Vec<KeyBlock> = Vec::new();
    let mut removals: Vec<KeyBlock> = Vec::new();
    let mut unreadable = Vec::new();
    let mut restored_values = 0usize;

    for block in &file.keys {
        let (root, sub) = roots.resolve(&block.path);

        if block.delete {
            match engine::export(roots, &block.path, view, true) {
                Ok((mut blocks, rep)) => {
                    restored_values += rep.values;
                    restores.append(&mut blocks);
                    for (p, e) in rep.skipped {
                        unreadable.push((p, e));
                    }
                }
                Err(e) if e.is_not_found() => {}
                Err(e) => unreadable.push((block.path.to_string(), e.to_string())),
            }
            continue;
        }

        let key = match root.open(&sub, KEY_READ, view) {
            Ok(k) => Some(k),
            Err(e) if e.is_not_found() => None,
            Err(e) => {
                unreadable.push((block.path.to_string(), e.to_string()));
                continue;
            }
        };

        let Some(key) = key else {
            // Whole key is new: undo is a delete of the topmost missing ancestor.
            let top = topmost_missing(roots, &block.path, view);
            removals.push(KeyBlock {
                path: top,
                delete: true,
                values: Vec::new(),
                line: 0,
            });
            continue;
        };

        let mut prior = Vec::new();
        for v in &block.values {
            let name = engine::value_api_name(&v.name);
            match key.get_value(name) {
                Ok(Some((ty, bytes))) => {
                    prior.push(ValueEntry {
                        name: v.name.clone(),
                        data: engine::raw_to_data(ty, &bytes),
                        line: 0,
                    });
                    restored_values += 1;
                }
                Ok(None) => prior.push(ValueEntry {
                    name: v.name.clone(),
                    data: RegData::Delete,
                    line: 0,
                }),
                Err(e) => unreadable.push((format!("{}\\{}", block.path, v.name), e.to_string())),
            }
        }
        if !prior.is_empty() {
            restores.push(KeyBlock {
                path: block.path.clone(),
                delete: false,
                values: prior,
                line: 0,
            });
        }
    }

    // Deduplicate removals: `[-A\B]` makes `[-A\B\C]` redundant.
    removals.sort_by_key(|k| k.path.fold());
    let mut kept: Vec<KeyBlock> = Vec::new();
    for r in removals {
        let f = r.path.fold();
        if kept
            .iter()
            .any(|k| f == k.path.fold() || f.starts_with(&format!("{}\\", k.path.fold())))
        {
            continue;
        }
        kept.push(r);
    }
    let new_keys = kept.iter().map(|k| k.path.to_string()).collect();

    let (mut keys, _) = crate::coalesce::coalesce(restores);
    keys.extend(kept);

    Snapshot {
        file: RegFile {
            format: RegFormat::V5,
            encoding: crate::encoding::SourceEncoding::Utf16Le,
            keys,
        },
        new_keys,
        restored_values,
        unreadable,
    }
}

/// Walk up from `path` to the highest ancestor that does not exist yet.
fn topmost_missing(roots: &Roots, path: &RegPath, view: View) -> RegPath {
    let (root, sub) = roots.resolve(path);
    let parts: Vec<&str> = sub.split('\\').filter(|s| !s.is_empty()).collect();
    for i in 1..=parts.len() {
        let prefix = parts[..i].join("\\");
        if root.open(&prefix, KEY_READ, view).is_err() {
            return RegPath {
                hive: path.hive,
                sub: prefix,
            };
        }
    }
    path.clone()
}

/// A unique undo path next to the source file.
///
/// Keeping it beside the input makes discovery straightforward, while the
/// shared suffix prevents concurrent operations on the same input from
/// overwriting one another.
pub fn default_path(source: &std::path::Path) -> std::path::PathBuf {
    let stem = source
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "regx".into());
    unique_path(
        source
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new(".")),
        &stem,
    )
}

/// A collision-resistant undo name in the current user's temporary directory.
///
/// PID separates concurrent processes, the monotonic sequence separates calls
/// within one process even when the clock has coarse resolution, and the
/// timestamp avoids reuse after Windows recycles a PID. This function has no
/// filesystem side effect, so callers can calculate a prospective path before
/// confirmation without violating the cancellation boundary.
pub fn temporary_path(operation: &str) -> std::path::PathBuf {
    unique_path(
        &std::env::temp_dir(),
        &format!("regx-{}", safe_component(operation)),
    )
}

fn safe_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn unique_path(directory: &std::path::Path, stem: &str) -> std::path::PathBuf {
    let sequence = TEMP_UNDO_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    directory.join(format!(
        "{stem}-{}-{nonce}-{sequence}.undo.reg",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::apply;
    use std::collections::HashSet;

    fn block(path: &str, values: Vec<(ValueName, RegData)>) -> KeyBlock {
        KeyBlock {
            path: RegPath::parse(path).unwrap(),
            delete: false,
            values: values
                .into_iter()
                .map(|(name, data)| ValueEntry {
                    name,
                    data,
                    line: 0,
                })
                .collect(),
            line: 0,
        }
    }

    #[test]
    fn temporary_undo_names_are_unique_and_sanitized_under_concurrency() {
        let threads = (0..16)
            .map(|_| {
                std::thread::spawn(|| {
                    (0..256)
                        .map(|_| temporary_path("copy/value"))
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let paths = threads
            .into_iter()
            .flat_map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(paths.len(), 4096);
        assert_eq!(
            paths.iter().collect::<HashSet<_>>().len(),
            paths.len(),
            "temporary undo allocator reused a path"
        );
        assert!(paths.iter().all(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("regx-copy-value-")
                        && name.ends_with(".undo.reg")
                        && !name.contains('/')
                        && !name.contains('\\')
                })
        }));
        assert!(
            paths.iter().all(|path| !path.exists()),
            "path allocation itself must not create an artifact"
        );

        let source = std::env::temp_dir().join("desired settings.reg");
        let adjacent = (0..1024).map(|_| default_path(&source)).collect::<Vec<_>>();
        assert_eq!(
            adjacent.iter().collect::<HashSet<_>>().len(),
            adjacent.len(),
            "source-adjacent undo allocator reused a path"
        );
        assert!(adjacent.iter().all(|path| {
            path.parent() == source.parent()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("desired settings-") && name.ends_with(".undo.reg")
                    })
                && !path.exists()
        }));
    }

    fn file(keys: Vec<KeyBlock>) -> RegFile {
        RegFile {
            format: RegFormat::V5,
            encoding: crate::encoding::SourceEncoding::Utf16Le,
            keys,
        }
    }

    #[test]
    fn undo_restores_prior_state_exactly() {
        let roots = Roots::live();
        let software = RegPath::parse("HKEY_CURRENT_USER\\Software").unwrap();
        if !engine::probe(&roots, &software, View::Native).writable {
            eprintln!("SKIPPED: HKCU\\Software is not writable on this host");
            return;
        }
        let base = "Software\\regx-undo-test";
        let root = RegPath::parse(&format!("HKEY_CURRENT_USER\\{base}")).unwrap();

        // Seed: one pre-existing key with one value.
        let seed = file(vec![block(
            &format!("HKEY_CURRENT_USER\\{base}"),
            vec![(
                ValueName::Named("keep".into()),
                RegData::Sz("before".into()),
            )],
        )]);
        assert!(apply(&roots, &seed, View::Native, false)
            .failures
            .is_empty());

        // Change: overwrite `keep`, add `added`, and create a nested new key.
        let change = file(vec![
            block(
                &format!("HKEY_CURRENT_USER\\{base}"),
                vec![
                    (ValueName::Named("keep".into()), RegData::Sz("after".into())),
                    (ValueName::Named("added".into()), RegData::Dword(7)),
                ],
            ),
            block(
                &format!("HKEY_CURRENT_USER\\{base}\\new\\deep"),
                vec![(ValueName::Named("x".into()), RegData::Dword(1))],
            ),
        ]);

        let snap = snapshot(&roots, &change, View::Native);
        assert!(snap.is_complete(), "{:?}", snap.unreadable);
        // Topmost missing ancestor is `new`, not `new\deep`.
        assert_eq!(snap.new_keys.len(), 1);
        assert!(snap.new_keys[0].ends_with("\\new"), "{:?}", snap.new_keys);

        assert!(apply(&roots, &change, View::Native, false)
            .failures
            .is_empty());

        // Roll back and verify we are byte-identical to the seed state.
        let r = apply(&roots, &snap.file, View::Native, false);
        assert!(r.failures.is_empty(), "{:?}", r.failures);

        let (blocks, _) = engine::export(&roots, &root, View::Native, true).unwrap();
        assert_eq!(blocks.len(), 1, "the created subtree should be gone");
        assert_eq!(blocks[0].values.len(), 1, "`added` should be gone");
        assert_eq!(blocks[0].values[0].data, RegData::Sz("before".into()));

        // Cleanup.
        let mut del = block(&format!("HKEY_CURRENT_USER\\{base}"), vec![]);
        del.delete = true;
        apply(&roots, &file(vec![del]), View::Native, false);
    }

    #[test]
    fn undo_of_a_delete_block_recreates_the_subtree() {
        let roots = Roots::live();
        let software = RegPath::parse("HKEY_CURRENT_USER\\Software").unwrap();
        if !engine::probe(&roots, &software, View::Native).writable {
            eprintln!("SKIPPED: HKCU\\Software is not writable on this host");
            return;
        }
        let base = "Software\\regx-undo-del";
        let root = RegPath::parse(&format!("HKEY_CURRENT_USER\\{base}")).unwrap();

        let seed = file(vec![
            block(
                &format!("HKEY_CURRENT_USER\\{base}"),
                vec![(ValueName::Default, RegData::Sz("top".into()))],
            ),
            block(
                &format!("HKEY_CURRENT_USER\\{base}\\sub"),
                vec![(ValueName::Named("n".into()), RegData::Dword(5))],
            ),
        ]);
        apply(&roots, &seed, View::Native, false);

        let mut del = block(&format!("HKEY_CURRENT_USER\\{base}"), vec![]);
        del.delete = true;
        let change = file(vec![del]);

        let snap = snapshot(&roots, &change, View::Native);
        assert_eq!(snap.file.keys.len(), 2);
        assert_eq!(snap.restored_values, 2);

        apply(&roots, &change, View::Native, false);
        assert!(engine::export(&roots, &root, View::Native, true).is_err());

        apply(&roots, &snap.file, View::Native, false);
        let (blocks, _) = engine::export(&roots, &root, View::Native, true).unwrap();
        assert_eq!(blocks.len(), 2);

        let mut cleanup = block(&format!("HKEY_CURRENT_USER\\{base}"), vec![]);
        cleanup.delete = true;
        apply(&roots, &file(vec![cleanup]), View::Native, false);
    }
}
