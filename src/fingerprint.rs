//! Stable, payload-safe registry-state fingerprints.
//!
//! The digest covers exact case-preserved paths and value names, key/value
//! deletion state, numeric registry types, and raw payload bytes. Source order
//! and duplicate blocks do not affect it: inputs are coalesced with the same
//! last-write-wins rules used elsewhere, then sorted using Windows'
//! case-insensitive identity with exact spelling as a deterministic tie-break.

use crate::coalesce;
use crate::model::{fold_str, KeyBlock, RegData, ValueName};
use crate::sha256::Sha256;
use crate::value;

pub const VERSION: u32 = 1;
const DOMAIN: &[u8] = b"regx-registry-fingerprint-v1\0";

pub struct Result {
    pub sha256: String,
    pub conflicts: usize,
}

pub fn calculate(keys: Vec<KeyBlock>) -> Result {
    let (mut keys, report) = coalesce::coalesce(keys);
    keys.sort_by(|left, right| {
        left.path
            .fold()
            .cmp(&right.path.fold())
            .then_with(|| left.path.to_string().cmp(&right.path.to_string()))
    });

    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    put_u64(&mut hash, keys.len() as u64);
    for mut key in keys {
        put_bytes(&mut hash, key.path.to_string().as_bytes());
        hash.update(&[u8::from(key.delete)]);
        key.values.sort_by(|left, right| {
            let left_name = value_name(&left.name);
            let right_name = value_name(&right.name);
            fold_str(left_name)
                .cmp(&fold_str(right_name))
                .then_with(|| left_name.cmp(right_name))
        });
        put_u64(&mut hash, key.values.len() as u64);
        for entry in key.values {
            match &entry.name {
                ValueName::Default => hash.update(&[0]),
                ValueName::Named(name) => {
                    hash.update(&[1]);
                    put_bytes(&mut hash, name.as_bytes());
                }
            }
            match &entry.data {
                RegData::Delete => hash.update(&[0]),
                data => {
                    hash.update(&[1]);
                    let (ty, raw) =
                        value::data_to_raw(data).expect("non-delete registry data has raw bytes");
                    hash.update(&ty.to_le_bytes());
                    put_bytes(&mut hash, &raw);
                }
            }
        }
    }

    Result {
        sha256: hash
            .finish()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        conflicts: report.conflicts.len(),
    }
}

fn value_name(name: &ValueName) -> &str {
    match name {
        ValueName::Default => "",
        ValueName::Named(name) => name,
    }
}

fn put_bytes(hash: &mut Sha256, bytes: &[u8]) {
    put_u64(hash, bytes.len() as u64);
    hash.update(bytes);
}

fn put_u64(hash: &mut Sha256, value: u64) {
    hash.update(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Hive, RegPath, ValueEntry};

    fn block(path: &str, values: Vec<(&str, RegData)>) -> KeyBlock {
        KeyBlock {
            path: RegPath {
                hive: Hive::Hkcu,
                sub: path.into(),
            },
            delete: false,
            values: values
                .into_iter()
                .map(|(name, data)| ValueEntry {
                    name: ValueName::Named(name.into()),
                    data,
                    line: 1,
                })
                .collect(),
            line: 1,
        }
    }

    #[test]
    fn source_order_does_not_change_the_fingerprint() {
        let a = block("Software\\A", vec![("z", RegData::Dword(1))]);
        let b = block("Software\\B", vec![("a", RegData::Sz("x".into()))]);
        assert_eq!(
            calculate(vec![a.clone(), b.clone()]).sha256,
            calculate(vec![b, a]).sha256
        );
    }

    #[test]
    fn exact_type_and_payload_changes_change_the_fingerprint() {
        let dword = block("Software\\A", vec![("v", RegData::Dword(1))]);
        let raw = block(
            "Software\\A",
            vec![(
                "v",
                RegData::Hex {
                    ty: crate::model::REG_BINARY,
                    bytes: 1u32.to_le_bytes().to_vec(),
                },
            )],
        );
        assert_ne!(calculate(vec![dword]).sha256, calculate(vec![raw]).sha256);
    }
}
