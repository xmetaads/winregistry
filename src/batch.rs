//! Versioned JSON batch manifests.

use crate::encoding;
use crate::formats;
use crate::model::{RegFile, RegFormat};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;

pub const SCHEMA_VERSION: u64 = 1;
pub const SCHEMA_URL: &str = "https://winregistry.org/schemas/batch-v1.json";
pub const RESULT_SCHEMA_URL: &str = "https://winregistry.org/schemas/batch-result-v1.json";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub struct Operation {
    pub id: String,
    pub file: RegFile,
}

pub fn read(path: &Path) -> Result<Vec<Operation>, String> {
    let bytes = crate::file_io::read_limited(path, MAX_MANIFEST_BYTES, "batch manifest")?;
    let root: Value =
        serde_json::from_slice(&bytes).map_err(|error| format!("invalid batch JSON: {error}"))?;
    if string_field(&root, "schema")? != SCHEMA_URL {
        return Err("batch manifest names an unknown schema".into());
    }
    let version = root
        .get("schemaVersion")
        .and_then(Value::as_u64)
        .ok_or("batch manifest is missing an integer schemaVersion")?;
    if version != SCHEMA_VERSION {
        return Err(format!(
            "unsupported batch schemaVersion {version}; expected {SCHEMA_VERSION}"
        ));
    }
    let items = root
        .get("operations")
        .and_then(Value::as_array)
        .ok_or("batch manifest is missing operations")?;
    if items.is_empty() {
        return Err("batch manifest contains no operations".into());
    }
    if items.len() > 10_000 {
        return Err("batch manifest exceeds the 10000-operation limit".into());
    }

    let mut ids = BTreeSet::new();
    let mut operations = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let id = string_field(item, "id")
            .map_err(|error| format!("operations[{index}]: {error}"))?
            .to_string();
        if id.is_empty() {
            return Err(format!("operations[{index}].id cannot be empty"));
        }
        if !ids.insert(id.to_lowercase()) {
            return Err(format!("duplicate batch operation id {id:?}"));
        }
        let keys = item
            .get("keys")
            .ok_or_else(|| format!("operations[{index}] is missing keys"))?;
        let registry = json!({ "keys": keys });
        let registry_bytes = serde_json::to_vec(&registry)
            .map_err(|error| format!("operations[{index}]: {error}"))?;
        let (keys, _) = formats::json::read(&registry_bytes)
            .map_err(|error| format!("operations[{index}] ({id}): {error}"))?;
        if keys.is_empty() {
            return Err(format!("operations[{index}] ({id}) contains no key blocks"));
        }
        operations.push(Operation {
            id,
            file: RegFile {
                format: RegFormat::V5,
                encoding: encoding::SourceEncoding::Utf16Le,
                keys,
            },
        });
    }
    Ok(operations)
}

fn string_field<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {name:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_ids_and_empty_operations() {
        let root = std::env::temp_dir().join(format!("regx-batch-{}.json", std::process::id()));
        std::fs::write(
            &root,
            format!(
                r#"{{"schema":"{SCHEMA_URL}","schemaVersion":1,"operations":[
                    {{"id":"A","keys":[{{"path":"HKCU\\Software\\A","values":[]}}]}},
                    {{"id":"a","keys":[{{"path":"HKCU\\Software\\B","values":[]}}]}}
                ]}}"#
            ),
        )
        .unwrap();
        assert!(read(&root).unwrap_err().contains("duplicate"));
        let _ = std::fs::remove_file(root);
    }
}
