//! Digest-bound copy/move collision-preview artifacts.

use crate::encoding;
use crate::formats;
use crate::model::{RegFile, RegFormat, RegPath, ValueName};
use crate::saved_plan;
use crate::sha256;
use crate::undo;
use crate::winreg::View;
use crate::writer;
use serde_json::{json, Value};
use std::path::Path;

pub const SCHEMA_VERSION: u64 = 2;
pub const SCHEMA_URL: &str = "https://winregistry.org/schemas/copy-plan-v2.json";
pub const RESULT_SCHEMA_URL: &str = "https://winregistry.org/schemas/copy-plan-result-v2.json";
const LEGACY_SCHEMA_URL: &str = "https://winregistry.org/schemas/copy-plan-v1.json";
const MAX_PLAN_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub struct Artifact {
    pub operation: String,
    pub view: View,
    pub source_computer: Option<String>,
    pub source: RegPath,
    pub destination: RegPath,
    pub source_value: Option<ValueName>,
    pub destination_value: Option<ValueName>,
    pub overwrite: bool,
    pub source_digest: String,
    pub current_digest: String,
    pub copy_file: RegFile,
    pub delete_file: RegFile,
}

pub struct SaveInput<'a> {
    pub operation: &'a str,
    pub view_label: &'a str,
    pub source_computer: Option<&'a str>,
    pub source: &'a RegPath,
    pub destination: &'a RegPath,
    pub source_value: Option<&'a ValueName>,
    pub destination_value: Option<&'a ValueName>,
    pub overwrite: bool,
    pub source_file: &'a RegFile,
    pub copy_file: &'a RegFile,
    pub delete_file: &'a RegFile,
    pub current: &'a undo::Snapshot,
}

pub fn save(destination: &Path, input: SaveInput<'_>) -> Result<(), String> {
    if destination.exists() {
        return Err(format!(
            "{} already exists; refusing to overwrite a copy/move plan",
            destination.display()
        ));
    }
    if !input.current.is_complete() {
        return Err("copy/move plan has an incomplete current-state snapshot".into());
    }
    if input.source_computer.is_some() && input.operation != "copy" {
        return Err("remote-source plans can only copy; remote move is forbidden".into());
    }
    let copy_json = registry_json(input.copy_file)?;
    let delete_json = registry_json(input.delete_file)?;
    let payload = json!({
        "tool": env!("CARGO_PKG_NAME"),
        "toolVersion": env!("CARGO_PKG_VERSION"),
        "operation": input.operation,
        "view": input.view_label,
        "sourceComputer": input.source_computer,
        "source": input.source.to_string(),
        "destination": input.destination.to_string(),
        "scope": if input.source_value.is_some() { "value" } else { "subtree" },
        "sourceValue": input.source_value.map(value_name_json),
        "destinationValue": input.destination_value.map(value_name_json),
        "overwrite": input.overwrite,
        "sourceDigest": saved_plan::file_digest(input.source_file),
        "currentDigest": saved_plan::snapshot_digest(input.current),
        "copyDigest": saved_plan::file_digest(input.copy_file),
        "deleteDigest": saved_plan::file_digest(input.delete_file),
        "copy": copy_json,
        "removeSource": delete_json,
    });
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|error| format!("cannot encode copy/move plan payload: {error}"))?;
    let artifact = json!({
        "schema": SCHEMA_URL,
        "schemaVersion": SCHEMA_VERSION,
        "payloadSha256": sha256::hash_hex(&payload_bytes),
        "payload": payload,
    });
    let mut bytes = serde_json::to_vec_pretty(&artifact)
        .map_err(|error| format!("cannot encode copy/move plan: {error}"))?;
    bytes.push(b'\n');
    crate::file_io::atomic_write(destination, &bytes)
        .map_err(|error| format!("cannot write {}: {error}", destination.display()))
}

pub fn load(path: &Path) -> Result<Artifact, String> {
    let bytes = crate::file_io::read_limited(path, MAX_PLAN_BYTES, "copy/move plan")?;
    let root: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid copy/move plan JSON: {error}"))?;
    let schema = string_field(&root, "schema")?;
    if schema != SCHEMA_URL && schema != LEGACY_SCHEMA_URL {
        return Err("copy/move plan names an unknown schema".into());
    }
    let version = root
        .get("schemaVersion")
        .and_then(Value::as_u64)
        .ok_or("copy/move plan is missing an integer schemaVersion")?;
    if (schema == SCHEMA_URL && version != SCHEMA_VERSION)
        || (schema == LEGACY_SCHEMA_URL && version != 1)
    {
        return Err(format!(
            "unsupported copy/move plan schemaVersion {version} for {schema}"
        ));
    }
    let payload = root
        .get("payload")
        .ok_or("copy/move plan is missing payload")?;
    let expected_payload = string_field(&root, "payloadSha256")?;
    let payload_bytes = serde_json::to_vec(payload)
        .map_err(|error| format!("cannot canonicalize copy/move plan payload: {error}"))?;
    let actual_payload = sha256::hash_hex(&payload_bytes);
    if actual_payload != expected_payload {
        return Err(format!(
            "copy/move plan payload digest mismatch (expected {expected_payload}, found {actual_payload})"
        ));
    }

    let operation = string_field(payload, "operation")?.to_string();
    if operation != "copy" && operation != "move" {
        return Err(format!("unknown copy/move operation {operation:?}"));
    }
    let label = string_field(payload, "view")?;
    let view = match label {
        "native" => View::Native,
        "32" => View::Bits32,
        "64" => View::Bits64,
        other => return Err(format!("unknown registry view {other:?}")),
    };
    let source = RegPath::parse(string_field(payload, "source")?)
        .ok_or("copy/move plan has an invalid source path")?;
    let destination = RegPath::parse(string_field(payload, "destination")?)
        .ok_or("copy/move plan has an invalid destination path")?;
    let (source_value, destination_value) = if version == 1 {
        (None, None)
    } else {
        match string_field(payload, "scope")? {
            "subtree" => {
                if !payload.get("sourceValue").is_some_and(Value::is_null)
                    || !payload.get("destinationValue").is_some_and(Value::is_null)
                {
                    return Err("subtree plan must have null value names".into());
                }
                (None, None)
            }
            "value" => (
                Some(value_name_field(payload, "sourceValue")?),
                Some(value_name_field(payload, "destinationValue")?),
            ),
            other => return Err(format!("unknown copy/move plan scope {other:?}")),
        }
    };
    let copy_file = registry_file(payload, "copy")?;
    let delete_file = registry_file(payload, "removeSource")?;
    let source_computer = match payload.get("sourceComputer") {
        Some(Value::Null) | None => None,
        Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
        _ => return Err("copy/move plan has an invalid sourceComputer".into()),
    };
    verify_file_digest(payload, "copyDigest", &copy_file)?;
    verify_file_digest(payload, "deleteDigest", &delete_file)?;
    if operation == "copy" && !delete_file.keys.is_empty() {
        return Err("copy plan unexpectedly contains source deletion".into());
    }
    if operation == "move" && delete_file.keys.len() != 1 {
        return Err("move plan must contain exactly one source deletion".into());
    }
    if source_computer.is_some() && operation != "copy" {
        return Err("remote-source plans can only copy; remote move is forbidden".into());
    }

    Ok(Artifact {
        operation,
        view,
        source_computer,
        source,
        destination,
        source_value,
        destination_value,
        overwrite: payload
            .get("overwrite")
            .and_then(Value::as_bool)
            .ok_or("copy/move plan is missing boolean overwrite")?,
        source_digest: string_field(payload, "sourceDigest")?.to_string(),
        current_digest: string_field(payload, "currentDigest")?.to_string(),
        copy_file,
        delete_file,
    })
}

fn value_name_json(name: &ValueName) -> &str {
    match name {
        ValueName::Default => "",
        ValueName::Named(name) => name,
    }
}

fn value_name_field(payload: &Value, name: &str) -> Result<ValueName, String> {
    let value = string_field(payload, name)?;
    Ok(if value.is_empty() {
        ValueName::Default
    } else {
        ValueName::Named(value.to_string())
    })
}

fn registry_json(file: &RegFile) -> Result<Value, String> {
    serde_json::from_str(&writer::to_json(file))
        .map_err(|error| format!("cannot serialize registry state: {error}"))
}

fn registry_file(payload: &Value, name: &str) -> Result<RegFile, String> {
    let value = payload
        .get(name)
        .ok_or_else(|| format!("copy/move plan is missing {name}"))?;
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("cannot decode copy/move plan {name}: {error}"))?;
    let (keys, _) = formats::json::read(&bytes)
        .map_err(|error| format!("invalid copy/move plan {name}: {error}"))?;
    Ok(RegFile {
        format: RegFormat::V5,
        encoding: encoding::SourceEncoding::Utf16Le,
        keys,
    })
}

fn verify_file_digest(payload: &Value, name: &str, file: &RegFile) -> Result<(), String> {
    let expected = string_field(payload, name)?;
    let actual = saved_plan::file_digest(file);
    if expected == actual {
        Ok(())
    } else {
        Err(format!(
            "copy/move plan {name} mismatch (expected {expected}, found {actual})"
        ))
    }
}

fn string_field<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("copy/move plan is missing string field {name:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Hive, KeyBlock, RegData, ValueEntry};

    fn file(path: &str) -> RegFile {
        RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf8,
            keys: vec![KeyBlock {
                path: RegPath::parse(path).unwrap(),
                delete: false,
                values: Vec::new(),
                line: 0,
            }],
        }
    }

    #[test]
    fn artifact_detects_payload_tampering() {
        let root = std::env::temp_dir().join(format!(
            "regx-copy-plan-unit-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("copy.plan.json");
        let source_path = RegPath {
            hive: Hive::Hkcu,
            sub: "Software\\Source".into(),
        };
        let destination_path = RegPath {
            hive: Hive::Hkcu,
            sub: "Software\\Destination".into(),
        };
        let source = file("HKCU\\Software\\Source");
        let copy = file("HKCU\\Software\\Destination");
        let delete = RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf8,
            keys: Vec::new(),
        };
        let current = undo::Snapshot {
            file: file("HKCU\\Software\\Destination"),
            new_keys: Vec::new(),
            restored_values: 0,
            unreadable: Vec::new(),
        };
        save(
            &path,
            SaveInput {
                operation: "copy",
                view_label: "native",
                source_computer: None,
                source: &source_path,
                destination: &destination_path,
                source_value: None,
                destination_value: None,
                overwrite: false,
                source_file: &source,
                copy_file: &copy,
                delete_file: &delete,
                current: &current,
            },
        )
        .unwrap();
        assert_eq!(load(&path).unwrap().operation, "copy");

        let mut value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["payload"]["overwrite"] = Value::Bool(true);
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        assert!(load(&path).unwrap_err().contains("payload digest mismatch"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn value_plan_binds_both_names_and_exact_payload() {
        let root = std::env::temp_dir().join(format!(
            "regx-copy-value-plan-unit-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("value.plan.json");
        let source_path = RegPath::parse("HKCU\\Software\\Source").unwrap();
        let destination_path = RegPath::parse("HKCU\\Software\\Destination").unwrap();
        let source_name = ValueName::Named("Old".into());
        let destination_name = ValueName::Named("New".into());
        let value = |path: RegPath, name: ValueName, data: RegData| RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf8,
            keys: vec![KeyBlock {
                path,
                delete: false,
                values: vec![ValueEntry {
                    name,
                    data,
                    line: 0,
                }],
                line: 0,
            }],
        };
        let source = value(
            source_path.clone(),
            source_name.clone(),
            RegData::Sz("payload".into()),
        );
        let copy = value(
            destination_path.clone(),
            destination_name.clone(),
            RegData::Sz("payload".into()),
        );
        let delete = value(source_path.clone(), source_name.clone(), RegData::Delete);
        let current = undo::Snapshot {
            file: file("HKCU\\Software\\Destination"),
            new_keys: Vec::new(),
            restored_values: 0,
            unreadable: Vec::new(),
        };
        save(
            &path,
            SaveInput {
                operation: "move",
                view_label: "native",
                source_computer: None,
                source: &source_path,
                destination: &destination_path,
                source_value: Some(&source_name),
                destination_value: Some(&destination_name),
                overwrite: false,
                source_file: &source,
                copy_file: &copy,
                delete_file: &delete,
                current: &current,
            },
        )
        .unwrap();
        let artifact = load(&path).unwrap();
        assert_eq!(artifact.source_value, Some(source_name));
        assert_eq!(artifact.destination_value, Some(destination_name));
        assert_eq!(
            artifact.copy_file.keys[0].values[0].data,
            RegData::Sz("payload".into())
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_v1_subtree_plan_remains_readable() {
        let root = std::env::temp_dir().join(format!(
            "regx-copy-v1-plan-unit-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("legacy.plan.json");
        let source_path = RegPath::parse("HKCU\\Software\\Source").unwrap();
        let destination_path = RegPath::parse("HKCU\\Software\\Destination").unwrap();
        let source = file("HKCU\\Software\\Source");
        let copy = file("HKCU\\Software\\Destination");
        let delete = RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf8,
            keys: Vec::new(),
        };
        let current = undo::Snapshot {
            file: file("HKCU\\Software\\Destination"),
            new_keys: Vec::new(),
            restored_values: 0,
            unreadable: Vec::new(),
        };
        save(
            &path,
            SaveInput {
                operation: "copy",
                view_label: "native",
                source_computer: None,
                source: &source_path,
                destination: &destination_path,
                source_value: None,
                destination_value: None,
                overwrite: false,
                source_file: &source,
                copy_file: &copy,
                delete_file: &delete,
                current: &current,
            },
        )
        .unwrap();
        let mut document: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        document["schema"] = Value::String(LEGACY_SCHEMA_URL.into());
        document["schemaVersion"] = Value::from(1);
        let payload = document["payload"].as_object_mut().unwrap();
        payload.remove("scope");
        payload.remove("sourceValue");
        payload.remove("destinationValue");
        let payload_bytes = serde_json::to_vec(&document["payload"]).unwrap();
        document["payloadSha256"] = Value::String(sha256::hash_hex(&payload_bytes));
        std::fs::write(&path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
        let artifact = load(&path).unwrap();
        assert!(artifact.source_value.is_none());
        assert!(artifact.destination_value.is_none());
        let _ = std::fs::remove_dir_all(root);
    }
}
