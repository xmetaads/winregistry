//! Versioned, digest-bound plan artifacts.
//!
//! A saved plan is not authority to write forever. It binds the exact source
//! bytes, the resolved desired mutations for each view, and the minimal current
//! state needed to undo those mutations. `apply-plan` verifies all three before
//! the first registry write.

use crate::encoding;
use crate::formats;
use crate::model::{RegFile, RegFormat};
use crate::sha256;
use crate::undo;
use crate::winreg::View;
use crate::writer;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION: u64 = 1;
pub const SCHEMA_URL: &str = "https://winregistry.org/schemas/saved-plan-v1.json";
const MAX_PLAN_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub struct SavedView {
    pub label: String,
    pub view: View,
    pub desired: RegFile,
    pub current_digest: String,
}

#[derive(Debug)]
pub struct Artifact {
    pub sources: Vec<(PathBuf, String)>,
    pub views: Vec<SavedView>,
}

pub fn file_digest(file: &RegFile) -> String {
    sha256::hash_hex(writer::to_json(file).as_bytes())
}

pub fn snapshot_digest(snapshot: &undo::Snapshot) -> String {
    file_digest(&snapshot.file)
}

pub fn save(
    destination: &Path,
    sources: &[PathBuf],
    prune: bool,
    prune_keys: bool,
    views: &[(&str, &RegFile, &undo::Snapshot)],
) -> Result<(), String> {
    if destination.exists() {
        return Err(format!(
            "{} already exists; refusing to overwrite a saved plan",
            destination.display()
        ));
    }
    if sources
        .iter()
        .any(|path| path.as_os_str() == "-" || crate::ipc::is_named_pipe(path))
    {
        return Err(
            "a saved plan requires regular source files; stream input cannot be re-verified".into(),
        );
    }

    let mut source_values = Vec::new();
    for source in sources {
        let canonical = std::fs::canonicalize(source)
            .map_err(|error| format!("cannot resolve source {}: {error}", source.display()))?;
        let bytes = std::fs::read(&canonical)
            .map_err(|error| format!("cannot read source {}: {error}", canonical.display()))?;
        source_values.push(json!({
            "path": canonical.to_string_lossy(),
            "sha256": sha256::hash_hex(&bytes),
        }));
    }

    let mut view_values = Vec::new();
    for (label, desired, current) in views {
        if !current.is_complete() {
            return Err(format!(
                "view {label} has an incomplete current-state snapshot"
            ));
        }
        let desired_json: Value = serde_json::from_str(&writer::to_json(desired))
            .map_err(|error| format!("cannot serialize desired state for view {label}: {error}"))?;
        view_values.push(json!({
            "view": label,
            "desiredDigest": file_digest(desired),
            "currentDigest": snapshot_digest(current),
            "desired": desired_json,
        }));
    }

    let payload = json!({
        "tool": env!("CARGO_PKG_NAME"),
        "toolVersion": env!("CARGO_PKG_VERSION"),
        "prune": prune,
        "pruneKeys": prune_keys,
        "sources": source_values,
        "views": view_values,
    });
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|error| format!("cannot encode saved-plan payload: {error}"))?;
    let artifact = json!({
        "schema": SCHEMA_URL,
        "schemaVersion": SCHEMA_VERSION,
        "payloadSha256": sha256::hash_hex(&payload_bytes),
        "payload": payload,
    });
    let mut bytes = serde_json::to_vec_pretty(&artifact)
        .map_err(|error| format!("cannot encode saved plan: {error}"))?;
    bytes.push(b'\n');
    crate::file_io::atomic_write(destination, &bytes)
        .map_err(|error| format!("cannot write {}: {error}", destination.display()))
}

pub fn load(path: &Path) -> Result<Artifact, String> {
    let bytes = crate::file_io::read_limited(path, MAX_PLAN_BYTES, "saved plan")?;
    let root: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid saved-plan JSON: {error}"))?;
    if string_field(&root, "schema")? != SCHEMA_URL {
        return Err("saved plan names an unknown schema".into());
    }
    let version = root
        .get("schemaVersion")
        .and_then(Value::as_u64)
        .ok_or("saved plan is missing an integer schemaVersion")?;
    if version != SCHEMA_VERSION {
        return Err(format!(
            "unsupported saved-plan schemaVersion {version}; expected {SCHEMA_VERSION}"
        ));
    }
    let payload = root.get("payload").ok_or("saved plan is missing payload")?;
    let expected = string_field(&root, "payloadSha256")?;
    let payload_bytes = serde_json::to_vec(payload)
        .map_err(|error| format!("cannot canonicalize saved-plan payload: {error}"))?;
    let actual = sha256::hash_hex(&payload_bytes);
    if actual != expected {
        return Err(format!(
            "saved-plan payload digest mismatch (expected {expected}, found {actual})"
        ));
    }

    let source_values = payload
        .get("sources")
        .and_then(Value::as_array)
        .ok_or("saved-plan payload is missing sources")?;
    if source_values.is_empty() {
        return Err("saved plan contains no source files".into());
    }
    let mut sources = Vec::new();
    for source in source_values {
        sources.push((
            PathBuf::from(string_field(source, "path")?),
            string_field(source, "sha256")?.to_string(),
        ));
    }

    let view_values = payload
        .get("views")
        .and_then(Value::as_array)
        .ok_or("saved-plan payload is missing views")?;
    if view_values.is_empty() {
        return Err("saved plan contains no registry views".into());
    }
    if view_values.len() > 2 {
        return Err("saved plan contains more than two registry views".into());
    }
    let mut views = Vec::new();
    for item in view_values {
        let label = string_field(item, "view")?.to_string();
        let view = match label.as_str() {
            "native" => View::Native,
            "32" => View::Bits32,
            "64" => View::Bits64,
            other => return Err(format!("saved plan has unknown registry view {other:?}")),
        };
        let desired_value = item
            .get("desired")
            .ok_or_else(|| format!("view {label} is missing desired state"))?;
        let desired_bytes = serde_json::to_vec(desired_value)
            .map_err(|error| format!("cannot decode desired state for view {label}: {error}"))?;
        let (keys, _) = formats::json::read(&desired_bytes)
            .map_err(|error| format!("invalid desired state for view {label}: {error}"))?;
        let desired = RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf16Le,
            keys,
        };
        let desired_digest = string_field(item, "desiredDigest")?.to_string();
        let actual_desired = file_digest(&desired);
        if actual_desired != desired_digest {
            return Err(format!(
                "view {label} desired-state digest mismatch (expected {desired_digest}, found {actual_desired})"
            ));
        }
        views.push(SavedView {
            label,
            view,
            desired,
            current_digest: string_field(item, "currentDigest")?.to_string(),
        });
    }
    views.sort_by_key(|item| match item.view {
        View::Native => 0,
        View::Bits32 => 1,
        View::Bits64 => 2,
    });
    if views.windows(2).any(|pair| pair[0].label == pair[1].label) {
        return Err("saved plan contains a duplicate registry view".into());
    }
    if views.len() > 1 && views.iter().any(|item| item.view == View::Native) {
        return Err("saved plan cannot combine native with explicit registry views".into());
    }
    Ok(Artifact { sources, views })
}

pub fn verify_sources(artifact: &Artifact) -> Result<(), String> {
    for (path, expected) in &artifact.sources {
        let bytes = std::fs::read(path)
            .map_err(|error| format!("cannot re-read source {}: {error}", path.display()))?;
        let actual = sha256::hash_hex(&bytes);
        if &actual != expected {
            return Err(format!(
                "source {} changed after planning (expected {expected}, found {actual})",
                path.display()
            ));
        }
    }
    Ok(())
}

fn string_field<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("saved plan is missing string field {name:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Hive, KeyBlock, RegPath};

    fn empty_file() -> RegFile {
        RegFile {
            format: RegFormat::V5,
            encoding: encoding::SourceEncoding::Utf16Le,
            keys: vec![KeyBlock {
                path: RegPath {
                    hive: Hive::Hkcu,
                    sub: "Software\\SavedPlan".into(),
                },
                delete: false,
                values: vec![],
                line: 0,
            }],
        }
    }

    #[test]
    fn canonical_file_digest_is_stable() {
        let file = empty_file();
        assert_eq!(file_digest(&file), file_digest(&file.clone()));
    }

    #[test]
    fn artifact_binds_payload_source_and_desired_state() {
        let root = std::env::temp_dir().join(format!(
            "regx-saved-plan-unit-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("desired.reg");
        std::fs::write(&source, b"source bytes").unwrap();
        let artifact_path = root.join("plan.json");
        let desired = empty_file();
        let current = undo::Snapshot {
            file: desired.clone(),
            new_keys: vec![],
            restored_values: 0,
            unreadable: vec![],
        };
        save(
            &artifact_path,
            std::slice::from_ref(&source),
            false,
            false,
            &[("native", &desired, &current)],
        )
        .unwrap();

        let loaded = load(&artifact_path).unwrap();
        assert_eq!(loaded.views.len(), 1);
        assert_eq!(file_digest(&loaded.views[0].desired), file_digest(&desired));
        verify_sources(&loaded).unwrap();

        std::fs::write(&source, b"changed source bytes").unwrap();
        assert!(verify_sources(&loaded).unwrap_err().contains("changed"));

        let mut artifact: Value =
            serde_json::from_slice(&std::fs::read(&artifact_path).unwrap()).unwrap();
        artifact["payload"]["toolVersion"] = Value::String("tampered".into());
        std::fs::write(
            &artifact_path,
            serde_json::to_vec_pretty(&artifact).unwrap(),
        )
        .unwrap();
        assert!(load(&artifact_path)
            .unwrap_err()
            .contains("payload digest mismatch"));
        let _ = std::fs::remove_dir_all(root);
    }
}
