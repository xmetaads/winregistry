use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("website/schemas")
}

#[test]
fn every_published_schema_is_valid_json_with_a_stable_identity() {
    for entry in std::fs::read_dir(root()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let document: Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).expect("schema must be JSON");
        assert_eq!(
            document["$schema"],
            "https://json-schema.org/draft/2020-12/schema",
            "{}",
            path.display()
        );
        let expected = format!(
            "https://winregistry.org/schemas/{}",
            path.file_name().unwrap().to_string_lossy()
        );
        assert_eq!(document["$id"], expected, "{}", path.display());
    }
}

#[test]
fn cli_schema_catalog_covers_every_machine_readable_command() {
    let path = root().join("cli-output-v1.json");
    let document: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let map = document["x-regx-command-map"].as_object().unwrap();
    let actual = map.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = [
        "--self-check",
        "apply-copy-plan",
        "apply-plan",
        "audit",
        "backup",
        "batch",
        "copy",
        "copy-value",
        "delete",
        "diff",
        "discover",
        "export",
        "fingerprint",
        "formats",
        "hive batch",
        "hive delete",
        "hive copy",
        "hive diff",
        "hive copy-value",
        "hive export",
        "hive fingerprint",
        "hive import",
        "hive undo",
        "hive info",
        "hive ls",
        "hive permissions",
        "hive probe",
        "hive query",
        "hive search",
        "hive stats",
        "hive set",
        "hive sync",
        "hive move",
        "hive move-value",
        "import",
        "inspect",
        "ls",
        "move",
        "move-value",
        "permissions",
        "plan",
        "probe",
        "query",
        "restore",
        "search",
        "stats",
        "set",
        "sync",
        "undo",
        "validate",
        "watch",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);

    let definitions = document["$defs"].as_object().unwrap();
    for (command, reference) in map {
        let reference = reference.as_str().unwrap();
        if let Some(name) = reference.strip_prefix("#/$defs/") {
            assert!(
                definitions.contains_key(name),
                "{command} points at missing definition {name}"
            );
        } else {
            let file = reference
                .strip_prefix("https://winregistry.org/schemas/")
                .unwrap_or_else(|| panic!("{command} has an unsupported schema reference"));
            assert!(root().join(file).is_file(), "{command}: missing {file}");
        }
    }
}

fn validate(instance: &Value, schema: &Value, document: &Value) -> Result<(), String> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let name = reference
            .strip_prefix("#/$defs/")
            .ok_or_else(|| format!("external reference {reference} is not supported here"))?;
        return validate(instance, &document["$defs"][name], document);
    }
    if let Some(choices) = schema.get("oneOf").and_then(Value::as_array) {
        let matches = choices
            .iter()
            .filter(|choice| validate(instance, choice, document).is_ok())
            .count();
        if matches != 1 {
            return Err(format!("oneOf matched {matches} alternatives"));
        }
    }
    if let Some(parts) = schema.get("allOf").and_then(Value::as_array) {
        for (index, part) in parts.iter().enumerate() {
            validate(instance, part, document)
                .map_err(|error| format!("allOf[{index}]: {error}"))?;
        }
    }
    if let Some(condition) = schema.get("if") {
        if validate(instance, condition, document).is_ok() {
            if let Some(consequence) = schema.get("then") {
                validate(instance, consequence, document)
                    .map_err(|error| format!("then: {error}"))?;
            }
        }
    }
    if let Some(expected) = schema.get("const") {
        if instance != expected {
            return Err(format!("expected const {expected}, found {instance}"));
        }
    }
    if let Some(expected) = schema.get("type") {
        let matches = |kind: &str| match kind {
            "array" => instance.is_array(),
            "boolean" => instance.is_boolean(),
            "integer" => instance.as_i64().is_some() || instance.as_u64().is_some(),
            "null" => instance.is_null(),
            "number" => instance.is_number(),
            "object" => instance.is_object(),
            "string" => instance.is_string(),
            _ => false,
        };
        let valid = expected.as_str().is_some_and(matches)
            || expected
                .as_array()
                .is_some_and(|kinds| kinds.iter().filter_map(Value::as_str).any(matches));
        if !valid {
            return Err(format!("expected type {expected}, found {instance}"));
        }
    }
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        let object = instance
            .as_object()
            .ok_or_else(|| "required fields need an object".to_string())?;
        for field in required.iter().filter_map(Value::as_str) {
            if !object.contains_key(field) {
                return Err(format!("missing required field {field}"));
            }
        }
    }
    if let (Some(properties), Some(object)) = (
        schema.get("properties").and_then(Value::as_object),
        instance.as_object(),
    ) {
        for (name, child_schema) in properties {
            if let Some(child) = object.get(name) {
                validate(child, child_schema, document)
                    .map_err(|error| format!("{name}: {error}"))?;
            }
        }
        if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
            for name in object.keys() {
                if !properties.contains_key(name) {
                    return Err(format!("unexpected property {name}"));
                }
            }
        } else if let Some(additional) = schema
            .get("additionalProperties")
            .filter(|value| value.is_object())
        {
            for (name, child) in object {
                if !properties.contains_key(name) {
                    validate(child, additional, document)
                        .map_err(|error| format!("{name}: {error}"))?;
                }
            }
        }
    }
    if schema.get("properties").is_none() {
        if let (Some(additional), Some(object)) = (
            schema
                .get("additionalProperties")
                .filter(|value| value.is_object()),
            instance.as_object(),
        ) {
            for (name, child) in object {
                validate(child, additional, document)
                    .map_err(|error| format!("{name}: {error}"))?;
            }
        }
    }
    if schema.get("unevaluatedProperties") == Some(&Value::Bool(false)) {
        if let Some(object) = instance.as_object() {
            let mut evaluated = BTreeSet::new();
            collect_evaluated_properties(schema, document, &mut evaluated)?;
            for name in object.keys() {
                if !evaluated.contains(name) {
                    return Err(format!("unexpected unevaluated property {name}"));
                }
            }
        }
    }
    if let (Some(items), Some(array)) = (schema.get("items"), instance.as_array()) {
        for (index, child) in array.iter().enumerate() {
            validate(child, items, document).map_err(|error| format!("[{index}]: {error}"))?;
        }
    }
    if let Some(array) = instance.as_array() {
        if let Some(minimum) = schema.get("minItems").and_then(Value::as_u64) {
            if array.len() < minimum as usize {
                return Err(format!("expected at least {minimum} items"));
            }
        }
        if let Some(maximum) = schema.get("maxItems").and_then(Value::as_u64) {
            if array.len() > maximum as usize {
                return Err(format!("expected at most {maximum} items"));
            }
        }
        if schema.get("uniqueItems") == Some(&Value::Bool(true)) {
            for (index, item) in array.iter().enumerate() {
                if array[..index].contains(item) {
                    return Err(format!("item [{index}] is not unique"));
                }
            }
        }
    }
    if let Some(text) = instance.as_str() {
        if let Some(minimum) = schema.get("minLength").and_then(Value::as_u64) {
            if text.chars().count() < minimum as usize {
                return Err(format!("expected at least {minimum} characters"));
            }
        }
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
            let expression =
                regex::Regex::new(pattern).map_err(|error| format!("invalid pattern: {error}"))?;
            if !expression.is_match(text) {
                return Err(format!("string does not match pattern {pattern:?}"));
            }
        }
    }
    if let (Some(number), Some(minimum)) = (
        instance.as_f64(),
        schema.get("minimum").and_then(Value::as_f64),
    ) {
        if number < minimum {
            return Err(format!("expected number >= {minimum}"));
        }
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if !values.contains(instance) {
            return Err(format!("{instance} is not in enum"));
        }
    }
    Ok(())
}

fn collect_evaluated_properties(
    schema: &Value,
    document: &Value,
    names: &mut BTreeSet<String>,
) -> Result<(), String> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let name = reference
            .strip_prefix("#/$defs/")
            .ok_or_else(|| format!("external reference {reference} is not supported here"))?;
        return collect_evaluated_properties(&document["$defs"][name], document, names);
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        names.extend(properties.keys().cloned());
    }
    for keyword in ["allOf", "oneOf"] {
        if let Some(parts) = schema.get(keyword).and_then(Value::as_array) {
            for part in parts {
                collect_evaluated_properties(part, document, names)?;
            }
        }
    }
    Ok(())
}

#[test]
fn representative_real_cli_outputs_validate_against_the_catalog() {
    let document: Value =
        serde_json::from_slice(&std::fs::read(root().join("cli-output-v1.json")).unwrap()).unwrap();
    let map = document["x-regx-command-map"].as_object().unwrap();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_regx"));
    let scratch = std::env::temp_dir().join(format!("regx-schema-contract-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let input = scratch.join("input.reg");
    std::fs::write(
        &input,
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\SchemaContract]\r\n\
         \"Text\"=\"text\"\r\n\
         \"Dword\"=dword:0000002a\r\n\
         \"Delete\"=-\r\n\
         \"Raw\"=hex(1234):00,ff\r\n",
    )
    .unwrap();
    let input_arg = input.to_string_lossy().into_owned();
    let export_arg = scratch.join("both.reg").to_string_lossy().into_owned();
    let backup_arg = scratch.join("backup.hiv").to_string_lossy().into_owned();
    let audit = scratch.join("audit.jsonl");
    std::fs::write(&audit, "").unwrap();
    let audit_arg = audit.to_string_lossy().into_owned();

    let cases = [
        ("--self-check", vec!["--self-check", "--output", "json"]),
        ("formats", vec!["formats", "--output", "json"]),
        ("inspect", vec!["inspect", &input_arg, "--output", "json"]),
        ("validate", vec!["validate", &input_arg, "--output", "json"]),
        ("plan", vec!["plan", &input_arg, "--output", "json"]),
        (
            "search",
            vec!["search", &input_arg, "text", "--output", "json"],
        ),
        (
            "watch",
            vec![
                "watch",
                "HKCU\\Environment",
                "--timeout",
                "1",
                "--output",
                "json",
            ],
        ),
        ("audit", vec!["audit", &audit_arg, "--output", "json"]),
        ("discover", vec!["discover", &input_arg, "--output", "json"]),
        (
            "hive info",
            vec!["hive", &input_arg, "info", "--output", "json"],
        ),
        (
            "import",
            vec!["import", &input_arg, "--dry-run", "-y", "--output", "json"],
        ),
        (
            "undo",
            vec!["undo", &input_arg, "--dry-run", "-y", "--output", "json"],
        ),
        (
            "query",
            vec!["query", "HKCU\\Environment", "--output", "json"],
        ),
        ("ls", vec!["ls", "HKCU\\Software", "--output", "json"]),
        ("stats", vec!["stats", &input_arg, "--output", "json"]),
        (
            "fingerprint",
            vec!["fingerprint", &input_arg, "--output", "json"],
        ),
        (
            "query",
            vec![
                "query",
                "HKCU\\Environment",
                "--view",
                "both",
                "--output",
                "json",
            ],
        ),
        (
            "export",
            vec!["export", "HKCU\\Environment", "--output", "json"],
        ),
        (
            "export",
            vec![
                "export",
                "HKCU\\Environment",
                "--view",
                "both",
                "--out",
                &export_arg,
                "--dry-run",
                "--output",
                "json",
            ],
        ),
        (
            "diff",
            vec![
                "diff",
                "HKCU\\Environment",
                &input_arg,
                "--view",
                "both",
                "--dry-run",
                "--output",
                "json",
            ],
        ),
        (
            "diff",
            vec!["diff", &input_arg, &input_arg, "--output", "json"],
        ),
        ("probe", vec!["probe", "HKCU\\Software", "--output", "json"]),
        (
            "probe",
            vec![
                "probe",
                "HKCU\\Software",
                "--view",
                "both",
                "--output",
                "json",
            ],
        ),
        (
            "permissions",
            vec!["permissions", "HKCU\\Software", "--output", "json"],
        ),
        (
            "permissions",
            vec![
                "permissions",
                "HKCU\\Software",
                "--compare",
                "HKCU\\Software",
                "--output",
                "json",
            ],
        ),
        (
            "backup",
            vec![
                "backup",
                "HKCU\\Environment",
                &backup_arg,
                "--dry-run",
                "--output",
                "json",
            ],
        ),
        (
            "backup",
            vec![
                "backup",
                "HKCU\\Environment",
                &backup_arg,
                "--view",
                "both",
                "--dry-run",
                "--output",
                "json",
            ],
        ),
    ];
    for (name, args) in cases {
        let output = Command::new(&binary).args(&args).output().unwrap();
        assert!(
            matches!(output.status.code(), Some(0 | 4 | 5 | 7)),
            "{name}: {:?}",
            output
        );
        let instance: Value = serde_json::from_slice(&output.stdout).unwrap();
        let reference = map[name].as_str().unwrap();
        let definition = &document["$defs"][reference.trim_start_matches("#/$defs/")];
        validate(&instance, definition, &document)
            .unwrap_or_else(|error| panic!("{name}: {error}\n{instance}"));
    }

    let converted = Command::new(&binary)
        .args(["convert", &input_arg, "--to", "json"])
        .output()
        .unwrap();
    assert!(converted.status.success(), "{converted:?}");
    let registry_data: Value = serde_json::from_slice(&converted.stdout).unwrap();
    validate(
        &registry_data,
        &document["$defs"]["registryData"],
        &document,
    )
    .unwrap_or_else(|error| panic!("registryData: {error}\n{registry_data}"));

    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn strict_core_schemas_reject_unknown_fields_and_wrong_types() {
    let document: Value =
        serde_json::from_slice(&std::fs::read(root().join("cli-output-v1.json")).unwrap()).unwrap();
    let cases = [
        (
            "probe",
            serde_json::json!({
                "path": "HKEY_CURRENT_USER\\Software",
                "computer": null,
                "exists": true,
                "readable": true,
                "writable": false,
                "creatable": false,
                "detail": ""
            }),
            "exists",
        ),
        (
            "backup",
            serde_json::json!({
                "source": "HKEY_CURRENT_USER\\Software",
                "sourceComputer": null,
                "file": "backup.hiv",
                "dryRun": true,
                "keys": 1,
                "values": 2,
                "bytes": null,
                "sha256": null
            }),
            "keys",
        ),
        (
            "permissions",
            serde_json::json!({
                "path": "HKEY_CURRENT_USER\\Software",
                "computer": null,
                "views": [],
                "failures": []
            }),
            "views",
        ),
        (
            "list",
            serde_json::json!({
                "path": "HKEY_CURRENT_USER\\Software",
                "computer": null,
                "recursive": false,
                "include": [],
                "exclude": [],
                "limit": 1000,
                "views": [{
                    "view": "native",
                    "keys": ["HKEY_CURRENT_USER\\Software\\Acme"],
                    "skipped": [],
                    "truncated": false
                }],
                "failures": []
            }),
            "views",
        ),
        (
            "diff",
            serde_json::json!({
                "a": "a.reg",
                "computerA": null,
                "b": "b.reg",
                "computerB": null,
                "mapA": null,
                "mapB": null,
                "incomplete": false,
                "summaryOnly": false,
                "include": [],
                "exclude": [],
                "includeValues": [],
                "excludeValues": [],
                "added": 0,
                "modified": 0,
                "removed": 0,
                "patch": null,
                "patchFormat": "reg",
                "patchWritten": false,
                "dryRun": false,
                "bytes": null,
                "sha256": null,
                "changes": []
            }),
            "added",
        ),
        (
            "stats",
            serde_json::json!({
                "source": "input.reg",
                "format": "reg",
                "rootAs": null,
                "keys": 1,
                "values": 1,
                "keyDeletes": 0,
                "valueDeletes": 0,
                "maxDepth": 2,
                "payloadBytes": 4,
                "types": { "REG_DWORD": 1 },
                "conflicts": 0,
                "incomplete": false,
                "matched": true,
                "include": [],
                "exclude": [],
                "includeValues": [],
                "excludeValues": []
            }),
            "keys",
        ),
        ("registryData", serde_json::json!({ "keys": [] }), "keys"),
        (
            "apply",
            serde_json::json!({
                "keysCreated": 0,
                "keysDeleted": 0,
                "valuesSet": 0,
                "valuesDeleted": 0,
                "failures": []
            }),
            "keysCreated",
        ),
        ("viewApply", serde_json::json!({ "views": [] }), "views"),
        (
            "undoApply",
            serde_json::json!({
                "atomic": true,
                "views": [{
                    "view": "native",
                    "redo": "redo.reg",
                    "redoBytes": 512,
                    "redoSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "apply": null,
                    "rolledBack": false,
                    "rollback": null
                }]
            }),
            "atomic",
        ),
        (
            "exportStatus",
            serde_json::json!({
                "source": "HKEY_CURRENT_USER\\Software",
                "computer": null,
                "rootAs": null,
                "format": "reg",
                "recursive": true,
                "include": [],
                "exclude": [],
                "includeValues": [],
                "excludeValues": [],
                "file": "out.reg",
                "dryRun": true,
                "keys": 0,
                "values": 0,
                "skipped": 0,
                "bytes": null,
                "sha256": null
            }),
            "keys",
        ),
        (
            "exportBoth",
            serde_json::json!({
                "source": "HKEY_CURRENT_USER\\Software",
                "computer": null,
                "rootAs": null,
                "format": "reg",
                "recursive": true,
                "include": [],
                "exclude": [],
                "includeValues": [],
                "excludeValues": [],
                "views": [{
                    "view": "32",
                    "file": null,
                    "dryRun": true,
                    "keys": 0,
                    "values": 0,
                    "skipped": 0,
                    "data": null,
                    "bytes": null,
                    "sha256": null
                }],
                "failures": []
            }),
            "views",
        ),
        (
            "plan",
            serde_json::json!({
                "files": ["input.reg"],
                "prune": false,
                "redacted": false,
                "blocked": false,
                "savedPlan": null,
                "savedPlanBytes": null,
                "savedPlanSha256": null,
                "redirect": { "skipped": 0, "refused": 0 },
                "policy": { "configured": false, "decisions": [], "denied": [] },
                "rollback": {
                    "path": "input.undo.reg",
                    "complete": true,
                    "restoredValues": 0,
                    "newKeys": 0,
                    "unreadable": 0
                },
                "changes": [],
                "failures": []
            }),
            "prune",
        ),
        (
            "copyMove",
            serde_json::json!({
                "operation": "copy",
                "source": "HKEY_CURRENT_USER\\Software\\Source",
                "destination": "HKEY_CURRENT_USER\\Software\\Destination",
                "view": "native",
                "sourceComputer": null,
                "plan": "copy.plan.json",
                "planBytes": 512,
                "planSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "sourceDigest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "currentDigest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "saved": true
            }),
            "planBytes",
        ),
        (
            "valueCopyMove",
            serde_json::json!({
                "operation": "copy-value",
                "source": "HKEY_CURRENT_USER\\Software\\Source",
                "sourceValue": "Selected",
                "destination": "HKEY_CURRENT_USER\\Software\\Destination",
                "destinationValue": "Copied",
                "plans": [{
                    "view": "native",
                    "plan": "copy-value.plan.json",
                    "planBytes": 512,
                    "planSha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }],
                "saved": true
            }),
            "plans",
        ),
        (
            "search",
            serde_json::json!({
                "source": "input.reg",
                "remoteComputer": null,
                "query": "text",
                "mode": "substring",
                "caseSensitive": false,
                "include": [],
                "exclude": [],
                "includeValues": [],
                "excludeValues": [],
                "limit": 100,
                "truncated": false,
                "incomplete": false,
                "matches": []
            }),
            "limit",
        ),
        (
            "watchEvent",
            serde_json::json!({
                "sequence": 1,
                "path": "HKEY_CURRENT_USER\\Software",
                "timedOut": true,
                "recursive": false,
                "timeoutSeconds": 1
            }),
            "sequence",
        ),
        (
            "watchEvent",
            serde_json::json!({
                "sequence": 1,
                "path": "HKEY_CURRENT_USER\\Software\\Watch",
                "timedOut": false,
                "recursive": true,
                "keyRemoved": false,
                "incomplete": false,
                "added": 0,
                "modified": 1,
                "removed": 0,
                "changes": [{
                    "kind": "value",
                    "change": "modified",
                    "path": "HKEY_CURRENT_USER\\Software\\Watch",
                    "name": "Raw",
                    "leftExact": { "name": "Raw", "typeId": 4660, "raw": "00 ff" },
                    "rightExact": { "name": "Raw", "typeId": 4660, "raw": "01 ff" }
                }]
            }),
            "sequence",
        ),
        (
            "audit",
            serde_json::json!({
                "file": "audit.jsonl",
                "records": 0,
                "sessions": 0,
                "intact": true,
                "broken": []
            }),
            "records",
        ),
        (
            "audit",
            serde_json::json!({
                "file": "audit.jsonl",
                "archive": "audit-001.jsonl",
                "dryRun": true,
                "records": 2,
                "archiveBytes": null,
                "archiveSha256": null,
                "eligible": true
            }),
            "archiveBytes",
        ),
        (
            "audit",
            serde_json::json!({
                "file": "audit.jsonl",
                "anchor": "audit.anchor",
                "dryRun": false,
                "records": 2,
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "tailHash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "signed": false,
                "anchorBytes": 256,
                "anchorSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "written": true
            }),
            "anchorBytes",
        ),
        (
            "audit",
            serde_json::json!({
                "file": "audit.jsonl",
                "anchor": "audit.anchor",
                "records": 2,
                "chainIntact": true,
                "anchorMatches": true,
                "intact": true,
                "expectedSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "actualSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "expectedTailHash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "actualTailHash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "signed": false,
                "signatureValid": false
            }),
            "records",
        ),
        (
            "discover",
            serde_json::json!({
                "executable": null,
                "anchor": "input.reg",
                "stem": "input",
                "policy": false,
                "registryPointer": false,
                "strict": false,
                "notes": [],
                "searched": [],
                "risky": 1,
                "found": [{
                    "path": "input.reg",
                    "resolvedPath": "C:\\resolved\\input.reg",
                    "origin": "current directory",
                    "rank": 9,
                    "format": "reg",
                    "size": 1,
                    "risks": ["CurrentDirectory"],
                    "riskDetails": [{
                        "kind": "CurrentDirectory",
                        "explanation": "working-directory configuration can be planted"
                    }]
                }]
            }),
            "found",
        ),
        (
            "hiveInfo",
            serde_json::json!({
                "file": "input.reg",
                "size": 1,
                "signatureValid": false,
                "readable": false,
                "writable": false,
                "detail": "not a hive",
                "rootSubkeys": []
            }),
            "size",
        ),
        (
            "hiveList",
            serde_json::json!({
                "subkey": "",
                "recursive": false,
                "include": [],
                "exclude": [],
                "limit": 1000,
                "truncated": false,
                "keys": [],
                "skipped": []
            }),
            "recursive",
        ),
        (
            "hiveProbe",
            serde_json::json!({
                "subkey": "Software\\MyApp",
                "exists": true,
                "readable": true,
                "writable": true,
                "creatable": true,
                "detail": "existing key is writable"
            }),
            "writable",
        ),
        (
            "hivePermissions",
            serde_json::json!({
                "subkey": "Software\\MyApp",
                "views": [{
                    "view": "native",
                    "ownerSid": "S-1-5-21",
                    "inheritanceEnabled": true,
                    "sddl": "O:S-1-5-21",
                    "effective": {
                        "queryValue": true,
                        "enumerateSubkeys": true,
                        "notify": true,
                        "setValue": true,
                        "createSubkey": true,
                        "delete": true
                    }
                }],
                "failures": []
            }),
            "views",
        ),
        (
            "hiveExport",
            serde_json::json!({
                "hive": "offline.hiv",
                "subkey": "",
                "rootAs": "HKEY_CURRENT_USER\\Offline",
                "format": "reg",
                "include": [],
                "exclude": [],
                "includeValues": [],
                "excludeValues": [],
                "file": "out.reg",
                "dryRun": true,
                "keys": 0,
                "values": 0,
                "skipped": 0
            }),
            "keys",
        ),
        (
            "hiveCopyMove",
            serde_json::json!({
                "operation": "move",
                "source": "Software\\Old",
                "destination": "Software\\New",
                "overwrite": false,
                "dryRun": false,
                "undo": "move.undo.reg",
                "undoBytes": 512,
                "undoSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "copy": {
                    "keysCreated": 1,
                    "keysDeleted": 0,
                    "valuesSet": 1,
                    "valuesDeleted": 0,
                    "failures": []
                },
                "removeSource": {
                    "keysCreated": 0,
                    "keysDeleted": 1,
                    "valuesSet": 0,
                    "valuesDeleted": 0,
                    "failures": []
                },
                "rolledBack": false,
                "rollback": null
            }),
            "overwrite",
        ),
        (
            "hiveApply",
            serde_json::json!({
                "undo": "set.undo.reg",
                "undoBytes": 512,
                "undoSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "apply": {
                    "keysCreated": 0,
                    "keysDeleted": 0,
                    "valuesSet": 1,
                    "valuesDeleted": 0,
                    "failures": []
                },
                "rolledBack": false,
                "rollback": null
            }),
            "rolledBack",
        ),
        (
            "hiveUndoApply",
            serde_json::json!({
                "redo": "redo.reg",
                "redoBytes": 512,
                "redoSha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "apply": {
                    "keysCreated": 0,
                    "keysDeleted": 0,
                    "valuesSet": 1,
                    "valuesDeleted": 0,
                    "failures": []
                },
                "rolledBack": false,
                "rollback": null
            }),
            "rolledBack",
        ),
        (
            "hiveSync",
            serde_json::json!({
                "prune": true,
                "pruneKeys": true,
                "dryRun": false,
                "undo": "sync.undo.reg",
                "undoBytes": 512,
                "undoSha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "apply": {
                    "keysCreated": 0,
                    "keysDeleted": 1,
                    "valuesSet": 1,
                    "valuesDeleted": 1,
                    "failures": []
                },
                "rolledBack": false,
                "rollback": null
            }),
            "prune",
        ),
    ];

    for (name, valid, typed_field) in cases {
        let schema = &document["$defs"][name];
        validate(&valid, schema, &document).unwrap_or_else(|error| panic!("{name}: {error}"));

        let mut unknown = valid.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), Value::Bool(true));
        assert!(
            validate(&unknown, schema, &document).is_err(),
            "{name} accepted an unknown field"
        );

        let mut wrong = valid;
        wrong
            .as_object_mut()
            .unwrap()
            .insert(typed_field.into(), Value::String("wrong".into()));
        assert!(
            validate(&wrong, schema, &document).is_err(),
            "{name} accepted the wrong type for {typed_field}"
        );
    }

    assert!(validate(
        &serde_json::json!("not-a-digest"),
        &serde_json::json!({ "type": "string", "pattern": "^[0-9a-f]{64}$" }),
        &document,
    )
    .is_err());
    assert!(validate(
        &serde_json::json!([1, 1]),
        &serde_json::json!({ "type": "array", "uniqueItems": true }),
        &document,
    )
    .is_err());
    assert!(validate(
        &serde_json::json!({ "REG_DWORD": "one" }),
        &serde_json::json!({
            "type": "object",
            "additionalProperties": { "$ref": "#/$defs/nonNegative" }
        }),
        &document,
    )
    .is_err());
    assert!(validate(
        &serde_json::json!({ "scope": "value" }),
        &serde_json::json!({
            "type": "object",
            "if": {
                "properties": { "scope": { "const": "value" } }
            },
            "then": { "required": ["value"] }
        }),
        &document,
    )
    .is_err());

    let inspect_conflict = serde_json::json!({
        "path": "HKEY_CURRENT_USER\\Software\\A",
        "value": "Mode",
        "firstLine": 3,
        "lastLine": 7,
        "old": "first",
        "new": "second",
        "oldExact": { "name": "Mode", "type": "REG_SZ", "data": "first" },
        "newExact": { "name": "Mode", "type": "REG_SZ", "data": "second" }
    });
    let conflict_schema = &document["$defs"]["inspectConflict"];
    validate(&inspect_conflict, conflict_schema, &document).unwrap();
    let mut extra_conflict = inspect_conflict.clone();
    extra_conflict["unexpected"] = Value::Bool(true);
    assert!(validate(&extra_conflict, conflict_schema, &document).is_err());
    let mut wrong_conflict = inspect_conflict;
    wrong_conflict["firstLine"] = Value::String("three".into());
    assert!(validate(&wrong_conflict, conflict_schema, &document).is_err());

    let registry_data = serde_json::json!({
        "keys": [{
            "path": "HKEY_CURRENT_USER\\Software\\A",
            "delete": false,
            "values": [{
                "name": "Text",
                "type": "REG_SZ",
                "data": "value"
            }]
        }]
    });
    validate(
        &registry_data,
        &document["$defs"]["registryData"],
        &document,
    )
    .unwrap();
    let mut extra_value = registry_data.clone();
    extra_value["keys"][0]["values"][0]["unexpected"] = Value::Bool(true);
    assert!(validate(&extra_value, &document["$defs"]["registryData"], &document).is_err());
    let mut wrong_value = registry_data;
    wrong_value["keys"][0]["values"][0]["data"] = Value::Bool(true);
    assert!(validate(&wrong_value, &document["$defs"]["registryData"], &document).is_err());

    let query_data = serde_json::json!([{
        "key": "HKEY_CURRENT_USER\\Software\\A",
        "values": [{
            "name": "Text",
            "type": "REG_SZ",
            "data": "value",
            "exact": { "name": "Text", "type": "REG_SZ", "data": "value" }
        }]
    }]);
    validate(&query_data, &document["$defs"]["queryData"], &document).unwrap();
    let mut bad_query = query_data;
    bad_query[0]["values"][0]["extra"] = Value::Null;
    assert!(validate(&bad_query, &document["$defs"]["queryData"], &document).is_err());

    let search_match = serde_json::json!({
        "field": "data",
        "path": "HKEY_CURRENT_USER\\Software\\A",
        "name": "Raw",
        "type": "REG_BINARY",
        "data": "00 ff",
        "exact": { "name": "Raw", "typeId": 3, "raw": "00 ff" }
    });
    validate(&search_match, &document["$defs"]["searchMatch"], &document).unwrap();
    let mut bad_search_match = search_match;
    bad_search_match["exact"]["raw"] = Value::Bool(true);
    assert!(validate(
        &bad_search_match,
        &document["$defs"]["searchMatch"],
        &document
    )
    .is_err());

    let diff_change = serde_json::json!({
        "kind": "value",
        "change": "modified",
        "path": "HKEY_CURRENT_USER\\Software\\A",
        "name": "Raw",
        "left": "00 ff",
        "right": "01 ff",
        "leftExact": { "name": "Raw", "typeId": 3, "raw": "00 ff" },
        "rightExact": { "name": "Raw", "typeId": 3, "raw": "01 ff" }
    });
    validate(&diff_change, &document["$defs"]["diffChange"], &document).unwrap();
    let mut bad_diff_change = diff_change;
    bad_diff_change["leftExact"]["typeId"] = Value::String("3".into());
    assert!(validate(
        &bad_diff_change,
        &document["$defs"]["diffChange"],
        &document
    )
    .is_err());

    let plan_data = serde_json::json!({
        "type": "REG_BINARY",
        "data": "00 ff",
        "exact": { "name": "Raw", "typeId": 3, "raw": "00 ff" }
    });
    validate(&plan_data, &document["$defs"]["planData"], &document).unwrap();
    let mut bad_plan_data = plan_data;
    bad_plan_data["exact"]["raw"] = Value::Array(Vec::new());
    assert!(validate(&bad_plan_data, &document["$defs"]["planData"], &document).is_err());
}

#[test]
fn real_dual_view_copy_plan_result_validates_strictly() {
    let schema: Value =
        serde_json::from_slice(&std::fs::read(root().join("copy-plan-result-v1.json")).unwrap())
            .unwrap();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_regx"));
    let id = std::process::id();
    let source = format!("HKCU\\Software\\regx-schema-plan-source-{id}");
    let destination = format!("HKCU\\Software\\regx-schema-plan-dest-{id}");
    let scratch = std::env::temp_dir().join(format!("regx-schema-copy-plan-{id}"));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).unwrap();
    let plan = scratch.join("copy.plan.json");
    let plan_arg = plan.to_string_lossy().into_owned();

    let seeded = Command::new(&binary)
        .args([
            "set",
            &source,
            "-v",
            "Marker",
            "-d",
            "schema",
            "--view",
            "both",
            "-y",
            "--log-level",
            "error",
        ])
        .output()
        .unwrap();
    if !seeded.status.success() {
        let _ = std::fs::remove_dir_all(&scratch);
        return;
    }
    let saved = Command::new(&binary)
        .args([
            "copy",
            &source,
            &destination,
            "--view",
            "both",
            "--save-plan",
            &plan_arg,
        ])
        .output()
        .unwrap();
    assert!(saved.status.success(), "{saved:?}");
    let applied = Command::new(&binary)
        .args([
            "apply-copy-plan",
            &plan_arg,
            "--view",
            "both",
            "--dry-run",
            "--output",
            "json",
            "-y",
        ])
        .output()
        .unwrap();

    let _ = Command::new(&binary)
        .args([
            "delete",
            &source,
            "-r",
            "--view",
            "both",
            "-y",
            "--log-level",
            "error",
        ])
        .output();
    let _ = Command::new(&binary)
        .args([
            "delete",
            &destination,
            "-r",
            "--view",
            "both",
            "-y",
            "--log-level",
            "error",
        ])
        .output();
    let _ = std::fs::remove_dir_all(&scratch);

    assert!(applied.status.success(), "{applied:?}");
    let instance: Value = serde_json::from_slice(&applied.stdout).unwrap();
    validate(&instance, &schema, &schema)
        .unwrap_or_else(|error| panic!("apply-copy-plan: {error}\n{instance}"));

    let mut invalid = instance;
    invalid
        .as_object_mut()
        .unwrap()
        .insert("unexpected".into(), Value::Bool(true));
    assert!(validate(&invalid, &schema, &schema).is_err());
}
