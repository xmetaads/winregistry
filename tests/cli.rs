//! Integration tests that drive the built binary.
//!
//! The unit tests inside `src/` cover the engines. These cover the *contract* —
//! exit codes, output shape, and the promise that `--dry-run` writes nothing.
//! Those are documented as stable, so a regression in them is a broken promise
//! to anyone scripting against the tool, and nothing else guards them.
//!
//! Every test that touches the live registry works under a unique subkey of
//! `HKCU\Software\regx-it-<test>` and removes it afterwards.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

// Exit codes, mirrored from src/cli.rs. Duplicated on purpose: if someone
// changes the constant, this file should fail rather than silently agree.
const OK: i32 = 0;
const USAGE: i32 = 2;
const PARSE: i32 = 3;
const ACCESS_DENIED: i32 = 4;
const PARTIAL: i32 = 5;
const REDIRECTION_REFUSED: i32 = 6;
const IO: i32 = 7;
const NOT_FOUND: i32 = 8;
fn bin() -> PathBuf {
    // CARGO_BIN_EXE_<name> is set by cargo for integration tests.
    PathBuf::from(env!("CARGO_BIN_EXE_regx"))
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to launch regx")
}

fn top_level_commands_from_help(help: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut in_commands = false;
    for line in help.lines() {
        if line == "Commands:" {
            in_commands = true;
            continue;
        }
        if in_commands && line == "Options:" {
            break;
        }
        if !in_commands || !line.starts_with("  ") || line.starts_with("   ") {
            continue;
        }
        if let Some(command) = line.split_whitespace().next() {
            commands.push(command.to_string());
        }
    }
    commands
}

fn run_stdin(args: &[&str], input: &str) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch regx");
    child
        .stdin
        .take()
        .expect("stdin pipe missing")
        .write_all(input.as_bytes())
        .expect("failed to write stdin");
    child.wait_with_output().expect("failed to wait for regx")
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("process terminated by signal")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A scratch directory that cleans up after itself even when a test panics.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let d = std::env::temp_dir().join(format!("regx-it-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Scratch(d)
    }
    fn path(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }
    fn write(&self, file: &str, contents: &str) -> PathBuf {
        let p = self.path(file);
        std::fs::write(&p, contents).unwrap();
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A live registry key removed on drop, so a failing assertion cannot leave
/// state behind for the next run.
struct LiveKey(String);

impl LiveKey {
    fn new(name: &str) -> LiveKey {
        let k = format!("HKCU\\Software\\regx-it-{name}");
        let _ = run(&[
            "delete",
            &k,
            "-r",
            "--view",
            "both",
            "-y",
            "--log-level",
            "error",
        ]);
        LiveKey(k)
    }
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for LiveKey {
    fn drop(&mut self) {
        let _ = run(&[
            "delete",
            &self.0,
            "-r",
            "--view",
            "both",
            "-y",
            "--log-level",
            "error",
        ]);
    }
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Is this process elevated?
///
/// A handful of assertions here are about the *environment* rather than the
/// code: that an HKLM write is refused, that `probe` reports HKLM as read-only.
/// They are the product's central premise and worth testing, but they only mean
/// anything when the tests run as a standard user.
///
/// GitHub's `windows-latest` runners execute as an administrator, so those
/// assertions are inverted there. Rather than delete them or let CI go red on a
/// property of the runner, each one checks first and says plainly when it could
/// not assert what it exists to assert.
fn elevated() -> bool {
    // Asking the binary keeps this consistent with what the product itself
    // reports, instead of a second opinion that could disagree.
    let o = run(&["--self-check", "--output", "json"]);
    let text = stdout(&o);
    text.contains("running ELEVATED") || !text.contains("not elevated")
}

fn skip_if_elevated(what: &str) -> bool {
    if elevated() {
        eprintln!(
            "SKIPPED: {what} - this process is elevated, so the assertion is \
             not meaningful. Run the tests as a standard user to exercise it."
        );
        return true;
    }
    false
}

fn skip_if_hkcu_not_writable(what: &str) -> bool {
    let probe = run(&["probe", "HKCU\\Software", "--output", "json"]);
    if code(&probe) != OK {
        eprintln!(
            "SKIPPED: {what} - HKCU\\Software is not writable in this host: {}",
            stdout(&probe)
        );
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Basic contract
// ---------------------------------------------------------------------------

#[test]
fn version_and_help_succeed() {
    let v = run(&["--version"]);
    assert_eq!(code(&v), OK);
    assert!(stdout(&v).contains("regx"), "{}", stdout(&v));

    let h = run(&["--help"]);
    assert_eq!(code(&h), OK);
    let help = stdout(&h);
    let commands = top_level_commands_from_help(&help);
    assert!(
        !commands.is_empty(),
        "no commands parsed from --help:\n{help}"
    );
    for command in commands {
        let command_help = run(&[&command, "--help"]);
        assert_eq!(
            code(&command_help),
            OK,
            "`regx {command} --help` failed: {}",
            stderr(&command_help)
        );
    }
}

#[test]
fn sync_exposes_explicit_undo_controls() {
    let help = run(&["sync", "--help"]);
    assert_eq!(code(&help), OK);
    assert!(stdout(&help).contains("--backup"));
    assert!(stdout(&help).contains("--no-backup"));

    let conflict = run(&[
        "sync",
        "desired.reg",
        "--backup",
        "desired.undo.reg",
        "--no-backup",
    ]);
    assert_eq!(code(&conflict), USAGE);
}

#[test]
fn website_documents_every_top_level_command() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs =
        std::fs::read_to_string(root.join("website/docs.html")).expect("website documentation");
    let help = run(&["--help"]);
    assert_eq!(code(&help), OK, "{}", stderr(&help));
    let commands = top_level_commands_from_help(&stdout(&help));
    assert!(!commands.is_empty(), "no commands parsed from --help");
    for command in &commands {
        let markup = format!("<code>{command}</code>");
        assert!(
            docs.contains(&markup),
            "website/docs.html does not document `{command}`"
        );
    }
    let audit = std::fs::read_to_string(root.join("docs/PROJECT_AUDIT.md")).expect("project audit");
    let count_claim = format!("application has {} top-level commands", commands.len());
    assert!(
        audit.to_ascii_lowercase().contains(&count_claim),
        "docs/PROJECT_AUDIT.md must contain the current claim {count_claim:?}"
    );
    for marker in [
        "regx stats  &lt;SOURCE&gt;",
        "query, ls, stats, fingerprint, set, delete",
        "<span class=\"tok-flag\">--root-as</span> KEY",
        "maximum depth relative to the mapped requested root",
        "Offline hive stats maps the mounted hive root",
    ] {
        assert!(
            docs.contains(marker),
            "website/docs.html is missing the stats mapping contract marker {marker:?}"
        );
    }
}

#[test]
fn completions_honors_the_global_self_check_before_emitting_script() {
    let output = run(&["completions", "powershell", "--self-check"]);
    assert_eq!(code(&output), OK, "{}", stderr(&output));
    let text = stdout(&output);
    let report = text.find("regx self-check").expect("self-check report");
    let script = text
        .find("Register-ArgumentCompleter")
        .expect("PowerShell completion script");
    assert!(report < script, "self-check must run before the command");
}

#[test]
fn batch_manifest_is_atomic_and_reports_each_operation() {
    if skip_if_hkcu_not_writable("atomic batch contract") {
        return;
    }
    let d = Scratch::new("batch");
    let key = LiveKey::new("batch");
    let manifest_json = serde_json::json!({
        "schema": "https://winregistry.org/schemas/batch-v1.json",
        "schemaVersion": 1,
        "operations": [
            {"id": "first", "keys": [{"path": key.as_str(), "values": [
                {"name": "A", "type": "REG_SZ", "data": "one"}
            ]}]},
            {"id": "second", "keys": [{"path": key.as_str(), "values": [
                {"name": "B", "type": "REG_DWORD", "data": 2}
            ]}]}
        ]
    });
    let manifest = d.write(
        "batch.json",
        &serde_json::to_string(&manifest_json).unwrap(),
    );
    let undo = d.path("batch-undo.reg");
    let applied = run(&[
        "batch",
        &s(&manifest),
        "--redirect",
        "off",
        "--view",
        "both",
        "--backup",
        &s(&undo),
        "-y",
        "--output",
        "json",
    ]);
    assert_eq!(code(&applied), OK, "{}", stderr(&applied));
    let text = stdout(&applied);
    assert!(
        text.contains("\"id\":\"first\",\"status\":\"applied\""),
        "{text}"
    );
    assert!(
        text.contains("\"id\":\"second\",\"status\":\"applied\""),
        "{text}"
    );
    assert!(text.contains("\"view\":\"32\""), "{text}");
    assert!(text.contains("\"view\":\"64\""), "{text}");
    let applied_json: serde_json::Value =
        serde_json::from_slice(&applied.stdout).expect("live batch JSON");
    for (entry, path) in applied_json["undo"]
        .as_array()
        .unwrap()
        .iter()
        .zip([d.path("batch-undo.32.reg"), d.path("batch-undo.64.reg")])
    {
        assert!(path.exists());
        assert_eq!(
            entry["bytes"].as_u64().unwrap(),
            std::fs::metadata(path).unwrap().len()
        );
        assert_eq!(entry["sha256"].as_str().unwrap().len(), 64);
    }

    for value in ["A", "B"] {
        let queried = run(&[
            "query",
            key.as_str(),
            "-v",
            value,
            "--view",
            "both",
            "--output",
            "json",
        ]);
        assert_eq!(code(&queried), OK, "{}", stderr(&queried));
    }
}

#[test]
fn batch_dry_run_emits_versioned_results_without_an_undo_file() {
    let d = Scratch::new("batch-dry-run");
    let manifest = d.write(
        "batch.json",
        r#"{
          "schema":"https://winregistry.org/schemas/batch-v1.json",
          "schemaVersion":1,
          "operations":[{
            "id":"preview",
            "keys":[{
              "path":"HKCU\\Software\\regx-it-batch-preview",
              "values":[{"name":"Mode","type":"REG_SZ","data":"dry"}]
            }]
          }]
        }"#,
    );
    let undo = d.path("must-not-exist.reg");
    let preview = run(&[
        "batch",
        &s(&manifest),
        "--redirect",
        "off",
        "--backup",
        &s(&undo),
        "--dry-run",
        "--output",
        "json",
    ]);
    assert!(
        matches!(code(&preview), OK | ACCESS_DENIED),
        "{}",
        stderr(&preview)
    );
    let text = stdout(&preview);
    assert!(
        text.contains("\"schema\":\"https://winregistry.org/schemas/batch-result-v1.json\""),
        "{text}"
    );
    assert!(
        text.contains("\"id\":\"preview\",\"status\":\"planned\"")
            || text.contains("\"id\":\"preview\",\"status\":\"failed\""),
        "{text}"
    );
    let preview_json: serde_json::Value =
        serde_json::from_slice(&preview.stdout).expect("batch preview JSON");
    assert_eq!(preview_json["undo"].as_array().unwrap().len(), 1);
    assert!(preview_json["undo"][0]["bytes"].is_null());
    assert!(preview_json["undo"][0]["sha256"].is_null());
    assert!(!undo.exists());

    let conflicting = d.write(
        "batch-conflict.json",
        r#"{
          "schema":"https://winregistry.org/schemas/batch-v1.json",
          "schemaVersion":1,
          "operations":[{
            "id":"redirect-collision",
            "keys":[
              {"path":"HKLM\\SOFTWARE\\regx-it-batch-conflict","values":[{"name":"Mode","type":"REG_SZ","data":"native"}]},
              {"path":"HKLM\\SOFTWARE\\WOW6432Node\\regx-it-batch-conflict","values":[{"name":"mode","type":"REG_SZ","data":"wow"}]}
            ]
          }]
        }"#,
    );
    let conflict_undo = d.path("batch-conflict-undo.reg");
    let refused = run(&[
        "batch",
        &s(&conflicting),
        "--conflicts",
        "error",
        "--backup",
        &s(&conflict_undo),
        "-y",
    ]);
    assert_eq!(code(&refused), PARSE, "{}", stderr(&refused));
    assert!(stderr(&refused).contains("introduced inside operations"));
    assert!(!conflict_undo.exists());
}

#[test]
fn unconfirmed_batch_writes_neither_registry_nor_undo_artifact() {
    let d = Scratch::new("batch-unconfirmed");
    let key = LiveKey::new("batch-unconfirmed");
    let key_json = serde_json::to_string(key.as_str()).unwrap();
    let manifest = d.write(
        "batch.json",
        &format!(
            r#"{{
              "schema":"https://winregistry.org/schemas/batch-v1.json",
              "schemaVersion":1,
              "operations":[{{
                "id":"must-not-run",
                "keys":[{{"path":{},"values":[{{"name":"Value","type":"REG_SZ","data":"no"}}]}}]
              }}]
            }}"#,
            key_json
        ),
    );
    let undo = d.path("must-not-exist.reg");
    let cancelled = run(&[
        "batch",
        &s(&manifest),
        "--redirect",
        "off",
        "--backup",
        &s(&undo),
    ]);
    assert_eq!(code(&cancelled), OK, "{}", stderr(&cancelled));
    assert!(stderr(&cancelled).contains("aborted"));
    assert!(
        !undo.exists(),
        "confirmation refusal still wrote an undo file"
    );
    let absent = run(&["query", key.as_str(), "-v", "Value"]);
    assert_eq!(code(&absent), NOT_FOUND, "{}", stderr(&absent));
}

#[test]
fn set_and_delete_are_confirmed_undoable_and_cancel_without_artifacts() {
    let d = Scratch::new("set-delete-undo");
    let key = LiveKey::new("set-delete-undo");
    let cancelled_set_undo = d.path("cancelled-set.reg");
    let set_undo = d.path("set.reg");
    let cancelled_delete_undo = d.path("cancelled-delete.reg");
    let delete_undo = d.path("delete.reg");

    let cancelled_set = run(&[
        "set",
        key.as_str(),
        "-v",
        "Name",
        "-d",
        "cancelled",
        "--redirect",
        "off",
        "--backup",
        &s(&cancelled_set_undo),
    ]);
    assert_eq!(code(&cancelled_set), OK, "{}", stderr(&cancelled_set));
    assert!(stderr(&cancelled_set).contains("aborted"));
    assert!(!cancelled_set_undo.exists());
    let absent = run(&["query", key.as_str(), "-v", "Name", "--output", "json"]);
    assert_eq!(code(&absent), NOT_FOUND, "{}", stderr(&absent));

    let cancelled_delete = run(&[
        "delete",
        key.as_str(),
        "-v",
        "Name",
        "--backup",
        &s(&cancelled_delete_undo),
    ]);
    assert_eq!(code(&cancelled_delete), OK, "{}", stderr(&cancelled_delete));
    assert!(stderr(&cancelled_delete).contains("aborted"));
    assert!(!cancelled_delete_undo.exists());
    assert_eq!(
        code(&run(&["query", key.as_str(), "-v", "Name"])),
        NOT_FOUND
    );

    if skip_if_hkcu_not_writable("set/delete undo contract") {
        return;
    }

    let seeded = run(&[
        "set",
        key.as_str(),
        "-v",
        "Name",
        "-d",
        "before",
        "--redirect",
        "off",
        "-y",
    ]);
    assert_eq!(code(&seeded), OK, "{}", stderr(&seeded));

    let changed = run(&[
        "set",
        key.as_str(),
        "-v",
        "Name",
        "-d",
        "after",
        "--redirect",
        "off",
        "--backup",
        &s(&set_undo),
        "--output",
        "json",
        "-y",
    ]);
    assert_eq!(code(&changed), OK, "{}", stderr(&changed));
    assert!(set_undo.exists());
    let changed_json: serde_json::Value =
        serde_json::from_slice(&changed.stdout).expect("set result JSON");
    assert_eq!(
        changed_json["views"][0]["undoBytes"].as_u64().unwrap(),
        std::fs::metadata(&set_undo).unwrap().len()
    );
    assert_eq!(
        changed_json["views"][0]["undoSha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        code(&run(&[
            "import",
            &s(&set_undo),
            "--redirect",
            "off",
            "--no-backup",
            "-y",
        ])),
        OK
    );
    let restored = run(&["query", key.as_str(), "-v", "Name", "--output", "json"]);
    assert!(stdout(&restored).contains("before"));

    let deleted = run(&[
        "delete",
        key.as_str(),
        "-v",
        "Name",
        "--backup",
        &s(&delete_undo),
        "-y",
    ]);
    assert_eq!(code(&deleted), OK, "{}", stderr(&deleted));
    assert!(delete_undo.exists());
    assert_eq!(
        code(&run(&["query", key.as_str(), "-v", "Name"])),
        NOT_FOUND
    );
    assert_eq!(
        code(&run(&[
            "import",
            &s(&delete_undo),
            "--redirect",
            "off",
            "--no-backup",
            "-y",
        ])),
        OK
    );
    assert_eq!(code(&run(&["query", key.as_str(), "-v", "Name"])), OK);
}

#[test]
fn failed_batch_rolls_back_earlier_operations() {
    if skip_if_hkcu_not_writable("batch rollback contract")
        || skip_if_elevated("batch access-denied rollback contract")
    {
        return;
    }
    let d = Scratch::new("batch-rollback");
    let key = LiveKey::new("batch-rollback");
    let manifest = d.write(
        "batch.json",
        &format!(
            r#"{{
              "schema":"https://winregistry.org/schemas/batch-v1.json",
              "schemaVersion":1,
              "operations":[
                {{"id":"write-user","keys":[{{"path":"{}","values":[{{"name":"Transient","type":"REG_SZ","data":"remove-me"}}]}}]}},
                {{"id":"deny-machine","keys":[{{"path":"HKLM\\SYSTEM\\regx-batch-denied","values":[{{"name":"X","type":"REG_DWORD","data":1}}]}}]}}
              ]
            }}"#,
            key.as_str()
        ),
    );
    let applied = run(&[
        "batch",
        &s(&manifest),
        "--redirect",
        "off",
        "-y",
        "--output",
        "json",
    ]);
    assert_eq!(code(&applied), ACCESS_DENIED, "{}", stderr(&applied));
    let text = stdout(&applied);
    assert!(
        text.contains("\"id\":\"write-user\",\"status\":\"rolledBack\""),
        "{text}"
    );
    assert!(
        text.contains("\"id\":\"deny-machine\",\"status\":\"rolledBack\""),
        "{text}"
    );
    assert!(text.contains("\"rollback\":["), "{text}");

    let absent = run(&["query", key.as_str(), "-v", "Transient"]);
    assert_eq!(code(&absent), NOT_FOUND, "{}", stderr(&absent));
}

#[test]
fn no_command_is_a_usage_error_not_a_crash() {
    let o = run(&[]);
    assert_eq!(code(&o), USAGE, "no command is a CLI usage error");
    assert!(stderr(&o).contains("--help"), "{}", stderr(&o));

    let same = run(&["copy", "HKCU\\Software\\A", "HKCU\\Software\\A", "-y"]);
    assert_eq!(code(&same), USAGE, "same-source copy is a usage error");
    assert!(stderr(&same).contains("same key"), "{}", stderr(&same));

    let unsafe_delete = run(&["delete", "HKCU\\Software\\A", "-y"]);
    assert_eq!(
        code(&unsafe_delete),
        USAGE,
        "a missing recursive acknowledgement is a usage error"
    );
    assert!(
        stderr(&unsafe_delete).contains("pass -r"),
        "{}",
        stderr(&unsafe_delete)
    );
}

#[test]
fn an_unknown_flag_exits_usage() {
    let o = run(&["query", "HKCU\\Software", "--not-a-real-flag"]);
    assert_eq!(code(&o), USAGE);
}

#[test]
fn remote_registry_flags_are_read_only_and_restrict_supported_hives() {
    let unsupported = run(&["query", "HKCU\\Software", "--computer", "example.invalid"]);
    assert_eq!(code(&unsupported), USAGE);
    assert!(
        stderr(&unsupported).contains("only HKLM and HKU"),
        "{}",
        stderr(&unsupported)
    );
    let list_unsupported = run(&["ls", "HKCU\\Software", "--computer", "example.invalid"]);
    assert_eq!(code(&list_unsupported), USAGE);
    assert!(stderr(&list_unsupported).contains("only HKLM and HKU"));

    let d = Scratch::new("remote-read-only");
    let local = d.write(
        "local.reg",
        "Windows Registry Editor Version 5.00\n\n[HKCU\\Software\\A]\n",
    );
    let remote_file = run(&["search", &s(&local), "A", "--computer", "example.invalid"]);
    assert_eq!(code(&remote_file), USAGE);
    assert!(
        stderr(&remote_file).contains("requires SOURCE"),
        "{}",
        stderr(&remote_file)
    );

    let diff_file = run(&[
        "diff",
        &s(&local),
        &s(&local),
        "--computer-a",
        "example.invalid",
    ]);
    assert_eq!(code(&diff_file), USAGE);
    assert!(
        stderr(&diff_file).contains("requires SOURCE"),
        "{}",
        stderr(&diff_file)
    );

    let diff_unsupported = run(&[
        "diff",
        &s(&local),
        "HKCU\\Software",
        "--computer-b",
        "example.invalid",
    ]);
    assert_eq!(code(&diff_unsupported), USAGE);
    assert!(
        stderr(&diff_unsupported).contains("only HKLM and HKU"),
        "{}",
        stderr(&diff_unsupported)
    );

    let diff_help = run(&["diff", "--help"]);
    assert_eq!(code(&diff_help), OK);
    assert!(stdout(&diff_help).contains("--computer-a"));
    assert!(stdout(&diff_help).contains("--computer-b"));
    assert!(stdout(&diff_help).contains("--map-a"));
    assert!(stdout(&diff_help).contains("--map-b"));
    assert!(stdout(&diff_help).contains("--value"));
    assert!(stdout(&diff_help).contains("--exclude-value"));

    let dual_diff = run(&[
        "diff",
        "HKCU\\Software",
        &s(&local),
        "--computer-a",
        "example.invalid",
        "--view",
        "both",
        "--output",
        "json",
    ]);
    assert_eq!(code(&dual_diff), PARTIAL, "{}", stderr(&dual_diff));
    let report: serde_json::Value = serde_json::from_slice(&dual_diff.stdout).unwrap();
    assert_eq!(report["computerA"], "example.invalid");
    assert!(report["computerB"].is_null());
    assert_eq!(report["failures"].as_array().unwrap().len(), 2);
    assert!(report["failures"]
        .as_array()
        .unwrap()
        .iter()
        .all(|failure| failure["side"] == "a"
            && failure["problem"]
                .as_str()
                .unwrap()
                .contains("only HKLM and HKU")));

    for (command, flag) in [("probe", "--computer"), ("permissions", "--computer")] {
        let rejected = run(&[
            command,
            "HKCU\\Software",
            flag,
            "example.invalid",
            "--output",
            "json",
        ]);
        assert_eq!(code(&rejected), USAGE, "{command}: {}", stderr(&rejected));
        assert!(
            stderr(&rejected).contains("only HKLM and HKU"),
            "{command}: {}",
            stderr(&rejected)
        );
    }

    let compare_rejected = run(&[
        "permissions",
        "HKCU\\Software",
        "--compare",
        "HKCU\\Software",
        "--compare-computer",
        "example.invalid",
    ]);
    assert_eq!(code(&compare_rejected), USAGE);
    assert!(
        stderr(&compare_rejected).contains("only HKLM and HKU"),
        "{}",
        stderr(&compare_rejected)
    );

    for command in ["ls", "probe", "permissions"] {
        let help = run(&[command, "--help"]);
        assert_eq!(code(&help), OK);
        assert!(stdout(&help).contains("--computer"));
    }
    let permissions_help = run(&["permissions", "--help"]);
    assert!(stdout(&permissions_help).contains("--compare-computer"));

    let backup_path = d.path("remote.hiv");
    let backup_rejected = run(&[
        "backup",
        "HKCU\\Software",
        &s(&backup_path),
        "--computer",
        "example.invalid",
    ]);
    assert_eq!(code(&backup_rejected), USAGE);
    assert!(
        stderr(&backup_rejected).contains("only HKLM and HKU"),
        "{}",
        stderr(&backup_rejected)
    );
    assert!(!backup_path.exists());
    let backup_help = run(&["backup", "--help"]);
    assert_eq!(code(&backup_help), OK);
    assert!(stdout(&backup_help).contains("--computer"));

    let mutation = run(&[
        "set",
        "HKLM\\Software\\A",
        "-v",
        "X",
        "-d",
        "1",
        "--computer",
        "example.invalid",
    ]);
    assert_eq!(code(&mutation), USAGE);

    let unsupported_copy = run(&[
        "copy",
        "HKCU\\Software\\Source",
        "HKCU\\Software\\Destination",
        "--source-computer",
        "example.invalid",
        "-y",
    ]);
    assert_eq!(code(&unsupported_copy), USAGE);
    assert!(
        stderr(&unsupported_copy).contains("only HKLM and HKU"),
        "{}",
        stderr(&unsupported_copy)
    );

    let remote_move = run(&[
        "move",
        "HKLM\\Software\\Source",
        "HKCU\\Software\\Destination",
        "--source-computer",
        "example.invalid",
        "-y",
    ]);
    assert_eq!(code(&remote_move), USAGE);
}

#[test]
fn every_documented_command_appears_in_formats_output() {
    let o = run(&["formats"]);
    assert_eq!(code(&o), OK);
    for f in [
        "reg", "pol", "admx", "gpp", "inf", "json", "csv", "ini", "hive",
    ] {
        assert!(
            stdout(&o).contains(f),
            "format `{f}` missing from `regx formats`"
        );
    }
}

#[test]
fn input_help_lists_every_supported_text_format() {
    for command in ["import", "convert", "diff", "inspect", "sync", "plan"] {
        let o = run(&[command, "--help"]);
        assert_eq!(code(&o), OK, "`regx {command} --help` failed");
        let help = stdout(&o);
        for format in ["reg", "pol", "admx", "gpp", "inf", "json", "csv", "ini"] {
            assert!(
                help.contains(format),
                "format `{format}` missing from `regx {command} --help`"
            );
        }
    }
    for command in ["import", "diff", "sync"] {
        let o = run(&["hive", "offline.hiv", command, "--help"]);
        assert_eq!(code(&o), OK, "`regx hive {command} --help` failed");
        let help = stdout(&o);
        for format in ["reg", "pol", "admx", "gpp", "inf", "json", "csv", "ini"] {
            assert!(
                help.contains(format),
                "format `{format}` missing from `regx hive {command} --help`"
            );
        }
    }
    let hive_export = run(&["hive", "offline.hiv", "export", "--help"]);
    assert_eq!(code(&hive_export), OK);
    for format in ["reg", "json", "csv", "pol"] {
        assert!(
            stdout(&hive_export).contains(format),
            "output format `{format}` missing from `regx hive export --help`"
        );
    }
    for option in [
        "--root-as",
        "--no-recursive",
        "--include",
        "--exclude",
        "--value",
        "--exclude-value",
    ] {
        assert!(
            stdout(&hive_export).contains(option),
            "`{option}` missing from `regx hive export --help`"
        );
    }
    let live_export = run(&["export", "--help"]);
    assert_eq!(code(&live_export), OK);
    for option in [
        "--root-as",
        "--no-recursive",
        "--include",
        "--exclude",
        "--value",
        "--exclude-value",
    ] {
        assert!(
            stdout(&live_export).contains(option),
            "`{option}` missing from `regx export --help`"
        );
    }
    for command in [
        vec!["stats", "--help"],
        vec!["hive", "offline.hiv", "stats", "--help"],
    ] {
        let help = run(&command);
        assert_eq!(code(&help), OK, "{}", stderr(&help));
        for option in [
            "--root-as",
            "--include",
            "--exclude",
            "--value",
            "--exclude-value",
        ] {
            assert!(
                stdout(&help).contains(option),
                "`{option}` missing from `regx {}`",
                command.join(" ")
            );
        }
    }
}

#[test]
fn recursive_key_pruning_requires_value_pruning_acknowledgement() {
    for command in ["sync", "plan"] {
        let o = run(&[command, "missing.reg", "--prune-keys"]);
        assert_eq!(code(&o), USAGE, "regx {command}: {}", stderr(&o));
        assert!(stderr(&o).contains("--prune"), "{}", stderr(&o));
    }
}

#[test]
fn watch_uses_a_bounded_native_notification_wait() {
    let o = run(&[
        "watch",
        "HKCU\\Environment",
        "--no-recursive",
        "--timeout",
        "1",
        "--output",
        "json",
    ]);
    assert_eq!(code(&o), OK, "{}", stderr(&o));
    let text = stdout(&o);
    assert!(text.contains("\"timedOut\": true"), "{text}");
    assert!(text.contains("\"recursive\": false"), "{text}");

    let both = run(&[
        "watch",
        "HKCU\\Environment",
        "--view",
        "both",
        "--timeout",
        "1",
        "--output",
        "json",
    ]);
    assert_eq!(code(&both), OK, "{}", stderr(&both));
    let json: serde_json::Value = serde_json::from_slice(&both.stdout).unwrap();
    assert_eq!(json["timedOut"], true);
    assert_eq!(json["views"].as_array().map(Vec::len), Some(2));
}

#[test]
fn watch_view_both_identifies_the_trigger_and_diffs_each_view() {
    if skip_if_hkcu_not_writable("dual-view watch notification") {
        return;
    }
    let key = LiveKey::new("watch-both");
    let created = run(&[
        "set",
        key.as_str(),
        "-v",
        "Value",
        "-d",
        "before",
        "--view",
        "both",
        "-y",
    ]);
    assert_eq!(code(&created), OK, "{}", stderr(&created));

    let watcher = Command::new(bin())
        .args([
            "watch",
            key.as_str(),
            "--view",
            "both",
            "--timeout",
            "5",
            "--output",
            "json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let changed = run(&[
        "set",
        key.as_str(),
        "-v",
        "Value",
        "-d",
        "after",
        "--view",
        "32",
        "-y",
    ]);
    assert_eq!(code(&changed), OK, "{}", stderr(&changed));
    let watched = watcher.wait_with_output().unwrap();
    assert_eq!(code(&watched), OK, "{}", stderr(&watched));
    let json: serde_json::Value = serde_json::from_slice(&watched.stdout).unwrap();
    assert_eq!(json["timedOut"], false);
    assert_eq!(json["triggeredView"], "32");
    assert_eq!(json["views"].as_array().map(Vec::len), Some(2));

    let _ = run(&[
        "delete",
        key.as_str(),
        "-r",
        "--view",
        "both",
        "-y",
        "--log-level",
        "error",
    ]);
}

#[test]
fn backup_view_both_writes_and_names_each_hive() {
    let d = Scratch::new("backup-both");
    let base = d.path("registry.hiv");
    let o = run(&[
        "backup",
        "HKCU\\Environment",
        &s(&base),
        "--view",
        "both",
        "--output",
        "json",
    ]);
    assert_eq!(code(&o), OK, "{}", stderr(&o));
    let json: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(json["sourceComputer"].is_null());
    let views = json["views"].as_array().unwrap();
    assert_eq!(views.len(), 2);
    assert_eq!(views[0]["view"], "32");
    assert!(views[0]["file"]
        .as_str()
        .unwrap()
        .ends_with("registry.32.hiv"));
    assert_eq!(views[1]["view"], "64");
    assert!(views[1]["file"]
        .as_str()
        .unwrap()
        .ends_with("registry.64.hiv"));
    for (index, hive) in [d.path("registry.32.hiv"), d.path("registry.64.hiv")]
        .into_iter()
        .enumerate()
    {
        assert!(hive.exists());
        assert_eq!(
            views[index]["bytes"].as_u64().unwrap(),
            std::fs::metadata(&hive).unwrap().len()
        );
        let digest = views[index]["sha256"].as_str().unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let info = run(&["hive", &s(&hive), "info", "--output", "json"]);
        assert_eq!(code(&info), OK, "{}", stderr(&info));
        serde_json::from_slice::<serde_json::Value>(&info.stdout).unwrap();
    }
}

#[test]
fn backup_and_restore_view_both_round_trip() {
    if skip_if_hkcu_not_writable("dual-view backup/restore contract") {
        return;
    }
    let d = Scratch::new("restore-both");
    let base = d.path("registry.hiv");
    let undo = d.path("restore.undo.reg");
    let dest = LiveKey::new("restore-both-dest");
    let saved = run(&[
        "backup",
        "HKCU\\Environment",
        &s(&base),
        "--view",
        "both",
        "--output",
        "json",
    ]);
    assert_eq!(code(&saved), OK, "{}", stderr(&saved));

    let restored = run(&[
        "restore",
        &s(&base),
        dest.as_str(),
        "--view",
        "both",
        "--backup",
        &s(&undo),
        "-y",
        "--output",
        "json",
    ]);
    assert_eq!(code(&restored), OK, "{}", stderr(&restored));
    let json: serde_json::Value = serde_json::from_slice(&restored.stdout).unwrap();
    assert_eq!(json["views"].as_array().map(Vec::len), Some(2));
    assert!(d.path("restore.undo.32.reg").exists());
    assert!(d.path("restore.undo.64.reg").exists());
    for (view, undo_file) in json["views"]
        .as_array()
        .unwrap()
        .iter()
        .zip([d.path("restore.undo.32.reg"), d.path("restore.undo.64.reg")])
    {
        assert_eq!(
            view["undoBytes"].as_u64().unwrap(),
            std::fs::metadata(&undo_file).unwrap().len()
        );
        assert_eq!(view["undoSha256"].as_str().unwrap().len(), 64);
    }

    let queried = run(&["query", dest.as_str(), "--view", "both", "--output", "json"]);
    assert_eq!(code(&queried), OK, "{}", stderr(&queried));
    let views: serde_json::Value = serde_json::from_slice(&queried.stdout).unwrap();
    assert_eq!(views["views"].as_array().map(Vec::len), Some(2));
}

#[test]
fn copy_and_move_view_both_preserve_wow64_state_and_write_undo_pairs() {
    if skip_if_hkcu_not_writable("dual-view copy/move contract") {
        return;
    }
    let d = Scratch::new("copy-move-both");
    let source = LiveKey::new("copy-move-both-source");
    let copied = LiveKey::new("copy-move-both-copy");
    let moved = LiveKey::new("copy-move-both-move");
    let seeded = run(&[
        "set",
        source.as_str(),
        "-v",
        "Marker",
        "-t",
        "REG_SZ",
        "-d",
        "dual",
        "--view",
        "both",
        "-y",
    ]);
    assert_eq!(code(&seeded), OK, "{}", stderr(&seeded));

    let copy_undo = d.path("copy.undo.reg");
    let copy = run(&[
        "copy",
        source.as_str(),
        copied.as_str(),
        "--view",
        "both",
        "--backup",
        &s(&copy_undo),
        "-y",
        "--output",
        "json",
    ]);
    assert_eq!(code(&copy), OK, "{}", stderr(&copy));
    let copy_json: serde_json::Value = serde_json::from_slice(&copy.stdout).unwrap();
    assert_eq!(copy_json["views"].as_array().map(Vec::len), Some(2));
    assert!(d.path("copy.undo.32.reg").exists());
    assert!(d.path("copy.undo.64.reg").exists());
    for (view, path) in copy_json["views"]
        .as_array()
        .unwrap()
        .iter()
        .zip([d.path("copy.undo.32.reg"), d.path("copy.undo.64.reg")])
    {
        assert_eq!(
            view["backupBytes"].as_u64().unwrap(),
            std::fs::metadata(path).unwrap().len()
        );
        assert_eq!(view["backupSha256"].as_str().unwrap().len(), 64);
    }

    let move_undo = d.path("move.undo.reg");
    let moved_out = run(&[
        "move",
        source.as_str(),
        moved.as_str(),
        "--view",
        "both",
        "--backup",
        &s(&move_undo),
        "-y",
        "--output",
        "json",
    ]);
    assert_eq!(code(&moved_out), OK, "{}", stderr(&moved_out));
    assert!(d.path("move.undo.32.reg").exists());
    assert!(d.path("move.undo.64.reg").exists());

    for destination in [copied.as_str(), moved.as_str()] {
        let queried = run(&[
            "query",
            destination,
            "-v",
            "Marker",
            "--view",
            "both",
            "--output",
            "json",
        ]);
        assert_eq!(code(&queried), OK, "{}", stderr(&queried));
        let json: serde_json::Value = serde_json::from_slice(&queried.stdout).unwrap();
        assert_eq!(json["views"].as_array().map(Vec::len), Some(2));
    }
    let source_missing = run(&[
        "query",
        source.as_str(),
        "--view",
        "both",
        "--output",
        "json",
    ]);
    assert_eq!(
        code(&source_missing),
        NOT_FOUND,
        "{}",
        stderr(&source_missing)
    );
}

#[test]
fn saved_copy_plan_view_both_verifies_and_applies_as_one_operation() {
    if skip_if_hkcu_not_writable("dual-view saved copy plan contract") {
        return;
    }
    let d = Scratch::new("copy-plan-both");
    let source = LiveKey::new("copy-plan-both-source");
    let destination = LiveKey::new("copy-plan-both-destination");
    let plan = d.path("copy.plan.json");
    let undo = d.path("apply.undo.reg");
    assert_eq!(
        code(&run(&[
            "set",
            source.as_str(),
            "-v",
            "Marker",
            "-d",
            "bound",
            "--view",
            "both",
            "-y",
        ])),
        OK
    );
    let saved = run(&[
        "copy",
        source.as_str(),
        destination.as_str(),
        "--view",
        "both",
        "--save-plan",
        &s(&plan),
        "--output",
        "json",
    ]);
    assert_eq!(code(&saved), OK, "{}", stderr(&saved));
    assert!(d.path("copy.plan.32.json").exists());
    assert!(d.path("copy.plan.64.json").exists());
    let saved_json: serde_json::Value =
        serde_json::from_slice(&saved.stdout).expect("saved dual-view copy plan JSON");
    for (view, path) in saved_json["views"]
        .as_array()
        .unwrap()
        .iter()
        .zip([d.path("copy.plan.32.json"), d.path("copy.plan.64.json")])
    {
        assert_eq!(
            view["planBytes"].as_u64().unwrap(),
            std::fs::metadata(path).unwrap().len()
        );
        assert_eq!(view["planSha256"].as_str().unwrap().len(), 64);
    }

    let applied = run(&[
        "apply-copy-plan",
        &s(&plan),
        "--view",
        "both",
        "--backup",
        &s(&undo),
        "--output",
        "json",
        "-y",
    ]);
    assert_eq!(code(&applied), OK, "{}", stderr(&applied));
    let json: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert_eq!(json["views"].as_array().map(Vec::len), Some(2));
    assert!(d.path("apply.undo.32.reg").exists());
    assert!(d.path("apply.undo.64.reg").exists());
    let queried = run(&[
        "query",
        destination.as_str(),
        "-v",
        "Marker",
        "--view",
        "both",
        "--output",
        "json",
    ]);
    assert_eq!(code(&queried), OK, "{}", stderr(&queried));
}

#[test]
fn probe_view_both_reports_each_capability_independently() {
    let o = run(&[
        "probe",
        "HKCU\\Software",
        "--view",
        "both",
        "--output",
        "json",
    ]);
    assert!(
        matches!(code(&o), OK | PARTIAL | ACCESS_DENIED),
        "{}",
        stderr(&o)
    );
    let text = stdout(&o);
    let report: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(report["computer"].is_null());
    assert!(text.contains("\"view\":\"32\""), "{text}");
    assert!(text.contains("\"view\":\"64\""), "{text}");
    assert_eq!(text.matches("\"writable\"").count(), 2, "{text}");
}

#[test]
fn query_view_both_is_separate_and_json_value_filter_is_honoured() {
    let o = run(&[
        "query",
        "HKCU\\Environment",
        "-v",
        "TEMP",
        "--view",
        "both",
        "--output",
        "json",
    ]);
    assert_eq!(code(&o), OK, "{}", stderr(&o));
    let text = stdout(&o);
    assert!(text.contains("\"view\":\"32\""), "{text}");
    assert!(text.contains("\"view\":\"64\""), "{text}");
    assert!(text.contains("\"name\": \"TEMP\""), "{text}");
    assert!(!text.contains("\"name\": \"TMP\""), "{text}");

    let missing = run(&[
        "query",
        "HKCU\\Environment",
        "-v",
        "regx-definitely-missing",
        "--output",
        "json",
    ]);
    assert_eq!(code(&missing), NOT_FOUND, "{}", stdout(&missing));
}

#[test]
fn permissions_reports_security_descriptor_and_effective_access() {
    let o = run(&["permissions", "HKCU\\Software", "--output", "json"]);
    assert_eq!(code(&o), OK, "{}", stderr(&o));
    let text = stdout(&o);
    let report: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(report["computer"].is_null());
    for field in [
        "\"ownerSid\"",
        "\"inheritanceEnabled\"",
        "\"sddl\"",
        "\"queryValue\"",
        "\"enumerateSubkeys\"",
        "\"notify\"",
        "\"setValue\"",
        "\"createSubkey\"",
        "\"delete\"",
    ] {
        assert!(text.contains(field), "missing {field}: {text}");
    }
    assert!(text.contains("S-1-"), "{text}");
    assert!(text.contains("\"queryValue\":true"), "{text}");
}

#[test]
fn permissions_compare_reports_each_view_and_can_gate_on_drift() {
    let equal = run(&[
        "permissions",
        "HKCU\\Software",
        "--compare",
        "HKCU\\Software",
        "--view",
        "both",
        "--output",
        "json",
        "--exit-code",
    ]);
    assert_eq!(code(&equal), OK, "{}", stderr(&equal));
    let text = stdout(&equal);
    let report: serde_json::Value = serde_json::from_slice(&equal.stdout).unwrap();
    assert!(report["sourceComputer"].is_null());
    assert!(report["targetComputer"].is_null());
    assert!(text.contains("\"equal\":true"), "{text}");
    assert!(text.contains("\"view\":\"32\""), "{text}");
    assert!(text.contains("\"view\":\"64\""), "{text}");
    assert!(text.contains("\"differences\":[]"), "{text}");

    let different = run(&[
        "permissions",
        "HKCU\\Software",
        "--compare",
        "HKLM\\Software",
        "--view",
        "both",
        "--output",
        "json",
        "--exit-code",
    ]);
    assert_eq!(code(&different), PARTIAL, "{}", stderr(&different));
    let text = stdout(&different);
    assert!(text.contains("\"equal\":false"), "{text}");
    assert!(text.contains("\"sddl\""), "{text}");
}

#[test]
fn file_reading_commands_accept_stdin_once() {
    let reg = concat!(
        "Windows Registry Editor Version 5.00\n\n",
        "[HKEY_CURRENT_USER\\Software\\regx-stdin-contract]\n",
        "\"Name\"=\"pipeline\"\n"
    );

    let converted = run_stdin(&["convert", "-", "--redirect", "off"], reg);
    assert_eq!(code(&converted), OK, "{}", stderr(&converted));
    assert!(stdout(&converted).contains("regx-stdin-contract"));
    assert!(stderr(&converted).contains("<stdin>"));

    let inspected = run_stdin(&["inspect", "-", "--output", "json"], reg);
    assert_eq!(code(&inspected), OK, "{}", stderr(&inspected));
    assert!(stdout(&inspected).contains("\"file\": \"<stdin>\""));
    assert!(stdout(&inspected).contains("\"format\": \"reg\""));

    let validated = run_stdin(&["validate", "-"], reg);
    assert_eq!(code(&validated), OK, "{}", stderr(&validated));
    assert!(stdout(&validated).contains("<stdin>"));

    let repeated = run_stdin(&["merge", "-", "-"], reg);
    assert_eq!(code(&repeated), USAGE);
    assert!(stderr(&repeated).contains("can only be used once"));
}

#[test]
fn stdin_fix_requires_an_output_file() {
    let reg = "Windows Registry Editor Version 5.00\n";
    let o = run_stdin(&["validate", "-", "--fix"], reg);
    assert_eq!(code(&o), USAGE);
    assert!(stderr(&o).contains("requires --out"), "{}", stderr(&o));
}

#[test]
fn convert_emits_round_trippable_json_and_csv() {
    let d = Scratch::new("convert-output");
    let source = d.write(
        "source.reg",
        concat!(
            "Windows Registry Editor Version 5.00\n\n",
            "[HKEY_CURRENT_USER\\Software\\regx-output]\n",
            "@=\"default\"\n",
            "\"Count\"=dword:0000002a\n",
            "\"Raw\"=hex(1234):00,01,fe,ff,07\n",
            "\"Gone\"=-\n\n",
            "[HKEY_CURRENT_USER\\Software\\regx-output\\Empty]\n\n",
            "[-HKEY_CURRENT_USER\\Software\\regx-output\\Deleted]\n"
        ),
    );

    for format in ["json", "csv"] {
        let structured = d.path(&format!("out.{format}"));
        let to_structured = run(&[
            "convert",
            &s(&source),
            "--redirect",
            "off",
            "--to",
            format,
            "-o",
            &s(&structured),
        ]);
        assert_eq!(
            code(&to_structured),
            OK,
            "{format}: {}",
            stderr(&to_structured)
        );

        let roundtrip = d.path(&format!("roundtrip-{format}.reg"));
        let back = run(&[
            "convert",
            &s(&structured),
            "--redirect",
            "off",
            "-o",
            &s(&roundtrip),
        ]);
        assert_eq!(code(&back), OK, "{format}: {}", stderr(&back));

        let compared = run(&["diff", &s(&source), &s(&roundtrip), "--exit-code"]);
        assert_eq!(
            code(&compared),
            OK,
            "{format} did not round trip:\n{}\n{}",
            stdout(&compared),
            stderr(&compared)
        );
    }
}

#[test]
fn convert_writes_round_trippable_registry_pol_and_refuses_lossy_states() {
    let d = Scratch::new("convert-pol-output");
    let source = d.write(
        "source.reg",
        concat!(
            "Windows Registry Editor Version 5.00\n\n",
            "[HKEY_CURRENT_USER\\Software\\Policies\\regx-output]\n",
            "\"Gone\"=-\n",
            "\"Text\"=\"Unicode 例\"\n",
            "\"Count\"=dword:0000002a\n",
            "\"Raw\"=hex:00,01,fe,ff,07\n\n",
            "[-HKEY_CURRENT_USER\\Software\\Policies\\regx-output\\Deleted]\n"
        ),
    );
    let policy = d.path("Registry.pol");
    let converted = run(&[
        "convert",
        &s(&source),
        "--redirect",
        "off",
        "--to",
        "pol",
        "-o",
        &s(&policy),
    ]);
    assert_eq!(code(&converted), OK, "{}", stderr(&converted));
    let bytes = std::fs::read(&policy).unwrap();
    assert_eq!(&bytes[..8], b"PReg\x01\0\0\0");
    assert!(stderr(&converted).contains("HKEY_CURRENT_USER"));

    let roundtrip = d.path("roundtrip.reg");
    let back = run(&[
        "convert",
        &s(&policy),
        "--pol-root",
        "HKCU",
        "--redirect",
        "off",
        "-o",
        &s(&roundtrip),
    ]);
    assert_eq!(code(&back), OK, "{}", stderr(&back));
    let compared = run(&["diff", &s(&source), &s(&roundtrip), "--exit-code"]);
    assert_eq!(
        code(&compared),
        OK,
        "Registry.pol did not round trip:\n{}\n{}",
        stdout(&compared),
        stderr(&compared)
    );

    let streamed = run(&["convert", &s(&source), "--redirect", "off", "--to", "pol"]);
    assert_eq!(code(&streamed), OK, "{}", stderr(&streamed));
    assert_eq!(streamed.stdout, bytes);

    let empty_key = d.write(
        "empty.reg",
        "Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\Software\\Empty]\n",
    );
    let empty_policy = d.path("empty.pol");
    let empty_converted = run(&[
        "convert",
        &s(&empty_key),
        "--redirect",
        "off",
        "--to",
        "pol",
        "-o",
        &s(&empty_policy),
    ]);
    assert_eq!(code(&empty_converted), OK, "{}", stderr(&empty_converted));
    let empty_back = d.path("empty-back.reg");
    assert_eq!(
        code(&run(&[
            "convert",
            &s(&empty_policy),
            "--pol-root",
            "HKCU",
            "-o",
            &s(&empty_back)
        ])),
        OK
    );
    assert_eq!(
        code(&run(&[
            "diff",
            &s(&empty_key),
            &s(&empty_back),
            "--exit-code"
        ])),
        OK
    );

    let unsupported = d.write(
        "unsupported.reg",
        "Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\Software\\A]\n\"Custom\"=hex(1234):01\n",
    );
    let refused = run(&[
        "convert",
        &s(&unsupported),
        "--redirect",
        "off",
        "--to",
        "pol",
        "-o",
        &s(&d.path("must-not-exist.pol")),
    ]);
    assert_ne!(code(&refused), OK);
    assert!(stderr(&refused).contains("does not define registry type"));
    assert!(!d.path("must-not-exist.pol").exists());
}

#[test]
fn policy_directives_that_cannot_be_modeled_fail_closed_for_writes() {
    fn utf16z(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    }
    fn record(key: &str, name: &str, ty: u32, data: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&('[' as u16).to_le_bytes());
        bytes.extend_from_slice(&utf16z(key));
        bytes.extend_from_slice(&(';' as u16).to_le_bytes());
        bytes.extend_from_slice(&utf16z(name));
        bytes.extend_from_slice(&(';' as u16).to_le_bytes());
        bytes.extend_from_slice(&ty.to_le_bytes());
        bytes.extend_from_slice(&(';' as u16).to_le_bytes());
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(';' as u16).to_le_bytes());
        bytes.extend_from_slice(data);
        bytes.extend_from_slice(&(']' as u16).to_le_bytes());
        bytes
    }

    let d = Scratch::new("pol-fidelity");
    let policy = d.path("lossy.pol");
    let mut bytes = b"PReg\x01\0\0\0".to_vec();
    bytes.extend(record(
        "Software\\Policies\\Acme",
        "**delvals.",
        1,
        &utf16z(" "),
    ));
    std::fs::write(&policy, bytes).unwrap();

    let inspected = run(&[
        "inspect",
        &s(&policy),
        "--pol-root",
        "HKCU",
        "--output",
        "json",
    ]);
    assert_eq!(code(&inspected), PARTIAL, "{}", stderr(&inspected));
    let report: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert!(report[0]["losses"][0]
        .as_str()
        .unwrap()
        .contains("preserving subkeys"));
    assert_eq!(report[0]["keyDeletes"], 0);

    let converted_path = d.path("must-not-exist.reg");
    let converted = run(&[
        "convert",
        &s(&policy),
        "--pol-root",
        "HKCU",
        "-o",
        &s(&converted_path),
    ]);
    assert_eq!(code(&converted), PARSE, "{}", stderr(&converted));
    assert!(stderr(&converted).contains("requires an exact registry-data model"));
    assert!(!converted_path.exists());

    let imported = run(&[
        "import",
        &s(&policy),
        "--pol-root",
        "HKCU",
        "--dry-run",
        "-y",
    ]);
    assert_eq!(code(&imported), PARSE, "{}", stderr(&imported));
    assert!(stderr(&imported).contains("preserving subkeys"));
}

#[test]
fn policy_and_inf_semantic_losses_fail_closed_across_the_cli() {
    let d = Scratch::new("format-fidelity");
    let admx = d.write(
        "loss.admx",
        r#"<policyDefinitions revision="1.0" schemaVersion="1.0">
          <policies><policy name="Configured" class="User"
            key="Software\Policies\Acme" valueName="Enabled">
            <enabledValue><decimal value="1"/></enabledValue>
            <elements><text id="Server" valueName="Server"/></elements>
          </policy></policies>
        </policyDefinitions>"#,
    );
    let gpp = d.write(
        "Registry.xml",
        r#"<RegistrySettings><Registry name="Targeted">
          <Properties action="U" hive="HKCU" key="Software\Acme"
            name="Enabled" type="REG_DWORD" value="1"/>
          <Filters><FilterGroup name="Example"/></Filters>
        </Registry></RegistrySettings>"#,
    );
    let gpp_lifecycle = d.write(
        "Registry-lifecycle.xml",
        r#"<RegistrySettings><Registry name="Remove later" removePolicy="1">
          <Properties action="U" hive="HKCU" key="Software\Acme"
            name="Enabled" type="REG_DWORD" value="1"/>
        </Registry></RegistrySettings>"#,
    );
    let gpp_wrong_root = d.write(
        "Registry-wrapped.xml",
        r#"<Unrelated><Registry name="Must not be discovered">
          <Properties action="U" hive="HKCU" key="Software\Acme"
            name="Enabled" type="REG_DWORD" value="1"/>
        </Registry></Unrelated>"#,
    );
    let inf = d.write(
        "loss.inf",
        concat!(
            "[Version]\nSignature=\"$WINDOWS NT$\"\n",
            "[DefaultInstall]\nAddReg=Conditional\n",
            "[Conditional]\n",
            "HKCU,\"Software\\Acme\",\"OnlyIfMissing\",0x00000002,\"x\"\n"
        ),
    );
    let inf_token = d.write(
        "undefined-token.inf",
        concat!(
            "[Version]\nSignature=\"$WINDOWS NT$\"\n",
            "[DefaultInstall]\nAddReg=TokenData\n",
            "[TokenData]\n",
            "HKCU,\"Software\\Acme\",\"Server\",0x00000000,\"%UNDEFINED%\"\n"
        ),
    );
    let inf_duplicate = d.write(
        "duplicate-token.inf",
        concat!(
            "[Version]\nSignature=\"$WINDOWS NT$\"\n",
            "[DefaultInstall]\nAddReg=TokenData\n",
            "[TokenData]\n",
            "HKCU,\"Software\\Acme\",\"Server\",0x00000000,\"%SERVER%\"\n",
            "[Strings]\nSERVER=\"first\"\nserver=\"second\"\n"
        ),
    );

    for (label, input, expected) in [
        ("admx", admx, "administrator supplies"),
        ("gpp", gpp, "item-level targeting"),
        ("gpp-lifecycle", gpp_lifecycle.clone(), "removePolicy"),
        ("inf", inf, "current registry state"),
        ("inf-token", inf_token, "undefined [Strings] token"),
        ("inf-duplicate", inf_duplicate, "duplicate token"),
    ] {
        let inspected = run(&["inspect", &s(&input), "--output", "json"]);
        assert_eq!(code(&inspected), PARTIAL, "{label}: {}", stderr(&inspected));
        let report: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
        assert!(
            report[0]["losses"]
                .as_array()
                .unwrap()
                .iter()
                .any(|loss| loss.as_str().unwrap().contains(expected)),
            "{label}: {}",
            stdout(&inspected)
        );

        let output = d.path(&format!("{label}-must-not-exist.reg"));
        let converted = run(&["convert", &s(&input), "-o", &s(&output)]);
        assert_eq!(code(&converted), PARSE, "{label}: {}", stderr(&converted));
        assert!(!output.exists(), "{label}: partial output was created");

        let imported = run(&["import", &s(&input), "--dry-run", "-y"]);
        assert_eq!(code(&imported), PARSE, "{label}: {}", stderr(&imported));
    }

    let inspected = run(&["inspect", &s(&gpp_wrong_root), "--from", "gpp"]);
    assert_eq!(code(&inspected), PARSE, "{}", stderr(&inspected));
    assert!(
        stderr(&inspected).contains("unexpected GPP root"),
        "{}",
        stderr(&inspected)
    );
    let output = d.path("wrapped-must-not-exist.reg");
    let converted = run(&[
        "convert",
        &s(&gpp_wrong_root),
        "--from",
        "gpp",
        "-o",
        &s(&output),
    ]);
    assert_eq!(code(&converted), PARSE, "{}", stderr(&converted));
    assert!(!output.exists(), "invalid wrapper produced an artifact");

    let exact = d.write(
        "exact.reg",
        "Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\Software\\Exact]\n\"X\"=\"y\"\n",
    );
    let merged_output = d.path("lossy-merge-must-not-exist.reg");
    let merged = run(&[
        "merge",
        &s(&exact),
        &s(&gpp_lifecycle),
        "-o",
        &s(&merged_output),
    ]);
    assert_eq!(code(&merged), PARSE, "{}", stderr(&merged));
    assert!(stderr(&merged).contains("merge requires an exact"));
    assert!(
        !merged_output.exists(),
        "merge emitted output after a semantic loss"
    );
}

#[test]
fn convert_refuses_names_that_would_corrupt_reg_line_structure() {
    let json = r#"{"keys":[{"path":"HKCU\\Software\\Visible\nHidden","values":[]}]}"#;
    let output = run_stdin(
        &["convert", "-", "--from", "json", "--redirect", "off"],
        json,
    );
    assert_eq!(code(&output), 7, "{}", stderr(&output));
    assert!(
        stdout(&output).is_empty(),
        "partial .reg output was emitted"
    );
    assert!(
        stderr(&output).contains("control character"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn convert_encodes_multiline_sz_as_lossless_hex_one() {
    let json = r#"{"keys":[{"path":"HKCU\\Software\\A","values":[{"name":"Text","type":"REG_SZ","data":"first\nsecond\u0000tail"}]}]}"#;
    let converted = run_stdin(
        &["convert", "-", "--from", "json", "--redirect", "off"],
        json,
    );
    assert_eq!(code(&converted), OK, "{}", stderr(&converted));
    let reg = stdout(&converted);
    assert!(reg.contains("\"Text\"=hex(1):"), "{reg}");
    assert!(
        !reg.contains("first\nsecond"),
        "raw newline leaked into .reg"
    );

    let validated = run_stdin(&["validate", "-"], &reg);
    assert_eq!(code(&validated), OK, "{}", stderr(&validated));
}

#[test]
fn reg4_file_output_is_ansi_without_a_unicode_bom() {
    let scratch = Scratch::new("reg4-encoding");
    let source = scratch.write(
        "source.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\A]\r\n\
         \"Text\"=\"ASCII\"\r\n",
    );
    let output = scratch.path("legacy.reg");
    let converted = run(&[
        "convert",
        &s(&source),
        "--redirect",
        "off",
        "--reg4",
        "-o",
        &s(&output),
    ]);
    assert_eq!(code(&converted), OK, "{}", stderr(&converted));

    let bytes = std::fs::read(&output).unwrap();
    assert!(bytes.starts_with(b"REGEDIT4\r\n"), "{bytes:?}");
    assert!(
        !bytes.starts_with(&[0xff, 0xfe]),
        "REGEDIT4 has a UTF-16 BOM"
    );

    let streamed = run(&["convert", &s(&source), "--redirect", "off", "--reg4"]);
    assert_eq!(code(&streamed), OK, "{}", stderr(&streamed));
    assert_eq!(streamed.stdout, bytes, "stdout and file encoding diverged");

    let inspected = run(&["inspect", &s(&output), "--output", "json"]);
    assert_eq!(code(&inspected), OK, "{}", stderr(&inspected));
    assert!(stdout(&inspected).contains("\"format\": \"reg\""));
    assert!(
        stdout(&inspected).contains("\"dialect\": \"REGEDIT4\""),
        "{}",
        stdout(&inspected)
    );
    assert!(stdout(&inspected).contains("\"encoding\": \"ANSI("));
}

#[test]
fn search_filters_files_and_stdin_by_field() {
    let reg = concat!(
        "Windows Registry Editor Version 5.00\n\n",
        "[HKEY_CURRENT_USER\\Software\\Công Cụ]\n",
        "\"ServerName\"=\"example.test\"\n",
        "\"Blob\"=hex:de,ad,be,ef\n\n",
        "[HKEY_CURRENT_USER\\Software\\Other]\n",
        "\"ServerBackup\"=\"example.invalid\"\n"
    );
    let d = Scratch::new("search");
    let source = d.write("search.reg", reg);

    let by_name = run(&[
        "search",
        &s(&source),
        "servername",
        "--field",
        "name",
        "--output",
        "json",
    ]);
    assert_eq!(code(&by_name), OK, "{}", stderr(&by_name));
    assert!(stdout(&by_name).contains("\"field\": \"name\""));
    assert!(stdout(&by_name).contains("ServerName"));

    let by_raw_data = run_stdin(
        &["search", "-", "ad be", "--field", "data", "--from", "reg"],
        reg,
    );
    assert_eq!(code(&by_raw_data), OK, "{}", stderr(&by_raw_data));
    assert!(stdout(&by_raw_data).contains("Blob"));

    let absent = run(&["search", &s(&source), "not-present"]);
    assert_eq!(code(&absent), NOT_FOUND);

    let glob = run(&[
        "search",
        &s(&source),
        "Server*",
        "--match",
        "glob",
        "--field",
        "name",
        "--include",
        "HKCU\\Software\\C*",
        "--output",
        "json",
    ]);
    assert_eq!(code(&glob), OK, "{}", stderr(&glob));
    let text = stdout(&glob);
    assert!(text.contains("\"mode\": \"glob\""), "{text}");
    assert!(text.contains("ServerName"), "{text}");
    assert!(!text.contains("ServerBackup"), "{text}");

    let by_value_name = run(&[
        "search",
        &s(&source),
        "*",
        "--match",
        "glob",
        "--value",
        "Blob",
        "--exclude-value",
        "Server*",
        "--output",
        "json",
    ]);
    assert_eq!(code(&by_value_name), OK, "{}", stderr(&by_value_name));
    let scoped: serde_json::Value = serde_json::from_slice(&by_value_name.stdout).unwrap();
    assert_eq!(scoped["includeValues"], serde_json::json!(["Blob"]));
    assert_eq!(scoped["excludeValues"], serde_json::json!(["Server*"]));
    let scoped_matches = scoped["matches"].as_array().unwrap();
    assert!(!scoped_matches.is_empty());
    assert!(scoped_matches
        .iter()
        .all(|item| { item["field"] != "key" && item["name"] == "Blob" }));

    let regex = run(&[
        "search",
        &s(&source),
        "^example\\.(test|invalid)$",
        "--match",
        "regex",
        "--field",
        "data",
        "--exclude",
        "**\\Other",
    ]);
    assert_eq!(code(&regex), OK, "{}", stderr(&regex));
    assert!(stdout(&regex).contains("example.test"));
    assert!(!stdout(&regex).contains("example.invalid"));

    let exact_case = run(&[
        "search",
        &s(&source),
        "SERVERNAME",
        "--field",
        "name",
        "--case-sensitive",
    ]);
    assert_eq!(code(&exact_case), NOT_FOUND);

    let invalid = run(&["search", &s(&source), "(", "--match", "regex"]);
    assert_eq!(code(&invalid), USAGE);
    assert!(stderr(&invalid).contains("invalid search pattern"));
}

#[test]
fn search_never_fabricates_text_from_malformed_utf16() {
    let d = Scratch::new("search-malformed-utf16");
    let input = d.write(
        "malformed.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\SearchMalformed]\r\n\
         \"Broken\"=hex(2):00,d8,00,00\r\n",
    );

    let replacement = run(&[
        "search",
        &s(&input),
        "\u{fffd}",
        "--field",
        "data",
        "--output",
        "json",
    ]);
    assert_eq!(code(&replacement), NOT_FOUND, "{}", stdout(&replacement));

    let raw = run(&[
        "search",
        &s(&input),
        "00 d8 00 00",
        "--field",
        "data",
        "--output",
        "json",
    ]);
    assert_eq!(code(&raw), OK, "{}", stderr(&raw));
    let result: serde_json::Value = serde_json::from_slice(&raw.stdout).unwrap();
    assert_eq!(result["matches"][0]["field"], "data");
    assert_eq!(result["matches"][0]["exact"]["name"], "Broken");
    assert_eq!(result["matches"][0]["exact"]["typeId"], 2);
    assert_eq!(result["matches"][0]["exact"]["raw"], "00 d8 00 00");
}

#[test]
fn live_search_view_both_reports_independent_limits_and_results() {
    let output = run(&[
        "search",
        "HKCU\\Environment",
        "Environment",
        "--field",
        "key",
        "--view",
        "both",
        "--limit",
        "1",
        "--output",
        "json",
    ]);
    assert!(matches!(code(&output), OK | PARTIAL), "{}", stderr(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["limitPerView"], 1);
    let views = json["views"].as_array().unwrap();
    assert_eq!(views.len(), 2, "{}", stdout(&output));
    for view in views {
        for item in view["matches"].as_array().unwrap() {
            assert!(item["exact"].is_null(), "key matches have no value payload");
        }
    }
    assert_eq!(views[0]["view"], "32");
    assert_eq!(views[1]["view"], "64");
    assert!(views.iter().all(|view| {
        view["matches"]
            .as_array()
            .is_some_and(|matches| matches.len() == 1)
    }));
}

#[test]
fn diff_glob_filters_and_summary_keep_patch_scope_consistent() {
    let d = Scratch::new("diff-filters");
    let left = d.write(
        "left.reg",
        concat!(
            "Windows Registry Editor Version 5.00\n\n",
            "[HKEY_CURRENT_USER\\Software\\Alpha]\n\"Value\"=\"one\"\n\n",
            "[HKEY_CURRENT_USER\\Software\\Beta]\n\"Value\"=\"one\"\n"
        ),
    );
    let right = d.write(
        "right.reg",
        concat!(
            "Windows Registry Editor Version 5.00\n\n",
            "[HKEY_CURRENT_USER\\Software\\Alpha]\n\"Value\"=\"two\"\n\n",
            "[HKEY_CURRENT_USER\\Software\\Beta]\n\"Value\"=\"two\"\n"
        ),
    );

    let summary = run(&[
        "diff",
        &s(&left),
        &s(&right),
        "--include",
        "HKCU\\Software\\Alpha",
        "--summary-only",
        "--output",
        "json",
        "--exit-code",
    ]);
    assert_eq!(code(&summary), PARTIAL, "{}", stderr(&summary));
    let text = stdout(&summary);
    let report: serde_json::Value = serde_json::from_slice(&summary.stdout).unwrap();
    assert!(report["computerA"].is_null());
    assert!(report["computerB"].is_null());
    assert!(text.contains("\"summaryOnly\": true"), "{text}");
    assert!(text.contains("\"modified\": 1"), "{text}");
    assert!(text.contains("\"changes\": [\n\n  ]"), "{text}");
    assert!(!text.contains("Beta"), "{text}");

    let patch = d.path("alpha-only.reg");
    let written = run(&[
        "diff",
        &s(&left),
        &s(&right),
        "--exclude",
        "**\\Beta",
        "-o",
        &s(&patch),
    ]);
    assert_eq!(code(&written), OK, "{}", stderr(&written));
    let patch_text = String::from_utf16_lossy(
        &std::fs::read(&patch)
            .unwrap()
            .chunks_exact(2)
            .skip(1)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    );
    assert!(patch_text.contains("Alpha"), "{patch_text}");
    assert!(!patch_text.contains("Beta"), "{patch_text}");
}

#[test]
fn diff_root_mapping_compares_migrations_and_emits_target_root_patch() {
    let d = Scratch::new("diff-root-map");
    let left = d.write(
        "left.reg",
        concat!(
            "Windows Registry Editor Version 5.00\n\n",
            "[HKEY_LOCAL_MACHINE\\Software\\Vendor\\App]\n\"Channel\"=\"stable\"\n\n",
            "[HKEY_LOCAL_MACHINE\\Software\\Vendor\\App\\Child]\n\"Keep\"=dword:00000001\n"
        ),
    );
    let right = d.write(
        "right.reg",
        concat!(
            "Windows Registry Editor Version 5.00\n\n",
            "[HKEY_CURRENT_USER\\Software\\Vendor\\App]\n\"Channel\"=\"beta\"\n\n",
            "[HKEY_CURRENT_USER\\Software\\Vendor\\App\\Child]\n\"Keep\"=dword:00000001\n"
        ),
    );
    let patch = d.path("migration.reg");
    let mapping = "HKLM\\Software\\Vendor\\App=HKCU\\Software\\Vendor\\App";
    let output = run(&[
        "diff",
        &s(&left),
        &s(&right),
        "--map-a",
        mapping,
        "--output",
        "json",
        "--exit-code",
        "-o",
        &s(&patch),
    ]);
    assert_eq!(code(&output), PARTIAL, "{}", stderr(&output));
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["mapA"], mapping);
    assert!(status["mapB"].is_null());
    assert_eq!(status["added"], 0);
    assert_eq!(status["modified"], 1);
    assert_eq!(status["removed"], 0);
    assert_eq!(status["patchWritten"], true);
    assert_eq!(
        status["bytes"].as_u64().unwrap(),
        std::fs::metadata(&patch).unwrap().len()
    );
    assert_eq!(status["sha256"].as_str().unwrap().len(), 64);

    let compared = run(&["diff", &s(&left), &s(&right), "--map-a", mapping]);
    assert_eq!(code(&compared), OK, "{}", stderr(&compared));
    let text = stdout(&compared);
    assert!(text.contains("HKEY_CURRENT_USER\\Software\\Vendor\\App\\Channel"));
    assert!(!text.contains("HKEY_LOCAL_MACHINE"), "{text}");

    let patch_text = String::from_utf16_lossy(
        &std::fs::read(&patch)
            .unwrap()
            .chunks_exact(2)
            .skip(1)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    );
    assert!(patch_text.contains("HKEY_CURRENT_USER\\Software\\Vendor\\App"));
    assert!(!patch_text.contains("HKEY_LOCAL_MACHINE"), "{patch_text}");

    for bad in [
        "relative=HKCU\\Software\\Vendor\\App",
        "HKLM\\Software\\Other=HKCU\\Software\\Vendor\\App",
        "HKLM\\Software\\Vendor\\App",
    ] {
        let invalid = run(&["diff", &s(&left), &s(&right), "--map-a", bad]);
        assert_eq!(code(&invalid), USAGE, "{}: {}", bad, stderr(&invalid));
    }
}

#[test]
fn diff_value_filter_never_turns_a_scoped_delete_into_a_key_delete() {
    let d = Scratch::new("diff-values");
    let left = d.write(
        "left.reg",
        concat!(
            "Windows Registry Editor Version 5.00\n\n",
            "[HKEY_CURRENT_USER\\Software\\ScopedDiff]\n",
            "\"selected\"=hex:00,ff,7a\n",
            "\"untouched\"=\"keep me\"\n"
        ),
    );
    let empty = d.write("empty.reg", "Windows Registry Editor Version 5.00\n");
    let patch = d.path("selected-only.reg");
    let output = run(&[
        "diff",
        &s(&left),
        &s(&empty),
        "--value",
        "selected",
        "--output",
        "json",
        "--exit-code",
        "-o",
        &s(&patch),
    ]);
    assert_eq!(code(&output), PARTIAL, "{}", stderr(&output));
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["includeValues"], serde_json::json!(["selected"]));
    assert_eq!(status["excludeValues"], serde_json::json!([]));
    assert_eq!(status["added"], 0);
    assert_eq!(status["modified"], 0);
    assert_eq!(status["removed"], 1);
    assert_eq!(status["patchWritten"], true);
    assert_eq!(status["changes"][0]["leftExact"]["typeId"], 3);
    assert_eq!(status["changes"][0]["leftExact"]["raw"], "00 ff 7a");
    assert!(status["changes"][0]["rightExact"].is_null());

    let bytes = std::fs::read(&patch).unwrap();
    let patch_text = String::from_utf16_lossy(
        &bytes
            .chunks_exact(2)
            .skip(1)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    );
    assert!(patch_text.contains("\"selected\"=-"), "{patch_text}");
    assert!(!patch_text.contains("[-HKEY_"), "{patch_text}");
    assert!(!patch_text.contains("untouched"), "{patch_text}");

    let merged = d.path("merged.reg");
    let merge = run(&["merge", &s(&left), &s(&patch), "-o", &s(&merged)]);
    assert_eq!(code(&merge), OK, "{}", stderr(&merge));
    let expected = d.write(
        "expected.reg",
        concat!(
            "Windows Registry Editor Version 5.00\n\n",
            "[HKEY_CURRENT_USER\\Software\\ScopedDiff]\n",
            "\"untouched\"=\"keep me\"\n"
        ),
    );
    let verified = run(&["diff", &s(&merged), &s(&expected), "--exit-code"]);
    assert_eq!(code(&verified), OK, "{}", stdout(&verified));
}

#[test]
fn diff_view_both_writes_independent_patches_and_exit_gate() {
    let d = Scratch::new("diff-both");
    let desired_text = "Windows Registry Editor Version 5.00\r\n\r\n\
                        [HKEY_CURRENT_USER\\Environment]\r\n\
                        \"regx-dual-view-contract\"=\"expected\"\r\n";
    let desired = d.write("desired.reg", desired_text);
    let patch = d.path("drift.reg");
    let output = run(&[
        "diff",
        "HKCU\\Environment",
        &s(&desired),
        "--view",
        "both",
        "--out",
        &s(&patch),
        "--exit-code",
        "--output",
        "json",
    ]);
    assert_eq!(code(&output), PARTIAL, "{}", stderr(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let views = json["views"].as_array().unwrap();
    assert_eq!(views.len(), 2, "{}", stdout(&output));
    assert_eq!(views[0]["view"], "32");
    assert_eq!(views[1]["view"], "64");
    assert!(views.iter().all(|view| {
        view["added"].as_u64().unwrap()
            + view["modified"].as_u64().unwrap()
            + view["removed"].as_u64().unwrap()
            > 0
    }));
    for (view, file) in views
        .iter()
        .zip([d.path("drift.32.reg"), d.path("drift.64.reg")])
    {
        assert!(file.exists(), "{}", file.display());
        assert_eq!(
            view["bytes"].as_u64().unwrap(),
            std::fs::metadata(&file).unwrap().len()
        );
        assert_eq!(view["sha256"].as_str().unwrap().len(), 64);
        let parsed = run(&["validate", &s(&file), "--strict"]);
        assert_eq!(code(&parsed), OK, "{}: {}", file.display(), stderr(&parsed));
    }

    let stdin = run_stdin(
        &[
            "diff",
            "-",
            "HKCU\\Environment",
            "--view",
            "both",
            "--output",
            "json",
        ],
        desired_text,
    );
    assert_eq!(code(&stdin), OK, "{}", stderr(&stdin));
    let stdin_json: serde_json::Value = serde_json::from_slice(&stdin.stdout).unwrap();
    assert_eq!(stdin_json["views"].as_array().map(Vec::len), Some(2));
    for view in stdin_json["views"].as_array().unwrap() {
        assert!(view["bytes"].is_null());
        assert!(view["sha256"].is_null());
    }
}

#[test]
fn plan_is_structured_and_never_writes() {
    if skip_if_hkcu_not_writable("plan exact value contract") {
        return;
    }
    let key = "HKCU\\Environment";
    let value_name = format!("regx-it-plan-contract-{}", std::process::id());
    let _ = run(&[
        "delete",
        key,
        "-v",
        &value_name,
        "-y",
        "--log-level",
        "error",
    ]);
    let reg = format!(
        "Windows Registry Editor Version 5.00\n\n[{key}]\n\
         \"{value_name}\"=hex:00,ff,7a\n"
    );

    let planned = run_stdin(
        &[
            "plan",
            "-",
            "--from",
            "reg",
            "--redirect",
            "off",
            "--output",
            "json",
        ],
        &reg,
    );
    assert!(
        matches!(code(&planned), OK | PARTIAL),
        "{}",
        stderr(&planned)
    );
    let text = stdout(&planned);
    for field in [
        "\"blocked\"",
        "\"redirect\"",
        "\"policy\"",
        "\"rollback\"",
        "\"changes\"",
        "\"failures\"",
    ] {
        assert!(text.contains(field), "missing {field}:\n{text}");
    }
    let plan_json: serde_json::Value = serde_json::from_slice(&planned.stdout).unwrap();
    let raw_change = plan_json["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["name"] == value_name)
        .expect("raw value plan change");
    assert!(raw_change["before"].is_null());
    assert_eq!(raw_change["after"]["exact"]["typeId"], 3);
    assert_eq!(raw_change["after"]["exact"]["raw"], "00 ff 7a");

    let after = run(&["query", key, "-v", &value_name, "--output", "json"]);
    assert_eq!(code(&after), NOT_FOUND, "plan wrote to the registry");

    let d = Scratch::new("plan-save-contract");
    let saved_stdin = run_stdin(
        &[
            "plan",
            "-",
            "--from",
            "reg",
            "--redirect",
            "off",
            "--save",
            &s(&d.path("stdin.plan.json")),
        ],
        &reg,
    );
    assert_eq!(code(&saved_stdin), USAGE);
    assert!(stderr(&saved_stdin).contains("stdin cannot be re-verified"));

    let dry_run_save = run(&[
        "plan",
        "missing.reg",
        "--dry-run",
        "--save",
        &s(&d.path("dry.plan.json")),
    ]);
    assert_eq!(code(&dry_run_save), USAGE);
    assert!(!d.path("dry.plan.json").exists());
}

#[test]
fn copy_and_move_are_two_phase_audited_and_undoable() {
    if skip_if_hkcu_not_writable("copy/move live-registry contract") {
        return;
    }
    let source = LiveKey::new("copy-source");
    let dest = LiveKey::new("copy-dest");
    let moved = LiveKey::new("copy-moved");
    let d = Scratch::new("copy-move");
    let copy_undo = d.path("copy.undo.reg");
    let move_undo = d.path("move.undo.reg");
    let audit = d.path("audit.jsonl");

    let seeded = run(&[
        "set",
        source.as_str(),
        "-v",
        "Name",
        "-d",
        "original",
        "--redirect",
        "off",
        "-y",
    ]);
    assert_eq!(code(&seeded), OK, "{}", stderr(&seeded));
    let child = format!("{}\\Child", source.as_str());
    let seeded_child = run(&[
        "set",
        &child,
        "-v",
        "Count",
        "-t",
        "REG_DWORD",
        "-d",
        "42",
        "--redirect",
        "off",
        "-y",
    ]);
    assert_eq!(code(&seeded_child), OK, "{}", stderr(&seeded_child));

    let dry_undo = d.path("copy-dry.undo.reg");
    let preview = run(&[
        "copy",
        source.as_str(),
        dest.as_str(),
        "--backup",
        &s(&dry_undo),
        "--dry-run",
        "--output",
        "json",
        "-y",
    ]);
    assert_eq!(code(&preview), OK, "{}", stderr(&preview));
    let preview_json: serde_json::Value =
        serde_json::from_slice(&preview.stdout).expect("copy preview JSON");
    assert!(preview_json["backupBytes"].is_null());
    assert!(preview_json["backupSha256"].is_null());
    assert!(!dry_undo.exists());

    let copied = run(&[
        "copy",
        source.as_str(),
        dest.as_str(),
        "--backup",
        &s(&copy_undo),
        "--audit-log",
        &s(&audit),
        "--output",
        "json",
        "-y",
    ]);
    assert_eq!(code(&copied), OK, "{}", stderr(&copied));
    assert!(copy_undo.exists());
    let copied_json: serde_json::Value =
        serde_json::from_slice(&copied.stdout).expect("direct copy JSON");
    assert_eq!(copied_json["operation"], "copy");
    assert_eq!(
        copied_json["backupBytes"].as_u64().unwrap(),
        std::fs::metadata(&copy_undo).unwrap().len()
    );
    assert_eq!(copied_json["backupSha256"].as_str().unwrap().len(), 64);
    assert_eq!(
        code(&run(&["query", dest.as_str(), "-v", "Name"])),
        OK,
        "destination value missing"
    );

    let moved_out = run(&[
        "move",
        dest.as_str(),
        moved.as_str(),
        "--backup",
        &s(&move_undo),
        "--audit-log",
        &s(&audit),
        "-y",
    ]);
    assert_eq!(code(&moved_out), OK, "{}", stderr(&moved_out));
    assert_eq!(code(&run(&["query", dest.as_str()])), NOT_FOUND);
    assert_eq!(code(&run(&["query", moved.as_str(), "-v", "Name"])), OK);

    let undo_move = run(&[
        "import",
        &s(&move_undo),
        "--redirect",
        "off",
        "--no-backup",
        "-y",
    ]);
    assert_eq!(code(&undo_move), OK, "{}", stderr(&undo_move));
    assert_eq!(code(&run(&["query", dest.as_str(), "-v", "Name"])), OK);
    assert_eq!(code(&run(&["query", moved.as_str()])), NOT_FOUND);

    let verified = run(&["audit", &s(&audit)]);
    assert_eq!(code(&verified), OK, "{}", stderr(&verified));
    let log = std::fs::read_to_string(audit).unwrap();
    assert!(log.contains("value.set"));
    assert!(log.contains("key.delete"));
}

#[test]
fn copy_and_move_value_preserve_sibling_values_and_are_undoable() {
    if skip_if_hkcu_not_writable("copy/move value live-registry contract") {
        return;
    }
    let source = LiveKey::new("copy-value-source");
    let dest = LiveKey::new("copy-value-dest");
    let d = Scratch::new("copy-move-value");
    let copy_undo = d.path("copy-value.undo.reg");
    let move_undo = d.path("move-value.undo.reg");
    let copy_plan = d.path("copy-value.plan.json");

    for (key, name, data) in [
        (source.as_str(), "Selected", "payload"),
        (source.as_str(), "Sibling", "keep-source"),
        (dest.as_str(), "Sibling", "keep-dest"),
    ] {
        let seeded = run(&[
            "set",
            key,
            "-v",
            name,
            "-d",
            data,
            "--redirect",
            "off",
            "-y",
        ]);
        assert_eq!(code(&seeded), OK, "{}", stderr(&seeded));
    }

    let preview = run(&[
        "copy-value",
        source.as_str(),
        "Selected",
        dest.as_str(),
        "--dest-value",
        "Copied",
        "--save-plan",
        &s(&copy_plan),
        "--output",
        "json",
    ]);
    assert_eq!(code(&preview), OK, "{}", stderr(&preview));
    assert!(copy_plan.exists());
    let preview_json: serde_json::Value =
        serde_json::from_slice(&preview.stdout).expect("saved value copy plan JSON");
    assert_eq!(preview_json["operation"], "copy-value");
    assert_eq!(
        preview_json["plans"][0]["planBytes"].as_u64().unwrap(),
        std::fs::metadata(&copy_plan).unwrap().len()
    );
    assert_eq!(
        preview_json["plans"][0]["planSha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    let changed = run(&[
        "set",
        source.as_str(),
        "-v",
        "Selected",
        "-d",
        "changed-after-preview",
        "--redirect",
        "off",
        "-y",
    ]);
    assert_eq!(code(&changed), OK, "{}", stderr(&changed));
    let stale = run(&["apply-copy-plan", &s(&copy_plan), "-y"]);
    assert_eq!(code(&stale), PARTIAL, "{}", stderr(&stale));
    assert_eq!(
        code(&run(&["query", dest.as_str(), "-v", "Copied"])),
        NOT_FOUND
    );
    let restored_source = run(&[
        "set",
        source.as_str(),
        "-v",
        "Selected",
        "-d",
        "payload",
        "--redirect",
        "off",
        "-y",
    ]);
    assert_eq!(code(&restored_source), OK, "{}", stderr(&restored_source));
    let copied = run(&[
        "apply-copy-plan",
        &s(&copy_plan),
        "--backup",
        &s(&copy_undo),
        "--output",
        "json",
        "-y",
    ]);
    assert_eq!(code(&copied), OK, "{}", stderr(&copied));
    assert!(copy_undo.exists());
    let copied_json: serde_json::Value =
        serde_json::from_slice(&copied.stdout).expect("applied value copy plan JSON");
    assert_eq!(copied_json["scope"], "value");
    assert_eq!(
        copied_json["backupBytes"].as_u64().unwrap(),
        std::fs::metadata(&copy_undo).unwrap().len()
    );
    assert_eq!(copied_json["backupSha256"].as_str().unwrap().len(), 64);
    assert_eq!(code(&run(&["query", dest.as_str(), "-v", "Copied"])), OK);
    assert_eq!(code(&run(&["query", dest.as_str(), "-v", "Sibling"])), OK);
    assert_eq!(
        code(&run(&["query", source.as_str(), "-v", "Selected"])),
        OK
    );

    let collision = run(&[
        "copy-value",
        source.as_str(),
        "Selected",
        dest.as_str(),
        "--dest-value",
        "Copied",
        "-y",
    ]);
    assert_eq!(code(&collision), USAGE);
    assert!(stderr(&collision).contains("--overwrite"));

    let moved = run(&[
        "move-value",
        dest.as_str(),
        "Copied",
        source.as_str(),
        "--dest-value",
        "Renamed",
        "--backup",
        &s(&move_undo),
        "-y",
    ]);
    assert_eq!(code(&moved), OK, "{}", stderr(&moved));
    assert_eq!(
        code(&run(&["query", dest.as_str(), "-v", "Copied"])),
        NOT_FOUND
    );
    assert_eq!(code(&run(&["query", source.as_str(), "-v", "Renamed"])), OK);
    assert_eq!(code(&run(&["query", dest.as_str(), "-v", "Sibling"])), OK);

    let undo = run(&[
        "import",
        &s(&move_undo),
        "--redirect",
        "off",
        "--no-backup",
        "-y",
    ]);
    assert_eq!(code(&undo), OK, "{}", stderr(&undo));
    assert_eq!(code(&run(&["query", dest.as_str(), "-v", "Copied"])), OK);
    assert_eq!(
        code(&run(&["query", source.as_str(), "-v", "Renamed"])),
        NOT_FOUND
    );
}

#[test]
fn saved_copy_plan_applies_only_while_source_and_destination_match() {
    if skip_if_hkcu_not_writable("saved copy-plan live-state contract") {
        return;
    }
    let source = LiveKey::new("copy-plan-source");
    let destination = LiveKey::new("copy-plan-destination");
    let stale_source_destination = LiveKey::new("copy-plan-stale-source");
    let stale_destination = LiveKey::new("copy-plan-stale-destination");
    let d = Scratch::new("copy-plan");

    assert_eq!(
        code(&run(&[
            "set",
            source.as_str(),
            "-v",
            "Name",
            "-d",
            "planned",
            "--redirect",
            "off",
            "-y",
        ])),
        OK
    );

    let plan = d.path("copy.plan.json");
    let preview = run(&[
        "copy",
        source.as_str(),
        destination.as_str(),
        "--save-plan",
        &s(&plan),
        "--output",
        "json",
    ]);
    assert_eq!(code(&preview), OK, "{}", stderr(&preview));
    assert!(plan.exists());
    let preview_json: serde_json::Value =
        serde_json::from_slice(&preview.stdout).expect("saved copy plan JSON");
    assert_eq!(preview_json["saved"], true);
    assert_eq!(
        preview_json["planBytes"].as_u64().unwrap(),
        std::fs::metadata(&plan).unwrap().len()
    );
    assert_eq!(preview_json["planSha256"].as_str().unwrap().len(), 64);
    assert_eq!(code(&run(&["query", destination.as_str()])), NOT_FOUND);

    let undo = d.path("copy-plan.undo.reg");
    let applied = run(&[
        "apply-copy-plan",
        &s(&plan),
        "--backup",
        &s(&undo),
        "--output",
        "json",
        "-y",
    ]);
    assert_eq!(code(&applied), OK, "{}", stderr(&applied));
    assert!(undo.exists());
    assert!(
        stdout(&applied)
            .contains("\"schema\":\"https://winregistry.org/schemas/copy-plan-result-v2.json\""),
        "{}",
        stdout(&applied)
    );
    assert_eq!(
        code(&run(&["query", destination.as_str(), "-v", "Name"])),
        OK
    );

    let stale_source_plan = d.path("stale-source.plan.json");
    assert_eq!(
        code(&run(&[
            "copy",
            source.as_str(),
            stale_source_destination.as_str(),
            "--save-plan",
            &s(&stale_source_plan),
        ])),
        OK
    );
    assert_eq!(
        code(&run(&[
            "set",
            source.as_str(),
            "-v",
            "Name",
            "-d",
            "changed",
            "--redirect",
            "off",
            "-y",
        ])),
        OK
    );
    let rejected_source = run(&["apply-copy-plan", &s(&stale_source_plan), "-y"]);
    assert_eq!(code(&rejected_source), PARTIAL);
    assert!(stderr(&rejected_source).contains("source changed"));
    assert_eq!(
        code(&run(&["query", stale_source_destination.as_str()])),
        NOT_FOUND
    );

    let stale_destination_plan = d.path("stale-destination.plan.json");
    assert_eq!(
        code(&run(&[
            "copy",
            source.as_str(),
            stale_destination.as_str(),
            "--save-plan",
            &s(&stale_destination_plan),
        ])),
        OK
    );
    assert_eq!(
        code(&run(&[
            "set",
            stale_destination.as_str(),
            "-v",
            "External",
            "-d",
            "preserve",
            "--redirect",
            "off",
            "-y",
        ])),
        OK
    );
    let rejected_destination = run(&["apply-copy-plan", &s(&stale_destination_plan), "-y"]);
    assert_eq!(code(&rejected_destination), PARTIAL);
    assert!(stderr(&rejected_destination).contains("current state changed"));
    assert_eq!(
        code(&run(&[
            "query",
            stale_destination.as_str(),
            "-v",
            "External",
        ])),
        OK
    );
}

#[test]
fn backup_and_restore_application_hive_round_trip() {
    if skip_if_hkcu_not_writable("backup/restore live-registry contract") {
        return;
    }
    let source = LiveKey::new("backup-source");
    let d = Scratch::new("backup-restore");
    let hive = d.path("snapshot.hiv");
    let undo = d.path("restore.undo.reg");

    let seeded = run(&[
        "set",
        source.as_str(),
        "-v",
        "Name",
        "-d",
        "native-hive",
        "--redirect",
        "off",
        "-y",
    ]);
    assert_eq!(code(&seeded), OK, "{}", stderr(&seeded));
    let child = format!("{}\\Child", source.as_str());
    assert_eq!(
        code(&run(&[
            "set",
            &child,
            "-v",
            "Count",
            "-t",
            "REG_DWORD",
            "-d",
            "42",
            "--redirect",
            "off",
            "-y",
        ])),
        OK
    );

    let saved = run(&["backup", source.as_str(), &s(&hive), "--output", "json"]);
    assert_eq!(code(&saved), OK, "{}", stderr(&saved));
    let saved_json: serde_json::Value = serde_json::from_slice(&saved.stdout).unwrap();
    assert!(saved_json["sourceComputer"].is_null());
    assert!(hive.exists());
    assert_eq!(
        saved_json["bytes"].as_u64().unwrap(),
        std::fs::metadata(&hive).unwrap().len()
    );
    assert_eq!(saved_json["sha256"].as_str().unwrap().len(), 64);
    assert!(stdout(&saved).contains("\"limitations\""));
    assert_eq!(code(&run(&["hive", &s(&hive), "info"])), OK);

    assert_eq!(code(&run(&["delete", source.as_str(), "-r", "-y"])), OK);
    let restored = run(&[
        "restore",
        &s(&hive),
        source.as_str(),
        "--backup",
        &s(&undo),
        "--output",
        "json",
        "-y",
    ]);
    assert_eq!(code(&restored), OK, "{}", stderr(&restored));
    assert!(undo.exists());
    let restored_json: serde_json::Value = serde_json::from_slice(&restored.stdout).unwrap();
    assert_eq!(restored_json["rolledBack"], false);
    assert_eq!(
        restored_json["undoBytes"].as_u64().unwrap(),
        std::fs::metadata(&undo).unwrap().len()
    );
    assert_eq!(restored_json["undoSha256"].as_str().unwrap().len(), 64);
    assert_eq!(code(&run(&["query", source.as_str(), "-v", "Name"])), OK);
    assert_eq!(code(&run(&["query", &child, "-v", "Count"])), OK);
}

#[test]
fn set_and_delete_view_both_report_each_atomic_phase() {
    if skip_if_hkcu_not_writable("dual-view mutation contract") {
        return;
    }
    let key = LiveKey::new("view-both");
    let set = run(&[
        "set",
        key.as_str(),
        "-v",
        "Name",
        "-d",
        "both",
        "--redirect",
        "off",
        "--view",
        "both",
        "--output",
        "json",
        "-y",
    ]);
    assert_eq!(code(&set), OK, "{}", stderr(&set));
    let set_json = stdout(&set);
    assert!(set_json.contains("\"view\":\"32\""), "{set_json}");
    assert!(set_json.contains("\"view\":\"64\""), "{set_json}");
    assert_eq!(set_json.matches("\"rolledBack\":false").count(), 2);

    let deleted = run(&[
        "delete",
        key.as_str(),
        "-v",
        "Name",
        "--view",
        "both",
        "--output",
        "json",
        "-y",
    ]);
    assert_eq!(code(&deleted), OK, "{}", stderr(&deleted));
    let delete_json = stdout(&deleted);
    assert!(delete_json.contains("\"view\":\"32\""), "{delete_json}");
    assert!(delete_json.contains("\"view\":\"64\""), "{delete_json}");
}

#[test]
fn import_view_both_writes_and_uses_distinct_undo_snapshots() {
    if skip_if_hkcu_not_writable("dual-view import contract") {
        return;
    }
    let key = LiveKey::new("import-view-both");
    let d = Scratch::new("import-view-both");
    let source = d.write(
        "source.reg",
        &format!(
            "Windows Registry Editor Version 5.00\n\n[{}]\n\"Name\"=\"both\"\n",
            key.as_str()
        ),
    );
    let undo_base = d.path("bundle.reg");
    let imported = run(&[
        "import",
        &s(&source),
        "--redirect",
        "off",
        "--view",
        "both",
        "--backup",
        &s(&undo_base),
        "--output",
        "json",
        "-y",
    ]);
    assert_eq!(code(&imported), OK, "{}", stderr(&imported));
    let text = stdout(&imported);
    assert!(text.contains("\"view\":\"32\""), "{text}");
    assert!(text.contains("\"view\":\"64\""), "{text}");
    let imported_json: serde_json::Value =
        serde_json::from_slice(&imported.stdout).expect("dual-view import JSON");
    let undo32 = d.path("bundle.32.reg");
    let undo64 = d.path("bundle.64.reg");
    assert!(undo32.exists(), "32-bit undo snapshot missing");
    assert!(undo64.exists(), "64-bit undo snapshot missing");
    for (view, path) in imported_json["views"]
        .as_array()
        .unwrap()
        .iter()
        .zip([&undo32, &undo64])
    {
        assert_eq!(
            view["undoBytes"].as_u64().unwrap(),
            std::fs::metadata(path).unwrap().len()
        );
        assert_eq!(view["undoSha256"].as_str().unwrap().len(), 64);
    }

    let redo_base = d.path("redo.reg");
    let reverted = run(&[
        "undo",
        &s(&undo32),
        "--view",
        "both",
        "--backup",
        &s(&redo_base),
        "--output",
        "json",
        "-y",
    ]);
    assert_eq!(code(&reverted), OK, "{}", stderr(&reverted));
    let reverted_json: serde_json::Value =
        serde_json::from_slice(&reverted.stdout).expect("undo JSON");
    assert_eq!(reverted_json["atomic"], true);
    assert_eq!(reverted_json["views"].as_array().unwrap().len(), 2);
    assert_eq!(reverted_json["views"][0]["redo"], s(&d.path("redo.32.reg")));
    assert_eq!(reverted_json["views"][1]["redo"], s(&d.path("redo.64.reg")));
    assert!(reverted_json["views"][0].get("undo").is_none());
    assert!(d.path("redo.32.reg").is_file());
    assert!(d.path("redo.64.reg").is_file());
    for (view, path) in reverted_json["views"]
        .as_array()
        .unwrap()
        .iter()
        .zip([d.path("redo.32.reg"), d.path("redo.64.reg")])
    {
        assert_eq!(
            view["redoBytes"].as_u64().unwrap(),
            std::fs::metadata(path).unwrap().len()
        );
        assert_eq!(view["redoSha256"].as_str().unwrap().len(), 64);
    }
    for view in ["32", "64"] {
        let queried = run(&["query", key.as_str(), "--view", view]);
        assert_eq!(
            code(&queried),
            NOT_FOUND,
            "view {view}: {}",
            stdout(&queried)
        );
    }
}

#[test]
fn undo_dry_run_is_reversible_in_json_and_requires_complete_bundles() {
    let d = Scratch::new("undo-dry-run");
    let key = "HKCU\\Software\\regx-it-undo-dry-run";
    let member32 = d.write(
        "bundle.32.reg",
        &format!("Windows Registry Editor Version 5.00\n\n[-{key}]\n"),
    );
    let missing_pair = run(&["undo", &s(&member32), "--view", "both", "--dry-run", "-y"]);
    assert_ne!(code(&missing_pair), OK);
    assert!(
        stderr(&missing_pair).contains("bundle.64.reg"),
        "{}",
        stderr(&missing_pair)
    );

    let _member64 = d.write(
        "bundle.64.reg",
        &format!("Windows Registry Editor Version 5.00\n\n[-{key}]\n"),
    );
    let redo = d.path("redo.reg");
    let preview = run(&[
        "undo",
        &s(&member32),
        "--view",
        "both",
        "--backup",
        &s(&redo),
        "--dry-run",
        "--output",
        "json",
        "-y",
    ]);
    assert_eq!(code(&preview), OK, "{}", stderr(&preview));
    let json: serde_json::Value =
        serde_json::from_slice(&preview.stdout).expect("undo preview JSON");
    assert_eq!(json["atomic"], true);
    assert_eq!(json["views"].as_array().unwrap().len(), 2);
    assert_eq!(json["views"][0]["redo"], s(&d.path("redo.32.reg")));
    assert_eq!(json["views"][1]["redo"], s(&d.path("redo.64.reg")));
    assert!(json["views"][0].get("undo").is_none());
    for view in json["views"].as_array().unwrap() {
        assert!(view["redoBytes"].is_null());
        assert!(view["redoSha256"].is_null());
    }
    assert!(!d.path("redo.32.reg").exists());
    assert!(!d.path("redo.64.reg").exists());
}

#[test]
fn import_and_export_select_values_without_applying_key_operations() {
    if skip_if_hkcu_not_writable("value-level import/export selection") {
        return;
    }
    let d = Scratch::new("value-selection");
    let key = LiveKey::new("value-selection");
    for (name, value) in [("Keep", "old-keep"), ("Drop", "old-drop")] {
        let seeded = run(&[
            "set",
            key.as_str(),
            "-v",
            name,
            "-d",
            value,
            "--redirect",
            "off",
            "--view",
            "both",
            "-y",
        ]);
        assert_eq!(code(&seeded), OK, "{}", stderr(&seeded));
    }
    let child = format!("{}\\Child", key.as_str());
    let seeded_child = run(&[
        "set",
        &child,
        "-v",
        "Nested",
        "-d",
        "child",
        "--redirect",
        "off",
        "--view",
        "both",
        "-y",
    ]);
    assert_eq!(code(&seeded_child), OK, "{}", stderr(&seeded_child));

    let selected = d.path("selected.reg");
    let exported = run(&[
        "export",
        key.as_str(),
        "--value",
        "keep",
        "-o",
        &s(&selected),
        "--output",
        "json",
    ]);
    assert_eq!(code(&exported), OK, "{}", stderr(&exported));
    let selected_status: serde_json::Value = serde_json::from_slice(&exported.stdout).unwrap();
    assert_eq!(selected_status["format"], "reg");
    assert_eq!(selected_status["recursive"], true);
    assert_eq!(selected_status["includeValues"][0], "keep");
    assert_eq!(selected_status["keys"], 1);
    assert_eq!(selected_status["values"], 1);
    let inspected = run(&["search", &s(&selected), "*", "--match", "glob"]);
    assert_eq!(code(&inspected), OK, "{}", stderr(&inspected));
    assert!(stdout(&inspected).contains("Keep"));
    assert!(!stdout(&inspected).contains("Drop"));

    let absent = d.path("absent.reg");
    let no_match = run(&[
        "export",
        key.as_str(),
        "--value",
        "Missing*",
        "-o",
        &s(&absent),
    ]);
    assert_eq!(code(&no_match), NOT_FOUND);
    assert!(!absent.exists());

    let shallow = d.path("shallow.json");
    let shallow_export = run(&[
        "export",
        key.as_str(),
        "--no-recursive",
        "--to",
        "json",
        "-o",
        &s(&shallow),
        "--output",
        "json",
    ]);
    assert_eq!(code(&shallow_export), OK, "{}", stderr(&shallow_export));
    let shallow_status: serde_json::Value = serde_json::from_slice(&shallow_export.stdout).unwrap();
    assert_eq!(shallow_status["recursive"], false);
    assert_eq!(shallow_status["keys"], 1);
    assert_eq!(shallow_status["values"], 2);
    let child_in_shallow = run(&["search", &s(&shallow), "Nested", "--field", "name"]);
    assert_eq!(code(&child_in_shallow), NOT_FOUND);

    let scoped = d.path("child-only.json");
    let scoped_export = run(&[
        "export",
        key.as_str(),
        "--include",
        "**\\Child",
        "--to",
        "json",
        "-o",
        &s(&scoped),
        "--output",
        "json",
    ]);
    assert_eq!(code(&scoped_export), OK, "{}", stderr(&scoped_export));
    let scoped_status: serde_json::Value = serde_json::from_slice(&scoped_export.stdout).unwrap();
    assert_eq!(scoped_status["include"], serde_json::json!(["**\\Child"]));
    assert_eq!(scoped_status["keys"], 1);
    assert_eq!(scoped_status["values"], 1);
    let scoped_data: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&scoped).unwrap()).unwrap();
    assert_eq!(scoped_data["keys"].as_array().unwrap().len(), 1);
    assert!(scoped_data["keys"][0]["path"]
        .as_str()
        .unwrap()
        .ends_with("\\Child"));

    let no_key_artifact = d.path("missing-key.reg");
    let no_key_match = run(&[
        "export",
        key.as_str(),
        "--include",
        "**\\Missing",
        "-o",
        &s(&no_key_artifact),
    ]);
    assert_eq!(code(&no_key_match), NOT_FOUND);
    assert!(!no_key_artifact.exists());

    let source = d.write(
        "source.reg",
        &format!(
            "Windows Registry Editor Version 5.00\r\n\r\n[{}]\r\n\
             \"Keep\"=\"new-keep\"\r\n\"Drop\"=\"new-drop\"\r\n\r\n\
             [-{}\\Child]\r\n",
            key.as_str(),
            key.as_str()
        ),
    );
    let imported = run(&[
        "import",
        &s(&source),
        "--value",
        "Keep",
        "--redirect",
        "off",
        "--view",
        "both",
        "-y",
    ]);
    assert_eq!(code(&imported), OK, "{}", stderr(&imported));

    for (name, expected) in [("Keep", "new-keep"), ("Drop", "old-drop")] {
        let queried = run(&[
            "query",
            key.as_str(),
            "-v",
            name,
            "--view",
            "both",
            "--output",
            "json",
        ]);
        assert_eq!(code(&queried), OK, "{}", stderr(&queried));
        assert!(stdout(&queried).contains(expected), "{}", stdout(&queried));
    }
}

#[test]
fn dual_view_plan_emits_independent_view_results_and_undo_paths() {
    let reg = concat!(
        "Windows Registry Editor Version 5.00\n\n",
        "[HKEY_CURRENT_USER\\Software\\regx-it-plan-both]\n",
        "\"Enabled\"=dword:00000001\n"
    );
    let o = run_stdin(
        &[
            "plan",
            "-",
            "--from",
            "reg",
            "--redirect",
            "off",
            "--view",
            "both",
            "--output",
            "json",
        ],
        reg,
    );
    assert!(matches!(code(&o), OK | PARTIAL), "{}", stderr(&o));
    let text = stdout(&o);
    assert!(text.contains("\"views\""), "{text}");
    assert!(text.contains("\"view\": \"32\""), "{text}");
    assert!(text.contains("\"view\": \"64\""), "{text}");
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    let path32 = document["views"][0]["rollback"]["path"]
        .as_str()
        .expect("32-bit rollback path");
    let path64 = document["views"][1]["rollback"]["path"]
        .as_str()
        .expect("64-bit rollback path");
    assert!(path32.ends_with(".undo.32.reg"), "{path32}");
    assert!(path64.ends_with(".undo.64.reg"), "{path64}");
    assert_eq!(
        path32.strip_suffix(".32.reg"),
        path64.strip_suffix(".64.reg"),
        "both views must belong to one unique undo bundle"
    );
    assert!(!Path::new(path32).exists());
    assert!(!Path::new(path64).exists());

    let text_plan = run_stdin(
        &[
            "plan",
            "-",
            "--from",
            "reg",
            "--redirect",
            "off",
            "--view",
            "both",
        ],
        reg,
    );
    assert!(
        matches!(code(&text_plan), OK | PARTIAL),
        "{}",
        stderr(&text_plan)
    );
    let text = stdout(&text_plan);
    assert!(text.contains("View 32"), "{text}");
    assert!(text.contains("View 64"), "{text}");
}

#[test]
fn saved_plan_applies_only_while_source_and_current_state_match() {
    if skip_if_hkcu_not_writable("saved-plan live-state contract") {
        return;
    }
    let d = Scratch::new("saved-plan");
    let key = LiveKey::new("saved-plan");
    let seed = run(&[
        "set",
        key.as_str(),
        "-v",
        "Channel",
        "-d",
        "seed",
        "--redirect",
        "off",
        "--view",
        "both",
        "-y",
    ]);
    assert_eq!(code(&seed), OK, "{}", stderr(&seed));

    let source_text = |value: &str| {
        format!(
            "Windows Registry Editor Version 5.00\r\n\r\n[{}]\r\n\"Channel\"=\"{value}\"\r\n",
            key.as_str()
        )
    };
    let source = d.write("desired.reg", &source_text("planned"));
    let single_artifact = d.path("single.plan.json");
    let single_planned = run(&[
        "plan",
        &s(&source),
        "--redirect",
        "off",
        "--save",
        &s(&single_artifact),
        "--output",
        "json",
    ]);
    assert_eq!(code(&single_planned), OK, "{}", stderr(&single_planned));
    let single_json: serde_json::Value =
        serde_json::from_slice(&single_planned.stdout).expect("saved single-view plan JSON");
    assert_eq!(
        single_json["savedPlan"].as_str(),
        Some(single_artifact.to_string_lossy().as_ref())
    );
    assert_eq!(
        single_json["savedPlanBytes"].as_u64().unwrap(),
        std::fs::metadata(&single_artifact).unwrap().len()
    );
    assert_eq!(single_json["savedPlanSha256"].as_str().unwrap().len(), 64);

    let artifact = d.path("change.plan.json");
    let planned = run(&[
        "plan",
        &s(&source),
        "--redirect",
        "off",
        "--view",
        "both",
        "--save",
        &s(&artifact),
        "--output",
        "json",
    ]);
    assert_eq!(code(&planned), OK, "{}", stderr(&planned));
    assert!(artifact.exists());
    let planned_json: serde_json::Value =
        serde_json::from_slice(&planned.stdout).expect("saved dual-view plan JSON");
    assert_eq!(
        planned_json["savedPlanBytes"].as_u64().unwrap(),
        std::fs::metadata(&artifact).unwrap().len()
    );
    assert_eq!(planned_json["savedPlanSha256"].as_str().unwrap().len(), 64);

    let applied = run(&["apply-plan", &s(&artifact), "-y", "--output", "json"]);
    assert_eq!(code(&applied), OK, "{}", stderr(&applied));
    let applied_json: serde_json::Value =
        serde_json::from_slice(&applied.stdout).expect("apply-plan JSON");
    assert_eq!(applied_json["views"].as_array().unwrap().len(), 2);
    for view in applied_json["views"].as_array().unwrap() {
        let undo = PathBuf::from(view["undo"].as_str().unwrap());
        assert_eq!(
            view["undoBytes"].as_u64().unwrap(),
            std::fs::metadata(undo).unwrap().len()
        );
        assert_eq!(view["undoSha256"].as_str().unwrap().len(), 64);
    }

    let stale_source = d.write("stale-source.reg", &source_text("source-next"));
    let stale_source_plan = d.path("stale-source.plan.json");
    assert_eq!(
        code(&run(&[
            "plan",
            &s(&stale_source),
            "--redirect",
            "off",
            "--view",
            "both",
            "--save",
            &s(&stale_source_plan),
        ])),
        OK
    );
    std::fs::write(&stale_source, format!("{}\r\n", source_text("source-next"))).unwrap();
    let rejected_source = run(&["apply-plan", &s(&stale_source_plan), "-y"]);
    assert_eq!(code(&rejected_source), PARTIAL);
    assert!(stderr(&rejected_source).contains("source"));

    let stale_state = d.write("stale-state.reg", &source_text("state-next"));
    let stale_state_plan = d.path("stale-state.plan.json");
    assert_eq!(
        code(&run(&[
            "plan",
            &s(&stale_state),
            "--redirect",
            "off",
            "--view",
            "both",
            "--save",
            &s(&stale_state_plan),
        ])),
        OK
    );
    let external = run(&[
        "set",
        key.as_str(),
        "-v",
        "Channel",
        "-d",
        "external",
        "--redirect",
        "off",
        "--view",
        "both",
        "-y",
    ]);
    assert_eq!(code(&external), OK, "{}", stderr(&external));
    let rejected_state = run(&["apply-plan", &s(&stale_state_plan), "-y"]);
    assert_eq!(code(&rejected_state), PARTIAL);
    assert!(stderr(&rejected_state).contains("current state changed"));

    let after = run(&[
        "query",
        key.as_str(),
        "-v",
        "Channel",
        "--view",
        "both",
        "--output",
        "json",
    ]);
    assert_eq!(code(&after), OK, "{}", stderr(&after));
    assert!(stdout(&after).contains("external"));
}

#[test]
fn sync_prune_view_both_uses_per_view_desired_state_and_undo() {
    if skip_if_hkcu_not_writable("dual-view reconciliation") {
        return;
    }
    let d = Scratch::new("sync-prune-both");
    let key = LiveKey::new("sync-prune-both");
    for (name, value) in [("Keep", "yes"), ("Drop", "no")] {
        let seeded = run(&[
            "set",
            key.as_str(),
            "-v",
            name,
            "-d",
            value,
            "--redirect",
            "off",
            "--view",
            "both",
            "-y",
        ]);
        assert_eq!(code(&seeded), OK, "{}", stderr(&seeded));
    }

    let desired = d.path("desired.reg");
    std::fs::write(
        &desired,
        format!(
            "Windows Registry Editor Version 5.00\r\n\r\n[{}]\r\n\"Keep\"=\"yes\"\r\n",
            key.as_str()
        ),
    )
    .unwrap();
    let undo = d.path("sync.undo.reg");
    let synced = run(&[
        "sync",
        &s(&desired),
        "--redirect",
        "off",
        "--prune",
        "--view",
        "both",
        "--backup",
        &s(&undo),
        "--output",
        "json",
        "-y",
    ]);
    assert_eq!(code(&synced), OK, "{}", stderr(&synced));
    let text = stdout(&synced);
    assert!(text.contains("\"view\":\"32\""), "{text}");
    assert!(text.contains("\"view\":\"64\""), "{text}");
    assert!(d.path("sync.undo.32.reg").exists());
    assert!(d.path("sync.undo.64.reg").exists());
}

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

#[test]
fn missing_key_exits_not_found() {
    let o = run(&["query", "HKCU\\Software\\regx-it-definitely-absent"]);
    assert_eq!(code(&o), NOT_FOUND, "stderr: {}", stderr(&o));
}

#[test]
fn hklm_write_exits_access_denied_without_elevation() {
    if skip_if_elevated("HKLM writes are denied") {
        // An elevated run would genuinely create the key, so remove it rather
        // than leaving the test's own litter behind on the machine.
        let _ = run(&[
            "delete",
            "HKLM\\SOFTWARE\\regx-it-should-fail",
            "-r",
            "-y",
            "--log-level",
            "error",
        ]);
        return;
    }
    // The product's central premise: never elevate, fail cleanly instead.
    let o = run(&[
        "set",
        "HKLM\\SOFTWARE\\regx-it-should-fail",
        "-v",
        "x",
        "-d",
        "y",
        "-y",
        "--redirect",
        "off",
    ]);
    assert_eq!(
        code(&o),
        ACCESS_DENIED,
        "an HKLM write must be denied, not silently virtualised. stderr: {}",
        stderr(&o)
    );
}

#[test]
fn a_syntax_error_exits_parse() {
    let sc = Scratch::new("badsyntax");
    let f = sc.write(
        "bad.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n[HKCU\\A\r\n",
    );
    let o = run(&["convert", &s(&f)]);
    assert_eq!(code(&o), PARSE, "stderr: {}", stderr(&o));
}

#[test]
fn malformed_unicode_is_rejected_without_partial_output() {
    let sc = Scratch::new("malformed-unicode");
    let cases: &[(&str, &[u8], &str)] = &[
        ("odd-utf16.reg", &[0xff, 0xfe, 0x41], "odd trailing byte"),
        (
            "surrogate.reg",
            &[0xff, 0xfe, 0x00, 0xd8],
            "unpaired surrogate",
        ),
        (
            "invalid-utf8.reg",
            &[0xef, 0xbb, 0xbf, 0xff],
            "invalid UTF-8",
        ),
    ];

    for (name, bytes, expected) in cases {
        let input = sc.path(name);
        let output = sc.path(&format!("{name}.converted.reg"));
        std::fs::write(&input, bytes).unwrap();
        let result = run(&["convert", &s(&input), "-o", &s(&output)]);
        assert_eq!(code(&result), PARSE, "{name}: stderr: {}", stderr(&result));
        assert!(
            stderr(&result).contains(expected),
            "{name}: stderr: {}",
            stderr(&result)
        );
        assert!(!output.exists(), "{name}: partial output was created");
    }
}

#[test]
fn a_hive_file_is_refused_with_a_pointer_to_the_hive_command() {
    let sc = Scratch::new("hivefile");
    let f = sc.path("fake.dat");
    std::fs::write(&f, b"regf\x00\x00\x00\x00").unwrap();
    let o = run(&["convert", &s(&f)]);
    assert_ne!(code(&o), OK);
    assert!(stderr(&o).contains("regx hive"), "stderr: {}", stderr(&o));
}

// ---------------------------------------------------------------------------
// --dry-run writes nothing
// ---------------------------------------------------------------------------

#[test]
fn dry_run_does_not_touch_the_registry() {
    if skip_if_hkcu_not_writable("dry-run live registry contract") {
        return;
    }
    let key = LiveKey::new("dryrun");
    let o = run(&[
        "set",
        key.as_str(),
        "-v",
        "x",
        "-d",
        "y",
        "-y",
        "--dry-run",
        "--output",
        "json",
    ]);
    assert_eq!(code(&o), OK, "stderr: {}", stderr(&o));
    let dry_json: serde_json::Value = serde_json::from_slice(&o.stdout).expect("dry-run set JSON");
    assert!(dry_json["views"][0]["undo"].is_null());
    assert!(dry_json["views"][0]["undoBytes"].is_null());
    assert!(dry_json["views"][0]["undoSha256"].is_null());

    let after = run(&["query", key.as_str()]);
    assert_eq!(code(&after), NOT_FOUND, "--dry-run created the key");
}

#[test]
fn dry_run_does_not_write_output_files() {
    let sc = Scratch::new("dryout");
    let src = sc.write(
        "in.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\X]\r\n\"a\"=\"b\"\r\n",
    );
    let out = sc.path("out.reg");
    let o = run(&["convert", &s(&src), "-o", &s(&out), "--dry-run"]);
    assert_eq!(code(&o), OK);
    assert!(!out.exists(), "--dry-run wrote {}", out.display());
}

// ---------------------------------------------------------------------------
// Round trips through the live registry
// ---------------------------------------------------------------------------

#[test]
fn set_query_export_delete_round_trip() {
    if skip_if_hkcu_not_writable("set/query/export/delete live round trip") {
        return;
    }
    let key = LiveKey::new("roundtrip");
    let sc = Scratch::new("roundtrip");

    assert_eq!(
        code(&run(&[
            "set",
            key.as_str(),
            "-v",
            "Text",
            "-d",
            "hello",
            "-y"
        ])),
        OK
    );
    assert_eq!(
        code(&run(&[
            "set",
            key.as_str(),
            "-v",
            "Num",
            "-t",
            "REG_DWORD",
            "-d",
            "42",
            "-y"
        ])),
        OK
    );

    let q = run(&["query", key.as_str()]);
    assert_eq!(code(&q), OK);
    assert!(stdout(&q).contains("hello"), "{}", stdout(&q));
    assert!(stdout(&q).contains("42"), "{}", stdout(&q));

    let exported = sc.path("out.reg");
    assert_eq!(
        code(&run(&["export", key.as_str(), "-o", &s(&exported)])),
        OK
    );
    assert!(exported.exists());

    // A .reg file is UTF-16LE with a BOM; anything else and regedit rejects it.
    let bytes = std::fs::read(&exported).unwrap();
    assert_eq!(
        &bytes[..2],
        &[0xFF, 0xFE],
        "export must be BOM-prefixed UTF-16LE"
    );

    assert_eq!(code(&run(&["delete", key.as_str(), "-r", "-y"])), OK);
    assert_eq!(code(&run(&["query", key.as_str()])), NOT_FOUND);
}

#[test]
fn live_ls_lists_keys_without_exposing_values() {
    if skip_if_hkcu_not_writable("live key listing") {
        return;
    }
    let root = LiveKey::new("list");
    let child = format!("{}\\Child", root.as_str());
    let grandchild = format!("{child}\\Grandchild");
    for (key, value) in [(&child, "secret-child"), (&grandchild, "secret-grandchild")] {
        let seeded = run(&[
            "set",
            key,
            "-v",
            "Payload",
            "-d",
            value,
            "--redirect",
            "off",
            "--view",
            "both",
            "-y",
        ]);
        assert_eq!(code(&seeded), OK, "{}", stderr(&seeded));
    }

    let shallow = run(&["ls", root.as_str()]);
    assert_eq!(code(&shallow), OK, "{}", stderr(&shallow));
    assert!(stdout(&shallow).contains("Child"), "{}", stdout(&shallow));
    assert!(!stdout(&shallow).contains("Grandchild"));
    assert!(!stdout(&shallow).contains("secret-"));

    let recursive = run(&["ls", root.as_str(), "-r", "--output", "json"]);
    assert_eq!(code(&recursive), OK, "{}", stderr(&recursive));
    let report: serde_json::Value = serde_json::from_slice(&recursive.stdout).unwrap();
    assert_eq!(report["recursive"], true);
    assert!(report["computer"].is_null());
    let keys = report["views"][0]["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(|key| key.ends_with("\\Child")));
    assert!(keys
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(|key| key.ends_with("\\Child\\Grandchild")));
    assert!(!stdout(&recursive).contains("secret-"));

    let scoped = run(&[
        "ls",
        root.as_str(),
        "-r",
        "--include",
        "**\\Grandchild",
        "--output",
        "json",
    ]);
    assert_eq!(code(&scoped), OK, "{}", stderr(&scoped));
    let scoped_report: serde_json::Value = serde_json::from_slice(&scoped.stdout).unwrap();
    assert_eq!(
        scoped_report["include"],
        serde_json::json!(["**\\Grandchild"])
    );
    let scoped_keys = scoped_report["views"][0]["keys"].as_array().unwrap();
    assert_eq!(scoped_keys.len(), 1);
    assert!(scoped_keys[0]
        .as_str()
        .unwrap()
        .ends_with("\\Child\\Grandchild"));
    assert_eq!(scoped_report["views"][0]["truncated"], false);

    let limited = run(&[
        "ls",
        root.as_str(),
        "-r",
        "--limit",
        "1",
        "--output",
        "json",
    ]);
    assert_eq!(code(&limited), OK, "{}", stderr(&limited));
    let limited_report: serde_json::Value = serde_json::from_slice(&limited.stdout).unwrap();
    assert_eq!(limited_report["limit"], 1);
    assert_eq!(
        limited_report["views"][0]["keys"].as_array().unwrap().len(),
        1
    );
    assert_eq!(limited_report["views"][0]["truncated"], true);

    let both = run(&["ls", root.as_str(), "--view", "both", "--output", "json"]);
    assert_eq!(code(&both), OK, "{}", stderr(&both));
    let both_report: serde_json::Value = serde_json::from_slice(&both.stdout).unwrap();
    assert_eq!(both_report["views"].as_array().unwrap().len(), 2);
    assert!(both_report["failures"].as_array().unwrap().is_empty());

    let stats = run(&["stats", root.as_str(), "--view", "both", "--output", "json"]);
    assert_eq!(code(&stats), OK, "{}", stderr(&stats));
    let stats_text = stdout(&stats);
    assert!(!stats_text.contains("secret-"), "{stats_text}");
    let stats_report: serde_json::Value = serde_json::from_str(&stats_text).unwrap();
    assert_eq!(stats_report["views"].as_array().unwrap().len(), 2);
    assert!(stats_report["failures"].as_array().unwrap().is_empty());
    for view in stats_report["views"].as_array().unwrap() {
        assert_eq!(view["keys"], 3);
        assert_eq!(view["values"], 2);
        assert_eq!(view["maxDepth"], 2);
        assert_eq!(view["incomplete"], false);
        assert_eq!(view["matched"], true);
    }

    let fingerprint = run(&[
        "fingerprint",
        root.as_str(),
        "--view",
        "both",
        "--output",
        "json",
    ]);
    assert_eq!(code(&fingerprint), OK, "{}", stderr(&fingerprint));
    let fingerprint_text = stdout(&fingerprint);
    assert!(!fingerprint_text.contains("secret-"), "{fingerprint_text}");
    let fingerprint_report: serde_json::Value = serde_json::from_str(&fingerprint_text).unwrap();
    assert_eq!(fingerprint_report["canonicalVersion"], 1);
    assert_eq!(fingerprint_report["views"].as_array().unwrap().len(), 2);
    for view in fingerprint_report["views"].as_array().unwrap() {
        assert_eq!(view["sha256"].as_str().unwrap().len(), 64);
        assert_eq!(view["incomplete"], false);
        assert!(view["expected"].is_null());
        assert!(view["matches"].is_null());
    }

    let mapped_fingerprint = run(&[
        "fingerprint",
        root.as_str(),
        "--root-as",
        "HKCU\\Software\\PortableFingerprint",
        "--output",
        "json",
    ]);
    assert_eq!(
        code(&mapped_fingerprint),
        OK,
        "{}",
        stderr(&mapped_fingerprint)
    );
    let mapped_report: serde_json::Value =
        serde_json::from_slice(&mapped_fingerprint.stdout).unwrap();
    assert_eq!(
        mapped_report["rootAs"],
        "HKEY_CURRENT_USER\\Software\\PortableFingerprint"
    );
    assert_ne!(
        mapped_report["views"][0]["sha256"],
        fingerprint_report["views"][0]["sha256"]
    );

    let view32 = fingerprint_report["views"]
        .as_array()
        .unwrap()
        .iter()
        .find(|view| view["view"] == "32")
        .unwrap()["sha256"]
        .as_str()
        .unwrap();
    let view64 = fingerprint_report["views"]
        .as_array()
        .unwrap()
        .iter()
        .find(|view| view["view"] == "64")
        .unwrap()["sha256"]
        .as_str()
        .unwrap();
    let expected_both = run(&[
        "fingerprint",
        root.as_str(),
        "--view",
        "both",
        "--expect-32",
        view32,
        "--expect-64",
        view64,
        "--output",
        "json",
    ]);
    assert_eq!(code(&expected_both), OK, "{}", stderr(&expected_both));
    let expected_report: serde_json::Value = serde_json::from_slice(&expected_both.stdout).unwrap();
    assert!(expected_report["views"]
        .as_array()
        .unwrap()
        .iter()
        .all(|view| view["matches"] == true));

    let incomplete_pair = run(&[
        "fingerprint",
        root.as_str(),
        "--view",
        "both",
        "--expect-32",
        view32,
    ]);
    assert_eq!(code(&incomplete_pair), USAGE);
}

#[test]
fn stats_summarizes_registry_data_without_exposing_payloads() {
    let scratch = Scratch::new("stats");
    let input = scratch.write(
        "input.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\Stats]\r\n\
         \"Text\"=\"secret\"\r\n\
         \"Number\"=dword:0000002a\r\n\
         \"Gone\"=-\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\Stats\\Child]\r\n\
         \"Blob\"=hex:01,02,03\r\n\r\n\
         [-HKEY_CURRENT_USER\\Software\\Removed]\r\n",
    );
    let output = run(&["stats", input.to_str().unwrap(), "--output", "json"]);
    assert_eq!(code(&output), OK, "{}", stderr(&output));
    let text = stdout(&output);
    assert!(!text.contains("secret"), "{text}");
    assert!(!text.contains("01,02,03"), "{text}");
    let report: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["format"], "reg");
    assert!(report["rootAs"].is_null());
    assert_eq!(report["keys"], 2);
    assert_eq!(report["values"], 3);
    assert_eq!(report["keyDeletes"], 1);
    assert_eq!(report["valueDeletes"], 1);
    assert_eq!(report["maxDepth"], 3);
    assert_eq!(report["payloadBytes"], 21);
    assert_eq!(report["types"]["REG_SZ"], 1);
    assert_eq!(report["types"]["REG_DWORD"], 1);
    assert_eq!(report["types"]["REG_BINARY"], 1);
    assert_eq!(report["conflicts"], 0);
    assert_eq!(report["incomplete"], false);
    assert_eq!(report["matched"], true);
    assert_eq!(report["include"], serde_json::json!([]));
    assert_eq!(report["includeValues"], serde_json::json!([]));

    let scoped_stats = run(&[
        "stats",
        input.to_str().unwrap(),
        "--include",
        "**\\Stats\\Child",
        "--value",
        "Blob",
        "--output",
        "json",
    ]);
    assert_eq!(code(&scoped_stats), OK, "{}", stderr(&scoped_stats));
    let scoped_stats_json: serde_json::Value =
        serde_json::from_slice(&scoped_stats.stdout).unwrap();
    assert_eq!(scoped_stats_json["matched"], true);
    assert_eq!(scoped_stats_json["keys"], 1);
    assert_eq!(scoped_stats_json["values"], 1);
    assert_eq!(scoped_stats_json["payloadBytes"], 3);
    assert_eq!(
        scoped_stats_json["include"],
        serde_json::json!(["**\\Stats\\Child"])
    );
    assert_eq!(
        scoped_stats_json["includeValues"],
        serde_json::json!(["Blob"])
    );

    let missing_stats = run(&[
        "stats",
        input.to_str().unwrap(),
        "--include",
        "**\\DefinitelyMissing",
        "--output",
        "json",
    ]);
    assert_eq!(
        code(&missing_stats),
        NOT_FOUND,
        "{}",
        stderr(&missing_stats)
    );
    let missing_stats_json: serde_json::Value =
        serde_json::from_slice(&missing_stats.stdout).unwrap();
    assert_eq!(missing_stats_json["matched"], false);
    assert_eq!(missing_stats_json["keys"], 0);
    assert_eq!(missing_stats_json["values"], 0);

    let invalid_view = run(&[
        "stats",
        input.to_str().unwrap(),
        "--view",
        "both",
        "--output",
        "json",
    ]);
    assert_eq!(code(&invalid_view), USAGE);
    assert!(stderr(&invalid_view).contains("requires SOURCE to be a live registry key"));

    let invalid_root_as = run(&[
        "stats",
        input.to_str().unwrap(),
        "--root-as",
        "HKCU\\Portable",
    ]);
    assert_eq!(code(&invalid_root_as), USAGE);
    assert!(stderr(&invalid_root_as).contains("requires SOURCE to be a live registry key"));

    let reordered = scratch.write(
        "reordered.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [-HKEY_CURRENT_USER\\Software\\Removed]\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\Stats\\Child]\r\n\
         \"Blob\"=hex:01,02,03\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\Stats]\r\n\
         \"Gone\"=-\r\n\
         \"Number\"=dword:0000002a\r\n\
         \"Text\"=\"secret\"\r\n",
    );
    let first = run(&["fingerprint", input.to_str().unwrap(), "--output", "json"]);
    let second = run(&[
        "fingerprint",
        reordered.to_str().unwrap(),
        "--output",
        "json",
    ]);
    assert_eq!(code(&first), OK, "{}", stderr(&first));
    assert_eq!(code(&second), OK, "{}", stderr(&second));
    let first_text = stdout(&first);
    assert!(!first_text.contains("secret"), "{first_text}");
    let first_json: serde_json::Value = serde_json::from_str(&first_text).unwrap();
    let second_json: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(first_json["canonicalVersion"], 1);
    assert_eq!(first_json["algorithm"], "sha256");
    assert!(first_json["rootAs"].is_null());
    assert_eq!(first_json["sha256"], second_json["sha256"]);
    assert_eq!(first_json["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(first_json["matched"], true);
    assert_eq!(first_json["keys"], 3);
    assert_eq!(first_json["values"], 4);

    let expected = first_json["sha256"].as_str().unwrap().to_ascii_uppercase();
    let matched = run(&[
        "fingerprint",
        input.to_str().unwrap(),
        "--expect",
        &expected,
        "--output",
        "json",
    ]);
    assert_eq!(code(&matched), OK, "{}", stderr(&matched));
    let matched_json: serde_json::Value = serde_json::from_slice(&matched.stdout).unwrap();
    assert_eq!(matched_json["expected"], expected.to_ascii_lowercase());
    assert_eq!(matched_json["matches"], true);

    let wrong = "0".repeat(64);
    let drift = run(&[
        "fingerprint",
        input.to_str().unwrap(),
        "--expect",
        &wrong,
        "--output",
        "json",
    ]);
    assert_eq!(code(&drift), PARTIAL, "{}", stderr(&drift));
    let drift_json: serde_json::Value = serde_json::from_slice(&drift.stdout).unwrap();
    assert_eq!(drift_json["matches"], false);

    let malformed = run(&[
        "fingerprint",
        input.to_str().unwrap(),
        "--expect",
        "not-a-sha256",
    ]);
    assert_eq!(code(&malformed), USAGE);
    assert!(stderr(&malformed).contains("64 hexadecimal"));

    let scoped_first = run(&[
        "fingerprint",
        input.to_str().unwrap(),
        "--include",
        "**\\Stats\\Child",
        "--value",
        "Blob",
        "--output",
        "json",
    ]);
    let scoped_second = run(&[
        "fingerprint",
        reordered.to_str().unwrap(),
        "--include",
        "**\\Stats\\Child",
        "--value",
        "Blob",
        "--output",
        "json",
    ]);
    assert_eq!(code(&scoped_first), OK, "{}", stderr(&scoped_first));
    assert_eq!(code(&scoped_second), OK, "{}", stderr(&scoped_second));
    let scoped_json: serde_json::Value = serde_json::from_slice(&scoped_first.stdout).unwrap();
    let scoped_reordered_json: serde_json::Value =
        serde_json::from_slice(&scoped_second.stdout).unwrap();
    assert_eq!(
        scoped_json["include"],
        serde_json::json!(["**\\Stats\\Child"])
    );
    assert_eq!(scoped_json["includeValues"], serde_json::json!(["Blob"]));
    assert_eq!(scoped_json["keys"], 1);
    assert_eq!(scoped_json["values"], 1);
    assert_eq!(scoped_json["sha256"], scoped_reordered_json["sha256"]);
    assert_ne!(scoped_json["sha256"], first_json["sha256"]);

    let no_match = run(&[
        "fingerprint",
        input.to_str().unwrap(),
        "--include",
        "**\\DefinitelyMissing",
        "--output",
        "json",
    ]);
    assert_eq!(code(&no_match), NOT_FOUND, "{}", stderr(&no_match));
    let no_match_json: serde_json::Value = serde_json::from_slice(&no_match.stdout).unwrap();
    assert_eq!(no_match_json["matched"], false);
    assert_eq!(no_match_json["keys"], 0);
    assert_eq!(no_match_json["values"], 0);

    let file_root_as = run(&[
        "fingerprint",
        input.to_str().unwrap(),
        "--root-as",
        "HKCU\\Portable",
    ]);
    assert_eq!(code(&file_root_as), USAGE);
    assert!(stderr(&file_root_as).contains("requires SOURCE to be a live registry key"));
}

#[test]
fn import_writes_an_undo_file_that_actually_reverts() {
    if skip_if_hkcu_not_writable("import undo live round trip") {
        return;
    }
    let key = LiveKey::new("undo");
    let sc = Scratch::new("undo");
    let reg = sc.write(
        "change.reg",
        &format!(
            "Windows Registry Editor Version 5.00\r\n\r\n[{}]\r\n\"a\"=\"one\"\r\n\"n\"=dword:00000005\r\n",
            key.as_str().replace("HKCU", "HKEY_CURRENT_USER")
        ),
    );

    let imported = run(&["import", &s(&reg), "-y"]);
    assert_eq!(code(&imported), OK, "{}", stderr(&imported));
    assert!(stdout(&run(&["query", key.as_str()])).contains("one"));

    let imported_stderr = stderr(&imported);
    let undo = imported_stderr
        .lines()
        .find(|line| line.contains("undo snapshot"))
        .and_then(|line| line.rsplit_once(" -> "))
        .map(|(_, path)| PathBuf::from(path))
        .unwrap_or_else(|| panic!("import did not report its undo path: {imported_stderr}"));
    assert!(
        undo.exists(),
        "import must write an undo snapshot beside the input"
    );
    assert_eq!(undo.parent(), reg.parent());
    let undo_name = undo.file_name().and_then(|name| name.to_str()).unwrap();
    assert!(undo_name.starts_with("change-"), "{undo_name}");
    assert!(undo_name.ends_with(".undo.reg"), "{undo_name}");

    let redo = sc.path("redo.reg");
    assert_eq!(
        code(&run(&["undo", &s(&undo), "--backup", &s(&redo), "-y"])),
        OK
    );
    assert!(redo.is_file(), "undo must preserve a redo snapshot");
    assert_eq!(
        code(&run(&["query", key.as_str()])),
        NOT_FOUND,
        "the undo file did not remove the key it created"
    );
}

#[test]
fn diff_reports_drift_and_its_patch_closes_it() {
    if skip_if_hkcu_not_writable("live diff and patch round trip") {
        return;
    }
    let key = LiveKey::new("drift");
    let sc = Scratch::new("drift");

    run(&["set", key.as_str(), "-v", "Channel", "-d", "stable", "-y"]);
    let baseline = sc.path("baseline.reg");
    assert_eq!(
        code(&run(&["export", key.as_str(), "-o", &s(&baseline)])),
        OK
    );

    run(&["set", key.as_str(), "-v", "Channel", "-d", "beta", "-y"]);

    let d = run(&["diff", &s(&baseline), key.as_str(), "--exit-code"]);
    assert_eq!(
        code(&d),
        PARTIAL,
        "drift must be reportable as a non-zero exit"
    );
    assert!(stdout(&d).contains("beta"), "{}", stdout(&d));

    for (format, extension) in [("json", "json"), ("csv", "csv"), ("pol", "pol")] {
        let formatted_patch = sc.path(&format!("restore.{extension}"));
        let rendered = run(&[
            "diff",
            key.as_str(),
            &s(&baseline),
            "--to",
            format,
            "-o",
            &s(&formatted_patch),
            "--output",
            "json",
        ]);
        assert_eq!(code(&rendered), OK, "{format}: {}", stderr(&rendered));
        let report: serde_json::Value = serde_json::from_slice(&rendered.stdout).unwrap();
        assert_eq!(report["patchFormat"], format);
        assert_eq!(report["patchWritten"], true);
        let inspected = if format == "pol" {
            run(&[
                "inspect",
                &s(&formatted_patch),
                "--pol-root",
                "HKCU",
                "--output",
                "json",
            ])
        } else {
            run(&["inspect", &s(&formatted_patch), "--output", "json"])
        };
        assert_eq!(code(&inspected), OK, "{format}: {}", stderr(&inspected));
        let contents: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
        assert_eq!(contents[0]["values"], 1, "{format}: {}", stdout(&inspected));
    }

    // The inverse patch restores the baseline.
    let patch = sc.path("restore.reg");
    assert_eq!(
        code(&run(&[
            "diff",
            key.as_str(),
            &s(&baseline),
            "-o",
            &s(&patch)
        ])),
        OK
    );
    assert_eq!(code(&run(&["import", &s(&patch), "-y", "--no-backup"])), OK);

    let after = run(&["diff", &s(&baseline), key.as_str(), "--exit-code"]);
    assert_eq!(
        code(&after),
        OK,
        "patch did not close the drift: {}",
        stdout(&after)
    );
}

// ---------------------------------------------------------------------------
// Format detection through the CLI
// ---------------------------------------------------------------------------

#[test]
fn every_text_format_is_detected_and_converts_to_reg() {
    let sc = Scratch::new("formats");
    let cases: &[(&str, &str, &str)] = &[
        ("a.ini", "ini", "[HKEY_CURRENT_USER\\Software\\X]\nName = value\n"),
        (
            "a.csv",
            "csv",
            "key,name,type,data\nHKCU\\Software\\X,Name,REG_SZ,value\n",
        ),
        (
            "a.json",
            "json",
            "{\"HKCU\\\\Software\\\\X\": {\"Name\": \"value\"}}",
        ),
        (
            "a.inf",
            "inf",
            "[Version]\nSignature=\"$WINDOWS NT$\"\n[I]\nAddReg=R\n[R]\nHKCU,\"Software\\X\",\"Name\",0x0,\"value\"\n",
        ),
        (
            "gpp-fragment.txt",
            "gpp",
            "<Registry name=\"X\"><Properties action=\"U\" hive=\"HKCU\" key=\"Software\\X\" name=\"Name\" type=\"REG_SZ\" value=\"value\"/></Registry>",
        ),
    ];

    for (file, format, body) in cases {
        let p = sc.write(file, body);
        let o = run(&["inspect", &s(&p)]);
        assert_eq!(code(&o), OK, "{file}: {}", stderr(&o));
        assert!(
            stdout(&o).contains(format),
            "{file} was not detected as {format}: {}",
            stdout(&o)
        );

        let c = run(&[
            "convert",
            &s(&p),
            "--redirect",
            "off",
            "--log-level",
            "error",
        ]);
        assert_eq!(code(&c), OK, "{file}: {}", stderr(&c));
        assert!(stdout(&c).contains("value"), "{file}: {}", stdout(&c));
    }

    let localized = sc.write(
        "localized.inf",
        concat!(
            "[Version]\nSignature=\"$WINDOWS NT$\"\n",
            "[DefaultInstall]\nAddReg=R\n",
            "[R]\nHKCU,\"Software\\X\",\"Greeting\",0,\\\n",
            "  \"%Greeting%\"\n",
            "[Strings]\nGreeting=\"default\"\n",
            "[Strings.0409]\nGreeting=\"US; English\" ; localized comment\n"
        ),
    );
    let selected = run(&[
        "convert",
        &s(&localized),
        "--inf-language",
        "0409",
        "--redirect",
        "off",
        "--log-level",
        "error",
    ]);
    assert_eq!(code(&selected), OK, "{}", stderr(&selected));
    assert!(stdout(&selected).contains("US; English"));
    assert!(!stdout(&selected).contains("\"default\""));

    let invalid = run(&["inspect", &s(&localized), "--inf-language", "en-US"]);
    assert_eq!(code(&invalid), USAGE);
    assert!(stderr(&invalid).contains("four-hex-digit Windows LANGID"));

    let merge_json = sc.write(
        "merge-a.json",
        "{\"HKCU\\\\Software\\\\MergeFormats\": {\"FromJson\": \"value\"}}",
    );
    let merge_gpp = sc.write(
        "merge-b.txt",
        "<Registry name=\"Merge\"><Properties action=\"U\" hive=\"HKCU\" \
         key=\"Software\\MergeFormats\" name=\"FromGpp\" type=\"REG_SZ\" \
         value=\"value\"/></Registry>",
    );
    let merged_path = sc.path("mixed.reg");
    let merged = run(&[
        "merge",
        &s(&merge_json),
        &s(&merge_gpp),
        "-o",
        &s(&merged_path),
    ]);
    assert_eq!(code(&merged), OK, "{}", stderr(&merged));
    let inspected = run(&["inspect", &s(&merged_path), "--output", "json"]);
    assert_eq!(code(&inspected), OK, "{}", stderr(&inspected));
    let report: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(report[0]["values"], 2, "{}", stdout(&inspected));
    assert_eq!(
        report[0]["dialect"], "Windows Registry Editor Version 5.00",
        "mixed-format merge must default to V5"
    );

    let reg4_path = sc.path("mixed-reg4.reg");
    let reg4 = run(&[
        "merge",
        &s(&merge_json),
        &s(&merge_gpp),
        "--reg4",
        "-o",
        &s(&reg4_path),
    ]);
    assert_eq!(code(&reg4), OK, "{}", stderr(&reg4));
    let inspected = run(&["inspect", &s(&reg4_path), "--output", "json"]);
    let report: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(report[0]["dialect"], "REGEDIT4");

    for (format, extension) in [("json", "json"), ("csv", "csv"), ("pol", "pol")] {
        let output = sc.path(&format!("mixed.{extension}"));
        let merged = run(&[
            "merge",
            &s(&merge_json),
            &s(&merge_gpp),
            "--to",
            format,
            "-o",
            &s(&output),
        ]);
        assert_eq!(code(&merged), OK, "{format}: {}", stderr(&merged));
        let inspected = if format == "pol" {
            run(&[
                "inspect",
                &s(&output),
                "--pol-root",
                "HKCU",
                "--output",
                "json",
            ])
        } else {
            run(&["inspect", &s(&output), "--output", "json"])
        };
        assert_eq!(code(&inspected), OK, "{format}: {}", stderr(&inspected));
        let report: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
        assert_eq!(report[0]["values"], 2, "{format}: {}", stdout(&inspected));
    }

    let incompatible = run(&[
        "merge",
        &s(&merge_json),
        &s(&merge_gpp),
        "--to",
        "json",
        "--reg4",
    ]);
    assert_eq!(code(&incompatible), USAGE);
    assert!(stderr(&incompatible).contains("--to reg"));

    let conflict_a = sc.write(
        "conflict-a.json",
        "{\"HKCU\\\\Software\\\\MergeFormats\": {\"Shared\": \"first\"}}",
    );
    let conflict_b = sc.write(
        "conflict-b.json",
        "{\"HKCU\\\\Software\\\\MergeFormats\": {\"shared\": \"second\"}}",
    );
    let refused_path = sc.path("conflict-refused.reg");
    let refused = run(&[
        "merge",
        &s(&conflict_a),
        &s(&conflict_b),
        "--conflicts",
        "error",
        "-o",
        &s(&refused_path),
    ]);
    assert_eq!(code(&refused), PARSE, "{}", stderr(&refused));
    assert!(stderr(&refused).contains("1 semantic conflict"));
    assert!(
        !refused_path.exists(),
        "conflict refusal must precede output"
    );

    let key_present = sc.write(
        "key-present.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\MergeFormats]\r\n\
         \"Shared\"=\"present\"\r\n",
    );
    let key_deleted = sc.write(
        "key-deleted.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [-HKEY_CURRENT_USER\\Software\\MergeFormats]\r\n",
    );
    let structural_path = sc.path("structural-conflict.reg");
    let structural = run(&[
        "merge",
        &s(&key_present),
        &s(&key_deleted),
        "--conflicts",
        "error",
        "-o",
        &s(&structural_path),
    ]);
    assert_eq!(code(&structural), PARSE, "{}", stderr(&structural));
    assert!(stderr(&structural).contains("conflict HKEY_CURRENT_USER"));
    assert!(stderr(&structural).contains("(key)"));
    assert!(!structural_path.exists());

    let intra_source = sc.write(
        "intra-conflict.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\MergeFormats]\r\n\
         \"Shared\"=\"first\"\r\n\
         \"Raw\"=hex:00,ff\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\MergeFormats]\r\n\
         \"shared\"=\"second\"\r\n\
         \"raw\"=hex:01,ff\r\n",
    );
    let neutral_source = sc.write(
        "neutral.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\MergeNeutral]\r\n",
    );
    let patch_target = sc.write(
        "patch-target.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\MergeFormats]\r\n\
         \"Shared\"=\"target\"\r\n",
    );
    for (format, extension) in [("json", "json"), ("csv", "csv"), ("pol", "pol")] {
        let output = sc.path(&format!("diff-patch.{extension}"));
        let rendered = run(&[
            "diff",
            &s(&key_present),
            &s(&patch_target),
            "--to",
            format,
            "-o",
            &s(&output),
            "--output",
            "json",
        ]);
        assert_eq!(code(&rendered), OK, "{format}: {}", stderr(&rendered));
        let report: serde_json::Value = serde_json::from_slice(&rendered.stdout).unwrap();
        assert_eq!(report["patchFormat"], format);
        assert_eq!(report["patchWritten"], true);
        let inspected = if format == "pol" {
            run(&[
                "inspect",
                &s(&output),
                "--pol-root",
                "HKCU",
                "--output",
                "json",
            ])
        } else {
            run(&["inspect", &s(&output), "--output", "json"])
        };
        assert_eq!(code(&inspected), OK, "{format}: {}", stderr(&inspected));
        let contents: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
        assert_eq!(contents[0]["values"], 1);
    }
    let intra_output = sc.path("intra-refused.reg");
    let inspected_conflict = run(&["inspect", &s(&intra_source), "--output", "json"]);
    assert_eq!(
        code(&inspected_conflict),
        PARTIAL,
        "{}",
        stderr(&inspected_conflict)
    );
    let inspection: serde_json::Value = serde_json::from_slice(&inspected_conflict.stdout).unwrap();
    let conflict = &inspection[0]["conflicts"][0];
    assert_eq!(
        conflict["path"],
        "HKEY_CURRENT_USER\\Software\\MergeFormats"
    );
    assert_eq!(conflict["value"], "shared");
    assert_eq!(conflict["old"], "first");
    assert_eq!(conflict["new"], "second");
    assert!(conflict["firstLine"].as_u64().is_some());
    assert!(conflict["lastLine"].as_u64().is_some());
    let raw_conflict = inspection[0]["conflicts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|conflict| conflict["value"] == "raw")
        .expect("raw conflict");
    assert_eq!(raw_conflict["oldExact"]["typeId"], 3);
    assert_eq!(raw_conflict["oldExact"]["raw"], "00 ff");
    assert_eq!(raw_conflict["newExact"]["typeId"], 3);
    assert_eq!(raw_conflict["newExact"]["raw"], "01 ff");
    let parsed_values = inspection[0]["data"]["keys"][0]["values"]
        .as_array()
        .expect("inspect parsed registry data");
    let parsed_raw = parsed_values
        .iter()
        .find(|value| value["name"] == "raw")
        .expect("parsed raw value");
    assert_eq!(parsed_raw["typeId"], 3);
    assert_eq!(parsed_raw["raw"], "01 ff");
    let parsed_shared = parsed_values
        .iter()
        .find(|value| value["name"] == "shared")
        .expect("parsed shared value");
    assert_eq!(parsed_shared["type"], "REG_SZ");
    assert_eq!(parsed_shared["data"], "second");

    let ambiguous_patch = sc.path("ambiguous-diff.reg");
    let ambiguous_diff = run(&[
        "diff",
        &s(&intra_source),
        &s(&neutral_source),
        "--out",
        &s(&ambiguous_patch),
        "--output",
        "json",
    ]);
    assert_eq!(
        code(&ambiguous_diff),
        PARTIAL,
        "{}",
        stderr(&ambiguous_diff)
    );
    let diff_json: serde_json::Value = serde_json::from_slice(&ambiguous_diff.stdout).unwrap();
    assert_eq!(diff_json["incomplete"], true);
    assert_eq!(diff_json["patchWritten"], false);
    assert!(diff_json["bytes"].is_null());
    assert!(diff_json["sha256"].is_null());
    assert!(!ambiguous_patch.exists(), "incomplete diff wrote a patch");

    let ambiguous_both_base = sc.path("ambiguous-both.json");
    let ambiguous_both = run(&[
        "diff",
        &s(&intra_source),
        "HKCU\\Environment",
        "--view",
        "both",
        "--to",
        "json",
        "--out",
        &s(&ambiguous_both_base),
        "--output",
        "json",
    ]);
    assert_eq!(
        code(&ambiguous_both),
        PARTIAL,
        "{}",
        stderr(&ambiguous_both)
    );
    let both_json: serde_json::Value = serde_json::from_slice(&ambiguous_both.stdout).unwrap();
    assert_eq!(both_json["patchFormat"], "json");
    for view in both_json["views"].as_array().unwrap() {
        assert_eq!(view["incomplete"], true);
        assert_eq!(view["patchWritten"], false);
        assert!(view["bytes"].is_null());
        assert!(view["sha256"].is_null());
    }
    assert!(!sc.path("ambiguous-both.32.json").exists());
    assert!(!sc.path("ambiguous-both.64.json").exists());

    let ambiguous_search = run(&["search", &s(&intra_source), "second", "--output", "json"]);
    assert_eq!(
        code(&ambiguous_search),
        PARTIAL,
        "{}",
        stderr(&ambiguous_search)
    );
    let search_json: serde_json::Value = serde_json::from_slice(&ambiguous_search.stdout).unwrap();
    assert_eq!(search_json["incomplete"], true);
    assert!(!search_json["matches"].as_array().unwrap().is_empty());

    let intra_merge = run(&[
        "merge",
        &s(&intra_source),
        &s(&neutral_source),
        "--conflicts",
        "error",
        "-o",
        &s(&intra_output),
    ]);
    assert_eq!(code(&intra_merge), PARSE, "{}", stderr(&intra_merge));
    assert!(stderr(&intra_merge).contains("inside this input"));
    assert!(!intra_output.exists());

    let converted_output = sc.path("convert-intra-refused.json");
    let refused_convert = run(&[
        "convert",
        &s(&intra_source),
        "--conflicts",
        "error",
        "--to",
        "json",
        "-o",
        &s(&converted_output),
    ]);
    assert_eq!(
        code(&refused_convert),
        PARSE,
        "{}",
        stderr(&refused_convert)
    );
    assert!(stdout(&refused_convert).is_empty());
    assert!(!converted_output.exists());

    let redirect_collision = sc.write(
        "convert-redirect-conflict.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_LOCAL_MACHINE\\SOFTWARE\\ConvertConflict]\r\n\
         \"Mode\"=\"native\"\r\n\r\n\
         [HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\ConvertConflict]\r\n\
         \"mode\"=\"wow\"\r\n",
    );
    let redirected_output = sc.path("convert-redirect-refused.reg");
    let refused_redirect = run(&[
        "convert",
        &s(&redirect_collision),
        "--conflicts",
        "error",
        "-o",
        &s(&redirected_output),
    ]);
    assert_eq!(
        code(&refused_redirect),
        PARSE,
        "{}",
        stderr(&refused_redirect)
    );
    assert!(stderr(&refused_redirect).contains("after redirection"));
    assert!(stdout(&refused_redirect).is_empty());
    assert!(!redirected_output.exists());

    let undo = sc.path("conflict-undo.reg");
    let audit = sc.path("conflict-audit.jsonl");
    let refused_import = run(&[
        "import",
        &s(&intra_source),
        "--conflicts",
        "error",
        "--backup",
        &s(&undo),
        "--audit-log",
        &s(&audit),
        "-y",
    ]);
    assert_eq!(code(&refused_import), PARSE, "{}", stderr(&refused_import));
    assert!(!undo.exists(), "conflict preflight must precede undo");
    assert!(!audit.exists(), "conflict preflight must precede audit");

    let saved_plan = sc.path("conflict-plan.json");
    let refused_plan = run(&[
        "plan",
        &s(&intra_source),
        "--conflicts",
        "error",
        "--save",
        &s(&saved_plan),
    ]);
    assert_eq!(code(&refused_plan), PARSE, "{}", stderr(&refused_plan));
    assert!(!saved_plan.exists());

    let refused_sync = run(&["sync", &s(&intra_source), "--conflicts", "error", "-y"]);
    assert_eq!(code(&refused_sync), PARSE, "{}", stderr(&refused_sync));

    let accepted_path = sc.path("conflict-last-wins.json");
    let accepted = run(&[
        "merge",
        &s(&conflict_a),
        &s(&conflict_b),
        "--conflicts",
        "last-wins",
        "--to",
        "json",
        "-o",
        &s(&accepted_path),
    ]);
    assert_eq!(code(&accepted), OK, "{}", stderr(&accepted));
    let accepted_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&accepted_path).unwrap()).unwrap();
    assert_eq!(accepted_json["keys"][0]["values"][0]["data"], "second");
}

#[test]
fn forcing_the_wrong_format_fails_rather_than_guessing() {
    let sc = Scratch::new("forcefmt");
    let p = sc.write("a.ini", "[HKEY_CURRENT_USER\\Software\\X]\nName = value\n");
    let o = run(&["inspect", &s(&p), "--from", "json"]);
    assert_ne!(code(&o), OK, "an INI read as JSON must fail loudly");
}

#[test]
fn an_unknown_format_name_is_rejected_with_a_pointer() {
    let sc = Scratch::new("badfmt");
    let p = sc.write("a.ini", "[HKEY_CURRENT_USER\\Software\\X]\nName = value\n");
    let o = run(&["inspect", &s(&p), "--from", "yaml"]);
    assert_ne!(code(&o), OK);
    assert!(stderr(&o).contains("regx formats"), "{}", stderr(&o));
}

// ---------------------------------------------------------------------------
// JSON output shape
// ---------------------------------------------------------------------------

fn looks_like_json(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text).is_ok()
}

#[test]
fn json_output_is_well_formed_for_every_command_that_offers_it() {
    if skip_if_hkcu_not_writable("live JSON output matrix") {
        return;
    }
    let key = LiveKey::new("json");
    run(&[
        "set",
        key.as_str(),
        "-v",
        "Text",
        "-d",
        "a \"quoted\" \\ value",
        "-y",
    ]);

    for args in [
        vec!["query", key.as_str(), "--output", "json"],
        vec!["probe", key.as_str(), "--output", "json"],
        vec!["formats", "--output", "json"],
        vec!["--self-check", "--output", "json"],
    ] {
        let o = run(&args);
        let text = stdout(&o);
        assert!(
            looks_like_json(&text),
            "`{}` produced malformed JSON:\n{text}",
            args.join(" ")
        );
        assert!(
            !text.trim().is_empty(),
            "`{}` produced no JSON",
            args.join(" ")
        );
    }
}

#[test]
fn json_mode_never_silently_emits_plain_text_or_multiple_documents() {
    let sc = Scratch::new("json-contract");
    let a = sc.write(
        "a.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\JsonContractA]\r\n\
         \"x\"=\"one\"\r\n",
    );
    let b = sc.write(
        "b.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\JsonContractB]\r\n\
         \"x\"=\"two\"\r\n",
    );
    let inspect = run(&[
        "inspect",
        &s(&a),
        &s(&b),
        "--output",
        "json",
        "--log-level",
        "error",
    ]);
    let rendered = stdout(&inspect);
    assert_eq!(code(&inspect), OK, "{}", stderr(&inspect));
    assert!(looks_like_json(&rendered), "{rendered}");
    let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(parsed.as_array().map(Vec::len), Some(2), "{rendered}");

    let validate = run(&["validate", &s(&a), "--output", "json"]);
    assert_eq!(code(&validate), OK, "{}", stderr(&validate));
    let validated: serde_json::Value = serde_json::from_slice(&validate.stdout).unwrap();
    assert_eq!(validated.as_array().map(Vec::len), Some(1));
    assert_eq!(validated[0]["valid"], true);

    for args in [
        vec!["convert", &s(&a), "--output", "json"],
        vec!["merge", &s(&a), &s(&b), "--output", "json"],
        vec!["completions", "powershell", "--output", "json"],
        vec!["--self-check", "formats", "--output", "json"],
    ] {
        let output = run(&args);
        assert_eq!(code(&output), USAGE, "{}", args.join(" "));
        assert!(stdout(&output).trim().is_empty(), "{}", args.join(" "));
        assert!(
            stderr(&output).contains("JSON document")
                || stderr(&output).contains("registry-data JSON")
                || stderr(&output).contains("then use `convert --to json`")
                || stderr(&output).contains("cannot be encoded as JSON")
                || stderr(&output).contains("offline-hive operation"),
            "{}: {}",
            args.join(" "),
            stderr(&output)
        );
    }
}

#[test]
fn export_with_an_output_file_reports_json_instead_of_plain_text() {
    let sc = Scratch::new("export-json");
    let destination = sc.path("out.csv");

    let output = run(&[
        "export",
        "HKCU\\Environment",
        "--to",
        "csv",
        "--out",
        &s(&destination),
        "--dry-run",
        "--output",
        "json",
    ]);
    assert!(matches!(code(&output), OK | PARTIAL), "{}", stderr(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["file"], s(&destination));
    assert_eq!(json["dryRun"], true);
    assert!(json["bytes"].is_null());
    assert!(json["sha256"].is_null());
    assert!(!destination.exists());

    for (format, extension) in [("json", "json"), ("csv", "csv"), ("pol", "pol")] {
        let artifact = sc.path(&format!("live.{extension}"));
        let exported = run(&[
            "export",
            "HKCU\\Environment",
            "--to",
            format,
            "--out",
            &s(&artifact),
        ]);
        assert!(
            matches!(code(&exported), OK | PARTIAL),
            "{format}: {}",
            stderr(&exported)
        );
        assert!(artifact.exists(), "{format}: {}", artifact.display());

        let artifact_arg = s(&artifact);
        let mut inspect_args = vec!["inspect", &artifact_arg, "--output", "json"];
        if format == "pol" {
            inspect_args.extend(["--pol-root", "HKCU"]);
        }
        let inspected = run(&inspect_args);
        assert!(
            matches!(code(&inspected), OK | PARTIAL),
            "{format}: {}",
            stderr(&inspected)
        );
        assert!(looks_like_json(&stdout(&inspected)), "{format}");
    }

    let shallow = sc.path("current-version.json");
    let scoped = run(&[
        "export",
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        "--no-recursive",
        "--value",
        "ProductName",
        "--root-as",
        "HKCU\\Snapshot\\CurrentVersion",
        "--to",
        "json",
        "--out",
        &s(&shallow),
        "--output",
        "json",
    ]);
    assert!(matches!(code(&scoped), OK | PARTIAL), "{}", stderr(&scoped));
    let scoped_status: serde_json::Value = serde_json::from_slice(&scoped.stdout).unwrap();
    assert_eq!(scoped_status["recursive"], false);
    assert_eq!(
        scoped_status["rootAs"],
        "HKEY_CURRENT_USER\\Snapshot\\CurrentVersion"
    );
    assert_eq!(scoped_status["includeValues"][0], "ProductName");
    assert_eq!(scoped_status["keys"], 1);
    assert_eq!(scoped_status["values"], 1);
    assert_eq!(
        scoped_status["bytes"].as_u64().unwrap(),
        std::fs::metadata(&shallow).unwrap().len()
    );
    assert_eq!(scoped_status["sha256"].as_str().unwrap().len(), 64);
    let rebased = run(&[
        "search",
        &s(&shallow),
        "HKEY_CURRENT_USER\\Snapshot\\CurrentVersion",
        "--field",
        "key",
    ]);
    assert_eq!(code(&rebased), OK, "{}", stderr(&rebased));
    let profile_list = run(&["search", &s(&shallow), "ProfileList", "--field", "key"]);
    assert_eq!(code(&profile_list), NOT_FOUND);

    let reg4_json = run(&["export", "HKCU\\Environment", "--to", "json", "--reg4"]);
    assert_eq!(code(&reg4_json), USAGE);
    assert!(stderr(&reg4_json).contains("--to reg"));

    let stdout_conflict = run(&[
        "export",
        "HKCU\\Environment",
        "--to",
        "csv",
        "--output",
        "json",
    ]);
    assert_eq!(code(&stdout_conflict), USAGE);
    assert!(stderr(&stdout_conflict).contains("--out"));
}

#[test]
fn export_view_both_keeps_the_registry_views_separate() {
    let sc = Scratch::new("export-both");
    let destination = sc.path("out.reg");
    let destination_arg = s(&destination);
    let output = run(&[
        "export",
        "HKCU\\Environment",
        "--view",
        "both",
        "--out",
        &destination_arg,
        "--output",
        "json",
    ]);
    assert!(matches!(code(&output), OK | PARTIAL), "{}", stderr(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let views = json["views"].as_array().unwrap();
    assert_eq!(views.len(), 2, "{}", stdout(&output));
    assert_eq!(views[0]["view"], "32");
    assert_eq!(views[1]["view"], "64");
    assert!(views.iter().all(|view| view["dryRun"] == false));
    assert_eq!(json["format"], "reg");
    assert_eq!(json["recursive"], true);
    assert_eq!(json["includeValues"], serde_json::json!([]));
    for (view, file) in views
        .iter()
        .zip([sc.path("out.32.reg"), sc.path("out.64.reg")])
    {
        assert!(file.exists(), "{}", file.display());
        let bytes = std::fs::read(&file).unwrap();
        assert_eq!(view["bytes"], bytes.len() as u64);
        assert_eq!(view["sha256"].as_str().unwrap().len(), 64);
        assert!(
            bytes.starts_with(&[0xff, 0xfe]),
            "dual-view exports must be importable UTF-16 .reg files"
        );
    }

    let json_destination = sc.path("out.json");
    let json_views = run(&[
        "export",
        "HKCU\\Environment",
        "--view",
        "both",
        "--to",
        "json",
        "--value",
        "Path",
        "--root-as",
        "HKCU\\ExportedEnvironment",
        "--out",
        &s(&json_destination),
        "--output",
        "json",
    ]);
    assert!(
        matches!(code(&json_views), OK | PARTIAL),
        "{}",
        stderr(&json_views)
    );
    let json_view_status: serde_json::Value = serde_json::from_slice(&json_views.stdout).unwrap();
    assert_eq!(json_view_status["format"], "json");
    assert_eq!(
        json_view_status["rootAs"],
        "HKEY_CURRENT_USER\\ExportedEnvironment"
    );
    assert_eq!(json_view_status["includeValues"][0], "Path");
    for view in json_view_status["views"].as_array().unwrap() {
        assert_eq!(view["values"], 1);
    }
    for file in [sc.path("out.32.json"), sc.path("out.64.json")] {
        assert!(file.exists(), "{}", file.display());
        let inspected = run(&["inspect", &s(&file), "--output", "json"]);
        assert!(
            matches!(code(&inspected), OK | PARTIAL),
            "{}",
            stderr(&inspected)
        );
        let rebased = run(&[
            "search",
            &s(&file),
            "HKEY_CURRENT_USER\\ExportedEnvironment",
            "--field",
            "key",
        ]);
        assert_eq!(code(&rebased), OK, "{}", stderr(&rebased));
    }

    let ambiguous = run(&["export", "HKCU\\Environment", "--view", "both"]);
    assert_eq!(code(&ambiguous), USAGE);
    assert!(stderr(&ambiguous).contains("needs --out"));

    let invalid_root = run(&["export", "HKCU\\Environment", "--root-as", "relative"]);
    assert_eq!(code(&invalid_root), USAGE);
}

#[test]
fn probe_json_reports_hklm_software_as_not_writable() {
    if skip_if_elevated("probe reports HKLM as read-only") {
        return;
    }
    let o = run(&["probe", "HKLM\\SOFTWARE", "--output", "json"]);
    let text = stdout(&o);
    assert!(looks_like_json(&text), "{text}");
    assert!(text.contains("\"writable\": false"), "{text}");
    assert_eq!(code(&o), ACCESS_DENIED);
}

// ---------------------------------------------------------------------------
// validate --fix
// ---------------------------------------------------------------------------

#[test]
fn validate_fix_repairs_and_reports_lossy_changes() {
    let sc = Scratch::new("fix");
    let broken = sc.write(
        "broken.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\X]\r\n\
         \"s\"=hex(2):25,00,50,00\r\n\
         \"m\"=hex(7):61,00\r\n",
    );
    let fixed = sc.path("fixed.reg");

    let preview = run(&[
        "validate",
        &s(&broken),
        "--fix",
        "--dry-run",
        "--output",
        "json",
    ]);
    assert_eq!(code(&preview), OK, "stderr: {}", stderr(&preview));
    let preview_json: serde_json::Value =
        serde_json::from_slice(&preview.stdout).expect("validate repair JSON");
    assert_eq!(preview_json[0]["written"], false);
    assert_eq!(preview_json[0]["dryRun"], true);
    assert!(preview_json[0]["output"].is_null());
    assert!(preview_json[0]["bytes"].is_null());
    assert!(preview_json[0]["sha256"].is_null());
    assert!(preview_json[0]["backup"].is_null());
    assert!(preview_json[0]["backupBytes"].is_null());
    assert!(preview_json[0]["backupSha256"].is_null());
    assert_eq!(
        preview_json[0]["repairedData"]["keys"][0]["values"][0]["typeId"],
        2
    );
    assert_eq!(
        preview_json[0]["repairedData"]["keys"][0]["values"][0]["raw"],
        "25 00 50 00 00 00"
    );
    assert_eq!(
        preview_json[0]["repairedData"]["keys"][0]["values"][1]["typeId"],
        7
    );
    assert_eq!(
        preview_json[0]["repairedData"]["keys"][0]["values"][1]["raw"],
        "61 00 00 00 00 00"
    );

    let o = run(&[
        "validate",
        &s(&broken),
        "--fix",
        "-o",
        &s(&fixed),
        "--output",
        "json",
    ]);
    assert_eq!(code(&o), OK, "stderr: {}", stderr(&o));
    let repaired: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(repaired[0]["fixes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|fix| fix["message"].as_str().unwrap().contains("NUL terminator")));
    assert!(fixed.exists());
    assert_eq!(repaired[0]["output"], s(&fixed));
    assert_eq!(
        repaired[0]["bytes"].as_u64().unwrap(),
        std::fs::metadata(&fixed).unwrap().len()
    );
    assert_eq!(repaired[0]["sha256"].as_str().unwrap().len(), 64);
    assert!(repaired[0]["backup"].is_null());

    // The repaired file must itself validate cleanly.
    let v = run(&["validate", &s(&fixed), "--strict"]);
    assert_eq!(
        code(&v),
        OK,
        "the repaired file still warns: {}",
        stdout(&v)
    );

    let in_place = run(&[
        "validate",
        &s(&broken),
        "--fix",
        "--backup",
        "--output",
        "json",
    ]);
    assert_eq!(code(&in_place), OK, "stderr: {}", stderr(&in_place));
    let in_place_json: serde_json::Value = serde_json::from_slice(&in_place.stdout)
        .expect("backup mode must emit only the JSON document");
    let backup = broken.with_extension("reg.bak");
    assert_eq!(in_place_json[0]["output"], s(&broken));
    assert_eq!(in_place_json[0]["backup"], s(&backup));
    assert_eq!(
        in_place_json[0]["backupBytes"].as_u64().unwrap(),
        std::fs::metadata(&backup).unwrap().len()
    );
    assert_eq!(in_place_json[0]["backupSha256"].as_str().unwrap().len(), 64);

    let first = sc.write(
        "first.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\X]\r\n\
         \"s\"=hex(2):25,00,50,00\r\n",
    );
    let second = sc.write(
        "second.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\Y]\r\n\"x\"=\"y\"\r\n",
    );
    let first_before = std::fs::read(&first).unwrap();
    let second_before = std::fs::read(&second).unwrap();
    let multiple = run(&["validate", &s(&first), &s(&second), "--fix"]);
    assert_eq!(code(&multiple), USAGE, "{}", stderr(&multiple));
    assert!(stderr(&multiple).contains("exactly one input"));
    assert_eq!(std::fs::read(&first).unwrap(), first_before);
    assert_eq!(std::fs::read(&second).unwrap(), second_before);
}

#[test]
fn validate_refuses_to_fix_a_file_with_syntax_errors() {
    let sc = Scratch::new("fixrefuse");
    let bad = sc.write(
        "bad.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n[HKCU\\A\r\n",
    );
    let o = run(&["validate", &s(&bad), "--fix"]);
    assert_eq!(code(&o), PARSE);
    assert!(stderr(&o).contains("only repairs"), "{}", stderr(&o));
}

// ---------------------------------------------------------------------------
// Redirection
// ---------------------------------------------------------------------------

#[test]
fn redirection_refuses_system_and_skips_low_confidence() {
    let sc = Scratch::new("redirect");
    let f = sc.write(
        "machine.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\X]\r\n\"Start\"=dword:00000002\r\n\r\n\
         [HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Acme]\r\n\"P\"=dword:00000001\r\n\r\n\
         [HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\.acme]\r\n@=\"Acme.Doc\"\r\n",
    );
    let o = run(&["convert", &s(&f), "--redirect", "auto"]);

    let err = stderr(&o);
    assert!(err.contains("refuse"), "SYSTEM must be refused: {err}");
    assert!(
        err.contains("skip"),
        "the machine policy must be skipped: {err}"
    );
    // The Classes key is the one reliable mapping and must survive.
    assert!(
        stdout(&o).contains("HKEY_CURRENT_USER\\SOFTWARE\\Classes\\.acme"),
        "{}",
        stdout(&o)
    );
    assert_eq!(
        code(&o),
        PARTIAL,
        "something was skipped, so this is a partial run"
    );
}

#[test]
fn redirection_recognises_windows_setup_shell_and_logon_mechanisms() {
    let sc = Scratch::new("redirect-windows-mechanisms");
    let f = sc.write(
        "mechanisms.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\{ABC}]\r\n\
         \"StubPath\"=\"setup.exe\"\r\n\r\n\
         [HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders]\r\n\
         \"Desktop\"=\"C:\\\\Desktop\"\r\n\r\n\
         [HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]\r\n\
         \"Shell\"=\"explorer.exe\"\r\n",
    );
    let o = run(&[
        "convert",
        &s(&f),
        "--redirect",
        "auto",
        "--on-refuse",
        "fail",
    ]);
    let err = stderr(&o);

    assert_eq!(code(&o), REDIRECTION_REFUSED, "{err}");
    assert!(
        stdout(&o).is_empty(),
        "refused conversion must emit no file"
    );
    for mechanism in ["Active Setup", "User Shell Folders", "Winlogon"] {
        assert!(
            err.contains(mechanism),
            "missing {mechanism} classification: {err}"
        );
    }
}

// ---------------------------------------------------------------------------
// Offline hives
// ---------------------------------------------------------------------------

#[test]
fn hive_create_write_reopen_without_elevation() {
    let sc = Scratch::new("hive");
    let hive = sc.path("app.hive");

    let o = run(&[
        "hive",
        &s(&hive),
        "--create",
        "-y",
        "exec",
        "-c",
        "set Software\\MyApp -v License -d OK",
        "-c",
        "set Software\\MyApp -v Seats -t REG_DWORD -d 25",
        "-c",
        "set Software\\MyApp -d DefaultPayload",
        "-c",
        "set Software\\MyApp\\Drift -v Extra -d RemoveMe",
    ]);
    assert_eq!(code(&o), OK, "stderr: {}", stderr(&o));
    assert!(hive.exists(), "the hive file was not created");

    // A fresh process must see the persisted data.
    let q = run(&["hive", &s(&hive), "query", "Software\\MyApp", "-r"]);
    assert_eq!(code(&q), OK, "stderr: {}", stderr(&q));
    assert!(stdout(&q).contains("OK"), "{}", stdout(&q));
    assert!(stdout(&q).contains("25"), "{}", stdout(&q));

    for (format, extension, subkey, expected_key) in [
        (
            "reg",
            "reg",
            "Software\\MyApp",
            "HKEY_CURRENT_USER\\Offline\\Software\\MyApp",
        ),
        (
            "json",
            "json",
            "Software\\MyApp",
            "HKEY_CURRENT_USER\\Offline\\Software\\MyApp",
        ),
        (
            "csv",
            "csv",
            "Software\\MyApp",
            "HKEY_CURRENT_USER\\Offline\\Software\\MyApp",
        ),
        (
            "pol",
            "pol",
            "Software\\MyApp\\Drift",
            "HKEY_CURRENT_USER\\Offline\\Software\\MyApp\\Drift",
        ),
    ] {
        let artifact = sc.path(&format!("hive-export.{extension}"));
        let exported = run(&[
            "hive",
            &s(&hive),
            "export",
            subkey,
            "--root-as",
            "HKEY_CURRENT_USER\\Offline",
            "--to",
            format,
            "--out",
            &s(&artifact),
            "--output",
            "json",
        ]);
        assert_eq!(code(&exported), OK, "{format}: {}", stderr(&exported));
        let status: serde_json::Value = serde_json::from_slice(&exported.stdout).unwrap();
        assert_eq!(status["format"], format);
        assert_eq!(status["rootAs"], "HKEY_CURRENT_USER\\Offline");
        assert!(artifact.is_file(), "{format}: {}", artifact.display());
        let artifact_arg = s(&artifact);
        let mut search_args = vec!["search", &artifact_arg, expected_key, "--field", "key"];
        if format == "pol" {
            search_args.extend(["--pol-root", "HKCU"]);
        }
        let searched = run(&search_args);
        assert_eq!(code(&searched), OK, "{format}: {}", stderr(&searched));
    }
    let selected_export = sc.path("hive-export-selected.json");
    let selected = run(&[
        "hive",
        &s(&hive),
        "export",
        "Software\\MyApp",
        "--to",
        "json",
        "--value",
        "lic*",
        "--out",
        &s(&selected_export),
        "--output",
        "json",
    ]);
    assert_eq!(code(&selected), OK, "{}", stderr(&selected));
    let selected_status: serde_json::Value = serde_json::from_slice(&selected.stdout).unwrap();
    assert_eq!(selected_status["keys"], 1);
    assert_eq!(selected_status["values"], 1);
    let selected_search = run(&["search", &s(&selected_export), "License", "--field", "name"]);
    assert_eq!(code(&selected_search), OK);
    let omitted_search = run(&["search", &s(&selected_export), "Seats", "--field", "name"]);
    assert_eq!(code(&omitted_search), NOT_FOUND);

    let shallow_export = sc.path("hive-export-shallow.json");
    let shallow = run(&[
        "hive",
        &s(&hive),
        "export",
        "Software\\MyApp",
        "--to",
        "json",
        "--no-recursive",
        "--out",
        &s(&shallow_export),
    ]);
    assert_eq!(code(&shallow), OK, "{}", stderr(&shallow));
    let child_search = run(&["search", &s(&shallow_export), "Drift", "--field", "key"]);
    assert_eq!(code(&child_search), NOT_FOUND);

    let no_match_artifact = sc.path("hive-export-no-match.json");
    let no_match = run(&[
        "hive",
        &s(&hive),
        "export",
        "Software\\MyApp",
        "--to",
        "json",
        "--value",
        "definitely-missing",
        "--out",
        &s(&no_match_artifact),
    ]);
    assert_eq!(code(&no_match), NOT_FOUND, "{}", stderr(&no_match));
    assert!(!no_match_artifact.exists());

    let unsafe_pol = sc.path("hive-export-unsafe.pol");
    let refused_pol = run(&[
        "hive",
        &s(&hive),
        "export",
        "Software\\MyApp",
        "--to",
        "pol",
        "--out",
        &s(&unsafe_pol),
    ]);
    assert_eq!(code(&refused_pol), IO, "{}", stderr(&refused_pol));
    assert!(stderr(&refused_pol).contains("default-value mutation"));
    assert!(!unsafe_pol.exists());
    let ambiguous_stdout = run(&[
        "hive",
        &s(&hive),
        "export",
        "Software",
        "--to",
        "csv",
        "--output",
        "json",
    ]);
    assert_eq!(code(&ambiguous_stdout), USAGE);
    assert!(stderr(&ambiguous_stdout).contains("use --out"));
    let invalid_root = run(&[
        "hive",
        &s(&hive),
        "export",
        "Software",
        "--root-as",
        "offline",
    ]);
    assert_eq!(code(&invalid_root), USAGE);

    let conflicting = sc.write(
        "hive-conflict.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\MyApp]\r\n\
         \"License\"=\"first\"\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\MyApp]\r\n\
         \"license\"=\"second\"\r\n",
    );
    for (operation, backup_name) in [
        ("import", "hive-conflict-import-undo.reg"),
        ("sync", "hive-conflict-sync-undo.reg"),
    ] {
        let backup = sc.path(backup_name);
        let refused = run(&[
            "hive",
            &s(&hive),
            "-y",
            operation,
            &s(&conflicting),
            "--strip-root",
            "HKCU",
            "--conflicts",
            "error",
            "--backup",
            &s(&backup),
        ]);
        assert_eq!(code(&refused), PARSE, "{operation}: {}", stderr(&refused));
        assert!(!backup.exists(), "{operation} wrote undo before refusal");
    }
    let unchanged = run(&["hive", &s(&hive), "query", "Software\\MyApp"]);
    assert_eq!(code(&unchanged), OK, "{}", stderr(&unchanged));
    assert!(stdout(&unchanged).contains("OK"));
    assert!(!stdout(&unchanged).contains("second"));

    let probe = run(&[
        "hive",
        &s(&hive),
        "probe",
        "Software\\MyApp",
        "--output",
        "json",
    ]);
    assert_eq!(code(&probe), OK, "{}", stderr(&probe));
    let probe_json: serde_json::Value =
        serde_json::from_slice(&probe.stdout).expect("hive probe JSON");
    assert_eq!(probe_json["subkey"], "Software\\MyApp");
    assert_eq!(probe_json["exists"], true);
    assert_eq!(probe_json["readable"], true);
    assert_eq!(probe_json["writable"], true);

    let creatable = run(&[
        "hive",
        &s(&hive),
        "probe",
        "Software\\Future",
        "--output",
        "json",
    ]);
    assert_eq!(code(&creatable), OK, "{}", stderr(&creatable));
    let creatable_json: serde_json::Value =
        serde_json::from_slice(&creatable.stdout).expect("hive missing-subkey probe JSON");
    assert_eq!(creatable_json["exists"], false);
    assert_eq!(creatable_json["creatable"], true);

    let permissions = run(&[
        "hive",
        &s(&hive),
        "permissions",
        "Software\\MyApp",
        "--output",
        "json",
    ]);
    assert_eq!(code(&permissions), OK, "{}", stderr(&permissions));
    let permissions_json: serde_json::Value =
        serde_json::from_slice(&permissions.stdout).expect("hive permissions JSON");
    assert_eq!(permissions_json["subkey"], "Software\\MyApp");
    let permission_views = permissions_json["views"].as_array().unwrap();
    assert_eq!(permission_views.len(), 1);
    assert_eq!(permission_views[0]["view"], "native");
    assert!(permission_views[0]["ownerSid"]
        .as_str()
        .is_some_and(|sid| sid.starts_with("S-")));
    assert!(permission_views[0]["sddl"].as_str().is_some());

    let batch_manifest = sc.write(
        "hive-batch.json",
        r#"{
          "schema":"https://winregistry.org/schemas/batch-v1.json",
          "schemaVersion":1,
          "operations":[
            {"id":"mode","keys":[{"path":"HKCU\\Software\\Batch","values":[{"name":"Mode","type":"REG_SZ","data":"atomic"}]}]},
            {"id":"count","keys":[{"path":"HKCU\\Software\\Batch","values":[{"name":"Count","type":"REG_DWORD","data":2}]}]}
          ]
        }"#,
    );
    let batch_undo = sc.path("hive-batch-undo.reg");
    let cancelled_undo = sc.path("hive-batch-cancelled.reg");
    let cancelled_batch = run(&[
        "hive",
        &s(&hive),
        "batch",
        &s(&batch_manifest),
        "--strip-root",
        "HKCU",
        "--backup",
        &s(&cancelled_undo),
    ]);
    assert_eq!(code(&cancelled_batch), OK, "{}", stderr(&cancelled_batch));
    assert!(stderr(&cancelled_batch).contains("aborted"));
    assert!(
        !cancelled_undo.exists(),
        "cancelled hive batch wrote its undo artifact"
    );
    let cancelled_query = run(&["hive", &s(&hive), "query", "Software\\Batch"]);
    assert_eq!(
        code(&cancelled_query),
        NOT_FOUND,
        "{}",
        stderr(&cancelled_query)
    );

    let batch_apply = run(&[
        "hive",
        &s(&hive),
        "-y",
        "batch",
        &s(&batch_manifest),
        "--strip-root",
        "HKCU",
        "--backup",
        &s(&batch_undo),
        "--output",
        "json",
    ]);
    assert_eq!(code(&batch_apply), OK, "{}", stderr(&batch_apply));
    let batch_json: serde_json::Value =
        serde_json::from_slice(&batch_apply.stdout).expect("hive batch JSON");
    assert_eq!(batch_json["atomic"], true);
    assert_eq!(batch_json["operations"][0]["status"], "applied");
    assert_eq!(batch_json["operations"][1]["status"], "applied");
    assert_eq!(batch_json["operations"][0]["views"][0]["view"], "native");
    assert!(batch_undo.is_file());
    assert_eq!(
        batch_json["undo"][0]["bytes"].as_u64().unwrap(),
        std::fs::metadata(&batch_undo).unwrap().len()
    );
    assert_eq!(batch_json["undo"][0]["sha256"].as_str().unwrap().len(), 64);
    let batch_query = run(&["hive", &s(&hive), "query", "Software\\Batch"]);
    assert_eq!(code(&batch_query), OK, "{}", stderr(&batch_query));
    assert!(stdout(&batch_query).contains("atomic"));
    assert!(stdout(&batch_query).contains('2'));

    let batch_preview = run(&[
        "hive",
        &s(&hive),
        "--dry-run",
        "batch",
        &s(&batch_manifest),
        "--strip-root",
        "HKCU",
        "--output",
        "json",
    ]);
    assert_eq!(code(&batch_preview), OK, "{}", stderr(&batch_preview));
    let preview_json: serde_json::Value =
        serde_json::from_slice(&batch_preview.stdout).expect("hive batch preview JSON");
    assert_eq!(preview_json["dryRun"], true);
    assert_eq!(preview_json["undo"].as_array().unwrap().len(), 1);
    assert!(preview_json["undo"][0]["bytes"].is_null());
    assert!(preview_json["undo"][0]["sha256"].is_null());
    assert_eq!(preview_json["operations"][0]["status"], "planned");

    let rollback_manifest = sc.write(
        "hive-batch-rollback.json",
        r#"{
          "schema":"https://winregistry.org/schemas/batch-v1.json",
          "schemaVersion":1,
          "operations":[
            {"id":"transient","keys":[{"path":"HKCU\\Software\\BatchRollback","values":[{"name":"Temp","type":"REG_SZ","data":"remove-me"}]}]},
            {"id":"invalid-root-delete","keys":[{"path":"HKCU","delete":true,"values":[]}]}
          ]
        }"#,
    );
    let rolled_back = run(&[
        "hive",
        &s(&hive),
        "-y",
        "batch",
        &s(&rollback_manifest),
        "--strip-root",
        "HKCU",
        "--output",
        "json",
    ]);
    assert_eq!(code(&rolled_back), USAGE, "{}", stderr(&rolled_back));
    assert!(rolled_back.stdout.is_empty());
    assert!(stderr(&rolled_back).contains("mounted hive root"));
    let transient_absent = run(&[
        "hive",
        &s(&hive),
        "query",
        "Software\\BatchRollback",
        "-v",
        "Temp",
    ]);
    assert_eq!(
        code(&transient_absent),
        NOT_FOUND,
        "{}",
        stderr(&transient_absent)
    );

    let unconfirmed = run(&[
        "hive",
        &s(&hive),
        "set",
        "Software\\MyApp",
        "-v",
        "Unconfirmed",
        "-d",
        "must-not-write",
        "--backup",
        &s(&sc.path("cancelled-set-undo.reg")),
    ]);
    assert_eq!(code(&unconfirmed), OK, "{}", stderr(&unconfirmed));
    assert!(stderr(&unconfirmed).contains("aborted"));
    let absent_unconfirmed = run(&[
        "hive",
        &s(&hive),
        "query",
        "Software\\MyApp",
        "-v",
        "Unconfirmed",
    ]);
    assert_eq!(
        code(&absent_unconfirmed),
        NOT_FOUND,
        "{}",
        stderr(&absent_unconfirmed)
    );
    assert!(
        !sc.path("cancelled-set-undo.reg").exists(),
        "cancelled hive set wrote an undo artifact"
    );

    let set_undo = sc.path("hive-set-undo.reg");
    let undoing_set = run(&[
        "hive",
        &s(&hive),
        "-y",
        "set",
        "Software\\MyApp",
        "-v",
        "License",
        "-d",
        "CHANGED",
        "--backup",
        &s(&set_undo),
        "--output",
        "json",
    ]);
    assert_eq!(code(&undoing_set), OK, "{}", stderr(&undoing_set));
    let set_json: serde_json::Value =
        serde_json::from_slice(&undoing_set.stdout).expect("hive set JSON");
    assert_eq!(set_json["undo"], s(&set_undo));
    assert!(set_undo.is_file());
    assert_eq!(
        set_json["undoBytes"].as_u64().unwrap(),
        std::fs::metadata(&set_undo).unwrap().len()
    );
    assert_eq!(set_json["undoSha256"].as_str().unwrap().len(), 64);
    let changed = run(&[
        "hive",
        &s(&hive),
        "query",
        "Software\\MyApp",
        "-v",
        "License",
    ]);
    assert!(stdout(&changed).contains("CHANGED"), "{}", stdout(&changed));

    let set_redo = sc.path("hive-set-redo.reg");
    let restored = run(&[
        "hive",
        &s(&hive),
        "-y",
        "undo",
        &s(&set_undo),
        "--backup",
        &s(&set_redo),
        "--output",
        "json",
    ]);
    assert_eq!(code(&restored), OK, "{}", stderr(&restored));
    let restored_json: serde_json::Value =
        serde_json::from_slice(&restored.stdout).expect("hive undo JSON");
    assert_eq!(restored_json["redo"], s(&set_redo));
    assert!(restored_json.get("undo").is_none());
    assert!(
        set_redo.is_file(),
        "hive undo must preserve a redo snapshot"
    );
    assert_eq!(
        restored_json["redoBytes"].as_u64().unwrap(),
        std::fs::metadata(&set_redo).unwrap().len()
    );
    assert_eq!(restored_json["redoSha256"].as_str().unwrap().len(), 64);
    let restored_value = run(&[
        "hive",
        &s(&hive),
        "query",
        "Software\\MyApp",
        "-v",
        "License",
    ]);
    assert!(
        stdout(&restored_value).contains("OK"),
        "{}",
        stdout(&restored_value)
    );
    let redo_undo = sc.path("hive-redo-undo.reg");
    let redone = run(&[
        "hive",
        &s(&hive),
        "-y",
        "undo",
        &s(&set_redo),
        "--backup",
        &s(&redo_undo),
    ]);
    assert_eq!(code(&redone), OK, "{}", stderr(&redone));
    assert!(redo_undo.is_file());
    let redone_value = run(&[
        "hive",
        &s(&hive),
        "query",
        "Software\\MyApp",
        "-v",
        "License",
    ]);
    assert!(
        stdout(&redone_value).contains("CHANGED"),
        "{}",
        stdout(&redone_value)
    );
    let restored_again = run(&["hive", &s(&hive), "-y", "undo", &s(&set_undo)]);
    assert_eq!(code(&restored_again), OK, "{}", stderr(&restored_again));

    let atomic_preview = run(&[
        "hive",
        &s(&hive),
        "--dry-run",
        "-y",
        "set",
        "Software\\MyApp",
        "-v",
        "Preview",
        "-d",
        "no-write",
        "--output",
        "json",
    ]);
    assert_eq!(code(&atomic_preview), OK, "{}", stderr(&atomic_preview));
    let atomic_json: serde_json::Value =
        serde_json::from_slice(&atomic_preview.stdout).expect("hive atomic JSON");
    assert!(atomic_json["apply"].is_object());
    assert!(atomic_json["undo"].is_null());
    assert!(atomic_json["undoBytes"].is_null());
    assert!(atomic_json["undoSha256"].is_null());
    assert_eq!(atomic_json["rolledBack"], false);
    assert!(atomic_json["rollback"].is_null());

    let hive_search = run(&[
        "hive",
        &s(&hive),
        "search",
        "Software",
        "license",
        "--field",
        "name",
        "--value",
        "Lic*",
        "--exclude-value",
        "Seats",
        "--output",
        "json",
    ]);
    assert_eq!(code(&hive_search), OK, "{}", stderr(&hive_search));
    let search_json: serde_json::Value =
        serde_json::from_slice(&hive_search.stdout).expect("hive search JSON");
    assert_eq!(search_json["query"], "license");
    assert_eq!(search_json["mode"], "substring");
    assert_eq!(search_json["includeValues"], serde_json::json!(["Lic*"]));
    assert_eq!(search_json["excludeValues"], serde_json::json!(["Seats"]));
    assert_eq!(search_json["matches"].as_array().unwrap().len(), 1);
    assert_eq!(search_json["matches"][0]["field"], "name");
    assert_eq!(search_json["matches"][0]["name"], "License");

    let regex_search = run(&[
        "hive",
        &s(&hive),
        "search",
        "Software",
        "^(License|Seats)$",
        "--match",
        "regex",
        "--field",
        "name",
        "--limit",
        "1",
        "--output",
        "json",
    ]);
    assert_eq!(code(&regex_search), OK, "{}", stderr(&regex_search));
    let regex_json: serde_json::Value =
        serde_json::from_slice(&regex_search.stdout).expect("hive regex search JSON");
    assert_eq!(regex_json["truncated"], true);
    assert_eq!(regex_json["matches"].as_array().unwrap().len(), 1);

    let absent_search = run(&["hive", &s(&hive), "search", "Software", "definitely-absent"]);
    assert_eq!(
        code(&absent_search),
        NOT_FOUND,
        "{}",
        stderr(&absent_search)
    );

    let read_only_exec = run(&["hive", &s(&hive), "exec", "-c", "search Software delete"]);
    assert_eq!(
        code(&read_only_exec),
        NOT_FOUND,
        "{}",
        stderr(&read_only_exec)
    );
    assert!(
        stderr(&read_only_exec).contains("(read-only)"),
        "a search term matching a mutation verb must not request hive write access: {}",
        stderr(&read_only_exec)
    );

    let values = run(&[
        "hive",
        &s(&hive),
        "-y",
        "exec",
        "-c",
        "copy-value Software\\MyApp License Software\\Copied --dest-value Clone",
        "-c",
        "move-value Software\\Copied Clone Software\\MyApp --dest-value Renamed",
        "-c",
        "copy-value Software\\MyApp @ Software\\Copied",
    ]);
    assert_eq!(code(&values), OK, "stderr: {}", stderr(&values));
    let values_stderr = stderr(&values);
    let value_undo_paths = values_stderr
        .lines()
        .filter_map(|line| {
            line.split_once("offline-hive undo -> ")
                .map(|(_, path)| path)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        value_undo_paths.len(),
        3,
        "every hive exec mutation needs its own undo path: {}",
        values_stderr
    );
    assert_eq!(
        value_undo_paths
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        value_undo_paths.len(),
        "hive exec reused a default undo path: {}",
        values_stderr
    );
    let source_after = run(&["hive", &s(&hive), "query", "Software\\MyApp"]);
    assert_eq!(code(&source_after), OK, "{}", stderr(&source_after));
    assert!(
        stdout(&source_after).contains("OK"),
        "{}",
        stdout(&source_after)
    );
    assert!(
        stdout(&source_after).contains("Renamed"),
        "{}",
        stdout(&source_after)
    );
    assert!(
        stdout(&source_after).contains("25"),
        "{}",
        stdout(&source_after)
    );
    let copied_after = run(&["hive", &s(&hive), "query", "Software\\Copied"]);
    assert_eq!(code(&copied_after), OK, "{}", stderr(&copied_after));
    assert!(
        !stdout(&copied_after).contains("Clone"),
        "{}",
        stdout(&copied_after)
    );
    assert!(
        stdout(&copied_after).contains("DefaultPayload"),
        "{}",
        stdout(&copied_after)
    );

    let dry_tree = run(&[
        "hive",
        &s(&hive),
        "--dry-run",
        "-y",
        "copy",
        "Software\\MyApp",
        "Software\\DryTree",
        "--output",
        "json",
    ]);
    assert_eq!(code(&dry_tree), OK, "{}", stderr(&dry_tree));
    let dry_json: serde_json::Value =
        serde_json::from_slice(&dry_tree.stdout).expect("hive dry-run copy JSON");
    assert_eq!(dry_json["dryRun"], true);
    let absent_dry_tree = run(&["hive", &s(&hive), "query", "Software\\DryTree"]);
    assert_eq!(
        code(&absent_dry_tree),
        NOT_FOUND,
        "{}",
        stderr(&absent_dry_tree)
    );

    let copy_tree = run(&[
        "hive",
        &s(&hive),
        "-y",
        "copy",
        "Software\\MyApp",
        "Software\\TreeCopy",
        "--output",
        "json",
    ]);
    assert_eq!(code(&copy_tree), OK, "{}", stderr(&copy_tree));
    let copy_json: serde_json::Value =
        serde_json::from_slice(&copy_tree.stdout).expect("hive copy JSON");
    assert_eq!(copy_json["operation"], "copy");
    assert_eq!(copy_json["rolledBack"], false);
    let copied_tree = run(&["hive", &s(&hive), "query", "Software\\TreeCopy", "-r"]);
    assert_eq!(code(&copied_tree), OK, "{}", stderr(&copied_tree));
    assert!(stdout(&copied_tree).contains("Renamed"));
    assert!(stdout(&copied_tree).contains("25"));

    let collision = run(&[
        "hive",
        &s(&hive),
        "-y",
        "copy",
        "Software\\MyApp",
        "Software\\TreeCopy",
    ]);
    assert_eq!(code(&collision), USAGE, "{}", stderr(&collision));
    assert!(stderr(&collision).contains("--overwrite"));

    let move_tree = run(&[
        "hive",
        &s(&hive),
        "-y",
        "move",
        "Software\\TreeCopy",
        "Software\\TreeMoved",
    ]);
    assert_eq!(code(&move_tree), OK, "{}", stderr(&move_tree));
    let old_tree = run(&["hive", &s(&hive), "query", "Software\\TreeCopy"]);
    assert_eq!(code(&old_tree), NOT_FOUND, "{}", stderr(&old_tree));
    let moved_tree = run(&["hive", &s(&hive), "query", "Software\\TreeMoved", "-r"]);
    assert_eq!(code(&moved_tree), OK, "{}", stderr(&moved_tree));
    assert!(stdout(&moved_tree).contains("Renamed"));

    let recursive = run(&[
        "hive",
        &s(&hive),
        "-y",
        "move",
        "Software\\MyApp",
        "Software\\MyApp\\Nested",
    ]);
    assert_eq!(code(&recursive), USAGE, "{}", stderr(&recursive));
    assert!(stderr(&recursive).contains("inside source"));

    let desired = sc.write(
        "hive-desired.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\MyApp]\r\n\
         \"License\"=\"FINAL\"\r\n\r\n\
         [HKEY_CURRENT_USER\\Software\\MyApp\\Keep]\r\n\
         \"Enabled\"=dword:00000001\r\n",
    );
    let drift_patch = sc.path("hive-drift.reg");
    let drift = run(&[
        "hive",
        &s(&hive),
        "diff",
        "Software\\MyApp",
        &s(&desired),
        "--strip-root",
        "HKCU",
        "--exit-code",
        "--out",
        &s(&drift_patch),
        "--output",
        "json",
    ]);
    assert_eq!(code(&drift), PARTIAL, "{}", stderr(&drift));
    assert!(drift_patch.is_file());
    let drift_json: serde_json::Value =
        serde_json::from_slice(&drift.stdout).expect("hive diff JSON");
    assert!(
        drift_json["added"].as_u64().unwrap()
            + drift_json["modified"].as_u64().unwrap()
            + drift_json["removed"].as_u64().unwrap()
            > 0
    );
    assert_eq!(drift_json["patchFormat"], "reg");
    assert_eq!(drift_json["patchWritten"], true);
    let desired_json = sc.write(
        "hive-desired.json",
        "{\"HKEY_CURRENT_USER\\\\Software\\\\MyApp\":{\"License\":\"FINAL\"},\
         \"HKEY_CURRENT_USER\\\\Software\\\\MyApp\\\\Keep\":{\"Enabled\":1}}",
    );
    let json_input_drift = run(&[
        "hive",
        &s(&hive),
        "diff",
        "Software\\MyApp",
        &s(&desired_json),
        "--strip-root",
        "HKCU",
        "--output",
        "json",
    ]);
    assert_eq!(code(&json_input_drift), OK, "{}", stderr(&json_input_drift));
    let json_input_status: serde_json::Value =
        serde_json::from_slice(&json_input_drift.stdout).unwrap();
    assert_eq!(json_input_status["added"], drift_json["added"]);
    assert_eq!(json_input_status["modified"], drift_json["modified"]);
    assert_eq!(json_input_status["removed"], drift_json["removed"]);
    let json_patch = sc.path("hive-drift.json");
    let json_drift = run(&[
        "hive",
        &s(&hive),
        "diff",
        "Software\\MyApp",
        &s(&desired),
        "--strip-root",
        "HKCU",
        "--to",
        "json",
        "--out",
        &s(&json_patch),
        "--output",
        "json",
    ]);
    assert_eq!(code(&json_drift), OK, "{}", stderr(&json_drift));
    let json_status: serde_json::Value = serde_json::from_slice(&json_drift.stdout).unwrap();
    assert_eq!(json_status["patchFormat"], "json");
    assert_eq!(json_status["patchWritten"], true);
    let inspected_json_patch = run(&["inspect", &s(&json_patch), "--output", "json"]);
    assert_eq!(
        code(&inspected_json_patch),
        OK,
        "{}",
        stderr(&inspected_json_patch)
    );
    let apply_patch = run(&["hive", &s(&hive), "-y", "import", &s(&drift_patch)]);
    assert_eq!(code(&apply_patch), OK, "{}", stderr(&apply_patch));
    let clean_diff = run(&[
        "hive",
        &s(&hive),
        "diff",
        "Software\\MyApp",
        &s(&desired),
        "--strip-root",
        "HKEY_CURRENT_USER",
        "--exit-code",
        "--summary-only",
    ]);
    assert_eq!(code(&clean_diff), OK, "{}", stderr(&clean_diff));
    assert!(stdout(&clean_diff).contains("0 added, 0 modified, 0 removed"));

    let imported_json = sc.write(
        "hive-import.json",
        "{\"HKEY_CURRENT_USER\\\\Software\\\\Imported\":{\"Name\":\"initial\"}}",
    );
    let imported = run(&[
        "hive",
        &s(&hive),
        "-y",
        "import",
        &s(&imported_json),
        "--strip-root",
        "HKCU",
    ]);
    assert_eq!(code(&imported), OK, "{}", stderr(&imported));
    let synced_csv = sc.write(
        "hive-sync.csv",
        "key,name,type,data\r\n\
         HKEY_CURRENT_USER\\Software\\Imported,Name,REG_SZ,synced\r\n",
    );
    let synced = run(&[
        "hive",
        &s(&hive),
        "-y",
        "sync",
        &s(&synced_csv),
        "--strip-root",
        "HKCU",
    ]);
    assert_eq!(code(&synced), OK, "{}", stderr(&synced));
    let imported_query = run(&[
        "hive",
        &s(&hive),
        "query",
        "Software\\Imported",
        "-v",
        "Name",
    ]);
    assert_eq!(code(&imported_query), OK, "{}", stderr(&imported_query));
    assert!(stdout(&imported_query).contains("synced"));

    let lossy_inf = sc.write(
        "hive-loss.inf",
        "[Version]\r\nSignature=\"$WINDOWS NT$\"\r\n\
         [DefaultInstall]\r\nAddReg=Conditional\r\n\
         [Conditional]\r\n\
         HKCU,\"Software\\MyApp\",\"License\",0x00000002,\"unsafe\"\r\n",
    );
    let unsafe_patch = sc.path("hive-loss-patch.reg");
    let lossy_diff = run(&[
        "hive",
        &s(&hive),
        "diff",
        "Software\\MyApp",
        &s(&lossy_inf),
        "--inf-section",
        "Conditional",
        "--strip-root",
        "HKCU",
        "--out",
        &s(&unsafe_patch),
        "--output",
        "json",
    ]);
    assert_eq!(code(&lossy_diff), PARTIAL, "{}", stderr(&lossy_diff));
    let lossy_status: serde_json::Value = serde_json::from_slice(&lossy_diff.stdout).unwrap();
    assert_eq!(lossy_status["incomplete"], true);
    assert_eq!(lossy_status["patchWritten"], false);
    assert!(!unsafe_patch.exists());
    for operation in ["import", "sync"] {
        let refused = run(&[
            "hive",
            &s(&hive),
            operation,
            &s(&lossy_inf),
            "--inf-section",
            "Conditional",
            "--strip-root",
            "HKCU",
            "--dry-run",
            "-y",
        ]);
        assert_eq!(code(&refused), PARSE, "{operation}: {}", stderr(&refused));
        assert!(
            stderr(&refused).contains("requires an exact registry-data model"),
            "{operation}: {}",
            stderr(&refused)
        );
    }

    let reseed_drift = run(&[
        "hive",
        &s(&hive),
        "-y",
        "exec",
        "-c",
        "set Software\\MyApp -v License -d OLD",
        "-c",
        "set Software\\MyApp -v Seats -t REG_DWORD -d 25",
        "-c",
        "set Software\\MyApp -v Renamed -d OK",
        "-c",
        "set Software\\MyApp -d DefaultPayload",
        "-c",
        "set Software\\MyApp\\Drift -v Extra -d RemoveMe",
    ]);
    assert_eq!(code(&reseed_drift), OK, "{}", stderr(&reseed_drift));

    let sync_dry = run(&[
        "hive",
        &s(&hive),
        "--dry-run",
        "-y",
        "sync",
        &s(&desired),
        "--strip-root",
        "HKCU",
        "--prune",
        "--prune-keys",
        "--output",
        "json",
    ]);
    assert_eq!(code(&sync_dry), OK, "{}", stderr(&sync_dry));
    let sync_dry_json: serde_json::Value =
        serde_json::from_slice(&sync_dry.stdout).expect("hive sync dry-run JSON");
    assert_eq!(sync_dry_json["dryRun"], true);
    let before_sync = run(&["hive", &s(&hive), "query", "Software\\MyApp", "-r"]);
    assert_eq!(code(&before_sync), OK, "{}", stderr(&before_sync));
    assert!(stdout(&before_sync).contains("RemoveMe"));
    assert!(stdout(&before_sync).contains("25"));

    let sync = run(&[
        "hive",
        &s(&hive),
        "-y",
        "sync",
        &s(&desired),
        "--strip-root",
        "HKEY_CURRENT_USER",
        "--prune",
        "--prune-keys",
        "--output",
        "json",
    ]);
    assert_eq!(code(&sync), OK, "{}", stderr(&sync));
    let sync_json: serde_json::Value =
        serde_json::from_slice(&sync.stdout).expect("hive sync JSON");
    assert_eq!(sync_json["prune"], true);
    assert_eq!(sync_json["pruneKeys"], true);
    assert_eq!(sync_json["rolledBack"], false);
    let after_sync = run(&["hive", &s(&hive), "query", "Software\\MyApp", "-r"]);
    assert_eq!(code(&after_sync), OK, "{}", stderr(&after_sync));
    let after_sync_text = stdout(&after_sync);
    assert!(after_sync_text.contains("FINAL"), "{after_sync_text}");
    assert!(after_sync_text.contains("Enabled"), "{after_sync_text}");
    assert!(!after_sync_text.contains("RemoveMe"), "{after_sync_text}");
    assert!(!after_sync_text.contains("Seats"), "{after_sync_text}");
    assert!(!after_sync_text.contains("Renamed"), "{after_sync_text}");

    let outside = sc.write(
        "outside.reg",
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_LOCAL_MACHINE\\Software\\Outside]\r\n\"Bad\"=\"No\"\r\n",
    );
    let refused_root = run(&[
        "hive",
        &s(&hive),
        "-y",
        "sync",
        &s(&outside),
        "--strip-root",
        "HKCU",
    ]);
    assert_eq!(code(&refused_root), USAGE, "{}", stderr(&refused_root));
    assert!(
        stderr(&refused_root).contains("hives differ"),
        "{}",
        stderr(&refused_root)
    );

    let i = run(&["hive", &s(&hive), "info"]);
    assert_eq!(code(&i), OK);
    assert!(stdout(&i).contains("regf"), "{}", stdout(&i));

    let invalid_view = run(&["hive", &s(&hive), "info", "--view", "both"]);
    assert_eq!(code(&invalid_view), USAGE, "{}", stderr(&invalid_view));
    assert!(
        stderr(&invalid_view).contains("no WOW64 registry-view split"),
        "{}",
        stderr(&invalid_view)
    );

    let hive_arg = s(&hive);
    for args in [
        vec!["hive", &hive_arg, "info", "--output", "json"],
        vec![
            "hive", &hive_arg, "ls", "Software", "-r", "--output", "json",
        ],
        vec!["hive", &hive_arg, "stats", "Software", "--output", "json"],
        vec![
            "hive",
            &hive_arg,
            "fingerprint",
            "Software",
            "--output",
            "json",
        ],
        vec!["hive", &hive_arg, "export", "Software", "--output", "json"],
    ] {
        let output = run(&args);
        assert_eq!(code(&output), OK, "{}: {}", args.join(" "), stderr(&output));
        serde_json::from_slice::<serde_json::Value>(&output.stdout)
            .unwrap_or_else(|error| panic!("{}: {error}: {}", args.join(" "), stdout(&output)));
    }

    let hive_fingerprint = run(&[
        "hive",
        &hive_arg,
        "fingerprint",
        "Software",
        "--output",
        "json",
    ]);
    assert_eq!(code(&hive_fingerprint), OK, "{}", stderr(&hive_fingerprint));
    let hive_fingerprint_json: serde_json::Value =
        serde_json::from_slice(&hive_fingerprint.stdout).unwrap();
    let hive_sha = hive_fingerprint_json["sha256"].as_str().unwrap();
    assert!(hive_fingerprint_json["expected"].is_null());
    assert!(hive_fingerprint_json["matches"].is_null());
    let hive_matched = run(&[
        "hive",
        &hive_arg,
        "fingerprint",
        "Software",
        "--expect",
        hive_sha,
        "--output",
        "json",
    ]);
    assert_eq!(code(&hive_matched), OK, "{}", stderr(&hive_matched));
    let hive_matched_json: serde_json::Value =
        serde_json::from_slice(&hive_matched.stdout).unwrap();
    assert_eq!(hive_matched_json["matches"], true);

    let hive_scoped = run(&[
        "hive",
        &hive_arg,
        "fingerprint",
        "Software",
        "--include",
        "Software\\MyApp\\Keep",
        "--value",
        "Enabled",
        "--output",
        "json",
    ]);
    assert_eq!(code(&hive_scoped), OK, "{}", stderr(&hive_scoped));
    let hive_scoped_json: serde_json::Value = serde_json::from_slice(&hive_scoped.stdout).unwrap();
    assert_eq!(
        hive_scoped_json["include"],
        serde_json::json!(["Software\\MyApp\\Keep"])
    );
    assert_eq!(
        hive_scoped_json["includeValues"],
        serde_json::json!(["Enabled"])
    );
    assert_eq!(hive_scoped_json["matched"], true);
    assert_eq!(hive_scoped_json["keys"], 1);
    assert_eq!(hive_scoped_json["values"], 1);

    let hive_stats_scoped = run(&[
        "hive",
        &hive_arg,
        "stats",
        "Software",
        "--include",
        "Software\\MyApp\\Keep",
        "--value",
        "Enabled",
        "--output",
        "json",
    ]);
    assert_eq!(
        code(&hive_stats_scoped),
        OK,
        "{}",
        stderr(&hive_stats_scoped)
    );
    let hive_stats_scoped_json: serde_json::Value =
        serde_json::from_slice(&hive_stats_scoped.stdout).unwrap();
    assert_eq!(hive_stats_scoped_json["matched"], true);
    assert_eq!(hive_stats_scoped_json["keys"], 1);
    assert_eq!(hive_stats_scoped_json["values"], 1);
    assert_eq!(
        hive_stats_scoped_json["includeValues"],
        serde_json::json!(["Enabled"])
    );

    let portable = sc.path("portable.reg");
    let portable_export = run(&[
        "hive",
        &hive_arg,
        "export",
        "Software",
        "--root-as",
        "HKCU\\PortableHive",
        "-o",
        &s(&portable),
    ]);
    assert_eq!(code(&portable_export), OK, "{}", stderr(&portable_export));
    let portable_hive_fingerprint = run(&[
        "hive",
        &hive_arg,
        "fingerprint",
        "Software",
        "--root-as",
        "HKCU\\PortableHive",
        "--output",
        "json",
    ]);
    let portable_file_fingerprint = run(&["fingerprint", &s(&portable), "--output", "json"]);
    assert_eq!(
        code(&portable_hive_fingerprint),
        OK,
        "{}",
        stderr(&portable_hive_fingerprint)
    );
    assert_eq!(
        code(&portable_file_fingerprint),
        OK,
        "{}",
        stderr(&portable_file_fingerprint)
    );
    let portable_hive_json: serde_json::Value =
        serde_json::from_slice(&portable_hive_fingerprint.stdout).unwrap();
    let portable_file_json: serde_json::Value =
        serde_json::from_slice(&portable_file_fingerprint.stdout).unwrap();
    assert_eq!(
        portable_hive_json["rootAs"],
        "HKEY_CURRENT_USER\\PortableHive"
    );
    assert_eq!(portable_hive_json["sha256"], portable_file_json["sha256"]);

    let portable_hive_stats = run(&[
        "hive",
        &hive_arg,
        "stats",
        "Software",
        "--root-as",
        "HKCU\\PortableHive",
        "--output",
        "json",
    ]);
    let original_hive_stats = run(&["hive", &hive_arg, "stats", "Software", "--output", "json"]);
    assert_eq!(
        code(&portable_hive_stats),
        OK,
        "{}",
        stderr(&portable_hive_stats)
    );
    assert_eq!(
        code(&original_hive_stats),
        OK,
        "{}",
        stderr(&original_hive_stats)
    );
    let portable_stats_json: serde_json::Value =
        serde_json::from_slice(&portable_hive_stats.stdout).unwrap();
    let original_stats_json: serde_json::Value =
        serde_json::from_slice(&original_hive_stats.stdout).unwrap();
    assert_eq!(
        portable_stats_json["rootAs"],
        "HKEY_CURRENT_USER\\PortableHive"
    );
    for field in [
        "keys",
        "values",
        "keyDeletes",
        "valueDeletes",
        "maxDepth",
        "payloadBytes",
        "types",
        "conflicts",
        "incomplete",
        "matched",
    ] {
        assert_eq!(
            portable_stats_json[field], original_stats_json[field],
            "mapped stats changed {field}"
        );
    }
    let portable_scoped_stats = run(&[
        "hive",
        &hive_arg,
        "stats",
        "Software",
        "--root-as",
        "HKCU\\PortableHive",
        "--include",
        "PortableHive\\Software\\MyApp\\Keep",
        "--value",
        "Enabled",
        "--output",
        "json",
    ]);
    assert_eq!(
        code(&portable_scoped_stats),
        OK,
        "{}",
        stderr(&portable_scoped_stats)
    );
    let portable_scoped_stats_json: serde_json::Value =
        serde_json::from_slice(&portable_scoped_stats.stdout).unwrap();
    assert_eq!(portable_scoped_stats_json["matched"], true);
    assert_eq!(portable_scoped_stats_json["keys"], 1);
    assert_eq!(portable_scoped_stats_json["values"], 1);

    let exec_json = run(&[
        "hive",
        &hive_arg,
        "exec",
        "-c",
        "query Software",
        "--output",
        "json",
    ]);
    assert_eq!(code(&exec_json), USAGE);
    assert!(stdout(&exec_json).trim().is_empty());
}

#[test]
fn hive_diff_value_filter_preserves_unselected_siblings() {
    let sc = Scratch::new("hive-diff-values");
    let hive = sc.path("scoped.hive");
    let created = run(&[
        "hive",
        &s(&hive),
        "--create",
        "-y",
        "exec",
        "-c",
        "set Software\\ScopedDiff -v selected -d remove",
        "-c",
        "set Software\\ScopedDiff -v untouched -d keep",
    ]);
    assert_eq!(code(&created), OK, "{}", stderr(&created));

    let desired = sc.write("empty.reg", "Windows Registry Editor Version 5.00\n");
    let patch = sc.path("selected-only.reg");
    let output = run(&[
        "hive",
        &s(&hive),
        "diff",
        "Software\\ScopedDiff",
        &s(&desired),
        "--value",
        "selected",
        "--output",
        "json",
        "--exit-code",
        "-o",
        &s(&patch),
    ]);
    assert_eq!(code(&output), PARTIAL, "{}", stderr(&output));
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["includeValues"], serde_json::json!(["selected"]));
    assert_eq!(status["removed"], 1);
    assert_eq!(status["patchWritten"], true);

    let bytes = std::fs::read(&patch).unwrap();
    let patch_text = String::from_utf16_lossy(
        &bytes
            .chunks_exact(2)
            .skip(1)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    );
    assert!(patch_text.contains("\"selected\"=-"), "{patch_text}");
    assert!(!patch_text.contains("[-HKEY_"), "{patch_text}");
    assert!(!patch_text.contains("untouched"), "{patch_text}");

    let applied = run(&["hive", &s(&hive), "-y", "import", &s(&patch)]);
    assert_eq!(code(&applied), OK, "{}", stderr(&applied));
    let queried = run(&["hive", &s(&hive), "query", "Software\\ScopedDiff"]);
    assert_eq!(code(&queried), OK, "{}", stderr(&queried));
    assert!(stdout(&queried).contains("untouched"));
    assert!(!stdout(&queried).contains("selected"));

    let help = run(&["hive", &s(&hive), "diff", "--help"]);
    assert_eq!(code(&help), OK);
    assert!(stdout(&help).contains("--value"));
    assert!(stdout(&help).contains("--exclude-value"));
}

#[test]
fn hive_export_filters_portable_key_paths() {
    let sc = Scratch::new("hive-export-key-filter");
    let hive = sc.path("scoped.hive");
    let created = run(&[
        "hive",
        &s(&hive),
        "--create",
        "-y",
        "exec",
        "-c",
        "set Software\\Scoped\\Keep -v Name -d keep",
        "-c",
        "set Software\\Scoped\\Drop -v Name -d drop",
    ]);
    assert_eq!(code(&created), OK, "{}", stderr(&created));

    let listed = run(&[
        "hive",
        &s(&hive),
        "ls",
        "Software\\Scoped",
        "--output",
        "json",
    ]);
    assert_eq!(code(&listed), OK, "{}", stderr(&listed));
    let listed_json: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(
        listed_json["keys"],
        serde_json::json!(["Software\\Scoped\\Drop", "Software\\Scoped\\Keep"])
    );
    assert_eq!(listed_json["truncated"], false);

    let limited_list = run(&[
        "hive",
        &s(&hive),
        "ls",
        "Software\\Scoped",
        "--limit",
        "1",
        "--output",
        "json",
    ]);
    assert_eq!(code(&limited_list), OK, "{}", stderr(&limited_list));
    let limited_json: serde_json::Value = serde_json::from_slice(&limited_list.stdout).unwrap();
    assert_eq!(limited_json["keys"].as_array().unwrap().len(), 1);
    assert_eq!(limited_json["truncated"], true);

    let scoped_list = run(&[
        "hive",
        &s(&hive),
        "ls",
        "Software\\Scoped",
        "--include",
        "**\\Keep",
        "--output",
        "json",
    ]);
    assert_eq!(code(&scoped_list), OK, "{}", stderr(&scoped_list));
    let scoped_json: serde_json::Value = serde_json::from_slice(&scoped_list.stdout).unwrap();
    assert_eq!(
        scoped_json["keys"],
        serde_json::json!(["Software\\Scoped\\Keep"])
    );

    let artifact = sc.path("keep.json");
    let exported = run(&[
        "hive",
        &s(&hive),
        "export",
        "Software\\Scoped",
        "--root-as",
        "HKCU\\Portable",
        "--include",
        "**\\Keep",
        "--to",
        "json",
        "-o",
        &s(&artifact),
        "--output",
        "json",
    ]);
    assert_eq!(code(&exported), OK, "{}", stderr(&exported));
    let status: serde_json::Value = serde_json::from_slice(&exported.stdout).unwrap();
    assert_eq!(status["include"], serde_json::json!(["**\\Keep"]));
    assert_eq!(status["keys"], 1);
    let data: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&artifact).unwrap()).unwrap();
    assert_eq!(data["keys"].as_array().unwrap().len(), 1);
    assert_eq!(
        data["keys"][0]["path"],
        "HKEY_CURRENT_USER\\Portable\\Software\\Scoped\\Keep"
    );

    let absent = sc.path("absent.reg");
    let no_match = run(&[
        "hive",
        &s(&hive),
        "export",
        "Software\\Scoped",
        "--include",
        "**\\Missing",
        "-o",
        &s(&absent),
    ]);
    assert_eq!(code(&no_match), NOT_FOUND);
    assert!(!absent.exists());
}

#[test]
fn query_json_embeds_exact_typed_values_not_only_previews() {
    let sc = Scratch::new("query-exact");
    let hive = sc.path("exact.hive");
    let created = run(&[
        "hive",
        &s(&hive),
        "--create",
        "-y",
        "exec",
        "-c",
        "set Software\\Exact -v Text -d hello",
        "-c",
        "set Software\\Exact -v Count -t REG_DWORD -d 42",
        "-c",
        "set Software\\Exact -v Raw -t REG_BINARY -d 00ff7a",
    ]);
    assert_eq!(code(&created), OK, "{}", stderr(&created));

    let queried = run(&[
        "hive",
        &s(&hive),
        "query",
        "Software\\Exact",
        "--output",
        "json",
    ]);
    assert_eq!(code(&queried), OK, "{}", stderr(&queried));
    let data: serde_json::Value = serde_json::from_slice(&queried.stdout).unwrap();
    let values = data[0]["values"].as_array().unwrap();
    let find = |name: &str| values.iter().find(|value| value["name"] == name).unwrap();
    assert_eq!(find("Text")["exact"]["type"], "REG_SZ");
    assert_eq!(find("Text")["exact"]["data"], "hello");
    assert_eq!(find("Count")["exact"]["type"], "REG_DWORD");
    assert_eq!(find("Count")["exact"]["data"], 42);
    assert_eq!(find("Raw")["exact"]["typeId"], 3);
    assert_eq!(find("Raw")["exact"]["raw"], "00 ff 7a");
    assert!(
        find("Raw")["data"].is_string(),
        "preview remains compatible"
    );
}

#[test]
fn a_text_file_is_rejected_as_a_hive_before_the_api_is_called() {
    let sc = Scratch::new("nothive");
    let f = sc.write("notahive.dat", "Windows Registry Editor Version 5.00\r\n");
    let o = run(&["hive", &s(&f), "info"]);
    assert_ne!(code(&o), OK);
    assert!(
        stdout(&o).contains("MISSING") || stderr(&o).contains("not a registry hive"),
        "stdout: {} stderr: {}",
        stdout(&o),
        stderr(&o)
    );
}

// ---------------------------------------------------------------------------
// discover
// ---------------------------------------------------------------------------

#[test]
fn discover_finds_the_sidecar_and_flags_nothing_when_clean() {
    let sc = Scratch::new("discover");
    std::fs::write(sc.path("tool.exe"), b"MZ").unwrap();
    sc.write(
        "tool.ini",
        "[HKEY_CURRENT_USER\\Software\\X]\nName = value\n",
    );

    let o = run(&["discover", &s(&sc.path("tool.exe"))]);
    assert_eq!(code(&o), OK, "stderr: {}", stderr(&o));
    assert!(stdout(&o).contains("tool.ini"), "{}", stdout(&o));
    assert!(
        stdout(&o).contains("beside the executable"),
        "{}",
        stdout(&o)
    );

    let json = run(&[
        "discover",
        &s(&sc.path("tool.exe")),
        "--strict",
        "--output",
        "json",
    ]);
    assert_eq!(code(&json), OK, "stderr: {}", stderr(&json));
    let report: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
    let reported_executable = PathBuf::from(report["executable"].as_str().unwrap());
    assert_eq!(
        std::fs::canonicalize(reported_executable).unwrap(),
        std::fs::canonicalize(sc.path("tool.exe")).unwrap()
    );
    assert_eq!(report["stem"], "tool");
    assert_eq!(report["policy"], false);
    assert_eq!(report["registryPointer"], false);
    assert_eq!(report["strict"], true);
    assert_eq!(report["risky"], 0);
    assert!(!report["notes"].as_array().unwrap().is_empty());
    assert!(!report["searched"].as_array().unwrap().is_empty());
    assert_eq!(report["found"][0]["origin"], "beside the executable");
    assert_eq!(
        report["found"][0]["path"],
        report["found"][0]["resolvedPath"]
    );
    assert_eq!(report["found"][0]["risks"], serde_json::json!([]));
    assert_eq!(report["found"][0]["riskDetails"], serde_json::json!([]));

    let anchor = sc.path("anchor");
    let cwd = sc.path("working");
    std::fs::create_dir_all(&anchor).unwrap();
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::write(anchor.join("risky.exe"), b"MZ").unwrap();
    std::fs::write(cwd.join("risky.ini"), b"[x]\ny=z\n").unwrap();
    let risky = Command::new(bin())
        .args([
            "discover",
            &s(&anchor.join("risky.exe")),
            "--strict",
            "--output",
            "json",
        ])
        .current_dir(&cwd)
        .output()
        .expect("failed to launch regx from the risky working directory");
    assert_eq!(code(&risky), PARTIAL, "stderr: {}", stderr(&risky));
    let report: serde_json::Value = serde_json::from_str(&stdout(&risky)).unwrap();
    let hit = report["found"]
        .as_array()
        .unwrap()
        .iter()
        .find(|hit| hit["origin"] == "current directory")
        .expect("current-directory hit");
    assert_eq!(hit["risks"], serde_json::json!(["CurrentDirectory"]));
    assert_eq!(hit["riskDetails"][0]["kind"], "CurrentDirectory");
    assert!(hit["riskDetails"][0]["explanation"]
        .as_str()
        .unwrap()
        .contains("working directory"));
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

#[test]
fn every_mutation_is_logged_and_the_chain_verifies() {
    if skip_if_hkcu_not_writable("live audit chain contract") {
        return;
    }
    let key = LiveKey::new("audit");
    let sc = Scratch::new("audit");
    let log = sc.path("audit.jsonl");

    for args in [
        vec!["set", key.as_str(), "-v", "Channel", "-d", "stable", "-y"],
        vec!["set", key.as_str(), "-v", "Channel", "-d", "beta", "-y"],
        vec!["delete", key.as_str(), "-v", "Channel", "-y"],
    ] {
        let mut full = args.clone();
        full.push("--audit-log");
        let l = s(&log);
        full.push(&l);
        assert_eq!(code(&run(&full)), OK, "{}", stderr(&run(&full)));
    }

    let text = std::fs::read_to_string(&log).unwrap();
    assert!(text.contains("\"event\": \"key.create\""), "{text}");
    assert!(text.contains("\"event\": \"value.set\""), "{text}");
    assert!(text.contains("\"event\": \"value.delete\""), "{text}");
    // The prior value must be recorded, not just the new one.
    assert!(
        text.contains("stable"),
        "the replaced value was not recorded: {text}"
    );

    let v = run(&["audit", &s(&log)]);
    assert_eq!(code(&v), OK, "{}", stdout(&v));
    assert!(stdout(&v).contains("Chain intact"), "{}", stdout(&v));
}

#[test]
fn tampering_with_the_log_is_detected() {
    let key = LiveKey::new("audittamper");
    let sc = Scratch::new("audittamper");
    let log = sc.path("audit.jsonl");

    run(&[
        "set",
        key.as_str(),
        "-v",
        "Channel",
        "-d",
        "stable",
        "-y",
        "--audit-log",
        &s(&log),
    ]);
    assert_eq!(code(&run(&["audit", &s(&log)])), OK);

    // Bytes only: no re-encoding, so this is the tamper and nothing else.
    let bytes = std::fs::read(&log).unwrap();
    std::fs::write(
        &log,
        String::from_utf8(bytes)
            .unwrap()
            .replace("stable", "PWNED!"),
    )
    .unwrap();

    let v = run(&["audit", &s(&log)]);
    assert_eq!(code(&v), PARTIAL, "an edited log must not verify");
    assert!(stdout(&v).contains("CHAIN BROKEN"), "{}", stdout(&v));
}

#[test]
fn detached_audit_anchor_detects_valid_tail_growth() {
    let d = Scratch::new("audit-anchor");
    let log = d.path("audit.jsonl");
    let anchor = d.path("audit.anchor");
    let hive = d.path("audit.hiv");
    let write_record = |value: &str, create: bool| {
        let command = format!("set Software\\Anchor -v Channel -d {value}");
        let mut args = vec!["hive", hive.to_str().unwrap()];
        if create {
            args.push("--create");
        }
        args.push("-y");
        args.extend(["exec", "-c", &command, "--audit-log", log.to_str().unwrap()]);
        run(&args)
    };
    let first = write_record("stable", true);
    assert_eq!(code(&first), OK, "{}", stderr(&first));

    let preview_anchor = d.path("preview.anchor");
    let preview = run(&[
        "audit",
        &s(&log),
        "--write-anchor",
        &s(&preview_anchor),
        "--dry-run",
        "--output",
        "json",
    ]);
    assert_eq!(code(&preview), OK, "{}", stderr(&preview));
    let preview_json: serde_json::Value =
        serde_json::from_slice(&preview.stdout).expect("anchor preview JSON");
    assert!(preview_json["anchorBytes"].is_null());
    assert!(preview_json["anchorSha256"].is_null());
    assert!(!preview_anchor.exists());

    let written = run(&[
        "audit",
        &s(&log),
        "--write-anchor",
        &s(&anchor),
        "--output",
        "json",
    ]);
    assert_eq!(code(&written), OK, "{}", stderr(&written));
    assert!(anchor.is_file());
    let written_json: serde_json::Value =
        serde_json::from_slice(&written.stdout).expect("written anchor JSON");
    assert_eq!(written_json["written"], true);
    assert_eq!(
        written_json["anchorBytes"].as_u64().unwrap(),
        std::fs::metadata(&anchor).unwrap().len()
    );
    assert_eq!(written_json["anchorSha256"].as_str().unwrap().len(), 64);

    let verified = run(&[
        "audit",
        &s(&log),
        "--verify-anchor",
        &s(&anchor),
        "--output",
        "json",
    ]);
    assert_eq!(code(&verified), OK, "{}", stdout(&verified));
    assert!(stdout(&verified).contains("\"anchorMatches\":true"));

    let second = write_record("beta", false);
    assert_eq!(code(&second), OK, "{}", stderr(&second));
    let stale = run(&[
        "audit",
        &s(&log),
        "--verify-anchor",
        &s(&anchor),
        "--output",
        "json",
    ]);
    assert_eq!(code(&stale), PARTIAL, "{}", stdout(&stale));
    assert!(stdout(&stale).contains("\"chainIntact\":true"));
    assert!(stdout(&stale).contains("\"anchorMatches\":false"));
}

#[test]
fn signed_audit_anchor_requires_the_same_secret_key() {
    let d = Scratch::new("signed-audit-anchor");
    let log = d.path("audit.jsonl");
    let anchor = d.path("audit.anchor");
    let key = d.path("anchor.key");
    let wrong = d.path("wrong.key");
    let hive = d.path("audit.hiv");
    std::fs::write(&key, [0x41u8; 32]).unwrap();
    std::fs::write(&wrong, [0x42u8; 32]).unwrap();
    let seeded = run(&[
        "hive",
        &s(&hive),
        "--create",
        "-y",
        "exec",
        "-c",
        "set Software\\Anchor -v Channel -d stable",
        "--audit-log",
        &s(&log),
    ]);
    assert_eq!(code(&seeded), OK, "{}", stderr(&seeded));

    let written = run(&[
        "audit",
        &s(&log),
        "--write-anchor",
        &s(&anchor),
        "--anchor-key",
        &s(&key),
        "--output",
        "json",
    ]);
    assert_eq!(code(&written), OK, "{}", stderr(&written));
    assert!(stdout(&written).contains("\"signed\":true"));
    assert!(std::fs::read_to_string(&anchor)
        .unwrap()
        .starts_with("regx-audit-anchor-v2\n"));

    let verified = run(&[
        "audit",
        &s(&log),
        "--verify-anchor",
        &s(&anchor),
        "--anchor-key",
        &s(&key),
        "--output",
        "json",
    ]);
    assert_eq!(code(&verified), OK, "{}", stderr(&verified));
    assert!(stdout(&verified).contains("\"signatureValid\":true"));

    let wrong_key = run(&[
        "audit",
        &s(&log),
        "--verify-anchor",
        &s(&anchor),
        "--anchor-key",
        &s(&wrong),
    ]);
    assert_eq!(code(&wrong_key), PARTIAL, "{}", stderr(&wrong_key));
    assert!(stderr(&wrong_key).contains("authentication failed"));

    let missing_key = run(&["audit", &s(&log), "--verify-anchor", &s(&anchor)]);
    assert_eq!(code(&missing_key), USAGE, "{}", stderr(&missing_key));
}

#[test]
fn audit_rotation_links_segments_and_detects_reorder_or_tampering() {
    let d = Scratch::new("audit-rotation");
    let active = d.path("active.jsonl");
    let archive = d.path("archive-001.jsonl");
    let make_record = |name: &str| {
        run(&[
            "set",
            "HKCU\\Software\\regx-it-audit-rotation",
            "-v",
            name,
            "-d",
            "value",
            "--redirect",
            "off",
            "--dry-run",
            "--audit-log",
            &s(&active),
            "-y",
        ])
    };
    let first = make_record("First");
    assert!(matches!(code(&first), OK | ACCESS_DENIED));
    assert!(active.exists());

    let preview_archive = d.path("preview.jsonl");
    let preview = run(&[
        "audit",
        &s(&active),
        "--rotate-to",
        &s(&preview_archive),
        "--dry-run",
        "--output",
        "json",
    ]);
    assert_eq!(code(&preview), OK, "{}", stderr(&preview));
    let preview_json: serde_json::Value =
        serde_json::from_slice(&preview.stdout).expect("rotation preview JSON");
    assert!(preview_json["archiveBytes"].is_null());
    assert!(preview_json["archiveSha256"].is_null());
    assert!(!preview_archive.exists());

    let rotated = run(&[
        "audit",
        &s(&active),
        "--rotate-to",
        &s(&archive),
        "--output",
        "json",
    ]);
    assert_eq!(code(&rotated), OK, "{}", stderr(&rotated));
    assert!(archive.exists());
    let rotated_json: serde_json::Value =
        serde_json::from_slice(&rotated.stdout).expect("rotation result JSON");
    assert_eq!(rotated_json["rotated"], true);
    assert_eq!(
        rotated_json["archiveBytes"].as_u64().unwrap(),
        std::fs::metadata(&archive).unwrap().len()
    );
    assert_eq!(rotated_json["archiveSha256"].as_str().unwrap().len(), 64);

    let second = make_record("Second");
    assert!(matches!(code(&second), OK | ACCESS_DENIED));
    let chain = run(&[
        "audit",
        &s(&archive),
        "--chain",
        &s(&active),
        "--output",
        "json",
    ]);
    assert_eq!(code(&chain), OK, "{}", stderr(&chain));
    assert!(stdout(&chain).contains("\"intact\":true"));

    let reversed = run(&["audit", &s(&active), "--chain", &s(&archive)]);
    assert_eq!(code(&reversed), PARTIAL);

    let text = std::fs::read_to_string(&archive).unwrap();
    std::fs::write(&archive, text.replace("First", "Edited")).unwrap();
    let tampered = run(&["audit", &s(&archive), "--chain", &s(&active)]);
    assert_eq!(code(&tampered), PARTIAL);
}

#[test]
fn redaction_keeps_the_secret_out_of_the_log_entirely() {
    if skip_if_hkcu_not_writable("live audit redaction contract") {
        return;
    }
    let key = LiveKey::new("auditredact");
    let sc = Scratch::new("auditredact");
    let log = sc.path("audit.jsonl");
    let secret = "SECRET-LICENCE-9Q4Z";

    let o = run(&[
        "set",
        key.as_str(),
        "-v",
        "Licence",
        "-d",
        secret,
        "-y",
        "--audit-log",
        &s(&log),
        "--audit-redact",
    ]);
    assert_eq!(code(&o), OK, "{}", stderr(&o));

    let text = std::fs::read_to_string(&log).unwrap();
    // The value is redacted, and so is the command line that carried it —
    // the session header is where this leaked before.
    assert!(
        !text.contains(secret),
        "the secret leaked into the log:\n{text}"
    );
    assert!(text.contains("sha256"), "no digest recorded: {text}");
    assert!(
        text.contains("<redacted:"),
        "the command line was not redacted: {text}"
    );
    // Redaction must not cost the audit its usefulness.
    assert!(text.contains("Licence"), "the value name was lost: {text}");
    assert_eq!(code(&run(&["audit", &s(&log)])), OK);
}

#[test]
fn a_dry_run_is_logged_as_simulated_and_changes_nothing() {
    if skip_if_hkcu_not_writable("audited live dry-run contract") {
        return;
    }
    let key = LiveKey::new("auditdry");
    let sc = Scratch::new("auditdry");
    let log = sc.path("audit.jsonl");

    let o = run(&[
        "set",
        key.as_str(),
        "-v",
        "x",
        "-d",
        "y",
        "-y",
        "--dry-run",
        "--audit-log",
        &s(&log),
    ]);
    assert_eq!(code(&o), OK);

    let text = std::fs::read_to_string(&log).unwrap();
    assert!(text.contains("\"outcome\": \"simulated\""), "{text}");
    assert_eq!(
        code(&run(&["query", key.as_str()])),
        NOT_FOUND,
        "--dry-run wrote to the registry despite logging"
    );
}

#[test]
fn the_audit_log_can_be_enforced_through_the_environment() {
    if skip_if_hkcu_not_writable("environment-enforced live audit contract") {
        return;
    }
    let key = LiveKey::new("auditenv");
    let sc = Scratch::new("auditenv");
    let log = sc.path("audit.jsonl");

    // A machine-wide policy sets REGX_AUDIT_LOG; individual invocations must
    // not have to remember the flag for the trail to exist.
    let o = Command::new(bin())
        .args(["set", key.as_str(), "-v", "x", "-d", "y", "-y"])
        .env("REGX_AUDIT_LOG", &log)
        .output()
        .expect("failed to launch regx");
    assert_eq!(code(&o), OK, "{}", stderr(&o));
    assert!(log.exists(), "REGX_AUDIT_LOG was ignored");
    assert_eq!(code(&run(&["audit", &s(&log)])), OK);
}

// ---------------------------------------------------------------------------
// Administrative policy
// ---------------------------------------------------------------------------

#[test]
fn self_check_states_whether_a_policy_applies() {
    let o = run(&["--self-check"]);
    let text = stdout(&o);
    assert!(
        text.contains("administration"),
        "--self-check must say what an administrator has imposed:\n{text}"
    );
    // On a machine with none configured it has to say so plainly, rather than
    // leaving silence to be read as "no restrictions" or as "not checked".
    assert!(
        text.contains("no administrative policy") || text.contains("Policies\\regx"),
        "{text}"
    );
}

#[test]
fn the_shipped_admx_is_readable_by_regx_itself() {
    // The template an administrator deploys is parsed by the same reader used
    // for anyone else's ADMX, so a mistake in it surfaces here rather than in
    // the Group Policy editor.
    let admx = Path::new("policy/regx.admx");
    if !admx.exists() {
        return; // running from somewhere other than the repository root
    }

    let o = run(&["inspect", &s(admx)]);
    assert_eq!(code(&o), PARTIAL, "{}", stderr(&o));
    let text = stdout(&o) + &stderr(&o);

    assert!(text.contains("admx"), "not detected as ADMX:\n{text}");
    assert!(
        text.contains("6 of 6 policy definition"),
        "every setting should be declared:\n{text}"
    );
    // The ADML must be found and resolve the display names, or the editor
    // shows raw $(string.Id) tokens.
    assert!(
        text.contains("display string(s) resolved"),
        "the en-US ADML was not found:\n{text}"
    );
    // Everything lands under the machine policy key, which is the point.
    assert!(text.contains("HKEY_LOCAL_MACHINE"), "{text}");
    for configured in ["AuditLog", "MinConfidence", "DenyKeys"] {
        assert!(
            text.contains(configured),
            "administrator-supplied {configured} was not exposed as a fidelity loss:\n{text}"
        );
    }
}

#[test]
fn version_reports_build_provenance() {
    let o = run(&["--version"]);
    let text = stdout(&o);
    for field in ["commit:", "date:", "target:", "source:"] {
        assert!(
            text.contains(field),
            "--version is missing {field}:\n{text}"
        );
    }
}

#[test]
fn self_check_reports_the_elevation_state_correctly() {
    let o = run(&["--self-check"]);
    // Exit is OK or PARTIAL depending on the host's policy configuration.
    assert!(code(&o) == OK || code(&o) == PARTIAL, "exit {}", code(&o));
    let text = stdout(&o);
    assert!(text.contains("elevation"), "{text}");

    // Whichever way the host is configured, --self-check has to say so
    // accurately: reporting an elevated process as unelevated would be worse
    // than the elevation itself, because the operator would trust it.
    if elevated() {
        assert!(
            text.contains("ELEVATED"),
            "an elevated host must be reported as such:\n{text}"
        );
    } else {
        assert!(
            text.contains("not elevated"),
            "a standard-user host must be reported as such:\n{text}"
        );
    }
}

#[test]
fn completions_cover_every_supported_shell_without_registry_access() {
    for shell in ["bash", "elvish", "fish", "powershell", "zsh"] {
        let o = run(&["completions", shell]);
        assert_eq!(code(&o), OK, "{shell}: {}", stderr(&o));
        let text = stdout(&o);
        assert!(
            text.contains("regx") && text.contains("completions"),
            "{shell} completion is incomplete:\n{text}"
        );
        assert!(
            text.contains("apply-copy-plan") && text.contains("permissions"),
            "{shell} completion omitted shipped commands:\n{text}"
        );
    }
}
