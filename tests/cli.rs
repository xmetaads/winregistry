//! Integration tests that drive the built binary.
//!
//! The unit tests inside `src/` cover the engines. These cover the *contract* —
//! exit codes, output shape, and the promise that `--dry-run` writes nothing.
//! Those are documented as stable, so a regression in them is a broken promise
//! to anyone scripting against the tool, and nothing else guards them.
//!
//! Every test that touches the live registry works under a unique subkey of
//! `HKCU\Software\regx-it-<test>` and removes it afterwards.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

// Exit codes, mirrored from src/cli.rs. Duplicated on purpose: if someone
// changes the constant, this file should fail rather than silently agree.
const OK: i32 = 0;
const USAGE: i32 = 2;
const PARSE: i32 = 3;
const ACCESS_DENIED: i32 = 4;
const PARTIAL: i32 = 5;
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
        let _ = run(&["delete", &k, "-r", "-y", "--log-level", "error"]);
        LiveKey(k)
    }
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for LiveKey {
    fn drop(&mut self) {
        let _ = run(&["delete", &self.0, "-r", "-y", "--log-level", "error"]);
    }
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
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
    // Every command must be discoverable from the top-level help.
    for cmd in [
        "import", "export", "convert", "merge", "diff", "query", "set", "delete", "sync",
        "validate", "probe", "formats", "discover", "inspect", "hive",
    ] {
        assert!(stdout(&h).contains(cmd), "`{cmd}` missing from --help");
    }
}

#[test]
fn no_command_is_a_usage_error_not_a_crash() {
    let o = run(&[]);
    assert_eq!(code(&o), 7, "no command exits via the IO path with a hint");
    assert!(stderr(&o).contains("--help"), "{}", stderr(&o));
}

#[test]
fn an_unknown_flag_exits_usage() {
    let o = run(&["query", "HKCU\\Software", "--not-a-real-flag"]);
    assert_eq!(code(&o), USAGE);
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
    let key = LiveKey::new("dryrun");
    let o = run(&["set", key.as_str(), "-v", "x", "-d", "y", "-y", "--dry-run"]);
    assert_eq!(code(&o), OK, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).contains("would"),
        "dry-run must say so: {}",
        stderr(&o)
    );

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
fn import_writes_an_undo_file_that_actually_reverts() {
    let key = LiveKey::new("undo");
    let sc = Scratch::new("undo");
    let reg = sc.write(
        "change.reg",
        &format!(
            "Windows Registry Editor Version 5.00\r\n\r\n[{}]\r\n\"a\"=\"one\"\r\n\"n\"=dword:00000005\r\n",
            key.as_str().replace("HKCU", "HKEY_CURRENT_USER")
        ),
    );

    assert_eq!(code(&run(&["import", &s(&reg), "-y"])), OK);
    assert!(stdout(&run(&["query", key.as_str()])).contains("one"));

    let undo = sc.path("change.undo.reg");
    assert!(
        undo.exists(),
        "import must write an undo snapshot beside the input"
    );

    assert_eq!(code(&run(&["import", &s(&undo), "-y", "--no-backup"])), OK);
    assert_eq!(
        code(&run(&["query", key.as_str()])),
        NOT_FOUND,
        "the undo file did not remove the key it created"
    );
}

#[test]
fn diff_reports_drift_and_its_patch_closes_it() {
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

/// Minimal structural check: balanced braces/brackets outside strings, and the
/// expected top-level keys present. Enough to catch a malformed emitter without
/// pulling in a JSON dependency for the test suite.
fn looks_like_json(text: &str) -> bool {
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    for c in text.chars() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' | '[' => depth += 1,
            '}' | ']' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0 && !in_str
}

#[test]
fn json_output_is_well_formed_for_every_command_that_offers_it() {
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
fn probe_json_reports_hklm_software_as_not_writable() {
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

    let o = run(&["validate", &s(&broken), "--fix", "-o", &s(&fixed)]);
    assert_eq!(code(&o), OK, "stderr: {}", stderr(&o));
    assert!(stdout(&o).contains("NUL terminator"), "{}", stdout(&o));
    assert!(fixed.exists());

    // The repaired file must itself validate cleanly.
    let v = run(&["validate", &s(&fixed), "--strict"]);
    assert_eq!(
        code(&v),
        OK,
        "the repaired file still warns: {}",
        stdout(&v)
    );
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
        "exec",
        "-c",
        "set Software\\MyApp -v License -d OK",
        "-c",
        "set Software\\MyApp -v Seats -t REG_DWORD -d 25",
    ]);
    assert_eq!(code(&o), OK, "stderr: {}", stderr(&o));
    assert!(hive.exists(), "the hive file was not created");

    // A fresh process must see the persisted data.
    let q = run(&["hive", &s(&hive), "query", "Software\\MyApp", "-r"]);
    assert_eq!(code(&q), OK, "stderr: {}", stderr(&q));
    assert!(stdout(&q).contains("OK"), "{}", stdout(&q));
    assert!(stdout(&q).contains("25"), "{}", stdout(&q));

    let i = run(&["hive", &s(&hive), "info"]);
    assert_eq!(code(&i), OK);
    assert!(stdout(&i).contains("regf"), "{}", stdout(&i));
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
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

#[test]
fn every_mutation_is_logged_and_the_chain_verifies() {
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
fn redaction_keeps_the_secret_out_of_the_log_entirely() {
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
fn self_check_runs_and_reports_the_process_as_unelevated() {
    let o = run(&["--self-check"]);
    // Exit is OK or PARTIAL depending on the host's policy configuration.
    assert!(code(&o) == OK || code(&o) == PARTIAL, "exit {}", code(&o));
    let text = stdout(&o);
    assert!(text.contains("elevation"), "{text}");
    assert!(
        text.contains("not elevated"),
        "the test host must not be elevated - the product targets standard users:\n{text}"
    );
}
