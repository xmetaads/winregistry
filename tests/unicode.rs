//! Non-ASCII correctness.
//!
//! Registry keys and values hold whatever the user's language produces, and a
//! tool that mangles them is unusable outside an English-speaking office no
//! matter what else it does. These drive the built binary with Vietnamese,
//! CJK, Cyrillic, Greek, right-to-left Arabic and astral-plane text, through
//! every input format and through the live registry.
//!
//! The registry stores UTF-16; `.reg` version 5.00 is UTF-16LE; JSON, CSV and
//! INI are read as UTF-8. Every one of those boundaries is a place text can be
//! lost, and each is crossed at least once below.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const OK: i32 = 0;
const NOT_FOUND: i32 = 8;

/// Scripts chosen for what each one breaks:
/// - Vietnamese: stacked diacritics, and the language of this project
/// - CJK: outside the Basic Latin plane, common in enterprise Asia
/// - Cyrillic/Greek: letters that look like Latin but are not
/// - Arabic: right-to-left, which reorders on display but not in storage
/// - Astral: a surrogate pair in UTF-16, the classic off-by-one
const SAMPLES: &[(&str, &str)] = &[
    ("vietnamese", "Phần Mềm Ứng Dụng"),
    ("chinese", "软件设置"),
    ("japanese", "アプリケーション設定"),
    ("korean", "응용프로그램"),
    ("cyrillic", "Программа"),
    ("greek", "Εφαρμογή"),
    ("arabic", "إعدادات"),
    ("astral", "𝕊𝕠𝕗𝕥𝕨𝕒𝕣𝕖"),
    ("mixed", "Cấu hình 设置 Настройки"),
];

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_regx"))
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to launch regx")
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("terminated by signal")
}

/// stdout decoded as UTF-8. The manifest sets activeCodePage=UTF-8, so the
/// process emits UTF-8 regardless of the machine's ANSI codepage — that is
/// precisely what is being checked.
fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let d = std::env::temp_dir().join(format!("regx-uni-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Scratch(d)
    }
    fn path(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct LiveKey(String);

impl LiveKey {
    fn new(name: &str) -> LiveKey {
        let k = format!("HKCU\\Software\\regx-uni-{name}");
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

// ---------------------------------------------------------------------------

#[test]
fn non_ascii_values_survive_the_live_registry() {
    for (label, text) in SAMPLES {
        let key = LiveKey::new(label);

        let o = run(&["set", key.as_str(), "-v", "Name", "-d", text, "-y"]);
        assert_eq!(code(&o), OK, "{label}: {}", stderr(&o));

        let q = run(&["query", key.as_str()]);
        assert_eq!(code(&q), OK, "{label}: {}", stderr(&q));
        assert!(
            stdout(&q).contains(text),
            "{label}: {text:?} did not survive a set/query round trip.\n{}",
            stdout(&q)
        );
    }
}

#[test]
fn non_ascii_key_names_survive_the_live_registry() {
    for (label, text) in SAMPLES {
        let base = LiveKey::new(label);
        let nested = format!("{}\\{text}", base.as_str());

        let o = run(&["set", &nested, "-v", "x", "-d", "1", "-y"]);
        assert_eq!(code(&o), OK, "{label}: {}", stderr(&o));

        let q = run(&["query", base.as_str(), "-r"]);
        assert_eq!(code(&q), OK, "{label}: {}", stderr(&q));
        assert!(
            stdout(&q).contains(text),
            "{label}: the key name {text:?} was lost.\n{}",
            stdout(&q)
        );
    }
}

#[test]
fn non_ascii_survives_a_reg_export_and_reimport() {
    let sc = Scratch::new("regfile");
    for (label, text) in SAMPLES {
        let key = LiveKey::new(&format!("reg-{label}"));
        run(&["set", key.as_str(), "-v", text, "-d", text, "-y"]);

        let exported = sc.path(&format!("{label}.reg"));
        assert_eq!(
            code(&run(&["export", key.as_str(), "-o", &s(&exported)])),
            OK,
            "{label}"
        );

        // A version 5.00 file is UTF-16LE with a BOM; the text must be there
        // in that encoding, not mangled through the ANSI codepage.
        let bytes = std::fs::read(&exported).unwrap();
        assert_eq!(
            &bytes[..2],
            &[0xFF, 0xFE],
            "{label}: not UTF-16LE with a BOM"
        );
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let decoded = String::from_utf16(&units).expect("export is not valid UTF-16");
        assert!(
            decoded.contains(text),
            "{label}: {text:?} is not in the exported file"
        );

        // Remove it, re-import, and confirm it comes back identical.
        run(&["delete", key.as_str(), "-r", "-y"]);
        assert_eq!(
            code(&run(&["import", &s(&exported), "-y", "--no-backup"])),
            OK,
            "{label}"
        );
        let q = run(&["query", key.as_str()]);
        assert!(stdout(&q).contains(text), "{label}: lost on re-import");
    }
}

#[test]
fn non_ascii_survives_every_text_format() {
    let sc = Scratch::new("formats");
    let text = "Cấu hình 设置 Настройки";

    // Each format's own escaping rules applied to the same string.
    let cases: &[(&str, String)] = &[
        (
            "a.ini",
            format!("[HKEY_CURRENT_USER\\Software\\regx-uni-fmt]\nName = {text}\n"),
        ),
        (
            "a.csv",
            format!("key,name,type,data\nHKCU\\Software\\regx-uni-fmt,Name,REG_SZ,\"{text}\"\n"),
        ),
        (
            "a.json",
            format!("{{\"HKCU\\\\Software\\\\regx-uni-fmt\": {{\"Name\": \"{text}\"}}}}"),
        ),
        (
            "a.inf",
            format!(
                "[Version]\nSignature=\"$WINDOWS NT$\"\n[I]\nAddReg=R\n[R]\n\
                 HKCU,\"Software\\regx-uni-fmt\",\"Name\",0x0,\"{text}\"\n"
            ),
        ),
    ];

    for (file, body) in cases {
        let p = sc.path(file);
        // Written as UTF-8, which is what each of these formats is read as.
        std::fs::write(&p, body.as_bytes()).unwrap();

        let o = run(&[
            "convert",
            &s(&p),
            "--redirect",
            "off",
            "--log-level",
            "error",
        ]);
        assert_eq!(code(&o), OK, "{file}: {}", stderr(&o));
        assert!(
            stdout(&o).contains(text),
            "{file}: {text:?} was lost in conversion.\n{}",
            stdout(&o)
        );
    }
}

#[test]
fn non_ascii_reaches_the_audit_log_intact() {
    let sc = Scratch::new("audit");
    let key = LiveKey::new("audit");
    let log = sc.path("audit.jsonl");
    let text = "Phần Mềm 软件";

    let o = run(&[
        "set",
        key.as_str(),
        "-v",
        "Tên",
        "-d",
        text,
        "-y",
        "--audit-log",
        &s(&log),
    ]);
    assert_eq!(code(&o), OK, "{}", stderr(&o));

    // The log is UTF-8 JSON; non-ASCII is written literally rather than
    // \u-escaped, so it must survive as-is.
    let recorded = std::fs::read_to_string(&log).unwrap();
    assert!(
        recorded.contains(text),
        "the value was mangled:\n{recorded}"
    );
    assert!(recorded.contains("Tên"), "the value name was mangled");

    // And the chain must still verify: the hash covers the UTF-8 bytes, so a
    // re-encoding anywhere would break it.
    let v = run(&["audit", &s(&log)]);
    assert_eq!(code(&v), OK, "{}", stdout(&v));
    assert!(stdout(&v).contains("Chain intact"), "{}", stdout(&v));
}

#[test]
fn case_insensitive_matching_holds_for_non_ascii() {
    // The registry is case-insensitive, and so is regx's own folding. For a
    // diff, that means the same key in different case must compare equal —
    // including for scripts where case exists outside ASCII.
    let sc = Scratch::new("case");
    let a = sc.path("a.reg");
    let b = sc.path("b.reg");

    let write = |p: &Path, key: &str, value: &str| {
        let text = format!(
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\{key}]\r\n\"{value}\"=\"x\"\r\n"
        );
        let mut bytes = vec![0xFF, 0xFE];
        for u in text.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        std::fs::write(p, bytes).unwrap();
    };

    // Cyrillic and Greek both have well-defined upper/lower mappings.
    write(&a, "Программа", "Значение");
    write(&b, "ПРОГРАММА", "ЗНАЧЕНИЕ");

    let d = run(&["diff", &s(&a), &s(&b), "--log-level", "error"]);
    assert_eq!(code(&d), OK, "{}", stderr(&d));
    assert!(
        stdout(&d).contains("No differences"),
        "case-only differences must not register as a change:\n{}",
        stdout(&d)
    );
}

#[test]
fn a_non_ascii_key_can_be_deleted_by_a_differently_cased_name() {
    let key = LiveKey::new("delcase");
    let base = key.as_str().to_string();
    let sub = format!("{base}\\Программа");

    assert_eq!(code(&run(&["set", &sub, "-v", "x", "-d", "1", "-y"])), OK);

    // Windows resolves the key case-insensitively; so must we.
    let upper = format!("{base}\\ПРОГРАММА");
    assert_eq!(
        code(&run(&["delete", &upper, "-r", "-y"])),
        OK,
        "an upper-cased path should reach the same key"
    );
    assert_eq!(code(&run(&["query", &sub])), NOT_FOUND);
}

#[test]
fn expanding_case_mappings_do_not_merge_distinct_keys() {
    // Windows uppercases a registry path one character at a time, so a mapping
    // that would expand — ß to SS, the ﬁ ligature to FI — is not applied, and
    // these are two different keys. Folding with `str::to_uppercase` made regx
    // treat them as one and silently discard a key's values.
    //
    // The live registry is the authority here, so it is asked directly.
    let key = LiveKey::new("fold");
    let lower = format!("{}\\straße", key.as_str());
    let upper = format!("{}\\STRASSE", key.as_str());

    assert_eq!(
        code(&run(&["set", &lower, "-v", "mark", "-d", "LOWER", "-y"])),
        OK
    );
    assert_eq!(
        code(&run(&["set", &upper, "-v", "mark", "-d", "UPPER", "-y"])),
        OK
    );

    let q = run(&["query", key.as_str(), "-r"]);
    let text = stdout(&q);
    assert!(
        text.contains("LOWER") && text.contains("UPPER"),
        "Windows keeps both keys; regx must report both:\n{text}"
    );

    // And exporting then re-reading must preserve both, rather than coalescing
    // them on the way through.
    let sc = Scratch::new("fold");
    let out = sc.path("both.reg");
    assert_eq!(code(&run(&["export", key.as_str(), "-o", &s(&out)])), OK);

    let c = run(&[
        "convert",
        &s(&out),
        "--redirect",
        "off",
        "--log-level",
        "error",
    ]);
    let converted = stdout(&c);
    assert!(
        converted.contains("LOWER") && converted.contains("UPPER"),
        "a round trip through .reg merged two distinct keys:\n{converted}"
    );
}

#[test]
fn astral_plane_text_is_not_truncated_at_the_surrogate() {
    // A character outside the BMP is two UTF-16 units. Any code that counts
    // characters where it should count units, or vice versa, loses half of it.
    let key = LiveKey::new("astral");
    let text = "𝕊𝕠𝕗𝕥𝕨𝕒𝕣𝕖 𝟚𝟘𝟚𝟞";

    assert_eq!(
        code(&run(&["set", key.as_str(), "-v", "Name", "-d", text, "-y"])),
        OK
    );
    let q = run(&["query", key.as_str()]);
    assert!(stdout(&q).contains(text), "{}", stdout(&q));

    // The same, through a REG_MULTI_SZ, where the terminator logic counts units.
    assert_eq!(
        code(&run(&[
            "set",
            key.as_str(),
            "-v",
            "List",
            "-t",
            "REG_MULTI_SZ",
            "-d",
            "𝕒\\0𝕓",
            "-y"
        ])),
        OK
    );
    let q = run(&["query", key.as_str()]);
    assert!(
        stdout(&q).contains('𝕒') && stdout(&q).contains('𝕓'),
        "{}",
        stdout(&q)
    );
}

#[test]
fn json_output_escapes_non_ascii_without_losing_it() {
    let key = LiveKey::new("json");
    let text = "Cấu hình 设置";
    run(&["set", key.as_str(), "-v", "Name", "-d", text, "-y"]);

    let o = run(&["query", key.as_str(), "--output", "json"]);
    let text_out = stdout(&o);
    assert_eq!(code(&o), OK);
    // The emitter only escapes what JSON requires; anything above U+001F is
    // written literally, so the output stays readable in any editor.
    assert!(
        text_out.contains(text),
        "non-ASCII was escaped or lost in JSON output:\n{text_out}"
    );
}
