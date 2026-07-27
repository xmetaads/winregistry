use std::path::PathBuf;
use std::process::Command;

/// Record where this binary came from, so `regx --version` can answer the
/// question an enterprise asks about any executable it finds on a machine:
/// which source produced it?
///
/// The commit date is used rather than the wall clock deliberately — embedding
/// "now" would make two builds of the same source differ, which defeats the
/// point of a reproducible build. `SOURCE_DATE_EPOCH` overrides it if the
/// packaging system sets one.
fn provenance() {
    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git").args(args).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    };

    let commit = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let commit = if dirty {
        format!("{commit}-modified")
    } else {
        commit
    };

    let date = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .or_else(|| git(&["log", "-1", "--format=%cI"]))
        .unwrap_or_else(|| "unknown".into());

    println!("cargo:rustc-env=REGX_COMMIT={commit}");
    println!("cargo:rustc-env=REGX_COMMIT_DATE={date}");
    println!(
        "cargo:rustc-env=REGX_TARGET={}",
        std::env::var("TARGET").unwrap_or_else(|_| "unknown".into())
    );

    // Rebuild when HEAD moves so the recorded commit does not go stale.
    for p in [".git/HEAD", ".git/refs/heads/main"] {
        if PathBuf::from(p).exists() {
            println!("cargo:rerun-if-changed={p}");
        }
    }
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}

fn main() {
    provenance();

    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        return;
    }

    let manifest: PathBuf = [env!("CARGO_MANIFEST_DIR"), "app.manifest"]
        .iter()
        .collect();
    println!("cargo:rerun-if-changed=app.manifest");

    // Embed the manifest directly into the PE, keeping the "one file only"
    // constraint: no regx.exe.manifest sidecar next to the binary.
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
        manifest.display()
    );
    println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:NO");
}
