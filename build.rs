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
    // `.git/refs/heads/main` was insufficient: a build on any other branch
    // could keep an old embedded SHA after a commit, and linked worktrees use a
    // `.git` pointer file rather than a directory. Ask Git for its real paths.
    let mut watched = Vec::new();
    if let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) {
        watched.push(head);
    }
    if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"]) {
        if let Some(path) = git(&["rev-parse", "--git-path", &reference]) {
            watched.push(path);
        }
    }
    if let Some(packed) = git(&["rev-parse", "--git-path", "packed-refs"]) {
        watched.push(packed);
    }
    watched.sort();
    watched.dedup();
    for path in watched {
        println!("cargo:rerun-if-changed={}", PathBuf::from(path).display());
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

    // LINK otherwise assigns a fresh GUID to the embedded RSDS/PDB record on
    // every clean build. `/Brepro` derives it from build content, making two
    // independent builds of the same source byte-for-byte identical.
    println!("cargo:rustc-link-arg-bins=/Brepro");

    // MSVC's default PE stack reserve is 1 MiB. Clap constructs the complete
    // command graph on the main thread; with the format/search option surface
    // that crossed the reserve before `main` could dispatch even a trivial
    // command. Reserving 8 MiB costs virtual address space, not 8 MiB of
    // committed memory, and matches Rust's ordinary spawned-thread stack.
    println!("cargo:rustc-link-arg-bins=/STACK:8388608");
}
