use std::path::PathBuf;

fn main() {
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
