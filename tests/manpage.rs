//! Contract tests for the generated Unix manual.

#[allow(dead_code)]
#[path = "../src/cli.rs"]
mod cli;

use clap::CommandFactory as _;
use std::path::PathBuf;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("regx-man-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create manpage scratch directory");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn generated_manual_covers_the_root_and_every_subcommand() {
    std::thread::Builder::new()
        .name("regx-man-contract".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(assert_generated_manual)
        .expect("spawn manpage contract thread")
        .join()
        .expect("manpage contract thread panicked");
}

fn assert_generated_manual() {
    let scratch = Scratch::new();
    clap_mangen::generate_to(cli::Cli::command(), &scratch.0).expect("generate man pages");

    let root = std::fs::read_to_string(scratch.0.join("regx.1")).expect("root manual");
    assert!(root.contains(".TH regx 1"));
    assert!(root.contains("Portable, non\\-admin Windows Registry CLI"));

    let command = cli::Cli::command();
    let subcommands: Vec<_> = command
        .get_subcommands()
        .map(|subcommand| subcommand.get_name().to_owned())
        .collect();
    assert_eq!(subcommands.len(), 34, "top-level command inventory drifted");

    for name in subcommands {
        let file = scratch.0.join(format!("regx-{name}.1"));
        let contents = std::fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("{}: {error}", file.display()));
        assert!(
            contents.contains(&format!(".TH regx-{name} 1")),
            "{} has the wrong title",
            file.display()
        );
    }
}
