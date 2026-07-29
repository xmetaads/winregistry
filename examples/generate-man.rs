//! Generate the complete `regx` section-1 manual without adding a generator
//! dependency to the shipped executable.
//!
//! Usage:
//!   cargo run --example generate-man -- target/man

#[allow(dead_code)]
#[path = "../src/cli.rs"]
mod cli;

use clap::CommandFactory as _;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let out = args
        .next()
        .ok_or("output directory required; try `cargo run --example generate-man -- target/man`")?;
    if args.next().is_some() {
        return Err("expected exactly one output directory".into());
    }

    let result = std::thread::Builder::new()
        .name("regx-man-generator".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            std::fs::create_dir_all(&out).map_err(|error| error.to_string())?;
            clap_mangen::generate_to(cli::Cli::command(), &out).map_err(|error| error.to_string())
        })?
        .join()
        .map_err(|_| "man-page generator thread panicked")?;
    result.map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
    Ok(())
}
