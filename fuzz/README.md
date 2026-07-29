# Parser fuzzing

Three libFuzzer targets exercise parser code directly:

- `reg_bytes`: arbitrary bytes through BOM/encoding detection and the `.reg`
  state machine.
- `xml_bytes`: arbitrary UTF-8/lossy-UTF-8 through the bounded XML parser.
- `all_formats`: a selector byte routes the remaining bytes through forced
  `.reg`, PReg, JSON, CSV, INF, INI, ADMX, or GPP parsing. PReg inputs receive a
  valid fixed header so mutations reach record length and directive handling.

The checked-in corpus contains one valid seed per family/dialect. Run locally:

```text
cargo test --manifest-path fuzz/Cargo.toml --test seed_corpus
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked --version 0.13.2
cargo +nightly fuzz run --features fuzzing reg_bytes fuzz/corpus/reg_bytes
cargo +nightly fuzz run --features fuzzing xml_bytes fuzz/corpus/xml_bytes
cargo +nightly fuzz run --features fuzzing all_formats fuzz/corpus/all_formats
```

The first command also runs a deterministic 10,000-case mutation smoke through
all three entry points. It detects ordinary panics but is not a substitute for
coverage-guided libFuzzer with a sanitizer.

On Windows, install Visual Studio's **C++ AddressSanitizer** component and use a
Developer PowerShell so `clang_rt.asan_dynamic-x86_64.dll` is on `PATH`. The
GitHub smoke workflow is configured to run all targets on Linux with
AddressSanitizer, 10,000 executions each, on parser changes and weekly.

Crashes are written below `fuzz/artifacts/` and must be converted into a
permanent regression test before the corpus artifact is removed.
