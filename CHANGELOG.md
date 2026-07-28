# Changelog

Notable changes to `regx`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## The CLI contract

For a tool that gets scripted, the interface *is* the API. These are treated as
public and versioned accordingly — a breaking change to any of them requires a
major version bump:

- **Exit codes.** `0` success, `2` usage, `3` parse, `4` access denied,
  `5` partial, `6` redirection refused, `7` I/O, `8` not found.
- **`--output json` shapes** for `query`, `probe`, `diff`, `inspect`,
  `discover`, `formats` and `--self-check`.
- **Command and flag names**, and the meaning of `--dry-run`: it performs every
  read, so permission problems still surface, and no write of any kind.
- **The `.reg` files written** by `export`, `convert` and the undo snapshot:
  UTF-16LE with a BOM, CRLF, byte-compatible with `regedit`'s own output.

Human-readable stdout and stderr text is *not* part of the contract. Parse the
JSON.

## [Unreleased]

### Added

- **Tamper-evident audit log.** `--audit-log FILE` (or `REGX_AUDIT_LOG`, so it
  can be enforced machine-wide) appends one JSON object per registry mutation:
  timestamp, actor SID taken from the process token rather than the settable
  `%USERNAME%`, operation, and the value before as well as after. Records are
  hash-chained, so altering or removing a line breaks the chain and
  `regx audit FILE` reports where. A `--dry-run` is recorded as `simulated`,
  and failed attempts are recorded with their error.
- `--audit-redact` records the SHA-256 and length of each value instead of the
  value, for environments where the log would otherwise become a secret.
- **`--self-check` verifies the binary's own Authenticode signature** with
  `WinVerifyTrust`, against the same trust store AppLocker consults — so its
  answer is the answer AppLocker will reach. Reports `trusted`, `untrusted`
  (with the chain reason), `unsigned` or `unknown`, each with what it means for
  AppLocker, WDAC and SmartScreen. Revocation is deliberately not checked: this
  runs on machines with no outbound access, where the lookup stalls rather than
  answers.
- `diff` compares any two sources — file to file, file to live registry, or
  live to live — and emits a `.reg` patch that turns the first into the second.
  A drift report is therefore also the fix, and the inverse patch is the
  rollback. `--exit-code` makes it usable as a deployment gate.
- `regx --version` reports the commit, its date, the target triple and the
  source URL. The commit date is used rather than the build clock so two builds
  of the same source are identical; an uncommitted tree reports `-modified`.
- `tests/cli.rs`: 31 integration tests driving the built binary, covering exit
  codes, JSON output, `--dry-run` writing nothing, undo round trips, format
  detection, the audit chain and the offline hive lifecycle.
- CI on GitHub Actions: `fmt`, `clippy -D warnings`, both suites, x64 and ARM64
  builds, assertions that the shipped binary still carries an `asInvoker`
  manifest and a static CRT, `cargo-deny` for advisories and licences, and the
  site checkers. Test failures are re-emitted as annotations, because a raw log
  needs a token to read and "exit code 1" tells an outside reader nothing.
- A release workflow producing both architectures with SHA-256 checksums, a
  CycloneDX SBOM and a GitHub build provenance attestation. Code signing is
  wired in and skips cleanly until a certificate is configured, so enabling it
  is a secrets change rather than a workflow change, and every unsigned release
  emits a warning naming the gap.
- SHA-256 implemented in-tree and validated against the NIST vectors, rather
  than adding a cryptographic dependency for the two places hashing is needed.
- `docs/SIGNING.md`, `SECURITY.md`, `CONTRIBUTING.md`, `deny.toml`,
  `rust-toolchain.toml`, and `scripts/check_site.py` / `check_vercel.py` moved
  into the repository so CI runs what a developer runs.

### Fixed

- **`--audit-redact` leaked the secret it exists to hide.** Values were
  redacted; the command line recorded in the session header was not, so
  `regx set … -d SECRET` wrote the secret straight into the log. A redacted log
  that still contains the secret is worse than none, because it is trusted.
  Found by exercising the feature end to end, not by its unit tests.
- **A malformed input file exited `7` instead of the documented `3`.** Routing
  the readers through the shared format layer collapsed every reader failure
  into the generic I/O path, silently breaking the exit-code contract. Found by
  the new integration suite on its first run — which is why it exists.
- **`RUSTFLAGS` in the CI environment was unlinking the static CRT.** The
  environment variable replaces `rustflags` from `.cargo/config.toml` rather
  than adding to it, so `-D warnings` silently dropped `+crt-static` and
  produced binaries needing the VC++ redistributable. The release step now
  asserts the static link instead of assuming it.
- **The documentation claimed ARM64 support that had never been built.** The
  claim is now limited to what CI verifies: it compiles and links, and has not
  been run on ARM64 hardware.
- The first SHA-256 implementation hung. The buffering path overwrote the
  partial-block length when input ran out mid-block, so the padding loop never
  terminated; the streaming-versus-one-shot test at ten split points pins it.
- The audit verifier reported a UTF-8 BOM as tampering. A log that has been
  through a Windows editor or a PowerShell redirect commonly gains one, and a
  false accusation is the worst possible failure for this file.
- Registry paths were printed with a doubled separator (`Software\\Name`) in
  conflict, failure and diff output, from an over-escaped format string.
- Stale figures on the site: the advertised binary size and test count were
  several releases out of date.

### Changed

- Assertions about the *environment* rather than the code — that an HKLM write
  is refused, that System32 is not writable — now check the elevation state
  first and say plainly when they could not be exercised. They are only
  meaningful for a standard user, and GitHub's `windows-latest` runs elevated.
- `rust-toolchain.toml` pins an exact compiler version rather than `stable`, so
  CI cannot drift onto a different lint set than developers run.
- The whole tree is now `rustfmt`-clean and passes `clippy -D warnings`; it had
  never been formatted.

## [0.1.0]

First working version.

### Core

- `.reg` parser and writer with byte-exact round-tripping. Values that cannot be
  modelled losslessly stay raw `hex(N)`; a `REG_SZ` is only written as a quoted
  string when it is clean UTF-16, because a raw newline corrupts the next line.
- Both dialects: UTF-16LE `Version 5.00` and ANSI `REGEDIT4`, the latter decoded
  through `MultiByteToWideChar(CP_ACP)` to match `regedit`.
- A Win32 wrapper where the WOW64 view is always explicit, so behaviour never
  depends on how the binary was built.

### Smart Redirection

- Maps `HKLM`/`HKCR` paths to their per-user equivalent, grading each mapping by
  confidence and refusing those that would write cleanly and change nothing:
  machine policies wiped by Group Policy refresh, `SYSTEM` subtrees, and
  hash-protected `UserChoice`.

### Offline hives

- `RegLoadAppKey` mounts a hive file without `SeRestorePrivilege`. The handle is
  process-scoped, so mount, operate and unmount happen inside one process via
  `hive <FILE> exec`.

### Input formats

- `reg`, `pol` (Group Policy PReg binary), `admx` + `adml`, `gpp`
  (`Registry.xml`), `inf` (`[AddReg]`/`[DelReg]`), `json`, `csv`, `ini`.
  Detection reads content before extension.

### Safety

- `import` and `sync` compute the inverse of the pending change and write it as
  a `.undo.reg` before touching the registry.
- `validate --fix` repairs the damage `.reg` files pick up in transit, labelling
  every lossy repair and refusing to guess at malformed DWORD/QWORD payloads.
- `probe` really opens a key rather than inferring from its path.
- `discover` reproduces the companion-file search an executable performs and
  flags the rungs that are security bugs.
- `--self-check` reports what AppLocker, SRP, WDAC and the process token do to a
  portable binary in this environment.
