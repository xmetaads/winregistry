# regx

A portable, single-file Windows Registry CLI for **standard users**. Manifested
`asInvoker`, so it never raises a UAC prompt and never elevates. Static-linked
CRT, no installer, no runtime dependency.

```
cargo build --release      # -> target\release\regx.exe
cargo test                 # 344 tests, including live-registry, IPC, and native Shell round trips
cargo run --example generate-man -- target\man
cargo run --release --example benchmark-large -- target\release\regx.exe 5000
cargo test --manifest-path fuzz\Cargo.toml --test seed_corpus
```

## Repository layout

| Path | What it is |
|---|---|
| `src/` | The `regx` CLI (Rust, MSVC toolchain) |
| `app.manifest`, `build.rs` | `asInvoker` manifest, embedded into the PE at link time |
| `website/` | Static site for **winregistry.org** — no build step ([README](website/README.md)) |
| `vercel.json`, `.vercelignore` | Vercel deployment config: output directory, clean URLs, security headers |
| `dev-server.py` | Local preview that reproduces Vercel's routing — `python dev-server.py` |
| `design-system/` | Generated design system the site is built against |

**Platforms.** The pinned [Rust MSVC targets](https://doc.rust-lang.org/stable/rustc/platform-support/windows-msvc.html)
require Windows 10 or Windows Server 2016 and later. x64 is built and tested.
ARM64 is built by CI on every push, but
has not been run on ARM64 hardware — the claim is "it compiles and links", not
"it is verified there".

`.claude/skills/` is intentionally not committed: it holds ~7 MB of vendored
[ui-ux-pro-max](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill) data
used only when designing site pages. Reinstall it with
`npx ui-ux-pro-max-cli init --ai claude` if you need it.

---

## Commands

| Command | What it does |
|---|---|
| `import <FILE...>` | Merge whole inputs or selected value-name globs atomically |
| `undo <FILE>` | Safely apply an undo snapshot while automatically preserving a redo snapshot |
| `export <KEY>` | Export a live key to `.reg`, JSON, CSV, or `Registry.pol` |
| `convert <FILE>` | Read any supported format and write `.reg`, JSON, CSV or `Registry.pol`; optionally fail on source/redirection conflicts |
| `inspect <FILE...>` | Report format, fidelity losses, and structured semantic conflicts without applying |
| `discover [EXE_OR_DIR]` | Find an application's companion config files the way the application would, and flag the risky rungs |
| `diff <A> <B>` | Compare file/live sources with glob scope and summary mode; emit an A-to-B patch only from complete, unambiguous sources |
| `search <SOURCE> <QUERY>` | Substring/glob/regex search with field/path filters and explicit incomplete-source reporting |
| `watch <KEY>` | Wait for native registry notifications and report exact key/value drift without polling |
| `plan <FILE...>` | Resolve redirects, policy, rollback and exact mutations without writing |
| `apply-plan <PLAN>` | Apply a saved plan only while source bytes and live state still match |
| `batch <MANIFEST>` | Apply a versioned multi-operation manifest atomically with per-operation outcomes |
| `audit <FILE>` | Verify that an audit log has not been edited or had records removed |
| `lnk <OP>` | Resolve Windows Known Folders and create, inspect, delete, or manifest-apply native `.lnk` shortcuts |
| `formats` | List the input formats and how each is detected |
| `completions <SHELL>` | Generate Bash, Elvish, Fish, PowerShell or Zsh completion on stdout |
| `merge <FILE...>` | Combine any supported formats to `.reg`, JSON, CSV, or Registry.pol; optionally fail on conflicting assignments |
| `query <KEY>` | Read values |
| `ls <KEY>` | List scoped, bounded live/remote subkeys without reading value data |
| `stats <SOURCE>` | Count keys, values, types, payload bytes, deletes and depth without printing value data |
| `fingerprint <SOURCE>` | Compute a stable SHA-256 over exact registry state without printing value data |
| `set <KEY>` | Confirm and write one value with an automatic undo snapshot |
| `delete <KEY>` | Confirm and delete a key or value with an automatic undo snapshot |
| `copy <SOURCE> <DEST>` | Copy a live subtree; refuses collisions unless `--overwrite` is given |
| `move <SOURCE> <DEST>` | Move or rename a live subtree with a two-phase copy/delete and one undo snapshot |
| `copy-value <SOURCE_KEY> <VALUE> <DEST_KEY>` | Copy one value without copying sibling values or subkeys |
| `move-value <SOURCE_KEY> <VALUE> <DEST_KEY>` | Move or rename one value with two-phase rollback safety |
| `apply-copy-plan <PLAN>` | Apply a saved copy/move preview only while source and destination still match |
| `backup <KEY> <HIVEFILE>` | Save keys, types and raw data into a native application-hive `regf` file |
| `restore <HIVEFILE> <DEST>` | Atomically restore an application-hive backup into the live registry |
| `sync <FILE>` | Reconcile desired state; `--prune --prune-keys` removes undeclared subtrees and `--backup FILE` selects the undo path |
| `validate <FILE...>` | Lint; `--fix` repairs what is safely repairable |
| `probe <KEY>` | Can this user *actually* write here? |
| `permissions <KEY>` | Show or compare owner, DACL inheritance, SDDL and effective access per registry view |
| `hive <HIVEFILE> <OP>` | Offline hive editing, atomic batch, and access diagnostics via `RegLoadAppKey` — **no admin** |
| `--self-check` | What AppLocker / SRP / WDAC / the token do to this binary |

Unix section-1 manuals for the root command and every nested subcommand are
generated from the same Clap metadata:

```text
cargo run --example generate-man -- target/man
```

The generator is a development dependency and is not linked into `regx.exe`.

Large-data performance is measured end to end against the release executable:

```text
cargo run --release --example benchmark-large -- target/release/regx.exe 5000
```

The harness generates `.reg`, `Registry.pol`, and a private application hive
under `target/benchmark-large`; it reports elapsed time, throughput,
operations/second, and peak working set without touching the user's registry.

Parser fuzz targets and their checked-in seeds live under [`fuzz/`](fuzz/).
`reg_bytes`, `xml_bytes`, and selector-driven `all_formats` cover every input
reader directly. A deterministic local smoke test mutates 10,000 bounded inputs
through all three targets. The scheduled GitHub workflow is configured for
10,000 libFuzzer/AddressSanitizer executions per target; see
[`fuzz/README.md`](fuzz/README.md) for local setup.

Global flags: `--dry-run`, `-y/--yes`, `--output text|json`, `--view 64|32|both`,
`--log-level`, `--no-color`.

Machine-readable command output is catalogued by the
[CLI output schema v1](https://winregistry.org/schemas/cli-output-v1.json);
its `x-regx-command-map` points each command to the applicable JSON Schema
definition. `watch` emits one schema-valid event per line. Commands whose
stdout is itself another language reject the ambiguous global flag:
use `convert --to json` for registry data, while `merge` and `completions`
continue to emit `.reg` and shell-source streams respectively.

`--view both` is supported by `query`, `export`, `backup`, `restore`, `copy`,
`move`, `copy-value`, `move-value`, live `search`, live `diff`, `watch`, `probe`, `permissions`, `set`,
`delete`, `import`, `undo`, and `sync`
(including `--prune --prune-keys`). Reads emit distinct per-view results. Search applies
its limit independently to each view. Dual-view export writes `NAME.32.reg` and
`NAME.64.reg`, or returns both datasets in one JSON document when `--out` is
omitted. File-backed export status includes exact `bytes` and lowercase
`sha256` per artifact; dry-run and inline-data views use explicit nulls.
`diff --to reg|json|csv|pol -o PATCH` writes its applicable patch
directly in the selected registry-data format. Dual-view diff preserves the
extension while inserting `.32` and `.64`; if either view fails or either
source is incomplete, neither paired patch is written. JSON status seals each
written patch with exact `bytes` and lowercase `sha256`; absent, refused and
dry-run patches use explicit null evidence.
Mutations capture both inverse snapshots before writing; if either view fails,
every touched view is rolled back in reverse order. Import writes
`NAME.32.reg` and `NAME.64.reg` undo files and uses those exact in-memory
snapshots for rollback. `set` and `delete` also persist their exact inverse in
the temporary directory by default; `--backup FILE` selects a durable location,
and dual-view mode writes `FILE.32.reg` and `FILE.64.reg`. They prompt before
writing unless `-y` is allowed by policy, and cancellation creates neither the
registry change nor the requested backup. Temporary names combine PID,
nanosecond time and a process-local atomic sequence, so concurrent commands
cannot reuse the old millisecond-only or fixed-stdin path. No registry command silently treats
`both` as `native`.
`plan --view both` emits independent changes, failures, policy decisions and
rollback paths for each view without writing either one.
Unredacted JSON before/after states retain their compatible preview and embed
an `exact` registry-value object, so reviewers can distinguish type-only drift
and verify raw bytes. When policy requires redaction, the existing SHA-256-only
object is retained and no exact payload is exposed.

`convert`, `merge`, `import`, `sync`, and `plan` accept
`--conflicts last-wins|error`. The default preserves regedit-compatible input
order. `error` retains structured conflict evidence from each reader and from
the post-redirection combined model, then refuses differing value data or key
create/delete state before output, registry reads, undo, audit, prompts, or a
saved plan. Convert checks both the parsed source and its post-redirection
model before writing a file or stdout.
`inspect --output json` keeps the conflict previews and also reports
`oldExact`/`newExact` registry-value objects for value conflicts. Whole-key
create/delete conflicts use null because they have no value payload. Binary,
unknown-type, and malformed-string conflicts can therefore be repaired without
guessing from display text. Every report also embeds `data`, the complete
lossless parsed registry-data model. This remains available when fidelity
losses or semantic conflicts make the source incomplete, so inspection
automation can examine the retained keys and raw bytes even when `convert`
correctly refuses to present them as a safe output artifact.

`plan FILE --save change.plan.json` creates a
[versioned artifact](https://winregistry.org/schemas/saved-plan-v1.json) only
when policy, reads, rollback and reconciliation are complete. The artifact binds
the SHA-256 of every named source file, each per-view desired mutation, and the
current state needed to reverse those mutations. `apply-plan` verifies the
artifact payload, re-reads every source, rechecks current state and current
administrative policy, then captures/persists fresh undo snapshots before an
atomic audited apply. Source or registry drift exits `5` without mutation.
Stdin cannot be saved because it cannot be re-read; `--dry-run --save` is
rejected because dry-run writes no files.
With JSON output, `savedPlan`, `savedPlanBytes`, and `savedPlanSha256` identify
and seal the persisted single- or dual-view artifact. They are `null` when no
plan was requested or an incomplete/blocked plan was correctly not written.

`copy`/`move --view both --save-plan NAME.json` writes paired
`NAME.32.json` and `NAME.64.json` previews. Applying the base name with
`apply-copy-plan --view both` validates both artifacts, both sources, and both
current-state snapshots before writing either view, then uses paired undo files
and cross-view rollback.

`batch MANIFEST` reads
[batch schema v1](https://winregistry.org/schemas/batch-v1.json), whose
case-insensitively unique operation IDs each contain explicit JSON key/value
mutations. It validates and policy-checks every operation, captures every
affected view before the first write, and writes one logical undo bundle
(`NAME.reg`, or `NAME.32.reg` plus `NAME.64.reg`). Operations execute in order;
the first failure stops later work and rolls every touched view back to the
single pre-batch state. JSON reports `applied`, `planned`, `skipped`,
`notAttempted`, `rolledBack`, or `rollbackFailed` for each operation. The
manifest limit is 10,000 operations.
JSON results identify their separate
[result schema v1](https://winregistry.org/schemas/batch-result-v1.json).
Each per-view undo entry includes the planned path plus exact `bytes` and
`sha256` after persistence. Dry-run keeps the planned entries but uses null
evidence, for both live and offline-hive batches.

File-reading commands accept bounded stream input without a temporary file:
use `-` once for standard input, or `pipe:NAME` for a one-shot Windows named
pipe. Both forms preserve content-based format detection.

```powershell
Get-Content app.reg -Raw | regx inspect -
Get-Content policy.json -Raw | regx convert - --from json --redirect off
```

For direct process-to-process IPC, create a byte-mode pipe and close it after
writing one complete document. The client waits up to five seconds and reads at
most 64 MiB:

```powershell
$producer = Start-Job {
  $p = [IO.Pipes.NamedPipeServerStream]::new(
    "regx-input", [IO.Pipes.PipeDirection]::Out, 1,
    [IO.Pipes.PipeTransmissionMode]::Byte)
  try {
    $p.WaitForConnection()
    $bytes = [Text.Encoding]::UTF8.GetBytes((Get-Content policy.json -Raw))
    $p.Write($bytes, 0, $bytes.Length)
    $p.Flush()
  } finally { $p.Dispose() }
}
regx inspect pipe:regx-input --from json --output json
Wait-Job $producer | Receive-Job
```

The native `\\.\pipe\regx-input` spelling is also accepted. A stream
`import` or `sync` requires `-y` unless it is a dry run. `validate --fix`
requires `--out`, and saved plans reject streams because their source cannot be
re-verified after it closes.

### Windows Shell Known Folders and native shortcuts

Path-bearing CLI arguments and shortcut manifests recognize
`shell:Startup`, `shell:Desktop`, and `shell:Programs`. regx resolves each token
with `SHGetKnownFolderPath` (and the documented `SHGetFolderPathW` fallback),
not an environment-variable guess or an external shell.

```powershell
regx lnk create `
  --target "C:\Program Files\Acme\Acme.exe" `
  --output "shell:Startup\Acme.lnk" `
  --workdir "C:\Program Files\Acme" `
  --args=--background `
  --icon "C:\Program Files\Acme\Acme.exe,0" `
  --style hidden `
  -y

regx lnk inspect "shell:Startup\Acme.lnk" --output json
regx lnk delete "shell:Startup\Acme.lnk" --dry-run
```

Creation is implemented with `CoCreateInstance(CLSID_ShellLink)`,
`IShellLinkW`, and `IPersistFile`; the product never calls PowerShell or
`WScript.Shell`. It writes to a temporary `.lnk`, reads every field back through
COM, verifies it, and commits atomically. `hidden` and `minimized` both request
`SW_SHOWMINNOACTIVE`; they affect initial window presentation, not whether the
entry is visible in Startup management tools.

`lnk apply FILE` accepts repeatable `[SHORTCUT]` and `[DELETE_SHORTCUT]`
blocks from UTF-8/UTF-16 files, stdin (`-`), or a Windows named pipe. It
preflights the complete manifest, rejects duplicate destinations, confirms
once, and restores every earlier shortcut if a later action fails. Shortcut
mutations support `--dry-run`, `-y`, JSON output, and tamper-evident audit
records with exact before/after SHA-256 values.

```ini
[SHORTCUT]
Target=C:\Program Files\Acme\Acme.exe
Output=shell:Startup\Acme.lnk
WorkingDirectory=C:\Program Files\Acme
Arguments=--background
Description=Acme background client
Icon=C:\Program Files\Acme\Acme.exe,0
Style=hidden

[DELETE_SHORTCUT]
Path=shell:Desktop\Old Acme.lnk
```

Machine consumers can use the
[shortcut result schema](https://winregistry.org/schemas/shortcut-result-v1.json),
[capability inventory](https://winregistry.org/capabilities.json), and
[AI-agent summary](https://winregistry.org/llms.txt).

`import` and `export` accept repeatable `--value GLOB` and
`--exclude-value GLOB`; matching follows registry case-insensitivity and `@`
names the default value. Once a value filter is present, empty-key creation and
whole-key deletion blocks are deliberately omitted—value selection can never
silently become a key operation. An export with no matching values exits `8`
without creating its output file.
Live and offline-hive export also accept repeatable key-path `--include GLOB`
and `--exclude GLOB`. They match the portable path after `--root-as`;
`*` matches one registry-path component and `**` crosses separators. Key and
value filters compose, and a key selection with no match likewise exits `8`
without creating an artifact.
Live export is recursive by default; `--no-recursive` restricts it to the
requested key. Single- and dual-view status JSON records the effective
recursive mode, selected artifact format and value globs, and its key/value
counts are calculated after filtering.
`--root-as KEY` rebases the requested source key itself onto a validated
destination key and preserves every relative descendant. The transformation
is read-only and happens before REG/JSON/CSV/Registry.pol serialization, so an
HKLM or remote HKU snapshot can become an explicitly scoped HKCU migration
artifact without editing serialized text.

`convert --to reg|json|csv|pol` selects the registry-data output format. JSON uses
the explicit `{"keys": [...]}` schema; raw values include a numeric `typeId`
and hex `raw` payload so unknown types and malformed strings remain byte-exact.
CSV uses `hex(TYPE_ID)` for the same reason. `--to pol` emits a version-1 PReg
binary for one implicit HKCU or HKLM root, preserving empty keys, strings,
DWORDs, MS-GPREG-defined raw types, named-value deletes and subtree deletes. It
refuses mixed hives, implicit-root/default-value mutation, undefined types and
records larger than 65,535 bytes because the protocol does not define those
states exactly.

`copy` and `move` preserve the complete readable subtree. They refuse a
destination inside the source, abort if any source subkey is unreadable, apply
policy before prompting, and write a combined undo snapshot before changing
anything. `move` deletes the source only after every destination write
succeeds. An existing destination is rejected unless `--overwrite` is supplied;
that option merges into it and leaves unrelated destination values intact.
Any partial copy or source-removal failure triggers immediate audited rollback
from the combined snapshot.

Add `--save-plan FILE` to subtree or value copy/move to write a
[copy/move plan artifact](https://winregistry.org/schemas/copy-plan-v2.json)
instead of changing the registry. It binds the full readable source subtree or
exact source value, destination name, copy payload, optional exact source
deletion, and destination/current rollback state with SHA-256. Version 1
subtree plans remain readable. `apply-copy-plan` re-exports
the source, rebuilds the copy, checks current policy and destination state, and
refuses drift before writing a fresh undo file. Its machine result uses the
[result schema](https://winregistry.org/schemas/copy-plan-result-v2.json).
Saved-plan JSON seals every persisted subtree or value artifact independently
with `planBytes` and `planSha256`, including each member of a dual-view pair.
Mutation and `apply-copy-plan` JSON likewise seal every persisted per-view undo
with `backupBytes` and `backupSha256`; dry-run uses null evidence.
`copy --source-computer COMPUTER HKLM\... LOCAL_DEST` reads the source remotely
and writes only to the local destination. The same option works with
`--save-plan`; the computer identity and remote source content are digest-bound
and re-read by `apply-copy-plan`. `move` deliberately has no
`--source-computer`, so no remote deletion path exists.

Imports and syncs are compensating-transaction atomic by default. regx refuses
to start when the rollback snapshot is incomplete; if a later write fails after
earlier changes succeeded, it immediately applies that snapshot and reports both
the apply and rollback results. `--no-backup` explicitly opts out of both the
undo file and automatic rollback, so a partial state may then remain.
Machine-readable results for `set`, `delete`, `import`, `sync`, and
`apply-plan` identify every per-view undo file and seal it with exact
`undoBytes` and `undoSha256`; dry-run or `--no-backup` returns null evidence.
Applying an undo similarly seals the newly persisted redo with `redoBytes` and
`redoSha256` per view; undo dry-run returns null redo evidence.

`sync --prune` removes undeclared values from every declared key.
`sync --prune --prune-keys` additionally treats the declared paths as the
complete desired tree and recursively removes topmost unrepresented branches.
The stronger mode first exports every affected subtree completely, refuses ACL
gaps, then sends generated deletes through policy, plan, undo, audit, and atomic
rollback. `plan` accepts the same flags for an exact preview.

`watch` uses `RegNotifyChangeKeyValue`, not a polling loop. It snapshots the
selected key before each wait and reports added, modified, and removed keys or
values after a notification. `--count N` bounds the number of events,
`--timeout SECONDS` bounds idle time, and `--no-recursive` watches only the
selected key. JSON output is newline-delimited for streaming automation and
each value change carries lossless `leftExact`/`rightExact` registry-value
objects. Added and removed sides use `null`; present sides preserve typed
strings/DWORDs or the numeric type ID and exact raw bytes. This avoids a
notification-to-query race when automation needs the value that triggered an
event.

`query`, `ls`, `stats`, `fingerprint`, `export`, live-key `search`, `probe`, and
`permissions` accept
`--computer COMPUTER` for
read-only remote registry access through `RegConnectRegistryW`. Windows exposes
only `HKLM` and `HKU` through this API; regx rejects other hives before opening
a network connection. `diff --computer-a HOST` and `--computer-b HOST`
independently make either live side remote, enabling remote-to-file,
remote-to-local, and remote-to-remote drift checks, including `--view both`.
`ls` returns immediate children or all descendants with `-r` without reading
value payloads. Repeatable `--include`/`--exclude` globs scope canonical paths;
`--limit` defaults to 1,000 matching keys per view and reports truncation in
JSON. Offline `hive ls` applies the same controls to relative hive paths.
`stats` accepts any supported registry-data file, stream, or a live/remote key.
It reports effective last-write-wins key/value counts, registry types, exact raw
payload bytes, delete operations, maximum depth, conflicts, and completeness
without rendering value names or data. Live `--view both` remains separated per
view; `hive stats [SUBKEY]` provides the same read-only summary offline.
For migration reports, live/remote `stats SOURCE --root-as DEST_KEY` rebases the
requested subtree before filtering and measures depth relative to that mapped
root. `hive stats ... --root-as DEST_KEY` maps the mounted hive root the same
way as offline export and fingerprint. JSON records the resolved `rootAs`; file
inputs reject the option because they may contain multiple unrelated roots.
The same repeatable key `--include`/`--exclude` and value
`--value`/`--exclude-value` globs used by fingerprint/export restrict the
metrics to managed state. JSON echoes the scope and `matched`; no match exits
`8` instead of treating a zero summary as success.
`fingerprint` hashes the effective model with canonical version 1: exact
case-preserved paths and names, deletion state, numeric registry types, and raw
payload bytes are length-delimited beneath a domain separator. Source ordering
does not affect the SHA-256, while any exact state change does. File/live/remote
and dual-view sources are supported without printing value data;
`hive fingerprint [SUBKEY]` applies the same contract offline.
Use `--expect SHA256` to turn a file, single registry view, or hive subtree into
an exit-code drift gate: a mismatch is valid output with exit `5`, not a parse
failure. `--view both` instead requires the complete
`--expect-32 SHA256 --expect-64 SHA256` pair; supplying only one member or an
ambiguous single `--expect` fails with usage before registry access.
Repeat `--include GLOB`/`--exclude GLOB` for key paths and
`--value GLOB`/`--exclude-value GLOB` for value names when automation owns only
part of a source. Value scope deliberately omits whole-key delete/empty-key
operations, matching scoped export safety. JSON echoes all four filter lists
and reports selected key/value counts. A scope matching nothing exits `8` with
`matched:false`; it is never reported as a successful empty fingerprint.
For migration comparisons, `fingerprint LIVE_KEY --root-as DEST_KEY` rebases
the requested live/remote subtree before filtering and hashing. Offline
`hive fingerprint ... --root-as DEST_KEY` follows offline export semantics by
rebasing the mounted hive root. JSON records the resolved `rootAs`. File inputs
reject this option because an arbitrary multi-root registry-data file has no
unambiguous source root; use `diff --map-a/--map-b` when explicit file mapping
is required.
Use `--map-a FROM=TO` or `--map-b FROM=TO` to rebase one complete input
subtree before comparison. This makes migration drift meaningful across roots
such as `HKLM\Software\Vendor\App` and `HKCU\Software\Vendor\App`; counts,
filters, JSON changes, and the generated A-to-B patch all use the mapped path.
Every source key must be below `FROM`, and malformed or partial mappings fail
closed.
Repeat `--value GLOB` and `--exclude-value GLOB` to compare only selected
value names (`@` denotes the default value). Once value selection is active,
structural key additions/deletions are deliberately omitted: even if the
target lacks the entire key, the patch deletes only selected values and cannot
remove unselected siblings.
In JSON, value changes keep compatible `left`/`right` previews and add
`leftExact`/`rightExact`. Each present side uses the lossless registry-value
shape, so type-only drift, unknown types, and malformed raw strings remain
machine-verifiable in single-view, dual-view, remote, and offline-hive diffs.
No mutation command accepts those flags; copy exposes the
distinct read-only-source flag described above. The remote
computer must already permit the Remote Registry service, firewall path, and
ACL authorization. Exported `.reg` files intentionally contain normal local
hive paths so they remain portable.

`query --output json` keeps the established human `type` and `data` preview
fields and also embeds an `exact` registry-value object. String and DWORD data
remain typed, while every other registry type carries its numeric `typeId` and
raw bytes, so automation never has to reverse-engineer display text. The same
contract is used by offline `hive query` and per-view query results.
`search --output json` applies the same rule to value matches: `exact` embeds
the matching registry value with its numeric type ID and raw bytes, while a
key-path match reports `exact: null`. File, stdin, live, remote, dual-view, and
offline-hive search therefore do not degrade binary evidence into preview text.

`permissions` reads the key's actual security descriptor without changing it.
It reports the owner SID, whether DACL inheritance is enabled, portable SDDL,
and effective query/enumerate/notify/set/create-subkey/delete access by opening
the key with each specific right. `--view both` reports the 32-bit and 64-bit
views independently. Add `--compare OTHER` for field-level permission drift and
`--exit-code` to return `5` when the keys differ. `--compare-computer HOST`
independently locates the comparison key, so local-to-remote and
remote-to-remote ACL drift are both representable.

`backup` creates a real application-hive file through `RegLoadAppKey`, which
works for a standard user and can be reopened by `regx hive`. With
`--view both`, it preflights both views before writing `NAME.32.hiv` and
`NAME.64.hiv`, and removes both artifacts if either write fails. A matching
dual-view `restore NAME.hiv` reads that pair, captures both rollback snapshots
before writing, and emits separate undo files. `restore` rebases
that hive under an explicit destination, refuses collisions unless
`--overwrite` is used, and applies through policy, audit, an undo snapshot, and
automatic rollback. Keys, empty keys, registry types, and raw bytes are
preserved. ACLs, key classes, and last-write timestamps are not: Windows'
`RegSaveKeyEx` requires `SeBackupPrivilege`, which contradicts this project's
non-admin contract.
Restore JSON seals every persisted undo snapshot with `undoBytes` and
`undoSha256`, independently per view. Dry-run reports both as null because its
undo path is only a plan and no rollback artifact has been written.
`backup --computer HOST HKLM\... FILE.hiv` reads the subtree remotely and
creates only the local application-hive artifact. The hostname is retained in
JSON output; restore remains an explicitly local mutation. Successful backup
JSON also returns the exact artifact `bytes` and lowercase `sha256` for each
hive. Dry-run reports both fields as `null`, making it impossible to confuse a
planned path with a file whose contents were actually sealed.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 2 | CLI usage error |
| 3 | `.reg` parse error |
| 4 | access denied |
| 5 | partial success (something was skipped) |
| 6 | redirection refused |
| 7 | file I/O error |
| 8 | key or value not found |

---

## Input formats

`.reg` is only one shape registry data arrives in. Every reader funnels into the
same internal model, so redirection, coalescing, undo snapshots and apply work
on all of them unchanged.

| Format | Typical file | Notes |
|---|---|---|
| `reg` | `.reg` | regedit's own text format, UTF-16 or ANSI `REGEDIT4` |
| `pol` | `Registry.pol` | **Group Policy PReg binary.** Exactly models `**del.`, `**DeleteValues`, and `**DeleteKeys`; conditional, ACL, and value-wipe directives are reported as fidelity losses and fail closed for conversion or mutation. Writing enforces the MS-GPREG ASCII identifier and 65,535-byte record limits. |
| `admx` | `.admx` + `.adml` | **Policy template.** Reads concrete `enabledValue`/`disabledValue`; administrator-supplied `<elements>` are fidelity losses, never invented |
| `gpp` | `Registry.xml` | **Group Policy Preferences.** Value `R`/`U`, all `D`, and key `C`/`U` are modeled; value `C`, key `R`, bitfield updates, targeting, `removePolicy="1"`, and malformed items fail closed. Only the protocol's `RegistrySettings`/`Collection`/`Registry` container grammar is traversed; an outer `RegistrySettings disabled="1"` disables the complete preference type |
| `inf` | `.inf` | `[AddReg]` / `[DelReg]` with continued physical lines, strict quoted `[Strings]` tokens, `--inf-language 0409` locale selection, and custom raw types; ambiguous/context-dependent operations are fidelity losses |
| `json` | `.json` | compact `{path: {name: value}}` or explicit `{"keys": [...]}` |
| `csv` | `.csv`, `.tsv` | header naming `key, name, type, data` in any order |
| `ini` | `.ini`, `.cfg` | `[HKEY_...]` sections, optional `:type` suffix per name |
| `hive` | `NTUSER.DAT` | detected and redirected to `regx hive` |

The format is detected from **content first, extension second** — a
`Registry.pol` renamed to `.txt` is still a PReg file, and a `.reg` that is
really JSON is a mistake worth catching before it reaches the registry. XML
policy formats are classified from their actual parsed root: valid
`RegistrySettings`, `Collection`, and single-`Registry` GPP fragments survive a
rename, while a familiar tag nested under an unrelated wrapper is not accepted.
Override with `--from`.

```bash
regx inspect "C:\Windows\System32\GroupPolicy\Machine\Registry.pol"
```

A `Registry.pol` stores no hive of its own: the same bytes mean HKLM under
`Machine\` and HKCU under `User\`. `regx` infers it from the path and falls back
to `--pol-root`.

---

## Audit trail

A tool that changes the registry and leaves no attributable record of what it
changed cannot be deployed in a managed environment. `--audit-log` appends one
JSON object per mutation — timestamp, actor SID, operation, **before and after** —
to a file you nominate.

```bash
regx import app.reg --audit-log C:\logs\regx.jsonl
regx audit C:\logs\regx.jsonl          # verify it has not been touched
regx audit C:\logs\regx.jsonl --rotate-to C:\logs\regx-001.jsonl
regx audit C:\logs\regx-001.jsonl --chain C:\logs\regx.jsonl
regx audit C:\logs\regx.jsonl --write-anchor X:\anchors\regx.anchor
regx audit C:\logs\regx.jsonl --verify-anchor X:\anchors\regx.anchor
regx audit C:\logs\regx.jsonl --write-anchor X:\anchors\regx.anchor --anchor-key X:\keys\anchor.key
regx audit C:\logs\regx.jsonl --verify-anchor X:\anchors\regx.anchor --anchor-key X:\keys\anchor.key
```

`--write-anchor` atomically writes a detached checkpoint containing the
whole-file SHA-256, tail hash and record count. `--verify-anchor` reports both
internal-chain integrity and checkpoint equality. Keep the small anchor on a
different trust boundary; storing it beside the writable log does not protect
it from a coordinated rewrite.
`--anchor-key` writes and verifies a v2 HMAC-SHA256 anchor. The key file must
contain 32 to 65,536 raw secret bytes and should be ACL-protected on a separate
trust boundary. Missing/wrong keys fail, and keyed verification refuses an
unsigned v1 anchor to prevent downgrade.
JSON write results seal the persisted rotation archive or detached anchor with
its exact byte length and SHA-256. Dry-run reports both evidence fields as
`null`, so a planned path cannot be mistaken for an artifact that exists.

Set `REGX_AUDIT_LOG` to enforce it machine-wide, so an individual invocation
cannot skip the trail by forgetting the flag.

**The records are hash-chained.** Each carries the SHA-256 of the one before it,
so altering or removing a line breaks the chain from that point and `regx audit`
reports the line. This does not stop someone rewriting the whole file — nothing
local can, without a key the operator does not hold — but it turns silent
tampering into a detectable event, which is the property auditors ask for. Ship
the file somewhere append-only for the rest.

Rotation refuses a broken log and an existing archive. It durably copies the
intact active segment, then starts a new segment with a hashed `segment.start`
record binding both the prior tail hash and the archive's whole-file SHA-256.
`--chain` verifies segments in chronological order and detects editing,
omission, or reordering. Rotate only while regx writers are quiescent; the
command detects changes during the archive copy, but it is not a system-wide
logging service or coordinator.

**`--audit-redact`** records the SHA-256 of each value instead of the value.
Registry data holds licence keys and connection strings; without this the log
becomes a secret in its own right. Redaction covers the recorded command line
too — `regx set … -d SECRET` would otherwise put the secret straight into the
session header, which is exactly the hole an early version of this had.

A `--dry-run` is logged as `simulated`, so a rehearsal is distinguishable from
the real thing in the record.

## Administrative policy

A security team's objection to deploying a registry editor is not that it might
be unsigned — that is solvable with a certificate. It is that they cannot govern
what it does once it is on the machine.

`regx` reads policy from `HKLM\SOFTWARE\Policies\regx` and **nowhere else**.
A standard user can write freely to HKCU, so honouring a per-user copy would let
the person being restricted lift their own restrictions. HKCU is not consulted,
even as a fallback. By the same reasoning a command-line flag can make policy
stricter but never looser.

| Value | Type | Effect |
|---|---|---|
| `AuditLog` | `REG_SZ` | Every mutation is logged here, whether or not `--audit-log` was passed |
| `AuditRedact` | `REG_DWORD` | Force `--audit-redact` on |
| `MinConfidence` | `REG_SZ` | Redirection floor: `high`, `medium` or `low` |
| `DenyKeys` | `REG_MULTI_SZ` | Key prefixes `regx` refuses to write to, in the live registry **and** inside a mounted hive. A denied key aborts the whole operation rather than being quietly skipped |
| `DisableHive` | `REG_DWORD` | Forbid the offline hive engine |
| `RequireConfirm` | `REG_DWORD` | Ignore `-y`; a human confirms each write |

An ADMX template is in [`policy/`](policy/) for deployment through Group Policy.
`regx --self-check` reports what is in force, and `regx inspect policy/regx.admx`
reads the template with the same reader used for anyone else's — so a mistake in
it surfaces before the Group Policy editor sees it.

Deny matching is on whole path components and case-insensitive:
`HKCU\Software\Acme` covers `Acme` and its subkeys but not `AcmeOther`. This
restricts `regx` only; it is not an ACL and does not constrain other tools.

## Build provenance

```
$ regx --version
regx 0.3.0
commit:  2e212936c6af
date:    2026-07-28T03:59:11+07:00
target:  x86_64-pc-windows-msvc
licence: MIT
source:  https://github.com/xmetaads/winregistry
```

The commit date is used rather than the build clock, so two builds of the same
source are identical. A working tree with uncommitted changes is reported as
`<commit>-modified`.

Releases carry a SHA-256 beside each binary, a CycloneDX SBOM, and a GitHub
build provenance attestation.

Maintainers can exercise the complete asset validator, including its negative
cases, before creating a tag:

```bash
python scripts/check_release_identity.py --self-test
python scripts/check_release_assets.py --self-test
python scripts/check_release_identity.py v0.3.0 --require-git-tag
python scripts/check_release_assets.py dist v0.3.0
```

The identity check requires the exact tag at `HEAD`, the same Cargo version, a
dated changelog heading, and non-empty Keep a Changelog notes. It also emits
the exact notes consumed by GitHub, so preflight and publication cannot parse
the changelog differently. The asset check fails closed unless `dist` contains
exactly the two expected
PE architectures, the version-matched CycloneDX 1.5 SBOM, and complete,
non-duplicated `SHA256SUMS`. It also checks `asInvoker`, static CRT, and the
strict `<2 MiB` binary limit. The release workflow runs both validators
before publication rather than relying on separate CI-only interpretations.

**They are not yet code-signed.** `regx --self-check` reports its own signature
status by asking Windows, against the same trust store AppLocker consults, so
you can confirm rather than take this file's word for it.
[docs/SIGNING.md](docs/SIGNING.md) is the complete path from no certificate to a
signing pipeline — signing is the one barrier no feature work closes, and it
needs a certificate rather than code.
The release workflow fails closed when no valid signature is present. An owner
must explicitly set the repository variable `ALLOW_UNSIGNED_PREVIEW=true` to
publish an unsigned preview; a missing decision can no longer ship by warning.
That exception accepts only Windows' `NotSigned` state. An invalid, untrusted,
or hash-mismatched signature always fails release and post-release smoke.

## Companion-file discovery

Enterprise executables find their own configuration by anchoring on
`GetModuleFileNameW(NULL)` — the real path of the running module, used rather
than `argv[0]` because a parent process controls `argv[0]` and can point it
anywhere. Strip the extension, append `.ini`, and that is the classic sidecar;
.NET reaches `MyApp.exe.config` the same way. Around that, products layer a
search order.

`regx discover` reproduces that search, reports which rung each hit came from,
and flags the rungs that are load-bearing security bugs.

```bash
regx discover "C:\Program Files\Acme\updater.exe" --strict
```

With `--output json`, the versioned report also records the resolved
`executable`/`anchor`, enabled `policy`, `registryPointer`, and `strict`
controls, explanatory `notes`, every candidate path in `searched`, and the
aggregate `risky` hit count. The full probe trail is present in JSON regardless
of `--verbose`; that flag only expands human-readable output. Each hit retains
both the candidate `path` and canonical `resolvedPath`, plus compatible risk
names and structured `riskDetails` explanations. A junction or symlink target
can therefore be audited without resolving it again after the search.

| Rank | Origin | |
|---|---|---|
| 1 | explicit path | |
| 2 | environment variable | `<STEM>_CONFIG`, `<STEM>_HOME`, `<STEM>_INI` |
| 3 | beside the executable | the sidecar, plus the `.exe.<ext>` convention |
| 4–6 | `%LOCALAPPDATA%`, `%APPDATA%`, `%PROGRAMDATA%` | under `\<stem>\` |
| 7 | registry pointer | `Software\<stem>` `ConfigPath` (`--registry-pointer`) |
| 8 | Group Policy caches | `Registry.pol`, `PolicyDefinitions` (`--policy`) |
| 9 | **current directory** | reported as a risk, never trusted |
| 10 | **`%WINDIR%`** | where `GetPrivateProfileString` silently resolves a bare file name |

Risks reported per hit: sourced from the working directory; sitting in a
directory this user can write to while the executable's own directory is
protected; reached through a reparse point; resolving outside the anchor;
on a network path; or matching only after 8.3 short-name expansion.

Directory writability is **asked of the OS**, not inferred from the path: the
directory is opened for `FILE_ADD_FILE`, which is an access check with no side
effect — the same principle as `regx probe`.

---

## Smart Redirection

Rewrites `HKLM` / `HKCR` paths to `HKCU` so a standard user can apply a `.reg`
written for machine scope. Every mapping carries a **confidence** and a reason;
`--min-confidence` (default `medium`) is the gate.

| Source | Confidence | Why |
|---|---|---|
| `HKCR\*`, `HKLM\SOFTWARE\Classes\*` | **high** | HKCR is a merged view; the per-user branch wins |
| `HKLM\...\CurrentVersion\Run`, `RunOnce` | **high** | Windows reads the per-user copy too |
| `HKLM\SOFTWARE\<Vendor>\<App>` | **medium** | Only works if the app falls back to HKCU |
| `HKLM\SOFTWARE\Policies\*` | **low** | SYSTEM services read HKLM only, **and Group Policy refresh wipes `HKCU\Software\Policies` every ~90 min** |
| `HKLM\...\Active Setup\Installed Components` | **refuse** | HKLM registers components; HKCU records per-user completion, so the branches are not interchangeable |
| `HKLM\...\Explorer\(User )Shell Folders` | **refuse** | Set the existing HKCU profile, preferably through the Windows Known Folder API; machine/user value sets differ |
| `HKLM\...\Winlogon` | **refuse** | `Shell` and `Userinit` control machine logon; redirecting them can break sign-in |
| `HKLM\SYSTEM`, `HARDWARE`, `SAM`, `SECURITY` | **refuse** | No per-user equivalent exists |
| `*\UserChoice` | **refuse** | Protected by a per-SID hash since Windows 8; file associations cannot be set from a `.reg` |

`SOFTWARE\WOW6432Node\X` is normalised to `SOFTWARE\X` before classification, so
32-bit and 64-bit exports of the same app collapse onto one destination. That
collapse is why every redirect run is followed by a **coalesce** pass
(case-insensitive, last write wins) — without it, redirection emits duplicate key
blocks.

---

## Offline Hive Engine (`regx hive`)

`RegLoadKey` — what `reg load` and regedit's *Load Hive* use — requires
`SeRestorePrivilege`, which a standard user's token does not hold.
**`RegLoadAppKeyW` does not.** It mounts the hive into a private slot visible
only to the calling process, so there is no global namespace entry to protect and
no privilege to check.

### Why there is no separate `mount` / `unmount`

The handle is **process-scoped**: closing it — including at process exit —
unloads the hive. So this cannot work:

```
regx hive mount NTUSER.DAT --as my_hive   # process 1 exits -> hive unloaded
regx hive set my_hive\Software\App ...    # process 2: nothing is mounted
regx hive unmount my_hive                 # process 3: nothing to unmount
```

There is no supported workaround: the handle cannot be published to the registry
namespace (that is exactly what the privilege check guards), and inheriting it
would require a resident daemon, which defeats "portable, no install".

Mount / operate / unmount therefore happens inside one process:

```bash
regx hive "C:\path\MyApp.hive" --create exec -c "set Software\MyApp -v License -d OK" -c "set Software\MyApp -v Seats -t REG_DWORD -d 25" -c "query Software\MyApp -r"
```

`--script FILE` reads the same operations one per line (`#` comments). Single
operations need no `exec`:

```bash
regx hive "C:\path\MyApp.hive" export Software --to json -o offline.json --root-as "HKEY_USERS\OFFLINE"
regx hive "C:\path\MyApp.hive" search Software license --field name
regx hive "C:\path\MyApp.hive" diff Software\MyApp desired.reg --strip-root HKCU --exit-code --to json -o drift.json
regx hive "C:\path\MyApp.hive" -y sync desired.reg --strip-root HKCU --conflicts error --prune --prune-keys --backup sync.undo.reg
regx hive "C:\path\MyApp.hive" -y copy Software\MyApp Software\MyApp.Backup --backup copy.undo.reg
regx hive "C:\path\MyApp.hive" -y move Software\MyApp.Backup Software\MyApp.Renamed
regx hive "C:\path\MyApp.hive" -y undo copy.undo.reg --backup copy.redo.reg
```

`copy` and `move` preserve the complete subtree, refuse an existing destination
unless `--overwrite` explicitly requests a merge, reject a destination inside
the source, consult administrative deny rules before prompting, and roll both
source and destination back if either phase fails. `copy-value` and
`move-value` provide the same workflow for one value without copying siblings.
`search` uses the same bounded substring, glob, and Unicode-regex matcher as
live/file search, including field selection, path include/exclude filters,
case-sensitive mode, value-name include/exclude filters, result limits,
truncation reporting, and strict JSON. Repeat `--value GLOB` and
`--exclude-value GLOB` to search only selected values; `@` selects the default
value, and activating value scope intentionally omits key-only matches.
`diff` compares a hive subtree directly with any supported registry-data file, can scope the
comparison with include/exclude globs, returns exit 5 as a drift gate, and
writes an applicable patch that turns the hive state into the desired state.
It also accepts repeatable `--value`/`--exclude-value` globs with the same
value-only safety rule as top-level `diff`: structural key changes are omitted,
so selected deletions preserve unselected siblings.
`sync` reconciles declared keys directly inside the hive. `--prune` removes
undeclared sibling values and `--prune-keys` removes unrepresented child
subtrees; every generated delete is policy-checked before confirmation, and a
complete in-memory inverse automatically restores partial failures.
`hive diff`, `hive import`, and `hive sync` use the same content-first readers
as their live/file counterparts, including `--from`, Registry.pol root, INF
section/language, and ADMX policy selectors. Mutations refuse semantic fidelity
losses before snapshotting. `hive import` and `hive sync` also accept
`--conflicts error`; duplicate
value/key-state disagreements are rejected after root stripping but before the
private hive is snapshotted or changed. Live `batch` applies the same policy to
collisions introduced inside an operation by Smart Redirection.
`hive export` completes the reverse path with
`--to reg|json|csv|pol`. Every format receives the explicit `--root-as` key
because an application hive has no permanent registry namespace; unsupported
Registry.pol states such as default-value mutation are rejected before an
artifact is created. `--no-recursive` restricts the snapshot to the requested
key, while repeatable `--include`/`--exclude` key-path globs and
`--value`/`--exclude-value` globs select paths and named or default
values without carrying key-create/delete operations into a value-only export.
An empty selection returns exit 8 and creates no artifact; JSON counts describe
the filtered output rather than the pre-filter hive read.
Application-hive handles have one namespace rather than separate WOW64 views,
so hive operations reject `--view 32`, `--view 64`, and `--view both`.
Every hive mutation honors normal confirmation and administrative
`RequireConfirm`; `-y` only bypasses prompts when policy permits it.
Set, delete, import, sync, subtree copy/move and value copy/move all capture a
complete inverse before the prompt and use it for audited automatic rollback.
After confirmation they also persist that exact inverse: `--backup FILE`
selects the path, input-driven operations default beside their input, and other
operations use a collision-resistant temporary file. Reapply any such artifact
with `hive HIVEFILE undo UNDO.reg -y`; the command removes the snapshot's HKCU
mount label automatically and writes a fresh redo snapshot before restoring.
JSON reports `undo` for ordinary mutations and `redo` for `hive undo`, alongside
exact `undoBytes`/`undoSha256` or `redoBytes`/`redoSha256`; dry-run uses null
evidence because no artifact is persisted.
`apply`, `rolledBack`, and `rollback`, rather than hiding
compensation behind a generic partial exit. Dry-run and cancelled operations
write no undo artifact.

### What a standard user can realistically open

Write access to the *file* is still required, and a hive already mounted by the
OS is held exclusively. Realistic targets: a logged-off secondary profile, a
**copy** of a hive, an application's private hive, or a hive on a mounted backup
or VHD. A logged-on user's `NTUSER.DAT` fails with `ERROR_SHARING_VIOLATION` by
design; `regx hive <file> info` reports this before you commit to a write.

---

## `validate --fix`

Repairs the damage `.reg` files pick up from forums, chat clients and blog code
blocks. Safe repairs are applied silently; **lossy** ones are applied but labelled.

| Defect | Repair | Class |
|---|---|---|
| `hex(1)/hex(2)/hex(6)` missing NUL terminator | append `00,00` | safe |
| `hex(7)` missing double NUL | append until double-NUL terminated | safe |
| Trailing whitespace after a `\` continuation | removed (regedit stops folding there and drops the rest of the payload) | safe |
| Control characters in a key path or value name | stripped | safe |
| Empty path components (`A\\\\B`) | collapsed | safe |
| Duplicate key blocks | coalesced, last write wins | safe / lossy if values conflict |
| Odd-length UTF-16 payload | padded with one NUL byte | **lossy** |
| `hex(4)` / `hex(b)` of the wrong length | **not** repaired — reported | — |

`--fix` refuses to run on a file with *syntax* errors: repairing those means
guessing the author's intent, not fixing a known defect.
It accepts exactly one input per invocation, so a later invalid file can never
leave an earlier file repaired as a partial multi-file operation. Plain
read-only `validate` still accepts several `.reg` files; use `inspect` for
structural and fidelity validation of any other supported format.
With `--output json`, a requested repair also returns `repairedData`: the full
lossless registry-data model that would be or was written. `--dry-run` therefore
lets automation consume repaired type IDs and raw bytes without rewriting the
source or interpreting human fix messages. The field is `null` for read-only
validation and syntax-error refusal. A written repair also reports its exact
`output`, `bytes`, and lowercase `sha256`. In-place `--backup` reports and
seals the backup independently; artifact fields remain null for validation-only,
no-op, refused, and dry-run results.

---

## Undo engine

`import` and `sync` compute the inverse of the pending change **before** writing
anything and save it as an ordinary `.reg` file beside the input. Its default
name starts with the input stem and carries the same PID/nanosecond/sequence
identity used in `%TEMP%`; concurrent operations on one input therefore keep
separate inverses. Use `--backup FILE` when automation needs a stable explicit
path. The registry offers no transaction, so this is the compensation.

- `[-KEY]` that exists → the whole subtree is exported, so undo recreates it
- key exists, value exists → current data recorded
- key exists, value absent → `"name"=-` recorded
- key does not exist → `[-TOPMOST_MISSING_ANCESTOR]`, not `[-KEY]` — deleting only
  the leaf would leave the intermediate keys we are about to create behind

Restores are ordered before removals. If any key could not be read, the undo file
is reported as **INCOMPLETE** rather than silently trusted.

---

## Getting past AppLocker / SRP / WDAC

UAC is not the real obstacle in a locked-down enterprise; application control is.
An unsigned `.exe` under `%TEMP%`, `Downloads` or `%APPDATA%` is precisely the
shape the default rule sets deny. `regx --self-check` reads the relevant policy
keys (all readable by a standard user) and reports what applies here.

**In order of what actually works:**

1. **Sign the binary.** A publisher rule follows the file anywhere; a path rule
   does not. An **EV code-signing certificate** additionally gives immediate
   SmartScreen reputation — a standard OV certificate has to accumulate it, so
   early downloads still see the "unrecognised app" interstitial.
   In a managed environment, a certificate from the organisation's **internal CA**
   is usually faster to obtain and is already trusted domain-wide; AppLocker
   publisher rules accept it.

   ```bash
   signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a target\release\regx.exe
   ```

   Always timestamp (`/tr`): without it, signatures stop validating when the
   certificate expires.

2. **Run from a path the policy already allows** — typically `%ProgramFiles%` or
   an IT-managed share — rather than from `Downloads`.

3. **Clear the Mark-of-the-Web** on a downloaded copy (`Unblock-File`), which is
   what triggers the SmartScreen interstitial. `--self-check` reads the
   `Zone.Identifier` stream and reports `ZoneId`.

**WDAC is different from the other two:** it ignores file location entirely. If a
user-mode code-integrity policy is deployed, only a signature or an explicit hash
rule will let the binary run — points 2 and 3 do not help. `--self-check`
distinguishes this case and deliberately does *not* warn merely because
`CodeIntegrity\CiPolicies\Active` is populated: stock Windows 11 ships
driver-blocklist policies there by default, and warning on their presence would
cry wolf on nearly every machine.

---

## Design notes

- **Byte-exact round-trip.** Values that cannot be losslessly modelled stay raw
  `hex(N)` bytes. A `REG_SZ` is only written as a quoted string when it is clean
  UTF-16 — even length, single trailing NUL, no embedded NUL, no control
  characters — because a raw newline in a `.reg` file corrupts the next line.
- **Escapes.** `.reg` has exactly two: `\\` and `\"`. There is no `\n` or `\t`.
- **Encoding.** `Version 5.00` is UTF-16LE with BOM; `REGEDIT4` is ANSI in the
  machine's codepage, decoded via `MultiByteToWideChar(CP_ACP)` so behaviour
  matches regedit. Output rejects best-fit/default-character substitution; use
  Version 5.00 when a name or string is not representable.
- **WOW64 is always explicit.** Every open/create passes an explicit
  `KEY_WOW64_*` bit, so behaviour never depends on how the binary was built.
- **Registry virtualization does not apply.** With an explicit manifest, LUAFV is
  off — an HKLM write returns `ACCESS_DENIED` rather than being silently
  redirected to `VirtualStore`. That honest error is what Smart Redirection reacts to.
- **Export never aborts on a denied subkey.** Partial export of your own hive is
  normal (GP-locked policy keys, `Protected` subtrees); skips are listed.

## Project and support

- [Roadmap](ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Support](.github/SUPPORT.md)
- [Security policy](SECURITY.md)
- [Current audit and backlog](docs/PROJECT_AUDIT.md)
