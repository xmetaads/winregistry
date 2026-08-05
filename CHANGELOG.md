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
- **`--output json` shapes** for `query`, `probe`, `permissions`, `diff`,
  `inspect`, `discover`, `search`, `stats`, `fingerprint`, `watch`, `plan`,
  `copy`, `move`, `formats`, `lnk create`, `lnk inspect`, `lnk delete`,
  `lnk apply`,
  `apply-plan`, `apply-copy-plan`, `batch`, offline-hive operations and
  `--self-check`.
- **Command and flag names**, and the meaning of `--dry-run`: it performs every
  read, so permission problems still surface, and no write of any kind.
- **The `.reg` files written** by `export`, `convert` and the undo snapshot:
  UTF-16LE with a BOM, CRLF, byte-compatible with `regedit`'s own output.

Human-readable stdout and stderr text is *not* part of the contract. Parse the
JSON.

## [0.3.0] - 2026-08-05

### Added

- Native Windows Shell Known Folder resolution for `shell:Startup`,
  `shell:Desktop`, and `shell:Programs` in path-bearing CLI arguments and
  shortcut manifests. Resolution uses `SHGetKnownFolderPath`, with
  `SHGetFolderPathW` as the compatibility fallback; no shell or environment
  script is invoked.
- `lnk create`, `lnk inspect`, and `lnk delete` implement Unicode Windows Shell
  Links through `IShellLinkW` and `IPersistFile`. Target, arguments, working
  directory, description, icon path/index, and normal/hidden/minimized show
  styles round-trip through native COM before an atomic commit.
- `lnk apply` parses repeated `[SHORTCUT]` and `[DELETE_SHORTCUT]` blocks from
  UTF-8/UTF-16 files, stdin, or Windows named pipes. It preflights the complete
  manifest, rejects duplicate destinations, confirms once, and rolls back
  earlier changes if a later action fails.
- Shortcut writes support `--dry-run`, `-y`, JSON output, and tamper-evident
  audit events with exact artifact SHA-256 evidence. Public JSON Schema,
  `capabilities.json`, and `llms.txt` make the feature contract discoverable by
  individuals, enterprises, and AI agents.

## [0.2.0] - 2026-07-30

The first binary release. Everything below was developed after `0.1.0`; the
`v0.2.0` tag binds these notes to the matching Cargo package and release
artifacts.

### Added

- File-reading commands accept bounded, one-shot Windows Named Pipe input via
  `pipe:NAME`, `\\.\pipe\NAME`, or `//./pipe/NAME`, in addition to stdin.
  Connections time out after five seconds and registry-data streams are capped
  at 64 MiB. Mutations require `-y`, repairs require `--out`, and saved plans
  reject non-reverifiable streams. Real process-to-process IPC, timeout, and
  size-bound tests cover the contract.
- `stats` now accepts the same repeatable key-path and value-name include/
  exclude globs as scoped fingerprint/export across file, live, remote,
  dual-view, and offline-hive sources. JSON binds the scope to `matched` and
  the resulting metrics; an empty scope exits 8 rather than reporting a
  misleading successful zero summary.
- Live, remote, dual-view, and offline-hive `stats` now accept `--root-as` with
  the same portable mapping semantics as fingerprint/export. Filters run after
  mapping, `maxDepth` remains relative to the mapped requested subtree, JSON
  records `rootAs`, and ambiguous multi-root file inputs reject the option.
- `fingerprint` computes a canonical, domain-separated SHA-256 over exact
  registry paths, names, numeric types, raw payloads and deletion state without
  printing value data. It accepts files, stdin, local/remote live keys and
  independent WOW64 views; `hive fingerprint` provides the same v1 contract
  offline. Source ordering is irrelevant, while type or payload drift changes
  the digest. `--expect` turns file/single-view/hive checks into an exit-code
  gate; dual-view checks require the complete `--expect-32`/`--expect-64` pair
  and return exit 5 on drift. Repeatable key-path
  `--include`/`--exclude` and value-name `--value`/`--exclude-value` globs
  scope the canonical state; JSON records the scope and selected counts, while
  an empty scope exits 8 with `matched:false`.
  Live/remote fingerprint also accepts `--root-as KEY`; offline
  `hive fingerprint` rebases the mounted hive root with the same option before
  scope and hashing. This makes migration fingerprints portable across roots.
  File sources reject the ambiguous option. A cross-format test proves a
  rebased hive and its rebased REG export produce the same digest.
- Every offline-hive mutation result now seals its persisted undo with exact
  byte length and SHA-256; `hive undo` does the same for redo. This covers
  set/delete/import/sync/subtree/value copy/move, while dry-run uses null
  evidence.
- Direct subtree/value copy/move and `apply-copy-plan` JSON results now seal
  each persisted per-view undo with exact byte length and SHA-256, across
  single/dual-view and result schema v1/v2 contracts. Dry-run uses null
  evidence.
- Live and offline-hive batch results now seal each persisted per-view undo
  with exact byte length and SHA-256. Dry-run retains the planned undo entries
  with null evidence instead of returning an information-free empty array.
- `undo --output json` now seals every newly persisted per-view redo snapshot
  with exact byte length and SHA-256. Dry-run exposes null redo evidence.
- Machine-readable `set`, `delete`, `import`, `sync`, and `apply-plan` results
  now identify and seal every persisted per-view undo with exact byte length
  and SHA-256. Dry-run and `--no-backup` expose null evidence. `apply-plan`
  previously persisted undo files without reporting their paths in JSON.
- Subtree and value `copy`/`move --save-plan --output json` now seal every
  persisted plan with exact byte length and SHA-256, independently for paired
  WOW64 artifacts. The value saved-plan shape is now represented by the
  published CLI schema instead of falling outside its mutation-only contract.
- `plan --save --output json` now reports the persisted saved-plan path, exact
  byte length, and SHA-256 for both single- and dual-view plans. The fields are
  null when no artifact exists.
- Audit rotation and detached-anchor JSON now seal the persisted archive or
  anchor with its exact byte length and SHA-256. Dry-run returns explicit null
  artifact evidence.
- Successful `backup --output json` reports the exact byte length and SHA-256
  of every created application hive, including both WOW64 artifacts. Dry-run
  returns explicit null evidence instead of implying that the planned path has
  already been sealed.
- File-backed `export --output json` now provides the same exact byte length
  and SHA-256 evidence for single- and dual-view REG/JSON/CSV/Registry.pol
  artifacts. Dry-run and inline-data views return explicit null evidence.
- File-backed live and offline-hive `diff --output json` now seals each
  generated patch with its exact byte length and SHA-256, including independent
  dual-view artifacts. Omitted, dry-run, or incomplete-source patches expose
  null evidence. Single-view diff now writes before emitting success JSON, so
  a writer failure cannot leave a false successful document on stdout.
- `validate --fix --output json` now seals the written repair and optional
  in-place backup independently with output path, exact byte length and
  SHA-256. Validation-only, no-op, refused, and dry-run reports use null
  evidence. `--backup` no longer emits a text line before the JSON document.
- `restore --output json` now records the exact byte length and SHA-256 of its
  persisted undo snapshot, independently for both WOW64 views. Dry-run returns
  explicit null undo evidence.
- `discover --output json` now carries the resolved executable and anchor,
  enabled policy/registry/strict controls, explanatory notes, every candidate
  path probed but absent, and the aggregate risky-hit count. Machine consumers
  can audit search provenance without parsing text or depending on
  `--verbose`. Each hit also distinguishes the searched candidate from its
  canonical resolved target and pairs stable risk names with human-readable
  explanations.
- `diff --map-a FROM=TO` and `--map-b FROM=TO` compare equivalent registry
  subtrees across different roots and emit patches at the mapped destination.
  Mapping is validated against every key and fails closed on malformed or
  out-of-scope inputs.
- Repeatable `diff --value GLOB` and `--exclude-value GLOB` scope drift and
  patches to value names. Structural key changes are omitted whenever value
  selection is active, so a selected deletion cannot remove unselected sibling
  values even when the target key is absent. `hive diff` provides the same
  semantics for offline application hives.
- `query --output json` now embeds a lossless `exact` object beside its
  compatible type/data preview. Strings and DWORDs retain their JSON types;
  other values expose the numeric registry type ID and exact raw bytes across
  live, remote, dual-view, and offline-hive queries.
- `search --output json` now carries the same exact registry-value object for
  every name/type/data match, including unknown type IDs and malformed raw
  string bytes. Key-only matches explicitly use `exact: null`.
- Top-level and offline-hive `search` accept repeatable `--value GLOB` and
  `--exclude-value GLOB` selectors. Value scope is case-insensitive, uses `@`
  for the default value, suppresses key-only matches, and is reported explicitly
  in versioned JSON output.
- JSON value diffs now include lossless `leftExact` and `rightExact` payloads
  beside compatible previews. Added/removed sides use null, while present
  values preserve numeric type IDs and raw bytes across all diff modes.
- Unredacted `plan --output json` before/after states now embed an exact
  registry-value object beside their preview. Redacted plans remain digest-only
  and never expose the exact payload.
- `inspect --output json` conflict evidence now includes lossless
  `oldExact`/`newExact` registry values beside previews and source lines.
  Structural whole-key conflicts explicitly use null payloads.
- Streaming `watch --output json` value changes now include lossless
  `leftExact`/`rightExact` snapshots. Automation receives the value associated
  with the notification without a race-prone follow-up query; added and removed
  sides remain explicit nulls.
- A scheduled deployed-website smoke test compares winregistry.org with the
  reviewed HTML, CSS, scripts and social image, and verifies Vercel security
  headers, clean-URL redirects and the real 404 response. Local static checks
  additionally pin the truthful pre-release/version/platform claims so the
  currently deployed stale v0.1 page cannot be reintroduced silently.
- `validate --fix --output json` now includes `repairedData`, the complete
  lossless registry-data model that would be or was written. Dry-run repair
  consumers receive numeric type IDs and exact raw bytes without modifying or
  re-reading the source; read-only validation and syntax refusal use null.
- `inspect --output json` now embeds `data`, the complete lossless parsed
  registry-data model, alongside format/loss/conflict evidence. Retained keys,
  numeric type IDs and raw bytes remain available for an incomplete source
  even when `convert` correctly refuses to emit it as a safe artifact.

- **Multi-format offline-hive export.** `hive export --to
  reg|json|csv|pol` completes the offline round-trip pipeline. `--root-as` is
  now validated as an absolute registry key and is applied to the data model
  for every serializer, rather than being a REG-only display substitution.
  Strict status JSON reports the selected format; incomplete reads exit
  partial, and unrepresentable Registry.pol states create no artifact.
  `--no-recursive`, repeatable `--include`/`--exclude` key-path globs, and
  `--value`/`--exclude-value` value-name globs provide
  the same bounded snapshot workflow offline; no-match exits 8 without output
  and status counts are computed after filtering.
- **Live and remote key listing.** Top-level `ls` lists immediate child keys
  without exposing value payloads; `-r` walks descendants. It supports native,
  32-bit, 64-bit and dual views plus read-only remote HKLM/HKU, with strict
  per-view JSON and partial ACL evidence. Offline `hive ls` now follows its
  documented subkey semantics instead of echoing the requested key when
  recursion is disabled. Both forms support repeatable key-path
  `--include`/`--exclude` globs and a per-view `--limit` (default 1,000), with
  explicit machine-readable truncation instead of unbounded recursive output.
- **All-format offline-hive desired state.** `hive diff`, `hive import`, and
  `hive sync` now read REG, Registry.pol, ADMX/ADML, GPP XML, INF, JSON, CSV,
  and INI through the shared content-first pipeline and expose its format
  selectors. Mutating operations reject semantic fidelity losses before
  snapshot, confirmation, undo, audit, or hive writes; diff reports ambiguous
  input as incomplete and refuses patch output.
- **Multi-format, atomic dual-view diff patches.** `diff` and offline
  `hive diff` now accept `--to reg|json|csv|pol` for `-o` artifacts. Status
  JSON declares the requested format and whether the patch was actually
  written. Dual-view comparison preflights both patches and writes neither
  when either view fails, is incomplete, or contains ambiguous source data.
- **Multi-format live export.** `export --to reg|json|csv|pol` now writes live
  registry snapshots directly in every round-trip output format. Paired WOW64
  exports preserve `.32`/`.64` artifact names, while
  `--output json --out FILE` continues to emit status JSON independently of
  the selected artifact format. `--no-recursive` fixes the previously
  unavoidable recursive default. Single- and dual-view status now declare the
  effective scope, output format and value globs, with key/value counts
  computed from the filtered artifact rather than the pre-filter read.
  `--root-as KEY` validates and rebases the source subtree in the shared model
  before every serializer, including paired WOW64 output, so migration
  artifacts no longer require unsafe post-processing of serialized paths.
- **Cross-format merge.** `merge` now reads every supported registry-data
  format through the shared content-first pipeline, exposes the policy-reader
  selectors, and refuses any source with semantic fidelity losses before
  creating output. `--to reg|json|csv|pol` writes directly through the shared
  round-trip writers, eliminating an intermediate convert step. REG output is
  V5 regardless of input order unless `--reg4` is explicitly requested;
  `--reg4` is rejected for every non-REG destination.
  `--conflicts error` additionally gives unattended pipelines a fail-closed
  mode: different assignments to the same case-insensitive key/value, as well
  as key create/delete disagreements, are reported and rejected before any
  output artifact is created.
  The same policy now applies to `import`, `sync`, and `plan`: reader-level
  conflicts inside one source and conflicts introduced by combining or Smart
  Redirection are retained as structured evidence and rejected before live
  registry reads, undo/audit artifacts, prompts, or saved-plan output.
  Offline `hive import` and `hive sync` now enforce the same policy after
  strict root stripping and before snapshot/mutation. Live `batch` can also
  reject conflicts introduced inside an operation by Smart Redirection.
  `convert` completes the artifact pipeline coverage by rejecting reader-level
  or post-redirection conflicts before file or stdout output.
- **Structured conflict inspection.** `inspect --output json` now exposes every
  semantic conflict as a strict path/value/line/old/new object instead of only
  a summary note. Text output prints the same evidence, and ambiguous input
  exits `5` while remaining fully inspectable.
- **Ambiguous-source propagation.** File-backed `diff` and `search` now treat
  retained semantic conflicts as incomplete input, set their existing JSON
  `incomplete` gate, and exit `5`. Diff refuses to write an applicable patch
  from incomplete or ambiguous sources instead of presenting a partial model
  as a safe repair.
- **Atomic validate repair boundary.** Read-only `validate` still lints several
  `.reg` files, while `validate --fix` now accepts exactly one input. A later
  invalid file can no longer leave earlier inputs rewritten as a partial
  multi-file repair. `inspect` remains the validator for all eight formats.
- **Registry.pol output.** `convert --to pol` now writes version-1 PReg binary
  output to a file or stdout. HKCU/HKLM value writes, default/named deletes,
  DWORDs, Unicode strings, protocol-defined raw types, empty keys, named-value
  and subtree deletes round-trip without drift. Mixed roots, implicit-root or
  default-value mutation, undefined types and payloads above 65,535 bytes fail
  before output. Delete
  directives use Microsoft's required REG_SZ single-space payload rather than
  a self-consistent but Windows-incompatible empty REG_NONE record.
- **Fail-closed Registry.pol fidelity.** Conditional `**soft`, value-only wipe
  `**delvals`, ACL, and unknown directives are exposed as inspection losses.
  Conversion and live/offline mutation refuse them instead of widening their
  meaning into unconditional writes or whole-key deletion.
- **Cross-format fidelity boundary.** ADMX administrator-supplied elements,
  GPP value Create, key Replace, bitfield updates, item-level targeting,
  remove-when-out-of-scope lifecycle,
  malformed GPP/INF items, INF
  conditional/append behavior, and per-line WOW64 routing now surface through
  the same strict `inspect.losses` contract. Conversion and mutation refuse the
  incomplete model. GPP now distinguishes key items from default values via
  `default="1"` and preserves exact key C/U, value R/U and delete actions.
  `RegistrySettings disabled="1"` skips the complete preference type as the
  protocol specifies; a non-schema item-level `disabled` attribute is rejected.
  GPP fragments are accepted only when rooted at `RegistrySettings`,
  `Collection`, or `Registry`, and the reader follows only valid collection
  nesting instead of discovering registry-looking elements under arbitrary XML.
  Content detection now uses that parsed XML root too: extensionless or renamed
  `Collection`/single-`Registry` fragments are recognized, while nested tag
  substrings no longer misclassify unrelated XML as GPP or ADMX.
  INF custom `0xTYPE0001` raw types preserve their numeric ID and bytes, while
  referenced section security descriptors are explicitly fidelity losses.
  Undefined or unterminated INF `%strkey%` references now fail closed across
  section names, subkeys, value names, and data; only the documented `%%`
  escape produces a literal percent.
  `--inf-language LANGID` selects locale-specific `[Strings.LanguageID]`
  sections using Windows' exact, neutral, same-language-family, then
  undecorated fallback order; without it regx deliberately uses `[Strings]`.
  Physical INF lines ending in an unquoted `\` are folded with their original
  starting line number. `[Strings]` now preserves quoted edge whitespace and
  semicolons, condenses `""`, strips only the outer quote pair, and reports
  duplicate, malformed, or unterminated definitions instead of last-write-wins.
  CSV also preserves quoted edge spaces in names and data
  and rejects rows without a key instead of silently dropping them.
- **First-class reversible undo.** `regx undo FILE` restores a generated
  snapshot with redirection forcibly disabled and captures a redo snapshot
  before touching the registry. Dual-view bundles accept either their base or
  a `.32.reg`/`.64.reg` member, require both members, and restore both views
  under one confirmation and cross-view rollback boundary. JSON reports the
  exact redo path for every view under the semantically distinct `redo` field.
- **First-class offline-hive undo.** `regx hive HIVEFILE undo FILE` replaces
  the error-prone `import --strip-root HKCU` recovery recipe. It removes the
  generated mount label automatically, applies administrative policy and
  confirmation, captures a redo snapshot before writing, audits the mutation,
  and automatically rolls back a partial restore. Its strict JSON contract
  likewise reports `redo`, never a misleading second `undo`.
- **Undoable direct mutations.** Live `set` and `delete` now require the shared
  confirmation gate and persist the same complete inverse used by automatic
  rollback. `--backup FILE` selects the artifact, dual-view mode writes paired
  `.32.reg`/`.64.reg` files, and JSON reports each exact path. Cancellation is
  an executable no-side-effect contract: neither registry state nor the
  requested backup changes before acceptance.
- **Collision-resistant temporary undo allocation.** Every live and
  offline-hive mutation that defaults to `%TEMP%` now shares PID,
  nanosecond-time, and atomic-sequence naming. This replaces fixed stdin and
  millisecond-only paths that concurrent commands could overwrite. A
  4,096-allocation threaded test proves uniqueness without filesystem side
  effects, and a real `hive exec` proves consecutive mutations expose distinct
  restorable paths.
- **Collision-resistant source-adjacent undo allocation.** Import, sync,
  batch, saved-plan apply, copy-plan apply, and offline-hive input operations
  no longer converge on one predictable `<stem>.undo.reg`. Their automatic
  artifact stays beside the source but carries the same process/time/sequence
  identity; `--backup FILE` remains the explicit stable-path contract.

- **Persistent undo for every offline-hive mutation.** `hive set`, `delete`,
  subtree/value copy and move, `import`, and `sync` now persist the exact
  complete inverse already used for automatic rollback. `--backup FILE`
  selects its location, JSON reports it, dry-run/cancellation writes nothing,
  and a real application-hive test reapplies the artifact through
  `hive undo` to prove restoration and redo preservation.

- **Atomic offline-hive batches.** `hive batch` applies the existing versioned
  JSON manifest under one private mount. It strictly re-roots and policy-checks
  every operation before writing, captures and persists one shared inverse,
  reports per-operation native-view outcomes, and rolls the whole batch back
  after a partial failure. Hive-root deletion is now refused during preflight
  on every mutation path instead of allowing a manifest to empty the mount.

- **Offline-hive access diagnostics.** `hive probe` checks existence and
  effective read/write/create access without changing the hive, while
  `hive permissions` reports owner SID, DACL inheritance, SDDL, and effective
  query/enumerate/notify/set/create/delete rights for one mounted subkey. Both
  use strict versioned JSON contracts and are exercised against a real private
  hive.
- **Offline-hive drift comparison.** `hive diff` compares a private-hive
  subtree directly with a desired `.reg`, shares scoped include/exclude and
  summary semantics with the main diff engine, supports exit-code gating, and
  emits an applicable patch. A real-hive contract applies that patch and proves
  the next comparison is clean.
- **Offline-hive reconciliation.** `hive sync` applies a `.reg` desired state
  directly to an application hive. Optional `--prune` and `--prune-keys`
  generate value/subtree deletes only after complete enumeration, re-run
  administrative policy over those generated mutations, snapshot every
  affected path, and automatically roll back a partial apply.
- **Offline-hive search.** `hive search` applies the same substring, glob, and
  bounded Unicode-regex semantics as file/live search to private application
  hives, including field selection, case-sensitive mode, path include/exclude
  filters, limits, truncation/incomplete reporting, and versioned JSON output.
- **Offline-hive subtree copy/move.** Application hives now support complete-
  subtree copy, move, and rename with explicit merge via `--overwrite`,
  recursive self-destination rejection, administrative deny checks,
  dry-run/JSON/audit output, complete preflight snapshots, and automatic
  two-phase rollback.
- **Repository operations.** Structured bug/feature forms, a pull-request
  safety checklist, CODEOWNERS, support guidance, a public roadmap, weekly
  Cargo/Actions dependency updates, CodeQL scanning, and a post-release
  checksum/provenance/binary smoke workflow. Artifact upload/download actions
  use their Node.js 24-native major versions, removing GitHub's Node.js 20
  deprecation warnings. The workflow checker now also requires ten community
  and security files and validates CODEOWNERS, private vulnerability routing,
  weekly Cargo/Actions Dependabot coverage, structured forms, and the PR safety
  checklist.
- **Fail-closed release asset preflight.** A dependency-free validator shared
  by local builds, CI negative tests, and the publish job checks exact asset
  inventory, complete unique checksums, AMD64/ARM64 PE machines, embedded
  `asInvoker`, static CRT, CycloneDX 1.5 identity/version, and the strict
  `<2 MiB` bound. Its self-test proves wrong architecture, tampering,
  elevation, SBOM drift, unexpected assets, and boundary-sized binaries fail.
- **Single-source release identity.** A second dependency-free validator now
  owns canonical semver tags, Cargo-version equality, dated changelog entries,
  non-empty Keep a Changelog notes, and the exact tag at `HEAD`. Preflight and
  publish call the same parser, and publish uses the notes it emits instead of
  reparsing with AWK. Six fixture cases cover valid identity and every failure
  boundary; the current intentionally `Unreleased` tree fails as expected.
- **Generated shell completion.** `completions` writes Bash, Elvish, Fish,
  PowerShell, or Zsh completion directly from the shipped Clap metadata.
- **Generated Unix manual.** A development-only generator recursively writes
  section-1 pages for the root and every nested command from the same metadata,
  without adding the renderer to the shipped executable.
- **Reproducible large-data benchmark.** A development-only harness measures
  `.reg`, `Registry.pol`, deep/wide application-hive writes, and recursive
  queries end to end, including throughput and peak working set.
- **Parser fuzzing.** Three libFuzzer targets with checked-in seeds cover raw
  `.reg` bytes, the bounded XML reader, and forced parsing through every text
  and PReg dialect. A deterministic 10,000-case mutation test runs without
  sanitizer dependencies, while a scheduled Linux/AddressSanitizer workflow is
  configured for 10,000 executions per target and on parser changes.
- **Strict byte decoding.** All text and policy readers reject truncated
  UTF-16, unpaired surrogates, and invalid BOM-marked UTF-8. Malformed
  `Registry.pol` string payloads remain byte-exact `hex(1)` values, and CLI
  conversion failures leave no partial output.
- **Two-sided remote diff.** `diff --computer-a/--computer-b` can compare
  remote HKLM/HKU against files, local registry state, or another remote
  computer, including independent 32/64-bit view results. Remote options remain
  read-only and fail before networking when attached to an invalid source.
- **Remote capability and ACL inspection.** `probe --computer` checks effective
  remote HKLM/HKU access without creating state. `permissions --computer` and
  `--compare-computer` independently locate both sides of an ACL comparison,
  with remote identity preserved in JSON output.
- **Remote-source application-hive backup.** `backup --computer` reads a remote
  HKLM/HKU subtree into a local native hive, including paired 32/64-bit
  artifacts. It never writes the remote registry and reports the source host in
  JSON.
- **Versioned command-output contracts.** A public Draft 2020-12 catalog maps
  every machine-readable command to its schema definition. Contract tests parse
  real CLI output and verify the catalog, published schema identities, and
  references.
- Core `probe`, `permissions`, `backup`, and `diff` schemas now reject unknown
  properties and wrong types at every newly versioned source/view/change
  boundary. Negative contract tests mutate valid instances to prove rejection.
- Registry-data schemas now model delete, `REG_SZ`, `REG_DWORD`, and raw
  type-id/byte values as mutually exclusive shapes instead of incorrectly
  requiring `type`, `typeId`, and `data` together. Apply, query, export, key,
  value, failure, and per-view objects are closed against unknown fields and
  exercised with real data-bearing CLI output.
- The remaining command contracts are now closed and typed through their
  nested objects, including plan, search, watch events, audit verification and
  rotation, discovery, offline-hive info/list/export, validation, formats,
  self-check, copy/move, and restore. This also corrects the discovery contract
  from a nonexistent `target` field to its real `anchor`/`stem` output.
- String-like raw registry data now uses strict UTF-16 for preview, policy
  lists, and data search. Well-formed `REG_EXPAND_SZ`/`REG_MULTI_SZ` remains
  human-readable; odd bytes and invalid surrogates fall back to lossless hex
  instead of fabricating replacement characters.
- `RegEnumKeyExW`/`RegEnumValueW` names now cross a strict UTF-16 boundary.
  Native malformed names return error 1113 and make the read incomplete rather
  than becoming a replacement-character path that could be queried or mutated
  under the wrong name.
- `Registry.pol` key and value names now use strict UTF-16 decoding. A malformed
  policy name is rejected instead of being rewritten and applied elsewhere.
- Added `copy-value` and `move-value` for copying, moving, or renaming one live
  registry value without touching siblings. They retain collision protection,
  undo, audit, dry-run, JSON, remote copy sources, dual-view atomic rollback,
  and equivalent private-hive operations.
- Copy-plan v2 extends digest-bound previews to value operations, including
  source/destination names, payload, remote identity, and current rollback
  state. The loader remains compatible with v1 subtree plans.
- Detached audit anchors can now be authenticated with `--anchor-key`. Signed
  v2 anchors use HMAC-SHA256 with constant-time verification; wrong or missing
  keys, edited signatures, and downgrade to unsigned v1 fail closed.
- The measured x64 executable grew with the value-operation safety path, so the
  truthful website/CI size contract is now `<2 MiB` rather than `<1.6 MiB`.
- **Administrative policy over regx itself.** Read from
  `HKLM\SOFTWARE\Policies\regx` and nowhere else — a standard user can write
  to HKCU, so honouring a per-user copy would let the restricted party lift
  their own restrictions. An administrator can mandate an audit log, force
  redaction, raise the redirection floor, deny key prefixes, disable the
  offline hive engine and take away `-y`. A flag may make policy stricter,
  never looser. An ADMX template ships in `policy/`, and `regx inspect` reads
  it with the same reader used for anyone else's.
- **Tamper-evident audit log.** `--audit-log FILE` (or `REGX_AUDIT_LOG`, so it
  can be enforced machine-wide) appends one JSON object per registry mutation:
  timestamp, actor SID taken from the process token rather than the settable
  `%USERNAME%`, operation, and the value before as well as after. Records are
  hash-chained, so altering or removing a line breaks the chain and
  `regx audit FILE` reports where. A `--dry-run` is recorded as `simulated`,
  and failed attempts are recorded with their error.
- `audit --rotate-to ARCHIVE` refuses broken logs and existing archives,
  preserves the old bytes, and starts a new segment whose hashed marker binds
  the previous tail and whole-file SHA-256. `audit FIRST --chain NEXT...`
  verifies continuity and detects edited, omitted, or reordered segments.
- `audit --write-anchor FILE` atomically creates a detached checkpoint binding
  the complete log digest, tail record, and record count.
  `--verify-anchor FILE` reports chain integrity and anchor equality separately,
  detecting a valid wholesale rewrite when the checkpoint is stored elsewhere.
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
- File-reading commands accept `-` once for stdin. Mutating stdin imports
  require `-y`, repeated stdin is rejected before the stream is consumed, and
  `validate - --fix` requires an explicit output path.
- `convert --to reg|json|csv|pol` emits registry data in a selected format. JSON
  and CSV carry numeric type ids and raw hex bytes for byte-exact round trips
  of malformed payloads and registry types unknown to regx.
- `search` filters any supported file, stdin, or live registry subtree by key
  path, value name, type, or full data payload. It supports Unicode-aware
  substring, glob and regex queries; repeatable glob include/exclude path
  filters; exact-case mode; and bounded text/JSON output. Regex compilation is
  size/nesting bounded. ACL-skipped live subkeys mark the result incomplete
  and exit `5`.
- `query`, `export`, and live-key `search` support read-only remote HKLM/HKU
  access with `--computer`, backed by `RegConnectRegistryW`. Unsupported hives
  and file sources are rejected before network access, and mutation commands
  do not expose the option.
- `copy --source-computer COMPUTER` performs remote-to-local copy while keeping
  the remote handle read-only. Saved copy plans bind and re-verify the remote
  computer and source content. `move` has no remote-source option, and artifact
  validation rejects any remote plan that contains source deletion.
- The PE now reserves an 8 MiB main-thread stack. The previous 1 MiB MSVC
  default was already near Clap's command-graph construction limit and could
  crash at startup as the CLI surface grew; reserved pages are not committed
  physical memory until used.
- `diff` now exposes incomplete live reads in JSON and exits `5`; previously it
  warned on stderr but still returned success.
- `diff` accepts repeatable, case-insensitive glob `--include`/`--exclude`
  path scopes and `--summary-only` for large trees. Counts, drift exit status,
  human/JSON output, and generated patch all use the same filtered scope;
  summary mode suppresses display details without emptying `-o` patch output.
- `plan` resolves import/sync into exact before/after mutations, redirect
  outcomes, policy decisions and rollback completeness without writing. It is
  backed by the same engine used for `--dry-run`.
- `plan --save FILE` emits a versioned, payload-digested artifact containing
  exact per-view desired mutations plus SHA-256 bindings for every named source
  and the relevant live state. `apply-plan` refuses payload tampering, source
  drift, current-state drift, incomplete rollback, or current policy denial
  before writing. A verified apply persists fresh per-view undo, audits every
  mutation, and rolls all touched views back atomically on failure. The v1 JSON
  Schema is published with the website.
- `batch MANIFEST` applies versioned schema-v1 operation groups in order with
  case-insensitively unique IDs and explicit per-operation JSON outcomes.
  Every target/view is snapshotted before the first write; a failure stops
  later operations and restores every touched view from one shared logical
  undo bundle. Dry runs validate and plan without writing that bundle.
- `copy` and `move` preserve a live registry subtree across keys or hives with
  collision refusal by default, guarded merge via `--overwrite`, policy and
  audit coverage, dry-run/JSON output, and one combined undo snapshot. A move
  deletes its source only after the destination phase succeeds completely.
  Partial copy or source-removal failures now automatically apply that combined
  snapshot instead of merely printing its path.
- `copy` and `move --save-plan FILE` write a versioned, payload-digested
  collision preview without registry mutation. The artifact binds source
  content, rebuilt destination payload, optional source deletion, selected
  view, and pre-write destination/current state. `apply-copy-plan` rejects
  payload tampering, source drift, destination drift, incomplete reads, and
  current policy denial before an audited atomic apply.
- `import` and `sync` now use their pre-write snapshot as an automatic
  compensation transaction. An incomplete snapshot stops the operation; a
  partial apply triggers immediate audited rollback. `--no-backup` remains the
  explicit non-atomic escape hatch, and JSON reports both phases.
- `import` and `export` support repeatable, case-insensitive value-name glob
  selection through `--value` and `--exclude-value`; `@` denotes the default
  value. Enabling selection omits empty-key creation and whole-key deletion
  blocks, so a value-scoped operation cannot escape into key scope. An export
  with no match exits `8` and writes no file.
- `sync --prune --prune-keys` performs complete desired-tree reconciliation,
  deleting only topmost live branches not represented by a declared path.
  It refuses incomplete ACL reads and routes generated deletes through policy,
  plan, undo, audit, and automatic rollback. `plan` supports the same preview.
- `watch` uses native `RegNotifyChangeKeyValue` notifications rather than
  polling, with recursive or key-only scope, bounded event count, idle timeout,
  exact snapshot diffs, and streaming lossless before/after JSON. Timed-out async
  registrations close their key before their event handle to cancel safely.
- `permissions` reads registry security descriptors without mutation and
  reports owner SID, DACL inheritance/protection, SDDL, and effective
  query/enumerate/notify/set/create-subkey/delete access. Both WOW64 views can
  be inspected independently in one JSON result. `--compare KEY` reports
  field-level drift, and `--exit-code` turns differences into exit `5`.
- Commands that cannot yet represent two independent registry views now refuse
  `--view both`. Previously the shared helper silently treated it as `native`,
  contradicting the CLI contract and risking one-view-only mutation.
- `query`, `probe`, and `permissions` now implement `--view both` with separate
  32-bit and 64-bit JSON/text results. `query -v NAME --output json` now applies
  the same value filter as text output and exits `8` when the value is absent.
- `export --view both` preserves WOW64 separation as `.32.reg`/`.64.reg` files,
  or emits both datasets and per-view failures in one JSON document.
- Live `search --view both` searches each WOW64 view independently and reports
  per-view matches, limits, truncation, ACL completeness, and failures.
- Live/file `diff --view both` compares both WOW64 views independently, reuses
  a file/stdin side safely, and writes separate `.32.reg`/`.64.reg` patches.
- `watch --view both` arms asynchronous Win32 notifications for both views,
  waits on both kernel events without polling, identifies the triggering view,
  and reports separate snapshot diffs.
- `backup --view both` preflights both WOW64 views, writes distinct
  `.32.hiv`/`.64.hiv` application hives, and removes the pair if either write
  fails.
- `restore --view both` validates a paired `.32.hiv`/`.64.hiv` backup, captures
  both rollback snapshots and undo files before mutation, and rolls back every
  touched view if either restore fails.
- `copy` and `move --view both` preflight both source/destination pairs, persist
  separate undo files, preserve the move copy-before-delete invariant per view,
  and roll back earlier successful views when a later view fails.
- Saved copy/move previews support dual-view `.32.json`/`.64.json` pairs.
  `apply-copy-plan --view both` verifies both source and current-state digests
  before mutation, then uses paired undo files and cross-view rollback.
- Release preflight binds the tag, exact commit, Cargo version, dated changelog,
  binaries, SBOM, notes, checksums, and post-publication version report to one
  release identity. The SBOM generator is version-pinned instead of floating.
- `set` and `delete` now implement atomic `--view both`: both rollback
  snapshots are captured before the first write, results are reported per view,
  and failure in either view restores every touched view in reverse order.
- `import` and `sync` now support atomic `--view both`, including
  `--prune --prune-keys`. Reconciliation computes a separate desired mutation
  for each view, captures both inverses once before mutation, persists distinct
  `.32.reg`/`.64.reg` undo files, and uses those same snapshots for
  reverse-order cross-view rollback.
- `plan --view both` emits independent changes, reconciliation failures,
  policy denials and rollback completeness for the 32-bit and 64-bit views.
- `backup` and `restore` provide a non-admin native application-hive workflow.
  Backups are genuine `regf` files that preserve keys, empty keys, types, and
  raw bytes; restore has collision refusal, policy, audit, undo, JSON, and
  automatic rollback. The interface explicitly does not claim to preserve
  ACLs, key classes, or timestamps because `RegSaveKeyEx` requires
  `SeBackupPrivilege`.
- `tests/unicode.rs`: 10 tests driving the binary with Vietnamese, CJK,
  Cyrillic, Greek, right-to-left Arabic and astral-plane text through every
  input format, the live registry and the audit log. The registry stores
  UTF-16, `.reg` is UTF-16LE and the text formats are UTF-8; each of those
  boundaries is a place text can be lost, and each is now crossed by a test.
- `tests/cli.rs`: 40 integration tests driving the built binary, covering exit
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
- Release and post-publication checks parse each executable's PE machine field
  (`0x8664` for x64, `0xAA64` for ARM64), and smoke verification validates
  GitHub provenance for both binaries rather than only the runnable x64 asset.
- Release collection rejects duplicate, missing, or unexpected executable/SBOM
  basenames instead of allowing `cp` to select the last collision. Smoke parses
  the checksummed SBOM and requires CycloneDX 1.5, component `regx`, and a
  version identical to the release tag.
- `ALLOW_UNSIGNED_PREVIEW=true` now permits only Authenticode `NotSigned`.
  Broken, hash-mismatched, or untrusted signatures fail publication and
  post-release smoke instead of being mislabeled as unsigned previews.
- SHA-256 implemented in-tree and validated against the NIST vectors, rather
  than adding a cryptographic dependency for the two places hashing is needed.
- `docs/SIGNING.md`, `SECURITY.md`, `CONTRIBUTING.md`, `deny.toml`,
  `rust-toolchain.toml`, and `scripts/check_site.py` / `check_vercel.py` moved
  into the repository so CI runs what a developer runs.

### Fixed

- The Windows Named Pipe integration-test producer now uses asynchronous
  connection waiting with a hard 10-second deadline instead of an unbounded
  `WaitForConnection`, and publishes a bounded readiness handshake before the
  client starts so a cold PowerShell launch cannot consume regx's five-second
  connection window. CI also caps x64 and standard-user jobs at 30 and 15
  minutes, so a failed client or runner cannot leave the workflow hanging for
  hours.
- The executable-output schema harness now evaluates `allOf`,
  `unevaluatedProperties`, regex patterns, schema-valued additional
  properties, unique arrays, and `if`/`then` conditions instead of silently
  skipping those published constraints. Stats schema composition no longer
  rejects its legitimate file/hive extension fields under a conforming Draft
  2020-12 evaluator.
- **Cancelled mutations no longer write undo artifacts.** Eleven live and
  offline mutation paths had captured a correct inverse but persisted it before
  asking for confirmation. Import, batch, saved-plan apply, subtree/value
  copy/move, restore, copy-plan apply, and offline-hive batch now perform every
  preflight read first, ask once, and only then write the undo file immediately
  before mutation. Executable tests prove cancelled live and hive batches leave
  neither registry state nor backup artifacts.
- Hive `set`, `delete`, and multi-block `import` now require a complete inverse
  before prompting and automatically perform an audited rollback after a
  partial failure. Their versioned JSON contract exposes the apply,
  `rolledBack`, and rollback reports rather than returning only the failed
  forward counts.
- Hive `set`, `delete`, `import`, `copy-value`, and `move-value` now pass
  through the same confirmation/policy gate as subtree copy/move and sync.
  Previously they could write without a prompt and bypass an administrator's
  `RequireConfirm` intent.
- Offline-hive commands now reject `--view 32`, `--view 64`, and `--view both`
  instead of silently using the private handle's single native view. An
  application-hive mount has no WOW64 view split.
- Hive `--strip-root` now requires every input key to be within the selected
  registry path and verifies the hive identity even when the prefix is a root.
  The shared subtree-rebase helper previously accepted an HKLM block below an
  empty-subpath HKCU source, allowing a partially or incorrectly re-rooted
  offline import.
- `hive exec` now parses each nested operation to decide whether the private
  hive needs write access. The previous word scan treated read-only arguments
  such as a search query equal to `move` as mutation verbs and unnecessarily
  mounted the file read/write.
- Semantic CLI errors now retain the documented exit taxonomy: no command,
  repeated stdin, invalid format/root/regex, unsafe delete, incompatible remote
  source, and similar preflight failures return usage `2`; administrative
  policy denials return access-denied `4`; remote Win32 failures retain
  access/not-found/I/O distinctions instead of all falling through to `7`.
- Registry exports, conversions, undo snapshots, and digest-bound plan
  artifacts now write through a synced sibling temporary file and commit with
  one replace operation, so an interrupted write cannot leave a truncated
  destination. Batch, saved-plan, and copy-plan JSON inputs also reject control
  artifacts larger than 64 MiB before parsing. Win32 byte-count conversions
  are checked instead of silently narrowing `usize` to `u32`/`i32`.
- Replaced ADMX, Group Policy Preferences XML, and INF readers' repeated linear
  search through prior keys with a shared insertion-ordered hash index. Each
  parser now handles 5,000 distinct keys in under 150 ms on the audit host
  while preserving first-seen spelling, order, and case-insensitive identity.
- Added an executable-to-website contract test covering all 34 top-level
  commands. It exposed and corrected the missing standalone `formats`
  documentation and prevents future CLI additions from silently disappearing
  from the web reference. The inventory is now derived from the executable's
  rendered help rather than a hand-maintained test array, closing the case
  where code and docs could omit the same new command from that array.
- The dependency-free site verifier now rejects duplicate DOM IDs, missing or
  ambiguous copy targets, and broken ARIA ID references. Its positive/negative
  fixture self-test runs in CI. The docs navigation now exposes `ls`, `stats`,
  and `fingerprint`, and the stats reference lists its complete mapping and
  include/exclude flag contract.
- The supply-chain policy now states all five direct runtime dependencies,
  including `clap_complete`. The repository verifier derives the dependency
  count and ordered names from Cargo.toml and rejects a stale SECURITY.md
  claim; the public branch still exposes its obsolete two-dependency text until
  the reviewed local tree is published.
- `completions` no longer dispatches before the global `--self-check` handler.
  A combined invocation now reports the environment first and then emits the
  requested shell script, matching the global-option contract.
- Every external GitHub Action is pinned to its full 40-character commit SHA,
  with the major/nightly label retained for Dependabot. A CI verifier rejects
  mutable refs, missing permissions blocks, `pull_request_target`, and
  `workflow_run`; release smoke also allowlists checksum filenames before
  joining or hashing paths.
- The release signing step no longer relies on an `if` expression referencing
  an environment variable declared only by that step. It always enters the
  step, decides from its scoped secret environment, skips cleanly when neither
  secret exists, and fails on a partially configured certificate/password
  pair instead of silently publishing unsigned.
- MSVC release links now use `/Brepro`, removing the random 16-byte PDB/RSDS
  GUID that made otherwise identical clean builds hash differently. Build
  provenance watches the actual symbolic HEAD, current branch ref and packed
  refs instead of only `main`, including linked worktrees. CI performs a fresh
  relink and requires the SHA-256 to remain identical.
- Registry API calls now reject embedded NULs before Windows can silently
  truncate a key/value name and mutate a different location than the plan or
  audit record names. Key components and value names are bounded using UTF-16
  code units—the unit Win32 actually consumes—covering supplementary Unicode
  characters correctly.
- Live writes also reject line-breaking control characters in key/value names,
  and every `.reg` output path validates that names are representable before
  serialization. JSON/XML input can therefore no longer create or emit a name
  that a later `.reg` export would split into a different structure.
- `REG_SZ` data containing newline, NUL or another quoted-string control is now
  emitted as byte-exact UTF-16LE `hex(1)` instead of placing the character
  literally inside a `.reg` line. Clean strings remain human-readable quoted
  values; unit and JSON-to-REG CLI contracts compare the raw round-trip bytes.
- `--reg4` file and stdout output now call `WideCharToMultiByte(CP_ACP)` and reject
  best-fit/default-character substitution instead of writing UTF-8 bytes under
  an ANSI header. `inspect` reports the actual source encoding and REGEDIT4
  versus Version 5.00 dialect; the reader no longer overwrites that metadata
  with synthetic UTF-16/V5 defaults.
- Replaced the `Registry.pol` reader's linear search through every previously
  seen key with an insertion-ordered hash index. Parsing 5,000 distinct policy
  records on the audit host fell from 6.234 s to 0.048 s while preserving
  record order and duplicate-key behavior.
- Moved pure registry-value conversion out of the Win32 engine so file parsers
  can be built, tested, and fuzzed without linking live-registry code.
- Fixed `--output json` paths that emitted multiple JSON documents, plain text,
  or no stdout: self-check, multi-file inspect, validate, export-to-file, and
  offline-hive info/list/export/set/delete/import. Ambiguous data/script stream
  combinations now fail with usage guidance instead of silently violating the
  requested output format.

- **The offline hive engine bypassed administrative policy.** Its three write
  paths called the unaudited apply and consulted no deny list, so an
  administrator's mandatory audit log and denied keys stopped at the live
  registry — editing the same key inside somebody's NTUSER.DAT was recorded
  nowhere and refused by nothing. Hive writes are now audited and deny-checked,
  matched on the subkey path since a mounted file has no hive component. The
  unaudited entry point is `#[cfg(test)]` now, so the binary contains no way to
  write without reaching the log.
- **Case folding merged registry keys that Windows keeps apart.** `fold_str`
  used `str::to_uppercase`, which applies full Unicode case mapping where one
  character can expand to several: `ß` becomes `SS`, the `ﬁ` ligature becomes
  `FI`. Windows uppercases a path one character at a time through
  `RtlUpcaseUnicodeChar` and does not apply an expanding mapping, so
  `Software\straße` and `Software\STRASSE` are two distinct keys — confirmed
  against the live registry, which creates two subkeys. `coalesce` merged them
  and kept one path with the other's values, and `diff` reported them equal.
  Folding is now per-character and leaves any expansion alone.
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
- Recognises Active Setup, User Shell Folders/Shell Folders and Winlogon as
  distinct Windows mechanisms. Their HKLM and HKCU branches are not equivalent,
  so unsafe rewrites are refused with an actionable reason.
- Stops assigning blanket high confidence to the entire Explorer subtree.
  Unrecognised Explorer settings now use generic application confidence, with
  dedicated case-insensitive and WOW6432Node coverage for the protected rules.

### Offline hives

- `RegLoadAppKey` mounts a hive file without `SeRestorePrivilege`. The handle is
  process-scoped, so mount, operate and unmount happen inside one process via
  `hive <FILE> exec`.

### Input formats

- `reg`, `pol` (Group Policy PReg binary), `admx` + `adml`, `gpp`
  (`Registry.xml`), `inf` (`[AddReg]`/`[DelReg]`), `json`, `csv`, `ini`.
  Detection reads content before extension.
- Fix an INF `AddReg` panic on the valid three-field form
  `root,subkey,value`; it now produces the specified default empty `REG_SZ`.
- Make Windows CI fixtures robust to JSON backslashes, 8.3 short path aliases,
  and copy-plan result schema v2.

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
