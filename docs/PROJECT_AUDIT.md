# Project audit and development backlog

Last verified: 2026-07-29

This document tracks the current product state across the `regx` executable,
winregistry.org, and the GitHub repository. A green build is necessary, but it
does not by itself mean the product is complete.

## Current evidence

### Application

- Rust 1.94.1 is pinned; x64 and ARM64 MSVC targets are declared.
- `cargo fmt --all --check`, Clippy with warnings denied, and the release build
  pass locally.
- The current local x64 release-profile binary is 1,906,688 bytes (1.82 MiB), statically
  linked and manifested `asInvoker`; local website copy now uses the truthful
  `<2 MiB` bound. The current margin is 190,464 bytes, so CI remains the
  authoritative guard while the project has room for additional capabilities.
- The size profile was re-measured before widening that bound. `opt-level=s`
  produced 2,184,704 bytes (+405,504), while explicit `/OPT:REF` and
  `/OPT:ICF=10` produced the exact same 1,779,200-byte hash as the linker
  defaults. The existing `opt-level=z`, fat LTO, one codegen unit, aborting
  panics and stripping are retained; the new headroom does not come from
  removing Unicode regex, shell completion, static CRT, or another capability.
- The suite contains 325 tests after the pipeline, output, search, saved-plan,
  batch, copy/move, atomic-rollback, and complete-reconciliation tests added
  during this audit. All 213 unit, 96 CLI, 10 Unicode, 5 schema-contract, and
  1 generated-manual contract test pass locally;
  live HKCU cases now self-identify and skip on a host that denies HKCU writes,
  while the dedicated standard-user CI job executes them for real.
- Latest GitHub CI on commit `70ef0bb` completed successfully in 4m40s. Its
  x64, standard-user, signing rehearsal, ARM64, supply-chain, and site-check
  jobs all passed, and it produced both architecture artifacts.
- The application has 35 top-level commands and eight text/policy input
  formats, plus offline hive detection.
- `discover` now exposes its complete provenance in strict JSON: resolved
  executable/anchor, enabled discovery controls, notes, the full absent probe
  trail, aggregate risky-hit count, and ranked found-file evidence. Each hit
  preserves both the searched candidate and canonical resolved target, plus
  structured risk explanations. Automation no longer loses evidence that was
  previously available only in text or vulnerable to a later path change.
- `merge` now consumes all eight text/policy formats through the same
  content-first reader as inspect/convert/import, with shared INF/ADMX/PReg
  selectors and fail-closed semantic-loss handling. It writes REG, JSON, CSV,
  or Registry.pol directly through the shared round-trip writers. REG defaults
  to V5 independently of input order; legacy REGEDIT4 requires explicit
  `--reg4` and is rejected for non-REG destinations.
  `--conflicts error` provides an opt-in fail-closed merge policy for
  automation, rejecting different assignments to the same case-insensitive
  key/value and key create/delete disagreements before output while the default
  retains documented last-write-wins compatibility.
  `import`, `sync`, and `plan` share that policy at the mutation preflight
  boundary. Conflict metadata survives per-format parsing, and post-combine or
  redirection collisions are checked before registry reads, snapshots, audit
  creation, confirmation, or saved-plan output.
  `convert` applies the same check to both reader-level and post-redirection
  models before file or stdout output, so every data-producing multi-operation
  pipeline has an explicit fail-closed mode.
- `inspect` now makes the retained conflict evidence observable. Its strict
  JSON contract includes path, value, first/last source lines and old/new
  previews for every conflict; text prints the same evidence and inspection
  exits partial without hiding the representable result.
- File-backed `diff` and `search` propagate that ambiguity through their
  existing `incomplete` contract and partial exit. Diff will still report the
  visible comparison but no longer writes a patch when either source is
  incomplete, preventing a lossy reader decision from becoming an apparently
  applicable remediation artifact.
- Diff remediation artifacts now use the same complete writer set as export,
  convert, and merge: `--to reg|json|csv|pol`. Both live and offline-hive diff
  expose the format, while JSON reports `patchWritten` rather than forcing
  automation to infer side effects. Dual-view diff preflights both artifacts
  and writes neither when either view fails or is incomplete, closing the
  prior partial-pair and ambiguous-static-source write paths. Every written
  patch now carries its exact byte length and streaming SHA-256 in JSON,
  independently per view. Single-view writing occurs before success JSON is
  emitted, preventing a late writer failure from producing a false artifact
  claim.
- `export` now writes live registry data directly as REG, JSON, CSV, or
  Registry.pol through the same round-trip writers. Status JSON remains
  separate when `--out` is present, paired WOW64 artifacts retain their
  `.32`/`.64` identity, and incompatible stdout/REGEDIT4 combinations fail
  before any artifact is created. Every file-backed status includes the exact
  flushed byte length and a streaming SHA-256 digest, independently per WOW64
  view; dry-run and inline registry-data output carry explicit null evidence.
- `validate --fix` is now a one-input artifact mutation. Read-only validation
  may lint many `.reg` files, but a later malformed file can no longer follow
  and strand an already-rewritten earlier file. Other formats use `inspect`,
  which reports both structural failures and semantic fidelity losses without
  pretending their policy semantics can be physically repaired as `.reg`.
  Machine-readable fix reports embed the complete lossless `repairedData`
  model during dry-run and real writes, so repair automation no longer has to
  interpret prose or re-read a changed file to recover numeric type IDs and
  raw bytes. Read-only validation and syntax refusal explicitly use null.
  Written repairs now also expose their exact path, byte length and streaming
  SHA-256; an in-place backup is sealed independently. The prior backup status
  line no longer corrupts JSON stdout.
- Value-level `copy-value` and `move-value` operations now complement whole-
  subtree copy/move. They preserve sibling values, support destination rename,
  default values, collision refusal/overwrite, remote copy sources, both
  registry views, dry-run/JSON, audit logging, combined undo snapshots and
  cross-view rollback. The same operations run inside private application
  hives, providing a real non-admin persistence test.
- The offline application-hive engine now also copies, moves, and renames
  complete subtrees. It refuses destination collisions without an explicit
  merge, rejects recursive self-destinations, applies policy before prompting,
  snapshots both paths, and rolls back a partial copy/delete sequence. The
  persistence contract is exercised against a real private `regf` hive.
- Offline hives now expose the same access diagnostics needed before a risky
  edit: `hive probe` checks existence and effective read/write/create access
  without mutation, while `hive permissions` reports owner SID, inheritance,
  SDDL, and effective query/enumerate/notify/set/create/delete rights. Their
  strict JSON forms are validated and the executable contract runs against a
  real private hive.

- `hive batch` closes the multi-operation atomicity gap left by `hive exec`.
  The existing schema-v1 manifest is strictly re-rooted and policy-checked in
  full, one complete inverse is captured before confirmation and persisted
  only after acceptance, every operation is reported, and a mid-batch failure
  restores all earlier changes. Testing
  this path exposed that Win32 permits deleting the private mount's root;
  every hive mutation path now rejects such a delete during preflight, so a
  later malicious operation cannot erase the hive or allow earlier operations
  to run.
- Offline hives now support structured search without exporting an
  intermediate `.reg` file. Key/name/type/data fields, substring/glob/bounded
  Unicode regex modes, exact-case matching, include/exclude path globs, limits,
  truncation and incomplete-read reporting share the main search engine and
  its published JSON contract.
- `hive sync` now performs desired-state reconciliation inside a private hive.
  Value pruning and recursive subtree pruning require complete reads, generated
  deletes are policy-checked, the entire mutation set is snapshotted before the
  prompt, and partial application automatically restores that snapshot.
  `--strip-root` also rejects every cross-hive or out-of-prefix input instead
  of silently producing a partially re-rooted mutation set.
  `hive import` and `hive sync` additionally share the live pipeline's
  `--conflicts error` preflight after root stripping. All three desired-state
  operations (`diff`, `import`, and `sync`) now use the shared content-first
  reader for REG, Registry.pol, ADMX/ADML, GPP XML, INF, JSON, CSV, and INI,
  including the format-specific selectors. Import/sync reject fidelity losses
  before any snapshot or artifact; diff marks them incomplete and suppresses
  patch output. A real private-hive test
  proves refusal creates no undo and leaves persisted values unchanged. Live
  batch operations apply the same guard to collisions introduced by Smart
  Redirection before their shared snapshot.
- `hive diff` compares an offline subtree directly against a normalized desired
  registry-data source, supports scoped/summary/exit-gate output, writes a real patch, and is
  tested by applying that patch to a private hive and proving the next diff is
  empty before independently exercising sync.
- `hive export` now serializes REG, JSON, CSV, and Registry.pol through the
  shared writers. Its validated `--root-as` key is applied to the model before
  every serializer, strict JSON reports the requested format, skipped ACL
  reads return partial, and Registry.pol incompatibilities are proven to leave
  no output artifact. Recursive scope and value-name include/exclude globs are
  implemented; the real-hive contract proves one-value selection, child
  exclusion, filtered counts, and no-match/no-artifact exit 8. Together with
  all-format diff/import/sync, offline hive
  data now has a symmetric round-trip path.
- Live export now has an actual shallow mode through `--no-recursive`; the
  older default-true `--recursive` switch could never disable traversal.
  Status JSON for both native and paired WOW64 export records format,
  effective recursion and value-name globs, and reports post-filter counts.
  A stable HKLM contract verifies a one-value shallow snapshot without
  requiring a writable user hive; dual-view contracts verify per-view filtered
  counts.
- Live export also accepts a validated `--root-as KEY`. The requested source
  root is replaced with that destination while relative descendants remain
  intact before any serializer runs. Stable HKLM and paired-HKCU contracts
  search the resulting JSON artifacts for their canonical rebased paths, and
  malformed relative destinations fail at usage preflight.
- Every offline-hive mutation now uses the shared confirmation gate. Set,
  delete, import, value copy/move, subtree copy/move and sync all honor
  administrative `RequireConfirm`; an unconfirmed write is tested to leave the
  persisted hive unchanged.
- Confirmation is now a real no-side-effect boundary across all twenty-one
  artifact-producing mutation commands. Live and offline import, batch,
  saved-plan apply, direct set/delete, subtree/value copy/move, restore, sync,
  and copy-plan apply finish policy and rollback preflight before prompting,
  but do not persist undo files or open the audit writer until the operator
  accepts. Executable live and private-hive tests prove cancellation leaves
  both registry state and the requested backup path absent.
- Every offline-hive mutation now persists its already-complete rollback
  snapshot after confirmation. `--backup` selects the artifact for set/delete,
  subtree/value copy/move, import and sync; batch retains its shared inverse.
  Strict JSON exposes the path, and a real application-hive round trip uses
  `hive undo`, restores the prior value, reapplies the redo, then restores it
  again.
- Set, delete, and import now join sync and copy/move on the atomic path: a
  complete inverse is captured before confirmation, partial writes trigger an
  audited rollback, and strict JSON distinguishes the forward report from the
  compensation report. A dry-run executable contract validates that shape.
- Application-hive commands reject non-native `--view` selections. A private
  `RegLoadAppKeyW` handle has one namespace rather than live-registry WOW64
  views, so silently accepting `32`, `64`, or `both` would be a false contract.
- Successful application-hive backups now stream SHA-256 over the bytes that
  were actually flushed and report both digest and byte length in strict JSON,
  independently for each WOW64 artifact. Dry-run uses explicit null evidence;
  automation cannot mistake a planned filename for an integrity-bound backup.
- Copy-plan v2 binds value scope and both source/destination value names as
  well as the exact payload and current rollback state. `apply-copy-plan`
  rejects source or destination drift for value operations; legacy v1 subtree
  artifacts remain readable.
- Exit classification is typed at the top-level boundary: semantic CLI
  preflight failures return usage `2`, parser failures `3`, policy/Win32 access
  denials `4`, missing registry state `8`, and only uncategorized I/O remains
  `7`. Regression tests cover no-command, stdin, regex, remote-root, copy and
  destructive-confirmation cases that previously leaked into the I/O code.
- A fresh RustSec database scan reports no known vulnerability across the 43
  locked dependency packages. The normal dependency graph has no duplicate
  crate versions.
- Two clean local x64 release builds produce the identical 1,906,688-byte executable
  and SHA-256
  `3b93e8cbcf4ce8d716eb67eef85affb716caa983cb36714a4c5e95e382f6e236`.
  `/Brepro` removed the previously random 16-byte RSDS GUID, CI now relinks and
  compares hashes, and build provenance watches Git's actual symbolic ref so a
  non-main branch or linked worktree cannot retain a stale embedded commit.
- Every Win32 key/value-name boundary rejects embedded NUL before conversion to
  a NUL-terminated API string, so displayed/audited paths cannot differ from
  the location Windows receives. Component/name limits are measured in UTF-16
  code units (255 and 16,383), with parser and API-boundary regression tests.
- Control characters that cannot occupy a physical `.reg` key/value-name line
  are rejected by both live-write boundaries and the `.reg` serializer. JSON,
  CSV and XML can represent such characters, but can no longer use that wider
  syntax to create registry state that regx cannot export losslessly.
  A CLI contract feeds an escaped newline through JSON and proves conversion
  fails before emitting even a partial `.reg` header.
- `REG_SZ` payload controls are a different case from controls in names: their
  bytes are representable via `hex(1)`. The writer automatically switches from
  quoted text to NUL-terminated UTF-16LE hex and byte-compares a parse-back,
  including embedded newline and NUL, rather than rejecting or corrupting data.
- REGEDIT4 files are encoded through the host's real `CP_ACP` with best-fit
  substitution disabled; UTF-8 bytes are no longer mislabeled as ANSI, and
  unrepresentable text fails with guidance to use V5. `inspect` preserves and
  reports source dialect/encoding instead of normalized internal defaults,
  with strict schema fields and a byte-level CLI contract.
- Every text-format reader now rejects truncated UTF-16, unpaired surrogates,
  and invalid BOM-marked UTF-8 before parsing. The CLI returns parse exit code
  3 without creating a partial output file. `Registry.pol` preserves malformed
  or hidden `REG_SZ` bytes as raw `hex(1)` instead of dropping or replacing
  them. Malformed delete-directive text is now a fidelity loss that blocks
  conversion and mutation rather than silently omitting the requested delete.
- Human preview, policy lists, and data search likewise decode string-like raw
  values only when every UTF-16 code unit is valid. Odd bytes or unpaired
  surrogates remain searchable as exact hex and never acquire replacement text.
- Native key/value enumeration now rejects malformed UTF-16 names with Win32
  error 1113 instead of substituting `U+FFFD` and calling the API again under a
  different name. A private application-hive test creates such a native value
  directly and proves enumeration fails safely without administrator rights.
- `Registry.pol` key and value names now cross the same strict UTF-16 boundary.
  A malformed policy name is rejected instead of being rewritten with U+FFFD
  and potentially applied to a different registry location.
- `Registry.pol` fidelity is now an explicit safety boundary. Directives such
  as `**delvals.` (delete values while preserving subkeys), `**soft.Name`
  (write only when absent), and ACL/unknown directives are retained as
  inspection losses instead of being widened into unconditional writes or
  whole-key deletes. `inspect` exposes those losses in text and strict JSON;
  conversion and every live/offline import path fail closed before creating an
  artifact, snapshot, audit session, or registry mutation.
- The same fidelity boundary now covers every context-dependent policy reader.
  ADMX `<elements>` need administrator-entered data; GPP value Create depends
  on absence, key Replace requires delete-and-recreate ordering, bitfield
  updates depend on the current DWORD/masks, item-level targeting depends
  on the client environment, and `removePolicy="1"` requires a future undo
  after the GPO leaves scope; INF
  `NOCLOBBER`, `APPEND`, `OVERWRITEONLY`, and per-line WOW64 flags depend on
  current state or routing, while `[Section.security]` carries ACL changes.
  These and malformed/skipped policy items populate
  `inspect.losses` and block conversion plus live/offline mutation. Exact GPP
  value R/U, all D, and key C/U operations remain usable; `default="1"` is
  distinguished from a blank-name key item. The protocol-level outer
  `RegistrySettings disabled="1"` disables the complete preference type;
  non-schema item-level `disabled` is rejected. The GPP reader accepts the
  protocol's `RegistrySettings`, `Collection`, and `Registry` roots and follows
  only valid collection nesting, so unrelated XML wrappers cannot smuggle in
  registry-looking descendants. Shared content detection now classifies XML by
  that parsed root rather than substring search, so renamed Collection/single-
  Registry fragments work without letting a nested tag impersonate GPP or
  ADMX. INF key-only, named-delete and
  key-delete operations remain usable. Custom binary registry types preserve
  their high-word type ID and exact bytes instead of being rejected. INF
  `%strkey%` expansion is strict across section references, subkeys, value
  names, and data: undefined or unterminated tokens are losses, while `%%`
  remains the documented literal-percent escape. `--inf-language LANGID`
  selects `[Strings.LanguageID]` with SetupAPI's exact, neutral,
  same-primary-language, and undecorated fallback order; omission deliberately
  selects `[Strings]` so output never depends silently on the audit host locale.
  Physical `\` continuations are folded without losing the first line number;
  quoted string parsing preserves edge whitespace and semicolons, condenses
  doubled quotes, and reports case-insensitive duplicates, malformed trailing
  text, unterminated quotes, or an unterminated final continuation as losses.
  CSV quoted value names and string data now preserve leading/trailing spaces,
  while a missing key is a parse error rather than a silently discarded row.
- All 27 external action invocations across five local workflows are pinned to
  full commit SHAs. `scripts/check_workflows.py` enforces immutable refs,
  explicit permissions, and absence of privileged relay triggers in CI. The
  release smoke test allowlists the three checksum asset names before any path
  is resolved, preventing a crafted checksum entry from escaping `dist`.
- Release validation is now one dependency-free implementation used locally,
  in CI, and immediately before publication. It requires the exact two
  executable assets plus CycloneDX document, strict one-to-one SHA256SUMS
  coverage, correct AMD64/ARM64 PE machines, embedded `asInvoker`, no dynamic
  CRT import, version-matched CycloneDX 1.5 identity, and an actual
  `<2 MiB` size. Seven self-test cases prove valid acceptance and rejection
  of architecture, tampering, elevation, SBOM, inventory, and boundary faults.
- Release identity likewise has one dependency-free implementation across
  local checks, CI, preflight, and publish. It binds canonical
  `vMAJOR.MINOR.PATCH`, Cargo package version, one dated changelog heading,
  non-empty structured notes, and the exact tag at `HEAD`; publish consumes
  the same emitted notes instead of a second AWK parser. Six fixtures cover
  acceptance plus version, date, notes, tag-presence, and canonical-tag
  failures. The current `v0.2.0` check intentionally fails because its heading
  is still `Unreleased`, proving an accidental tag cannot pass.
- Signing-secret detection happens inside the scoped signing step. The prior
  step-level `if: env.SIGNING_CERT` could be evaluated before that step's
  environment existed and skip signing; the workflow now distinguishes a
  deliberate no-secret preview from a broken one-secret configuration.
- A current-tree and all-commit-history credential-pattern scan found no
  private-key blocks, AWS/GitHub/Slack token signatures, suspicious credential
  filenames, PFX/PEM/key files, or environment files. Three generic
  `secret = "..."` history matches are deliberate fake redaction-test fixtures,
  not credentials; their values are asserted absent from audit output.
- The public Security page still describes only the original two direct
  dependencies. The local policy now names the five actual runtime
  dependencies (`clap`, `clap_complete`, `anyhow`, `regex`, and `serde_json`).
  `scripts/check_workflows.py` derives that ordered inventory directly from
  Cargo.toml and fails if SECURITY.md's count or names drift again.
- Registry-data outputs, undo bundles, and saved plan artifacts are committed
  by a synced same-directory temporary file plus atomic replacement. The three
  JSON control-artifact readers enforce a 64 MiB ceiling before deserialization;
  ordinary registry exports and hive inputs remain unrestricted because large
  legitimate registries must not be rejected by an arbitrary product limit.
  Win32 data-length conversions now reject/fallback before a narrowing cast.
- All undo artifacts that default to `%TEMP%` now use one collision-resistant
  allocator combining PID, nanosecond time, and an atomic sequence. It replaces
  four millisecond-only copy/move/restore sites, direct set/delete naming,
  offline-hive naming, and the fixed stdin path. A 4,096-name concurrent unit
  test proves uniqueness without creating files, while a real three-mutation
  `hive exec` proves every operation reports a distinct persisted undo path.
- Source-adjacent automatic undo paths use the same allocator rather than a
  fixed `<stem>.undo.reg`. This covers import/sync, live and offline batch,
  saved-plan/copy-plan apply, and offline-hive input mutations, so concurrent
  operations on one source cannot select the same inverse filename.
  `--backup FILE` remains the deliberate stable-path override.
- Generated inverses now have a first-class `undo` workflow instead of asking
  operators to reconstruct safe `import` flags. It forces redirection off,
  captures a redo snapshot before applying, accepts either member of a
  dual-view bundle, requires both members, and restores both views under one
  confirmation and rollback boundary. Dry-run/schema tests pin its redo paths
  without creating artifacts; live round-trip tests cover single and paired
  snapshots when HKCU is writable. Its dedicated strict JSON definition calls
  the newly captured artifact `redo`; it does not overload the mutation
  contract's `undo` field with the opposite meaning. Each persisted redo is
  sealed with exact byte length and streaming SHA-256; dry-run exposes null
  evidence.
- Offline application hives now expose the matching `hive undo` workflow
  instead of requiring operators to remember `import --strip-root HKCU`. It
  removes the generated mount label, policy-checks and confirms the exact
  inverse, captures a redo snapshot, audits the write, and rolls back a partial
  restore. A real private-hive round trip verifies both restored state and the
  persisted redo artifact. Its dedicated JSON definition uses the same
  unambiguous `redo` field. Every offline set/delete/import/sync/subtree/value
  copy/move undo and every redo is sealed with exact bytes and streaming
  SHA-256; dry-run uses null evidence.
- ADMX, GPP XML, and INF readers share an insertion-ordered hash index instead
  of rescanning every prior key. Synthetic 5,000-distinct-key inspections took
  147.5 ms, 135.2 ms, and 86.4 ms respectively on the audit host; a 10,000-key
  regression test also verifies first-seen order and case-insensitive merging.
- A CLI/site contract launches the built executable, derives the complete
  34-command inventory from its rendered top-level help, and requires every
  command to have a matching code
  reference in `website/docs.html`. This caught the previously implicit-only
  `formats` entry; the page now documents its text and JSON usage explicitly.
  There is no hand-maintained command list that can drift in lockstep with the
  website and hide a newly added command.
- The same comparison exposed an early-dispatch exception: `completions`
  ignored a simultaneously requested global `--self-check`. Dispatch now runs
  the environment report first, with an integration contract for the ordering.

### Website

- The Vercel-compatible local preview has been rendered in the in-app browser
  at 375, 768, 1024, and 1440 CSS pixels. Home and documentation pages have no
  page-level horizontal overflow, broken images, duplicate IDs, or console
  warnings/errors; all 29 documentation sections have matching TOC links.
- Desktop/mobile navigation, Escape-to-close focus restoration, theme
  switching/persistence, copy feedback, and documentation anchor positioning
  were exercised rather than inferred from source. This exposed a mobile UX
  defect: the 29-link TOC was 1,131 px tall and hid the document heading below
  the first screen. At tablet/mobile widths it is now capped to half the
  viewport with contained internal scrolling; at 375 px the heading moved from
  1,292 px to 567 px while page overflow remained absent.
- The production home page and documentation load without console errors.
- The production site has no horizontal page overflow at 375, 768, 1024, or
  1440 CSS pixels.
- Local link, anchor, CSP, security-header, contrast, focus, reduced-motion,
  and Vercel checks pass. The site verifier now also rejects duplicate IDs,
  copy buttons whose target is absent or ambiguous, and unresolved
  `aria-controls`/`aria-labelledby`/`aria-describedby` references. A synthetic
  positive/negative self-test runs in CI so these checks cannot silently
  become no-ops.
- Home and documentation pages now share a checked 1731×909 Open Graph/Twitter
  preview image; the site verifier enforces the asset, minimum dimensions,
  social-card aspect ratio, and metadata.
- Production is behind the local worktree: it still advertises v0.1, 851 KB,
  138 tests, Windows 8.1 compatibility, and an already-released x64 build. It
  has no Open Graph image metadata.
- GitHub has no binary release, so no page may claim that an x64 binary is
  already released or link a primary download action to `releases/latest`.
- A direct production-browser audit on 2026-07-29 found the deployed site is
  still the obsolete v0.1 build: it claims 851 KB, 138 tests, Windows 8.1 and
  an x64 release, while GitHub has no release. The live HTML also lacks the
  checked-in Open Graph image metadata and the image URL returns 404. Routing,
  security headers, the 404 response, JavaScript assets and responsive layouts
  remain healthy; both pages have no horizontal overflow at 375 px or 1440 px
  and the documentation has no dead in-page anchors.
- A fresh byte-level production check on 2026-07-29 confirms that state has
  not changed: the live home SHA-256 is
  `ad948c42cf88e571eb302a92ac14a0b3b7b2c2b8e502c078fa4aaa17d4eff766`
  and live docs SHA-256 is
  `fb8e2b299c3e998244c835c949a0d8bab533aa68915dcd1c98f2c5b124cb92a4`.
  Security headers, clean redirects, 404 routing and both JavaScript assets
  still pass, while home/docs HTML, CSS and the missing Open Graph image remain
  the same four deployment failures.
- `scripts/check_deployed_site.py` now compares production HTML and key assets
  byte-for-byte with the reviewed site (normalizing HTML line endings), checks
  every global Vercel security header, the `/docs.html` clean-URL redirect and
  a real unknown-route 404. The scheduled/manual `website-smoke.yml` workflow
  makes deployment drift visible after these local changes reach GitHub. Its
  first direct run correctly reports four current failures: stale home/docs
  HTML, stale CSS and the missing social image.
- Transport failures in the deployed-site verifier are now a concise
  one-failure report rather than an uncaught `urllib` traceback. Its
  dependency-free `--self-test` injects a failed opener, proves the underlying
  reason survives as a typed request error, and runs in the ordinary site CI
  job without requiring network access.

### GitHub

- Repository: `xmetaads/winregistry`, public, default branch `main`.
- The connected GitHub API was rechecked on 2026-07-29: the repository has
  exactly one visible branch (`main`) and still has no open/closed issues or
  pull requests. Public HEAD remains
  `70ef0bb55d5273f5aaf9e0b937819e50768a1242`.
- A second current connector/API audit confirms the public repository remains
  writable by the connected account but unchanged: one branch (`main`), no
  tags, an empty releases response, and no issues or pull requests. No external
  mutation was performed.
- A separate read-only remote-ref query confirms that `main` is the only head
  and that the public repository has no tags, so there is no published release
  ref for the release workflow or website to consume.
- Local `main`, `origin/main`, and the latest successful CI run point at
  commit `70ef0bb`.
- The publication gap is not a small patch: public `main` tracks 68 files,
  while the current workspace exposes 123 non-target files. The tracked diff
  alone changes 44 files by +24,796/-2,216 lines, with another 55 untracked
  paths. Local HEAD has not diverged because none of this work is committed.
- The public README at that commit reports 158 tests, versus 325 in the current
  verified worktree.
- There are currently no releases, issues, or pull requests.
- Security policy, security advisories, and secret scanning are enabled.
- Private vulnerability reporting and Dependabot alerts are disabled.
- Code scanning is not configured.
- That CI run warned that `actions/upload-artifact@v4` still targets Node.js
  20. The local workflows now use Node.js 24-native
  `actions/upload-artifact@v6` and `actions/download-artifact@v7`; this
  remains unverified on GitHub until pushed.
- The local worktree now supplies issue forms, a pull-request template,
  CODEOWNERS, support guidance, a public roadmap, Dependabot configuration,
  CodeQL analysis, and a post-release verification workflow. These remain
  absent from GitHub until the changes are reviewed and pushed.
- `scripts/check_workflows.py`, which already guards immutable Action refs and
  workflow permissions, now also makes ten repository-surface files a tested
  contract: CODEOWNERS, PR/support/security guidance, three structured issue
  forms plus their locked-down config, Dependabot, and the roadmap. It checks
  ownership, private vulnerability routing, weekly Cargo/Actions updates, and
  PR safety-review coverage; CI cannot silently publish the code while dropping
  the GitHub collaboration surface again.
- Local CI defaults to read-only repository access; release permissions are
  narrowed per job. CI and release builds now enforce the website's `<2 MiB`
  x64 contract instead of merely printing binary size. The comparison is
  strict (`>=` fails), matching the wording rather than allowing equality.

## Confirmed defects and misleading states

1. **No downloadable product.** The website's product proposition is a portable
   executable, but GitHub has no release. This is the largest launch blocker.
2. **Unsigned binary.** The release workflow can publish hashes, SBOMs, and
   provenance, but without a code-signing certificate SmartScreen, AppLocker,
   and WDAC cannot establish publisher trust.
3. **Website drift.** Version, binary size, test count, and release status were
   stale or contradicted GitHub. Local pages have been corrected to describe
   the first release as pending.
4. **Incomplete command help.** `--from` accepted ADMX and GPP while help text
   omitted both. The help and its integration contract test have been fixed.
5. **No user-facing backlog on GitHub.** The local worktree now adds
   `ROADMAP.md` and structured feature/bug forms, but they are not visible to
   users until reviewed and pushed.
6. **`--view both` silently selected native view.** The shared view helper
   collapsed `both` to `native`. Registry commands now handle both views
   explicitly: `query`, `export`, `backup`, `restore`, `copy`, `move`,
   `apply-copy-plan`, live `search`, live `diff`, `watch`, `probe`,
   `permissions`, `set`, `delete`, `import`, and `sync`, including pruning
   reconciliation.
   Mutations capture both snapshots before mutation and perform reverse-order
   cross-view rollback. `plan` emits independent desired states and rollback
   evidence for both views without writing either one. `export` writes distinct
   `.32.reg`/`.64.reg` files or one structured JSON document; live search keeps
   matches, truncation, and completeness separate with a per-view limit. Live
   diff keeps drift and failures separate and writes independent view patches.
   Watch arms both notification handles and reports the triggering view plus
   both post-notification diffs without polling.
7. **Unsupported Windows 8.1 claim.** The production footer claimed Windows
   8.1 support, but the pinned standard Rust MSVC targets require Windows 10 or
   Windows Server 2016 and later. Local README and both website footers now use
   the toolchain's real platform floor.

## Functional gaps

The list below distinguishes product gaps from deliberate constraints. It uses
Microsoft's `reg.exe` command set as the compatibility baseline, then adds
capabilities implied by regx's own pipeline-oriented positioning.

### `reg.exe` compatibility accounting

| `reg.exe` operation | regx coverage | Status |
|---|---|---|
| `QUERY` | `query`, `search` | Implemented, including both WOW64 views and read-only remote HKLM/HKU |
| `ADD` | `set`, `import`, `sync`, `batch` | Implemented with policy, dry-run, audit and undo |
| `DELETE` | `delete`, reconciliation pruning | Implemented with cross-view rollback |
| `COPY` | `copy`, `move`, saved copy plans | Implemented locally and remote-to-local for copy |
| `SAVE` | `backup` | Implemented through a standard-user application hive; ACLs, classes and timestamps are intentionally not claimed |
| `RESTORE` | `restore` | Implemented under an explicit destination with collision and rollback guards |
| `COMPARE` | `diff` | Implemented for file/live combinations with scoped patches |
| `EXPORT` | `export` | Implemented as `.reg`, JSON, CSV, or Registry.pol |
| `IMPORT` | `import` | Implemented for all supported formats |
| `LOAD` / `UNLOAD` | `hive ...`, `hive exec` | Deliberately process-scoped: global load/unload needs privileged namespace mutation and conflicts with the non-admin contract |
| `FLAGS` | none | Deliberate omission: the operation is restricted to HKLM\Software virtualization flags, while regx neither elevates nor promises machine-wide mutation |

The two deliberate omissions are documented constraints, not silently missing
commands. regx additionally supplies planning, validation/fix, format
conversion, monitoring, permissions, discovery, audit verification, atomic
batching, offline hive editing, and machine-readable contracts that `reg.exe`
does not.

### P0 — needed before the first public binary

- Publish and verify an x64 release containing the executable, SHA256SUMS,
  CycloneDX SBOM, and GitHub provenance attestation.
- Decide whether an unsigned preview release is acceptable. A production
  release needs Authenticode signing and a protected signing identity. The
  workflow now fails closed unless signing succeeds or a repository owner
  explicitly sets `ALLOW_UNSIGNED_PREVIEW=true`.
  That exception is restricted to Authenticode `NotSigned`; invalid, untrusted,
  or hash-mismatched signature states fail both publication and post-release
  smoke even when unsigned previews are enabled.
- **Post-release smoke workflow (implemented during this audit).** It downloads
  every checksummed release asset, verifies `SHA256SUMS` and GitHub provenance,
  confirms the SBOM exists, and runs `--version`, `--help`, and `--self-check`
  against the published x64 binary. It also rejects missing/extra checksum
  coverage and a binary version/target that disagrees with the release tag.
  Release preflight requires one exact tag/commit/Cargo version and a dated
  changelog, and every build/SBOM/publish checkout uses that same ref. It cannot
  run until a release exists.
  Provenance is verified independently for both executable assets, and both
  the build job and post-release smoke parse the PE header to require AMD64
  machine `0x8664` for `regx-x86_64.exe` and ARM64 machine `0xAA64` for
  `regx-aarch64.exe`; an artifact cannot pass merely by carrying the right
  filename. The current source and all targets pass local ARM64 `cargo check`.
  Publish now requires exactly one x64 executable, one ARM64 executable, and
  one generated SBOM instead of silently overwriting duplicate basenames.
  Post-release smoke parses the SBOM and requires CycloneDX 1.5, component
  `regx`, and the exact release-tag version rather than accepting any
  checksummed JSON file.
  Before release creation, the assembled directory also passes
  `scripts/check_release_assets.py`, the same validator whose seven positive
  and negative fixture cases run in ordinary CI. This removes drift between
  local preflight and the Bash/PowerShell workflow implementations.
  Tag/package/changelog identity and release-note extraction similarly share
  `scripts/check_release_identity.py`; its six fixture cases run in CI, while
  both preflight and publish require the actual tag to point at checked-out
  `HEAD`.
  This audit host lacks the Visual C++ ARM64 linker libraries (`libcmt.lib`), so
  final local linking cannot replace the workflow's explicit ARM64 component
  installation or the still-required real-hardware compatibility run.
- Deploy the corrected website only after its release state matches GitHub.
- Merge the supplied Dependabot and CodeQL configuration, then enable private
  vulnerability reporting and Dependabot alerts in repository settings.

### P1 — major application capabilities

- **Copy/move/rename keys (implemented during this audit).** `copy` and `move`
  now preserve complete readable subtrees, reject collisions by default,
  support guarded merge, policy, audit, dry-run, JSON, combined undo, and
  automatic rollback after either phase fails. Dual-view operations preflight
  and snapshot both views, retain the copy-before-delete invariant, and roll
  back across views. Dual-view saved plans use paired digest-bound artifacts
  that are both revalidated before mutation. `--save-plan` emits a
  digest-bound collision preview; `apply-copy-plan` rechecks source content,
  rebuilt payload, destination/current state, and policy before mutation.
  Artifact and result schemas are published with the website. Machine-readable
  creation seals each subtree or value plan with exact bytes and streaming
  SHA-256, independently for both members of a dual-view pair; the CLI schema
  now explicitly covers the value saved-plan variant. Direct mutation and
  verified-plan apply results also seal every persisted per-view undo with
  exact bytes and streaming SHA-256; dry-run exposes null evidence.
- **Application-hive backup/restore (implemented during this audit).** `backup`
  creates a native `regf` application hive preserving keys, empty keys, types,
  and raw bytes. `--computer` may read HKLM/HKU remotely while creating only
  local artifacts. Dual-view backup preflights both views and emits separate
  `.32.hiv`/`.64.hiv` artifacts. Dual-view restore validates that pair and
  captures both inverses before writing; `restore` uses collision guards, policy, audit, undo, and
  atomic rollback. Restore JSON now seals every persisted undo with exact byte
  length and streaming SHA-256, independently per view; dry-run uses null
  evidence. ACLs, key classes, and timestamps cannot be preserved by
  this non-admin route. Microsoft's `RegSaveKeyEx` alternative requires
  `SeBackupPrivilege`, so full system-hive metadata backup remains an explicit
  privileged non-goal.
- **Advanced registry search.** `search` now filters key paths, value names,
  types and data across files/stdin/live trees using substring, glob, or
  bounded Unicode regex queries. Repeatable glob include/exclude path rules
  and exact-case mode are implemented. Repeatable value-name include/exclude
  globs scope both top-level and offline-hive search; activating value scope
  suppresses key-only matches so automation cannot escape the declared
  boundary. Machine-readable value matches embed
  the exact typed/raw registry value instead of only a preview; key-only
  matches explicitly carry no value payload. The contract is shared by file,
  stdin, live, remote, dual-view, and offline-hive search.
- **Change monitoring (implemented during this audit).** `watch` uses
  `RegNotifyChangeKeyValue` with recursive/key-only scope, count, timeout,
  snapshot diffs, and streaming JSON. Value changes carry lossless
  `leftExact`/`rightExact` snapshots, including numeric type IDs and raw bytes,
  so consumers do not need a race-prone query after notification.
  Microsoft explicitly rejects remote handles with `ERROR_INVALID_HANDLE`, so
  remote watch is a platform constraint rather than an omitted polling mode.
- **Additional output formats.** JSON and CSV registry-data output round-trips
  exactly. `convert --to pol` also writes version-1 PReg binaries with exact
  empty-key/named-value/defined-raw-type/delete round trips for one HKCU or HKLM
  root. The writer follows MS-GPREG's 65,535-byte record ceiling and required
  REG_SZ single-space delete payload, and fail-closes on mixed roots, root
  or default-value mutation and undefined types. Future formats may still be
  added as real use cases require them.
- **Complete reconciliation (implemented during this audit).** `sync --prune`
  removes undeclared values; adding `--prune-keys` performs guarded recursive
  desired-tree reconciliation. ACL gaps abort preflight and generated deletes
  use policy, plan, undo, audit, and atomic rollback.
- **Automatic rollback on partial apply (implemented during this audit).**
  Import/sync now refuse incomplete snapshots and automatically apply the
  audited inverse after partial failure. `--no-backup` is the explicit
  non-atomic escape hatch. Live `sync` now exposes the same
  `--backup FILE | --no-backup` controls as `import`, instead of forcing its
  default beside-input undo path; a dual-view live contract proves an explicit
  base path produces the expected independent `.32.reg` and `.64.reg` members.
  The shared machine result for direct mutation,
  import/sync, and saved-plan apply identifies every per-view undo and seals
  the persisted bytes with streaming SHA-256; non-persisting modes use null
  evidence.
- **Read-only remote registry (implemented during this audit).** `query`,
  `ls`, `export`, live-key `search`, `probe`, `permissions`, and either side of `diff`
  connect through
  `RegConnectRegistryW`. Only the Win32-supported HKLM/HKU roots are accepted;
  file inputs and every mutation command reject the option before networking.
  `diff --computer-a/--computer-b` supports remote-to-file, remote-to-local,
  and remote-to-remote comparisons, including independent WOW64 views.
  `permissions --computer/--compare-computer` independently locates both ACL
  sources, while remote `probe` only tests handle access and never creates a
  scratch key.
  `copy --source-computer` additionally supports remote-to-local copy and
  digest-bound previews while applying only against local Roots. `move` has no
  remote option, and plan validation rejects remote source deletion.
- **Value-free key enumeration (implemented during this audit).** Top-level
  `ls` lists immediate child keys without reading value payloads, with `-r`
  for descendants, independent WOW64 views, remote HKLM/HKU, ACL skips and
  strict per-view JSON. Offline `hive ls` now uses the same enumeration engine:
  its non-recursive form returns children instead of merely echoing the
  requested key. Repeatable include/exclude globs scope canonical live paths
  or relative hive paths, and a default 1,000-match per-view limit stops
  traversal with an explicit `truncated` flag rather than emitting an
  unbounded recursive inventory.
- **Payload-safe source statistics (implemented during this audit).** Top-level
  `stats` accepts every supported file, stdin, or a local/remote live key and
  reports effective last-write-wins key/value counts, registry type counts,
  exact raw payload bytes, delete operations, maximum depth, conflicts, and
  completeness without rendering value names or data. Live dual-view output
  remains separated; offline `hive stats` exposes the same summary for a
  relative subtree. File inputs reject registry-view flags instead of implying
  view semantics they do not have.
  Key-path and value-name include/exclude globs now share the scoped
  fingerprint/export pipeline across file/live/remote/dual-view and offline
  hive sources. JSON echoes scope plus `matched`; no match exits not-found
  instead of returning a misleading successful zero summary.
  Live/remote/dual-view and offline-hive statistics also support `--root-as`
  using the same migration mapping as fingerprint/export. Scope is evaluated
  after mapping, depth stays relative to the mapped requested subtree, JSON
  records the canonical destination, and ambiguous file inputs reject it.
  The Draft 2020-12 stats schema composition was also corrected so referenced common
  fields no longer reject the legitimate file/hive extension properties under
  a conforming `allOf` evaluator.
  The local contract harness now also executes the published `pattern`,
  schema-valued `additionalProperties`, `uniqueItems`, and `if`/`then`
  keywords. Negative fixtures reject malformed SHA-256 text, duplicate
  supposedly unique items, non-numeric registry type counts, and conditional
  objects missing their required value-specific fields.
- **Canonical payload-safe fingerprints (implemented during this audit).**
  `fingerprint` computes a versioned, domain-separated SHA-256 over the
  effective registry model without printing value data. Exact case-preserved
  paths/names, delete state, numeric registry types and length-delimited raw
  bytes are covered; block/value ordering is normalized, so equivalent source
  order does not create false drift. File, stdin, local/remote live,
  independent WOW64 views, and offline `hive fingerprint` share the same
  canonical v1 contract and explicit conflict/completeness reporting.
  `--expect` makes file, single-view, and hive checks usable directly as
  exit-code gates; dual-view checks require both `--expect-32` and
  `--expect-64`, normalize hexadecimal case, and exit partial on drift without
  misclassifying a valid mismatch as parse or I/O failure.
  Repeatable key include/exclude and value include/exclude globs now reuse the
  scoped export semantics across file/live/remote/dual-view and offline hive
  sources. JSON binds the declared scope to selected key/value counts. A scope
  matching nothing exits not-found with `matched:false`, preventing a typo
  from becoming a successful fingerprint of empty state; a missing member of a
  dual-view scope makes the combined result partial.
  Live/remote `--root-as` now rebases the requested subtree before scope/hash;
  offline hive mode rebases the mounted hive root in parity with offline
  export. Resolved mapping is explicit in JSON, malformed/out-of-prefix
  mappings fail through the existing rebase guards, and file inputs reject the
  ambiguous option. A cross-format integration case proves a rebased private
  hive and its equivalently rebased REG export have the identical digest.
- **Permissions inspection (implemented during this audit).** `permissions`
  reports owner SID, DACL inheritance/protection, SDDL, and effective
  query/enumerate/notify/set/create-subkey/delete access per WOW64 view.
  `--compare` reports field-level drift between two keys per view, and
  `--exit-code` makes the result usable as a configuration gate. Either side
  may be remote HKLM/HKU without enabling a remote mutation path.

### P2 — completeness and operational quality

- **Digest-bound saved plans (implemented during this audit).** `plan --save`
  emits schema v1 only for complete, unblocked named-file plans. The payload,
  every source, per-view desired mutations and relevant current state are
  SHA-256 bound. `apply-plan` re-verifies those bindings and current policy,
  persists fresh undo, audits the apply, and uses cross-view rollback. The
  schema is published at `/schemas/saved-plan-v1.json`. Machine-readable plan
  creation also seals the persisted artifact with its exact byte length and
  streaming SHA-256; omitted or refused saves expose explicit null evidence.
- **Scoped large-tree diff (implemented during this audit).** Repeatable glob
  include/exclude filters and summary-only output share one filtered diff, so
  counts, exit gates, JSON and generated patches cannot disagree on scope.
  Explicit `--map-a FROM=TO` and `--map-b FROM=TO` mappings compare equivalent
  migration subtrees across different registry roots; every source key must
  remain below the declared `FROM`, and the mapped destination drives filters,
  reports, and applicable patches.
  Repeatable value-name include/exclude globs provide a second scope dimension.
  Activating them removes structural key changes and represents selected values
  below a missing target key as individual deletions, preventing a scoped patch
  from deleting unselected sibling state. Offline `hive diff` shares the same
  behavior and machine-readable fields rather than maintaining a weaker
  parallel implementation.
  When either side is live, dual-view mode compares both WOW64 views and emits
  separate `.32.reg`/`.64.reg` patches; a file or stdin baseline is parsed once.
- **Value-level import/export selection (implemented during this audit).**
  Repeatable include/exclude globs match value names case-insensitively, with
  `@` for default. When selection is active, key deletes and empty-key creates
  are structurally omitted, and an empty export returns not-found without a
  file.
- **Scoped key-path export (implemented during this audit).** Live, remote,
  dual-view, and offline-hive exports accept repeatable `--include` and
  `--exclude` globs against the portable post-`--root-as` path. `*` remains
  component-bounded while `**` crosses registry separators; path and value
  filters compose, counts describe the selected artifact, and an empty scope
  exits not-found without creating a file. Strict status schemas carry both
  filter dimensions.
- **Atomic batch manifests (implemented during this audit).** A published v1
  schema groups ordered, uniquely identified JSON mutations. The CLI validates
  and policy-checks the whole manifest, captures every selected registry view
  before any write, emits one logical per-view undo bundle, reports every
  operation, and rolls the complete batch back on its first failure. The same
  manifest now runs under one offline-hive mount with strict re-rooting, a
  persistent shared inverse, native-view outcomes, and whole-batch rollback.
  Every machine-readable per-view undo is sealed with exact bytes and streaming
  SHA-256; dry-run retains planned paths with null evidence for both engines.
- **Audit-log rotation, detached anchors, and cross-file verification (implemented during this
  audit).** Rotation refuses broken input and overwrite, durably archives the
  old bytes, and starts a hashed segment marker binding the prior tail and
  whole-file SHA-256. Ordered chain verification detects edit, omission, and
  reorder. `audit --write-anchor` atomically records the full-file digest, tail
  hash and record count; `--verify-anchor` distinguishes internal-chain damage
  from a valid log whose detached checkpoint no longer matches. The checkpoint
  must live on another trust boundary to detect a coordinated rewrite.
  Optional `--anchor-key` writes authenticated v2 checkpoints using
  HMAC-SHA256 and constant-time tag comparison. Wrong/missing keys, signature
  edits, and unsigned-v1 downgrade while a key is required all fail closed;
  unsigned v1 anchors remain compatible for external append-only storage.
  Machine-readable rotation and anchor-write results seal the actual persisted
  artifact with its exact byte length and streaming SHA-256; dry-run returns
  null evidence rather than claiming a planned path exists.
- **Versioned JSON output contracts (implemented during this audit).**
  `/schemas/cli-output-v1.json` maps every machine-readable command to its
  applicable Draft 2020-12 definition or dedicated artifact/result schema.
  Real CLI output is parsed and checked against representative definitions;
  the contract harness enforces types, required/unknown fields, constants,
  alternatives, enums, and array/string/number bounds. A live dual-view saved
  copy-plan result is validated against its dedicated strict schema.
  `probe`, `permissions`, `backup`, and `diff` now also close unknown
  properties and type every nested source, view, effective-right and change
  object; a negative harness proves both extra fields and wrong types fail.
  The shared registry-data definition now matches its four real mutually
  exclusive value encodings (delete, string, DWORD, raw type-id/bytes);
  apply/query/export and their nested key/value/failure/view objects are also
  strict and are validated against data-bearing executable output.
  Plan/search/watch/audit/discovery/offline-hive, validation, formats,
  self-check, copy/move, and restore now close and type their nested objects as
  well. Representative executable output covers the safe non-mutating forms,
  including bounded watch timeout and invalid-file hive inspection. The
  discovery schema was corrected from a nonexistent `target` property to the
  emitted `anchor` and `stem`.
  Query values now preserve their compatible display preview while embedding a
  required exact registry-value object; numeric type IDs and raw bytes survive
  live, remote, dual-view, and offline-hive machine output without parsing
  human text.
  Value-level diff changes likewise require `leftExact` and `rightExact`
  alongside compatible previews, covering file/live/remote, dual-view, mapped,
  value-scoped, and offline-hive comparisons without degrading raw evidence.
  Unredacted plan changes now embed the same exact typed/raw object in
  before/after states, while policy-redacted plans remain SHA-256-only so the
  richer contract does not weaken secret handling.
  Inspection conflict evidence also preserves exact before/after registry
  values and source lines; structural key-state conflicts use null payloads.
  Every inspection report now also embeds the full lossless parsed `data`
  model. Repair automation can examine retained keys, numeric type IDs and raw
  bytes from an incomplete source without weakening `convert`'s fail-closed
  artifact boundary or inferring malformed-string changes from previews.
  `validate`, multi-file `inspect`, offline-hive info/list/export/mutations,
  export-to-file, and self-check were corrected where the global JSON flag had
  produced text, no stdout, or multiple documents. Data/script streams reject
  the ambiguous flag with usage guidance; `convert --to json` remains the
  registry-data route and `watch` remains newline-delimited events.
- **Shell completions (implemented during this audit).** `completions` emits
  Bash, Elvish, Fish, PowerShell, or Zsh scripts directly from Clap metadata,
  so the command and flag inventory cannot drift from the executable.
- **Man-page/reference generation (implemented during this audit).**
  `cargo run --example generate-man -- OUT_DIR` recursively emits section-1
  manuals for the root and every nested subcommand from the same Clap
  metadata. It is a development-only dependency, so the shipped executable
  does not carry the generator.
- **Large-data performance and memory benchmark (implemented during this
  audit).** The release-executable harness generates `.reg`, `Registry.pol`,
  and a private deep/wide application hive, then reports elapsed time,
  throughput, operations/second, and peak working set. At scale 5,000 on the
  audit host, `.reg` converted in 0.090 s at 13.2 MiB peak working set,
  `Registry.pol` in 0.048 s at 11.0 MiB, hive creation/write in 4.471 s at
  7.6 MiB, and recursive hive query in 0.165 s at 8.4 MiB. These are baseline
  observations, not portable performance guarantees.
- **Parser fuzzing (implemented during this audit).** Three direct
  libFuzzer targets cover raw `.reg` bytes, XML, and selector-driven forced
  parsing of `.reg`, PReg, JSON, CSV, INF, INI, ADMX, and GPP. Ten checked-in
  seeds and a deterministic 10,000-case mutation smoke pass a 69-test standalone
  harness, all targets compile, and a pinned weekly/parser-change Linux workflow
  is configured for 10,000 AddressSanitizer executions per target. The audit
  Windows host lacks Visual Studio's optional C++
  AddressSanitizer runtime, so a local instrumented campaign cannot run until
  that component is installed; the failure is explicit rather than treated as
  fuzz success.
- Compatibility testing on every claimed Windows version and real ARM64
  hardware.

## Deliberate non-goals to preserve

- Never request elevation or silently rely on registry virtualization.
- Never claim that an HKLM-to-HKCU rewrite has machine-wide effect.
- Never invent missing ADMX element values or malformed binary data.
- Do not add global `mount`/`unmount` commands for `RegLoadAppKey`; its handle is
  process-scoped, so the existing single-process `hive exec` model is honest.
- Do not claim remote `watch`: `RegNotifyChangeKeyValue` requires a local
  handle. Polling would weaken the command's native-notification guarantee.
- Do not expose secrets in audit logs or command-line records.

## Recommended implementation order

1. Finish release readiness and make website/GitHub claims truthful.
2. Exercise the release workflow on a real signed or explicitly approved
   unsigned preview tag, then run its download/checksum/provenance smoke test.
3. Evaluate broader optional remote access without weakening the local
   standard-user model; remote query/export/search and remote copy sources are
   already implemented.
4. Review fuzz findings and benchmark regressions continuously; both harnesses
   are implemented, while full OS/hardware compatibility remains external.

Each new mutation path must call the administrative policy guard before
prompting or writing, emit audit events, respect both registry views, support
dry-run and JSON output, and include a test that fails without the feature.
