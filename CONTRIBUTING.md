# Contributing

## Build and test

```bash
cargo build --release      # -> target\release\regx.exe
cargo test                 # unit + integration
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
```

All four must pass; CI enforces them. The tree is warning-free and should stay
that way.

### Run the tests unelevated

A handful of assertions are about the *environment* rather than the code: that
an HKLM write is refused, that `probe` reports HKLM read-only, that System32 is
not writable, that `--self-check` says "not elevated". They encode the product's
central premise, and they only mean anything as a standard user. Each one
detects an elevated host and says plainly that it could not be exercised, so an
elevated shell does not turn CI red on a property of the machine — but it also
verifies nothing.

CI covers this: a `Test (standard user)` job creates an unprivileged local
account on the runner and re-runs the compiled test binaries as it, then fails
if those assertions skipped again. Locally, just use a normal shell.

The suite writes only under `HKCU\Software\regx-it-*` and removes each key on
drop, including when an assertion fails.

## What a change needs

**A test that fails without it.** The unit tests in `src/` cover the engines;
`tests/cli.rs` covers the contract — exit codes, JSON shape, and the promise
that `--dry-run` writes nothing. A change to any documented behaviour belongs in
`tests/cli.rs`.

**Honest failure.** Two rules run through this codebase:

- *Never invent data.* An ADMX `<element>` holds whatever an administrator
  typed; a malformed DWORD payload could be anything. Both are reported, not
  guessed. If you cannot determine a value, say so and stop.
- *Never report a no-op as success.* Smart Redirection grades every mapping and
  refuses the ones that would write cleanly and change nothing. New mappings
  need a confidence level and a reason, not just a path rewrite.

**Comments that explain why.** The code has a lot of Win32 and file-format
minutiae in it. A comment saying what a line does is noise; one saying why the
obvious approach is wrong is the reason the next person does not break it.

## Adding an input format

1. A module under `src/formats/` returning `(Vec<KeyBlock>, Vec<String>)` —
   blocks and human-readable notes about anything the reader had to decide.
2. A `Format` variant, a `parse_name` alias and a detection rule in
   `src/formats/mod.rs`. Detection reads **content before extension**.
3. Unit tests in the module, plus an entry in
   `every_text_format_is_detected_and_converts_to_reg` in `tests/cli.rs`.
4. Rows in the tables in `README.md` and `website/docs.html`, and in
   `FORMAT_TABLE` in `src/main.rs` so `regx formats` stays accurate.

Everything downstream — redirection, coalescing, undo, apply — then works on the
new format for free. That is the point of the layer.

## Touching the website

`website/` is static: no build step, no framework. `python dev-server.py`
reproduces Vercel's routing locally, which a plain file server does not.

Before pushing:

```bash
python3 scripts/check_site.py
python3 scripts/check_vercel.py
python3 scripts/check_workflows.py
```

The Content-Security-Policy has no `unsafe-inline`, so an inline `<script>` or a
`style=""` attribute will be blocked in production. The checkers fail on both.

When editing `.github/workflows/`, pin every external `uses:` entry to a full
commit SHA and retain a version comment such as `# v5`; Dependabot uses that
comment when proposing safe updates. Privileged relay triggers
`pull_request_target` and `workflow_run` are intentionally forbidden.

## Commits

Explain the reasoning, not the diff. State what was wrong, why the fix is the
right shape, and what you decided not to do. A reader six months from now has
the diff already; what they lack is the argument.
