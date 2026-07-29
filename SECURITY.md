# Security policy

## Reporting a vulnerability

Report privately through GitHub's **Report a vulnerability** button on the
[Security tab](https://github.com/xmetaads/winregistry/security), which opens a
draft advisory visible only to the maintainers.

Please do not open a public issue for a vulnerability first.

What helps most in a report: the `regx` version (`regx --version`), the Windows
build, the exact command line, and the smallest input file that reproduces it.
Output from `regx --self-check` describes the environment in one paste.

Expect an acknowledgement within 5 working days and an assessment within 15.

## What is in scope

This is a tool that writes to the registry on behalf of a user, so the
interesting failures are the ones where it does something the operator did not
ask for:

- **Writing outside what the input declared** — a path traversal through a key
  name, a redirect landing somewhere unintended, `--dry-run` touching anything.
- **An undo file that does not undo.** A snapshot reported as complete but
  which fails to restore the prior state is a data-loss bug, not a cosmetic one.
- **Parser memory-safety or denial of service.** All input formats are parsed in
  safe Rust, but a hang or unbounded allocation on a malformed file still counts.
  The XML reader refuses `DOCTYPE` and bounds nesting depth for this reason.
- **Elevation.** The binary is manifested `asInvoker` and has no code path that
  requests elevation. Anything that causes it to gain privilege is critical.
- **Reading a file the operator did not name** — for example `discover`
  following a link outside the anchor without reporting it.

## What is not a vulnerability

- **`regx` writing where the user told it to.** It is a registry editor. Making
  a change that breaks an application is the operator's decision, and the
  reason `--dry-run`, `probe` and the automatic undo snapshot exist.
- **An `ACCESS_DENIED` you did not expect.** That is the tool working: it never
  elevates. `regx probe <KEY>` reports what your token can actually do.
- **A hit reported by `discover` in a risky location.** `discover` reports the
  search an application *would* perform; the finding is the point.
- **AppLocker, SRP, WDAC or SmartScreen blocking an unsigned binary.** That is
  those systems working as designed. See the AppLocker section of the docs.

## Audit-anchor keys

`audit --anchor-key` reads 32 to 65,536 raw secret bytes and never writes the
key into the anchor, audit log, JSON output, or command-line record. Restrict
the key file with Windows ACLs and preferably keep it on a different host or
protected volume from the log. Anyone who can read the key can authenticate a
replacement checkpoint; anyone who can modify it can cause verification to
fail.

## Supply chain

Five direct dependencies, `clap`, `clap_complete`, `anyhow`, `regex`, and
`serde_json`, chosen to keep this answer short. Shell completion is generated
from the same Clap command tree; regex compilation has explicit automaton and
nesting limits; serde_json is used for versioned saved-plan artifacts and their
schema.
CI runs `cargo deny check` on every push for advisories, licences and sources.
The build statically links the CRT, so there is no runtime redistributable to
track separately.

## Signing

Released binaries are not yet code-signed. Until they are, verify a download
against the SHA-256 published with the release, and read the AppLocker and WDAC
section of the documentation before deploying into a managed environment.
