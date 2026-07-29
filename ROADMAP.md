# Roadmap

The roadmap records outcomes, not promised dates. An item moves to a release
only after its safety contract and verification evidence exist.

## First public preview

- Publish x64 and ARM64 executables, SHA-256 checksums, CycloneDX SBOM, and
  GitHub build provenance. The assembled directory must first pass the shared
  local/CI release identity and asset validators.
- Run the post-publication smoke workflow against the downloadable x64 asset.
- Decide whether the preview may be unsigned. The workflow now fails closed
  unless signing succeeds or an owner explicitly sets
  `ALLOW_UNSIGNED_PREVIEW=true`; production use requires an Authenticode
  signing identity.
- Deploy winregistry.org only when its download and version claims match the
  published GitHub release.
- Enable private vulnerability reporting, Dependabot alerts, and code scanning
  in repository settings; repository workflows/configuration are already
  supplied for Dependabot and CodeQL.

## Hardening

- Expand the implemented versioned CLI-output schema catalog with every future
  command and validate additional environment-dependent variants in CI.
- Detached external audit anchors, cross-file rotation, continuity verification,
  and optional HMAC-SHA256 anchor authentication are implemented. Unsigned v1
  checkpoints remain readable; keyed writes use downgrade-resistant v2.
- Expand parser fuzz corpora from every future regression. Direct libFuzzer
  targets, scheduled AddressSanitizer smoke, large-data parser/hive benchmarks,
  and a Registry.pol quadratic-time fix are implemented.
- Compatibility runs on every claimed Windows version and ARM64 hardware.

See [docs/PROJECT_AUDIT.md](docs/PROJECT_AUDIT.md) for evidence, constraints,
and implementation order. Feature proposals belong in the structured GitHub
feature-request form.
