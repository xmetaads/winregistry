# Code signing

Signing is the single largest barrier to deploying `regx` in a managed
environment, and it is the one gap no amount of feature work closes. AppLocker
judges a **publisher**; WDAC ignores file location entirely; SmartScreen warns
on anything without reputation. An unsigned binary is blocked or warned on no
matter where it sits or how good it is.

`regx` cannot sign itself. What follows is the complete path from "we have no
certificate" to "the release pipeline signs every build".

## Where you are now

```
regx --self-check
```

The `signature` line reports the answer Windows itself gives — the same trust
store AppLocker consults, so it is the answer AppLocker will reach:

| Reported | Meaning |
|---|---|
| `trusted` | A publisher rule can allow this binary anywhere it is copied |
| `untrusted` | Signed, but the issuing CA is not trusted on this machine |
| `unsigned` | Only a path or hash rule can allow it; SmartScreen will warn |
| `unknown` | The check could not run; the reason is printed |

Until a certificate exists, verify a download against the SHA-256 published
beside it in the release. That proves the file was not altered in transit. It
proves nothing about who built it — only a signature does that.

## Choosing a certificate

| | EV code signing | OV code signing | Internal CA |
|---|---|---|---|
| SmartScreen reputation | Immediate | Accrues over time | None (irrelevant inside the domain) |
| Trusted outside your org | Yes | Yes | No |
| Private key storage | Hardware token or cloud HSM, mandatory | HSM since June 2023 | Your PKI's rules |
| Typical lead time | 1–3 weeks (org vetting) | Days | Hours, if a PKI exists |
| Cost | Highest | Moderate | Sunk |

**If `regx` is deployed only inside one organisation, the internal CA is almost
always the right answer.** It is faster to obtain, already trusted on every
domain-joined machine, and an AppLocker publisher rule accepts it. Public
distribution needs a public CA; EV if first-download friction matters.

Since June 2023 the CA/Browser Forum has required code-signing private keys to
live on hardware or in an approved cloud HSM. A `.pfx` on a build agent's disk
is no longer issuable by a public CA — plan for a cloud signing service
(Azure Trusted Signing, DigiCert KeyLocker, SSL.com eSigner) or a token.

## Signing with an internal CA

Ask your PKI team for a certificate with **Code Signing (1.3.6.1.5.5.7.3.3)** in
Extended Key Usage. Generate the request on the machine that will hold the key,
so the private key never travels:

```powershell
# On the signing machine. -KeyExportPolicy NonExportable keeps the private key
# where it was generated, which is the point of doing it here.
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=Your Organisation, O=Your Organisation, C=VN" `
    -KeyExportPolicy NonExportable `
    -KeyUsage DigitalSignature `
    -CertStoreLocation Cert:\CurrentUser\My `
    -HashAlgorithm SHA256

# For a real internal CA, submit a CSR instead and import what comes back.
```

A self-signed certificate is fine **for testing the pipeline** — it will report
`untrusted` on any machine that has not been told to trust it, which is exactly
correct. Do not ship one.

## Signing a build

```powershell
signtool sign `
    /fd SHA256 `
    /tr http://timestamp.digicert.com /td SHA256 `
    /a `
    target\release\regx.exe

signtool verify /pa /v target\release\regx.exe
```

`/tr` is not optional. Without a timestamp the signature stops validating the
day the certificate expires, and every copy already deployed goes with it. The
timestamp is what makes a signature outlive its certificate.

`/fd SHA256` sets the file digest; SHA-1 is rejected by current Windows.

## Signing in CI

`.github/workflows/release.yml` already contains the step. It is inert until
two repository secrets exist, so turning it on is a secrets change rather than
a workflow change:

| Secret | Contents |
|---|---|
| `SIGNING_CERT_BASE64` | The `.pfx`, base64-encoded |
| `SIGNING_CERT_PASSWORD` | Its password |

```powershell
# Produce the base64 blob to paste into the secret.
[Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.pfx")) | Set-Clipboard
```

The workflow writes the `.pfx` to the runner's temp directory, signs, verifies,
and deletes it in a `finally` block so a failed signature does not leave the
certificate on disk.

**This path is only available with a `.pfx`, which a public CA will no longer
issue.** For a cloud signing service, replace the `signtool sign /f` invocation
with that service's action — the surrounding verification and staging steps do
not change.

The workflow fails closed when the staged executable is not validly signed.
Publishing an intentionally unsigned preview requires a repository owner to
set the Actions variable `ALLOW_UNSIGNED_PREVIEW=true`; that path emits a
prominent warning. Leaving the variable unset cannot silently establish
unsigned releases as the default.
The exception applies only when Windows reports `NotSigned`. A present but
broken, hash-mismatched, expired, or untrusted signature always fails the
release, even when unsigned previews are enabled. Post-release smoke repeats
that check for both architectures.

## The pipeline is already rehearsed

Before spending on a certificate, it is worth knowing the machinery around it
works. CI runs a `Signing pipeline` job on every push that:

1. generates a throwaway self-signed certificate on the runner,
2. signs a build with `signtool`,
3. confirms Windows attaches the signature and — correctly — refuses to
   validate a chain it does not trust,
4. confirms `regx --self-check` agrees with Windows: the unsigned build reports
   `unsigned`, the signed-but-untrusted one reports `untrusted`.

The runner is destroyed afterwards and nothing touches a developer's machine or
trust store. What it establishes is that when a real certificate arrives,
swapping it in is the only remaining step — the surrounding wiring has already
been exercised.

The rehearsal deliberately omits `/tr`. A public timestamp service will not
countersign a certificate it has never seen, and the release workflow does pass
`/tr` with a real one.

## Verifying a release

```powershell
# Maintainer preflight: exact inventory, hashes, PE machines, manifests and SBOM.
python scripts/check_release_identity.py v0.2.0 --require-git-tag
python scripts/check_release_assets.py dist v0.2.0

# Integrity: does this file match what was published?
(Get-FileHash regx-x86_64.exe -Algorithm SHA256).Hash.ToLower()
# Compare against SHA256SUMS from the release.

# Authenticity: who signed it, and does the chain hold here?
Get-AuthenticodeSignature regx-x86_64.exe | Format-List Status, SignerCertificate

# What the binary itself reports, using the same trust store AppLocker uses
.\regx-x86_64.exe --self-check
```

The release also carries a GitHub build provenance attestation, which ties the
binary to the workflow run and commit that produced it:

```bash
gh attestation verify regx-x86_64.exe --repo xmetaads/winregistry
```

That is independent of code signing: it answers "which build produced this",
not "who vouches for it". An enterprise deployment wants both.

The validator has a dependency-free negative suite:

```powershell
python scripts/check_release_assets.py --self-test
python scripts/check_release_identity.py --self-test
```

Together they prove that mismatched Cargo/tag identities, undated or empty
changelog entries, untagged commits, wrong architecture, checksum tampering,
elevation requests, wrong SBOM identity, unexpected assets, and a binary
exactly at the nominal size boundary are rejected. CI runs both suites, and
the publish job runs the same validators against the tagged source and
assembled assets.

## If you cannot sign yet

In order of how well they work:

1. **Run from a path the policy already allows** — usually `%ProgramFiles%` or
   an IT-managed share, not `Downloads`. This satisfies a path rule. It does
   nothing for WDAC.
2. **Have IT add a hash rule** for the specific build. Precise, and it has to be
   redone for every release, which is why publisher rules exist.
3. **Clear the Mark-of-the-Web** on a downloaded copy with `Unblock-File`. This
   removes the SmartScreen interstitial. It does not affect AppLocker or WDAC.

`regx --self-check` reports which of these apply on the machine in front of you.
