#!/usr/bin/env python3
"""Static safety checks for GitHub workflows and repository community files."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
GITHUB = ROOT / ".github"
USE = re.compile(r"^\s*(?:-\s+)?uses:\s+(\S+?)(?:\s+#\s*(\S.*))?\s*$")
PINNED = re.compile(r"^([^@]+)@([0-9a-f]{40})$")


def main() -> int:
    failures: list[str] = []
    checked = 0
    files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    if not files:
        failures.append("no workflow files found")

    for path in files:
        text = path.read_text(encoding="utf-8")
        if "pull_request_target:" in text:
            failures.append(f"{path.name}: pull_request_target is forbidden")
        if "workflow_run:" in text:
            failures.append(f"{path.name}: workflow_run is forbidden")
        if re.search(r"^\s*if:.*\bsecrets\.", text, re.MULTILINE):
            failures.append(
                f"{path.name}: secrets cannot be referenced directly by an if expression"
            )
        if "permissions:" not in text:
            failures.append(f"{path.name}: no explicit permissions block")

        for number, line in enumerate(text.splitlines(), 1):
            if "uses:" not in line:
                continue
            match = USE.match(line)
            if not match:
                failures.append(f"{path.name}:{number}: cannot parse uses line")
                continue
            spec, version_comment = match.groups()
            if spec.startswith("./"):
                continue
            checked += 1
            pin = PINNED.match(spec)
            if not pin:
                failures.append(
                    f"{path.name}:{number}: action is not pinned to a full commit SHA: {spec}"
                )
            if not version_comment:
                failures.append(
                    f"{path.name}:{number}: pinned action needs a version comment for updates"
                )

    smoke = WORKFLOWS / "release-smoke.yml"
    if smoke.is_file():
        text = smoke.read_text(encoding="utf-8")
        provenance_loop = (
            'foreach ($asset in @("dist/regx-x86_64.exe", '
            '"dist/regx-aarch64.exe"))'
        )
        if provenance_loop not in text or "gh attestation verify $asset" not in text:
            failures.append(
                f"{smoke.name}: release smoke does not attest both executable assets"
            )
        for machine in ("0x8664", "0xAA64"):
            if machine not in text:
                failures.append(
                    f"{smoke.name}: release smoke does not verify PE machine {machine}"
                )
        for field in (
            '$sbom.bomFormat -ne "CycloneDX"',
            '$sbom.specVersion -ne "1.5"',
            '$sbom.metadata.component.name -ne "regx"',
            "$sbom.metadata.component.version -ne $expectedVersion",
        ):
            if field not in text:
                failures.append(
                    f"{smoke.name}: release smoke is missing SBOM contract `{field}`"
                )
        if '$signature.Status -notin @("Valid", "NotSigned")' not in text:
            failures.append(
                f"{smoke.name}: release smoke accepts an invalid Authenticode state"
            )
    else:
        failures.append("release-smoke.yml is missing")

    release = WORKFLOWS / "release.yml"
    if release.is_file():
        text = release.read_text(encoding="utf-8")
        for contract in (
            'expected exactly one generated CycloneDX document',
            'for name in regx-x86_64.exe regx-aarch64.exe regx.cdx.json',
            'expected exactly one %s artifact',
        ):
            if contract not in text:
                failures.append(
                    f"{release.name}: release inventory is missing contract `{contract}`"
                )
        signing_contracts = (
            'if ($LASTEXITCODE -ne 0) { throw "signtool verification failed" }',
            '$sig.Status -eq "NotSigned" -and $env:ALLOW_UNSIGNED_PREVIEW -eq "true"',
            '$sig.Status -ne "NotSigned"',
            "ALLOW_UNSIGNED_PREVIEW never permits a broken or untrusted signature",
        )
        for contract in signing_contracts:
            if contract not in text:
                failures.append(
                    f"{release.name}: unsigned-preview policy is missing `{contract}`"
                )
        if 'python3 scripts/check_release_assets.py dist "$RELEASE_TAG"' not in text:
            failures.append(
                f"{release.name}: publish does not run the shared release asset validator"
            )
        if "$limit = 2 * 1MB" not in text or "if ($bytes -ge $limit)" not in text:
            failures.append(
                f"{release.name}: binary-size check does not enforce the strict <2 MiB bound"
            )
        identity_call = (
            'python3 scripts/check_release_identity.py "$RELEASE_TAG"'
        )
        if text.count(identity_call) != 2:
            failures.append(
                f"{release.name}: preflight and publish must share the release identity validator"
            )
        if "--require-git-tag --notes-out dist/NOTES.md" not in text:
            failures.append(
                f"{release.name}: publish does not extract notes through the identity validator"
            )
        if "awk -v head=" in text:
            failures.append(
                f"{release.name}: release notes still use a second inline parser"
            )

    ci = WORKFLOWS / "ci.yml"
    if ci.is_file():
        text = ci.read_text(encoding="utf-8")
        if "python3 scripts/check_release_assets.py --self-test" not in text:
            failures.append("ci.yml does not exercise release-validator negative cases")
        if "python3 scripts/check_release_identity.py --self-test" not in text:
            failures.append(
                "ci.yml does not exercise release-identity negative cases"
            )
        if "$limit = 2 * 1MB" not in text or "if ($bytes -ge $limit)" not in text:
            failures.append(
                "ci.yml binary-size check does not enforce the strict <2 MiB bound"
            )
    else:
        failures.append("ci.yml is missing")

    release_validator = ROOT / "scripts" / "check_release_assets.py"
    if not release_validator.is_file():
        failures.append("scripts/check_release_assets.py is missing")
    elif "SIZE_LIMIT = 2 * 1024 * 1024" not in release_validator.read_text(
        encoding="utf-8"
    ):
        failures.append(
            "release validator binary-size contract does not match CI's strict <2 MiB bound"
        )
    identity_validator = ROOT / "scripts" / "check_release_identity.py"
    if not identity_validator.is_file():
        failures.append("scripts/check_release_identity.py is missing")

    required_repository_files = (
        GITHUB / "CODEOWNERS",
        GITHUB / "PULL_REQUEST_TEMPLATE.md",
        GITHUB / "SUPPORT.md",
        GITHUB / "dependabot.yml",
        GITHUB / "ISSUE_TEMPLATE" / "config.yml",
        GITHUB / "ISSUE_TEMPLATE" / "bug.yml",
        GITHUB / "ISSUE_TEMPLATE" / "feature.yml",
        GITHUB / "ISSUE_TEMPLATE" / "question.yml",
        ROOT / "ROADMAP.md",
        ROOT / "SECURITY.md",
    )
    for path in required_repository_files:
        if not path.is_file():
            failures.append(
                f"repository community surface is missing {path.relative_to(ROOT)}"
            )

    cargo_toml = ROOT / "Cargo.toml"
    security = ROOT / "SECURITY.md"
    if cargo_toml.is_file() and security.is_file():
        cargo_text = cargo_toml.read_text(encoding="utf-8")
        dependency_section = re.search(
            r"^\[dependencies\]\s*$\n(.*?)(?=^\[|\Z)",
            cargo_text,
            re.MULTILINE | re.DOTALL,
        )
        if not dependency_section:
            failures.append("Cargo.toml has no parseable [dependencies] section")
        else:
            dependencies = re.findall(
                r"^([A-Za-z0-9_-]+)\s*=",
                dependency_section.group(1),
                re.MULTILINE,
            )
            security_text = security.read_text(encoding="utf-8")
            security_flat = re.sub(r"\s+", " ", security_text)
            number_words = {
                0: "Zero",
                1: "One",
                2: "Two",
                3: "Three",
                4: "Four",
                5: "Five",
                6: "Six",
                7: "Seven",
                8: "Eight",
                9: "Nine",
                10: "Ten",
            }
            count_word = number_words.get(len(dependencies), str(len(dependencies)))
            expected_claim = (
                f"{count_word} direct dependencies, "
                + ", ".join(f"`{name}`" for name in dependencies[:-1])
                + f", and `{dependencies[-1]}`"
            )
            if expected_claim not in security_flat:
                failures.append(
                    "SECURITY.md direct-dependency claim does not match Cargo.toml: "
                    f"expected `{expected_claim}`"
                )

    codeowners = GITHUB / "CODEOWNERS"
    if codeowners.is_file() and not re.search(
        r"^\*\s+@xmetaads(?:\s|$)",
        codeowners.read_text(encoding="utf-8"),
        re.MULTILINE,
    ):
        failures.append("CODEOWNERS must assign the repository root to @xmetaads")

    issue_config = GITHUB / "ISSUE_TEMPLATE" / "config.yml"
    if issue_config.is_file():
        text = issue_config.read_text(encoding="utf-8")
        if "blank_issues_enabled: false" not in text:
            failures.append("issue forms must disable unstructured blank issues")
        if "/security/advisories/new" not in text:
            failures.append("issue forms must route vulnerabilities to private advisories")

    for name in ("bug.yml", "feature.yml", "question.yml"):
        path = GITHUB / "ISSUE_TEMPLATE" / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for field in ("name:", "description:", "body:"):
            if not re.search(rf"^{re.escape(field)}", text, re.MULTILINE):
                failures.append(f"{path.relative_to(ROOT)} is missing top-level {field}")

    dependabot = GITHUB / "dependabot.yml"
    if dependabot.is_file():
        text = dependabot.read_text(encoding="utf-8")
        for ecosystem in ("cargo", "github-actions"):
            if not re.search(
                rf'package-ecosystem:\s*["\']?{re.escape(ecosystem)}["\']?\s*$',
                text,
                re.MULTILINE,
            ):
                failures.append(f"dependabot.yml is missing ecosystem {ecosystem}")
        if len(re.findall(r'interval:\s*["\']?weekly["\']?\s*$', text, re.MULTILINE)) < 2:
            failures.append("dependabot.yml must schedule both ecosystems weekly")

    pull_request_template = GITHUB / "PULL_REQUEST_TEMPLATE.md"
    if pull_request_template.is_file():
        text = pull_request_template.read_text(encoding="utf-8").lower()
        contracts = {
            "tests": r"\btests?\b",
            "policy": r"\bpolicy\b",
            "rollback": r"\brollback\b|\brolls back\b",
            "json": r"\bjson\b",
        }
        for contract, pattern in contracts.items():
            if not re.search(pattern, text):
                failures.append(
                    f"PULL_REQUEST_TEMPLATE.md is missing the {contract} review contract"
                )

    if failures:
        print("FAIL")
        for failure in failures:
            print(f"  error {failure}")
        return 1
    print(f"PASS\n  ok    {checked} external action use(s) pinned to full commit SHAs")
    print(f"  ok    {len(files)} workflow(s) declare permissions and avoid privileged relay triggers")
    print(
        f"  ok    {len(required_repository_files)} repository community/security files are present"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
