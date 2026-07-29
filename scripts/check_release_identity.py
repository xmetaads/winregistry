#!/usr/bin/env python3
"""Validate one release identity across tag, Cargo, Git and changelog."""

from __future__ import annotations

import argparse
import re
import subprocess
import tempfile
from pathlib import Path


TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
PACKAGE = re.compile(
    r'^\[package\]\s*$.*?^version\s*=\s*"([^"]+)"\s*$',
    re.MULTILINE | re.DOTALL,
)
HEADING = re.compile(r"^## \[([^\]]+)\] - (.+)$", re.MULTILINE)
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class IdentityError(ValueError):
    pass


def cargo_version(root: Path) -> str:
    path = root / "Cargo.toml"
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise IdentityError(f"cannot read {path}: {error}") from error
    match = PACKAGE.search(text)
    if not match:
        raise IdentityError("Cargo.toml has no [package] version")
    return match.group(1)


def changelog_entry(root: Path, version: str) -> tuple[str, str]:
    path = root / "CHANGELOG.md"
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise IdentityError(f"cannot read {path}: {error}") from error
    matches = [match for match in HEADING.finditer(text) if match.group(1) == version]
    if len(matches) != 1:
        raise IdentityError(
            f"CHANGELOG.md must contain exactly one heading for {version}; "
            f"found {len(matches)}"
        )
    match = matches[0]
    date = match.group(2).strip()
    if not DATE.fullmatch(date):
        raise IdentityError(
            f"CHANGELOG.md heading for {version} must use YYYY-MM-DD, found {date!r}"
        )
    next_heading = HEADING.search(text, match.end())
    notes = text[match.end() : next_heading.start() if next_heading else len(text)].strip()
    if not notes:
        raise IdentityError(f"CHANGELOG.md entry for {version} has no release notes")
    if not re.search(r"^### (Added|Changed|Deprecated|Removed|Fixed|Security)\s*$", notes, re.MULTILINE):
        raise IdentityError(
            f"CHANGELOG.md entry for {version} needs a Keep a Changelog subsection"
        )
    return date, notes + "\n"


def tags_at_head(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "tag", "--points-at", "HEAD"],
        cwd=root,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or f"git exited {result.returncode}"
        raise IdentityError(f"cannot inspect tags at HEAD: {detail}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def validate(
    root: Path,
    tag: str,
    *,
    require_git_tag: bool,
    known_tags: list[str] | None = None,
) -> tuple[str, str]:
    match = TAG.fullmatch(tag)
    if not match:
        raise IdentityError(f"release tag must be exact vMAJOR.MINOR.PATCH, found {tag!r}")
    version = tag[1:]
    package = cargo_version(root)
    if package != version:
        raise IdentityError(
            f"release tag {tag} does not match Cargo.toml version {package}"
        )
    date, notes = changelog_entry(root, version)
    if require_git_tag:
        tags = tags_at_head(root) if known_tags is None else known_tags
        count = tags.count(tag)
        if count != 1:
            raise IdentityError(
                f"checked-out commit must carry tag {tag} exactly once; "
                f"tags at HEAD are {tags}"
            )
    return date, notes


def write_fixture(root: Path, *, version: str = "0.2.0", date: str = "2026-07-29") -> None:
    (root / "Cargo.toml").write_text(
        f'[package]\nname = "regx"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    (root / "CHANGELOG.md").write_text(
        "# Changelog\n\n"
        f"## [{version}] - {date}\n\n"
        "### Added\n\n- Release identity fixture.\n\n"
        "## [0.1.0] - 2026-01-01\n\n### Added\n\n- Earlier release.\n",
        encoding="utf-8",
    )


def self_test() -> list[str]:
    with tempfile.TemporaryDirectory(prefix="regx-release-identity-") as raw:
        root = Path(raw)

        def must_fail(fragment: str, tag: str = "v0.2.0") -> None:
            try:
                validate(
                    root,
                    tag,
                    require_git_tag=True,
                    known_tags=["v0.2.0"],
                )
            except IdentityError as error:
                if fragment not in str(error):
                    raise IdentityError(
                        f"negative test expected {fragment!r}, found: {error}"
                    )
            else:
                raise IdentityError(
                    f"invalid identity passed validation; expected {fragment!r}"
                )

        write_fixture(root)
        date, notes = validate(
            root,
            "v0.2.0",
            require_git_tag=True,
            known_tags=["v0.2.0"],
        )
        if date != "2026-07-29" or "Release identity fixture." not in notes:
            raise IdentityError("valid fixture returned the wrong date or notes")

        write_fixture(root, version="0.3.0")
        must_fail("does not match Cargo.toml")

        write_fixture(root, date="Unreleased")
        must_fail("must use YYYY-MM-DD")

        write_fixture(root)
        (root / "CHANGELOG.md").write_text(
            "# Changelog\n\n## [0.2.0] - 2026-07-29\n\n"
            "## [0.1.0] - 2026-01-01\n\n### Added\n\n- Earlier.\n",
            encoding="utf-8",
        )
        must_fail("has no release notes")

        write_fixture(root)
        try:
            validate(
                root,
                "v0.2.0",
                require_git_tag=True,
                known_tags=[],
            )
        except IdentityError as error:
            if "tags at HEAD" not in str(error):
                raise IdentityError(f"missing-tag negative test misfired: {error}")
        else:
            raise IdentityError("untagged commit passed release identity validation")

        write_fixture(root)
        must_fail("exact vMAJOR.MINOR.PATCH", "0.2.0")

    return [
        "matching tag, package, dated changelog and notes accepted",
        "Cargo version mismatch rejected",
        "Unreleased changelog rejected",
        "empty release notes rejected",
        "tag absent from HEAD rejected",
        "non-canonical tag rejected",
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tag", nargs="?")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--require-git-tag", action="store_true")
    parser.add_argument("--notes-out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            messages = self_test()
        else:
            if args.tag is None:
                parser.error("TAG is required unless --self-test is used")
            date, notes = validate(
                args.root,
                args.tag,
                require_git_tag=args.require_git_tag,
            )
            if args.notes_out:
                args.notes_out.parent.mkdir(parents=True, exist_ok=True)
                args.notes_out.write_text(notes, encoding="utf-8", newline="\n")
            messages = [
                f"{args.tag}: Cargo version, changelog date {date}, and notes agree",
                *(
                    [f"{args.tag}: checked-out HEAD carries the exact tag"]
                    if args.require_git_tag
                    else []
                ),
                *(
                    [f"release notes -> {args.notes_out}"]
                    if args.notes_out
                    else []
                ),
            ]
    except (OSError, IdentityError) as error:
        print(f"FAIL\n  {error}")
        return 1
    print("PASS")
    for message in messages:
        print(f"  ok    {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
