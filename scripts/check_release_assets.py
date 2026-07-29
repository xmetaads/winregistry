#!/usr/bin/env python3
"""Fail-closed validation for a complete regx release asset directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import tempfile
from pathlib import Path


EXPECTED = {
    "regx-x86_64.exe",
    "regx-aarch64.exe",
    "regx.cdx.json",
}
MACHINES = {
    "regx-x86_64.exe": 0x8664,
    "regx-aarch64.exe": 0xAA64,
}
SIZE_LIMIT = 2 * 1024 * 1024
FORBIDDEN_IMPORTS = (b"VCRUNTIME140", b"MSVCP140", b"api-ms-win-crt")
TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
CHECKSUM = re.compile(r"^([0-9a-fA-F]{64})\s+\*?([^/\\]+)$")


class ReleaseError(ValueError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pe_machine(data: bytes, name: str) -> int:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ReleaseError(f"{name} is not a PE file")
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset + 6 > len(data) or data[offset : offset + 4] != b"PE\0\0":
        raise ReleaseError(f"{name} has an invalid PE header offset/signature")
    return struct.unpack_from("<H", data, offset + 4)[0]


def validate_executable(path: Path, expected_machine: int) -> list[str]:
    data = path.read_bytes()
    if len(data) >= SIZE_LIMIT:
        raise ReleaseError(
            f"{path.name} is {len(data)} bytes; contract requires <2 MiB "
            f"({SIZE_LIMIT} bytes)"
        )
    machine = pe_machine(data, path.name)
    if machine != expected_machine:
        raise ReleaseError(
            f"{path.name} has PE machine 0x{machine:04X}; "
            f"expected 0x{expected_machine:04X}"
        )
    lowered = data.lower()
    if (
        b"requestedexecutionlevel" not in lowered
        or b'level="asinvoker"' not in lowered
    ):
        raise ReleaseError(f"{path.name} does not embed an asInvoker manifest")
    if (
        b'level="requireadministrator"' in lowered
        or b'level="highestavailable"' in lowered
    ):
        raise ReleaseError(f"{path.name} requests elevation")
    for dependency in FORBIDDEN_IMPORTS:
        if dependency.lower() in lowered:
            raise ReleaseError(
                f"{path.name} imports {dependency.decode()}; static CRT required"
            )
    return [
        f"{path.name}: {len(data)} bytes",
        f"{path.name}: PE machine 0x{machine:04X}, asInvoker, static CRT",
    ]


def read_checksums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        match = CHECKSUM.fullmatch(raw)
        if not match:
            raise ReleaseError(f"SHA256SUMS line {number} is malformed: {raw!r}")
        digest, name = match.groups()
        if name not in EXPECTED:
            raise ReleaseError(f"SHA256SUMS names unexpected asset {name!r}")
        if name in entries:
            raise ReleaseError(f"SHA256SUMS names {name!r} more than once")
        entries[name] = digest.lower()
    if set(entries) != EXPECTED:
        missing = sorted(EXPECTED - set(entries))
        extra = sorted(set(entries) - EXPECTED)
        raise ReleaseError(f"checksum coverage mismatch; missing={missing}, extra={extra}")
    return entries


def validate_sbom(path: Path, version: str) -> str:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"{path.name} is not valid UTF-8 JSON: {error}") from error
    component = document.get("metadata", {}).get("component", {})
    actual = (
        document.get("bomFormat"),
        str(document.get("specVersion")),
        component.get("name"),
        str(component.get("version")),
    )
    expected = ("CycloneDX", "1.5", "regx", version)
    if actual != expected:
        raise ReleaseError(
            "SBOM identity mismatch; "
            f"found format/spec/name/version={actual}, expected={expected}"
        )
    return f"{path.name}: CycloneDX 1.5 component regx {version}"


def validate(directory: Path, tag: str) -> list[str]:
    match = TAG.fullmatch(tag)
    if not match:
        raise ReleaseError(f"tag must be exact vMAJOR.MINOR.PATCH, found {tag!r}")
    version = tag[1:]
    if not directory.is_dir():
        raise ReleaseError(f"release directory does not exist: {directory}")

    present = {path.name for path in directory.iterdir() if path.is_file()}
    required = EXPECTED | {"SHA256SUMS"}
    missing = sorted(required - present)
    release_like = {
        name
        for name in present
        if name.endswith(".exe") or name.endswith(".cdx.json")
    }
    unexpected = sorted(release_like - EXPECTED)
    if missing or unexpected:
        raise ReleaseError(
            f"release asset set mismatch; missing={missing}, unexpected={unexpected}"
        )

    entries = read_checksums(directory / "SHA256SUMS")
    messages: list[str] = []
    for name in sorted(EXPECTED):
        actual = sha256(directory / name)
        if actual != entries[name]:
            raise ReleaseError(
                f"checksum mismatch for {name}: expected {entries[name]}, found {actual}"
            )
        messages.append(f"{name}: SHA-256 {actual}")

    for name, machine in MACHINES.items():
        messages.extend(validate_executable(directory / name, machine))
    messages.append(validate_sbom(directory / "regx.cdx.json", version))
    return messages


def fake_pe(machine: int) -> bytes:
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, machine)
    data.extend(b'<requestedExecutionLevel level="asInvoker" uiAccess="false"/>')
    return bytes(data)


def write_fixture(directory: Path, version: str = "0.2.0") -> None:
    for name, machine in MACHINES.items():
        (directory / name).write_bytes(fake_pe(machine))
    (directory / "regx.cdx.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "metadata": {
                    "component": {"name": "regx", "version": version}
                },
            }
        ),
        encoding="utf-8",
    )
    (directory / "SHA256SUMS").write_text(
        "".join(
            f"{sha256(directory / name)}  {name}\n" for name in sorted(EXPECTED)
        ),
        encoding="ascii",
    )


def self_test() -> list[str]:
    with tempfile.TemporaryDirectory(prefix="regx-release-check-") as raw:
        directory = Path(raw)

        def must_fail(fragment: str) -> None:
            try:
                validate(directory, "v0.2.0")
            except ReleaseError as error:
                if fragment not in str(error):
                    raise ReleaseError(
                        f"negative test expected {fragment!r}, found: {error}"
                    )
            else:
                raise ReleaseError(
                    f"invalid release passed validation; expected {fragment!r}"
                )

        write_fixture(directory)
        validate(directory, "v0.2.0")

        original = (directory / "regx-aarch64.exe").read_bytes()
        damaged = bytearray(original)
        struct.pack_into("<H", damaged, 0x84, 0x8664)
        (directory / "regx-aarch64.exe").write_bytes(damaged)
        (directory / "SHA256SUMS").write_text(
            "".join(
                f"{sha256(directory / name)}  {name}\n"
                for name in sorted(EXPECTED)
            ),
            encoding="ascii",
        )
        must_fail("PE machine")

        write_fixture(directory)
        (directory / "regx-x86_64.exe").write_bytes(
            (directory / "regx-x86_64.exe").read_bytes() + b"tampered"
        )
        must_fail("checksum mismatch")

        write_fixture(directory)
        binary = directory / "regx-x86_64.exe"
        binary.write_bytes(
            binary.read_bytes()
            + b'<requestedExecutionLevel level="requireAdministrator"/>'
        )
        (directory / "SHA256SUMS").write_text(
            "".join(
                f"{sha256(directory / name)}  {name}\n"
                for name in sorted(EXPECTED)
            ),
            encoding="ascii",
        )
        must_fail("requests elevation")

        write_fixture(directory)
        sbom = json.loads((directory / "regx.cdx.json").read_text(encoding="utf-8"))
        sbom["metadata"]["component"]["version"] = "9.9.9"
        (directory / "regx.cdx.json").write_text(json.dumps(sbom), encoding="utf-8")
        (directory / "SHA256SUMS").write_text(
            "".join(
                f"{sha256(directory / name)}  {name}\n"
                for name in sorted(EXPECTED)
            ),
            encoding="ascii",
        )
        must_fail("SBOM identity mismatch")

        write_fixture(directory)
        (directory / "unexpected.exe").write_bytes(fake_pe(0x8664))
        must_fail("asset set mismatch")
        (directory / "unexpected.exe").unlink()

        write_fixture(directory)
        binary = directory / "regx-x86_64.exe"
        binary.write_bytes(binary.read_bytes().ljust(SIZE_LIMIT, b"\0"))
        (directory / "SHA256SUMS").write_text(
            "".join(
                f"{sha256(directory / name)}  {name}\n"
                for name in sorted(EXPECTED)
            ),
            encoding="ascii",
        )
        must_fail("contract requires <2 MiB")

    return [
        "valid complete fixture accepted",
        "wrong PE architecture rejected",
        "checksum tampering rejected",
        "elevation manifest rejected",
        "wrong SBOM identity rejected",
        "unexpected release asset rejected",
        "strict binary-size boundary rejected",
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path, nargs="?")
    parser.add_argument("tag", nargs="?")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            messages = self_test()
        else:
            if args.directory is None or args.tag is None:
                parser.error("DIRECTORY and TAG are required unless --self-test is used")
            messages = validate(args.directory, args.tag)
    except (OSError, ReleaseError) as error:
        print(f"FAIL\n  {error}")
        return 1
    print("PASS")
    for message in messages:
        print(f"  ok    {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
