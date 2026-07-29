#!/usr/bin/env python3
"""Verify that winregistry.org serves the reviewed website tree.

This is deliberately dependency-free so a scheduled GitHub workflow can catch
an old or misconfigured Vercel deployment without installing a browser stack.
It compares normalized text because an intermediary may canonicalize line
endings, but otherwise requires the deployed HTML and key assets to match the
checked-in bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "website"
VERCEL = ROOT / "vercel.json"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RequestError(RuntimeError):
    """A transport failure, distinct from an HTTP response."""


def request(url: str, *, follow: bool = True) -> tuple[int, bytes, object]:
    handlers: list[object] = [urllib.request.HTTPSHandler(context=ssl.create_default_context())]
    if not follow:
        handlers.append(NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "regx-deployed-site-check/1"},
    )
    try:
        with opener.open(req, timeout=20) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as error:
        return error.code, error.read(), error.headers
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        reason = getattr(error, "reason", error)
        raise RequestError(f"{url}: {reason}") from error


def normalized_html(data: bytes) -> bytes:
    text = data.decode("utf-8").replace("\r\n", "\n").rstrip() + "\n"
    return text.encode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def self_test() -> int:
    original = urllib.request.build_opener

    class FailingOpener:
        def open(self, *_args, **_kwargs):
            raise urllib.error.URLError(OSError("deliberate transport failure"))

    try:
        urllib.request.build_opener = lambda *_handlers: FailingOpener()
        try:
            request("https://example.invalid/")
        except RequestError as error:
            if "deliberate transport failure" not in str(error):
                raise AssertionError(f"transport reason was lost: {error}") from error
        else:
            raise AssertionError("transport failure did not become RequestError")
    finally:
        urllib.request.build_opener = original
    print("PASS: deployed-site transport failure is reported without a traceback")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base-url",
        default="https://www.winregistry.org",
        help="deployed origin to verify",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="exercise transport-failure handling without network access",
    )
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    base = args.base_url.rstrip("/")
    failures: list[str] = []
    successes: list[str] = []

    for route, local_name in (("/", "index.html"), ("/docs", "docs.html")):
        status, body, headers = request(base + route)
        if status != 200:
            failures.append(f"{route}: expected HTTP 200, got {status}")
            continue
        local = (SITE / local_name).read_bytes()
        actual_hash = digest(normalized_html(body))
        expected_hash = digest(normalized_html(local))
        if actual_hash != expected_hash:
            failures.append(
                f"{route}: deployed HTML differs from {local_name} "
                f"(live {actual_hash}, local {expected_hash})"
            )
        else:
            successes.append(f"{route}: HTML matches {local_name}")

        config = json.loads(VERCEL.read_text(encoding="utf-8"))
        global_headers = {
            item["key"].lower(): item["value"]
            for rule in config["headers"]
            if rule["source"] == "/(.*)"
            for item in rule["headers"]
        }
        for name, expected in global_headers.items():
            actual = headers.get(name)
            if actual != expected:
                failures.append(
                    f"{route}: header {name} is {actual!r}, expected {expected!r}"
                )
        if not any(f.startswith(f"{route}: header ") for f in failures):
            successes.append(f"{route}: security headers match vercel.json")

    status, _, headers = request(base + "/docs.html", follow=False)
    location = headers.get("location", "")
    resolved = urllib.parse.urljoin(base + "/docs.html", location)
    if status not in (301, 302, 307, 308) or resolved.rstrip("/") != base + "/docs":
        failures.append(
            f"/docs.html: expected redirect to {base}/docs, got {status} {location!r}"
        )
    else:
        successes.append("/docs.html: clean-URL redirect is active")

    missing_route = "/__regx_deployment_probe_missing__"
    status, body, _ = request(base + missing_route)
    if status != 404:
        failures.append(f"{missing_route}: expected HTTP 404, got {status}")
    elif normalized_html(body) != normalized_html((SITE / "404.html").read_bytes()):
        failures.append(f"{missing_route}: deployed 404 body differs from website/404.html")
    else:
        successes.append("unknown routes serve the reviewed 404 page with status 404")

    for route, local_path in (
        ("/assets/img/og-winregistry.png", SITE / "assets" / "img" / "og-winregistry.png"),
        ("/assets/css/style.css", SITE / "assets" / "css" / "style.css"),
        ("/assets/js/app.js", SITE / "assets" / "js" / "app.js"),
        ("/assets/js/theme.js", SITE / "assets" / "js" / "theme.js"),
    ):
        status, body, _ = request(base + route)
        if status != 200:
            failures.append(f"{route}: expected HTTP 200, got {status}")
        elif digest(body) != digest(local_path.read_bytes()):
            failures.append(f"{route}: deployed bytes differ from {local_path.relative_to(ROOT)}")
        else:
            successes.append(f"{route}: deployed bytes match")

    print("PASS" if not failures else "FAIL")
    for message in successes:
        print(f"  ok    {message}")
    for message in failures:
        print(f"  FAIL  {message}")
    print(f"\n{len(successes)} ok, {len(failures)} fail")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RequestError as error:
        print("FAIL")
        print(f"  FAIL  network request failed: {error}")
        print("\n0 ok, 1 fail")
        sys.exit(1)
