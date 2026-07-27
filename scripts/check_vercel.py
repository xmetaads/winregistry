#!/usr/bin/env python3
"""Assert vercel.json still matches what the pages actually need.

The deployment config and the markup drift apart silently: a page starts
loading a new origin and the CSP blocks it, or someone adds a `.html` link
while cleanUrls is on and every visitor eats a redirect. Both are invisible
until production, so they are checked here.

    python3 scripts/check_vercel.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "website"
CONFIG = ROOT / "vercel.json"

fails: list[str] = []
oks: list[str] = []

cfg = json.loads(CONFIG.read_text(encoding="utf-8"))

# --------------------------------------------------------------------------
# Routing
# --------------------------------------------------------------------------
if cfg.get("outputDirectory") != "website":
    fails.append("outputDirectory must be 'website'")
else:
    oks.append("outputDirectory = website")

if cfg.get("cleanUrls") is not True:
    fails.append("cleanUrls must be true: every internal link uses the extensionless form")
else:
    oks.append("cleanUrls = true")

if cfg.get("trailingSlash") is not False:
    fails.append("trailingSlash must be false, or a page is reachable at two URLs")
else:
    oks.append("trailingSlash = false")

# With cleanUrls on, an internal .html link costs a 308 on every visit.
for page in sorted(SITE.glob("*.html")):
    html = page.read_text(encoding="utf-8")
    for ref in re.findall(r'href="(/[^"]*\.html[^"]*)"', html):
        fails.append(f"{page.name}: {ref} should use the clean URL form")
if not any("clean URL form" in f for f in fails):
    oks.append("no internal link relies on a .html redirect")

# --------------------------------------------------------------------------
# Headers
# --------------------------------------------------------------------------
headers: dict[str, str] = {}
asset_cache = ""
for block in cfg.get("headers", []):
    for h in block["headers"]:
        if block["source"].startswith("/assets"):
            if h["key"] == "Cache-Control":
                asset_cache = h["value"]
        else:
            headers.setdefault(h["key"], h["value"])

REQUIRED = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "X-Frame-Options",
    "Permissions-Policy",
]
for key in REQUIRED:
    if key not in headers:
        fails.append(f"missing header {key}")
if all(k in headers for k in REQUIRED):
    oks.append(f"all {len(REQUIRED)} security headers declared")

csp = headers.get("Content-Security-Policy", "")
for bad in ("unsafe-inline", "unsafe-eval"):
    if bad in csp:
        fails.append(f"CSP contains {bad}")
if csp and "unsafe" not in csp:
    oks.append("CSP has no unsafe-* directives")

# Asset filenames carry no content hash, so an immutable cache would strand
# users on a stale stylesheet after every deploy.
if "immutable" in asset_cache:
    fails.append(
        "assets are cached immutable but their filenames have no content hash; "
        "a deploy would not reach existing visitors"
    )
elif asset_cache:
    oks.append(f"asset cache is revalidating: {asset_cache}")

# --------------------------------------------------------------------------
# Every origin the browser actually fetches must be allowed
# --------------------------------------------------------------------------
SUBRESOURCE = re.compile(
    r'<link\b[^>]*\brel="(?:stylesheet|preload|icon|preconnect)"[^>]*\bhref="(https?://[^/"]+)"'
    r'|<script\b[^>]*\bsrc="(https?://[^/"]+)"'
    r'|<img\b[^>]*\bsrc="(https?://[^/"]+)"'
)
origins: set[str] = set()
for page in sorted(SITE.glob("*.html")):
    for groups in SUBRESOURCE.findall(page.read_text(encoding="utf-8")):
        origins.update(g for g in groups if g)

for origin in sorted(origins):
    if origin not in csp:
        fails.append(f"a page loads {origin} but the CSP does not allow it")
if origins and not any("does not allow" in f for f in fails):
    oks.append(f"CSP covers every external subresource: {', '.join(sorted(origins))}")

# --------------------------------------------------------------------------
# Files Vercel serves specially
# --------------------------------------------------------------------------
for name in ["404.html", "robots.txt", "sitemap.xml"]:
    if (SITE / name).is_file():
        oks.append(f"{name} present")
    else:
        fails.append(f"{name} is missing from the output directory")

# A sitemap that lists a redirecting URL wastes crawl budget on every entry.
sitemap = SITE / "sitemap.xml"
if sitemap.is_file():
    for loc in re.findall(r"<loc>([^<]+)</loc>", sitemap.read_text(encoding="utf-8")):
        if loc.endswith(".html"):
            fails.append(f"sitemap lists {loc}, which redirects under cleanUrls")

print("PASS")
for m in oks:
    print("  ok    " + m)
if fails:
    print("FAIL")
    for m in fails:
        print("  FAIL  " + m)
print(f"\n{len(oks)} ok, {len(fails)} fail")
sys.exit(1 if fails else 0)
