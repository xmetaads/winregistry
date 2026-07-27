#!/usr/bin/env python3
"""Static checks for the winregistry.org pages.

Filesystem-only and dependency-free so it runs identically on a developer's
machine and on a CI runner. It answers the questions that would otherwise only
surface after a deploy: does every link resolve, does every text/background pair
clear WCAG AA, and are the rules the design system committed to still in force.

    python3 scripts/check_site.py
"""
from __future__ import annotations

import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "website"
CSS = SITE / "assets" / "css" / "style.css"

fails: list[str] = []
warns: list[str] = []
oks: list[str] = []


def ok(m: str) -> None:
    oks.append(m)


def fail(m: str) -> None:
    fails.append(m)


def warn(m: str) -> None:
    warns.append(m)


pages = sorted(SITE.glob("*.html"))
if not pages:
    sys.exit(f"no pages found under {SITE}")


# --------------------------------------------------------------------------
# References and anchors
# --------------------------------------------------------------------------
def resolve(ref: str) -> Path | None:
    """Map a site-absolute or relative href to a file, honouring cleanUrls."""
    stem = ref.split("#")[0].split("?")[0].lstrip("/").rstrip("/")
    if stem in ("", "."):
        return SITE / "index.html"
    direct = SITE / stem
    if direct.is_file():
        return direct
    clean = SITE / (stem + ".html")
    if clean.is_file():
        return clean
    return None


for page in pages:
    html = page.read_text(encoding="utf-8")
    ids = set(re.findall(r'id="([^"]+)"', html))

    for ref in re.findall(r'(?:href|src)="([^"]+)"', html):
        if ref.startswith(("http://", "https://", "mailto:", "data:", "#")):
            continue
        target = resolve(ref)
        if target is None:
            fail(f"{page.name}: broken reference -> {ref}")
            continue
        if "#" in ref:
            frag = ref.split("#", 1)[1]
            other = target.read_text(encoding="utf-8")
            if f'id="{frag}"' not in other:
                fail(f"{page.name}: {ref} points at a missing anchor")

    for anchor in re.findall(r'href="#([^"]+)"', html):
        if anchor not in ids:
            fail(f"{page.name}: dead in-page anchor #{anchor}")

ok(f"references and anchors resolve across {len(pages)} page(s)")


# --------------------------------------------------------------------------
# Markup rules the design system commits to
# --------------------------------------------------------------------------
EMOJI = [(0x1F300, 0x1FAFF), (0x2600, 0x27BF), (0xFE0F, 0xFE0F), (0x2B00, 0x2BFF)]

for page in pages:
    html = page.read_text(encoding="utf-8")

    for i, line in enumerate(html.splitlines(), 1):
        for ch in line:
            if any(lo <= ord(ch) <= hi for lo, hi in EMOJI):
                fail(
                    f"{page.name}:{i}: emoji {ch!r} "
                    f"({unicodedata.name(ch, '?')}) - icons must be SVG"
                )

    for m in re.finditer(r"<button\b([^>]*)>(.*?)</button>", html, re.S):
        attrs, inner = m.group(1), m.group(2)
        if "aria-label" not in attrs and not re.sub(r"<[^>]+>", "", inner).strip():
            fail(f"{page.name}: a <button> has no accessible name")

    # The CSP sent by Vercel omits 'unsafe-inline', so these would be blocked.
    if re.search(r'<style\b', html):
        fail(f"{page.name}: inline <style> is blocked by the CSP")
    for m in re.finditer(r'style="[^"]*"', html):
        fail(f"{page.name}: inline style attribute {m.group(0)!r} is blocked by the CSP")
    for m in re.finditer(r"<script\b([^>]*)>", html):
        if "src=" not in m.group(1):
            fail(f"{page.name}: inline <script> is blocked by the CSP")

    if 'lang="' not in html[: html.find(">", html.find("<html")) + 1]:
        fail(f"{page.name}: <html> is missing lang")
    if 'name="viewport"' not in html:
        fail(f"{page.name}: missing viewport meta")
    if "user-scalable=no" in html or "maximum-scale=1" in html:
        fail(f"{page.name}: the viewport disables zoom")
    if "<h1" not in html:
        fail(f"{page.name}: no <h1>")

ok("no emoji icons, no inline style or script, zoom allowed, each page has an h1")


# --------------------------------------------------------------------------
# Contrast, read from the stylesheet rather than hard-coded here
# --------------------------------------------------------------------------
def channel(c: float) -> float:
    c /= 255
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def ratio(fg: str, bg: str) -> float:
    a, b = luminance(fg), luminance(bg)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


css = CSS.read_text(encoding="utf-8")


def tokens(selector: str) -> dict[str, str]:
    """Pull `--name: #hex;` declarations out of one rule block."""
    m = re.search(re.escape(selector) + r"\s*\{(.*?)\n\}", css, re.S)
    if not m:
        sys.exit(f"could not find the {selector} block in style.css")
    return {
        name: value
        for name, value in re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})", m.group(1))
    }


dark = tokens(":root")
light = {**dark, **tokens(':root[data-theme=\'light\']')}

CASES = [
    ("body text on page", "color-foreground", "color-background"),
    ("muted text on page", "color-muted-foreground", "color-background"),
    ("accent text on page", "color-accent-text", "color-background"),
    ("body text on card", "color-foreground", "color-muted"),
    ("muted text on card", "color-muted-foreground", "color-muted"),
    ("accent text on card", "color-accent-text", "color-muted"),
    ("success pill", "color-success", "color-muted"),
    ("destructive pill", "color-destructive", "color-muted"),
]

for theme_name, theme in (("dark", dark), ("light", light)):
    for label, fg, bg in CASES:
        if fg not in theme or bg not in theme:
            warn(f"{theme_name}: token --{fg} or --{bg} not found, skipped")
            continue
        r = ratio(theme[fg], theme[bg])
        line = f"{theme_name:5} | {label:22} {theme[fg]} on {theme[bg]} = {r:.2f}:1"
        (ok if r >= 4.5 else fail)(line if r >= 4.5 else line + "  << below 4.5:1")

    # White on the primary button fill.
    if "color-accent" in theme:
        r = ratio("#ffffff", theme["color-accent"])
        line = f"{theme_name:5} | {'white on primary button':22} = {r:.2f}:1"
        (ok if r >= 4.5 else fail)(line if r >= 4.5 else line + "  << below 4.5:1")


# --------------------------------------------------------------------------
# Stylesheet rules
# --------------------------------------------------------------------------
for needed, why in [
    ("prefers-reduced-motion", "reduced-motion support"),
    (":focus-visible", "visible focus states"),
    ("cursor: pointer", "pointer cursor on controls"),
    ("overflow-x: auto", "wide content scrolls in its own container"),
    ("@media (max-width: 768px)", "mobile breakpoint"),
    ("scroll-padding-top", "anchors clear the fixed header"),
    (".js .reveal", "scroll reveal is gated behind JS, so the no-JS view stays visible"),
]:
    (ok if needed in css else fail)(f"css: {why}")


# --------------------------------------------------------------------------
print("PASS")
for m in oks:
    print("  ok    " + m)
if warns:
    print("WARN")
    for m in warns:
        print("  warn  " + m)
if fails:
    print("FAIL")
    for m in fails:
        print("  FAIL  " + m)
print(f"\n{len(oks)} ok, {len(warns)} warn, {len(fails)} fail")
sys.exit(1 if fails else 0)
