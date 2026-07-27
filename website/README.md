# winregistry.org

Static marketing and documentation site for **regx**, deployed on **Vercel**.
No build step, no framework, no npm install — three HTML files, one stylesheet,
two scripts. That is deliberate: the product's pitch is "one file, no
dependencies", and a site that needs a toolchain to render would undercut it.

```
website/                    <- vercel.json outputDirectory
├── index.html              /
├── docs.html               /docs      (cleanUrls)
├── 404.html                served for any unknown path
├── README.md
└── assets/
    ├── css/style.css       design tokens + components
    ├── js/theme.js         runs in <head>, before first paint
    ├── js/app.js           progressive enhancement, deferred
    └── img/favicon.svg
```

Configuration lives in `../vercel.json` and `../.vercelignore` at the
repository root.

## Run it locally

```bash
python dev-server.py
```

Then open <http://localhost:8899/>.

Use this rather than `python -m http.server`: the site links to `/docs`, not
`/docs.html`, so a plain file server 404s on every internal link and hides real
routing bugs until deploy. `dev-server.py` reproduces the three routing rules
from `vercel.json` — clean URLs, no trailing slash, and `404.html` with a real
404 status — using only the standard library. `vercel dev` works too if you
have the CLI.

## Before going live

- [x] Repository links point at <https://github.com/xmetaads/winregistry>.
- [ ] Point the download button at a real release asset once one exists — it
      currently links to the install section of the docs.
- [ ] Add an `og:image` (1200×630). The Open Graph tags are in place but there
      is no image yet, so link previews will render text-only.
- [ ] Confirm the stated figures still match the shipped binary: the hero
      quotes 656 KB and 40 tests.

## Deploying to Vercel

Import <https://github.com/xmetaads/winregistry> as a Vercel project and accept
the defaults. `vercel.json` at the repository root supplies everything:

| Setting | Value | Why |
|---|---|---|
| Framework Preset | **Other** | There is no framework and no build step |
| Build Command | *(leave empty)* | Nothing to build |
| Output Directory | `website` | Set by `outputDirectory` in `vercel.json` |
| Root Directory | *(leave empty)* | **Important — see below** |

> **Leave Root Directory empty.** Vercel reads `vercel.json` from the Root
> Directory. If you set it to `website`, the root `vercel.json` is ignored and
> you silently lose clean URLs, the CSP and every other header. Either leave it
> empty (recommended, matches this repo) or move `vercel.json` into `website/`
> and drop the `outputDirectory` line.

### What `vercel.json` configures

- **`cleanUrls: true`** — `/docs` serves `docs.html`, and `/docs.html`
  308-redirects to `/docs`. Every internal link in this site already uses the
  clean form.
- **`trailingSlash: false`** — `/docs/` redirects to `/docs`, so a page is never
  reachable at two URLs.
- **Security headers** on every response: a Content-Security-Policy with no
  `unsafe-inline`, plus HSTS, `nosniff`, `Referrer-Policy`, `X-Frame-Options`,
  `Permissions-Policy` and COOP.
- **Caching.** `/assets/*` gets `max-age=3600, stale-while-revalidate=604800`,
  **not** `immutable`. Asset filenames carry no content hash, so a year-long
  immutable cache would strand users on a stale stylesheet after every deploy.
  If you ever add a build step that fingerprints filenames, switch to
  `max-age=31536000, immutable` then — not before. HTML is always revalidated.

`404.html` is picked up automatically for unknown paths; no rewrite rule needed.

### The CSP constrains how you edit these pages

`script-src 'self'` and `style-src` without `unsafe-inline` mean:

- **No inline `<script>`.** The pre-paint theme switch lives in
  `assets/js/theme.js`, loaded synchronously in `<head>`.
- **No `style=""` attributes.** They would be blocked and simply not apply. Use
  a class — `.mt-lg`, `.ml-auto` and `.lead` exist for the one-off cases.
- **New external origins must be added to the CSP** in `vercel.json`, or the
  browser blocks them. Currently allowed: `fonts.googleapis.com` (stylesheet)
  and `fonts.gstatic.com` (font files).

## Other hosts

Nothing here is Vercel-specific beyond `vercel.json`. On Cloudflare Pages or
Netlify set the output directory to `website`, enable clean URLs, and port the
headers to `_headers`. On GitHub Pages, clean URLs are not configurable — you
would need to rename `docs.html` to `docs/index.html` and revert the links.

## Design system

Generated with [ui-ux-pro-max](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill)
and recorded in `../design-system/winregistry-org/MASTER.md`. That file is the
source of truth for future pages; read it before adding one.

Three tokens deliberately deviate from what the generator produced, each for a
measured reason. They are commented at the top of `assets/css/style.css`:

| Token | Generated | Shipped | Why |
|---|---|---|---|
| `--color-destructive` | `#22C55E` (green) | red | Green for "destructive" is semantically wrong; success is now a separate token |
| Card background | `#020617` | `--color-muted` | Identical to the page background — cards would have been invisible |
| Accent as text | `#A16207` | `#F0B429` | `#A16207` on `#020617` measures 4.32:1, under the 4.5:1 floor. The original is kept for solid fills, where white on it reaches 4.92:1 |

The light theme has no counterpart in the generated system, which is dark-only.
It exists because the pre-delivery checklist requires light-mode contrast to be
verified, and a documentation site gets read in daylight.

### Substitutions

The design system recommends GSAP ScrollTrigger for the scroll reveal. This site
uses `IntersectionObserver` with CSS transitions instead, reproducing the same
spec — 350 ms, 12 px offset, ease-out, plays once. A 70 KB CDN dependency was
not worth it here, and it would have needed its own CSP origin. The reveal is
gated behind a `.js` class on `<html>`, so the no-JS and crawler view shows
every section.

Fonts are linked from each `<head>` rather than `@import`-ed inside
`style.css`. An `@import` cannot begin downloading until the stylesheet has
itself been fetched and parsed, which serialises two round trips on first paint.

## Accessibility

Verified: every text/background pair in both themes clears 4.5:1 (lowest is
4.61:1), no emoji used as icons, all controls have accessible names, focus is
visible, `prefers-reduced-motion` is respected, zoom is not disabled, and wide
tables scroll inside their own container rather than the page.

**Not yet verified:** rendering has only been checked programmatically. Open the
site at 375 / 768 / 1024 / 1440 px and tab through it before launch.
