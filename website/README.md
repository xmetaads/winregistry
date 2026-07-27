# winregistry.org

Static marketing and documentation site for **regx**. No build step, no
framework, no npm install — three HTML files, one stylesheet, one script.
That is deliberate: the product's pitch is "one file, no dependencies", and a
site that needs a toolchain to render would undercut it.

```
website/
├── index.html          landing page
├── docs.html           full command reference
├── 404.html
├── README.md
└── assets/
    ├── css/style.css   design tokens + components
    ├── js/app.js       progressive enhancement only
    └── img/favicon.svg
```

## Run it locally

```bash
python -m http.server 8899 --directory website
```

Then open <http://localhost:8899/>.

## Before going live

- [x] Repository links point at <https://github.com/xmetaads/winregistry>.
- [ ] Point the download button at a real release asset once one exists — it
      currently links to the install section of the docs.
- [ ] Add an `og:image` (1200×630). The Open Graph tags are in place but there
      is no image yet, so link previews will render text-only.
- [ ] Confirm the stated figures still match the shipped binary: the hero
      quotes 656 KB and 40 tests.

## Deploying

Any static host works. The only server-side requirement is that `404.html` is
served for unknown paths.

**Cloudflare Pages** — build command: none, output directory: `website`.
404 handling is automatic.

**GitHub Pages** — publish the `website/` directory. `404.html` is picked up
automatically.

**Netlify** — publish directory `website`, no build command.

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
not worth it here. The reveal is gated behind a `.js` class on `<html>`, so the
no-JS and crawler view shows every section.

## Accessibility

Verified: every text/background pair in both themes clears 4.5:1 (lowest is
4.61:1), no emoji used as icons, all controls have accessible names, focus is
visible, `prefers-reduced-motion` is respected, zoom is not disabled, and wide
tables scroll inside their own container rather than the page.

**Not yet verified:** rendering has only been checked programmatically. Open the
site at 375 / 768 / 1024 / 1440 px and tab through it before launch.
