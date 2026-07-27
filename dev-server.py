#!/usr/bin/env python3
"""Local preview that behaves like the Vercel deployment.

`python -m http.server` serves files literally, so `/docs` 404s locally even
though it works in production. That gap hides real routing bugs until deploy.
This mirrors the three routing rules configured in vercel.json:

  cleanUrls: true      /docs        -> website/docs.html
                       /docs.html   -> 308 redirect to /docs
  trailingSlash: false /docs/       -> 308 redirect to /docs
  404                  unknown path -> website/404.html with status 404

Standard library only; no Vercel CLI required.

    python dev-server.py [port]
"""
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parent / "website"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8899


class VercelLikeHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def _redirect(self, location):
        # 308 preserves the method, which is what Vercel sends.
        self.send_response(308)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def send_head(self):
        parts = urlsplit(self.path)
        path = parts.path

        # cleanUrls: an explicit .html URL redirects to its extensionless form.
        if path.endswith(".html") and path != "/404.html":
            target = path[: -len(".html")]
            if target.endswith("/index"):
                target = target[: -len("index")]
            return self._redirect(urlunsplit(("", "", target or "/", parts.query, parts.fragment)))

        # trailingSlash: false
        if len(path) > 1 and path.endswith("/"):
            return self._redirect(urlunsplit(("", "", path.rstrip("/"), parts.query, parts.fragment)))

        # Extensionless request -> the matching .html file.
        if path != "/" and "." not in path.rsplit("/", 1)[-1]:
            candidate = ROOT / (path.lstrip("/") + ".html")
            if candidate.is_file():
                self.path = path + ".html"
                if parts.query:
                    self.path += "?" + parts.query
                return super().send_head()

        # Anything that exists is served normally.
        target = ROOT / path.lstrip("/")
        if path == "/" or target.exists():
            return super().send_head()

        # Everything else: the real 404 page, with a real 404 status.
        page = ROOT / "404.html"
        if not page.is_file():
            self.send_error(404)
            return None
        body = page.read_bytes()
        self.send_response(404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command == "HEAD":
            return None
        self.wfile.write(body)
        return None

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s\n" % (fmt % args))


if __name__ == "__main__":
    if not ROOT.is_dir():
        sys.exit(f"website/ not found next to {Path(__file__).name}")
    print(f"winregistry.org -> http://localhost:{PORT}/   (Ctrl+C to stop)")
    print("routing matches vercel.json: cleanUrls, no trailing slash, 404.html\n")
    try:
        ThreadingHTTPServer(("127.0.0.1", PORT), VercelLikeHandler).serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
