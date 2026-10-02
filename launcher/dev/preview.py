#!/usr/bin/env python3
"""Browser preview of the launcher UI, for working on web/ without Windows or pywebview.

Serves launcher/web over plain HTTP and slips dev/mock-api.js into index.html ahead of the
app's own scripts. The mock stands in for the Python bridge (window.pywebview.api) with canned
answers, so every screen can be opened in an ordinary browser:

    python launcher/dev/preview.py                    # http://127.0.0.1:8765/
    python launcher/dev/preview.py --port 9000 --web some/other/web

Query parameters pick the situation the mock pretends to be in, e.g.
    /?scenario=fresh            first start: no admin, nothing set up yet
    /?scenario=ready&mode=host  everything green, server not started
    /?scenario=hosting          server running, players online
    /?scenario=joining          guest with a host address and a guessed career save
(see SCENARIOS in mock-api.js for the full list).

Nothing here is bundled: TurboRivals.spec ships launcher/web only.
"""

from __future__ import annotations

import argparse
import functools
import http.server
from pathlib import Path

DEV_DIR = Path(__file__).resolve().parent
WEB_DIR = DEV_DIR.parent / "web"
DEV_PREFIX = "/__dev__/"
INJECT = b'<script src="/__dev__/mock-api.js"></script>'


class PreviewHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, web_dir: Path, **kwargs):
        self.web_dir = web_dir
        super().__init__(*args, directory=str(web_dir), **kwargs)

    def end_headers(self):
        # Always the file on disk, never a stale copy - this is a tool for editing those files.
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.startswith(DEV_PREFIX):
            return self._send_file(DEV_DIR / path[len(DEV_PREFIX):])
        if path in ("/", "/index.html"):
            html = (self.web_dir / "index.html").read_bytes()
            head = html.find(b"<head>")
            if head < 0:
                self.send_error(500, "index.html has no <head>")
                return
            cut = head + len(b"<head>")
            return self._send_bytes(html[:cut] + INJECT + html[cut:], "text/html; charset=utf-8")
        return super().do_GET()

    def _send_file(self, file: Path):
        try:
            file.resolve().relative_to(DEV_DIR)
            body = file.read_bytes()
        except (OSError, ValueError):
            self.send_error(404)
            return
        ctype = "text/javascript; charset=utf-8" if file.suffix == ".js" else "application/octet-stream"
        self._send_bytes(body, ctype)

    def _send_bytes(self, body: bytes, ctype: str):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--web", type=Path, default=WEB_DIR, help="web root to serve")
    args = ap.parse_args()

    handler = functools.partial(PreviewHandler, web_dir=args.web.resolve())
    with http.server.ThreadingHTTPServer((args.host, args.port), handler) as httpd:
        print(f"TurboRivals UI preview on http://{args.host}:{args.port}/  (Ctrl+C to stop)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
