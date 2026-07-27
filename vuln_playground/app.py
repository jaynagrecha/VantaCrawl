#!/usr/bin/env python3
"""VantaCrawl dirty vuln playground — standalone intentionally vulnerable target.

Not part of the scanner. Do not import into production crawl paths.
Separate from acceptance_lab (which is the frozen post-PR #81 baseline).

Run:
  ./run.sh
  # or
  PORT=9080 python3 app.py

Scan with VantaCrawl against http://127.0.0.1:9080/ (or $PORT).
"""

from __future__ import annotations

import argparse
import html
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from http_util import page, parse_params, send  # noqa: E402
from registry import catalog, linked_index, load_vuln_modules, resolve  # noqa: E402

# Shared OOB inbox (same process can host callback + poll for local scans)
_OOB_HITS: Dict[str, dict] = {}
_OOB_LOCK = threading.Lock()


class PlaygroundHandler(BaseHTTPRequestHandler):
    server_version = "VantaCrawlVulnPlayground/1.0"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    def do_HEAD(self) -> None:
        self._dispatch(head_only=True)

    def do_OPTIONS(self) -> None:
        # CORS preflight helper for /cors/open
        origin = self.headers.get("Origin") or "*"
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _dispatch(self, head_only: bool = False) -> None:
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/") or "/"

        if path.startswith("/oob/"):
            return self._oob(path, head_only=head_only)

        if path == "/":
            return self._index(head_only=head_only)
        if path == "/catalog.json":
            import json

            body = json.dumps(catalog(), indent=2).encode("utf-8")
            return send(
                self,
                200,
                body,
                headers={"Content-Type": "application/json"},
                head_only=head_only,
            )
        if path == "/healthz":
            return send(
                self,
                200,
                b"ok",
                headers={"Content-Type": "text/plain"},
                head_only=head_only,
            )

        spec = resolve(path)
        if spec is None:
            body = page("Not Found", f"<p>No route for <code>{html.escape(path)}</code></p>")
            return send(self, 404, body, head_only=head_only)

        params = parse_params(self)
        return spec.handler(self, params, head_only=head_only)

    def _index(self, head_only: bool = False) -> None:
        by_family: Dict[str, list] = {}
        for spec in linked_index():
            by_family.setdefault(spec.family, []).append(spec)
        sections = []
        for family in sorted(by_family):
            items = "".join(
                f'<li><span class="tag">{html.escape(family)}</span>'
                f'<a href="{html.escape(s.path)}">{html.escape(s.title)}</a> '
                f'<code>{html.escape(s.path)}</code> — '
                f'<em>{html.escape(s.expected)}</em></li>'
                for s in by_family[family]
            )
            sections.append(f"<h2>{html.escape(family)}</h2><ul>{items}</ul>")
        body = page(
            "VantaCrawl Vuln Playground",
            "<p><span class='tag'>DIRTY PLAYGROUND</span> "
            "Standalone intentionally vulnerable target for VantaCrawl prod-style scans. "
            "Not the acceptance baseline — edit freely under <code>vulns/</code>.</p>"
            "<p>Machine catalog: <a href='/catalog.json'><code>/catalog.json</code></a> · "
            "Health: <a href='/healthz'><code>/healthz</code></a> · "
            "Local OOB: <code>/oob/&lt;nonce&gt;/ping</code> + <code>/oob/poll?nonce=…</code></p>"
            + "".join(sections)
            + "<p>Hidden (not linked): <code>/secret-admin-panel</code>, <code>/robots.txt</code></p>",
        )
        send(self, 200, body, head_only=head_only)

    def _oob(self, path: str, head_only: bool = False) -> None:
        # /oob/<nonce>/ping  or  /oob/poll?nonce=
        parts = [p for p in path.split("/") if p]
        if len(parts) >= 3 and parts[0] == "oob" and parts[2] == "ping":
            nonce = parts[1]
            with _OOB_LOCK:
                _OOB_HITS[nonce] = {
                    "nonce": nonce,
                    "path": path,
                    "source_ip": self.client_address[0],
                    "ua": self.headers.get("User-Agent") or "",
                }
            return send(
                self,
                200,
                b"pong",
                headers={"Content-Type": "text/plain"},
                head_only=head_only,
            )
        if path == "/oob/poll" or path.startswith("/oob/poll"):
            from urllib.parse import parse_qs

            qs = parse_qs(urlparse(self.path).query)
            nonce = (qs.get("nonce") or [""])[0]
            with _OOB_LOCK:
                hit = _OOB_HITS.get(nonce)
            if hit:
                import json

                body = json.dumps(
                    {
                        "confirmed": True,
                        "nonce": nonce,
                        "interactions": [hit],
                        "scan_id": "playground",
                    }
                ).encode("utf-8")
            else:
                import json

                body = json.dumps(
                    {"confirmed": False, "nonce": nonce, "interactions": []}
                ).encode("utf-8")
            return send(
                self,
                200,
                body,
                headers={"Content-Type": "application/json"},
                head_only=head_only,
            )
        send(self, 404, page("OOB", "<p>unknown oob route</p>"), head_only=head_only)


def main() -> None:
    loaded = load_vuln_modules()
    parser = argparse.ArgumentParser(description="VantaCrawl vuln playground")
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT") or os.environ.get("PLAYGROUND_PORT") or "9080"),
    )
    args = parser.parse_args()
    httpd = ThreadingHTTPServer((args.host, args.port), PlaygroundHandler)
    print(
        f"vuln playground on http://{args.host}:{args.port}/  "
        f"(modules={len(loaded)} routes={len(catalog())})",
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye", flush=True)


if __name__ == "__main__":
    main()
