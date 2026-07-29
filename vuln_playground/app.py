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
    # Generic public fingerprint — avoid advertising this as a vuln lab.
    server_version = "Apache/2.4.58 (Unix)"
    sys_version = ""
    # HTTP/1.0 disables keep-alive; prevents intermittent proxy/CF "Not Found"
    # races under ThreadingHTTPServer (local fallback only — Render uses Waitress).
    protocol_version = "HTTP/1.0"

    def setup(self) -> None:
        super().setup()
        self.close_connection = True

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
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, TRACE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_TRACE(self) -> None:
        self._dispatch()

    def do_PUT(self) -> None:
        self._dispatch()

    def do_DELETE(self) -> None:
        self._dispatch()

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
        if path.startswith("/static/"):
            return self._static(path, head_only=head_only)

        spec = resolve(path)
        if spec is None:
            body = page("Not Found", f"<p>No route for <code>{html.escape(path)}</code></p>")
            return send(self, 404, body, head_only=head_only)

        params = parse_params(self)
        return spec.handler(self, params, head_only=head_only)

    def _static(self, path: str, head_only: bool = False) -> None:
        rel = path[len("/static/") :]
        if not rel or ".." in rel.split("/") or rel.startswith("/"):
            return send(self, 404, page("Not Found", "<p>static miss</p>"), head_only=head_only)
        target = (ROOT / "static" / rel).resolve()
        static_root = (ROOT / "static").resolve()
        if not str(target).startswith(str(static_root)) or not target.is_file():
            return send(self, 404, page("Not Found", "<p>static miss</p>"), head_only=head_only)
        data = target.read_bytes()
        ctype = "application/octet-stream"
        if target.suffix == ".js":
            ctype = "application/javascript; charset=utf-8"
        elif target.suffix == ".css":
            ctype = "text/css; charset=utf-8"
        elif target.suffix == ".txt":
            ctype = "text/plain; charset=utf-8"
        return send(self, 200, data, headers={"Content-Type": ctype}, head_only=head_only)

    def _index(self, head_only: bool = False) -> None:
        # Public index looks like a mundane product catalog — expected
        # findings stay in EXPECTED.md /vulns module docs, not on the homepage.
        links = []
        for spec in linked_index():
            # Prefer bland titles for the public nav
            label = spec.title.split("(")[0].strip()
            links.append(
                f'<li><a href="{html.escape(spec.path)}">{html.escape(label)}</a></li>'
            )
        body = page(
            "Horizon Catalog",
            "<p>Welcome to the Horizon product catalog demo.</p>"
            "<p>Browse sample tools, account settings, and support utilities.</p>"
            f"<ul>{''.join(links)}</ul>"
            "<p><a href='/healthz'>Status</a></p>",
        )
        send(self, 200, body, head_only=head_only)

    def _oob(self, path: str, head_only: bool = False) -> None:
        # /oob/<nonce>/ping|/redirect  or  /oob/poll[/<nonce>]?nonce=
        from urllib.parse import parse_qs

        parts = [p for p in path.split("/") if p]
        qs = parse_qs(urlparse(self.path).query)
        if len(parts) >= 3 and parts[0] == "oob" and parts[2] in ("ping", "redirect"):
            nonce = parts[1]
            scan_id = (qs.get("scan_id") or [""])[0]
            probe_id = (qs.get("probe_id") or [""])[0]
            with _OOB_LOCK:
                _OOB_HITS[nonce] = {
                    "nonce": nonce,
                    "path": path,
                    "callback_type": parts[2],
                    "source_ip": self.client_address[0],
                    "ua": self.headers.get("User-Agent") or "",
                    "scan_id": scan_id,
                    "probe_id": probe_id,
                }
            if parts[2] == "redirect":
                # Intentionally weak: Location to a same-host benign page.
                # Scanners must not treat client-followed redirects as OOB proof.
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            return send(
                self,
                200,
                b"pong",
                headers={"Content-Type": "text/plain"},
                head_only=head_only,
            )
        if path == "/oob/poll" or path.startswith("/oob/poll"):
            nonce = (qs.get("nonce") or [""])[0]
            if not nonce and len(parts) >= 3 and parts[0] == "oob" and parts[1] == "poll":
                nonce = parts[2]
            with _OOB_LOCK:
                hit = _OOB_HITS.get(nonce)
            if hit:
                import json

                payload = {
                    "confirmed": True,
                    "nonce": nonce,
                    "interactions": [hit],
                }
                if hit.get("scan_id"):
                    payload["scan_id"] = hit.get("scan_id")
                if hit.get("probe_id"):
                    payload["probe_id"] = hit.get("probe_id")
                body = json.dumps(payload).encode("utf-8")
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
        f"horizon-catalog listening on http://{args.host}:{args.port}/  "
        f"(modules={len(loaded)} routes={len(catalog())})",
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye", flush=True)


if __name__ == "__main__":
    main()
