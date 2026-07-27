#!/usr/bin/env python3
"""Controlled VantaCrawl acceptance-test application (stdlib only).

Endpoints intentionally cover Passive/Safe/Extended/Lab probe expectations.
Not part of the scanner — do not import into production crawl paths.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent
FIXTURE_CANARY = ROOT / "fixtures" / "canary.txt"
CANARY_CONTENT = FIXTURE_CANARY.read_text(encoding="utf-8").strip() if FIXTURE_CANARY.exists() else "CANARY_OK_ACCEPTANCE_TOKEN"

# Shared OOB state (same process hosts lab + callback by default)
_OOB_HITS: Dict[str, Dict[str, Any]] = {}
_OOB_LOCK = threading.Lock()
_RATE_HITS: Dict[str, List[float]] = {}
_REQ_COUNT = 0
_REQ_LOCK = threading.Lock()


def _read_body(handler: BaseHTTPRequestHandler) -> bytes:
    length = int(handler.headers.get("Content-Length") or 0)
    if length <= 0:
        return b""
    return handler.rfile.read(length)


def _parse_params(handler: BaseHTTPRequestHandler) -> Dict[str, str]:
    parsed = urllib.parse.urlparse(handler.path)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    out = {k: (v[0] if v else "") for k, v in qs.items()}
    if handler.command == "POST":
        raw = _read_body(handler).decode("utf-8", errors="replace")
        ctype = (handler.headers.get("Content-Type") or "").lower()
        if "application/json" in ctype:
            try:
                data = json.loads(raw or "{}")
                if isinstance(data, dict):
                    for k, v in data.items():
                        out[str(k)] = str(v)
            except Exception:
                pass
        else:
            form = urllib.parse.parse_qs(raw, keep_blank_values=True)
            for k, v in form.items():
                out[k] = v[0] if v else ""
    return out


def _send(handler: BaseHTTPRequestHandler, status: int, body: bytes, headers: Optional[Dict[str, str]] = None) -> None:
    handler.send_response(status)
    hdrs = {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"}
    if headers:
        hdrs.update(headers)
    for k, v in hdrs.items():
        handler.send_header(k, v)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _page(title: str, body: str) -> bytes:
    return (
        f"<!DOCTYPE html><html><head><title>{html.escape(title)}</title></head>"
        f"<body><h1>{html.escape(title)}</h1>{body}</body></html>"
    ).encode("utf-8")


INDEX_LINKS = [
    ("/sqli/vuln?id=1", "SQLi vulnerable"),
    ("/sqli/safe?id=1", "SQLi safe"),
    ("/xss/reflected?q=hello", "XSS reflected"),
    ("/xss/encoded?q=hello", "XSS encoded"),
    ("/xss/browser?q=hello", "XSS browser-executing"),
    ("/xss/form", "XSS POST form"),
    ("/ssrf/callback?url=http://example.com", "SSRF callback"),
    ("/ssrf/reflect?url=http://example.com", "SSRF reflection-only"),
    ("/rce/arith?cmd=id", "RCE arithmetic"),
    ("/rce/reflect?cmd=id", "RCE reflection-only"),
    ("/ssti/eval?name=World", "SSTI evaluation"),
    ("/ssti/reflect?name=World", "SSTI reflection-only"),
    ("/trav/view?file=note.txt", "Traversal canary"),
    ("/crlf?q=test", "CRLF injection"),
    ("/redirect?next=/", "Open redirect"),
    ("/soft404/anything", "Soft-404 family"),
    ("/wildcard/anything", "Wildcard route"),
    ("/secret-admin-panel/", "Hidden directory"),
    # Checkpoint + rate-limit intentionally NOT linked from the crawl index.
    # Hitting them mid-crawl trips the edge circuit breaker and pauses active probes
    # before vulnerability endpoints are exercised. They remain reachable for a
    # dedicated breaker-exercise scan (/breaker-zone).
]


class LabHandler(BaseHTTPRequestHandler):
    server_version = "VantaCrawlAcceptanceLab/1.0"

    def log_message(self, fmt: str, *args) -> None:  # quieter
        return

    def do_GET(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    def do_HEAD(self) -> None:
        self._dispatch(head_only=True)

    def _dispatch(self, head_only: bool = False) -> None:
        global _REQ_COUNT
        with _REQ_LOCK:
            _REQ_COUNT += 1
            n = _REQ_COUNT

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path or "/"
        # Normalize trailing slash except root
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/") or "/"

        # OOB callback / poll (may share this port)
        if path.startswith("/oob/"):
            return self._oob(path, head_only=head_only)

        params = _parse_params(self)

        routes = {
            "/": self._index,
            "/sqli/vuln": self._sqli_vuln,
            "/sqli/safe": self._sqli_safe,
            "/xss/reflected": self._xss_reflected,
            "/xss/encoded": self._xss_encoded,
            "/xss/browser": self._xss_browser,
            "/xss/form": self._xss_form,
            "/ssrf/callback": self._ssrf_callback,
            "/ssrf/reflect": self._ssrf_reflect,
            "/rce/arith": self._rce_arith,
            "/rce/reflect": self._rce_reflect,
            "/ssti/eval": self._ssti_eval,
            "/ssti/reflect": self._ssti_reflect,
            "/trav/view": self._trav_view,
            "/crlf": self._crlf,
            "/redirect": self._redirect,
            "/checkpoint": self._checkpoint,
            "/rate-limit": self._rate_limit,
            "/breaker-zone": self._breaker_zone,
            "/active-breaker": self._active_breaker,
            "/secret-admin-panel": self._hidden,
            "/robots.txt": self._robots,
        }

        if path.startswith("/soft404"):
            return self._soft404(head_only=head_only)
        if path.startswith("/wildcard"):
            return self._wildcard(path, head_only=head_only)

        handler = routes.get(path)
        if handler is None:
            body = _page("Not Found", f"<p>No route for {html.escape(path)}</p>")
            if head_only:
                body = b""
            return _send(self, 404, body)

        return handler(params, head_only=head_only)

    def _index(self, params: Dict[str, str], head_only: bool = False) -> None:
        items = "".join(f'<li><a href="{html.escape(href)}">{html.escape(label)}</a></li>' for href, label in INDEX_LINKS)
        body = _page(
            "VantaCrawl Acceptance Lab",
            f"<p>Controlled lab for Passive / Safe / Extended / Lab scan acceptance.</p><ul>{items}</ul>"
            "<p>Breaker endpoints (not crawled from here): "
            "<code>/checkpoint</code>, <code>/rate-limit</code>, <code>/breaker-zone</code></p>",
        )
        if head_only:
            body = b""
        _send(self, 200, body)

    def _sqli_vuln(self, params: Dict[str, str], head_only: bool = False) -> None:
        val = params.get("id", "")
        if any(tok in val for tok in ("'", '"', "--", "/*", " OR ", " or ")):
            text = (
                "You have an error in your SQL syntax; check the manual that corresponds "
                f"to your MySQL server version for the right syntax to use near '{val}'"
            )
        else:
            text = f"Product id {html.escape(val)} details"
        body = _page("SQLi vuln", f"<pre>{html.escape(text)}</pre>")
        if head_only:
            body = b""
        _send(self, 200, body)

    def _sqli_safe(self, params: Dict[str, str], head_only: bool = False) -> None:
        # Always identical application response — no error differential
        body = _page("SQLi safe", "<pre>Product catalog entry</pre>")
        if head_only:
            body = b""
        _send(self, 200, body)

    def _xss_reflected(self, params: Dict[str, str], head_only: bool = False) -> None:
        q = params.get("q", "")
        # Reflect into HTML text node only (no tag breakout helpers)
        body = _page("XSS reflected", f"<p>Results for: {q}</p>")
        if head_only:
            body = b""
        _send(self, 200, body)

    def _xss_encoded(self, params: Dict[str, str], head_only: bool = False) -> None:
        q = html.escape(params.get("q", ""), quote=True)
        body = _page("XSS encoded", f"<p>Results for: {q}</p>")
        if head_only:
            body = b""
        _send(self, 200, body)

    def _xss_browser(self, params: Dict[str, str], head_only: bool = False) -> None:
        q = params.get("q", "")
        # Attribute-breakout sink: unescaped into value="..."
        body = (
            "<!DOCTYPE html><html><head><title>XSS browser</title></head><body>"
            f'<input id="q" value="{q}">'
            "<p>search sink</p></body></html>"
        ).encode("utf-8")
        if head_only:
            body = b""
        _send(self, 200, body)

    def _xss_form(self, params: Dict[str, str], head_only: bool = False) -> None:
        if self.command == "POST" or params.get("q"):
            q = params.get("q", "")
            body = (
                "<!DOCTYPE html><html><head><title>XSS form result</title></head><body>"
                f'<div data-q="{q}">posted</div>'
                f"<p>{q}</p></body></html>"
            ).encode("utf-8")
            if head_only:
                body = b""
            return _send(self, 200, body)
        body = _page(
            "XSS form",
            '<form method="POST" action="/xss/form">'
            '<input name="q" value="test"><button type="submit">Go</button></form>',
        )
        if head_only:
            body = b""
        _send(self, 200, body)

    def _ssrf_callback(self, params: Dict[str, str], head_only: bool = False) -> None:
        url = params.get("url", "")
        fetched = ""
        err = ""
        if url.startswith("http://") or url.startswith("https://"):
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=3) as resp:
                    fetched = resp.read(500).decode("utf-8", errors="replace")
            except Exception as exc:
                err = str(exc)[:200]
        body = _page(
            "SSRF callback",
            f"<p>Fetched URL (server-side).</p><pre>url={html.escape(url)}</pre>"
            f"<pre>err={html.escape(err)}</pre><pre>{html.escape(fetched[:300])}</pre>",
        )
        if head_only:
            body = b""
        _send(self, 200, body)

    def _ssrf_reflect(self, params: Dict[str, str], head_only: bool = False) -> None:
        url = params.get("url", "")
        # Reflection only — never fetch
        body = _page("SSRF reflect", f"<p>Invalid URL: {html.escape(url)}</p>")
        if head_only:
            body = b""
        _send(self, 200, body)

    def _rce_arith(self, params: Dict[str, str], head_only: bool = False) -> None:
        cmd = params.get("cmd", "")
        # Evaluate harmless expr pattern used by Safe kit
        m = re.search(r"expr\s+(\d+)\s*\+\s*(\d+)", cmd)
        if m:
            result = int(m.group(1)) + int(m.group(2))
            text = f"value={result}"
        else:
            # Marker-style printf/echo: emit marker token if present without executing arith
            m2 = re.search(r"(VC_RCE_[0-9a-f]+)", cmd)
            if m2 and ("printf" in cmd or "echo" in cmd):
                text = f"output:\n{m2.group(1)}\ndone"
            else:
                text = "ok"
        body = _page("RCE arith", f"<pre>{html.escape(text)}</pre>")
        if head_only:
            body = b""
        _send(self, 200, body)

    def _rce_reflect(self, params: Dict[str, str], head_only: bool = False) -> None:
        cmd = params.get("cmd", "")
        body = _page("RCE reflect", f"<pre>cmd={html.escape(cmd)}</pre>")
        if head_only:
            body = b""
        _send(self, 200, body)

    def _ssti_eval(self, params: Dict[str, str], head_only: bool = False) -> None:
        name = params.get("name", "")
        # Evaluate the arithmetic SSTI forms the Safe kit actually sends (a+b).
        out = name
        m = re.search(r"\{\{(\d+)\s*\+\s*(\d+)\}\}", name)
        if m:
            out = str(int(m.group(1)) + int(m.group(2)))
        else:
            m2 = re.search(r"\$\{(\d+)\s*\+\s*(\d+)\}", name)
            if m2:
                out = str(int(m2.group(1)) + int(m2.group(2)))
            else:
                m3 = re.search(r"#\{(\d+)\s*\+\s*(\d+)\}", name)
                if m3:
                    out = str(int(m3.group(1)) + int(m3.group(2)))
                else:
                    m4 = re.search(r"<%=\s*(\d+)\s*\+\s*(\d+)\s*%>", name)
                    if m4:
                        out = str(int(m4.group(1)) + int(m4.group(2)))
        body = _page("SSTI eval", f"<p>Hello {html.escape(out)}</p>")
        if head_only:
            body = b""
        _send(self, 200, body)

    def _ssti_reflect(self, params: Dict[str, str], head_only: bool = False) -> None:
        name = params.get("name", "")
        body = _page("SSTI reflect", f"<p>Hello {html.escape(name)}</p>")
        if head_only:
            body = b""
        _send(self, 200, body)

    def _trav_view(self, params: Dict[str, str], head_only: bool = False) -> None:
        file_param = params.get("file", "")
        # Serve canary when path points at fixture canary (lab configured path)
        text = "not found"
        status = 404
        if "canary.txt" in file_param or "VC_TRAVERSAL_" in file_param or "fixtures" in file_param:
            text = f"file content {CANARY_CONTENT}"
            status = 200
        elif file_param == "note.txt":
            text = "note: hello"
            status = 200
        elif ".." in file_param:
            # Differential path normalization signal without canary
            text = f"normalized path error for {file_param}"
            status = 400
        body = _page("Traversal", f"<pre>{html.escape(text)}</pre>")
        if head_only:
            body = b""
        _send(self, status, body)

    def _crlf(self, params: Dict[str, str], head_only: bool = False) -> None:
        q = params.get("q", "")
        # Vulnerable header injection if CRLF present in q
        extra = {}
        if "%0d" in q.lower() or "%0a" in q.lower() or "\r" in q or "\n" in q:
            # Decode common encodings
            decoded = urllib.parse.unquote(q)
            for line in re.split(r"\r\n|\n|\r", decoded):
                if ":" in line and line.lower().startswith("x-"):
                    k, v = line.split(":", 1)
                    extra[k.strip()] = v.strip()
            if "Set-Cookie" in decoded or "set-cookie" in decoded.lower():
                extra["Set-Cookie"] = "injected=1"
        body = _page("CRLF", f"<p>q ok</p>")
        if head_only:
            body = b""
        _send(self, 200, body, headers=extra or None)

    def _redirect(self, params: Dict[str, str], head_only: bool = False) -> None:
        nxt = params.get("next") or params.get("url") or params.get("redirect") or "/"
        # Open redirect — Location reflects attacker-controlled value
        body = b""
        _send(self, 302, body, headers={"Location": nxt})

    def _soft404(self, head_only: bool = False) -> None:
        # Always 200 with identical soft-404 content
        body = _page("Soft 404", "<p>Sorry, the page you requested could not be found.</p><p>Return home.</p>")
        if head_only:
            body = b""
        _send(self, 200, body)

    def _wildcard(self, path: str, head_only: bool = False) -> None:
        # Content-equivalent wildcard for any suffix
        body = _page("Wildcard", f"<p>Catch-all for {html.escape(path)}</p><p>static fingerprint AAA</p>")
        if head_only:
            body = b""
        _send(self, 200, body)

    def _hidden(self, params: Dict[str, str], head_only: bool = False) -> None:
        body = _page(
            "Secret Admin Panel",
            "<p>Genuine hidden directory — not linked from soft404/wildcard.</p>"
            "<p>Flag: HIDDEN_DIR_OK</p>",
        )
        if head_only:
            body = b""
        _send(self, 200, body)

    def _robots(self, params: Dict[str, str], head_only: bool = False) -> None:
        text = "User-agent: *\nDisallow: /secret-admin-panel/\n"
        body = text.encode("utf-8")
        if head_only:
            body = b""
        _send(self, 200, body, headers={"Content-Type": "text/plain"})

    def _breaker_zone(self, params: Dict[str, str], head_only: bool = False) -> None:
        body = _page(
            "Breaker zone",
            "<p>Dedicated active-probe breaker exercise (checkpoint only on probe payloads):</p><ul>"
            '<li><a href="/active-breaker?id=1&amp;q=test&amp;cmd=id&amp;url=http://example.com&amp;name=a&amp;file=b">active-breaker</a></li>'
            '<li><a href="/active-breaker?id=2&amp;q=test&amp;cmd=id">active-breaker-2</a></li>'
            '<li><a href="/active-breaker?id=3&amp;q=search">active-breaker-3</a></li>'
            '<li><a href="/rate-limit?id=1&amp;q=test">rate-limit-params</a></li>'
            '<li><a href="/rate-limit?id=2&amp;q=test">rate-limit-2</a></li>'
            "</ul>"
            "<p>Raw edge pages (crawl skips security — not used for active-probe breaker proof): "
            '<a href="/checkpoint">/checkpoint</a></p>',
        )
        if head_only:
            body = b""
        _send(self, 200, body)

    def _active_breaker(self, params: Dict[str, str], head_only: bool = False) -> None:
        """Application page that returns edge checkpoint only for active-probe payloads.

        Crawl/baseline stay application_response so security + active probes run.
        Probe mutations (quotes, XSS markers, callback URLs, …) return checkpoint.
        """
        joined = " ".join(str(v) for v in params.values())
        active = any(
            tok in joined
            for tok in (
                "VCXSS_",
                "VC_RCE_",
                "' AND ",
                "1 AND 1",
                "printf ",
                "echo ",
                "expr ",
                "{{",
                "${",
                "\r\nX-VantaCrawl",
                "169.254",
                "/oob/",
                "redirect-proof.vantacrawl",
            )
        ) or (joined.strip() in ("'", '"', "')", "'--", "' #")) or any(
            str(v).strip() in ("'", '"', "')", "'--", "' #") for v in params.values()
        )
        # Appended quote on numeric id: value like "1'" 
        if any("'" in str(v) or '"' in str(v) for v in params.values()):
            active = True
        if active:
            return self._checkpoint(params, head_only=head_only)
        body = _page(
            "Active breaker",
            "<p>ok application surface for breaker exercise</p>"
            f"<pre>id={html.escape(params.get('id',''))} q={html.escape(params.get('q',''))}</pre>",
        )
        if head_only:
            body = b""
        _send(self, 200, body)

    def _checkpoint(self, params: Dict[str, str] | None = None, head_only: bool = False) -> None:
        body = (
            "<!DOCTYPE html><html><head><title>Vercel Security Checkpoint</title></head>"
            "<body><h1>Vercel Security Checkpoint</h1>"
            "<p>Enable javascript and cookies to continue</p>"
            "<script>window.vercel={}</script>"
            "</body></html>"
        ).encode("utf-8")
        if head_only:
            body = b""
        _send(
            self,
            403,
            body,
            headers={"Server": "Vercel", "Content-Type": "text/html; charset=utf-8"},
        )

    def _rate_limit(self, params: Dict[str, str], head_only: bool = False) -> None:
        ip = self.client_address[0]
        now = time.time()
        with _OOB_LOCK:
            hits = _RATE_HITS.setdefault(ip, [])
            hits[:] = [t for t in hits if now - t < 10]
            hits.append(now)
            count = len(hits)
        if count > 3:
            body = _page("Rate limited", "<p>Too many requests</p>")
            if head_only:
                body = b""
            return _send(self, 429, body, headers={"Retry-After": "5"})
        body = _page("Rate limit probe", f"<p>ok hit={count}</p>")
        if head_only:
            body = b""
        _send(self, 200, body)

    def _oob(self, path: str, head_only: bool = False) -> None:
        # /oob/{nonce}/ping  or /oob/poll/{nonce}
        parts = [p for p in path.split("/") if p]
        # parts[0] == oob
        if len(parts) >= 3 and parts[1] == "poll":
            nonce = parts[2]
            with _OOB_LOCK:
                hit = _OOB_HITS.get(nonce)
            if hit:
                payload = {
                    "confirmed": True,
                    "nonce": nonce,
                    "interactions": [hit],
                    "callback_type": hit.get("callback_type", "http"),
                }
            else:
                payload = {"confirmed": False, "nonce": nonce, "interactions": []}
            raw = json.dumps(payload).encode("utf-8")
            if head_only:
                raw = b""
            return _send(self, 200, raw, headers={"Content-Type": "application/json"})

        if len(parts) >= 3 and parts[2] in ("ping", "redirect", "xxe"):
            nonce = parts[1]
            with _OOB_LOCK:
                _OOB_HITS[nonce] = {
                    "nonce": nonce,
                    "received_at": time.time(),
                    "path": path,
                    "callback_type": "http",
                    "source_ip": self.client_address[0],
                }
            raw = b"pong"
            if head_only:
                raw = b""
            return _send(self, 200, raw, headers={"Content-Type": "text/plain"})

        # Also accept /oob/{nonce} as hit
        if len(parts) == 2:
            nonce = parts[1]
            with _OOB_LOCK:
                _OOB_HITS[nonce] = {
                    "nonce": nonce,
                    "received_at": time.time(),
                    "path": path,
                    "callback_type": "http",
                    "source_ip": self.client_address[0],
                }
            raw = b"ok"
            if head_only:
                raw = b""
            return _send(self, 200, raw)

        _send(self, 404, b"oob unknown")


def main() -> None:
    parser = argparse.ArgumentParser(description="VantaCrawl acceptance lab")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    httpd = ThreadingHTTPServer((args.host, args.port), LabHandler)
    print(f"Acceptance lab listening on http://{args.host}:{args.port}/", flush=True)
    print(f"OOB ping:  http://{args.host}:{args.port}/oob/<nonce>/ping", flush=True)
    print(f"OOB poll:  http://{args.host}:{args.port}/oob/poll/<nonce>", flush=True)
    print(f"Canary:    {CANARY_CONTENT}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
