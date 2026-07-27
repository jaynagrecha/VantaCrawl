"""WSGI application for production (Waitress on Render).

Avoids stdlib ThreadingHTTPServer keep-alive races that caused intermittent
plain-text \"Not Found\" responses behind Cloudflare.
"""

from __future__ import annotations

import io
import sys
from email.message import Message
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Tuple

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from registry import load_vuln_modules  # noqa: E402

load_vuln_modules()

from app import PlaygroundHandler  # noqa: E402


class WSGIRequest:
    """Enough of BaseHTTPRequestHandler for vuln_playground handlers + send()."""

    server_version = "Apache/2.4.58 (Unix)"
    sys_version = ""

    def __init__(self, environ: Dict[str, Any], start_response: Callable[..., Any]):
        self.environ = environ
        self._start_response = start_response
        self.command = (environ.get("REQUEST_METHOD") or "GET").upper()
        path = environ.get("PATH_INFO") or "/"
        qs = environ.get("QUERY_STRING") or ""
        self.path = f"{path}?{qs}" if qs else path
        self.client_address = (
            str(environ.get("REMOTE_ADDR") or "0.0.0.0"),
            int(environ.get("REMOTE_PORT") or 0),
        )
        headers = Message()
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                name = key[5:].replace("_", "-").title()
                headers[name] = value
        if environ.get("CONTENT_TYPE"):
            headers["Content-Type"] = environ["CONTENT_TYPE"]
        if environ.get("CONTENT_LENGTH"):
            headers["Content-Length"] = environ["CONTENT_LENGTH"]
        self.headers = headers
        self.rfile = environ.get("wsgi.input") or io.BytesIO()
        self._status_code = 200
        self._headers: List[Tuple[str, str]] = []
        self._started = False
        self._body = io.BytesIO()
        self.wfile = self._body

    def send_response(self, code: int, message: str | None = None) -> None:
        self._status_code = int(code)

    def send_header(self, keyword: str, value: str) -> None:
        self._headers.append((str(keyword), str(value)))

    def end_headers(self) -> None:
        if self._started:
            return
        from http import HTTPStatus

        try:
            phrase = HTTPStatus(self._status_code).phrase
        except Exception:
            phrase = "OK"
        # Waitress computes Content-Length from the returned iterable.
        filtered = [(k, v) for k, v in self._headers if k.lower() != "content-length"]
        filtered.append(("Server", self.server_version))
        self._start_response(f"{self._status_code} {phrase}", filtered)
        self._started = True

    def address_string(self) -> str:
        return self.client_address[0]

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def body_bytes(self) -> bytes:
        if not self._started:
            self.end_headers()
        return self._body.getvalue()


def _bind_handler(req: WSGIRequest) -> PlaygroundHandler:
    """Attach PlaygroundHandler methods onto the WSGI request object."""
    handler = object.__new__(PlaygroundHandler)
    handler.__dict__.update(req.__dict__)
    handler.send_response = req.send_response  # type: ignore[method-assign]
    handler.send_header = req.send_header  # type: ignore[method-assign]
    handler.end_headers = req.end_headers  # type: ignore[method-assign]
    handler.address_string = req.address_string  # type: ignore[method-assign]
    handler.log_message = req.log_message  # type: ignore[method-assign]
    handler.do_GET = PlaygroundHandler.do_GET.__get__(handler, PlaygroundHandler)  # type: ignore
    handler.do_POST = PlaygroundHandler.do_POST.__get__(handler, PlaygroundHandler)  # type: ignore
    handler.do_HEAD = PlaygroundHandler.do_HEAD.__get__(handler, PlaygroundHandler)  # type: ignore
    handler.do_OPTIONS = PlaygroundHandler.do_OPTIONS.__get__(handler, PlaygroundHandler)  # type: ignore
    handler._dispatch = PlaygroundHandler._dispatch.__get__(handler, PlaygroundHandler)  # type: ignore
    handler._index = PlaygroundHandler._index.__get__(handler, PlaygroundHandler)  # type: ignore
    handler._oob = PlaygroundHandler._oob.__get__(handler, PlaygroundHandler)  # type: ignore
    return handler


def application(environ: Dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
    req = WSGIRequest(environ, start_response)
    handler = _bind_handler(req)
    method = req.command
    try:
        if method == "GET":
            handler.do_GET()
        elif method == "POST":
            handler.do_POST()
        elif method == "HEAD":
            handler.do_HEAD()
        elif method == "OPTIONS":
            handler.do_OPTIONS()
        else:
            req.send_response(405)
            req.send_header("Content-Type", "text/plain; charset=utf-8")
            req.end_headers()
            req.wfile.write(b"Method Not Allowed")
    except Exception as exc:
        sys.stderr.write(f"wsgi error: {exc}\n")
        if not req._started:
            req.send_response(500)
            req.send_header("Content-Type", "text/plain; charset=utf-8")
            req.end_headers()
            req.wfile.write(b"Internal Server Error")
    return [req.body_bytes()]


app = application
