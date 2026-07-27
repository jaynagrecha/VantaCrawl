"""SSRF: real fetch vs reflection-only vs metadata tease."""

from __future__ import annotations

import html
import urllib.request
from typing import Dict

from http_util import page, send
from registry import register


@register(
    "/ssrf/fetch",
    title="SSRF server-side fetch",
    family="ssrf",
    expected="ssrf oob_callback_confirmed when callback URL is fetched",
    tags=["active", "oob"],
    notes="Performs a real HTTP GET to url= (use VantaCrawl OOB callback).",
)
def ssrf_fetch(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    url = params.get("url", "")
    fetched = ""
    err = ""
    if url.startswith("http://") or url.startswith("https://"):
        try:
            req = urllib.request.Request(url, method="GET", headers={"User-Agent": "vuln-playground/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                fetched = resp.read(800).decode("utf-8", errors="replace")
        except Exception as exc:
            err = str(exc)[:240]
    body = page(
        "SSRF fetch",
        f"<p>Server-side fetch.</p><pre>url={html.escape(url)}</pre>"
        f"<pre>err={html.escape(err)}</pre><pre>{html.escape(fetched[:400])}</pre>",
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/ssrf/reflect",
    title="SSRF reflection-only",
    family="ssrf",
    expected="reflected_only — never confirmed SSRF via OOB",
    tags=["control", "fp-guard"],
)
def ssrf_reflect(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    url = params.get("url", "")
    send(
        handler,
        200,
        page("SSRF reflect", f"<p>Invalid URL echoed: {html.escape(url)}</p>"),
        head_only=head_only,
    )


@register(
    "/ssrf/imds-tease",
    title="SSRF IMDS path tease (no real IMDS)",
    family="ssrf",
    expected="lab/imds signal or skip — does not contact 169.254.169.254",
    tags=["lab"],
    notes="If url looks like metadata IP, returns fake JSON body without network I/O.",
)
def ssrf_imds(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    url = params.get("url", "")
    if "169.254.169.254" in url or "metadata" in url.lower():
        fake = '{"Code":"Success","Token":"PLAYGROUND_IMDS_FAKE"}'
        body = page("SSRF IMDS tease", f"<pre>{html.escape(fake)}</pre><p>url={html.escape(url)}</p>")
    else:
        body = page("SSRF IMDS tease", f"<p>Pass a metadata-looking url. Got: {html.escape(url)}</p>")
    send(handler, 200, body, head_only=head_only)
