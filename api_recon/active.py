"""Conservative active API path enumeration (GET/HEAD)."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from typing import Callable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

from async_runtime import is_running
from crawler_common import load_wordlist
from edge_checkpoint import (
    is_api_content_type,
    is_edge_checkpoint,
    looks_like_html_denial,
)
from enum_engine import REDIRECT_STATUSES, follow_same_host_redirects
from .models import ApiEndpoint

DEFAULT_BASES = ("/api/", "/api/v1/", "/api/v2/", "/v1/", "/v2/", "/rest/", "/graphql")
# Final statuses that *may* count as API hits after evidence gates
_HIT_STATUSES = {200, 201, 204, 401, 403}


def _probe_path(url: str) -> str:
    path = urlparse(url).path or "/"
    return path if path.startswith("/") else f"/{path}"


def _body_fingerprint(body: bytes) -> str:
    if not body:
        return "empty"
    return hashlib.sha256(body[:65536]).hexdigest()[:32]


async def _calibrate_denial_baseline(
    client: httpx.AsyncClient,
    origin: str,
    *,
    headers: dict,
) -> List[Tuple[int, str, str]]:
    """Probe random paths under API bases to capture generic edge denial fingerprints."""
    baselines: List[Tuple[int, str, str]] = []
    nonce = uuid.uuid4().hex[:12]
    for base in ("/api/", "/rest/", "/"):
        url = urljoin(origin + base, f"crawler-api-baseline-{nonce}")
        try:
            resp = await client.get(url, headers=headers, timeout=8, follow_redirects=False)
            raw = getattr(resp, "content", b"") or b""
            body = raw if isinstance(raw, (bytes, bytearray)) else b""
            try:
                ctype = (resp.headers.get("content-type") or "")[:80]
            except Exception:
                ctype = ""
            baselines.append((int(getattr(resp, "status_code", 0) or 0), ctype.lower(), _body_fingerprint(body)))
        except httpx.HTTPError:
            continue
        except Exception:
            continue
    return baselines


def _matches_denial_baseline(
    status: int,
    ctype: str,
    body_hash: str,
    baselines: List[Tuple[int, str, str]],
) -> bool:
    ct = (ctype or "").lower()
    for b_status, b_ct, b_hash in baselines:
        if status != b_status:
            continue
        if body_hash and b_hash and body_hash == b_hash:
            return True
        if "html" in ct and "html" in b_ct and status in (401, 403):
            return True
    return False


def _html_static_twin_exists(url: str, stats) -> bool:
    """Reject /status as API when /status.html was already discovered as HTML."""
    if stats is None:
        return False
    path = (urlparse(url).path or "/").rstrip("/")
    if not path or path == "/":
        return False
    twin = f"{path}.html"
    discovered = getattr(stats, "discovered_urls", None) or set()
    for u in discovered:
        try:
            p = urlparse(str(u)).path or ""
        except Exception:
            continue
        if p.rstrip("/") == twin or p.endswith(twin):
            return True
    return False


def _accept_api_hit(
    *,
    status: int,
    ctype: str,
    body: bytes,
    url: str,
    baselines: List[Tuple[int, str, str]],
    stats,
) -> Tuple[bool, str]:
    """Apply evidence gates before counting an API hit."""
    headers = {"content-type": ctype}
    if is_edge_checkpoint(status, body, headers):
        return False, "blocked_probe_candidate"
    if _html_static_twin_exists(url, stats):
        return False, "html_application_route"
    body_hash = _body_fingerprint(body)
    ct = (ctype or "").lower()

    if status in (200, 201, 204):
        if "text/html" in ct or ("html" in ct and "json" not in ct):
            return False, "html_application_route"
        if is_api_content_type(ctype, body):
            return True, "api_content"
        # Empty 204 on API-ish path can still be a hit
        if status == 204 and any(tok in (urlparse(url).path or "").lower() for tok in ("/api", "/rest", "/v1", "/v2", "graphql")):
            return True, "api_empty_success"
        return False, "no_api_evidence"

    if status in (401, 403):
        if looks_like_html_denial(status, ctype, body) or _matches_denial_baseline(
            status, ctype, body_hash, baselines
        ):
            return False, "blocked_probe_candidate"
        if is_api_content_type(ctype, body):
            return True, "protected_api_differential"
        # Distinct non-HTML denial (e.g. WWW-Authenticate JSON) still counts
        if "json" in ct or "xml" in ct:
            return True, "protected_api_differential"
        return False, "blocked_probe_candidate"

    return False, "negative"


async def run_active_api_enum(
    client: httpx.AsyncClient,
    start_url: str,
    *,
    wordlist_file: str,
    word_limit: int = 3000,
    headers: dict,
    concurrency: int = 20,
    method: str = "GET",
    running: Optional[Callable[[], bool]] = None,
    output_callback: Optional[Callable[[str], None]] = None,
    update_progress=None,
    follow_redirects: bool = True,
    max_redirect_hops: int = 5,
    stats=None,
) -> List[ApiEndpoint]:
    origin = f"{urlparse(start_url).scheme}://{urlparse(start_url).netloc}"
    words = load_wordlist(wordlist_file, max_words=max(1, int(word_limit) or 3000))
    if not words:
        words = [
            "health",
            "status",
            "users",
            "user",
            "login",
            "auth",
            "token",
            "me",
            "config",
            "swagger",
            "openapi",
            "docs",
            "graphql",
            "admin",
            "search",
            "products",
            "orders",
            "v1",
            "v2",
        ]

    targets: List[str] = []
    seen: Set[str] = set()
    for base in DEFAULT_BASES:
        for word in words:
            w = word.strip().lstrip("/")
            if not w:
                continue
            url = urljoin(origin + base, w)
            if url in seen:
                continue
            seen.add(url)
            targets.append(url)
            if word_limit and len(targets) >= word_limit:
                break
        if word_limit and len(targets) >= word_limit:
            break

    total = len(targets)
    if output_callback:
        output_callback(f"API active enum: {total:,} probes · {method} · {concurrency} threads")
    if stats is not None and hasattr(stats, "note_api_recon_progress"):
        stats.note_api_recon_progress(0, total=total, path="", hits=0)
    if update_progress and total:
        update_progress(total, 0, f"API recon 0/{total}")

    baselines = await _calibrate_denial_baseline(client, origin, headers=headers)
    if output_callback and baselines:
        output_callback(
            f"API denial baseline: {len(baselines)} control probe(s) "
            f"(generic HTML 401/403 will not count as API hits)"
        )

    sem = asyncio.Semaphore(max(1, int(concurrency) or 1))
    hits: List[ApiEndpoint] = []
    done = 0
    lock = asyncio.Lock()
    verb = (method or "HEAD").upper()
    if verb not in ("GET", "HEAD"):
        verb = "HEAD"
    # Prefer GET so content-type/body evidence is available for gates
    if verb == "HEAD":
        verb = "GET"

    def _publish(done_n: int, path: str = "") -> None:
        hit_n = len(hits)
        if stats is not None and hasattr(stats, "note_api_recon_progress"):
            stats.note_api_recon_progress(done_n, total=total, path=path, hits=hit_n)
        if update_progress and total and (done_n == 0 or done_n == total or done_n % 5 == 0):
            label = f"API recon {done_n}/{total}"
            if path:
                label = f"{label} · {path}"
            if hit_n:
                label = f"{label} · {hit_n} hit(s)"
            update_progress(total, done_n, label)

    async def probe(url: str) -> None:
        nonlocal done
        if running and not await is_running(running):
            return
        status = 0
        final_url = url
        hops = 0
        ctype = ""
        body = b""
        path = _probe_path(url)
        async with sem:
            if running and not running():
                return
            async with lock:
                if stats is not None and hasattr(stats, "note_api_recon_progress"):
                    stats.note_api_recon_progress(done, total=total, path=path, hits=len(hits))
            try:
                resp = await client.get(url, headers=headers, timeout=10, follow_redirects=False)
                status = int(getattr(resp, "status_code", 0) or 0)
                try:
                    ctype = (resp.headers.get("content-type") or "")[:80]
                except Exception:
                    ctype = ""
                raw = getattr(resp, "content", b"") or b""
                body = raw if isinstance(raw, (bytes, bytearray)) else b""
                if follow_redirects and status in REDIRECT_STATUSES:
                    (
                        status,
                        _length,
                        _hash,
                        body,
                        final_url,
                        hops,
                        _chain,
                        final_ctype,
                    ) = await follow_same_host_redirects(
                        client,
                        url,
                        max_hops=max_redirect_hops,
                        timeout=10,
                    )
                    if final_ctype:
                        ctype = final_ctype[:80]
                if stats is not None and hasattr(stats, "record_request"):
                    try:
                        stats.record_request(
                            phase="api_recon",
                            source="active",
                            url=url,
                            status=status,
                            final_url=final_url or url,
                            response_type=ctype,
                            bytes_=len(body),
                            outcome="ok" if status and status < 400 else "http_error",
                        )
                    except Exception:
                        pass
            except httpx.HTTPError:
                async with lock:
                    done += 1
                    _publish(done, path)
                return
        async with lock:
            done += 1
            if status in _HIT_STATUSES:
                ok, reason = _accept_api_hit(
                    status=status,
                    ctype=ctype,
                    body=body[:65536],
                    url=url,
                    baselines=baselines,
                    stats=stats,
                )
                if ok:
                    note = "Protected API path" if status in (401, 403) else ""
                    if hops:
                        note = (note + "; " if note else "") + f"via {hops} redirect hop(s) → {final_url}"
                    if reason and reason != "api_content":
                        note = (note + "; " if note else "") + reason
                    hits.append(
                        ApiEndpoint(
                            method=verb,
                            url=url,
                            path=urlparse(url).path or "/",
                            source="active",
                            status=status,
                            content_type=ctype,
                            note=note,
                        )
                    )
            _publish(done, path)

    await asyncio.gather(*(probe(u) for u in targets))
    if stats is not None and hasattr(stats, "note_api_recon_progress"):
        stats.note_api_recon_progress(total, total=total, path="", hits=len(hits))
    if update_progress and total:
        update_progress(total, total, f"API recon {total}/{total}")
    return hits
