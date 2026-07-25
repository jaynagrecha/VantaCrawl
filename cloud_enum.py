"""S3 and GCS bucket discovery (Gobuster cloud modes).

Wordlist cloud guessing must not pollute findings with generic 403 AccessDenied
responses. A 403 means inaccessible/denied — not a public bucket hit. Only
accept responses that demonstrate listing/public access, optionally when the
bucket name is related to the target domain.
"""

from __future__ import annotations

import asyncio
from typing import Callable, List
from urllib.parse import urlparse

import httpx

from async_runtime import is_running
from content_validate import classify_bucket_response
from crawler_common import load_wordlist


def _bucket_related_to_target(bucket: str, root: str) -> bool:
    """Loose ownership hint — never sufficient alone for a finding."""
    b = (bucket or "").lower().strip(".")
    r = (root or "").lower().strip(".")
    if not b or not r:
        return False
    # root label without TLD
    label = r.split(".")[0]
    if len(label) >= 4 and label in b:
        return True
    if r.replace(".", "-") in b or r.replace(".", "") in b:
        return True
    return False


def _is_public_listing(status: int, body: bytes | str, provider: str) -> bool:
    ok, note = classify_bucket_response(status, body, provider=provider)
    if not ok:
        return False
    # Reject existence-only / AccessDenied classifications for wordlist hits
    note_l = (note or "").lower()
    if "accessdenied" in note_l or "listing denied" in note_l or "ambiguous" in note_l:
        return False
    if status in (200, 204):
        text = (
            body.decode("utf-8", errors="replace")
            if isinstance(body, (bytes, bytearray))
            else (body or "")
        )
        # Require listing markers for S3/GCS
        if provider == "s3" and (
            "<listbucketresult" in text.lower()
            or "<contents>" in text.lower()
            or "<?xml" in text[:200].lower()
        ):
            return True
        if provider == "gcs" and (
            '"items"' in text
            or '"prefixes"' in text
            or "<listbucketresult" in text.lower()
        ):
            return True
        # Non-XML 200 with substantial non-HTML body can still be a listing
        if status == 200 and len(text) > 64 and "<html" not in text[:200].lower():
            return True
    return False


async def _probe_bucket(
    client: httpx.AsyncClient,
    url: str,
    *,
    provider: str,
    stats=None,
) -> tuple[bool, str, int]:
    """HEAD then GET — only public/listable buckets count as hits."""
    try:
        response = await client.head(url, timeout=8, follow_redirects=True)
    except httpx.HTTPError:
        return False, "request failed", 0
    status = response.status_code
    body = b""
    if status == 403:
        # 403 = denied/inaccessible — never a public bucket hit from wordlist guessing
        if stats is not None and hasattr(stats, "record_request"):
            try:
                stats.record_request(
                    phase="cloud_enum",
                    source=provider,
                    url=url,
                    status=status,
                    outcome="denied_not_hit",
                )
            except Exception:
                pass
        return False, f"{provider} HTTP 403 denied (not a public hit)", status
    if status in (200, 204, 301, 302, 307, 308):
        if status in (301, 302, 307, 308):
            # Redirects alone are weak — fetch body when possible
            try:
                get_resp = await client.get(url, timeout=8, follow_redirects=True)
                status = get_resp.status_code
                body = get_resp.content or b""
            except httpx.HTTPError:
                body = b""
        elif status in (200, 204):
            try:
                get_resp = await client.get(url, timeout=8, follow_redirects=True)
                status = get_resp.status_code
                body = get_resp.content or b""
            except httpx.HTTPError:
                body = b""
        if stats is not None and hasattr(stats, "record_request"):
            try:
                stats.record_request(
                    phase="cloud_enum",
                    source=provider,
                    url=url,
                    status=status,
                    bytes_=len(body),
                    outcome="ok" if status < 400 else "http_error",
                )
            except Exception:
                pass
        if _is_public_listing(status, body, provider):
            return True, f"{provider} public listing HTTP {status}", status
        return False, f"{provider} HTTP {status} (no public listing evidence)", status
    return False, f"ignored HTTP {status}", status


async def enumerate_s3_buckets(
    domain: str,
    wordlist_path: str,
    client: httpx.AsyncClient,
    *,
    running: Callable[[], bool],
    output_callback,
    max_names: int = 500,
    concurrency: int = 40,
    stats=None,
) -> List[str]:
    root = urlparse(f"https://{domain}").netloc.split(":")[0]
    root = root.replace("www.", "")
    words = load_wordlist(wordlist_path)[:max_names]
    found: List[str] = []
    sem = asyncio.Semaphore(max(1, concurrency))

    async def check_name(name: str):
        if not await is_running(running):
            return
        bucket = name.strip().lower()
        if not bucket:
            return
        # Prefer target-related names; still allow exact wordlist but require public listing
        for url in (
            f"https://{bucket}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{bucket}/",
        ):
            async with sem:
                ok, note, status = await _probe_bucket(
                    client, url, provider="s3", stats=stats
                )
            if ok:
                # Soft preference: note when name is unrelated
                if not _bucket_related_to_target(bucket, root):
                    output_callback(
                        f"S3 public listing (ownership unverified vs {root}): {url} [{status}] {note}"
                    )
                else:
                    output_callback(f"S3 bucket: {url} [{status}] {note}")
                found.append(url)
                return

    output_callback(f"S3 scan: {len(words)} names for {root} (public listings only; 403≠hit)")
    for index in range(0, len(words), concurrency):
        if not await is_running(running):
            break
        await asyncio.gather(*[check_name(w) for w in words[index : index + concurrency]], return_exceptions=True)
    return found


async def enumerate_gcs_buckets(
    domain: str,
    wordlist_path: str,
    client: httpx.AsyncClient,
    *,
    running: Callable[[], bool],
    output_callback,
    max_names: int = 500,
    concurrency: int = 40,
    stats=None,
) -> List[str]:
    root = urlparse(f"https://{domain}").netloc.split(":")[0].replace("www.", "")
    words = load_wordlist(wordlist_path)[:max_names]
    found: List[str] = []
    sem = asyncio.Semaphore(max(1, concurrency))

    async def check_name(name: str):
        if not await is_running(running):
            return
        bucket = name.strip().lower()
        if not bucket:
            return
        url = f"https://storage.googleapis.com/{bucket}/"
        async with sem:
            ok, note, status = await _probe_bucket(client, url, provider="gcs", stats=stats)
        if ok:
            if not _bucket_related_to_target(bucket, root):
                output_callback(
                    f"GCS public listing (ownership unverified vs {root}): {url} [{status}] {note}"
                )
            else:
                output_callback(f"GCS bucket: {url} [{status}] {note}")
            found.append(url)

    output_callback(f"GCS scan: {len(words)} bucket names (public listings only; 403≠hit)")
    for index in range(0, len(words), concurrency):
        if not await is_running(running):
            break
        await asyncio.gather(*[check_name(w) for w in words[index : index + concurrency]], return_exceptions=True)
    return found
