"""Non-blocking enum-hit follow-up (secrets / light passive checks).

Directory enum used to await a full re-GET + security suite on every hit.
On flaky static hosts (Netlify) that re-GET often hits curl error 28
(~12s timeout) and stalls the whole wordlist.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Callable, Optional, Set
from urllib.parse import urlparse

from crawler_common import looks_like_file_path_segment
from user_output import sanitize_error_message

# Archives / binaries / backups — record the hit, skip expensive follow-up.
_SKIP_FOLLOWUP_EXT_RE = re.compile(
    r"(?i)\.("
    r"zip|rar|7z|gz|tgz|tar|bz2|pdf|"
    r"png|jpe?g|gif|webp|ico|svg|avif|bmp|"
    r"woff2?|ttf|eot|otf|mp4|webm|mp3|wav|"
    r"exe|dll|bin|apk|dmg|iso|wasm|map|"
    r"bak|old|orig|swp|tmp|log"
    r")(?:$|\?)"
)

# Soft-deny file hits on static hosts rarely yield useful HTML for vuln scans.
_SOFT_DENY_STATUSES = frozenset({401, 403, 405})


def should_skip_enum_followup(url: str, status: int = 0, *, word: str = "") -> bool:
    """Return True when a follow-up fetch/scan would only burn time."""
    path = urlparse(url or "").path or ""
    name = (word or path.rsplit("/", 1)[-1] or "").strip()
    if _SKIP_FOLLOWUP_EXT_RE.search(path) or _SKIP_FOLLOWUP_EXT_RE.search(name):
        return True
    if int(status or 0) in _SOFT_DENY_STATUSES and looks_like_file_path_segment(name):
        return True
    return False


class EnumFollowupScheduler:
    """Fire-and-forget follow-ups with concurrency + timeout circuit breaker."""

    def __init__(
        self,
        *,
        client,
        config,
        stats,
        output_callback: Optional[Callable[[str], Any]] = None,
        run_security,
        extract_forms,
        concurrency: int = 2,
        timeout_s: float = 5.0,
        max_followups: int = 40,
        max_consecutive_timeouts: int = 4,
    ):
        self.client = client
        self.config = config
        self.stats = stats
        self.output_callback = output_callback or (lambda _m: None)
        self.run_security = run_security
        self.extract_forms = extract_forms
        self.timeout_s = float(timeout_s)
        self.max_followups = int(max_followups)
        self.max_consecutive_timeouts = int(max_consecutive_timeouts)
        self._sem = asyncio.Semaphore(max(1, int(concurrency)))
        self._tasks: Set[asyncio.Task] = set()
        self._scheduled = 0
        self._timeout_streak = 0
        self._disabled = False
        self._lock = asyncio.Lock()

    def schedule(self, probe) -> None:
        if self._disabled:
            return
        if self._scheduled >= self.max_followups:
            return
        if not (getattr(self.config, "enum_auto_crawl_hits", False) or getattr(self.config, "enum_auto_vuln_scan", False)):
            return
        url = getattr(probe, "url", "") or ""
        status = int(getattr(probe, "status", 0) or 0)
        word = getattr(probe, "word", "") or ""
        if should_skip_enum_followup(url, status, word=word):
            return
        self._scheduled += 1
        task = asyncio.create_task(self._run(probe), name=f"enum-followup:{url[:80]}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def drain(self, *, timeout: float = 45.0) -> None:
        """Wait briefly for in-flight follow-ups so enum can finish without hanging."""
        pending = list(self._tasks)
        if not pending:
            return
        done, still = await asyncio.wait(pending, timeout=max(1.0, float(timeout)))
        for task in still:
            task.cancel()
        if still:
            await asyncio.gather(*still, return_exceptions=True)
            self.output_callback(
                f"Enum follow-up: stopped {len(still)} still-running check(s) so the scan can continue."
            )

    async def _run(self, probe) -> None:
        if self._disabled:
            return
        async with self._sem:
            if self._disabled:
                return
            url = getattr(probe, "url", "") or ""
            status = int(getattr(probe, "status", 0) or 0)
            body = getattr(probe, "body", b"") or b""
            headers: dict = {}
            try:
                if body:
                    # Reuse enum probe body — avoids the curl-28 re-GET stall.
                    body_text = body.decode("utf-8", errors="replace")
                    headers = {"content-type": getattr(probe, "content_type", "") or "text/plain"}
                    headers["_status_code"] = str(status or 200)
                else:
                    response = await self.client.get(
                        url, timeout=self.timeout_s, follow_redirects=True
                    )
                    body = response.content or b""
                    body_text = body.decode("utf-8", errors="replace")
                    headers = dict(response.headers)
                    headers["_status_code"] = str(response.status_code)
                    status = int(response.status_code)
                async with self._lock:
                    self._timeout_streak = 0
            except Exception as error:
                async with self._lock:
                    self._timeout_streak += 1
                    streak = self._timeout_streak
                    if streak >= self.max_consecutive_timeouts:
                        self._disabled = True
                try:
                    self.stats.errors += 1
                except Exception:
                    pass
                msg = sanitize_error_message(error)
                self.output_callback(f"Hit follow-up scan failed: {url} ({msg})")
                if streak >= self.max_consecutive_timeouts:
                    self.output_callback(
                        "Enum follow-up paused after repeated timeouts — "
                        "directory scan continues without per-hit re-checks."
                    )
                return

            if not getattr(self.config, "enum_auto_vuln_scan", False):
                return
            # Skip noisy/empty soft-deny bodies
            if status in _SOFT_DENY_STATUSES and len(body_text.strip()) < 40:
                return
            forms = []
            try:
                ctype = headers.get("content-type", "")
                if body_text and ("html" in ctype.lower() or "<" in body_text[:500]):
                    forms = self.extract_forms(body_text, url, ctype) or []
            except Exception:
                forms = []
            prev_sec = getattr(self.config, "security_scan", False)
            prev_active = getattr(self.config, "vuln_active_probe", False)
            self.config.security_scan = True
            # Active probes on every enum hit are what multiplies curl-28 stalls.
            self.config.vuln_active_probe = False
            try:
                await self.run_security(
                    self.client,
                    self.config,
                    self.stats,
                    url,
                    body_text,
                    forms,
                    headers,
                    self.output_callback,
                    status_code=status or 200,
                    raw_body=body,
                )
            except Exception as error:
                try:
                    self.stats.errors += 1
                except Exception:
                    pass
                self.output_callback(
                    f"Hit follow-up scan failed: {url} ({sanitize_error_message(error)})"
                )
            finally:
                self.config.security_scan = prev_sec
                self.config.vuln_active_probe = prev_active
