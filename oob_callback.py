"""Out-of-band SSRF/XXE callback correlation for active probes.

Supports:
- Process-local event registry (tests + future local collector)
- Optional HTTP poll against a callback service / Interactsh-compatible endpoint
- DNS and HTTP event types

Never confirms from URL reflection alone — only correlated callback events.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin


@dataclass
class CallbackEvent:
    scan_id: str
    probe_id: str
    nonce: str
    callback_type: str  # dns | http
    received_at: float
    source_ip: str = ""
    request_path: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    confirmed: bool = True

    def as_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "probe_id": self.probe_id,
            "nonce": self.nonce,
            "callback_type": self.callback_type,
            "received_at": self.received_at,
            "source_ip": self.source_ip,
            "request_path": self.request_path,
            "headers": dict(self.headers),
            "confirmed": bool(self.confirmed),
        }


class OobCallbackCorrelator:
    """Correlate OOB callback nonces to scan/probe metadata."""

    def __init__(
        self,
        *,
        scan_id: str = "",
        callback_base: str = "",
        poll_url: str = "",
        http_client=None,
    ) -> None:
        self.scan_id = scan_id or "scan"
        self.callback_base = (callback_base or "").rstrip("/")
        self.poll_url = (poll_url or "").rstrip("/")
        self.http_client = http_client
        self._probes: Dict[str, Dict[str, Any]] = {}
        self._events: Dict[str, CallbackEvent] = {}
        self._lock = asyncio.Lock()

    @property
    def configured(self) -> bool:
        """True when a receiver/poller path exists (base or poll URL or live events)."""
        return bool(self.callback_base or self.poll_url)

    def register_probe(
        self,
        nonce: str,
        *,
        probe_id: str = "",
        endpoint: str = "",
        parameter: str = "",
        category: str = "ssrf",
        **extra: Any,
    ) -> None:
        n = str(nonce or "").strip()
        if not n:
            return
        self._probes[n] = {
            "scan_id": self.scan_id,
            "probe_id": probe_id or f"{category}:{n}",
            "endpoint": endpoint,
            "parameter": parameter,
            "category": category,
            **extra,
        }

    def record_event(
        self,
        nonce: str,
        *,
        callback_type: str = "http",
        source_ip: str = "",
        request_path: str = "",
        headers: Optional[Dict[str, str]] = None,
        probe_id: str = "",
    ) -> CallbackEvent:
        n = str(nonce or "").strip()
        meta = self._probes.get(n) or {}
        event = CallbackEvent(
            scan_id=str(meta.get("scan_id") or self.scan_id),
            probe_id=str(probe_id or meta.get("probe_id") or f"probe:{n}"),
            nonce=n,
            callback_type=(callback_type or "http").lower(),
            received_at=time.time(),
            source_ip=source_ip or "",
            request_path=request_path or "",
            headers=dict(headers or {}),
            confirmed=True,
        )
        self._events[n] = event
        return event

    def has_event(self, nonce: str) -> bool:
        return str(nonce or "").strip() in self._events

    def get_event(self, nonce: str) -> Optional[CallbackEvent]:
        return self._events.get(str(nonce or "").strip())

    def list_events(self) -> List[Dict[str, Any]]:
        return [e.as_dict() for e in self._events.values()]

    async def _poll_remote(self, nonce: str) -> bool:
        """Poll external callback service. Expects JSON with confirmed/interactions."""
        if not self.poll_url and not self.callback_base:
            return False
        client = self.http_client
        if client is None:
            return False
        n = str(nonce or "").strip()
        urls = []
        if self.poll_url:
            urls.append(f"{self.poll_url.rstrip('/')}/{n}")
            urls.append(f"{self.poll_url}?nonce={n}")
        if self.callback_base:
            urls.append(f"{self.callback_base}/_vantacrawl/poll/{n}")
            urls.append(urljoin(self.callback_base + "/", f"poll/{n}"))
        for url in urls:
            try:
                resp = await client.get(url, timeout=5, follow_redirects=True)
                status = int(getattr(resp, "status_code", 0) or 0)
                text = getattr(resp, "text", None) or ""
                if status >= 400:
                    continue
                low = text.lower()
                if '"confirmed": true' in low or '"confirmed":true' in low:
                    self.record_event(n, callback_type="http", request_path=url)
                    return True
                if '"interactions"' in low and n.lower() in low:
                    self.record_event(n, callback_type="http", request_path=url)
                    return True
                # DNS-style poll marker
                if '"protocol":"dns"' in low.replace(" ", "") and n.lower() in low:
                    self.record_event(n, callback_type="dns", request_path=url)
                    return True
            except Exception:
                continue
        return False

    async def received(self, nonce: str) -> bool:
        """Return True only when a correlated DNS/HTTP callback event exists."""
        n = str(nonce or "").strip()
        if not n:
            return False
        if self.has_event(n):
            return True
        if not self.configured:
            return False
        async with self._lock:
            if self.has_event(n):
                return True
            return await self._poll_remote(n)

    def make_callback_received(self):
        """Async callable matching ProbeModeSettings.callback_received(nonce) -> bool."""

        async def _cb(nonce: str) -> bool:
            return await self.received(nonce)

        return _cb
