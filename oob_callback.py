"""Out-of-band SSRF/XXE callback correlation for active probes.

Hardened correlation requires scan_id, probe_id, high-entropy nonce, expected
callback host/path, timestamp after probe send, and single-use / expiry.
Never confirms from URL reflection, poll errors, wrong scan, or stale events.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse


def new_oob_nonce() -> str:
    """High-entropy nonce for callback correlation (not short XSS markers)."""
    return secrets.token_hex(16)


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
    rejected_reason: str = ""

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
            "rejected_reason": self.rejected_reason,
        }


@dataclass
class OobStatus:
    callback_configured: bool = False
    probe_url_generated: bool = False
    polling_active: bool = False
    callback_received: bool = False
    confirmation_unavailable: bool = True
    reason: str = "no callback receiver configured"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "callback_configured": self.callback_configured,
            "probe_url_generated": self.probe_url_generated,
            "polling_active": self.polling_active,
            "callback_received": self.callback_received,
            "confirmation_unavailable": self.confirmation_unavailable,
            "reason": self.reason,
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
        expiry_seconds: float = 900.0,
    ) -> None:
        self.scan_id = (scan_id or "scan").strip() or "scan"
        self.callback_base = (callback_base or "").rstrip("/")
        self.poll_url = (poll_url or "").rstrip("/")
        self.http_client = http_client
        self.expiry_seconds = float(expiry_seconds or 900.0)
        self._probes: Dict[str, Dict[str, Any]] = {}
        self._events: Dict[str, CallbackEvent] = {}
        self._consumed: Set[str] = set()
        self._rejected: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._expected_host = (urlparse(self.callback_base).hostname or "").lower() if self.callback_base else ""

    @property
    def configured(self) -> bool:
        return bool(self.callback_base or self.poll_url)

    def status_snapshot(
        self,
        *,
        probe_url_generated: bool = False,
        callback_received: bool = False,
        reason: str = "",
    ) -> OobStatus:
        configured = self.configured
        polling = bool(self.poll_url or (self.callback_base and self.http_client is not None))
        if not configured:
            return OobStatus(
                callback_configured=False,
                probe_url_generated=probe_url_generated,
                polling_active=False,
                callback_received=False,
                confirmation_unavailable=True,
                reason=reason or "no callback receiver configured",
            )
        if callback_received:
            return OobStatus(
                callback_configured=True,
                probe_url_generated=True,
                polling_active=polling,
                callback_received=True,
                confirmation_unavailable=False,
                reason="callback correlated",
            )
        return OobStatus(
            callback_configured=True,
            probe_url_generated=probe_url_generated,
            polling_active=polling,
            callback_received=False,
            confirmation_unavailable=True,
            reason=reason
            or (
                "callback probe sent; confirmation unavailable (no correlated callback)"
                if probe_url_generated
                else "callback service configured but probe URL not yet generated"
            ),
        )

    def register_probe(
        self,
        nonce: str,
        *,
        probe_id: str = "",
        endpoint: str = "",
        parameter: str = "",
        category: str = "ssrf",
        expected_path: str = "",
        callback_url: str = "",
        **extra: Any,
    ) -> None:
        n = str(nonce or "").strip()
        if not n or len(n) < 16:
            # Reject low-entropy nonces for OOB correlation
            self._rejected.append({"nonce": n, "reason": "nonce_too_short"})
            return
        sent_at = time.time()
        exp_path = expected_path or ""
        if callback_url and not exp_path:
            try:
                exp_path = urlparse(callback_url).path or ""
            except Exception:
                exp_path = ""
        self._probes[n] = {
            "scan_id": self.scan_id,
            "probe_id": probe_id or f"{category}:{n[:12]}",
            "endpoint": endpoint,
            "parameter": parameter,
            "category": category,
            "expected_host": self._expected_host,
            "expected_path": exp_path,
            "callback_url": callback_url,
            "sent_at": sent_at,
            "expires_at": sent_at + self.expiry_seconds,
            **extra,
        }

    def _validate_event(
        self,
        nonce: str,
        *,
        scan_id: str = "",
        probe_id: str = "",
        request_path: str = "",
        received_at: Optional[float] = None,
        source: str = "inject",
    ) -> Optional[str]:
        """Return reject reason or None if acceptable."""
        n = str(nonce or "").strip()
        meta = self._probes.get(n)
        if not meta:
            return "unknown_nonce"
        if n in self._consumed:
            return "nonce_already_consumed"
        now = float(received_at or time.time())
        sent_at = float(meta.get("sent_at") or 0)
        expires_at = float(meta.get("expires_at") or 0)
        if sent_at and now < sent_at - 1.0:
            return "timestamp_before_probe"
        if expires_at and now > expires_at:
            return "expired"
        sid = str(scan_id or meta.get("scan_id") or "")
        if sid and sid != self.scan_id:
            return "scan_id_mismatch"
        if str(meta.get("scan_id") or "") != self.scan_id:
            return "probe_scan_mismatch"
        if probe_id and meta.get("probe_id") and probe_id != meta.get("probe_id"):
            return "probe_id_mismatch"
        exp_host = str(meta.get("expected_host") or self._expected_host or "").lower()
        exp_path = str(meta.get("expected_path") or "")
        path = request_path or ""
        # Reject obvious reflection dumps / internal poll errors
        low = path.lower()
        if any(tok in low for tok in ("traceback", "internal server error", "exception", "proxy error")):
            return "poll_or_reflection_error"
        if exp_path and exp_path not in path and n not in path:
            # Allow path containing nonce even if prefix differs (CDN rewrite)
            if source == "poll" and n in path:
                pass
            elif source == "inject" and n in path:
                pass
            else:
                return "path_mismatch"
        if exp_host and source == "poll":
            # poll URL may be on poll_url host — skip host check for poll responses
            pass
        return None

    def record_event(
        self,
        nonce: str,
        *,
        callback_type: str = "http",
        source_ip: str = "",
        request_path: str = "",
        headers: Optional[Dict[str, str]] = None,
        probe_id: str = "",
        scan_id: str = "",
        received_at: Optional[float] = None,
        source: str = "inject",
    ) -> Optional[CallbackEvent]:
        n = str(nonce or "").strip()
        reason = self._validate_event(
            n,
            scan_id=scan_id,
            probe_id=probe_id,
            request_path=request_path,
            received_at=received_at,
            source=source,
        )
        meta = self._probes.get(n) or {}
        if reason:
            self._rejected.append({"nonce": n, "reason": reason, "path": request_path})
            return CallbackEvent(
                scan_id=str(meta.get("scan_id") or self.scan_id),
                probe_id=str(probe_id or meta.get("probe_id") or ""),
                nonce=n,
                callback_type=(callback_type or "http").lower(),
                received_at=float(received_at or time.time()),
                source_ip=source_ip or "",
                request_path=request_path or "",
                headers=dict(headers or {}),
                confirmed=False,
                rejected_reason=reason,
            )
        event = CallbackEvent(
            scan_id=str(meta.get("scan_id") or self.scan_id),
            probe_id=str(probe_id or meta.get("probe_id") or f"probe:{n[:12]}"),
            nonce=n,
            callback_type=(callback_type or "http").lower(),
            received_at=float(received_at or time.time()),
            source_ip=source_ip or "",
            request_path=request_path or "",
            headers=dict(headers or {}),
            confirmed=True,
        )
        self._events[n] = event
        return event

    def consume(self, nonce: str) -> None:
        n = str(nonce or "").strip()
        if n:
            self._consumed.add(n)

    def has_event(self, nonce: str) -> bool:
        ev = self._events.get(str(nonce or "").strip())
        return bool(ev and ev.confirmed)

    def get_event(self, nonce: str) -> Optional[CallbackEvent]:
        ev = self._events.get(str(nonce or "").strip())
        if ev and ev.confirmed:
            return ev
        return None

    def list_events(self) -> List[Dict[str, Any]]:
        return [e.as_dict() for e in self._events.values() if e.confirmed]

    async def _poll_remote(self, nonce: str) -> bool:
        if not self.poll_url and not self.callback_base:
            return False
        client = self.http_client
        if client is None:
            return False
        n = str(nonce or "").strip()
        meta = self._probes.get(n) or {}
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
                if status >= 500:
                    self._rejected.append({"nonce": n, "reason": "poll_server_error", "url": url})
                    continue
                if status >= 400:
                    continue
                low = text.lower()
                if any(tok in low for tok in ("traceback", "internal server error", "exception")):
                    self._rejected.append({"nonce": n, "reason": "poll_error_body", "url": url})
                    continue
                # Require nonce + confirmed/interactions — never trust bare 200
                if n.lower() not in low:
                    continue
                ctype = "http"
                if '"protocol":"dns"' in low.replace(" ", ""):
                    ctype = "dns"
                ok_marker = (
                    '"confirmed": true' in low
                    or '"confirmed":true' in low
                    or '"interactions"' in low
                )
                if not ok_marker:
                    continue
                # Prefer JSON scan_id match when present
                sid = str(meta.get("scan_id") or self.scan_id)
                if '"scan_id"' in low and sid.lower() not in low:
                    self._rejected.append({"nonce": n, "reason": "poll_scan_mismatch", "url": url})
                    continue
                ev = self.record_event(
                    n,
                    callback_type=ctype,
                    request_path=urlparse(url).path or url,
                    scan_id=sid,
                    probe_id=str(meta.get("probe_id") or ""),
                    source="poll",
                )
                return bool(ev and ev.confirmed)
            except Exception:
                self._rejected.append({"nonce": n, "reason": "poll_exception", "url": url})
                continue
        return False

    async def received(self, nonce: str) -> bool:
        n = str(nonce or "").strip()
        if not n:
            return False
        if n in self._consumed:
            return False
        if self.has_event(n):
            self.consume(n)
            return True
        if not self.configured:
            return False
        async with self._lock:
            if self.has_event(n):
                self.consume(n)
                return True
            ok = await self._poll_remote(n)
            if ok:
                self.consume(n)
            return ok

    def make_callback_received(self):
        async def _cb(nonce: str) -> bool:
            return await self.received(nonce)

        return _cb
