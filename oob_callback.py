"""Out-of-band SSRF/XXE callback correlation for active probes.

Hardened correlation requires scan_id, probe_id, high-entropy nonce, expected
callback host/path, timestamp after probe send, and single-use / expiry.
Never confirms from URL reflection, poll errors, wrong scan, stale events,
or callbacks originating from the scanner / browser / poller itself.
"""

from __future__ import annotations

import asyncio
import secrets
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse


def new_oob_nonce() -> str:
    """High-entropy nonce for callback correlation (not short XSS markers)."""
    return secrets.token_hex(16)


def _local_ips() -> Set[str]:
    ips = {"127.0.0.1", "::1", "0.0.0.0", "localhost"}
    try:
        hostname = socket.gethostname()
        ips.add(hostname)
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if addr:
                ips.add(addr)
    except Exception:
        pass
    return ips


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
    requester_fingerprint: str = ""

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
            "requester_fingerprint": self.requester_fingerprint,
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
        reject_local_sources: bool = True,
    ) -> None:
        self.scan_id = (scan_id or "scan").strip() or "scan"
        self.callback_base = (callback_base or "").rstrip("/")
        self.poll_url = (poll_url or "").rstrip("/")
        self.http_client = http_client
        self.expiry_seconds = float(expiry_seconds or 900.0)
        self.reject_local_sources = bool(reject_local_sources)
        self._probes: Dict[str, Dict[str, Any]] = {}
        self._events: Dict[str, CallbackEvent] = {}
        self._consumed: Set[str] = set()
        self._rejected: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._expected_host = (urlparse(self.callback_base).hostname or "").lower() if self.callback_base else ""
        self._local_ips = _local_ips()
        self._poller_marker = "vantacrawl-oob-poller"

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

    def mint_nonce(self) -> str:
        """Allocate a fresh high-entropy nonce never previously registered."""
        for _ in range(8):
            n = new_oob_nonce()
            if n not in self._probes and n not in self._consumed and n not in self._events:
                return n
        return new_oob_nonce() + secrets.token_hex(4)

    def register_probe(
        self,
        nonce: str = "",
        *,
        probe_id: str = "",
        endpoint: str = "",
        parameter: str = "",
        category: str = "ssrf",
        expected_path: str = "",
        callback_url: str = "",
        **extra: Any,
    ) -> str:
        """Register a probe. Returns the bound nonce (minted when blank)."""
        n = str(nonce or "").strip() or self.mint_nonce()
        if len(n) < 16:
            self._rejected.append({"nonce": n, "reason": "nonce_too_short"})
            return ""
        # Never reuse a nonce across probes
        if n in self._probes or n in self._consumed or n in self._events:
            n = self.mint_nonce()
        sent_at = time.time()
        exp_path = expected_path or ""
        if callback_url and not exp_path:
            try:
                exp_path = urlparse(callback_url).path or ""
            except Exception:
                exp_path = ""
        pid = probe_id or f"{category}:{n[:12]}"
        self._probes[n] = {
            "scan_id": self.scan_id,
            "probe_id": pid,
            "endpoint": endpoint,
            "parameter": parameter,
            "category": category,
            "expected_host": self._expected_host,
            "expected_path": exp_path,
            "callback_url": callback_url,
            "issued_at": sent_at,
            "sent_at": sent_at,
            "expires_at": sent_at + self.expiry_seconds,
            **extra,
        }
        return n

    def _reject_source(
        self,
        *,
        source_ip: str = "",
        headers: Optional[Dict[str, str]] = None,
        source: str = "inject",
        requester_fingerprint: str = "",
    ) -> Optional[str]:
        if source == "poll":
            # Poll responses are not inbound callbacks — handled separately
            return None
        hdrs = {str(k).lower(): str(v) for k, v in dict(headers or {}).items()}
        ua = (hdrs.get("user-agent") or "").lower()
        fp = (requester_fingerprint or "").lower()
        if self._poller_marker in ua or self._poller_marker in fp:
            return "source_is_poller"
        if "selenium" in ua or "chromedriver" in ua or "headlesschrome" in ua:
            return "source_is_browser_worker"
        if "vantacrawl" in ua and "probe" in ua:
            return "source_is_scanner_worker"
        if self.reject_local_sources and source_ip:
            sip = source_ip.strip().lower()
            if sip in self._local_ips or sip.startswith("127.") or sip == "::1":
                # Local hits are only valid when the *target* fetched the callback
                # (same-host lab). Accept loopback but tag fingerprint — still bind
                # to exact nonce/probe. Do not reject 127.0.0.1 for local labs.
                pass
        return None

    def _validate_event(
        self,
        nonce: str,
        *,
        scan_id: str = "",
        probe_id: str = "",
        request_path: str = "",
        received_at: Optional[float] = None,
        source: str = "inject",
        source_ip: str = "",
        headers: Optional[Dict[str, str]] = None,
        requester_fingerprint: str = "",
    ) -> Optional[str]:
        """Return reject reason or None if acceptable."""
        n = str(nonce or "").strip()
        meta = self._probes.get(n)
        if not meta:
            return "unknown_nonce"
        if n in self._consumed:
            return "nonce_already_consumed"
        src_reason = self._reject_source(
            source_ip=source_ip,
            headers=headers,
            source=source,
            requester_fingerprint=requester_fingerprint,
        )
        if src_reason:
            return src_reason
        now = float(received_at or time.time())
        issued_at = float(meta.get("issued_at") or meta.get("sent_at") or 0)
        expires_at = float(meta.get("expires_at") or 0)
        # Strict: callback must be after probe issuance
        if issued_at and now < issued_at:
            return "timestamp_before_probe"
        if expires_at and now > expires_at:
            return "expired"
        sid = str(scan_id or meta.get("scan_id") or "")
        if sid and sid != self.scan_id:
            return "scan_id_mismatch"
        if str(meta.get("scan_id") or "") != self.scan_id:
            return "probe_scan_mismatch"
        # Probe ID must match when provided — never confirm probe A with probe B's id
        if probe_id and meta.get("probe_id") and probe_id != meta.get("probe_id"):
            return "probe_id_mismatch"
        exp_path = str(meta.get("expected_path") or "")
        path = request_path or ""
        low = path.lower()
        if any(tok in low for tok in ("traceback", "internal server error", "exception", "proxy error")):
            return "poll_or_reflection_error"
        if exp_path and exp_path not in path and n not in path:
            return "path_mismatch"
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
        requester_fingerprint: str = "",
    ) -> Optional[CallbackEvent]:
        n = str(nonce or "").strip()
        reason = self._validate_event(
            n,
            scan_id=scan_id,
            probe_id=probe_id,
            request_path=request_path,
            received_at=received_at,
            source=source,
            source_ip=source_ip,
            headers=headers,
            requester_fingerprint=requester_fingerprint,
        )
        meta = self._probes.get(n) or {}
        if reason:
            self._rejected.append(
                {
                    "nonce": n,
                    "reason": reason,
                    "path": request_path,
                    "source_ip": source_ip,
                    "probe_id": probe_id or meta.get("probe_id"),
                }
            )
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
                requester_fingerprint=requester_fingerprint,
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
            requester_fingerprint=requester_fingerprint,
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

    def _poll_body_is_confirmed(self, text: str, nonce: str) -> bool:
        """Require explicit confirmed:true for this nonce — never bare interactions key."""
        low = (text or "").lower()
        n = (nonce or "").lower()
        if not n or n not in low:
            return False
        if '"confirmed": true' in low or '"confirmed":true' in low:
            # Reject confirmed:false winning via substring games
            if '"confirmed": false' in low or '"confirmed":false' in low:
                # Ambiguous / mixed — require a positive interactions count
                if '"interactions": []' in low.replace(" ", "") or '"interactions":[]' in low.replace(" ", ""):
                    return False
            return True
        return False

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
        headers = {"User-Agent": f"VantaCrawl/{self._poller_marker}"}
        for url in urls:
            try:
                resp = await client.get(url, timeout=5, follow_redirects=False, headers=headers)
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
                if not self._poll_body_is_confirmed(text, n):
                    continue
                ctype = "http"
                if '"protocol":"dns"' in low.replace(" ", ""):
                    ctype = "dns"
                sid = str(meta.get("scan_id") or self.scan_id)
                if '"scan_id"' in low and sid.lower() not in low:
                    self._rejected.append({"nonce": n, "reason": "poll_scan_mismatch", "url": url})
                    continue
                # Prefer probe_id match when poll JSON includes it
                pid = str(meta.get("probe_id") or "")
                if pid and '"probe_id"' in low and pid.lower() not in low:
                    self._rejected.append({"nonce": n, "reason": "poll_probe_mismatch", "url": url})
                    continue
                # Extract source_ip from poll JSON when present
                source_ip = ""
                m_ip = None
                try:
                    import json as _json

                    payload = _json.loads(text)
                    interactions = payload.get("interactions") or []
                    if interactions and isinstance(interactions[0], dict):
                        source_ip = str(interactions[0].get("source_ip") or "")
                        # Interaction must reference this nonce
                        if str(interactions[0].get("nonce") or n) != n:
                            self._rejected.append({"nonce": n, "reason": "poll_interaction_nonce_mismatch"})
                            continue
                except Exception:
                    pass
                ev = self.record_event(
                    n,
                    callback_type=ctype,
                    request_path=urlparse(url).path or url,
                    scan_id=sid,
                    probe_id=pid,
                    source_ip=source_ip,
                    source="poll",
                    requester_fingerprint=self._poller_marker,
                )
                return bool(ev and ev.confirmed)
            except Exception:
                self._rejected.append({"nonce": n, "reason": "poll_exception", "url": url})
                continue
        return False

    async def received(self, nonce: str, *, probe_id: str = "") -> bool:
        """Return True only for this nonce (and optional probe_id), then consume."""
        n = str(nonce or "").strip()
        if not n:
            return False
        if n in self._consumed:
            return False
        meta = self._probes.get(n) or {}
        if probe_id and meta.get("probe_id") and probe_id != meta.get("probe_id"):
            self._rejected.append({"nonce": n, "reason": "received_probe_id_mismatch", "probe_id": probe_id})
            return False
        if self.has_event(n):
            ev = self.get_event(n)
            if probe_id and ev and ev.probe_id and ev.probe_id != probe_id:
                return False
            self.consume(n)
            return True
        if not self.configured:
            return False
        async with self._lock:
            if self.has_event(n):
                ev = self.get_event(n)
                if probe_id and ev and ev.probe_id and ev.probe_id != probe_id:
                    return False
                self.consume(n)
                return True
            ok = await self._poll_remote(n)
            if ok:
                self.consume(n)
            return ok

    def make_callback_received(self):
        async def _cb(nonce: str, probe_id: str = "") -> bool:
            return await self.received(nonce, probe_id=probe_id)

        return _cb
