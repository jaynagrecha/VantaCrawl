"""Per-host cookie jar for stealth scans (pairs with sticky_host UA strategy)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlparse

# Bot-manager / telemetry cookies — real on Akamai sites, but must stay host-scoped
_BM_COOKIE_RE = re.compile(
    r"(?i)^(?:_abck|ak_bmsc|bm_sz|bm_sv|bm_mi|bm_so|bm_lso|akamai_|akzip)$"
)


def _host_key(host_or_url: str) -> str:
    raw = (host_or_url or "").strip().lower()
    if "://" in raw:
        raw = urlparse(raw).netloc.lower()
    raw = raw.split("@")[-1]
    raw = raw.split(":")[0]
    if raw.startswith("."):
        raw = raw[1:]
    if raw.startswith("www."):
        raw = raw[4:]
    return raw


def _domain_matches(cookie_domain: str, request_host: str) -> bool:
    cd = _host_key(cookie_domain)
    rh = _host_key(request_host)
    if not cd or not rh:
        return False
    return rh == cd or rh.endswith("." + cd)


@dataclass
class SessionCookieStore:
    """Host-scoped cookies synced from browser fetches / pasted Cookie headers.

    Never flattens every host's cookies onto a single outbound request — that
    inflates Cookie volume and is a Bot Manager tell.
    """

    # host -> name -> value
    _by_host: Dict[str, Dict[str, str]] = field(default_factory=dict)
    # seed cookies without a domain (from pasted cookie_string) — applied only
    # after a host is known via ``bind_seed_to_host`` or ``header_for(url)`` once.
    _seed: Dict[str, str] = field(default_factory=dict)
    _seed_bound_host: str = ""

    def clear(self) -> None:
        self._by_host.clear()
        self._seed.clear()
        self._seed_bound_host = ""

    def load_cookie_string(self, raw: str, *, host: str = "") -> None:
        """Parse `a=b; c=d` into the jar (optionally scoped to host)."""
        text = (raw or "").strip()
        if not text:
            return
        if host:
            target = self._by_host.setdefault(_host_key(host), {})
            self._seed_bound_host = _host_key(host)
        else:
            target = self._seed
        for part in text.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name, value = part.split("=", 1)
            name = name.strip()
            if not name:
                continue
            target[name] = value.strip()

    def bind_seed_to_host(self, host_or_url: str) -> None:
        """Move unbound seed cookies onto a concrete host (first target)."""
        host = _host_key(host_or_url)
        if not host or not self._seed:
            return
        bucket = self._by_host.setdefault(host, {})
        for name, value in self._seed.items():
            bucket.setdefault(name, value)
        self._seed.clear()
        self._seed_bound_host = host

    def ingest_selenium_cookies(self, cookies: Iterable[Mapping], url: str) -> Tuple[int, List[str], List[str]]:
        """Merge Selenium get_cookies() rows.

        Returns ``(changed_count, new_names, changed_names)`` so callers can
        sync silently when only volatile BM cookie values mutate.
        """
        host = _host_key(url)
        changed = 0
        new_names: List[str] = []
        changed_names: List[str] = []
        for cookie in cookies or []:
            name = str(cookie.get("name") or "").strip()
            if not name:
                continue
            value = str(cookie.get("value") or "")
            domain = str(cookie.get("domain") or host)
            key = _host_key(domain) or host
            bucket = self._by_host.setdefault(key, {})
            prev = bucket.get(name)
            if prev is None:
                new_names.append(name)
                changed += 1
                changed_names.append(name)
            elif prev != value:
                changed += 1
                changed_names.append(name)
            bucket[name] = value
        return changed, new_names, changed_names

    def header_for(self, url: str) -> str:
        """Cookie header for one URL — host-scoped only (never all jars)."""
        host = _host_key(url)
        if self._seed and not self._seed_bound_host:
            # Bind paste-seed to first request host so BM cookies don't roam
            self.bind_seed_to_host(host)
        merged: Dict[str, str] = {}
        for domain, pairs in self._by_host.items():
            if _domain_matches(domain, host):
                merged.update(pairs)
        if host in self._by_host:
            merged.update(self._by_host[host])
        return "; ".join(f"{k}={v}" for k, v in merged.items() if k)

    def as_cookie_string(self) -> str:
        """Flatten for persistence/display only — never for outbound requests."""
        merged: Dict[str, str] = dict(self._seed)
        for pairs in self._by_host.values():
            merged.update(pairs)
        return "; ".join(f"{k}={v}" for k, v in merged.items() if k)

    def bm_cookie_count_for(self, url: str) -> int:
        header = self.header_for(url)
        if not header:
            return 0
        n = 0
        for part in header.split(";"):
            name = part.split("=", 1)[0].strip()
            if _BM_COOKIE_RE.match(name):
                n += 1
        return n

    def apply_to_client(self, client, url: str = "") -> str:
        """Write host-scoped Cookie header onto the client for ``url``.

        Requires a URL. Without one, clears a stale flat Cookie header rather
        than dumping every host's jar (bot tell: enormous Cookie volume).
        """
        headers = getattr(client, "headers", None)
        if not url:
            if headers is not None and "Cookie" in headers:
                try:
                    del headers["Cookie"]
                except Exception:
                    headers.pop("Cookie", None)
            return ""
        header = self.header_for(url)
        if headers is None:
            return header
        if header:
            try:
                headers["Cookie"] = header
            except Exception:
                pass
        elif "Cookie" in headers:
            try:
                del headers["Cookie"]
            except Exception:
                headers.pop("Cookie", None)
        # Best-effort httpx Cookies API
        jar = getattr(client, "cookies", None)
        if jar is not None and header and url:
            try:
                for part in header.split(";"):
                    part = part.strip()
                    if "=" not in part:
                        continue
                    name, value = part.split("=", 1)
                    domain = _host_key(url)
                    jar.set(name.strip(), value.strip(), domain=domain)
            except Exception:
                pass
        return header

    def host_count(self) -> int:
        return len(self._by_host)

    def dump(self) -> List[dict]:
        rows = []
        for host, pairs in self._by_host.items():
            for name, value in pairs.items():
                rows.append({"host": host, "name": name, "value": value})
        return rows
