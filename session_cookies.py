"""Per-host cookie jar for stealth scans (pairs with sticky_host UA strategy)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional
from urllib.parse import urlparse


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
    """Host-scoped cookies synced from browser fetches / pasted Cookie headers."""

    # host -> name -> value
    _by_host: Dict[str, Dict[str, str]] = field(default_factory=dict)
    # seed cookies without a domain (from pasted cookie_string)
    _seed: Dict[str, str] = field(default_factory=dict)

    def clear(self) -> None:
        self._by_host.clear()
        self._seed.clear()

    def load_cookie_string(self, raw: str, *, host: str = "") -> None:
        """Parse `a=b; c=d` into the jar (optionally scoped to host)."""
        text = (raw or "").strip()
        if not text:
            return
        target = self._by_host.setdefault(_host_key(host), {}) if host else self._seed
        for part in text.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name, value = part.split("=", 1)
            name = name.strip()
            if not name:
                continue
            target[name] = value.strip()

    def ingest_selenium_cookies(self, cookies: Iterable[Mapping], url: str) -> int:
        """Merge Selenium get_cookies() rows; returns number of names updated."""
        host = _host_key(url)
        updated = 0
        for cookie in cookies or []:
            name = str(cookie.get("name") or "").strip()
            if not name:
                continue
            value = str(cookie.get("value") or "")
            domain = str(cookie.get("domain") or host)
            key = _host_key(domain) or host
            bucket = self._by_host.setdefault(key, {})
            if bucket.get(name) != value:
                updated += 1
            bucket[name] = value
        return updated

    def header_for(self, url: str) -> str:
        host = _host_key(url)
        merged: Dict[str, str] = dict(self._seed)
        for domain, pairs in self._by_host.items():
            if _domain_matches(domain, host):
                merged.update(pairs)
        # Also include exact host bucket
        if host in self._by_host:
            merged.update(self._by_host[host])
        return "; ".join(f"{k}={v}" for k, v in merged.items() if k)

    def as_cookie_string(self) -> str:
        """Flatten all known cookies (for config.cookie_string persistence)."""
        merged: Dict[str, str] = dict(self._seed)
        for pairs in self._by_host.values():
            merged.update(pairs)
        return "; ".join(f"{k}={v}" for k, v in merged.items() if k)

    def apply_to_client(self, client, url: str = "") -> str:
        """Write Cookie header onto httpx / StealthAsyncClient-style clients."""
        header = self.header_for(url) if url else self.as_cookie_string()
        headers = getattr(client, "headers", None)
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
