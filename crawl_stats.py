"""Live crawl statistics and findings collection."""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class CrawlStats:
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    pages_crawled: int = 0
    links_found: int = 0
    enum_hits: int = 0
    enum_words_tested: int = 0
    enum_words_total: int = 0
    enum_started_at: Optional[float] = None
    enum_current_word: str = ""
    enum_current_path: str = "/"
    enum_current_depth: int = 0
    _enum_rate_samples: List[Tuple[float, int]] = field(default_factory=list)
    enum_hit_urls: List[str] = field(default_factory=list)
    bytes_downloaded: int = 0
    errors: int = 0
    skipped_duplicate: int = 0
    skipped_not_modified: int = 0
    status_codes: Counter = field(default_factory=Counter)
    enum_status_codes: Counter = field(default_factory=Counter)
    technologies: Counter = field(default_factory=Counter)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    broken_links: List[Dict[str, str]] = field(default_factory=list)
    sensitive_urls: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    content_hashes: Set[str] = field(default_factory=set)
    etag_cache: Dict[str, str] = field(default_factory=dict)
    last_modified_cache: Dict[str, str] = field(default_factory=dict)
    queue_size: int = 0
    paused: bool = False
    discovered_urls: Set[str] = field(default_factory=set)
    session_total_estimate: int = 0
    defense_tracker: Any = None
    evasion_session: Any = None
    _finding_dedupe: Set[str] = field(default_factory=set)
    finding_repeat_suppressed: int = 0

    # Discovery / specialty result buckets (for detailed reports)
    historical_seed_urls: List[str] = field(default_factory=list)
    subdomain_urls: List[str] = field(default_factory=list)
    js_route_urls: List[str] = field(default_factory=list)
    openapi_doc_urls: List[str] = field(default_factory=list)
    openapi_endpoints: List[str] = field(default_factory=list)
    api_endpoint_urls: List[str] = field(default_factory=list)
    api_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    api_docs: List[str] = field(default_factory=list)
    api_graphql_operations: List[Dict[str, str]] = field(default_factory=list)
    api_recon_probes_done: int = 0
    api_recon_probes_total: int = 0
    api_recon_hits: int = 0
    api_recon_current_path: str = ""
    api_recon_started_at: Optional[float] = None
    _api_recon_rate_samples: List[Tuple[float, int]] = field(default_factory=list)
    subdomain_probes_done: int = 0
    subdomain_probes_total: int = 0
    subdomain_hits: int = 0
    subdomain_current_host: str = ""
    rss_feed_urls: List[str] = field(default_factory=list)
    s3_buckets: List[str] = field(default_factory=list)
    gcs_buckets: List[str] = field(default_factory=list)
    vhost_hits: List[str] = field(default_factory=list)
    login_surfaces: List[str] = field(default_factory=list)
    websocket_urls: List[str] = field(default_factory=list)
    sourcemap_urls: List[str] = field(default_factory=list)
    cookie_inventory: List[Dict[str, str]] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    phones: List[str] = field(default_factory=list)
    internal_hosts: List[str] = field(default_factory=list)
    third_party_scripts: List[Dict[str, str]] = field(default_factory=list)
    link_rels: List[Dict[str, str]] = field(default_factory=list)
    security_headers_by_host: Dict[str, Dict[str, str]] = field(default_factory=dict)
    interesting_comments: List[str] = field(default_factory=list)
    dom_sinks: List[str] = field(default_factory=list)
    cloud_service_urls: List[str] = field(default_factory=list)
    sitemap_doc_urls: List[str] = field(default_factory=list)
    sitemap_page_urls: List[str] = field(default_factory=list)
    tls_sans: List[str] = field(default_factory=list)
    well_known_hits: List[Dict[str, str]] = field(default_factory=list)
    file_metadata: List[Dict[str, Any]] = field(default_factory=list)
    _http_methods_hosts: Set[str] = field(default_factory=set)
    _cors_hosts: Set[str] = field(default_factory=set)
    _header_hardening_hosts: Set[str] = field(default_factory=set)
    _file_upload_actions: Set[str] = field(default_factory=set)
    _host_recon_done: Set[str] = field(default_factory=set)
    _file_meta_seen: Set[str] = field(default_factory=set)
    _url_bucket_seen: Dict[str, Set[str]] = field(default_factory=dict)

    def record_url(self, bucket: str, url: str, *, limit: int = 5000) -> None:
        """Append a unique URL into a named discovery list (capped)."""
        if not url:
            return
        attr = {
            "historical": "historical_seed_urls",
            "subdomain": "subdomain_urls",
            "js": "js_route_urls",
            "openapi_doc": "openapi_doc_urls",
            "openapi_endpoint": "openapi_endpoints",
            "api_endpoint": "api_endpoint_urls",
            "rss": "rss_feed_urls",
            "s3": "s3_buckets",
            "gcs": "gcs_buckets",
            "vhost": "vhost_hits",
            "login": "login_surfaces",
            "websocket": "websocket_urls",
            "sourcemap": "sourcemap_urls",
            "email": "emails",
            "phone": "phones",
            "internal_host": "internal_hosts",
            "cloud": "cloud_service_urls",
            "sitemap_doc": "sitemap_doc_urls",
            "sitemap": "sitemap_page_urls",
            "tls_san": "tls_sans",
            "comment": "interesting_comments",
            "dom_sink": "dom_sinks",
        }.get(bucket)
        if not attr:
            return
        seen = self._url_bucket_seen.setdefault(bucket, set())
        if url in seen:
            return
        target: List[str] = getattr(self, attr)
        if len(target) >= limit:
            return
        seen.add(url)
        target.append(url)

    def record_status(self, status_code: int, enum: bool = False):
        if enum:
            self.enum_status_codes[status_code] += 1
        else:
            self.status_codes[status_code] += 1

    def record_finding(
        self,
        category: str,
        severity: str,
        url: str,
        detail: str,
        *,
        evidence: Optional[str] = None,
        impact: Optional[str] = None,
        role: Optional[str] = None,
        validation: Optional[str] = None,
        impact_summary: Optional[str] = None,
    ):
        # Collapse noisy repeats (same header gap on every page of a host)
        host = ""
        try:
            from urllib.parse import urlparse

            host = urlparse(url).netloc.lower()
        except Exception:
            host = url
        detail_key = (detail or "").strip().lower()
        evidence_key = (evidence or "").strip().lower()
        # Host-level dedupe ONLY for header_audit (same missing header site-wide)
        if category == "header_audit":
            dedupe_key = f"{category}|{detail_key}|{host}"
        elif evidence_key:
            dedupe_key = f"{category}|{detail_key}|{url}|{evidence_key}"
        else:
            dedupe_key = f"{category}|{detail_key}|{url}"
        if dedupe_key in self._finding_dedupe:
            self.finding_repeat_suppressed += 1
            return
        self._finding_dedupe.add(dedupe_key)
        row = {
            "category": category,
            "severity": severity,
            "url": url,
            "detail": detail,
            "time": time.time(),
        }
        if evidence:
            row["evidence"] = evidence
        if impact:
            row["impact"] = impact
        if role:
            row["role"] = role
        if validation:
            row["validation"] = validation
        if impact_summary:
            row["impact_summary"] = impact_summary
        self.findings.append(row)

    def is_duplicate_content(self, body: bytes) -> bool:
        if not body:
            return False
        digest = hashlib.sha256(body).hexdigest()
        if digest in self.content_hashes:
            self.skipped_duplicate += 1
            return True
        self.content_hashes.add(digest)
        return False

    def mark_finished(self) -> float:
        """Freeze elapsed time; returns total seconds."""
        if self.finished_at is None:
            self.finished_at = time.time()
        return max(self.finished_at - self.started_at, 0.0)

    def elapsed_seconds(self) -> float:
        end = self.finished_at if self.finished_at is not None else time.time()
        return max(end - self.started_at, 0.0)

    def note_enum_progress(
        self,
        words_done: int,
        *,
        word: str = "",
        path: str = "/",
        depth: int = 0,
    ) -> None:
        """Update enum counters, current probe, and rate samples for ETA."""
        now = time.time()
        if self.enum_started_at is None:
            self.enum_started_at = now
        self.enum_words_tested = max(0, int(words_done))
        if word:
            self.enum_current_word = str(word)
            self.enum_current_path = path or "/"
            self.enum_current_depth = int(depth)
        self._enum_rate_samples.append((now, self.enum_words_tested))
        cutoff = now - 30.0
        self._enum_rate_samples = [(t, n) for t, n in self._enum_rate_samples if t >= cutoff][-40:]

    def enum_elapsed_seconds(self) -> float:
        if self.enum_started_at is None:
            return 0.0
        return max(time.time() - self.enum_started_at, 0.0)

    def enum_eta_seconds(self) -> Optional[int]:
        """Blend phase-clock + recent-window rate; hide until warm-up."""
        total = int(self.enum_words_total or 0)
        done = int(self.enum_words_tested or 0)
        if total <= 0 or done <= 0 or done >= total or self.enum_started_at is None:
            return None
        enum_elapsed = self.enum_elapsed_seconds()
        # Warm-up: avoid absurd early ETAs (e.g. crawl time leaking into rate)
        if done < 200 and enum_elapsed < 10.0:
            return None
        phase_rate = done / max(enum_elapsed, 0.001)
        recent_rate = 0.0
        samples = self._enum_rate_samples
        if len(samples) >= 2:
            t0, n0 = samples[0]
            t1, n1 = samples[-1]
            if t1 > t0 and n1 > n0:
                recent_rate = (n1 - n0) / (t1 - t0)
        if recent_rate > 0:
            rate = 0.55 * recent_rate + 0.45 * phase_rate
        else:
            rate = phase_rate
        if rate <= 0:
            return None
        return max(0, int((total - done) / rate))

    def enum_probing_label(self) -> str:
        word = (self.enum_current_word or "").strip()
        if not word:
            return ""
        path = self.enum_current_path or "/"
        if path == "/":
            probe = f"/{word.lstrip('/')}"
        else:
            probe = f"{path.rstrip('/')}/{word.lstrip('/')}"
        return f"Trying: {probe} · level {int(self.enum_current_depth)}"

    def note_api_recon_progress(
        self,
        probes_done: int,
        *,
        total: int = 0,
        path: str = "",
        hits: Optional[int] = None,
    ) -> None:
        """Update API active-enum counters and current probe for the live cockpit."""
        now = time.time()
        if self.api_recon_started_at is None:
            self.api_recon_started_at = now
        if total > 0:
            self.api_recon_probes_total = max(self.api_recon_probes_total, int(total))
        self.api_recon_probes_done = max(0, int(probes_done))
        if path:
            self.api_recon_current_path = str(path)
        if hits is not None:
            self.api_recon_hits = max(0, int(hits))
        self._api_recon_rate_samples.append((now, self.api_recon_probes_done))
        cutoff = now - 30.0
        self._api_recon_rate_samples = [
            (t, n) for t, n in self._api_recon_rate_samples if t >= cutoff
        ][-40:]

    def api_recon_elapsed_seconds(self) -> float:
        if self.api_recon_started_at is None:
            return 0.0
        return max(time.time() - self.api_recon_started_at, 0.0)

    def api_recon_eta_seconds(self) -> Optional[int]:
        """ETA for active API probes; hide until a short warm-up."""
        total = int(self.api_recon_probes_total or 0)
        done = int(self.api_recon_probes_done or 0)
        if total <= 0 or done <= 0 or done >= total or self.api_recon_started_at is None:
            return None
        elapsed = self.api_recon_elapsed_seconds()
        if done < 25 and elapsed < 8.0:
            return None
        phase_rate = done / max(elapsed, 0.001)
        recent_rate = 0.0
        samples = self._api_recon_rate_samples
        if len(samples) >= 2:
            t0, n0 = samples[0]
            t1, n1 = samples[-1]
            if t1 > t0 and n1 > n0:
                recent_rate = (n1 - n0) / (t1 - t0)
        rate = (0.55 * recent_rate + 0.45 * phase_rate) if recent_rate > 0 else phase_rate
        if rate <= 0:
            return None
        return max(0, int((total - done) / rate))

    def api_recon_probing_label(self) -> str:
        path = (self.api_recon_current_path or "").strip()
        if not path:
            return ""
        done = int(self.api_recon_probes_done or 0)
        total = int(self.api_recon_probes_total or 0)
        if total > 0:
            return f"API probe: {path} · {done:,}/{total:,}"
        return f"API probe: {path}"

    def note_subdomain_progress(
        self,
        probes_done: int,
        *,
        total: int = 0,
        host: str = "",
        hits: Optional[int] = None,
    ) -> None:
        if total > 0:
            self.subdomain_probes_total = max(self.subdomain_probes_total, int(total))
        self.subdomain_probes_done = max(0, int(probes_done))
        if host:
            self.subdomain_current_host = str(host)
        if hits is not None:
            self.subdomain_hits = max(0, int(hits))

    def subdomain_probing_label(self) -> str:
        host = (self.subdomain_current_host or "").strip()
        done = int(self.subdomain_probes_done or 0)
        total = int(self.subdomain_probes_total or 0)
        if not host and total <= 0:
            return ""
        if host and total > 0:
            return f"Subdomain: {host} · {done:,}/{total:,}"
        if host:
            return f"Subdomain: {host}"
        return f"Subdomain enum {done:,}/{total:,}"

    def snapshot(self) -> Dict[str, Any]:
        elapsed = max(self.elapsed_seconds(), 0.001)
        evasion = self.evasion_session
        backoff_rem = 0.0
        heartbeat = ""
        if evasion is not None:
            try:
                backoff_rem = float(evasion.backoff_remaining())
                heartbeat = str(evasion.heartbeat_label() or "")
            except Exception:
                backoff_rem = 0.0
                heartbeat = ""
        return {
            "elapsed_seconds": round(elapsed, 1),
            "pages_crawled": self.pages_crawled,
            "links_found": self.links_found,
            "enum_hits": self.enum_hits,
            "enum_words_tested": self.enum_words_tested,
            "enum_words_total": self.enum_words_total,
            "enum_started_at": self.enum_started_at,
            "enum_elapsed_seconds": round(self.enum_elapsed_seconds(), 1),
            "enum_eta_seconds": self.enum_eta_seconds(),
            "enum_current_word": self.enum_current_word,
            "enum_current_path": self.enum_current_path,
            "enum_current_depth": self.enum_current_depth,
            "enum_probing": self.enum_probing_label(),
            "enum_hit_urls": list(self.enum_hit_urls),
            "api_recon_probes_done": self.api_recon_probes_done,
            "api_recon_probes_total": self.api_recon_probes_total,
            "api_recon_hits": self.api_recon_hits,
            "api_recon_current_path": self.api_recon_current_path,
            "api_recon_eta_seconds": self.api_recon_eta_seconds(),
            "api_recon_probing": self.api_recon_probing_label(),
            "subdomain_probes_done": self.subdomain_probes_done,
            "subdomain_probes_total": self.subdomain_probes_total,
            "subdomain_hits": self.subdomain_hits,
            "subdomain_current_host": self.subdomain_current_host,
            "subdomain_probing": self.subdomain_probing_label(),
            "bytes_downloaded": self.bytes_downloaded,
            "errors": self.errors,
            "queue_size": self.queue_size,
            "urls_per_minute": round(self.pages_crawled / elapsed * 60, 1),
            "status_codes": dict(self.status_codes),
            "enum_status_codes": dict(self.enum_status_codes),
            "findings_count": len(self.findings),
            "broken_links_count": len(self.broken_links),
            "technologies": dict(self.technologies.most_common(20)),
            "paused": self.paused,
            "backoff_remaining_seconds": round(backoff_rem, 1),
            "heartbeat": heartbeat,
            "defense": self.defense_tracker.to_dict() if self.defense_tracker else None,
            "discovered_url_count": len(self.discovered_urls),
            "historical_seed_count": len(self.historical_seed_urls),
            "subdomain_count": len(self.subdomain_urls),
            "js_route_count": len(self.js_route_urls),
            "openapi_doc_count": len(self.openapi_doc_urls),
            "openapi_endpoint_count": len(self.openapi_endpoints),
            "rss_feed_count": len(self.rss_feed_urls),
            "form_count": len(self.forms),
            "parameter_count": len(self.parameters),
            "sensitive_count": len(self.sensitive_urls),
            "s3_count": len(self.s3_buckets),
            "gcs_count": len(self.gcs_buckets),
            "vhost_count": len(self.vhost_hits),
            "login_count": len(self.login_surfaces),
            "websocket_count": len(self.websocket_urls),
            "sourcemap_count": len(self.sourcemap_urls),
            "cookie_count": len(self.cookie_inventory),
            "email_count": len(self.emails),
            "internal_host_count": len(self.internal_hosts),
            "third_party_count": len(self.third_party_scripts),
            "cloud_url_count": len(self.cloud_service_urls),
            "sitemap_url_count": len(self.sitemap_page_urls),
            "tls_san_count": len(self.tls_sans),
            "well_known_count": len(self.well_known_hits),
            "file_metadata_count": len(self.file_metadata),
        }

    def record_file_metadata(self, record: Dict[str, Any], *, limit: int = 500) -> bool:
        """Store unique file metadata by URL; returns True if newly recorded."""
        if not record:
            return False
        url = record.get("url") or ""
        if not url or url in self._file_meta_seen:
            return False
        if len(self.file_metadata) >= limit:
            return False
        self._file_meta_seen.add(url)
        # Keep a compact row for reports
        self.file_metadata.append(
            {
                "url": url,
                "kind": record.get("kind", ""),
                "engine": record.get("engine", ""),
                "size": record.get("size", 0),
                "interesting": dict(record.get("interesting") or {}),
                "fields": dict(record.get("fields") or {}),
            }
        )
        return True

    def record_cookie_inventory(self, cookies: List[Dict[str, str]], *, limit: int = 200) -> None:
        if not cookies:
            return
        seen = {(c.get("name", ""), c.get("flags", "")) for c in self.cookie_inventory}
        for cookie in cookies:
            key = (cookie.get("name", ""), cookie.get("flags", ""))
            if not key[0] or key in seen:
                continue
            if len(self.cookie_inventory) >= limit:
                break
            seen.add(key)
            self.cookie_inventory.append(cookie)

    def record_dict_rows(self, attr: str, rows: List[Dict[str, str]], key_fields: tuple, *, limit: int = 300) -> None:
        target: List[Dict[str, str]] = getattr(self, attr)
        seen = self._url_bucket_seen.setdefault(attr, set())
        for row in rows or []:
            key = "|".join(str(row.get(f, "")) for f in key_fields)
            if not key or key in seen:
                continue
            if len(target) >= limit:
                break
            seen.add(key)
            target.append(row)

    def record_security_headers(self, host: str, headers: Dict[str, str]) -> None:
        if not host or not headers:
            return
        host_l = host.lower()
        bucket = self.security_headers_by_host.setdefault(host_l, {})
        for key, value in headers.items():
            if key not in bucket and value:
                bucket[key] = value

    def format_friendly_line(self) -> str:
        from user_output import format_friendly_stats

        return format_friendly_stats(self)

    def format_live_line(self) -> str:
        snap = self.snapshot()
        enum_part = f"enum={snap['enum_hits']}"
        if snap.get("enum_words_total"):
            enum_part = (
                f"enum={snap['enum_hits']} tested={snap['enum_words_tested']:,}/"
                f"{snap['enum_words_total']:,}"
            )
        return (
            f"[Stats] crawled={snap['pages_crawled']} found={snap['links_found']} "
            f"{enum_part} queue={snap['queue_size']} "
            f"{snap['urls_per_minute']}/min errors={snap['errors']} "
            f"findings={snap['findings_count']}"
        )

    def to_json(self) -> str:
        return json.dumps(self.snapshot(), indent=2)
