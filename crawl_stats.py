"""Live crawl statistics and findings collection."""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Set


@dataclass
class CrawlStats:
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    pages_crawled: int = 0
    links_found: int = 0
    enum_hits: int = 0
    enum_words_tested: int = 0
    enum_words_total: int = 0
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

    def snapshot(self) -> Dict[str, Any]:
        elapsed = max(self.elapsed_seconds(), 0.001)
        return {
            "elapsed_seconds": round(elapsed, 1),
            "pages_crawled": self.pages_crawled,
            "links_found": self.links_found,
            "enum_hits": self.enum_hits,
            "enum_words_tested": self.enum_words_tested,
            "enum_words_total": self.enum_words_total,
            "enum_hit_urls": list(self.enum_hit_urls),
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
