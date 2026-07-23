"""Live crawl statistics and findings collection."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

_COOKIE_FINDING_NAME_RE = re.compile(r"(?i)cookie\s+`([^`]+)`")


@dataclass
class CrawlStats:
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    pages_crawled: int = 0
    links_found: int = 0
    # Mapper-quality counters (invariants: raw >= unique >= queued-ish)
    duplicates_skipped: int = 0
    out_of_scope_skipped: int = 0
    non_http_skipped: int = 0
    query_variants_skipped: int = 0
    route_variants_skipped: int = 0
    static_assets_recorded: int = 0
    soft_404s_filtered: int = 0
    forms_deduped: int = 0
    requests_queued: int = 0
    static_asset_urls: List[str] = field(default_factory=list)
    _form_keys_seen: Set[str] = field(default_factory=set)
    enum_hits: int = 0
    enum_words_tested: int = 0
    enum_words_total: int = 0
    # Separated enum accounting (base words ≠ generated candidates ≠ HTTP attempts)
    enum_base_words_loaded: int = 0
    enum_base_words_processed: int = 0
    enum_mutation_candidates: int = 0
    enum_extension_candidates: int = 0
    enum_unique_candidate_urls: int = 0
    enum_http_attempts: int = 0
    enum_rate_limited: int = 0
    enum_rejected_wildcard: int = 0
    enum_inconclusive: int = 0
    enum_requested_depth: int = 0
    enum_effective_depth: int = 0
    enum_depth_reason: str = ""
    enum_wildcard_calibration_ok: bool = True
    enum_wildcard_active: bool = False
    enum_validation_conclusion: str = ""
    enum_hit_records: List[Dict[str, Any]] = field(default_factory=list)
    enum_skipped_records: List[Dict[str, Any]] = field(default_factory=list)
    enum_attempt_fingerprints: List[Dict[str, Any]] = field(default_factory=list)
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
    # Append-only request ledger (capped) for auditable aggregates
    request_ledger: List[Dict[str, Any]] = field(default_factory=list)
    _request_ledger_cap: int = 8000
    sensitive_urls: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    content_hashes: Set[str] = field(default_factory=set)
    # norm_hash → first crawl URL (seeds enum content-equivalent rejection)
    page_content_by_hash: Dict[str, str] = field(default_factory=dict)
    # url → provenance kind (seed|crawl|enum|…) for report URL table
    url_kinds: Dict[str, str] = field(default_factory=dict)
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
    route_templates: List[str] = field(default_factory=list)
    protection_artifacts: List[str] = field(default_factory=list)
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

    def note_url_kind(self, url: str, kind: str) -> None:
        """Record first-seen provenance for a URL (seed/crawl/enum/…)."""
        if not url or not kind:
            return
        self.url_kinds.setdefault(url, str(kind))

    def note_page_content(self, url: str, normalized_hash: str) -> None:
        """Seed content-equivalence map from a crawled page body."""
        key = (normalized_hash or "").strip()
        if not key or key in ("empty", "head-only") or not url:
            return
        self.page_content_by_hash.setdefault(key, url)

    def record_status(self, status_code: int, enum: bool = False):
        if enum:
            self.enum_status_codes[status_code] += 1
        else:
            self.status_codes[status_code] += 1

    def record_request(
        self,
        *,
        phase: str = "crawl",
        source: str = "",
        url: str = "",
        depth: int = 0,
        status: Any = None,
        final_url: str = "",
        response_type: str = "",
        bytes_: int = 0,
        content_hash: str = "",
        duration_ms: float = 0.0,
        outcome: str = "",
        redirect_chain: Optional[List[str]] = None,
        title: str = "",
        raw_hash: str = "",
        normalized_hash: str = "",
        similarity: float = 0.0,
        path_shape: str = "",
        classification: str = "",
    ) -> None:
        """Append-only request ledger row (fetch-queue inventory stays separate)."""
        if len(self.request_ledger) >= int(getattr(self, "_request_ledger_cap", 8000) or 8000):
            return
        row = {
            "phase": phase,
            "source": source,
            "url": url,
            "canonical_url": url,
            "depth": int(depth or 0),
            "status": status,
            "final_url": final_url or url,
            "response_type": response_type,
            "bytes": int(bytes_ or 0),
            "hash": content_hash,
            "duration_ms": float(duration_ms or 0.0),
            "outcome": outcome,
            "ts": time.time(),
        }
        if redirect_chain is not None:
            row["redirect_chain"] = list(redirect_chain)[:12]
        if title:
            row["title"] = str(title)[:200]
        if raw_hash:
            row["raw_hash"] = raw_hash
        if normalized_hash:
            row["normalized_hash"] = normalized_hash
        if similarity:
            row["similarity"] = float(similarity)
        if path_shape:
            row["path_shape"] = path_shape
        if classification:
            row["classification"] = classification
        self.request_ledger.append(row)

    def record_enum_attempt(self, fingerprint: Dict[str, Any], *, limit: int = 5000) -> None:
        """Persist a capped fingerprint for every enum HTTP attempt (hits and misses)."""
        if not hasattr(self, "enum_attempt_fingerprints") or self.enum_attempt_fingerprints is None:
            self.enum_attempt_fingerprints = []
        bucket: List[Dict[str, Any]] = self.enum_attempt_fingerprints
        if len(bucket) >= limit:
            return
        bucket.append(dict(fingerprint or {}))

    @staticmethod
    def summarize_broken_links(rows: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Unique broken-link tallies — never inflate by repeated rows."""
        rows = list(rows or [])
        by_url: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            url = str(row.get("url") or "").strip()
            if not url:
                continue
            by_url[url] = row
        unique = list(by_url.values())
        class_counts: Counter = Counter()
        status_counts: Counter = Counter()
        for row in unique:
            status = str(row.get("status") or "error")
            status_counts[status] += 1
            class_ = str(row.get("class") or "")
            if not class_:
                if status == "404":
                    class_ = "not_found"
                elif status in ("401", "403", "405"):
                    class_ = "access_denied"
                elif status.startswith("5"):
                    class_ = "temporary_unavailable"
                elif status == "error":
                    class_ = "fetch_error"
                else:
                    class_ = "other"
            class_counts[class_] += 1
        return {
            "rows_total": len(rows),
            "unique_urls": len(unique),
            "by_class": dict(class_counts),
            "by_status": dict(status_counts),
            "unique_404": int(class_counts.get("not_found", 0)),
            "unique_access_denied": int(class_counts.get("access_denied", 0)),
            "unique_5xx": int(class_counts.get("temporary_unavailable", 0)),
            "unique_fetch_errors": int(
                class_counts.get("fetch_error", 0)
                + class_counts.get("dns_failure", 0)
                + class_counts.get("connection_failure", 0)
            ),
        }

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
        verification: Optional[str] = None,
        proof: Optional[dict] = None,
        confidence: Optional[str] = None,
        confidence_reason: Optional[str] = None,
    ):
        # Collapse noisy repeats (same header gap on every page of a host)
        host = ""
        try:
            from urllib.parse import urlparse

            host = urlparse(url).netloc.lower()
        except Exception:
            host = url
        if host.startswith("www."):
            host = host[4:]
        detail_key = (detail or "").strip().lower()
        evidence_key = (evidence or "").strip().lower()
        sev_l = (severity or "").strip().lower()
        impact_l = (impact or "").strip().lower()
        # Evidence label prefix: "js_env_leak: `…`" → "js_env_leak"
        evidence_label = evidence_key.split(":", 1)[0].strip() if evidence_key else ""
        cookie_name_match = _COOKIE_FINDING_NAME_RE.search(detail or "")
        cookie_name = (cookie_name_match.group(1) or "").strip().lower() if cookie_name_match else ""
        # Host-level dedupe for site-wide / inventory noise
        if category == "header_audit":
            dedupe_key = f"{category}|{detail_key}|{host}"
        elif category == "cors":
            # Credentialed CORS is origin-wide — one finding per host
            dedupe_key = f"cors|{host}"
        elif category == "secrets_exposure" and evidence_key:
            # Same secret value = one finding even when product labels differ (Ript vs Text)
            dedupe_key = f"{category}|{host}|{evidence_key}"
        elif category == "authentication" and cookie_name:
            # Same Set-Cookie on every HTML page → one finding per host+cookie name
            dedupe_key = f"authentication|cookie|{host}|{cookie_name}"
        elif category == "authentication" and evidence_label in (
            "auth_otp_surface",
            "auth_email_change",
            "auth_token_reuse",
            "otp/mfa",
            "change-email",
        ):
            # Shared JS bundle auth surface refs → one finding per host+signal
            dedupe_key = f"authentication|surface|{host}|{evidence_label or detail_key[:80]}"
        elif category == "authentication" and evidence_key and (
            "otp" in evidence_key or "change-email" in evidence_key or "mfa" in evidence_key
        ):
            dedupe_key = f"authentication|surface|{host}|{evidence_key[:80]}"
        elif (
            category == "authentication"
            and evidence_key
            and impact_l in ("possible_credential", "stealable_credential", "mitigated_credential")
        ):
            # Fallback when detail lacks Cookie `name` — same token value per host
            dedupe_key = f"authentication|cred|{host}|{evidence_key}"
        elif category == "cloud" and (
            "cloudfront" in detail_key or evidence_label == "cloudfront"
        ):
            # CDN references group by provider + evidence, not per page
            dedupe_key = f"cloud|cloudfront|{host}|{evidence_key[:120] or detail_key[:80]}"
        elif category == "file_upload":
            # Dedupe uploads by endpoint template (path without query)
            try:
                from urllib.parse import urlparse as _up

                upath = (_up(url).path or "/").rstrip("/") or "/"
            except Exception:
                upath = url
            dedupe_key = f"file_upload|{host}|{upath}"
        elif category in ("xss", "csrf") and evidence_key:
            # Same XSS sink / CSRF evidence across pages → one finding per host
            dedupe_key = f"{category}|{host}|{evidence_key}"
        elif category in ("js_intel", "business_logic", "bot_management") or (
            category == "mass_assignment" and sev_l == "info"
        ):
            # Same intel signal across every JS bundle / page → one per host+label
            dedupe_key = f"{category}|{host}|{evidence_label or detail_key[:120]}"
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
        if verification:
            row["verification"] = verification
        elif validation in ("confirmed", "active", "unverified", "invalid", "skipped"):
            # Map legacy validation → verification ladder where possible
            row["verification"] = {
                "confirmed": "confirmed",
                "active": "exploitable",
                "unverified": "detected",
                "invalid": "detected",
                "skipped": "detected",
            }.get(str(validation), "detected")
        if proof and isinstance(proof, dict):
            row["proof"] = proof
        if confidence:
            row["confidence"] = confidence
        if confidence_reason:
            row["confidence_reason"] = confidence_reason
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

    def enum_words_per_minute(self) -> float:
        samples = self._enum_rate_samples
        if len(samples) < 2:
            elapsed = self.enum_elapsed_seconds()
            done = int(self.enum_words_tested or 0)
            if elapsed <= 0 or done <= 0:
                return 0.0
            return done / elapsed * 60.0
        t0, n0 = samples[0]
        t1, n1 = samples[-1]
        if t1 <= t0 or n1 <= n0:
            return 0.0
        return (n1 - n0) / (t1 - t0) * 60.0

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
        snap = {
            "elapsed_seconds": round(elapsed, 1),
            "pages_crawled": self.pages_crawled,
            "links_found": self.links_found,
            "duplicates_skipped": self.duplicates_skipped,
            "out_of_scope_skipped": self.out_of_scope_skipped,
            "non_http_skipped": self.non_http_skipped,
            "query_variants_skipped": self.query_variants_skipped,
            "route_variants_skipped": self.route_variants_skipped,
            "static_assets_recorded": self.static_assets_recorded,
            "soft_404s_filtered": self.soft_404s_filtered,
            "forms_deduped": self.forms_deduped,
            "requests_queued": self.requests_queued,
            "enum_hits": self.enum_hits,
            "enum_words_tested": self.enum_words_tested,
            "enum_words_total": self.enum_words_total,
            "enum_base_words_loaded": int(getattr(self, "enum_base_words_loaded", 0) or 0),
            "enum_base_words_processed": int(getattr(self, "enum_base_words_processed", 0) or 0),
            "enum_mutation_candidates": int(getattr(self, "enum_mutation_candidates", 0) or 0),
            "enum_extension_candidates": int(getattr(self, "enum_extension_candidates", 0) or 0),
            "enum_unique_candidate_urls": int(getattr(self, "enum_unique_candidate_urls", 0) or 0),
            "enum_http_attempts": int(getattr(self, "enum_http_attempts", 0) or 0),
            "enum_rate_limited": int(getattr(self, "enum_rate_limited", 0) or 0),
            "enum_rejected_wildcard": int(getattr(self, "enum_rejected_wildcard", 0) or 0),
            "enum_inconclusive": int(getattr(self, "enum_inconclusive", 0) or 0),
            "enum_requested_depth": int(getattr(self, "enum_requested_depth", 0) or 0),
            "enum_effective_depth": int(getattr(self, "enum_effective_depth", 0) or 0),
            "enum_depth_reason": str(getattr(self, "enum_depth_reason", "") or ""),
            "enum_wildcard_calibration_ok": bool(getattr(self, "enum_wildcard_calibration_ok", True)),
            "enum_wildcard_active": bool(getattr(self, "enum_wildcard_active", False)),
            "enum_validation_conclusion": str(getattr(self, "enum_validation_conclusion", "") or ""),
            "enum_attempt_fingerprint_count": len(getattr(self, "enum_attempt_fingerprints", []) or []),
            "enum_started_at": self.enum_started_at,
            "enum_elapsed_seconds": round(self.enum_elapsed_seconds(), 1),
            "enum_eta_seconds": self.enum_eta_seconds(),
            "enum_words_per_minute": round(self.enum_words_per_minute(), 1),
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
            "broken_links_summary": self.summarize_broken_links(self.broken_links),
            "request_ledger_count": len(self.request_ledger),
            "request_ledger_cap": int(getattr(self, "_request_ledger_cap", 8000) or 8000),
            "technologies": dict(self.technologies.most_common(20)),
            "paused": self.paused,
            "backoff_remaining_seconds": round(backoff_rem, 1),
            "heartbeat": heartbeat,
            "defense": self.defense_tracker.to_dict() if self.defense_tracker else None,
            "discovered_url_count": len(self.discovered_urls),
            "historical_seed_count": len(self.historical_seed_urls),
            "subdomain_count": len(self.subdomain_urls),
            "js_route_count": len(self.js_route_urls),
            "route_template_count": len(self.route_templates),
            "protection_artifact_count": len(self.protection_artifacts),
            "openapi_doc_count": len(self.openapi_doc_urls),
            "discovered_url_export_cap": 5000,
            "discovered_urls_exported": min(len(self.discovered_urls), 5000),
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
        try:
            from report_status import scan_status_from_stats

            snap.update(scan_status_from_stats(self))
        except Exception:
            pass
        return snap

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
        """Deduplicate cookies by name+domain+path; track rotations and attribute variations."""
        if not cookies:
            return
        index: Dict[tuple, Dict[str, Any]] = {}
        for existing in self.cookie_inventory:
            key = (
                str(existing.get("name") or ""),
                str(existing.get("domain") or ""),
                str(existing.get("path") or ""),
            )
            if key[0]:
                index[key] = existing
        now = time.time()
        for cookie in cookies:
            name = str(cookie.get("name") or "")
            if not name:
                continue
            key = (
                name,
                str(cookie.get("domain") or ""),
                str(cookie.get("path") or ""),
            )
            if key in index:
                row = index[key]
                row["observed_rotations"] = int(row.get("observed_rotations") or 1) + 1
                row["last_seen"] = now
                # Track attribute variations
                flags = str(cookie.get("flags") or "")
                variations = row.setdefault("attribute_variations", [])
                if flags and flags not in variations and len(variations) < 8:
                    variations.append(flags)
                # Prefer richer role classification when available
                if cookie.get("role") and not row.get("role"):
                    row["role"] = cookie.get("role")
                continue
            if len(self.cookie_inventory) >= limit:
                break
            row = dict(cookie)
            row.setdefault("observed_rotations", 1)
            row.setdefault("first_seen", now)
            row["last_seen"] = now
            row.setdefault("attribute_variations", [str(cookie.get("flags") or "")] if cookie.get("flags") else [])
            index[key] = row
            self.cookie_inventory.append(row)

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
