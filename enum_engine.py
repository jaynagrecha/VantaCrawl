"""Gobuster-beater directory enumeration engine (Tiers 1–3)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

from async_runtime import is_running
from checkpoint import load_enum_checkpoint, save_enum_checkpoint
from crawl_config import CrawlConfig
from crawl_stats import CrawlStats
from crawler_common import (
    BYPASS_HTTP_CODES,
    build_enum_url,
    format_enum_path,
    load_wordlist,
    log_enum_batch_progress,
    log_to_file,
    response_length,
    enqueue_discovered_url,
    looks_like_file_path_segment,
    save_enum_hit_async,
)
from enum_validation import (
    ALL_SHAPES,
    CLASS_INCONCLUSIVE_429,
    CLASS_WILDCARD,
    HitProvenanceTracker,
    ResponseFingerprint,
    ShapeBaseline,
    WildcardProfile,
    classify_path_shape,
    control_paths_for_base,
    enum_validation_conclusion,
    fingerprint_from_response,
    matches_any_shape_baseline,
    normalize_body_for_hash,
    raw_body_hash,
)

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
from false_positive_store import FalsePositiveStore

DEFAULT_ENUM_EXTENSIONS = ("php", "asp", "aspx", "bak", "old", "txt", "zip", "sql", "config", "env")
TECH_WORDLIST_HINTS = {
    "WordPress": "wordpress",
    "Drupal": "drupal",
    "Joomla": "joomla",
    "ASP.NET": "iis",
    "PHP": "php",
}


@dataclass
class ProbeResult:
    url: str
    word: str
    status: int
    content_length: int
    body_hash: str
    path_segments: List[str]
    final_url: str = ""
    redirect_hops: int = 0
    # Optional body retained for hit follow-up (avoids a second GET that can stall enum)
    body: bytes = b""
    content_type: str = ""
    redirect_chain: List[str] = field(default_factory=list)
    title: str = ""
    raw_hash: str = ""
    normalized_hash: str = ""
    duration_ms: float = 0.0
    path_shape: str = ""
    fingerprint: Optional[ResponseFingerprint] = None
    classification: str = ""
    validated: bool = False
    already_known: bool = False
    acceptance_reason: str = ""
    baseline_used: str = ""
    wildcard_similarity: float = 0.0
    base_word: str = ""
    inconclusive: bool = False


class StatusCodeFilter:
    def __init__(self, whitelist: Optional[Set[int]], blacklist: Set[int]):
        self.whitelist = whitelist
        self.blacklist = blacklist

    def allows(self, status: int) -> bool:
        if status in self.blacklist:
            return False
        if self.whitelist is not None:
            return status in self.whitelist
        return status < 400 or status in BYPASS_HTTP_CODES


def parse_status_code_list(raw: str, default: Optional[Set[int]] = None) -> Optional[Set[int]]:
    if not raw or not str(raw).strip():
        return default
    out = set()
    for part in str(raw).replace(" ", "").split(","):
        if part.isdigit():
            out.add(int(part))
    return out or default


def parse_int_list(raw: str) -> Set[int]:
    if not raw or not str(raw).strip():
        return set()
    out = set()
    for part in str(raw).replace(" ", "").split(","):
        if part.isdigit():
            out.add(int(part))
    return out


def body_fingerprint(body: bytes, max_bytes: int = 512) -> str:
    if not body:
        return "empty"
    return hashlib.sha256(body[:max_bytes]).hexdigest()[:16]


def build_status_filter(config: CrawlConfig) -> StatusCodeFilter:
    # Redirects are resolved before scoring — whitelist applies to the *final* status.
    default_whitelist = {200, 204, 401, 403}
    whitelist = parse_status_code_list(config.enum_status_whitelist, default_whitelist)
    blacklist = parse_status_code_list(config.enum_status_blacklist, {404}) or {404}
    return StatusCodeFilter(whitelist, blacklist)


def hosts_compatible(url_a: str, url_b: str) -> bool:
    """Same host for redirect following (scheme may change; www ↔ apex allowed)."""
    ha = (urlparse(url_a).netloc or "").lower().split(":")[0]
    hb = (urlparse(url_b).netloc or "").lower().split(":")[0]
    if not ha or not hb:
        return False
    if ha == hb:
        return True
    if ha.startswith("www.") and ha[4:] == hb:
        return True
    if hb.startswith("www.") and hb[4:] == ha:
        return True
    return False


async def follow_same_host_redirects(
    client: httpx.AsyncClient,
    start_url: str,
    *,
    max_hops: int = 5,
    timeout: float = 8,
) -> Tuple[int, int, str, bytes, str, int, List[str], str]:
    """
    Follow Location hops on the same host. Returns
    (status, length, body_hash, body, final_url, hops_taken, redirect_chain, content_type).
    """
    current = start_url
    seen: Set[str] = set()
    body = b""
    status = 0
    hops = 0
    chain: List[str] = [start_url]
    content_type = ""
    max_hops = max(0, int(max_hops) or 0)
    for _ in range(max_hops + 1):
        if current in seen:
            break
        seen.add(current)
        try:
            response = await client.get(current, timeout=timeout, follow_redirects=False)
        except httpx.HTTPError:
            return 0, 0, "", b"", current, hops, chain, content_type
        status = response.status_code
        body = response.content or b""
        content_type = (response.headers.get("content-type") or "")[:120]
        length = len(body) or response_length(response)
        digest = body_fingerprint(body)
        if status not in REDIRECT_STATUSES:
            return status, length, digest, body, current, hops, chain, content_type
        location = (response.headers.get("location") or "").strip()
        if not location:
            return status, length, digest, body, current, hops, chain, content_type
        nxt = urljoin(current, location)
        if not hosts_compatible(start_url, nxt):
            # Off-site redirect: keep redirect status (usually not a hit after whitelist change)
            return status, length, digest, body, current, hops, chain, content_type
        current = nxt
        chain.append(nxt)
        hops += 1
    length = len(body) or 0
    return status, length, body_fingerprint(body), body, current, hops, chain, content_type


def iter_gobuster_word_variants(word: str, config: CrawlConfig) -> List[str]:
    word = word.strip().strip("/")
    if not word or word.startswith("#"):
        return []
    if not config.gobuster_style_extensions or "." in word:
        return [word]
    suffixes = config.parsed_enum_extensions()
    variants = [word]
    for suffix in suffixes:
        ext = suffix if suffix.startswith(".") else f".{suffix}"
        variants.append(word + ext)
    return variants


def extract_path_words(urls: Iterable[str], limit: int = 500) -> List[str]:
    words = []
    seen = set()
    for url in urls:
        path = urlparse(url).path.strip("/")
        if not path:
            continue
        for segment in path.split("/"):
            segment = segment.strip()
            if not segment or segment in seen:
                continue
            seen.add(segment)
            words.append(segment)
            if len(words) >= limit:
                return words
    return words


def extract_auto_prefixes(urls: Iterable[str], limit: int = 20) -> List[str]:
    prefixes = []
    seen = set()
    for url in urls:
        path = urlparse(url).path.strip("/")
        if not path:
            continue
        first = path.split("/")[0]
        if first and first not in seen:
            seen.add(first)
            prefixes.append(first)
        if len(prefixes) >= limit:
            break
    return prefixes


def build_smart_wordlist(
    config: CrawlConfig,
    *,
    seed_urls: List[str],
    technologies: Optional[Dict[str, int]] = None,
    merge_fn,
) -> List[str]:
    from mutation_scan import build_mutation_wordlist

    ordered: List[str] = []
    seen = set()
    # Cap early — Full Audit defaults to 15k; never read multi‑MB wordlists end-to-end first
    hard_limit = int(getattr(config, "enum_word_limit", 0) or 0)
    seeds = list(seed_urls or [])[:800]

    def add_words(words: List[str], source: str = ""):
        for word in words:
            word = word.strip()
            if not word or word in seen:
                continue
            seen.add(word)
            ordered.append(word)
            if hard_limit and len(ordered) >= hard_limit:
                return True
        return False

    if config.smart_wordlist_order:
        if add_words(extract_path_words(seeds)):
            return ordered[:hard_limit]
        if technologies:
            wl_dir = os.path.dirname(os.path.abspath(config.wordlist_file))
            if not os.path.isdir(wl_dir):
                wl_dir = os.path.join(os.path.dirname(wl_dir), "Wordlist")
            for tech, _count in technologies.items():
                hint = TECH_WORDLIST_HINTS.get(tech)
                if not hint:
                    continue
                for name in (f"{hint}.txt", f"{hint}-top.txt", f"common-{hint}.txt"):
                    path = os.path.join(wl_dir, name)
                    if os.path.isfile(path):
                        if add_words(load_wordlist(path, max_words=2000)):
                            return ordered[:hard_limit]
                        break

    if config.mutation_enum:
        mut_cap = int(getattr(config, "mutation_max_candidates", 5000) or 5000)
        if hard_limit:
            mut_cap = min(mut_cap, max(0, hard_limit - len(ordered)))
        if mut_cap > 0 and add_words(
            build_mutation_wordlist(
                seeds,
                use_builtin=config.mutation_builtin,
                mutate_seeds=config.mutation_from_seeds,
                extensions=config.parsed_enum_extensions(),
                max_candidates=mut_cap,
            )
        ):
            return ordered[:hard_limit]

    if config.use_wordlist:
        remaining = (hard_limit - len(ordered)) if hard_limit else 0
        # Prefer capped merge so Free-tier CPUs do not parse an entire 14MB list
        try:
            base_words = merge_fn(
                config.wordlist_file,
                config.extra_wordlists,
                max_words=remaining or hard_limit or 0,
            )
        except TypeError:
            base_words = merge_fn(config.wordlist_file, config.extra_wordlists)
            if remaining:
                base_words = base_words[:remaining]
        if config.legacy_wordlist_expansion and config.extension_aware_wordlist:
            expanded = list(base_words)
            for word in base_words:
                if "." not in word:
                    for ext in DEFAULT_ENUM_EXTENSIONS:
                        expanded.append(word + f".{ext}" if not ext.startswith(".") else word + ext)
                if hard_limit and len(expanded) + len(ordered) >= hard_limit:
                    break
            base_words = expanded
        add_words(base_words)

    if hard_limit and len(ordered) > hard_limit:
        return ordered[:hard_limit]
    return ordered


def directory_base_url(start_url: str, path_segments: Optional[List[str]] = None) -> str:
    """URL under which per-directory soft-404 probes are issued."""
    parsed = urlparse(start_url)
    path = parsed.path or "/"
    leaf = path.rsplit("/", 1)[-1]
    if leaf and "." in leaf:
        path = path[: path.rfind("/") + 1] or "/"
    if not path.endswith("/"):
        path += "/"
    segs = [s.strip("/") for s in (path_segments or []) if s and str(s).strip("/")]
    if segs:
        path = path.rstrip("/") + "/" + "/".join(segs) + "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


class DirectoryWildcardCache:
    """Calibrate soft-404 / wildcard fingerprints per directory prefix."""

    def __init__(self):
        self._cache: Dict[str, WildcardProfile] = {}

    def _key(self, path_segments: Optional[List[str]]) -> str:
        segs = [s.strip("/") for s in (path_segments or []) if s and str(s).strip("/")]
        return "/" + "/".join(segs) if segs else "/"

    async def for_path(
        self,
        client: httpx.AsyncClient,
        start_url: str,
        path_segments: Optional[List[str]],
        *,
        enabled: bool,
        root_fallback: Optional[WildcardProfile] = None,
    ) -> WildcardProfile:
        if not enabled:
            return root_fallback or WildcardProfile()
        key = self._key(path_segments)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        base = directory_base_url(start_url, path_segments)
        profile = await detect_wildcard(client, base)
        self._cache[key] = profile
        return profile


async def detect_wildcard(
    client: httpx.AsyncClient,
    base_url: str,
    *,
    probes: int = 2,
) -> WildcardProfile:
    """Calibrate path-shape-specific wildcard controls.

    Required shapes:
      /random-<nonce>, /.<nonce>, /index.<nonce>, /<nonce>.php,
      /<nonce>.bak, /<nonce>/<nonce>, /RANDOMCASE-<nonce>
    """
    shapes: Dict[str, ShapeBaseline] = {}
    signatures: Set[Tuple[int, int, str]] = set()
    notes: List[str] = []
    any_active = False
    for _round in range(max(1, int(probes) or 1)):
        controls = control_paths_for_base(base_url)
        for shape, url in controls.items():
            try:
                response = await client.get(url, timeout=6, follow_redirects=False)
                body = response.content or b""
                status = int(response.status_code)
                length = len(body) or response_length(response)
                raw = raw_body_hash(body)
                short = body_fingerprint(body)
                norm = normalize_body_for_hash(body)
                ctype = (response.headers.get("content-type") or "")[:120]
                from enum_validation import extract_title

                title = extract_title(body)
                looks_wildcard = status not in (0, 404, 410) or (
                    status in (404, 410) and length > 512 and norm not in ("", "empty")
                )
                if status in (200, 301, 302, 303, 307, 308, 401, 403):
                    looks_wildcard = True
                existing = shapes.get(shape)
                if existing is None:
                    shapes[shape] = ShapeBaseline(
                        shape=shape,
                        active=looks_wildcard,
                        status=status,
                        length=length,
                        raw_hash=raw,
                        normalized_hash=norm,
                        content_type=ctype,
                        title=title,
                        samples=1,
                        control_url=url,
                    )
                else:
                    existing.samples += 1
                    existing.active = existing.active or looks_wildcard
                    if looks_wildcard and (existing.status in (404, 410) or not existing.raw_hash):
                        existing.status = status
                        existing.length = length
                        existing.raw_hash = raw
                        existing.normalized_hash = norm
                        existing.content_type = ctype
                        existing.title = title
                        existing.control_url = url
                if looks_wildcard:
                    any_active = True
                    signatures.add((status, length, short))
                    notes.append(f"{shape}: HTTP {status} len={length} control={url}")
            except httpx.HTTPError as exc:
                notes.append(f"{shape}: probe_error ({exc.__class__.__name__})")
                shapes.setdefault(
                    shape,
                    ShapeBaseline(shape=shape, active=False, samples=0, control_url=url),
                )

    calibration_ok = True
    for shape in ALL_SHAPES:
        base = shapes.get(shape)
        if base and base.active and base.status in (200, 201, 204) and not base.raw_hash:
            calibration_ok = False

    return WildcardProfile(
        active=any_active,
        signatures=signatures if any_active else set(),
        shapes=shapes,
        calibration_ok=calibration_ok and bool(shapes),
        calibration_notes=notes[:40],
    )


async def probe_candidate(
    client: httpx.AsyncClient,
    url: str,
    *,
    use_head: bool = True,
    bypass_forbidden: bool = True,
    follow_redirects: bool = True,
    max_redirect_hops: int = 5,
) -> Tuple[int, int, str, bytes, str, int, List[str], str, float, str]:
    """
    Probe a URL. Returns
    (status, length, body_hash, body, final_url, redirect_hops, redirect_chain, content_type, duration_ms, retry_after).
    """
    body = b""
    t0 = time.perf_counter()

    def _retry_after(resp) -> str:
        try:
            return str(resp.headers.get("Retry-After") or resp.headers.get("retry-after") or "").strip()
        except Exception:
            return ""

    try:
        if use_head:
            response = await client.head(url, timeout=6, follow_redirects=False)
            status = response.status_code
            if status in (405, 501) or (bypass_forbidden and status in BYPASS_HTTP_CODES) or status in (
                200,
                204,
                301,
                302,
                303,
                307,
                308,
                401,
                403,
                429,
            ):
                if follow_redirects and status in REDIRECT_STATUSES:
                    result = await follow_same_host_redirects(
                        client, url, max_hops=max_redirect_hops, timeout=8
                    )
                    return (*result, (time.perf_counter() - t0) * 1000.0, "")
                if status == 429:
                    # Honor HEAD 429 without forcing a GET
                    return (
                        status,
                        response_length(response),
                        "head-only",
                        b"",
                        url,
                        0,
                        [url],
                        (response.headers.get("content-type") or "")[:120],
                        (time.perf_counter() - t0) * 1000.0,
                        _retry_after(response),
                    )
                response = await client.get(url, timeout=8, follow_redirects=False)
                body = response.content or b""
                status = response.status_code
                ctype = (response.headers.get("content-type") or "")[:120]
                if follow_redirects and status in REDIRECT_STATUSES:
                    result = await follow_same_host_redirects(
                        client, url, max_hops=max_redirect_hops, timeout=8
                    )
                    return (*result, (time.perf_counter() - t0) * 1000.0, "")
                return (
                    status,
                    len(body) or response_length(response),
                    body_fingerprint(body),
                    body,
                    url,
                    0,
                    [url],
                    ctype,
                    (time.perf_counter() - t0) * 1000.0,
                    _retry_after(response),
                )
            return (
                status,
                response_length(response),
                "head-only",
                body,
                url,
                0,
                [url],
                (response.headers.get("content-type") or "")[:120],
                (time.perf_counter() - t0) * 1000.0,
                _retry_after(response),
            )
        if follow_redirects:
            first = await client.get(url, timeout=8, follow_redirects=False)
            if first.status_code in REDIRECT_STATUSES:
                result = await follow_same_host_redirects(
                    client, url, max_hops=max_redirect_hops, timeout=8
                )
                return (*result, (time.perf_counter() - t0) * 1000.0, "")
            body = first.content or b""
            return (
                first.status_code,
                len(body) or response_length(first),
                body_fingerprint(body),
                body,
                url,
                0,
                [url],
                (first.headers.get("content-type") or "")[:120],
                (time.perf_counter() - t0) * 1000.0,
                _retry_after(first),
            )
        response = await client.get(url, timeout=8, follow_redirects=False)
        body = response.content or b""
        return (
            response.status_code,
            len(body) or response_length(response),
            body_fingerprint(body),
            body,
            url,
            0,
            [url],
            (response.headers.get("content-type") or "")[:120],
            (time.perf_counter() - t0) * 1000.0,
            _retry_after(response),
        )
    except httpx.HTTPError:
        return 0, 0, "", b"", url, 0, [url], "", (time.perf_counter() - t0) * 1000.0, ""


def is_probe_hit(
    probe: ProbeResult,
    *,
    status_filter: StatusCodeFilter,
    wildcard: WildcardProfile,
    baseline: Tuple[int, int],
    config: CrawlConfig,
    fp_store: Optional[FalsePositiveStore],
    exclude_lengths: Set[int],
    exclude_hashes: Set[str],
    stats: Optional[CrawlStats] = None,
) -> bool:
    if not probe.status:
        return False
    if probe.status == 429:
        return False
    if not status_filter.allows(probe.status):
        return False
    if probe.content_length in exclude_lengths:
        return False
    short_hash = (probe.body_hash or "")[:16]
    raw_hash = probe.raw_hash or probe.body_hash or ""
    norm_hash = probe.normalized_hash or ""
    if short_hash in exclude_hashes or raw_hash in exclude_hashes:
        return False
    if fp_store and fp_store.is_false_positive(probe.status, probe.content_length, short_hash, probe.url):
        return False

    matched, sim, shape_used = matches_any_shape_baseline(
        wildcard,
        path_or_word=probe.word or probe.url,
        status=probe.status,
        length=probe.content_length,
        raw_hash=raw_hash,
        normalized_hash=norm_hash,
        similarity_threshold=int(getattr(config, "enum_similarity_threshold", 64) or 64),
    )
    if matched:
        probe.wildcard_similarity = sim
        probe.baseline_used = shape_used
        probe.classification = CLASS_WILDCARD
        probe.acceptance_reason = f"matched_wildcard_shape:{shape_used}"
        probe.validated = False
        if stats is not None:
            stats.soft_404s_filtered += 1
            if hasattr(stats, "enum_rejected_wildcard"):
                stats.enum_rejected_wildcard = int(getattr(stats, "enum_rejected_wildcard", 0) or 0) + 1
        return False

    sig = (probe.status, probe.content_length, short_hash)
    if wildcard.active and sig in wildcard.signatures:
        probe.classification = CLASS_WILDCARD
        probe.validated = False
        if stats is not None:
            stats.soft_404s_filtered += 1
            if hasattr(stats, "enum_rejected_wildcard"):
                stats.enum_rejected_wildcard = int(getattr(stats, "enum_rejected_wildcard", 0) or 0) + 1
        return False

    baseline_len, baseline_status = baseline
    if (
        config.smart_false_positive
        and baseline_len
        and probe.content_length
        and probe.status == baseline_status
        and abs(probe.content_length - baseline_len) < config.enum_similarity_threshold
    ):
        if probe.body_hash and probe.body_hash not in ("", "head-only"):
            if fp_store and fp_store.is_false_positive(
                probe.status, probe.content_length, short_hash, probe.url
            ):
                return False
            pass
        else:
            if config.false_positive_learning and fp_store:
                fp_store.record_url_only(probe.url)
            if stats is not None:
                stats.soft_404s_filtered += 1
            return False
    if config.response_fingerprint and wildcard.active:
        near_wildcard = any(
            probe.status == s
            and abs(probe.content_length - length) < config.enum_similarity_threshold
            and (not h or h == short_hash or (raw_hash and raw_hash.startswith(h)))
            for s, length, h in wildcard.signatures
        )
        if near_wildcard:
            if stats is not None:
                stats.soft_404s_filtered += 1
                if hasattr(stats, "enum_rejected_wildcard"):
                    stats.enum_rejected_wildcard = int(getattr(stats, "enum_rejected_wildcard", 0) or 0) + 1
            return False
    return True


async def run_pro_directory_enum(
    config: CrawlConfig,
    client: httpx.AsyncClient,
    output_callback,
    running: Callable[[], bool],
    *,
    stats: CrawlStats,
    discovered: set,
    queue,
    link_depths: dict,
    use_priority: bool,
    manager,
    extensions,
    download_semaphore,
    update_progress=None,
    seed_urls: Optional[List[str]] = None,
    technologies: Optional[Dict[str, int]] = None,
    merge_wordlists_fn,
    on_hit_callback=None,
    reporter=None,
):
    from crawler_common import get_async_baseline

    from crawler_common import normalize_extensions

    seed_urls = seed_urls or []
    exclude_hashes = {h.strip() for h in (config.exclude_body_hashes or "").split(",") if h.strip()}
    fp_store = FalsePositiveStore(config.false_positive_file or os.path.join(os.path.dirname(config.checkpoint_file), "false_positives.json"))
    if config.false_positive_learning:
        fp_store.load()

    output_callback("Preparing directory enum (baseline / wildcard / wordlist)…")
    if update_progress:
        update_progress(1, 0, "Preparing directory enum…")

    baseline = await get_async_baseline(client, config.start_url)
    wildcard = await detect_wildcard(client, config.start_url) if config.wildcard_detection else WildcardProfile()
    wildcard_cache = DirectoryWildcardCache()
    if wildcard.active:
        shape_n = sum(1 for b in (wildcard.shapes or {}).values() if b.active)
        output_callback(
            f"Wildcard calibration — {shape_n} active path-shape baseline(s), "
            f"{len(wildcard.signatures)} legacy signature(s)"
        )
        for note in (wildcard.calibration_notes or [])[:8]:
            output_callback(f"  wildcard: {note}")
        wildcard_cache._cache["/"] = wildcard
    elif config.wildcard_detection:
        output_callback("Wildcard calibration — no catch-all responses detected")
    stats.enum_wildcard_calibration_ok = bool(getattr(wildcard, "calibration_ok", False))  # type: ignore[attr-defined]
    stats.enum_wildcard_active = bool(wildcard.active)  # type: ignore[attr-defined]
    per_dir = bool(getattr(config, "per_directory_wildcard", True)) and bool(config.wildcard_detection)

    # Flat enum vs depth: flat forces effective depth 0
    requested_depth = int(config.branch_depth_limit or config.max_depth or 0)
    if config.enum_flat_scan:
        effective_depth = 0
        depth_reason = "flat enumeration enabled"
    else:
        effective_depth = requested_depth
        depth_reason = ""
    stats.enum_requested_depth = requested_depth  # type: ignore[attr-defined]
    stats.enum_effective_depth = effective_depth  # type: ignore[attr-defined]
    stats.enum_depth_reason = depth_reason  # type: ignore[attr-defined]

    limit = int(getattr(config, "enum_word_limit", 0) or 0)
    output_callback(
        "Building enum wordlist…"
        + (f" (capped at {limit:,} words)" if limit else "")
    )
    if update_progress:
        update_progress(max(limit, 1), 0, "Building enum wordlist…")

    words = await asyncio.to_thread(
        build_smart_wordlist,
        config,
        seed_urls=list(seed_urls or [])[:800],
        technologies=technologies,
        merge_fn=merge_wordlists_fn,
    )
    total_words = len(words)
    # Separate counters: base words ≠ HTTP attempts
    stats.enum_base_words_loaded = total_words  # type: ignore[attr-defined]
    stats.enum_base_words_processed = 0  # type: ignore[attr-defined]
    stats.enum_mutation_candidates = int(getattr(config, "mutation_max_candidates", 0) or 0) if getattr(config, "mutation_enum", False) else 0  # type: ignore[attr-defined]
    ext_list = config.parsed_enum_extensions() if getattr(config, "gobuster_style_extensions", False) else []
    stats.enum_extension_candidates = len(ext_list)  # type: ignore[attr-defined]
    stats.enum_http_attempts = 0  # type: ignore[attr-defined]
    stats.enum_rate_limited = 0  # type: ignore[attr-defined]
    stats.enum_rejected_wildcard = 0  # type: ignore[attr-defined]
    stats.enum_unique_candidate_urls = 0  # type: ignore[attr-defined]
    stats.enum_inconclusive = 0  # type: ignore[attr-defined]
    # Progress bar uses base words only (never HTTP attempts as "words tested")
    stats.enum_words_total = total_words
    stats.enum_words_tested = 0
    output_callback(f"Enum wordlist ready: {total_words:,} base words.")
    if update_progress and total_words:
        from user_output import format_enum_progress

        update_progress(total_words, 0, format_enum_progress(0, total_words, 0))
    enum_progress = {"started_at": None, "rate": 0}
    found_set = set()
    provenance = HitProvenanceTracker(list(discovered or set()) + list(seed_urls or []))
    if hasattr(stats, "discovered_urls"):
        provenance.note_known(list(stats.discovered_urls or []))

    # Adaptive concurrency (stealth-aware)
    is_stealth = str(getattr(config, "profile", "") or "").lower() == "stealth" or str(
        getattr(config, "evasion_level", "") or ""
    ).lower() == "stealth"
    configured_conc = max(1, int(config.enum_concurrency) or 1)
    if is_stealth:
        live_concurrency = min(configured_conc, 3)
    else:
        live_concurrency = configured_conc
    concurrency_state = {
        "n": live_concurrency,
        "clean_streak": 0,
        "max": configured_conc if not is_stealth else min(configured_conc, 3),
        "min": 1 if is_stealth else max(1, min(2, configured_conc)),
        "retry_after_until": 0.0,
    }

    def live_download_extensions():
        if callable(extensions):
            return extensions()
        return normalize_extensions(config.extensions)

    resume_index = 0
    resume_segments: List[str] = []
    resume_depth = 0
    if config.resume_enum_checkpoint:
        state = load_enum_checkpoint(config.enum_checkpoint_file)
        if state and state.get("start_url") == config.start_url:
            resume_index = int(state.get("word_index", 0))
            resume_segments = list(state.get("path_segments", []))
            resume_depth = int(state.get("depth", 0))
            found_set.update(state.get("found_urls", []))
            output_callback(f"Resumed enum checkpoint at word {resume_index:,}/{total_words:,}")

    depth_label = (
        f"flat (requested depth {requested_depth}, effective 0 — {depth_reason})"
        if config.enum_flat_scan
        else f"depth {effective_depth}"
    )
    output_callback(
        f"Pro enum: {total_words:,} base words · concurrency {concurrency_state['n']} · {depth_label}"
    )

    async def handle_hit(probe: ProbeResult, depth: int):
        # Only persist / crawl / security-scan validated hits
        if not probe.validated:
            label = probe.classification or "rejected"
            output_callback(
                f"ENUM-SKIP [{label}] {probe.url} ({probe.acceptance_reason or 'not validated'})"
            )
            return
        if probe.url in found_set:
            return
        found_set.add(probe.url)
        stats.enum_hits += 1
        stats.enum_hit_urls.append(probe.url)
        # Rich result rows for SQLite / reports
        if not hasattr(stats, "enum_hit_records") or stats.enum_hit_records is None:  # type: ignore[attr-defined]
            stats.enum_hit_records = []  # type: ignore[attr-defined]
        rec = {
            "url": probe.url,
            "source": "directory_enum",
            "base_word": probe.base_word or probe.word,
            "variant": probe.word,
            "already_known": bool(probe.already_known),
            "requested_status": probe.status,
            "final_status": probe.status,
            "final_url": probe.final_url or probe.url,
            "classification": probe.classification,
            "path_shape": probe.path_shape,
            "acceptance_reason": probe.acceptance_reason,
            "baseline_used": probe.baseline_used,
            "wildcard_similarity": probe.wildcard_similarity,
            "validated": True,
            "fingerprint": probe.fingerprint.to_dict() if probe.fingerprint else {},
        }
        stats.enum_hit_records.append(rec)  # type: ignore[attr-defined]
        via = ""
        if probe.redirect_hops and probe.final_url and probe.final_url != probe.url:
            via = f" → {probe.final_url} ({probe.redirect_hops} hop(s))"
        output_callback(
            f"HIT [{probe.status}] {probe.url}{via} (size={probe.content_length}, {probe.classification})"
        )
        log_to_file(config.output_file_path, probe.url)
        discovered.add(probe.url)
        stats.discovered_urls.add(probe.url)
        if config.queue_enum_for_crawl:
            enqueue_discovered_url(
                probe.url,
                discovered,
                queue,
                config.output_file_path,
                output_callback,
                stats=stats,
                use_priority=use_priority,
                link_depth=link_depths.get(config.start_url, 0) + depth + 1,
                max_link_depth=config.link_depth_limit,
                link_depths=link_depths,
                skip_static_pages=bool(getattr(config, "skip_static_page_enqueue", True)),
                start_url=config.start_url,
                scope_mode=str(getattr(config, "scope_mode", "allowed-subdomains") or "allowed-subdomains"),
                base_url_for_canonical=config.start_url,
            )
        if config.download_files and config.download_dir and not config.skip_enum_download:
            await save_enum_hit_async(
                client,
                probe.url,
                config.download_dir,
                output_callback,
                live_download_extensions(),
                manager,
                config.preserve_structure,
                config.rewrite_local,
                config.save_server_side_as_txt,
                download_semaphore,
                config.bypass_forbidden,
                update_progress,
                mirror_page_assets=getattr(config, "mirror_page_assets", True),
                running=running,
            )
        if on_hit_callback:
            await on_hit_callback(probe)

    async def _honor_retry_after(headers_retry_after: str = "") -> None:
        delay = 0.0
        raw = (headers_retry_after or "").strip()
        if raw.isdigit():
            delay = float(raw)
        elif raw:
            delay = 5.0
        # Stealth: always add jitter
        if is_stealth:
            delay = max(delay, random.uniform(0.35, 1.25))
        if delay > 0:
            concurrency_state["retry_after_until"] = time.time() + delay
            await asyncio.sleep(delay)

    async def check_word(path_segments: List[str], word: str, depth: int) -> Optional[ProbeResult]:
        if not await is_running(running):
            return None
        status_filter = build_status_filter(config)
        exclude_lengths = parse_int_list(config.exclude_lengths)
        local_wildcard = await wildcard_cache.for_path(
            client,
            config.start_url,
            path_segments,
            enabled=per_dir,
            root_fallback=wildcard,
        )
        # Wait out Retry-After window
        wait_for = concurrency_state["retry_after_until"] - time.time()
        if wait_for > 0:
            await asyncio.sleep(min(wait_for, 30.0))
        if is_stealth:
            await asyncio.sleep(random.uniform(0.05, 0.35))

        variants = iter_gobuster_word_variants(word, config)
        for variant in variants:
            test_url = build_enum_url(config.start_url, path_segments, variant)
            if not test_url:
                continue
            stats.enum_unique_candidate_urls = int(getattr(stats, "enum_unique_candidate_urls", 0) or 0) + 1  # type: ignore[attr-defined]

            max_attempts = 3
            status = 0
            length = 0
            body_hash = ""
            body = b""
            final_url = test_url
            hops = 0
            chain: List[str] = [test_url]
            ctype = ""
            duration_ms = 0.0
            retry_after = ""
            for attempt in range(max_attempts):
                (
                    status,
                    length,
                    body_hash,
                    body,
                    final_url,
                    hops,
                    chain,
                    ctype,
                    duration_ms,
                    retry_after,
                ) = await probe_candidate(
                    client,
                    test_url,
                    use_head=config.enum_method.upper() != "GET",
                    bypass_forbidden=config.bypass_forbidden,
                    follow_redirects=bool(getattr(config, "enum_follow_redirects", True)),
                    max_redirect_hops=int(getattr(config, "enum_redirect_max_hops", 5) or 5),
                )
                stats.enum_http_attempts = int(getattr(stats, "enum_http_attempts", 0) or 0) + 1  # type: ignore[attr-defined]
                if config.status_code_report and status:
                    stats.record_status(status, enum=True)
                # Unified request ledger — enum phase
                if hasattr(stats, "record_request"):
                    stats.record_request(
                        phase="enumeration",
                        source="directory_enum",
                        url=test_url,
                        depth=depth,
                        status=status,
                        final_url=final_url or test_url,
                        response_type=ctype,
                        bytes_=length,
                        content_hash=body_hash,
                        duration_ms=duration_ms,
                        outcome="rate_limited" if status == 429 else ("ok" if status else "error"),
                    )
                if status != 429:
                    concurrency_state["clean_streak"] += 1
                    # Gradual recovery after clean responses
                    if (
                        is_stealth
                        and concurrency_state["clean_streak"] >= 12
                        and concurrency_state["n"] < concurrency_state["max"]
                    ):
                        concurrency_state["n"] += 1
                        concurrency_state["clean_streak"] = 0
                    break
                # 429 — not coverage; requeue with backoff
                stats.enum_rate_limited = int(getattr(stats, "enum_rate_limited", 0) or 0) + 1  # type: ignore[attr-defined]
                concurrency_state["clean_streak"] = 0
                if is_stealth or concurrency_state["n"] > concurrency_state["min"]:
                    concurrency_state["n"] = concurrency_state["min"]
                await _honor_retry_after(retry_after or "2")
                if attempt + 1 >= max_attempts:
                    stats.enum_inconclusive = int(getattr(stats, "enum_inconclusive", 0) or 0) + 1  # type: ignore[attr-defined]
                    return None  # inconclusive — not a hit, not a negative for coverage stats

            retained = body or b""
            if len(retained) > 262_144:
                retained = retained[:262_144]
            fp = fingerprint_from_response(
                url=test_url,
                status=status,
                body=retained,
                final_url=final_url or test_url,
                redirect_chain=chain,
                content_type=ctype,
                duration_ms=duration_ms,
                length=length,
            )
            # Prefer full hashes on the probe
            raw = fp.raw_hash
            norm = fp.normalized_hash
            probe = ProbeResult(
                test_url,
                variant,
                status,
                length,
                body_hash,
                list(path_segments),
                final_url=final_url or test_url,
                redirect_hops=hops,
                body=retained,
                content_type=ctype,
                redirect_chain=list(chain or []),
                title=fp.title,
                raw_hash=raw,
                normalized_hash=norm,
                duration_ms=duration_ms,
                path_shape=classify_path_shape(variant),
                fingerprint=fp,
                base_word=word,
            )
            if is_probe_hit(
                probe,
                status_filter=status_filter,
                wildcard=local_wildcard,
                baseline=baseline,
                config=config,
                fp_store=fp_store,
                exclude_lengths=exclude_lengths,
                exclude_hashes=exclude_hashes,
                stats=stats,
            ):
                # Provenance / case / content grouping before acceptance
                rec = provenance.classify_and_record(
                    url=probe.url,
                    base_word=word,
                    variant=variant,
                    requested_status=status,
                    final_status=status,
                    final_url=probe.final_url,
                    fingerprint=fp,
                    wildcard_rejected=False,
                    wildcard_similarity=probe.wildcard_similarity,
                    baseline_used=probe.baseline_used,
                    soft_404=False,
                    path_shape=probe.path_shape or classify_path_shape(variant),
                )
                probe.classification = rec.classification
                probe.validated = rec.validated
                probe.already_known = rec.already_known
                probe.acceptance_reason = rec.acceptance_reason
                probe.baseline_used = rec.baseline_used
                if not rec.validated:
                    # Track as skipped candidate, not a hit
                    if not hasattr(stats, "enum_skipped_records"):
                        stats.enum_skipped_records = []  # type: ignore[attr-defined]
                    stats.enum_skipped_records.append(rec.to_dict())  # type: ignore[attr-defined]
                    output_callback(
                        f"ENUM-REJECT [{rec.classification}] {probe.url} ({rec.acceptance_reason})"
                    )
                    continue
                return probe
            elif probe.classification == CLASS_WILDCARD:
                # Already counted in is_probe_hit
                continue
        return None

    async def enumerate_level(path_segments: List[str], depth: int, start_index: int = 0):
        max_d = effective_depth
        if depth > max_d or not await is_running(running):
            return
        if path_segments:
            output_callback(f"Enum under {format_enum_path(path_segments)} (depth {depth})")

        index = start_index if path_segments == resume_segments and depth == resume_depth else 0
        while index < len(words):
            batch_size = max(1, int(concurrency_state["n"]) or 1)
            if not await is_running(running):
                return
            if config.enum_word_limit and index >= config.enum_word_limit:
                output_callback(f"Enum word limit reached ({config.enum_word_limit:,}).")
                return
            batch = words[index : index + batch_size]
            if config.enum_word_limit:
                batch = batch[: max(0, config.enum_word_limit - index)]
            # Progress = base words processed (not HTTP attempts)
            done_words = min(index + len(batch), total_words)
            stats.enum_base_words_processed = max(  # type: ignore[attr-defined]
                int(getattr(stats, "enum_base_words_processed", 0) or 0),
                done_words if not path_segments else int(getattr(stats, "enum_base_words_processed", 0) or 0),
            )
            if not path_segments:
                stats.enum_words_tested = done_words
            if hasattr(stats, "note_enum_progress"):
                stats.note_enum_progress(
                    stats.enum_words_tested,
                    word=batch[-1] if batch else "",
                    path=format_enum_path(path_segments),
                    depth=depth,
                )
            log_enum_batch_progress(
                output_callback,
                path_segments,
                depth,
                index,
                batch_size,
                len(words),
                stats=stats,
                update_progress=update_progress,
                progress_state=enum_progress,
                batch_words=batch,
                use_cumulative_tested=False,
            )
            tasks = [asyncio.create_task(check_word(path_segments, word, depth)) for word in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    stats.errors += 1
                    from user_output import sanitize_error_message

                    output_callback(f"Enum probe error: {sanitize_error_message(result)}")
                    continue
                if not result:
                    continue
                await handle_hit(result, depth)
                if config.enum_flat_scan or effective_depth <= 0:
                    continue
                if looks_like_file_path_segment(result.word):
                    output_callback(
                        f"Skipping folder enum under file hit {format_enum_path(path_segments + [result.word])}"
                    )
                    continue
                if depth + 1 <= max_d:
                    await enumerate_level(path_segments + [result.word], depth + 1)
            next_index = index + batch_size
            if config.enum_checkpoint_interval and next_index and next_index % config.enum_checkpoint_interval == 0:
                save_enum_checkpoint(
                    config.enum_checkpoint_file,
                    config.start_url,
                    next_index,
                    path_segments,
                    depth,
                    list(found_set),
                )
            index = next_index

        # Clear "Trying:" after level completes so UI does not stick on last word forever
        if not path_segments and index >= len(words):
            stats.enum_current_word = ""
            stats.enum_words_tested = total_words

    prefix_roots: List[List[str]] = [[]]
    manual = [p.strip().strip("/") for p in (config.enum_prefixes or "").split(",") if p.strip()]
    auto = extract_auto_prefixes(seed_urls) if config.auto_prefix_enum and not manual else []
    for prefix in manual or auto:
        prefix_roots.append([prefix])

    # Do NOT multiply total by prefix roots into HTTP-attempt space —
    # progress stays base-word based; prefixes are sequential passes.
    stats.enum_words_total = total_words
    stats.enum_words_tested = 0
    stats.enum_base_words_loaded = total_words  # type: ignore[attr-defined]

    for roots in prefix_roots:
        await enumerate_level(roots, len(roots), resume_index if roots == resume_segments else 0)

    if config.false_positive_learning:
        fp_store.save()
    save_enum_checkpoint(config.enum_checkpoint_file, config.start_url, len(words), [], 0, list(found_set))
    stats.enum_current_word = ""
    stats.enum_words_tested = total_words
    stats.enum_base_words_processed = total_words  # type: ignore[attr-defined]
    conclusion = enum_validation_conclusion(
        http_attempts=int(getattr(stats, "enum_http_attempts", 0) or 0),
        accepted_hits=int(stats.enum_hits or 0),
        rejected_wildcard=int(getattr(stats, "enum_rejected_wildcard", 0) or 0),
        rate_limited=int(getattr(stats, "enum_rate_limited", 0) or 0),
        calibration_ok=bool(getattr(wildcard, "calibration_ok", True)),
        wildcard_active=bool(wildcard.active),
    )
    stats.enum_validation_conclusion = conclusion  # type: ignore[attr-defined]
    output_callback(f"Directory enumeration finished — {stats.enum_hits} validated hit(s).")
    output_callback(conclusion)
    return found_set
