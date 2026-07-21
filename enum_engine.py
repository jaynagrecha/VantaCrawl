"""Gobuster-beater directory enumeration engine (Tiers 1–3)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

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
    save_enum_hit_async,
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


@dataclass
class WildcardProfile:
    active: bool = False
    signatures: Set[Tuple[int, int, str]] = field(default_factory=set)


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
) -> Tuple[int, int, str, bytes, str, int]:
    """
    Follow Location hops on the same host. Returns
    (status, length, body_hash, body, final_url, hops_taken).
    """
    current = start_url
    seen: Set[str] = set()
    body = b""
    status = 0
    hops = 0
    max_hops = max(0, int(max_hops) or 0)
    for _ in range(max_hops + 1):
        if current in seen:
            break
        seen.add(current)
        try:
            response = await client.get(current, timeout=timeout, follow_redirects=False)
        except httpx.HTTPError:
            return 0, 0, "", b"", current, hops
        status = response.status_code
        body = response.content or b""
        length = len(body) or response_length(response)
        digest = body_fingerprint(body)
        if status not in REDIRECT_STATUSES:
            return status, length, digest, body, current, hops
        location = (response.headers.get("location") or "").strip()
        if not location:
            return status, length, digest, body, current, hops
        nxt = urljoin(current, location)
        if not hosts_compatible(start_url, nxt):
            # Off-site redirect: keep redirect status (usually not a hit after whitelist change)
            return status, length, digest, body, current, hops
        current = nxt
        hops += 1
    length = len(body) or 0
    return status, length, body_fingerprint(body), body, current, hops


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


async def detect_wildcard(
    client: httpx.AsyncClient,
    base_url: str,
    *,
    probes: int = 5,
) -> WildcardProfile:
    signatures: Set[Tuple[int, int, str]] = set()
    counts: Dict[Tuple[int, int, str], int] = {}
    for _ in range(probes):
        token = f"crawler-wildcard-{uuid.uuid4().hex[:12]}"
        url = build_enum_url(base_url, [], token)
        if not url:
            continue
        try:
            response = await client.get(url, timeout=6, follow_redirects=False)
            body = response.content or b""
            sig = (response.status_code, response_length(response), body_fingerprint(body))
            signatures.add(sig)
            counts[sig] = counts.get(sig, 0) + 1
        except httpx.HTTPError:
            continue
    dominant = max(counts.values()) if counts else 0
    # Require a clearer majority so 2/5 coincidental matches do not activate wildcard mode
    active = dominant >= max(3, probes - 1) and len(signatures) <= 2
    return WildcardProfile(active=active, signatures=signatures if active else set())


async def probe_candidate(
    client: httpx.AsyncClient,
    url: str,
    *,
    use_head: bool = False,
    bypass_forbidden: bool = True,
    follow_redirects: bool = True,
    max_redirect_hops: int = 5,
) -> Tuple[int, int, str, bytes, str, int]:
    """
    Probe a URL. When follow_redirects is on, same-host redirects are resolved and the
    *final* status/body are returned (hops > 0). Tuple:
    (status, length, body_hash, body, final_url, redirect_hops).
    """
    body = b""
    try:
        if use_head:
            response = await client.head(url, timeout=6, follow_redirects=False)
            status = response.status_code
            # Always GET when status looks interesting or body fingerprint would be useless
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
            ):
                if follow_redirects and status in REDIRECT_STATUSES:
                    return await follow_same_host_redirects(
                        client, url, max_hops=max_redirect_hops, timeout=8
                    )
                response = await client.get(url, timeout=8, follow_redirects=False)
                body = response.content or b""
                status = response.status_code
                if follow_redirects and status in REDIRECT_STATUSES:
                    return await follow_same_host_redirects(
                        client, url, max_hops=max_redirect_hops, timeout=8
                    )
                return status, len(body) or response_length(response), body_fingerprint(body), body, url, 0
            return status, response_length(response), "head-only", body, url, 0
        if follow_redirects:
            # Start resolve from the requested URL (handles HEAD-skipped GET path too)
            first = await client.get(url, timeout=8, follow_redirects=False)
            if first.status_code in REDIRECT_STATUSES:
                return await follow_same_host_redirects(
                    client, url, max_hops=max_redirect_hops, timeout=8
                )
            body = first.content or b""
            return (
                first.status_code,
                len(body) or response_length(first),
                body_fingerprint(body),
                body,
                url,
                0,
            )
        response = await client.get(url, timeout=8, follow_redirects=False)
        body = response.content or b""
        return response.status_code, len(body) or response_length(response), body_fingerprint(body), body, url, 0
    except httpx.HTTPError:
        return 0, 0, "", b"", url, 0


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
) -> bool:
    if not probe.status:
        return False
    if not status_filter.allows(probe.status):
        return False
    if probe.content_length in exclude_lengths:
        return False
    if probe.body_hash in exclude_hashes:
        return False
    if fp_store and fp_store.is_false_positive(probe.status, probe.content_length, probe.body_hash, probe.url):
        return False
    sig = (probe.status, probe.content_length, probe.body_hash)
    if wildcard.active and sig in wildcard.signatures:
        return False
    baseline_len, baseline_status = baseline
    # Soft-404 filter: length alone is too aggressive when hash differs (real content)
    if (
        config.smart_false_positive
        and baseline_len
        and probe.content_length
        and probe.status == baseline_status
        and abs(probe.content_length - baseline_len) < config.enum_similarity_threshold
    ):
        # If we have a real body fingerprint different from empty/head-only, keep as hit
        if probe.body_hash and probe.body_hash not in ("", "head-only"):
            # Still suppress when fingerprint matches a known FP signature for this host
            if fp_store and fp_store.is_false_positive(
                probe.status, probe.content_length, probe.body_hash, probe.url
            ):
                return False
            # Length-similar but hashed: treat as distinct content (reduce FN)
            pass
        else:
            if config.false_positive_learning and fp_store:
                # Learn per-URL only — do not poison global signature store with soft-404 sizes
                fp_store.record_url_only(probe.url)
            return False
    if config.response_fingerprint and wildcard.active:
        near_wildcard = any(
            probe.status == s
            and abs(probe.content_length - length) < config.enum_similarity_threshold
            and (not h or h == probe.body_hash)
            for s, length, h in wildcard.signatures
        )
        if near_wildcard:
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
    if wildcard.active:
        output_callback(f"Wildcard detected — filtering {len(wildcard.signatures)} response fingerprint(s)")

    limit = int(getattr(config, "enum_word_limit", 0) or 0)
    output_callback(
        "Building enum wordlist…"
        + (f" (capped at {limit:,} words)" if limit else "")
    )
    if update_progress:
        update_progress(max(limit, 1), 0, "Building enum wordlist…")

    # Off the event loop — large files + Free-tier CPU must not freeze live progress
    words = await asyncio.to_thread(
        build_smart_wordlist,
        config,
        seed_urls=list(seed_urls or [])[:800],
        technologies=technologies,
        merge_fn=merge_wordlists_fn,
    )
    total_words = len(words)
    stats.enum_words_total = total_words
    stats.enum_words_tested = 0
    output_callback(f"Enum wordlist ready: {total_words:,} words.")
    if update_progress and total_words:
        from user_output import format_enum_progress

        update_progress(total_words, 0, format_enum_progress(0, total_words, 0))
    enum_progress = {"started_at": None, "rate": 0}
    found_set = set()

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

    batch_size = max(1, int(config.enum_concurrency) or 1)
    output_callback(
        f"Pro enum: {total_words:,} words · {batch_size} threads · "
        f"{'flat' if config.enum_flat_scan else f'depth {config.branch_depth_limit or config.max_depth}'}"
    )

    async def handle_hit(probe: ProbeResult, depth: int):
        if probe.url in found_set:
            return
        found_set.add(probe.url)
        stats.enum_hits += 1
        stats.enum_hit_urls.append(probe.url)
        via = ""
        if probe.redirect_hops and probe.final_url and probe.final_url != probe.url:
            via = f" → {probe.final_url} ({probe.redirect_hops} hop(s))"
        output_callback(f"HIT [{probe.status}] {probe.url}{via} (size={probe.content_length})")
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

    async def check_word(path_segments: List[str], word: str, depth: int) -> Optional[ProbeResult]:
        if not running():
            return None
        # Re-read filters each probe so Pause → change settings → Resume applies live
        status_filter = build_status_filter(config)
        exclude_lengths = parse_int_list(config.exclude_lengths)
        for variant in iter_gobuster_word_variants(word, config):
            test_url = build_enum_url(config.start_url, path_segments, variant)
            if not test_url:
                continue
            status, length, body_hash, _body, final_url, hops = await probe_candidate(
                client,
                test_url,
                use_head=config.enum_method.upper() != "GET",
                bypass_forbidden=config.bypass_forbidden,
                follow_redirects=bool(getattr(config, "enum_follow_redirects", True)),
                max_redirect_hops=int(getattr(config, "enum_redirect_max_hops", 5) or 5),
            )
            if config.status_code_report and status:
                stats.record_status(status, enum=True)
            probe = ProbeResult(
                test_url,
                variant,
                status,
                length,
                body_hash,
                list(path_segments),
                final_url=final_url or test_url,
                redirect_hops=hops,
            )
            if is_probe_hit(
                probe,
                status_filter=status_filter,
                wildcard=wildcard,
                baseline=baseline,
                config=config,
                fp_store=fp_store,
                exclude_lengths=exclude_lengths,
                exclude_hashes=exclude_hashes,
            ):
                return probe
        return None

    async def enumerate_level(path_segments: List[str], depth: int, start_index: int = 0):
        max_d = 0 if config.enum_flat_scan else (config.branch_depth_limit or config.max_depth)
        if depth > max_d or not running():
            return
        if path_segments:
            output_callback(f"Enum under {format_enum_path(path_segments)} (depth {depth})")

        index = start_index if path_segments == resume_segments and depth == resume_depth else 0
        while index < len(words):
            batch_size = max(1, int(config.enum_concurrency) or 1)
            if not running():
                return
            if config.enum_word_limit and index >= config.enum_word_limit:
                output_callback(f"Enum word limit reached ({config.enum_word_limit:,}).")
                return
            batch = words[index : index + batch_size]
            if config.enum_word_limit:
                batch = batch[: max(0, config.enum_word_limit - index)]
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
            )
            tasks = [asyncio.create_task(check_word(path_segments, word, depth)) for word in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if not result or isinstance(result, Exception):
                    continue
                await handle_hit(result, depth)
                if not config.enum_flat_scan:
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

    prefix_roots: List[List[str]] = [[]]
    manual = [p.strip().strip("/") for p in (config.enum_prefixes or "").split(",") if p.strip()]
    auto = extract_auto_prefixes(seed_urls) if config.auto_prefix_enum and not manual else []
    for prefix in manual or auto:
        prefix_roots.append([prefix])

    for roots in prefix_roots:
        await enumerate_level(roots, len(roots), resume_index if roots == resume_segments else 0)

    if config.false_positive_learning:
        fp_store.save()
    save_enum_checkpoint(config.enum_checkpoint_file, config.start_url, len(words), [], 0, list(found_set))
    output_callback(f"Directory enumeration finished — {stats.enum_hits} hit(s).")
    return found_set
