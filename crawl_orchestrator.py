"""Full-featured crawl orchestrator integrating discovery, security, and reporting."""

from __future__ import annotations

import asyncio
import heapq
import os
import shutil
import time
from collections import deque
from typing import Callable, Optional
from urllib.parse import urlparse

import httpx

from checkpoint import load_checkpoint, restore_sets, save_checkpoint
from bfs_loop import run_concurrent_bfs
from crawl_config import CrawlConfig
from crawl_stats import CrawlStats
from crawler_common import (
    DownloadManager,
    async_path_exists,
    build_enum_url,
    crawl_page_async,
    enqueue_discovered_url,
    get_async_baseline,
    get_request_headers,
    init_crawl_state,
    is_html_url,
    is_valid_url,
    load_wordlist,
    log_to_file,
    looks_like_existing_path,
    normalize_extensions,
    response_length,
    save_body_async,
    download_referenced_assets,
    _should_skip_url,
    log_enum_batch_progress,
    format_enum_path,
    save_enum_hit_async,
    BYPASS_HTTP_CODES,
    emit_download_progress,
    format_byte_size,
)
from enum_engine import build_status_filter, run_pro_directory_enum
from cloud_enum import enumerate_gcs_buckets, enumerate_s3_buckets
from vhost_enum import enumerate_vhosts
from content_validate import needs_content_gate, validate_sensitive_content
from file_metadata import extract_file_metadata, looks_like_document, metadata_findings
from discovery_extra import (
    enumerate_subdomains,
    extract_js_routes,
    extract_openapi_urls,
    extract_rss_feeds,
    fetch_common_crawl_urls,
    fetch_wayback_urls,
    parse_openapi_endpoints,
)
from recon_active import run_host_recon_once
from recon_extract import (
    detect_login_surface,
    extract_cloud_urls,
    extract_dom_sinks,
    extract_emails,
    extract_interesting_comments,
    extract_internal_hosts,
    extract_link_header_urls,
    extract_link_rels,
    extract_phones,
    extract_sourcemap_urls,
    extract_third_party_scripts,
    extract_websocket_urls,
    inventory_cookies,
    inventory_security_headers,
)
from reporting import ReportWriter
from security_scan import (
    audit_security_headers,
    check_cors,
    discover_parameters,
    extract_forms,
    fingerprint_technology,
    probe_http_methods,
    run_active_vuln_probes,
    run_passive_vuln_scan,
    scan_secrets,
    scan_sensitive_path,
)

ENUM_EXTENSIONS = (".php", ".asp", ".aspx", ".bak", ".old", ".txt", ".zip", ".sql", ".config", ".env")


def _to_priority_queue(queue):
    """Convert deque/list of URLs into a heapq-compatible list."""
    from collections import deque

    items = list(queue) if isinstance(queue, deque) else list(queue)
    priority_queue = []
    counter = 0
    for item in items:
        if isinstance(item, (list, tuple)) and len(item) >= 2 and isinstance(item[0], int):
            url = item[-1]
            heapq.heappush(priority_queue, (item[0], counter, url))
        else:
            url = item
            if not isinstance(url, str) or not is_valid_url(url):
                counter += 1
                continue
            heapq.heappush(priority_queue, (0 if is_html_url(url) else 1, counter, url))
        counter += 1
    return priority_queue


class PauseController:
    def __init__(self, base_is_running: Callable[[], bool]):
        self._base = base_is_running
        self.paused = False
        self._was_paused = False
        self._on_resume: list = []

    def on_resume(self, callback: Callable[[], None]):
        self._on_resume.append(callback)

    def __call__(self) -> bool:
        while self.paused and self._base():
            self._was_paused = True
            time.sleep(0.25)
        if self._was_paused:
            self._was_paused = False
            for callback in self._on_resume:
                try:
                    callback()
                except Exception:
                    pass
        return self._base()

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False


def disk_space_ok(min_mb: int) -> bool:
    if min_mb <= 0:
        return True
    try:
        usage = shutil.disk_usage(os.path.dirname(os.path.abspath(__file__)))
        return usage.free >= min_mb * 1024 * 1024
    except OSError:
        return True


def expand_wordlist(words: list, extension_aware: bool) -> list:
    if not extension_aware:
        return words
    expanded = list(words)
    for word in words:
        if "." not in word:
            for ext in ENUM_EXTENSIONS:
                expanded.append(word + ext)
    return expanded


def merge_wordlists(primary: str, extras: list) -> list:
    words = load_wordlist(primary)
    seen = set(words)
    for path in extras:
        for word in load_wordlist(path):
            if word not in seen:
                seen.add(word)
                words.append(word)
    return words


async def gather_extra_seeds(config: CrawlConfig, output_callback) -> list:
    domain = urlparse(config.start_url).netloc
    seeds = []
    if config.wayback_seeds:
        output_callback("Fetching Wayback Machine seeds...")
        seeds.extend(await fetch_wayback_urls(domain))
    if config.common_crawl_seeds:
        output_callback("Fetching Common Crawl seeds...")
        seeds.extend(await fetch_common_crawl_urls(domain))
    output_callback(f"Loaded {len(seeds)} historical seed URLs.")
    return [url for url in seeds if is_valid_url(url)]


async def run_full_crawl_async(
    config: CrawlConfig,
    output_callback,
    is_running_func,
    manager: Optional[DownloadManager] = None,
    update_progress=None,
    page_html_fetcher=None,
    stats: Optional[CrawlStats] = None,
    pause_controller: Optional[PauseController] = None,
):
    manager = manager or DownloadManager()
    stats = stats or CrawlStats()
    pause_controller = pause_controller or PauseController(is_running_func)

    from user_output import wrap_output_callback

    output_callback = wrap_output_callback(output_callback)

    def running():
        return pause_controller() and disk_space_ok(config.disk_space_guard_mb)

    reporter = ReportWriter(config.report_dir(), config.start_url)
    base_domain = urlparse(config.start_url).netloc
    download_semaphore = asyncio.Semaphore(config.download_concurrency)

    def live_extensions():
        # Re-read each time so Pause → change settings → Resume can take effect
        return normalize_extensions(config.extensions)

    from evasion_layer import (
        evasion_from_crawl_config,
        make_httpx_hooks,
        run_decoy_warmup,
        sync_evasion_from_crawl_config,
    )
    from defense_verify import DefenseTracker, probe_defense_fingerprint, write_defense_reports

    evasion = evasion_from_crawl_config(config)
    defense = DefenseTracker(start_url=config.start_url) if getattr(config, "defense_verify", True) else None
    stats.defense_tracker = defense
    headers = config.merged_headers(evasion.base_client_headers() if evasion.config.enabled else get_request_headers())
    proxy = config.httpx_proxy()
    auth = config.httpx_auth()
    # Pass session always so hooks stay wired if stealth is re-enabled on resume
    event_hooks = make_httpx_hooks(evasion, output_callback, defense_tracker=defense)
    use_http2 = bool(getattr(config, "evasion_http2", True))

    extra_seeds = await gather_extra_seeds(config, output_callback) if running() else []
    for seed in extra_seeds:
        stats.record_url("historical", seed)
    visited = set()
    link_depths = {config.start_url: 0}

    if config.resume_checkpoint:
        data = load_checkpoint(config.checkpoint_file)
        if data and data.get("start_url") == config.start_url:
            visited, discovered, queue, link_depths = restore_sets(data)
            output_callback(f"Resumed checkpoint: {len(queue)} queued, {len(visited)} visited.")
        else:
            discovered, queue = init_crawl_state(
                config.start_url, config.restrict_domain, config.ignore_robots, extra_seeds
            )
    else:
        discovered, queue = init_crawl_state(
            config.start_url, config.restrict_domain, config.ignore_robots, extra_seeds
        )

    use_priority = config.priority_html_first
    if use_priority:
        queue = _to_priority_queue(queue)

    operations_since_checkpoint = 0
    last_stats_emit = time.time()

    if evasion.config.enabled:
        output_callback(
            f"Request stealth enabled ({evasion.effective_level()}) — "
            f"browser look-alike headers and pacing for your lab target."
        )

    async with httpx.AsyncClient(
        http2=use_http2,
        headers=headers,
        follow_redirects=True,
        proxy=proxy,
        auth=auth,
        event_hooks=event_hooks,
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    ) as client:
        if config.cookie_string:
            client.headers["Cookie"] = config.cookie_string

        def _apply_live_after_resume():
            sync_evasion_from_crawl_config(evasion, config)
            if config.cookie_string:
                client.headers["Cookie"] = config.cookie_string
            elif "Cookie" in client.headers:
                del client.headers["Cookie"]

        pause_controller.on_resume(_apply_live_after_resume)

        if defense is not None and running():
            await probe_defense_fingerprint(client, config.start_url, defense, output_callback)

        if evasion.config.enabled and evasion.config.decoy_requests and running():
            await run_decoy_warmup(client, config.start_url, evasion, output_callback)

        stats.discovered_urls.update(discovered)

        if config.distributed_redis_url:
            from distributed_queue import pop_url

            pulled = 0
            while True:
                redis_url = pop_url(config.distributed_redis_url, "crawler:queue")
                if not redis_url:
                    break
                if enqueue_discovered_url(
                    redis_url,
                    discovered,
                    queue,
                    config.output_file_path,
                    output_callback,
                    stats=stats,
                    use_priority=use_priority,
                    link_depth=0,
                    max_link_depth=config.link_depth_limit,
                    link_depths=link_depths,
                ):
                    pulled += 1
            if pulled:
                output_callback(f"Pulled {pulled} URL(s) from Redis queue")

        if config.distributed_redis_url:
            output_callback(f"Distributed mode: Redis at {config.distributed_redis_url}")

        if config.subdomain_enum and running() and not config.enum_only:
            output_callback("Enumerating subdomains...")
            baseline_length, baseline_status = await get_async_baseline(client, config.start_url)

            async def subdomain_exists(url):
                return await async_path_exists(
                    client, url, baseline_length, baseline_status, config.bypass_forbidden
                )

            subs = await enumerate_subdomains(
                base_domain,
                config.subdomain_wordlist,
                client,
                subdomain_exists,
                output_callback,
            )
            for sub_url in subs:
                stats.record_url("subdomain", sub_url)
                enqueue_discovered_url(
                    sub_url,
                    discovered,
                    queue,
                    config.output_file_path,
                    output_callback,
                    stats=stats,
                    use_priority=use_priority,
                    link_depth=0,
                    max_link_depth=config.link_depth_limit,
                    link_depths=link_depths,
                )

        checkpoint_lock = asyncio.Lock()

        async def _process_crawl_url(current_url):
            nonlocal operations_since_checkpoint, last_stats_emit
            if not running():
                return
            if _should_skip_url(current_url, visited, config.ignore_robots):
                return
            current_depth = link_depths.get(current_url, 0)
            if config.link_depth_limit and current_depth > config.link_depth_limit:
                return
            if current_url in visited:
                return
            output_callback(f"Crawling: {current_url}")
            visited.add(current_url)
            stats.pages_crawled += 1
            stats.queue_size = len(queue)
            operations_since_checkpoint += 1
            if update_progress:
                stats.session_total_estimate = stats.pages_crawled + len(queue)
                emit_download_progress(
                    update_progress,
                    max(stats.session_total_estimate, 1),
                    stats.pages_crawled,
                    f"Page {stats.pages_crawled} of ~{stats.session_total_estimate} · queue {len(queue)}",
                )
            try:
                page_html = None
                extra_urls = set()
                resp_headers = {}
                use_browser = page_html_fetcher and is_html_url(current_url)

                if use_browser:
                    fetch_result = await page_html_fetcher(client, current_url, config.deep_mirror)
                    if isinstance(fetch_result, tuple):
                        page_html = fetch_result[0]
                        dom = fetch_result[1] if len(fetch_result) > 1 else []
                        extra_urls.update(dom or [])
                    else:
                        page_html = fetch_result

                conditional = {}
                if config.incremental_mirror:
                    if current_url in stats.etag_cache:
                        conditional["If-None-Match"] = stats.etag_cache[current_url]
                    if current_url in stats.last_modified_cache:
                        conditional["If-Modified-Since"] = stats.last_modified_cache[current_url]

                new_links, body, content_type, resp_headers = await crawl_page_async(
                    client,
                    current_url,
                    visited,
                    base_domain,
                    config.restrict_domain,
                    page_html=page_html,
                    extra_urls=list(extra_urls) if extra_urls else None,
                    ignore_robots=config.ignore_robots,
                    bypass_forbidden=config.bypass_forbidden,
                    conditional_headers=conditional or None,
                )

                if resp_headers and not body and str(resp_headers.get("etag", "")):
                    stats.skipped_not_modified += 1
                    output_callback(f"Not modified (304): {current_url}")
                    return

                if resp_headers.get("etag"):
                    stats.etag_cache[current_url] = resp_headers["etag"]
                if resp_headers.get("last-modified"):
                    stats.last_modified_cache[current_url] = resp_headers["last-modified"]

                body_text = body.decode("utf-8", errors="replace") if body else ""

                if body:
                    _ingest_file_metadata(
                        stats, current_url, body, content_type, output_callback
                    )

                if config.rss_feeds and body_text:
                    for feed in extract_rss_feeds(body_text, current_url):
                        stats.record_url("rss", feed)
                        enqueue_discovered_url(
                            feed,
                            discovered,
                            queue,
                            config.output_file_path,
                            output_callback,
                            stats=stats,
                            use_priority=use_priority,
                            link_depth=current_depth + 1,
                            max_link_depth=config.link_depth_limit,
                            link_depths=link_depths,
                        )

                if config.openapi_parse:
                    for api_url in extract_openapi_urls(body_text, current_url, content_type):
                        stats.record_url("openapi_doc", api_url)
                        enqueue_discovered_url(
                            api_url,
                            discovered,
                            queue,
                            config.output_file_path,
                            output_callback,
                            stats=stats,
                            use_priority=use_priority,
                            link_depth=current_depth + 1,
                            max_link_depth=config.link_depth_limit,
                            link_depths=link_depths,
                        )
                    if "json" in content_type and ("openapi" in body_text or "swagger" in body_text):
                        for endpoint in parse_openapi_endpoints(body_text, current_url):
                            stats.record_url("openapi_endpoint", endpoint)
                            enqueue_discovered_url(
                                endpoint,
                                discovered,
                                queue,
                                config.output_file_path,
                                output_callback,
                                stats=stats,
                                use_priority=use_priority,
                                link_depth=current_depth + 1,
                                max_link_depth=config.link_depth_limit,
                                link_depths=link_depths,
                            )

                if config.js_bundle_analysis and body_text and ("javascript" in content_type or current_url.endswith(".js")):
                    for route in extract_js_routes(body_text, current_url):
                        stats.record_url("js", route)
                        enqueue_discovered_url(
                            route,
                            discovered,
                            queue,
                            config.output_file_path,
                            output_callback,
                            stats=stats,
                            use_priority=use_priority,
                            link_depth=current_depth + 1,
                            max_link_depth=config.link_depth_limit,
                            link_depths=link_depths,
                        )

                if body_text:
                    for map_url in extract_sourcemap_urls(body_text, current_url):
                        stats.record_url("sourcemap", map_url)
                        enqueue_discovered_url(
                            map_url,
                            discovered,
                            queue,
                            config.output_file_path,
                            output_callback,
                            stats=stats,
                            use_priority=use_priority,
                            link_depth=current_depth + 1,
                            max_link_depth=config.link_depth_limit,
                            link_depths=link_depths,
                        )
                    for ws_url in extract_websocket_urls(body_text, current_url):
                        stats.record_url("websocket", ws_url)

                page_host = urlparse(current_url).netloc
                _collect_passive_recon(
                    stats,
                    current_url,
                    body_text,
                    resp_headers,
                    page_host=page_host,
                    enqueue=lambda u: enqueue_discovered_url(
                        u,
                        discovered,
                        queue,
                        config.output_file_path,
                        output_callback,
                        stats=stats,
                        use_priority=use_priority,
                        link_depth=current_depth + 1,
                        max_link_depth=config.link_depth_limit,
                        link_depths=link_depths,
                    ),
                )

                # Once per host: sitemap + TLS SAN + well-known (capped)
                host_key = page_host.lower()
                if host_key and host_key not in stats._host_recon_done and running():
                    stats._host_recon_done.add(host_key)
                    try:
                        host_recon = await run_host_recon_once(
                            client, current_url, running=running
                        )
                        for san in host_recon.get("tls_sans") or []:
                            stats.record_url("tls_san", san)
                        for doc in host_recon.get("sitemap_docs") or []:
                            stats.record_url("sitemap_doc", doc)
                        for sm_url in host_recon.get("sitemap_urls") or []:
                            stats.record_url("sitemap", sm_url)
                            enqueue_discovered_url(
                                sm_url,
                                discovered,
                                queue,
                                config.output_file_path,
                                output_callback,
                                stats=stats,
                                use_priority=use_priority,
                                link_depth=current_depth + 1,
                                max_link_depth=config.link_depth_limit,
                                link_depths=link_depths,
                            )
                        for wk in host_recon.get("well_known") or []:
                            stats.record_dict_rows(
                                "well_known_hits",
                                [wk],
                                ("url", "status"),
                            )
                            if wk.get("url"):
                                stats.record_finding(
                                    "well_known",
                                    "info",
                                    wk["url"],
                                    f"{wk.get('evidence', 'well-known endpoint')} [HTTP {wk.get('status', '?')}]",
                                    evidence=wk.get("evidence"),
                                )
                        if host_recon.get("tls_sans"):
                            output_callback(
                                f"TLS SAN inventory ({host_key}): {len(host_recon['tls_sans'])} name(s)"
                            )
                        if host_recon.get("sitemap_urls"):
                            output_callback(
                                f"Sitemap URLs ({host_key}): {len(host_recon['sitemap_urls'])} page(s)"
                            )
                        if host_recon.get("well_known"):
                            output_callback(
                                f"Well-known hits ({host_key}): {len(host_recon['well_known'])}"
                            )
                    except Exception as error:
                        output_callback(f"Host recon skipped for {host_key}: {error}")

                forms = extract_forms(body_text, current_url, content_type) if config.form_discovery else []
                if forms:
                    stats.forms.extend(forms)
                    if config.form_submit_probe:
                        await _probe_form_actions(client, forms, output_callback, stats)

                login_why = detect_login_surface(current_url, body_text, forms)
                if login_why:
                    stats.record_url("login", f"{current_url}  ({login_why})")

                if config.security_scan:
                    try:
                        status_code = int(resp_headers.get("_status_code") or 200)
                    except (TypeError, ValueError):
                        status_code = 200
                    await _run_security_checks(
                        client,
                        config,
                        stats,
                        current_url,
                        body_text,
                        forms,
                        resp_headers,
                        output_callback,
                        status_code=status_code,
                        raw_body=body,
                    )

                if config.broken_link_report and new_links:
                    await _check_broken_links(
                        client,
                        stats,
                        new_links,
                        base_domain,
                        config.restrict_domain,
                        config.broken_link_sample_size,
                    )

                if config.download_files and config.download_dir:
                    if config.duplicate_content_detection and stats.is_duplicate_content(body):
                        output_callback(f"Skipped duplicate content: {current_url}")
                    else:
                        from content_filters import should_skip_download

                        skip_reason = should_skip_download(current_url, content_type, len(body), config)
                        if skip_reason:
                            output_callback(f"Skipped download: {current_url} ({skip_reason})")
                        else:
                            async with download_semaphore:
                                asset_urls, _saved_path = await save_body_async(
                                    current_url,
                                    body,
                                    config.download_dir,
                                    output_callback,
                                    live_extensions(),
                                    manager,
                                    config.preserve_structure,
                                    config.rewrite_local,
                                    content_type,
                                    config.save_server_side_as_txt,
                                    update_progress,
                                    return_asset_urls=True,
                                )
                            stats.bytes_downloaded += len(body)
                            if getattr(config, "mirror_page_assets", True) and asset_urls:
                                await download_referenced_assets(
                                    client,
                                    current_url,
                                    asset_urls,
                                    config.download_dir,
                                    output_callback,
                                    manager=manager,
                                    extensions=None,
                                    preserve_structure=config.preserve_structure,
                                    rewrite_local=config.rewrite_local,
                                    save_server_side_as_txt=config.save_server_side_as_txt,
                                    download_semaphore=download_semaphore,
                                    bypass_forbidden=config.bypass_forbidden,
                                    update_progress=update_progress,
                                    running=running,
                                    on_body_callback=lambda u, b, ct: _ingest_file_metadata(
                                        stats, u, b, ct, output_callback
                                    ),
                                )
                            if update_progress:
                                emit_download_progress(
                                    update_progress,
                                    max(stats.bytes_downloaded, 1),
                                    stats.bytes_downloaded,
                                    f"Total downloaded: {format_byte_size(stats.bytes_downloaded)}",
                                )

                if config.warc_export and body:
                    reporter.write_warc_record(current_url, 200, {}, body)

                for link in new_links:
                    enqueue_discovered_url(
                        link,
                        discovered,
                        queue,
                        config.output_file_path,
                        output_callback,
                        stats=stats,
                        use_priority=use_priority,
                        link_depth=current_depth + 1,
                        max_link_depth=config.link_depth_limit,
                        link_depths=link_depths,
                    )

            except Exception as error:
                stats.errors += 1
                output_callback(f"Error accessing {current_url}: {error}")

            if time.time() - last_stats_emit > 3:
                output_callback(stats.format_friendly_line())
                last_stats_emit = time.time()

            if operations_since_checkpoint >= config.checkpoint_interval:
                async with checkpoint_lock:
                    if operations_since_checkpoint >= config.checkpoint_interval:
                        _persist_checkpoint(config, visited, discovered, queue, link_depths, use_priority)
                        operations_since_checkpoint = 0

        if not config.enum_only:
            if config.crawl_concurrency > 1:
                await run_concurrent_bfs(
                    queue=queue,
                    use_priority=use_priority,
                    running=running,
                    crawl_concurrency=config.crawl_concurrency,
                    process_url=_process_crawl_url,
                )
            else:
                while queue and running():
                    if use_priority:
                        _, _, current_url = heapq.heappop(queue)
                    else:
                        current_url = queue.popleft()
                    await _process_crawl_url(current_url)
        elif config.enum_only:
            output_callback("=== Enum-only mode (Gobuster-beater) — skipping crawl phase ===")

        if running():
            await _run_full_enum_suite(
                config,
                client,
                output_callback,
                running,
                manager,
                live_extensions,
                download_semaphore,
                discovered,
                queue,
                link_depths,
                stats,
                use_priority,
                update_progress,
                list(discovered) + extra_seeds,
            )

    _persist_checkpoint(config, visited, discovered, queue, link_depths, use_priority)

    if config.distributed_redis_url:
        from distributed_queue import push_urls
        push_urls(config.distributed_redis_url, "crawler:queue", list(discovered))

    output_callback("\nGenerating reports...")
    from scan_setup_report import config_to_report_meta

    report_paths = reporter.write_all(
        stats,
        {
            "search_conclusion_report": config.search_conclusion_report,
            "html_report": config.html_report,
            "json_report": config.json_report,
            "sqlite_export": config.sqlite_export,
            "csv_export": config.csv_export,
        },
        config_meta=config_to_report_meta(config),
    )
    if stats.defense_tracker is not None:
        defense_paths = write_defense_reports(
            stats.defense_tracker, config.report_dir(), reporter.base_name
        )
        report_paths.update(defense_paths)
        output_callback("\n" + stats.defense_tracker.format_plain_report())
        if defense_paths.get("defense_html"):
            output_callback(f"Defense report (web page): {defense_paths['defense_html']}")
        if defense_paths.get("defense_txt"):
            output_callback(f"Defense report (text): {defense_paths['defense_txt']}")

    if reporter.last_conclusion:
        output_callback("\n" + reporter.last_conclusion.get("text", ""))
    if report_paths.get("search_report_html"):
        output_callback(f"\nSearch report (HTML): {report_paths['search_report_html']}")
    if report_paths.get("search_report_txt"):
        output_callback(f"Search report (text): {report_paths['search_report_txt']}")
    output_callback(stats.format_friendly_line())
    output_callback(f"All reports saved to: {config.report_dir()}")

    host = urlparse(config.start_url).netloc
    export_dir = config.report_dir()
    stats.discovered_urls.update(discovered)
    if config.site_graph_export:
        from feature_exports import write_site_graph_html

        path = write_site_graph_html(stats, config.start_url, os.path.join(export_dir, f"{reporter.base_name}_sitemap.html"))
        output_callback(f"Site map graph: {path}")
        report_paths["site_graph"] = path
    if config.burp_export and stats.findings:
        from feature_exports import write_burp_xml

        path = write_burp_xml(stats.findings, os.path.join(export_dir, f"{reporter.base_name}_burp.xml"), host)
        output_callback(f"Burp export: {path}")
        report_paths["burp"] = path
    if config.zap_export and stats.findings:
        from feature_exports import write_zap_json

        path = write_zap_json(stats.findings, os.path.join(export_dir, f"{reporter.base_name}_zap.json"))
        output_callback(f"ZAP export: {path}")
        report_paths["zap"] = path
    if config.nuclei_scan:
        from integrations_nuclei import run_nuclei_scan

        run_nuclei_scan(
            list(stats.discovered_urls) or [config.start_url],
            export_dir,
            output_callback,
            config.nuclei_severity,
        )

    return stats, report_paths, reporter.last_conclusion


async def _run_full_enum_suite(
    config,
    client,
    output_callback,
    running,
    manager,
    extensions,
    download_semaphore,
    discovered,
    queue,
    link_depths,
    stats,
    use_priority,
    update_progress,
    seed_urls,
):
    from enum_engine import parse_int_list

    output_callback("\n=== Pro directory enumeration ===")

    def resolve_extensions():
        if callable(extensions):
            return extensions()
        return extensions

    async def on_enum_hit(probe):
        if not (config.enum_auto_crawl_hits or config.enum_auto_vuln_scan):
            return
        try:
            response = await client.get(probe.url, timeout=12, follow_redirects=True)
            body_text = (response.content or b"").decode("utf-8", errors="replace")
            resp_headers = dict(response.headers)
            resp_headers["_status_code"] = str(response.status_code)
            forms = extract_forms(body_text, probe.url, resp_headers.get("content-type", "")) if body_text else []
            if config.enum_auto_vuln_scan:
                prev = config.security_scan
                config.security_scan = True
                await _run_security_checks(
                    client,
                    config,
                    stats,
                    probe.url,
                    body_text,
                    forms,
                    resp_headers,
                    output_callback,
                    status_code=response.status_code,
                    raw_body=response.content or b"",
                )
                config.security_scan = prev
        except Exception as error:
            output_callback(f"Hit follow-up scan failed: {probe.url} ({error})")

    await run_pro_directory_enum(
        config,
        client,
        output_callback,
        running,
        stats=stats,
        discovered=discovered,
        queue=queue,
        link_depths=link_depths,
        use_priority=use_priority,
        manager=manager,
        extensions=resolve_extensions(),
        download_semaphore=download_semaphore,
        update_progress=update_progress,
        seed_urls=seed_urls,
        technologies=dict(stats.technologies),
        merge_wordlists_fn=merge_wordlists,
        on_hit_callback=on_enum_hit,
    )

    if config.vhost_enum and running():
        baseline_length, baseline_status = await get_async_baseline(client, config.start_url)
        wl = config.vhost_wordlist or config.subdomain_wordlist
        vhosts = await enumerate_vhosts(
            config.start_url,
            wl,
            client,
            baseline_length=baseline_length,
            baseline_status=baseline_status,
            running=running,
            output_callback=output_callback,
            status_filter=build_status_filter(config),
            exclude_lengths=parse_int_list(config.exclude_lengths),
            concurrency=config.enum_concurrency,
        )
        for host in vhosts:
            stats.record_url("vhost", host)

    domain = urlparse(config.start_url).netloc
    bucket_wl = config.wordlist_file
    if not config.use_wordlist and not os.path.isfile(bucket_wl):
        bucket_wl = config.subdomain_wordlist
    if config.s3_enum and running():
        for url in await enumerate_s3_buckets(
            domain, bucket_wl, client, running=running, output_callback=output_callback, concurrency=config.enum_concurrency
        ):
            stats.record_url("s3", url)
    if config.gcs_enum and running():
        for url in await enumerate_gcs_buckets(
            domain, bucket_wl, client, running=running, output_callback=output_callback, concurrency=config.enum_concurrency
        ):
            stats.record_url("gcs", url)


def _ingest_file_metadata(stats, url, body, content_type, output_callback=None):
    """Extract PDF/Office/image/OLE metadata when body looks like a document."""
    if not body or not looks_like_document(url, content_type or "", body):
        return
    try:
        record = extract_file_metadata(url, body, content_type or "")
    except Exception as error:
        if output_callback:
            output_callback(f"File metadata parse failed: {url} ({error})")
        return
    if not record or not stats.record_file_metadata(record):
        return
    interesting = record.get("interesting") or {}
    if output_callback and interesting:
        preview = ", ".join(f"{k}={v}" for k, v in list(interesting.items())[:4])
        output_callback(f"File metadata ({record.get('kind')}): {url} — {preview}")
    for category, severity, detail, evidence in metadata_findings(record):
        stats.record_finding(category, severity, url, detail, evidence=evidence)


def _collect_passive_recon(stats, url, body_text, headers, *, page_host: str, enqueue):
    """Zero-request extractors from an already-fetched page."""
    text = body_text or ""
    host = (page_host or urlparse(url).netloc or "").lower()

    for email in extract_emails(text):
        stats.record_url("email", email)
    for phone in extract_phones(text):
        stats.record_url("phone", phone)
    for internal in extract_internal_hosts(text, page_host=host):
        stats.record_url("internal_host", internal)
    for cloud in extract_cloud_urls(text):
        stats.record_url("cloud", cloud)
        # Target = cloud URL so host-page spam collapses via dedupe key
        stats.record_finding(
            "cloud_url",
            "info",
            cloud,
            "Cloud service URL referenced in page/script content",
            evidence=cloud,
        )
    for comment in extract_interesting_comments(text):
        stats.record_url("comment", f"{url} :: {comment}")
    for sink in extract_dom_sinks(text):
        # Inventory only — sink+input proximity already gated; avoid finding spam
        stats.record_url("dom_sink", f"{url} :: {sink}")

    stats.record_dict_rows(
        "third_party_scripts",
        extract_third_party_scripts(text, page_host=host),
        ("host", "vendor"),
    )
    rels = extract_link_rels(text, url)
    stats.record_dict_rows("link_rels", rels, ("rel", "url"))
    for row in rels:
        if row.get("rel") in ("canonical", "manifest", "alternate", "search") and row.get("url"):
            enqueue(row["url"])
    for row in extract_link_header_urls(headers or {}, url):
        stats.record_dict_rows("link_rels", [row], ("rel", "url"))
        if row.get("url"):
            enqueue(row["url"])

    hdr_inv = inventory_security_headers(headers or {})
    if hdr_inv:
        stats.record_security_headers(host, hdr_inv)


async def _run_security_checks(
    client,
    config,
    stats,
    url,
    body_text,
    forms,
    headers,
    output_callback=None,
    *,
    status_code: int = 200,
    raw_body: bytes | None = None,
):
    def emit(category, severity, target, detail, evidence=None):
        stats.record_finding(category, severity, target, detail, evidence=evidence)
        if output_callback and severity in ("critical", "high", "medium"):
            extra = f" | evidence={evidence}" if evidence else ""
            output_callback(f"FINDING [{severity}] {category}: {target} — {detail}{extra}")

    content_type = (headers or {}).get("content-type", "")
    body_for_gate = raw_body if raw_body is not None else (body_text or "")

    if config.secret_scan:
        for label, severity, detail, evidence in scan_secrets(body_text, url):
            emit("secrets_exposure", severity, url, f"{label}: {detail}", evidence=evidence)
    sensitive = scan_sensitive_path(url)
    if sensitive and config.sensitive_file_highlights:
        confirmed = True
        evidence = None
        if needs_content_gate(url):
            proof = validate_sensitive_content(
                url, status=status_code, body=body_for_gate, content_type=content_type
            )
            if not proof:
                confirmed = False
            else:
                evidence = proof
        if confirmed:
            if url not in stats.sensitive_urls:
                stats.sensitive_urls.append(url)
            emit("sensitive_path", "high", url, sensitive, evidence=evidence)
    if config.header_audit:
        for cat, severity, detail in audit_security_headers(headers or {}, url):
            emit(cat, severity, url, detail)
    cookies = inventory_cookies(headers or {})
    if cookies:
        stats.record_cookie_inventory(cookies)
    if config.tech_fingerprint:
        for tech in fingerprint_technology(headers or {}, body_text):
            stats.technologies[tech] += 1
    if config.param_discovery:
        stats.parameters.extend(discover_parameters(url, body_text, forms))
    if config.cors_check:
        cors_issue = await check_cors(client, url)
        if cors_issue:
            sev = "high" if "credentials" in cors_issue.lower() else "medium"
            emit("cors", sev, url, cors_issue)
    # OPTIONS/TRACE once per host
    host = urlparse(url).netloc.lower()
    if host and host not in stats._http_methods_hosts and config.security_scan and config.vuln_scan:
        stats._http_methods_hosts.add(host)
        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}/"
        for category, severity, detail in await probe_http_methods(client, origin):
            emit(category, severity, origin, detail)
    if config.security_scan and config.vuln_scan:
        for category, severity, detail in run_passive_vuln_scan(
            url, body_text, forms, headers or {}, content_type
        ):
            emit(category, severity, url, detail)
        if config.vuln_active_probe:
            for category, severity, detail in await run_active_vuln_probes(
                client,
                url,
                forms=forms,
                max_params=config.active_probe_max_params,
                max_forms=config.active_probe_max_forms,
            ):
                emit(category, severity, url, detail)


async def _probe_form_actions(client, forms, output_callback, stats):
    for form in forms[:10]:
        action = form.get("action")
        if not action or form.get("method") != "GET":
            continue
        try:
            response = await client.get(action, timeout=10)
            stats.record_finding(
                "form_probe",
                "info",
                action,
                f"Form GET probe returned HTTP {response.status_code}",
            )
            output_callback(f"Form probe: {action} -> {response.status_code}")
        except httpx.HTTPError as error:
            output_callback(f"Form probe failed: {action} ({error})")


async def _check_broken_links(client, stats, links, base_domain, restrict_domain, sample_size=30):
    from crawler_common import should_follow_url

    if sample_size == 0:
        sample_size = len(links)
    for link in list(links)[:sample_size]:
        if not should_follow_url(link, base_domain, restrict_domain):
            continue
        try:
            response = await client.head(link, timeout=8, follow_redirects=True)
            if response.status_code >= 400:
                stats.broken_links.append({"url": link, "status": str(response.status_code)})
        except httpx.HTTPError:
            stats.broken_links.append({"url": link, "status": "error"})


def _persist_checkpoint(config, visited, discovered, queue, link_depths, use_priority):
    if use_priority:
        flat_queue = [url for _, _, url in queue]
    elif hasattr(queue, "copy"):
        flat_queue = list(queue)
    else:
        flat_queue = list(queue)
    save_checkpoint(
        config.checkpoint_file,
        list(visited),
        list(discovered),
        flat_queue,
        start_url=config.start_url,
        link_depths=link_depths,
    )

