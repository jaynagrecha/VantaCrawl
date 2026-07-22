"""HTML/JSON/SQLite/CSV reports, WARC export, screenshots."""

from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
import time
from html import escape
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from crawl_stats import CrawlStats
from report_html import render_search_report_html, url_table_html
from search_report import build_search_conclusion


def report_entity_slug(value: str, *, max_len: int = 48) -> str:
    """Filesystem-safe slug for scan title / entity labels (keeps letters, digits, . _ -)."""
    text = (value or "").strip()
    text = re.sub(r"[^\w.\-]+", "-", text, flags=re.UNICODE)
    text = re.sub(r"-{2,}", "-", text).strip("-._")
    return (text[:max_len].strip("-._") or "scan")


def build_report_base_name(start_url: str, title: str = "", *, timestamp: Optional[str] = None) -> str:
    """Name reports as `{title}__{host}_{timestamp}` when a title is set, else `{host}_{timestamp}`."""
    host = (urlparse(start_url).netloc or "").replace(":", "_").strip(".") or "target"
    stamp = timestamp or time.strftime("%Y%m%d_%H%M%S")
    title_slug = report_entity_slug(title) if (title or "").strip() else ""
    if title_slug and title_slug.lower() != host.lower():
        return f"{title_slug}__{host}_{stamp}"
    return f"{host}_{stamp}"


class ReportWriter:
    def __init__(self, report_dir: str, start_url: str, title: str = ""):
        self.report_dir = report_dir
        self.start_url = start_url
        self.title = (title or "").strip()
        self.host = urlparse(start_url).netloc.replace(":", "_") or "target"
        self.timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.base_name = build_report_base_name(start_url, self.title, timestamp=self.timestamp)
        os.makedirs(report_dir, exist_ok=True)
        self.warc_path = os.path.join(report_dir, f"{self.base_name}.warc")
        self._warc_handle = None
        self._screenshot_dir = os.path.join(report_dir, "screenshots", self.base_name)
        os.makedirs(self._screenshot_dir, exist_ok=True)
        self.last_paths: Dict[str, str] = {}
        self.last_conclusion: Dict[str, Any] = {}

    def write_all(self, stats: CrawlStats, config_flags: dict, config_meta: Optional[dict] = None) -> Dict[str, str]:
        paths = {}
        config_meta = config_meta or {}

        if config_flags.get("search_conclusion_report", True):
            paths.update(self.write_search_report(stats, config_meta))

        if config_flags.get("json_report", True):
            paths["json"] = self.write_json(stats)

        if config_flags.get("csv_export", True):
            paths["csv"] = self.write_csv(stats)

        if config_flags.get("sqlite_export", True):
            paths["sqlite"] = self.write_sqlite(stats)

        if config_flags.get("html_report", True):
            paths["html"] = self.write_html(stats, self.last_conclusion)

        if config_flags.get("assessment_report", True):
            paths.update(
                self.write_assessment_report(
                    stats,
                    config_meta,
                    conclusion=self.last_conclusion or None,
                )
            )

        self.close_warc()
        self.last_paths = paths
        return paths

    def write_search_report(self, stats: CrawlStats, config_meta: dict) -> Dict[str, str]:
        conclusion = build_search_conclusion(
            stats,
            self.start_url,
            profile=config_meta.get("profile", "full"),
            download_enabled=config_meta.get("download_files", False),
            security_enabled=config_meta.get("security_scan", True),
            output_file=config_meta.get("output_file", ""),
            download_dir=config_meta.get("download_dir", ""),
            config_meta=config_meta,
        )
        self.last_conclusion = conclusion

        txt_path = os.path.join(self.report_dir, f"{self.base_name}_SEARCH_REPORT.txt")
        with open(txt_path, "w", encoding="utf-8") as handle:
            handle.write(conclusion["text"])

        html_path = os.path.join(self.report_dir, f"{self.base_name}_SEARCH_REPORT.html")
        with open(html_path, "w", encoding="utf-8") as handle:
            handle.write(
                self._search_report_html(
                    conclusion,
                    stats,
                    profile=config_meta.get("profile", "full"),
                )
            )

        return {
            "search_report_txt": txt_path,
            "search_report_html": html_path,
        }

    def _url_list_html(self, urls, *, limit: int = 40) -> str:
        return url_table_html(urls, limit=limit)

    def _search_report_html(self, conclusion: dict, stats: CrawlStats, profile: str = "full") -> str:
        return render_search_report_html(
            start_url=self.start_url,
            base_name=self.base_name,
            conclusion=conclusion,
            stats=stats,
            profile=profile,
        )

    def write_assessment_report(
        self,
        stats: CrawlStats,
        config_meta: Optional[dict] = None,
        *,
        conclusion: Optional[dict] = None,
    ) -> Dict[str, str]:
        from assessment_html import render_assessment_html
        from assessment_report import build_assessment_document

        meta = dict(config_meta or {})
        doc = build_assessment_document(
            stats,
            self.start_url,
            config_meta=meta,
            conclusion=conclusion,
            job_title=str(meta.get("title") or ""),
            mode=str(meta.get("mode") or meta.get("profile") or ""),
        )
        html_path = os.path.join(self.report_dir, f"{self.base_name}_ASSESSMENT_REPORT.html")
        tech_name = f"{self.base_name}_SEARCH_REPORT.html"
        with open(html_path, "w", encoding="utf-8") as handle:
            handle.write(render_assessment_html(doc, technical_report_name=tech_name))

        # Compact plain-text executive companion
        txt_path = os.path.join(self.report_dir, f"{self.base_name}_ASSESSMENT_REPORT.txt")
        lines = [
            f"{doc.get('product')} — {doc.get('document_title')}",
            f"Target: {doc.get('start_url')}",
            f"Generated: {doc.get('generated_at')}",
            f"Overall risk: {doc.get('risk_level')}",
            "",
            str(doc.get("exec_headline") or ""),
            "",
            "Priority points:",
        ]
        for item in doc.get("top_executive_points") or []:
            lines.append(f"- {item}")
        lines.extend(["", "Remediation roadmap:"])
        for item in doc.get("roadmap") or []:
            lines.append(f"- [{item.get('priority')}] {item.get('item')}")
        lines.append("")
        with open(txt_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))

        return {
            "assessment_report_html": html_path,
            "assessment_report_txt": txt_path,
        }

    def write_json(self, stats: CrawlStats) -> str:
        path = os.path.join(self.report_dir, f"{self.base_name}.json")
        payload = stats.snapshot()
        payload["findings"] = stats.findings
        payload["broken_links"] = stats.broken_links
        payload["sensitive_urls"] = stats.sensitive_urls
        payload["forms"] = stats.forms
        payload["parameters"] = stats.parameters[:500]
        payload["discovered_urls"] = sorted(getattr(stats, "discovered_urls", set()))
        payload["enum_hit_urls"] = list(getattr(stats, "enum_hit_urls", []))
        payload["historical_seed_urls"] = list(getattr(stats, "historical_seed_urls", []))
        payload["subdomain_urls"] = list(getattr(stats, "subdomain_urls", []))
        payload["js_route_urls"] = list(getattr(stats, "js_route_urls", []))
        payload["openapi_doc_urls"] = list(getattr(stats, "openapi_doc_urls", []))
        payload["openapi_endpoints"] = list(getattr(stats, "openapi_endpoints", []))
        payload["api_endpoints"] = list(getattr(stats, "api_endpoints", []) or [])
        payload["api_docs"] = list(getattr(stats, "api_docs", []) or [])
        payload["api_graphql_operations"] = list(getattr(stats, "api_graphql_operations", []) or [])
        payload["rss_feed_urls"] = list(getattr(stats, "rss_feed_urls", []))
        payload["s3_buckets"] = list(getattr(stats, "s3_buckets", []))
        payload["gcs_buckets"] = list(getattr(stats, "gcs_buckets", []))
        payload["vhost_hits"] = list(getattr(stats, "vhost_hits", []))
        if self.last_conclusion:
            payload["conclusion"] = {
                "verdict_title": self.last_conclusion.get("verdict_title"),
                "verdict_body": self.last_conclusion.get("verdict_body"),
                "severity_counts": self.last_conclusion.get("severity_counts"),
            }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        return path

    def write_csv(self, stats: CrawlStats) -> str:
        path = os.path.join(self.report_dir, f"{self.base_name}_findings.csv")
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["category", "severity", "url", "detail", "evidence"])
            writer.writeheader()
            for row in stats.findings:
                writer.writerow({k: row.get(k, "") for k in writer.fieldnames})
        return path

    def write_sqlite(self, stats: CrawlStats) -> str:
        path = os.path.join(self.report_dir, f"{self.base_name}.db")
        conn = sqlite3.connect(path)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS findings (category TEXT, severity TEXT, url TEXT, detail TEXT, ts REAL)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS summary (key TEXT PRIMARY KEY, value TEXT)"
        )
        conn.executemany(
            "INSERT INTO findings VALUES (?,?,?,?,?)",
            [(f["category"], f["severity"], f["url"], f["detail"], f.get("time", 0)) for f in stats.findings],
        )
        if self.last_conclusion:
            conn.execute(
                "INSERT OR REPLACE INTO summary VALUES (?, ?)",
                ("verdict", self.last_conclusion.get("verdict_title", "")),
            )
            conn.execute(
                "INSERT OR REPLACE INTO summary VALUES (?, ?)",
                ("conclusion", self.last_conclusion.get("verdict_body", "")),
            )
        conn.commit()
        conn.close()
        return path

    def write_html(self, stats: CrawlStats, conclusion: Optional[dict] = None) -> str:
        path = os.path.join(self.report_dir, f"{self.base_name}.html")
        snap = stats.snapshot()
        conclusion = conclusion or self.last_conclusion
        verdict_block = ""
        if conclusion:
            verdict_block = f"""
<h2>Executive conclusion</h2>
<div style="background:#f0f6ff;border-left:4px solid #0969da;padding:1rem;margin-bottom:1.5rem;">
  <strong>{escape(conclusion.get('verdict_title', ''))}</strong>
  <p>{escape(conclusion.get('verdict_body', ''))}</p>
</div>"""

        rows = "".join(
            f"<tr><td>{escape(f['severity'])}</td><td>{escape(f['category'])}</td>"
            f"<td><a href='{escape(f['url'])}'>{escape(f['url'][:80])}</a></td>"
            f"<td>{escape(f['detail'])}</td></tr>"
            for f in stats.findings[:500]
        )
        tech = ", ".join(f"{k} ({v})" for k, v in stats.technologies.most_common(15))
        html = f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>Crawl Report - {escape(self.start_url)}</title>
<style>body{{font-family:sans-serif;margin:2em;max-width:960px}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:6px;text-align:left}}</style></head>
<body><h1>Detailed Crawl Report</h1><p>Target: {escape(self.start_url)}</p>
<p><a href="{escape(self.base_name + '_SEARCH_REPORT.html')}">View readable Search Report</a></p>
{verdict_block}
<h2>Summary</h2><ul>
<li>Pages crawled: {snap['pages_crawled']}</li>
<li>Links found: {snap['links_found']}</li>
<li>Enum hits: {snap['enum_hits']}</li>
<li>Findings: {snap['findings_count']}</li>
<li>Broken links: {snap['broken_links_count']}</li>
<li>Duration: {snap['elapsed_seconds']}s</li>
</ul><h2>Technologies</h2><p>{escape(tech or 'None detected')}</p>
<h2>Security Findings</h2><table><tr><th>Severity</th><th>Category</th><th>URL</th><th>Detail</th></tr>{rows or '<tr><td colspan=4>None</td></tr>'}</table>
</body></html>"""
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(html)
        return path

    def open_warc(self):
        if self._warc_handle is None:
            self._warc_handle = open(self.warc_path, "wb")

    def write_warc_record(self, url: str, status: int, headers: dict, body: bytes):
        if self._warc_handle is None:
            self.open_warc()
        header_block = (
            f"WARC/1.0\r\nWARC-Type: response\r\nWARC-Target-URI: {url}\r\n"
            f"Content-Type: application/http; msgtype=response\r\n"
            f"Content-Length: {len(body) + 100}\r\n\r\n"
            f"HTTP/1.1 {status}\r\n"
        ).encode("utf-8")
        for key, value in headers.items():
            header_block += f"{key}: {value}\r\n".encode("utf-8")
        header_block += b"\r\n"
        self._warc_handle.write(header_block + body + b"\r\n\r\n")

    def close_warc(self):
        if self._warc_handle:
            self._warc_handle.close()
            self._warc_handle = None

    def screenshot_path(self, url: str) -> str:
        safe = urlparse(url).path.replace("/", "_")[:80] or "root"
        return os.path.join(self._screenshot_dir, f"{safe}.png")


def write_stats_reports(
    stats: CrawlStats,
    *,
    report_dir: str,
    start_url: str,
    title: str = "",
    config=None,
    output_callback=None,
) -> Dict[str, str]:
    """Write assessment/search/JSON/CSV reports from whatever CrawlStats holds so far.

    Used on normal completion and on stop/cancel/fail so partial results still get a full report.
    """
    cb = output_callback or (lambda _msg: None)
    reporter = ReportWriter(report_dir, start_url, title=title or "")
    config_meta: Dict[str, Any] = {}
    try:
        from scan_setup_report import config_to_report_meta

        if config is not None:
            config_meta = config_to_report_meta(config)
            config_meta.setdefault("mode", getattr(config, "profile", "full"))
            if getattr(config, "report_title", ""):
                config_meta["title"] = str(config.report_title)
    except Exception:
        config_meta = {"title": title or "", "start_url": start_url}

    flags = {
        "search_conclusion_report": True if config is None else bool(getattr(config, "search_conclusion_report", True)),
        "html_report": True if config is None else bool(getattr(config, "html_report", True)),
        "json_report": True if config is None else bool(getattr(config, "json_report", True)),
        "sqlite_export": True if config is None else bool(getattr(config, "sqlite_export", True)),
        "csv_export": True if config is None else bool(getattr(config, "csv_export", True)),
        "assessment_report": True if config is None else bool(getattr(config, "assessment_report", True)),
    }
    cb("\nGenerating reports...")
    # Owner-facing Bot Manager presence / unchallenged-gap findings (detection only)
    try:
        from defense_verify import inject_bot_management_findings

        n = inject_bot_management_findings(stats)
        if n:
            cb(f"Added {n} bot-management hardening finding(s) from defense verification.")
    except Exception as exc:
        cb(f"Bot-management findings skipped: {exc}")
    paths = reporter.write_all(stats, flags, config_meta=config_meta)

    if getattr(stats, "defense_tracker", None) is not None:
        try:
            from defense_verify import write_defense_reports

            defense_paths = write_defense_reports(
                stats.defense_tracker, report_dir, reporter.base_name
            )
            paths.update(defense_paths)
            cb("\n" + stats.defense_tracker.format_plain_report())
            if defense_paths.get("defense_html"):
                cb(f"Defense report (web page): {defense_paths['defense_html']}")
            if defense_paths.get("defense_txt"):
                cb(f"Defense report (text): {defense_paths['defense_txt']}")
        except Exception as exc:
            cb(f"Defense report skipped: {exc}")

    if reporter.last_conclusion:
        cb("\n" + (reporter.last_conclusion.get("text") or ""))
    try:
        setattr(stats, "last_report_conclusion", reporter.last_conclusion)
    except Exception:
        pass
    if paths.get("assessment_report_html"):
        cb(f"\nAssessment report (HTML): {paths['assessment_report_html']}")
    if paths.get("assessment_report_txt"):
        cb(f"Assessment report (text): {paths['assessment_report_txt']}")
    if paths.get("search_report_html"):
        cb(f"Technical search report (HTML): {paths['search_report_html']}")
    if paths.get("search_report_txt"):
        cb(f"Technical search report (text): {paths['search_report_txt']}")
    try:
        cb(stats.format_friendly_line())
    except Exception:
        pass
    cb(f"All reports saved to: {report_dir}")
    return paths


FINDINGS_SNAPSHOT_NAME = "findings_snapshot.json"


def write_findings_snapshot(report_dir: str | Path, stats: CrawlStats) -> str:
    """Persist full findings so stop/force-cancel can still build assessment reports."""
    import json
    from pathlib import Path as _Path

    root = _Path(report_dir)
    root.mkdir(parents=True, exist_ok=True)
    path = root / FINDINGS_SNAPSHOT_NAME
    elapsed = 0.0
    try:
        elapsed = float(stats.elapsed_seconds()) if hasattr(stats, "elapsed_seconds") else 0.0
    except Exception:
        elapsed = 0.0
    queue_size = int(getattr(stats, "queue_size", 0) or 0)
    enum_total = int(getattr(stats, "enum_words_total", 0) or 0)
    enum_done = int(getattr(stats, "enum_words_tested", 0) or 0)
    directory_enum_enabled = enum_total > 0 or bool(getattr(stats, "enum_started_at", None))
    crawl_complete = queue_size <= 0 and int(getattr(stats, "pages_crawled", 0) or 0) > 0
    enum_complete = (not directory_enum_enabled) or (
        enum_total > 0 and enum_done >= enum_total
    )
    finished = bool(getattr(stats, "finished_at", None))
    if finished and crawl_complete and enum_complete:
        scan_status = "final"
    elif finished:
        scan_status = "stopped"
    else:
        scan_status = "partial"
    try:
        from report_status import scan_status_from_stats

        status_meta = scan_status_from_stats(stats)
        scan_status = str(status_meta.get("scan_status") or scan_status)
    except Exception:
        status_meta = {
            "scan_status": scan_status,
            "phase": "crawl" if not finished else "complete",
            "completion_percent": 100.0 if scan_status == "final" else 0.0,
            "remaining_jobs": queue_size,
            "report_generated_during_scan": scan_status == "partial",
            "directory_enum_enabled": directory_enum_enabled,
            "directory_enum_started": bool(getattr(stats, "enum_started_at", None)),
            "directory_enum_message": "",
            "is_final": scan_status == "final",
        }

    payload = {
        "pages_crawled": int(getattr(stats, "pages_crawled", 0) or 0),
        "links_found": int(getattr(stats, "links_found", 0) or 0),
        "errors": int(getattr(stats, "errors", 0) or 0),
        "bytes_downloaded": int(getattr(stats, "bytes_downloaded", 0) or 0),
        "queue_size": queue_size,
        "started_at": float(getattr(stats, "started_at", 0) or 0) or None,
        "finished_at": float(getattr(stats, "finished_at", 0) or 0) or None,
        "elapsed_seconds": round(elapsed, 1),
        "discovered_url_count": len(getattr(stats, "discovered_urls", set()) or set()),
        "discovered_urls_exported": min(len(getattr(stats, "discovered_urls", set()) or set()), 5000),
        "discovered_url_export_cap": 5000,
        "discovered_urls": list(getattr(stats, "discovered_urls", set()) or set())[:5000],
        "discovered_urls_note": (
            "discovered_urls list is capped at 5000 for export; discovered_url_count is the full total."
        ),
        "route_templates": list(getattr(stats, "route_templates", []) or [])[:500],
        "protection_artifacts": list(getattr(stats, "protection_artifacts", []) or [])[:200],
        "form_count": len(getattr(stats, "forms", []) or []),
        "login_count": len(getattr(stats, "login_surfaces", []) or []),
        "js_route_count": len(getattr(stats, "js_route_urls", []) or []),
        "cookie_count": len(getattr(stats, "cookie_inventory", []) or []),
        "requests_queued": int(getattr(stats, "requests_queued", 0) or 0),
        "static_assets_recorded": int(getattr(stats, "static_assets_recorded", 0) or 0),
        "forms_deduped": int(getattr(stats, "forms_deduped", 0) or 0),
        "internal_host_count": len(getattr(stats, "internal_hosts", []) or []),
        "enum_hits": int(getattr(stats, "enum_hits", 0) or 0),
        "enum_words_tested": enum_done,
        "enum_words_total": enum_total,
        "enum_hit_urls": list(getattr(stats, "enum_hit_urls", []) or [])[:200],
        "route_variants_skipped": int(getattr(stats, "route_variants_skipped", 0) or 0),
        "out_of_scope_skipped": int(getattr(stats, "out_of_scope_skipped", 0) or 0),
        "status_codes": dict(getattr(stats, "status_codes", {}) or {}),
        "findings": list(getattr(stats, "findings", []) or []),
        "technologies": dict(getattr(stats, "technologies", {}) or {}),
        "sensitive_urls": list(getattr(stats, "sensitive_urls", []) or [])[:100],
        "cookie_inventory": list(getattr(stats, "cookie_inventory", []) or [])[:200],
        "scan_status": status_meta.get("scan_status") or scan_status,
        "phase": status_meta.get("phase") or "crawl",
        "completion_percent": float(status_meta.get("completion_percent") or 0),
        "report_generated_during_scan": bool(status_meta.get("report_generated_during_scan")),
        "directory_enum_enabled": bool(status_meta.get("directory_enum_enabled")),
        "directory_enum_started": bool(status_meta.get("directory_enum_started")),
        "directory_enum_message": str(status_meta.get("directory_enum_message") or ""),
        "remaining_jobs": int(status_meta.get("remaining_jobs") or queue_size),
        "is_final": bool(status_meta.get("is_final")),
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, default=str), encoding="utf-8")
    return str(path)


def load_findings_snapshot(report_dir: str | Path) -> Optional[Dict[str, Any]]:
    import json
    from pathlib import Path as _Path

    path = _Path(report_dir) / FINDINGS_SNAPSHOT_NAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def crawl_stats_from_partial(
    *,
    snapshot: Optional[Dict[str, Any]] = None,
    progress: Optional[Dict[str, Any]] = None,
) -> CrawlStats:
    """Rebuild CrawlStats from a snapshot file and/or live progress JSON."""
    import time as _time

    stats = CrawlStats()
    snap = snapshot or {}
    prog = progress or {}

    started = float(snap.get("started_at") or prog.get("started_at") or 0) or None
    if started:
        stats.started_at = started
    else:
        # Prefer restoring elapsed rather than pretending the scan just started
        elapsed = float(snap.get("elapsed_seconds") or prog.get("elapsed_seconds") or 0)
        if elapsed > 0:
            stats.started_at = _time.time() - elapsed
    finished = float(snap.get("finished_at") or prog.get("finished_at") or 0) or None
    if finished:
        stats.finished_at = finished

    stats.pages_crawled = int(snap.get("pages_crawled") or prog.get("pages_crawled") or 0)
    stats.links_found = int(snap.get("links_found") or prog.get("links_found") or 0)
    stats.errors = int(snap.get("errors") or prog.get("errors") or 0)
    stats.bytes_downloaded = int(
        snap.get("bytes_downloaded") or prog.get("bytes_downloaded") or 0
    )
    stats.queue_size = int(snap.get("queue_size") or prog.get("queue_size") or 0)
    stats.enum_hits = int(snap.get("enum_hits") or prog.get("enum_hits") or 0)
    stats.enum_words_tested = int(
        snap.get("enum_words_tested") or prog.get("enum_words_tested") or 0
    )
    stats.enum_words_total = int(
        snap.get("enum_words_total") or prog.get("enum_words_total") or 0
    )
    stats.route_variants_skipped = int(
        snap.get("route_variants_skipped") or prog.get("route_variants_skipped") or 0
    )
    stats.out_of_scope_skipped = int(
        snap.get("out_of_scope_skipped") or prog.get("out_of_scope_skipped") or 0
    )
    urls = list(snap.get("enum_hit_urls") or prog.get("enum_hit_urls") or [])
    if urls:
        try:
            stats.enum_hit_urls = list(urls)[:200]
        except Exception:
            pass
    discovered = list(snap.get("discovered_urls") or [])
    disc_count = int(snap.get("discovered_url_count") or prog.get("discovered_url_count") or 0)
    if discovered:
        stats.discovered_urls.update(str(u) for u in discovered if u)
    elif disc_count > 0 and stats.pages_crawled:
        # Preserve count for reports when URL list was truncated out of the snapshot
        for i in range(min(disc_count, 50)):
            stats.discovered_urls.add(f"snapshot://discovered/{i}")
    techs = snap.get("technologies") or {}
    if isinstance(techs, dict):
        for k, v in techs.items():
            try:
                stats.technologies[str(k)] += int(v)
            except Exception:
                pass
    for u in list(snap.get("sensitive_urls") or [])[:100]:
        if u and u not in stats.sensitive_urls:
            stats.sensitive_urls.append(str(u))
    for row in list(snap.get("cookie_inventory") or [])[:200]:
        if isinstance(row, dict):
            stats.cookie_inventory.append(row)
    codes = snap.get("status_codes") or prog.get("status_codes") or {}
    if isinstance(codes, dict):
        for k, v in codes.items():
            try:
                stats.status_codes[int(k)] += int(v)
            except Exception:
                try:
                    stats.status_codes[str(k)] += int(v)
                except Exception:
                    pass

    # Attach scan-status metadata for report builders (not a CrawlStats field)
    stats._scan_status = str(  # type: ignore[attr-defined]
        snap.get("scan_status")
        or prog.get("scan_status")
        or ("partial" if not finished else "final")
    )
    stats._report_generated_during_scan = bool(  # type: ignore[attr-defined]
        snap.get("report_generated_during_scan")
        if "report_generated_during_scan" in snap
        else (not finished)
    )
    stats._directory_enum_enabled = bool(  # type: ignore[attr-defined]
        snap.get("directory_enum_enabled")
        if "directory_enum_enabled" in snap
        else (stats.enum_words_total > 0 or bool(stats.enum_started_at))
    )
    stats._directory_enum_started = bool(  # type: ignore[attr-defined]
        snap.get("directory_enum_started")
        if "directory_enum_started" in snap
        else bool(stats.enum_started_at)
    )
    stats._remaining_jobs = int(  # type: ignore[attr-defined]
        snap.get("remaining_jobs") or prog.get("queue_size") or stats.queue_size or 0
    )

    rows = list(snap.get("findings") or [])
    if not rows:
        # Fall back to progress preview / full list
        rows = list(prog.get("findings_full") or prog.get("findings_preview") or [])
    for item in rows:
        if not isinstance(item, dict):
            continue
        category = str(item.get("category") or "info")
        severity = str(item.get("severity") or item.get("severity_label") or "info")
        url = str(item.get("url") or "")
        detail = str(item.get("detail") or item.get("title") or "")
        evidence = item.get("evidence") or item.get("evidence_full") or None
        if evidence is not None:
            evidence = str(evidence)
        if not detail and not evidence:
            continue
        try:
            stats.record_finding(
                category,
                severity,
                url,
                detail,
                evidence=evidence or None,
                impact=item.get("impact"),
                role=item.get("role"),
                validation=item.get("validation"),
                impact_summary=item.get("impact_summary"),
                verification=item.get("verification"),
                proof=item.get("proof") if isinstance(item.get("proof"), dict) else None,
                confidence=item.get("confidence"),
                confidence_reason=item.get("confidence_reason"),
            )
        except Exception:
            stats.findings.append(
                {
                    "category": category,
                    "severity": severity,
                    "url": url,
                    "detail": detail,
                    **({"evidence": evidence} if evidence else {}),
                }
            )
    # Prefer authoritative counts from progress when snapshot findings were truncated
    reported = int(prog.get("findings") or 0)
    if reported > len(stats.findings):
        # Keep what we have; count is display-only in reports via len(findings)
        pass
    return stats


def write_partial_full_reports(
    *,
    report_dir: str | Path,
    start_url: str,
    title: str = "",
    progress: Optional[Dict[str, Any]] = None,
    config=None,
    stats: Optional[CrawlStats] = None,
    output_callback=None,
) -> Dict[str, str]:
    """Write assessment/search reports from live stats, snapshot, or progress JSON."""
    from pathlib import Path as _Path

    root = _Path(report_dir)
    root.mkdir(parents=True, exist_ok=True)
    if stats is None:
        snap = load_findings_snapshot(root)
        stats = crawl_stats_from_partial(snapshot=snap, progress=progress or {})
    elif not list(getattr(stats, "findings", []) or []):
        # Merge snapshot findings into empty stats
        snap = load_findings_snapshot(root)
        if snap:
            merged = crawl_stats_from_partial(snapshot=snap, progress=progress or {})
            if merged.findings:
                stats = merged
    if not list(getattr(stats, "findings", []) or []) and int(
        (progress or {}).get("findings") or 0
    ) == 0 and int(getattr(stats, "pages_crawled", 0) or 0) == 0:
        return {}
    return write_stats_reports(
        stats,
        report_dir=str(root.resolve()),
        start_url=start_url or "",
        title=title or "",
        config=config,
        output_callback=output_callback,
    )
