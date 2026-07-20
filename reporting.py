"""HTML/JSON/SQLite/CSV reports, WARC export, screenshots."""

from __future__ import annotations

import csv
import json
import os
import sqlite3
import time
from html import escape
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from crawl_stats import CrawlStats
from report_html import render_search_report_html, url_table_html
from search_report import build_search_conclusion


class ReportWriter:
    def __init__(self, report_dir: str, start_url: str):
        self.report_dir = report_dir
        self.start_url = start_url
        self.host = urlparse(start_url).netloc.replace(":", "_")
        self.timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.base_name = f"crawl_{self.host}_{self.timestamp}"
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
