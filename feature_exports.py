"""Compare runs, site graph, Burp/ZAP export."""

from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET
from html import escape
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

from crawl_stats import CrawlStats


def write_site_graph_html(stats: CrawlStats, start_url: str, output_path: str) -> str:
    urls = sorted(getattr(stats, "discovered_urls", set()) or {start_url})
    host = urlparse(start_url).netloc
    nodes = []
    edges = []
    for url in urls[:2000]:
        path = urlparse(url).path or "/"
        depth = path.count("/")
        nodes.append({"id": url, "label": path[:60] or "/", "level": depth})
    for url in urls[:2000]:
        parent_path = urlparse(url).path.rstrip("/")
        if not parent_path:
            continue
        parent = parent_path.rsplit("/", 1)[0] or "/"
        parent_url = f"{urlparse(url).scheme}://{host}{parent if parent.startswith('/') else '/' + parent}"
        if parent_url in urls and parent_url != url:
            edges.append({"from": parent_url, "to": url})

    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Site map — {escape(host)}</title>
<style>body{{font-family:system-ui;margin:0;background:#0d1117;color:#c9d1d9}}
#wrap{{display:flex;height:100vh}}#list{{width:40%;overflow:auto;padding:1rem;border-right:1px solid #30363d}}
#list a{{color:#58a6ff;text-decoration:none;display:block;padding:2px 0;font-size:13px}}
h1{{font-size:1.1rem}} .meta{{color:#8b949e;font-size:12px}}</style></head><body>
<div id="wrap"><div id="list"><h1>Site map ({len(urls)} URLs)</h1>
<p class="meta">Target: {escape(start_url)}</p><ul>
"""
    for url in urls[:500]:
        html += f'<li><a href="{escape(url)}" target="_blank">{escape(urlparse(url).path or "/")}</a></li>\n'
    if len(urls) > 500:
        html += f"<li class='meta'>… and {len(urls) - 500} more in JSON report</li>"
    html += "</ul></div><div style='flex:1;padding:1rem'><h2>Tree by path depth</h2><pre>"
    by_depth: Dict[int, List[str]] = {}
    for url in urls[:300]:
        d = (urlparse(url).path or "/").count("/")
        by_depth.setdefault(d, []).append(urlparse(url).path or "/")
    for depth in sorted(by_depth):
        html += f"\n--- depth {depth} ---\n"
        for p in by_depth[depth][:40]:
            html += escape(p) + "\n"
    html += "</pre></div></div></body></html>"
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(html)
    return output_path


def write_burp_xml(findings: List[dict], output_path: str, host: str) -> str:
    root = ET.Element("issues")
    for finding in findings:
        issue = ET.SubElement(root, "issue")
        ET.SubElement(issue, "name").text = finding.get("category", "finding")
        ET.SubElement(issue, "severity").text = finding.get("severity", "info").upper()
        ET.SubElement(issue, "host").text = host
        ET.SubElement(issue, "path").text = urlparse(finding.get("url", "")).path or "/"
        ET.SubElement(issue, "location").text = finding.get("url", "")
        detail = _export_safe_detail(finding)
        ET.SubElement(issue, "detail").text = detail
    tree = ET.ElementTree(root)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)
    return output_path


def write_zap_json(findings: List[dict], output_path: str) -> str:
    alerts = []
    risk_map = {"critical": "3", "high": "3", "medium": "2", "low": "1", "info": "0"}
    for finding in findings:
        detail = _export_safe_detail(finding)
        alerts.append({
            "sourceid": "crawler",
            "alert": finding.get("category", "finding"),
            "riskcode": risk_map.get(finding.get("severity", "info"), "0"),
            "name": detail[:200],
            "uri": finding.get("url", ""),
            "desc": detail,
        })
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump({"site": [{"alerts": alerts}]}, handle, indent=2)
    return output_path


def _export_safe_detail(finding: dict) -> str:
    """Strip full public client-key values from Burp/ZAP/CSV exports."""
    detail = str(finding.get("detail") or "")
    evidence = str(finding.get("evidence") or "")
    cat = str(finding.get("category") or "")
    try:
        from enum_validation import is_public_client_key_value
        from security_scan import mask_secret_value
    except Exception:
        return detail
    if is_public_client_key_value(evidence) or "public client-key" in cat.lower() or "pubkey-" in evidence.lower():
        masked = mask_secret_value(evidence) if evidence else ""
        if evidence and evidence in detail:
            detail = detail.replace(evidence, masked)
        # Also scrub bare pubkey-… tokens that may appear in detail
        import re

        detail = re.sub(r"(?i)\bpubkey-[A-Za-z0-9_-]{8,}\b", lambda m: mask_secret_value(m.group(0)), detail)
    return detail


def compare_crawl_reports(path_a: str, path_b: str, output_path: str) -> dict:
    data_a = _load_report(path_a)
    data_b = _load_report(path_b)
    urls_a = set(data_a.get("discovered_urls") or data_a.get("links_found_list") or [])
    urls_b = set(data_b.get("discovered_urls") or data_b.get("links_found_list") or [])
    enum_a = set(data_a.get("enum_hit_urls") or [])
    enum_b = set(data_b.get("enum_hit_urls") or [])
    findings_a = {f.get("url", "") + f.get("detail", "") for f in data_a.get("findings", [])}
    findings_b = {f.get("url", "") + f.get("detail", "") for f in data_b.get("findings", [])}
    only_a = sorted(urls_a - urls_b)
    only_b = sorted(urls_b - urls_a)
    new_enum = sorted(enum_b - enum_a)
    removed_enum = sorted(enum_a - enum_b)
    new_findings = sorted(findings_b - findings_a)
    removed_findings = sorted(findings_a - findings_b)
    summary = {
        "report_a": path_a,
        "report_b": path_b,
        "urls_only_in_a": len(only_a),
        "urls_only_in_b": len(only_b),
        "new_enum_hits": len(new_enum),
        "removed_enum_hits": len(removed_enum),
        "new_findings": len(new_findings),
        "removed_findings": len(removed_findings),
    }
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Crawl comparison</title>
<style>body{{font-family:system-ui;margin:2rem}} table{{border-collapse:collapse}} td,th{{border:1px solid #ccc;padding:6px}}</style></head>
<body><h1>Crawl comparison</h1><table>
<tr><th>Metric</th><th>Count</th></tr>
<tr><td>URLs only in A</td><td>{len(only_a)}</td></tr>
<tr><td>URLs only in B</td><td>{len(only_b)}</td></tr>
<tr><td>New enum hits in B</td><td>{len(new_enum)}</td></tr>
<tr><td>Removed enum hits</td><td>{len(removed_enum)}</td></tr>
<tr><td>New findings in B</td><td>{len(new_findings)}</td></tr>
<tr><td>Removed findings</td><td>{len(removed_findings)}</td></tr>
</table><h2>New enum hits in B</h2><ul>"""
    for u in new_enum[:100]:
        html += f"<li>{escape(u)}</li>"
    html += "</ul><h2>New URLs in B (sample)</h2><ul>"""
    for u in only_b[:100]:
        html += f"<li>{escape(u)}</li>"
    html += "</ul></body></html>"
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(html)
    summary["output"] = output_path
    return summary


def _load_report(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)
