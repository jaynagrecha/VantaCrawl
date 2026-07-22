"""Minimal HTML/TXT report when a scan ends before the full reporter runs."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from report_time import format_dual


def write_summary_report(
    report_dir: Path,
    *,
    job_id: str,
    title: str,
    start_url: str,
    status: str,
    progress: Optional[Dict[str, Any]] = None,
    log_tail: str = "",
    note: str = "",
) -> Tuple[str, str]:
    """Write *_SUMMARY_REPORT.html/txt so the UI always has something to open.

    Uses SUMMARY (not SEARCH/ASSESSMENT) so a stub never blocks the full reporter.
    """
    report_dir.mkdir(parents=True, exist_ok=True)
    base = f"job_{job_id.replace('-', '')[:12]}"
    html_path = report_dir / f"{base}_SUMMARY_REPORT.html"
    txt_path = report_dir / f"{base}_SUMMARY_REPORT.txt"

    progress = progress or {}
    pages = progress.get("pages_crawled", 0) or 0
    findings = progress.get("findings", 0) or 0
    enum_hits = progress.get("enum_hits", 0) or 0
    enum_urls: List[str] = list(progress.get("enum_hit_urls") or [])[:40]
    findings_preview = list(progress.get("findings_preview") or [])[:40]
    stamp = format_dual()
    reason = note or (
        "This scan ended before the full HTML report was generated "
        "(stopped early, force-cancelled, or blocked — e.g. Cloudflare)."
    )

    txt_lines = [
        f"VantaCrawl summary report",
        f"Job: {job_id}",
        f"Title: {title}",
        f"Target: {start_url}",
        f"Status: {status}",
        f"Generated: {stamp}",
        "",
        reason,
        "",
        f"Pages crawled: {pages}",
        f"Enum hits: {enum_hits}",
        f"Findings: {findings}",
        "",
        "Enum hit URLs:",
    ]
    txt_lines.extend(enum_urls or ["(none)"])
    txt_lines.extend(["", "Findings preview:"])
    if findings_preview:
        for item in findings_preview:
            if isinstance(item, dict):
                txt_lines.append(
                    f"- [{item.get('severity') or 'info'}] {item.get('title') or ''} {item.get('url') or ''}"
                )
            else:
                txt_lines.append(f"- {item}")
    else:
        txt_lines.append("(none)")
    if log_tail.strip():
        txt_lines.extend(["", "--- Log tail ---", log_tail.strip()[-8000:]])
    txt_path.write_text("\n".join(txt_lines), encoding="utf-8")

    enum_html = "".join(f"<li><code>{escape(u)}</code></li>" for u in enum_urls) or "<li class='muted'>(none)</li>"
    find_bits = []
    for item in findings_preview:
        if isinstance(item, dict):
            find_bits.append(
                "<li><strong>{}</strong> — {} <code>{}</code></li>".format(
                    escape(str(item.get("severity") or "info")),
                    escape(str(item.get("title") or "")),
                    escape(str(item.get("url") or "")),
                )
            )
    findings_html = "".join(find_bits) or "<li class='muted'>(none)</li>"
    log_html = escape((log_tail or "")[-6000:]) if log_tail else "<em class='muted'>No log captured.</em>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>{escape(title or "VantaCrawl")} — summary</title>
<style>
  body {{ margin:0; font-family: ui-sans-serif, system-ui, sans-serif; background:#0b1220; color:#e8eefc; }}
  main {{ max-width: 960px; margin: 0 auto; padding: 2rem 1.25rem; }}
  h1 {{ margin: 0 0 .35rem; font-size: 1.6rem; }}
  .muted {{ color: #8b9bb8; }}
  .card {{ background:#121a2b; border:1px solid #24304a; border-radius:14px; padding:1.1rem 1.25rem; margin:1rem 0; }}
  .stats {{ display:grid; grid-template-columns: repeat(3,1fr); gap:.75rem; }}
  .stat {{ background:#0b1220; border-radius:10px; padding:.8rem; text-align:center; }}
  .stat b {{ display:block; font-size:1.4rem; color:#3dd6c6; }}
  code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:.82rem; }}
  pre {{ white-space: pre-wrap; background:#070b14; padding:1rem; border-radius:10px; overflow:auto; max-height:320px; }}
  ul {{ padding-left: 1.2rem; }}
  a {{ color:#3dd6c6; }}
</style>
</head>
<body>
<main>
  <h1>{escape(title or "Scan summary")}</h1>
  <p class="muted mono">{escape(start_url)}</p>
  <div class="card">
    <p><strong>Status:</strong> {escape(status)} · <span class="muted">{escape(stamp)}</span></p>
    <p>{escape(reason)}</p>
  </div>
  <div class="stats">
    <div class="stat"><b>{escape(str(pages))}</b><span class="muted">Pages</span></div>
    <div class="stat"><b>{escape(str(enum_hits))}</b><span class="muted">Enum hits</span></div>
    <div class="stat"><b>{escape(str(findings))}</b><span class="muted">Findings</span></div>
  </div>
  <div class="card">
    <h2>Enum hits</h2>
    <ul>{enum_html}</ul>
  </div>
  <div class="card">
    <h2>Findings</h2>
    <ul>{findings_html}</ul>
  </div>
  <div class="card">
    <h2>Log tail</h2>
    <pre>{log_html}</pre>
  </div>
</main>
</body>
</html>
"""
    html_path.write_text(html, encoding="utf-8")
    return str(html_path), str(txt_path)
