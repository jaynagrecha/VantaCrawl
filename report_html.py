"""Dark commercial SaaS HTML search report (interactive)."""

from __future__ import annotations

import time
from html import escape
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse


def short_url(url: str, max_len: int = 78) -> str:
    text = url or ""
    if len(text) <= max_len:
        return text
    return text[:42] + "…" + text[-30:]


def url_table_html(
    urls: Optional[Sequence[str]],
    *,
    limit: int = 40,
    table_id: str = "",
    empty: str = "None in this run",
) -> str:
    items = list(urls or [])
    shown = items[:limit]
    tid = f' id="{escape(table_id)}"' if table_id else ""
    if not shown:
        return (
            f'<div class="empty"{tid}>{escape(empty)}</div>'
        )
    rows = []
    for index, url in enumerate(shown, 1):
        full = escape(url)
        short = escape(short_url(url))
        rows.append(
            f'<tr class="url-row" data-text="{full}">'
            f'<td class="col-idx">{index}</td>'
            f'<td class="col-url">'
            f'<a class="url-link" href="{full}" title="{full}" target="_blank" rel="noopener">{short}</a>'
            f'<button type="button" class="icon-btn copy-btn" data-copy="{full}" title="Copy URL">Copy</button>'
            f'<button type="button" class="icon-btn expand-btn" title="Show full URL">Full</button>'
            f'<div class="url-full hidden">{full}</div>'
            f"</td></tr>"
        )
    more = ""
    if len(items) > limit:
        more = (
            f'<tr class="more-row"><td colspan="2" class="muted">'
            f"Showing {limit:,} of {len(items):,} — full list in text/JSON appendix"
            f"</td></tr>"
        )
    return (
        f'<div class="table-wrap"{tid}><table class="url-table"><thead>'
        f'<tr><th>#</th><th>URL</th></tr></thead><tbody>'
        f'{"".join(rows)}{more}</tbody></table></div>'
    )


def kv_table_html(rows: Sequence[Dict[str, str]], columns: Sequence[tuple], *, empty: str = "None") -> str:
    if not rows:
        return f'<div class="empty">{escape(empty)}</div>'
    head = "".join(f"<th>{escape(label)}</th>" for _, label in columns)
    body = []
    for row in rows:
        cells = "".join(f"<td>{escape(str(row.get(key, '')))}</td>" for key, _ in columns)
        text = escape(" ".join(str(row.get(key, "")) for key, _ in columns))
        body.append(f'<tr class="url-row" data-text="{text}">{cells}</tr>')
    return (
        f'<div class="table-wrap"><table class="data-table"><thead><tr>{head}</tr></thead>'
        f'<tbody>{"".join(body)}</tbody></table></div>'
    )


def render_search_report_html(
    *,
    start_url: str,
    base_name: str,
    conclusion: dict,
    stats: Any,
    profile: str = "full",
) -> str:
    model = conclusion.get("report_model") or {}
    snap = conclusion.get("snapshot") or {}
    sev = conclusion.get("severity_counts") or {}
    groups = conclusion.get("finding_groups") or []

    critical = int(sev.get("critical", 0))
    high = int(sev.get("high", 0))
    medium = int(sev.get("medium", 0))
    low = int(sev.get("low", 0))
    info = int(sev.get("info", 0))

    if critical:
        verdict_tone = "critical"
    elif high:
        verdict_tone = "high"
    elif medium:
        verdict_tone = "medium"
    else:
        verdict_tone = "ok"

    issue_cards = []
    for group in groups:
        sev_label = escape(str(group.get("severity", "info")))
        urls = group.get("urls") or []
        urls_block = url_table_html(urls, limit=40, table_id="")
        evidence = group.get("evidence") or []
        if group.get("category") == "secrets_exposure":
            if evidence:
                evidence_html = (
                    "<ul class='chip-list'>"
                    + "".join(f"<li><code>{escape(e)}</code></li>" for e in evidence[:10])
                    + "</ul>"
                )
                evidence_block = f"<h4>Secret (masked)</h4>{evidence_html}"
            else:
                evidence_block = "<h4>Secret</h4><p class='muted'>Pattern matched; exact value not captured.</p>"
        elif evidence:
            evidence_block = (
                "<h4>Evidence</h4><ul class='chip-list'>"
                + "".join(f"<li><code>{escape(e)}</code></li>" for e in evidence[:8])
                + "</ul>"
            )
        else:
            evidence_block = ""
        issue_cards.append(
            f"""<article class="issue sev-{sev_label}" data-severity="{sev_label}" data-text="{escape(str(group.get('title', '')) + ' ' + str(group.get('detail', '')))}">
  <header class="issue-head">
    <span class="badge sev-{sev_label}">{sev_label.upper()}</span>
    <h3>{escape(group.get('title', ''))}</h3>
  </header>
  <p class="muted">Raw signal: {escape(group.get('detail', ''))} · seen {group.get('count', 0)}× on {group.get('unique_hosts', 0)} host(s)</p>
  <h4>Exact path(s)</h4>
  {urls_block}
  {evidence_block}
  <div class="issue-grid">
    <div><h4>What this means</h4><p>{escape(group.get('what', ''))}</p></div>
    <div><h4>Attacker use</h4><p>{escape(group.get('attacker', ''))}</p></div>
    <div><h4>How to fix</h4><p>{escape(group.get('fix', ''))}</p></div>
  </div>
</article>"""
        )
    issues_block = "\n".join(issue_cards) or '<p class="empty">No security issues recorded in this run.</p>'

    tech_list = model.get("tech_list")
    if not tech_list and stats is not None and hasattr(stats, "technologies"):
        try:
            tech_list = stats.technologies.most_common(20)
        except Exception:
            tech_list = []
    tech_items = "".join(
        f"<li>{escape(str(name))} <span class='pill'>{escape(str(count))}</span></li>"
        for name, count in (tech_list or [])
    ) or "<li class='muted'>None detected</li>"

    rec_items = "".join(
        f"<li>{escape(item)}</li>" for item in (conclusion.get("recommendations") or [])
    ) or "<li>No urgent actions identified.</li>"

    takeaway_items = "".join(
        f"<li>{escape(item)}</li>" for item in (model.get("takeaways") or [])
    ) or "<li>No standout items beyond routine checks.</li>"

    key_lines = model.get("key_findings_lines") or conclusion.get("interesting") or []
    key_findings_html_parts = []
    current = None
    for line in key_lines:
        if line.startswith("  Path:") or line.startswith("  Secret") or line.startswith("  Evidence") or line.startswith("  Detail:"):
            if current is None:
                current = {"title": "Finding", "kids": []}
            current["kids"].append(line.strip())
        else:
            if current:
                kids = "".join(f"<li>{escape(k)}</li>" for k in current["kids"]) or "<li>(no path)</li>"
                key_findings_html_parts.append(
                    f"<li><strong>{escape(current['title'])}</strong><ul>{kids}</ul></li>"
                )
            current = {"title": line, "kids": []}
    if current:
        kids = "".join(f"<li>{escape(k)}</li>" for k in current["kids"]) or "<li>(no path)</li>"
        key_findings_html_parts.append(
            f"<li><strong>{escape(current['title'])}</strong><ul>{kids}</ul></li>"
        )
    key_findings_block = "".join(key_findings_html_parts) or "<li>No findings with paths in this run.</li>"

    setup = conclusion.get("scan_setup") or model.get("scan_setup") or {}
    setup_actions = "".join(f"<li>{escape(a)}</li>" for a in (setup.get("actions") or []))
    setup_rows = "".join(
        f"<tr><th>{escape(label)}</th><td>{escape(str(value))}</td></tr>"
        for label, value in (setup.get("rows") or [])
    )

    defense = conclusion.get("defense") or model.get("defense") or {}
    if defense:
        defense_html = f"""
    <p class="lead"><strong>{escape(defense.get('verdict_title', ''))}</strong></p>
    <p>{escape(defense.get('verdict_body', ''))}</p>
    <div class="stats mini">
      <div class="stat"><div class="stat-num">{defense.get('caught_by_protection', 0)}</div><div class="stat-label">Caught</div></div>
      <div class="stat"><div class="stat-num">{defense.get('completed_without_challenge', 0)}</div><div class="stat-label">Gaps</div></div>
      <div class="stat"><div class="stat-num">{defense.get('catch_rate_percent', 0)}%</div><div class="stat-label">Catch rate</div></div>
    </div>"""
    else:
        defense_html = "<p class='muted'>Defense verification not enabled or no data.</p>"

    forms_html = "".join(
        f"<li><span class='pill'>{escape((f.get('method') or 'GET').upper())}</span> "
        f"{escape(f.get('action') or '(same page)')} — "
        f"<span class='muted'>{escape(', '.join(str(x) for x in (f.get('fields') or f.get('inputs') or [])[:8]) or 'no named fields')}</span></li>"
        for f in (model.get("form_rows") or [])[:25]
    ) or "<li class='muted'>(none)</li>"

    broken_html = url_table_html(
        [f"{item.get('url', '')}  [{item.get('status', '?')}]" for item in (model.get("broken") or [])],
        limit=30,
    )

    cookies = model.get("cookies") or []
    cookie_rows = kv_table_html(
        cookies[:40],
        (("name", "Name"), ("flags", "Flags")),
        empty="No cookies inventoried",
    )
    third_party = model.get("third_party") or []
    third_rows = kv_table_html(
        third_party[:40],
        (("vendor", "Vendor"), ("host", "Host"), ("url", "Sample URL")),
        empty="No third-party scripts",
    )
    link_rels = model.get("link_rels") or []
    link_rows = kv_table_html(
        link_rels[:40],
        (("rel", "Rel"), ("url", "URL")),
        empty="No link relations",
    )
    well_known = model.get("well_known") or []
    wk_rows = kv_table_html(
        well_known[:30],
        (("url", "URL"), ("status", "Status"), ("evidence", "Evidence")),
        empty="No well-known hits",
    )
    file_meta = model.get("file_metadata") or []
    fm_display = []
    for row in file_meta[:40]:
        interesting = row.get("interesting") or {}
        preview = ", ".join(f"{k}={v}" for k, v in list(interesting.items())[:4]) or "(fields only)"
        fm_display.append(
            {
                "kind": f"{row.get('kind', '?')}/{row.get('engine', '?')}",
                "url": row.get("url", ""),
                "meta": preview,
            }
        )
    fm_rows = kv_table_html(
        fm_display,
        (("kind", "Kind"), ("url", "URL"), ("meta", "Metadata")),
        empty="No file metadata extracted",
    )

    hdr_map = model.get("security_headers") or {}
    hdr_items = []
    for host, hdrs in list(hdr_map.items())[:12]:
        hdr_items.append(
            f"<li><strong>{escape(host)}</strong> — "
            f"<span class='muted'>{escape(', '.join(sorted(hdrs.keys())[:14]))}</span></li>"
        )
    hdr_html = "<ul>" + ("".join(hdr_items) or "<li class='muted'>(none)</li>") + "</ul>"

    appendix_findings = "".join(
        f'<tr class="finding-row" data-severity="{escape(str(f.get("severity", "")))}" '
        f'data-text="{escape(str(f.get("category", "")) + " " + str(f.get("url", "")) + " " + str(f.get("detail", "")))}">'
        f"<td><span class='badge sev-{escape(str(f.get('severity', 'info')))}'>{escape(str(f.get('severity', '')))}</span></td>"
        f"<td>{escape(str(f.get('category', '')))}</td>"
        f"<td class='col-url'><a class='url-link' href='{escape(f.get('url', ''))}' title='{escape(f.get('url', ''))}'>"
        f"{escape(short_url(f.get('url', '') or '', 64))}</a></td>"
        f"<td>{escape(str(f.get('detail', ''))[:180])}</td></tr>"
        for f in (model.get("findings") or [])[:300]
    ) or "<tr><td colspan='4' class='muted'>(none)</td></tr>"

    host = urlparse(start_url).netloc or start_url

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Assessment Report — {escape(host)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Manrope:wght@500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {{
  --bg: #0b1220;
  --bg-elev: #121a2b;
  --bg-soft: #182338;
  --line: #2a364d;
  --text: #e8eefc;
  --muted: #93a0b8;
  --accent: #3dd6c6;
  --accent-dim: rgba(61, 214, 198, 0.14);
  --critical: #ff6b7a;
  --high: #ffb020;
  --medium: #5b9dff;
  --low: #8b98b0;
  --ok: #3dd6c6;
  --shadow: 0 10px 40px rgba(0,0,0,.35);
  --radius: 14px;
}}
* {{ box-sizing: border-box; }}
html {{ scroll-behavior: smooth; }}
body {{
  margin: 0;
  font-family: Manrope, "Segoe UI", sans-serif;
  background:
    radial-gradient(1200px 600px at 10% -10%, rgba(61,214,198,.12), transparent 55%),
    radial-gradient(900px 500px at 100% 0%, rgba(91,157,255,.10), transparent 50%),
    var(--bg);
  color: var(--text);
  line-height: 1.55;
}}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
code, .url-link, .mono {{ font-family: "IBM Plex Mono", Consolas, monospace; font-size: .86em; }}
.topbar {{
  position: sticky; top: 0; z-index: 50;
  backdrop-filter: blur(14px);
  background: rgba(11, 18, 32, 0.88);
  border-bottom: 1px solid var(--line);
}}
.topbar-inner {{
  max-width: 1180px; margin: 0 auto; padding: .85rem 1.25rem;
  display: flex; flex-wrap: wrap; gap: .75rem; align-items: center;
}}
.brand {{
  font-weight: 800; letter-spacing: .02em; color: var(--text);
  min-width: 160px;
}}
.brand span {{ color: var(--accent); }}
.toolbar {{ display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; flex: 1; }}
#report-search {{
  flex: 1; min-width: 180px; max-width: 360px;
  background: var(--bg-soft); border: 1px solid var(--line); color: var(--text);
  border-radius: 10px; padding: .55rem .8rem; font: inherit;
}}
#report-search:focus {{ outline: 2px solid rgba(61,214,198,.35); border-color: var(--accent); }}
.sev-filters {{ display: flex; flex-wrap: wrap; gap: .35rem; }}
.chip {{
  border: 1px solid var(--line); background: var(--bg-soft); color: var(--muted);
  border-radius: 999px; padding: .28rem .7rem; font-size: .78rem; font-weight: 600;
  cursor: pointer; user-select: none;
}}
.chip.active {{ color: var(--text); border-color: var(--accent); background: var(--accent-dim); }}
.chip[data-sev="critical"].active {{ border-color: var(--critical); color: var(--critical); }}
.chip[data-sev="high"].active {{ border-color: var(--high); color: var(--high); }}
.chip[data-sev="medium"].active {{ border-color: var(--medium); color: var(--medium); }}
.btn {{
  border: 1px solid var(--line); background: var(--bg-soft); color: var(--text);
  border-radius: 10px; padding: .45rem .75rem; font: inherit; font-size: .82rem; font-weight: 600;
  cursor: pointer;
}}
.btn:hover {{ border-color: var(--accent); }}
.btn.primary {{ background: var(--accent-dim); border-color: rgba(61,214,198,.45); color: var(--accent); }}
.hint {{ color: var(--muted); font-size: .75rem; }}
.container {{ max-width: 1180px; margin: 0 auto; padding: 1.5rem 1.25rem 3rem; }}
.hero {{
  display: grid; gap: 1rem;
  grid-template-columns: 1.4fr 1fr;
  margin-bottom: 1.25rem;
}}
@media (max-width: 900px) {{ .hero {{ grid-template-columns: 1fr; }} }}
.card {{
  background: linear-gradient(180deg, rgba(255,255,255,.02), transparent), var(--bg-elev);
  border: 1px solid var(--line); border-radius: var(--radius);
  padding: 1.25rem 1.35rem; margin-bottom: 1rem; box-shadow: var(--shadow);
}}
.card h2 {{ margin: 0 0 .75rem; font-size: 1.15rem; }}
.card h3 {{ margin: 1rem 0 .45rem; font-size: 1rem; }}
.card h4 {{ margin: .85rem 0 .35rem; font-size: .92rem; color: var(--muted); font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }}
.section {{ margin-bottom: 1rem; }}
.section.collapsed .section-body {{ display: none; }}
.section-head {{
  display: flex; align-items: center; justify-content: space-between; gap: .75rem;
  cursor: pointer; user-select: none;
}}
.section-head h2 {{ margin: 0; }}
.chev {{ color: var(--muted); font-size: .85rem; }}
.part-label {{
  color: var(--accent); text-transform: uppercase; letter-spacing: .08em;
  font-size: .75rem; font-weight: 700; margin: 1.75rem 0 .65rem;
}}
.verdict {{
  border-radius: 12px; padding: 1rem 1.1rem; font-weight: 800; font-size: 1.15rem;
  border: 1px solid var(--line); margin-bottom: .75rem;
}}
.verdict.critical {{ background: rgba(255,107,122,.12); color: var(--critical); border-color: rgba(255,107,122,.35); }}
.verdict.high {{ background: rgba(255,176,32,.12); color: var(--high); border-color: rgba(255,176,32,.35); }}
.verdict.medium {{ background: rgba(91,157,255,.12); color: var(--medium); border-color: rgba(91,157,255,.35); }}
.verdict.ok {{ background: var(--accent-dim); color: var(--ok); border-color: rgba(61,214,198,.35); }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(110px, 1fr)); gap: .65rem; }}
.stats.mini {{ margin-top: .75rem; }}
.stat {{
  text-align: center; background: var(--bg-soft); border: 1px solid var(--line);
  border-radius: 12px; padding: .7rem .4rem;
}}
.stat-num {{ font-size: 1.35rem; font-weight: 800; color: var(--accent); }}
.stat-label {{ font-size: .72rem; color: var(--muted); margin-top: .15rem; }}
.toc {{ display: flex; flex-wrap: wrap; gap: .45rem .7rem; }}
.toc a {{
  color: var(--muted); font-size: .85rem; padding: .25rem .55rem;
  border-radius: 8px; border: 1px solid transparent;
}}
.toc a:hover {{ color: var(--text); border-color: var(--line); text-decoration: none; background: var(--bg-soft); }}
.muted {{ color: var(--muted); }}
.lead {{ font-size: 1.02rem; }}
.pill {{
  display: inline-block; background: var(--bg-soft); border: 1px solid var(--line);
  border-radius: 999px; padding: .05rem .45rem; font-size: .75rem; color: var(--muted);
}}
.badge {{
  display: inline-block; font-size: .7rem; font-weight: 800; letter-spacing: .04em;
  padding: .18rem .45rem; border-radius: 6px; margin-right: .4rem; vertical-align: middle;
}}
.badge.sev-critical {{ background: rgba(255,107,122,.15); color: var(--critical); }}
.badge.sev-high {{ background: rgba(255,176,32,.15); color: var(--high); }}
.badge.sev-medium {{ background: rgba(91,157,255,.15); color: var(--medium); }}
.badge.sev-low, .badge.sev-info {{ background: rgba(139,152,176,.15); color: var(--low); }}
.issue {{
  border: 1px solid var(--line); border-radius: 12px; padding: 1rem 1.1rem;
  margin: .85rem 0; background: var(--bg-soft);
}}
.issue.sev-critical {{ border-left: 4px solid var(--critical); }}
.issue.sev-high {{ border-left: 4px solid var(--high); }}
.issue.sev-medium {{ border-left: 4px solid var(--medium); }}
.issue.sev-low, .issue.sev-info {{ border-left: 4px solid var(--low); }}
.issue-head {{ display: flex; align-items: center; gap: .5rem; }}
.issue-head h3 {{ margin: 0; font-size: 1.02rem; }}
.issue-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: .75rem; margin-top: .5rem; }}
@media (max-width: 900px) {{ .issue-grid {{ grid-template-columns: 1fr; }} }}
.table-wrap {{ overflow: auto; border: 1px solid var(--line); border-radius: 12px; background: rgba(0,0,0,.15); }}
.url-table, .data-table, .findings, .setup {{
  width: 100%; border-collapse: collapse; font-size: .88rem;
}}
.url-table th, .data-table th, .findings th, .setup th,
.url-table td, .data-table td, .findings td, .setup td {{
  text-align: left; padding: .55rem .7rem; border-bottom: 1px solid var(--line); vertical-align: top;
}}
.url-table th, .data-table th, .findings th {{ color: var(--muted); font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; }}
.col-idx {{ width: 3rem; color: var(--muted); }}
.col-url .url-link {{
  display: inline-block; max-width: min(62vw, 640px); overflow: hidden; text-overflow: ellipsis;
  white-space: nowrap; vertical-align: middle; color: #b7fff6;
}}
.url-full {{
  margin-top: .35rem; padding: .45rem .55rem; border-radius: 8px;
  background: #0a101c; border: 1px solid var(--line); word-break: break-all;
  font-family: "IBM Plex Mono", monospace; font-size: .78rem; color: var(--muted);
}}
.url-full.hidden {{ display: none; }}
.icon-btn {{
  margin-left: .35rem; border: 1px solid var(--line); background: var(--bg-elev);
  color: var(--muted); border-radius: 6px; padding: .12rem .4rem; font-size: .7rem;
  cursor: pointer; vertical-align: middle;
}}
.icon-btn:hover {{ color: var(--text); border-color: var(--accent); }}
.empty {{ color: var(--muted); padding: .5rem 0; }}
.setup th {{ width: 38%; color: var(--muted); }}
.chip-list {{ padding-left: 1.1rem; }}
.hidden-by-filter {{ display: none !important; }}
.toast {{
  position: fixed; bottom: 1rem; right: 1rem; background: var(--bg-elev);
  border: 1px solid var(--accent); color: var(--text); padding: .65rem 0.9rem;
  border-radius: 10px; opacity: 0; pointer-events: none; transition: opacity .2s; z-index: 99;
}}
.toast.show {{ opacity: 1; }}
footer.meta {{ color: var(--muted); font-size: .85rem; margin-top: 1.5rem; }}
</style>
</head>
<body>
<header class="topbar">
  <div class="topbar-inner">
    <div class="brand">Vanta<span>Crawl</span> Technical Report</div>
    <div class="toolbar">
      <input id="report-search" type="search" placeholder="Search report  (press / )" autocomplete="off">
      <div class="sev-filters" title="Filter findings by severity">
        <button type="button" class="chip active" data-sev="all">All</button>
        <button type="button" class="chip" data-sev="critical">Critical</button>
        <button type="button" class="chip" data-sev="high">High</button>
        <button type="button" class="chip" data-sev="medium">Medium</button>
        <button type="button" class="chip" data-sev="low">Low</button>
        <button type="button" class="chip" data-sev="info">Info</button>
      </div>
      <button type="button" class="btn" id="btn-collapse">Collapse all</button>
      <button type="button" class="btn" id="btn-expand">Expand all</button>
      <button type="button" class="btn primary" id="btn-export">Export visible</button>
    </div>
    <div class="hint">Target: {escape(start_url)}</div>
  </div>
</header>

<main class="container">
  <div class="hero">
    <section class="card">
      <div class="verdict {verdict_tone}">{escape(conclusion.get('verdict_title', ''))}</div>
      <p>{escape(conclusion.get('verdict_body', ''))}</p>
      <p class="muted">Authorized testing · {escape(time.strftime('%Y-%m-%d %H:%M:%S'))} · Profile: {escape(profile)}</p>
    </section>
    <section class="card">
      <h2>Risk snapshot</h2>
      <div class="stats">
        <div class="stat"><div class="stat-num">{critical}</div><div class="stat-label">Critical</div></div>
        <div class="stat"><div class="stat-num">{high}</div><div class="stat-label">High</div></div>
        <div class="stat"><div class="stat-num">{medium}</div><div class="stat-label">Medium</div></div>
        <div class="stat"><div class="stat-num">{low + info}</div><div class="stat-label">Low / Info</div></div>
        <div class="stat"><div class="stat-num">{snap.get('pages_crawled', 0)}</div><div class="stat-label">Pages</div></div>
        <div class="stat"><div class="stat-num">{model.get('discovered_total', 0)}</div><div class="stat-label">URLs</div></div>
        <div class="stat"><div class="stat-num">{len(model.get('enum_hits') or [])}</div><div class="stat-label">Hidden</div></div>
        <div class="stat"><div class="stat-num">{len(model.get('subdomains') or [])}</div><div class="stat-label">Subdomains</div></div>
      </div>
    </section>
  </div>

  <nav class="card toc">
    <a href="#part-a">A Executive</a>
    <a href="#b1">B1 Crawl</a>
    <a href="#b2">B2 Hidden</a>
    <a href="#b3">B3 Discovery</a>
    <a href="#b4">B4 Cloud</a>
    <a href="#b5">B5 Sensitive</a>
    <a href="#b5b">B5b Auth</a>
    <a href="#b5c">B5c Recon</a>
    <a href="#b6">B6 Findings</a>
    <a href="#b7">B7 Defense</a>
    <a href="#b8">B8 Tech</a>
    <a href="#b9">B9 Broken</a>
    <a href="#b10">B10 Setup</a>
    <a href="#part-c">C Appendix</a>
  </nav>

  <div class="part-label" id="part-a">Part A — Executive summary</div>
  <section class="card section" data-section="a">
    <div class="section-head"><h2>Executive summary</h2><span class="chev">▾</span></div>
    <div class="section-body">
      <h3>Top takeaways</h3>
      <ul>{takeaway_items}</ul>
      <h3>Key findings (exact paths)</h3>
      <ul>{key_findings_block}</ul>
      <h3>Remediation roadmap</h3>
      <ul>{rec_items}</ul>
    </div>
  </section>

  <div class="part-label" id="part-b">Part B — Results by area</div>

  <section class="card section" id="b1" data-section="b1">
    <div class="section-head"><h2>B1. Crawl &amp; site map</h2><span class="chev">▾</span></div>
    <div class="section-body">
      <p>Crawled <strong>{snap.get('pages_crawled', 0)}</strong> page(s); discovery set has <strong>{model.get('discovered_total', 0)}</strong> URL(s).</p>
      <h3>Sample discovered URLs</h3>
      {url_table_html(model.get('discovered_sample'), limit=25, table_id='tbl-discovered')}
    </div>
  </section>

  <section class="card section" id="b2" data-section="b2">
    <div class="section-head"><h2>B2. Hidden paths</h2><span class="chev">▾</span></div>
    <div class="section-body">
      <p>{escape(str(snap.get('enum_words_tested', 0)))} / {escape(str(snap.get('enum_words_total', 0)))} names tried · <strong>{len(model.get('enum_hits') or [])}</strong> hit(s).</p>
      {url_table_html(model.get('enum_hits'), limit=40)}
    </div>
  </section>

  <section class="card section" id="b3" data-section="b3">
    <div class="section-head"><h2>B3. Discovery sources</h2><span class="chev">▾</span></div>
    <div class="section-body">
      <h3>Historical seeds ({len(model.get('historical') or [])})</h3>
      {url_table_html(model.get('historical'), limit=20)}
      <h3>Subdomains ({len(model.get('subdomains') or [])})</h3>
      {url_table_html(model.get('subdomains'), limit=30)}
      <h3>JavaScript routes ({len(model.get('js_routes') or [])})</h3>
      {url_table_html(model.get('js_routes'), limit=25)}
      <h3>OpenAPI</h3>
      {url_table_html(model.get('openapi_docs'), limit=10)}
      {url_table_html(model.get('openapi_endpoints'), limit=25)}
      <h3>API recon map</h3>
      {kv_table_html(
          list(model.get('api_endpoints') or [])[:40],
          (("method", "Method"), ("path", "Path"), ("status", "Status"), ("source", "Source"), ("url", "URL")),
          empty="No API endpoints mapped in this run",
      )}
      <h3>API docs (recon)</h3>
      {url_table_html(model.get('api_docs'), limit=15)}
      <h3>GraphQL fields</h3>
      {kv_table_html(
          list(model.get('api_graphql_operations') or [])[:40],
          (("type", "Type"), ("field", "Field")),
          empty="No GraphQL schema fields discovered",
      )}
      <h3>RSS / Atom ({len(model.get('rss') or [])})</h3>
      {url_table_html(model.get('rss'), limit=15)}
      <h3>Forms ({len(model.get('form_rows') or [])})</h3>
      <ul>{forms_html}</ul>
    </div>
  </section>

  <section class="card section" id="b4" data-section="b4">
    <div class="section-head"><h2>B4. Cloud &amp; virtual hosts</h2><span class="chev">▾</span></div>
    <div class="section-body">
      <h3>S3 ({len(model.get('s3') or [])})</h3>{url_table_html(model.get('s3'), limit=30)}
      <h3>GCS ({len(model.get('gcs') or [])})</h3>{url_table_html(model.get('gcs'), limit=30)}
      <h3>Vhosts ({len(model.get('vhosts') or [])})</h3>{url_table_html(model.get('vhosts'), limit=30)}
    </div>
  </section>

  <section class="card section" id="b5" data-section="b5">
    <div class="section-head"><h2>B5. Sensitive paths</h2><span class="chev">▾</span></div>
    <div class="section-body">{url_table_html(model.get('sensitive'), limit=40)}</div>
  </section>

  <section class="card section" id="b5b" data-section="b5b">
    <div class="section-head"><h2>B5b. Auth surfaces, cookies, WebSockets, source maps</h2><span class="chev">▾</span></div>
    <div class="section-body">
      <h3>Login / auth surfaces ({len(model.get('login_surfaces') or [])})</h3>
      {url_table_html(model.get('login_surfaces'), limit=30)}
      <h3>Cookies</h3>{cookie_rows}
      <h3>WebSockets ({len(model.get('websockets') or [])})</h3>
      {url_table_html(model.get('websockets'), limit=30)}
      <h3>Source maps ({len(model.get('sourcemaps') or [])})</h3>
      {url_table_html(model.get('sourcemaps'), limit=30)}
    </div>
  </section>

  <section class="card section" id="b5c" data-section="b5c">
    <div class="section-head"><h2>B5c. Extended recon inventory</h2><span class="chev">▾</span></div>
    <div class="section-body">
      <h3>Emails ({len(model.get('emails') or [])})</h3>{url_table_html(model.get('emails'), limit=40)}
      <h3>Phones ({len(model.get('phones') or [])})</h3>{url_table_html(model.get('phones'), limit=20)}
      <h3>Internal / staging hosts ({len(model.get('internal_hosts') or [])})</h3>
      {url_table_html(model.get('internal_hosts'), limit=40)}
      <h3>TLS SAN / CN ({len(model.get('tls_sans') or [])})</h3>
      {url_table_html(model.get('tls_sans'), limit=40)}
      <h3>Sitemap docs</h3>{url_table_html(model.get('sitemap_docs'), limit=10)}
      <h3>Sitemap pages ({len(model.get('sitemap_urls') or [])})</h3>
      {url_table_html(model.get('sitemap_urls'), limit=40)}
      <h3>Well-known</h3>{wk_rows}
      <h3>Cloud service URLs ({len(model.get('cloud_urls') or [])})</h3>
      {url_table_html(model.get('cloud_urls'), limit=30)}
      <h3>Third-party scripts</h3>{third_rows}
      <h3>Link relations</h3>{link_rows}
      <h3>Security headers by host</h3>{hdr_html}
      <h3>Interesting comments ({len(model.get('comments') or [])})</h3>
      {url_table_html(model.get('comments'), limit=20)}
      <h3>DOM sinks ({len(model.get('dom_sinks') or [])})</h3>
      {url_table_html(model.get('dom_sinks'), limit=20)}
      <h3>File metadata</h3>{fm_rows}
    </div>
  </section>

  <section class="card section" id="b6" data-section="b6">
    <div class="section-head"><h2>B6. Security findings</h2><span class="chev">▾</span></div>
    <div class="section-body" id="findings-panel">{issues_block}</div>
  </section>

  <section class="card section" id="b7" data-section="b7">
    <div class="section-head"><h2>B7. Defense verification</h2><span class="chev">▾</span></div>
    <div class="section-body">{defense_html}</div>
  </section>

  <section class="card section" id="b8" data-section="b8">
    <div class="section-head"><h2>B8. Technology inventory</h2><span class="chev">▾</span></div>
    <div class="section-body"><ul>{tech_items}</ul></div>
  </section>

  <section class="card section" id="b9" data-section="b9">
    <div class="section-head"><h2>B9. Broken links</h2><span class="chev">▾</span></div>
    <div class="section-body">{broken_html}</div>
  </section>

  <section class="card section" id="b10" data-section="b10">
    <div class="section-head"><h2>B10. Scan configuration</h2><span class="chev">▾</span></div>
    <div class="section-body">
      <p>{escape(setup.get('narrative', ''))}</p>
      <h3>Methods</h3><ul>{setup_actions or '<li>n/a</li>'}</ul>
      <h3>Settings snapshot</h3>
      <div class="table-wrap"><table class="setup"><tbody>{setup_rows}</tbody></table></div>
    </div>
  </section>

  <div class="part-label" id="part-c">Part C — Technical appendix</div>
  <section class="card section" data-section="c1">
    <div class="section-head"><h2>C1. Extended hidden paths</h2><span class="chev">▾</span></div>
    <div class="section-body">{url_table_html(model.get('enum_hits'), limit=200)}</div>
  </section>
  <section class="card section" data-section="c2">
    <div class="section-head"><h2>C2. Extended discovery</h2><span class="chev">▾</span></div>
    <div class="section-body">
      <h3>Historical</h3>{url_table_html(model.get('historical'), limit=80)}
      <h3>JS routes</h3>{url_table_html(model.get('js_routes'), limit=100)}
      <h3>OpenAPI endpoints</h3>{url_table_html(model.get('openapi_endpoints'), limit=100)}
    </div>
  </section>
  <section class="card section" data-section="c3">
    <div class="section-head"><h2>C3. Raw findings table</h2><span class="chev">▾</span></div>
    <div class="section-body">
      <div class="table-wrap">
        <table class="findings" id="raw-findings">
          <thead><tr><th>Severity</th><th>Category</th><th>URL</th><th>Detail</th></tr></thead>
          <tbody>{appendix_findings}</tbody>
        </table>
      </div>
    </div>
  </section>
  <section class="card section" data-section="c4">
    <div class="section-head"><h2>C4. Limitations</h2><span class="chev">▾</span></div>
    <div class="section-body">
      <ul>
        <li>Automated assessment aid — not a full manual penetration test.</li>
        <li>False positives/negatives possible; verify before major production changes.</li>
        <li>Stopping a large directory scan early reduces coverage of hidden paths.</li>
        <li>Active probes (if enabled) must only run on authorized targets.</li>
      </ul>
    </div>
  </section>

  <footer class="meta">Also saved: {escape(base_name)}_SEARCH_REPORT.txt · JSON/CSV/SQLite in the Reports folder.</footer>
</main>
<div class="toast" id="toast">Copied</div>

<script>
(function () {{
  const search = document.getElementById('report-search');
  const toast = document.getElementById('toast');
  let activeSeverity = 'all';
  let collapsedAll = false;

  function showToast(msg) {{
    toast.textContent = msg;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 1400);
  }}

  function applyFilters() {{
    const q = (search.value || '').trim().toLowerCase();
    document.querySelectorAll('.issue, .finding-row').forEach((el) => {{
      const sev = (el.getAttribute('data-severity') || '').toLowerCase();
      const text = (el.getAttribute('data-text') || el.textContent || '').toLowerCase();
      const sevOk = activeSeverity === 'all' || sev === activeSeverity;
      const qOk = !q || text.includes(q);
      el.classList.toggle('hidden-by-filter', !(sevOk && qOk));
    }});
    document.querySelectorAll('.url-row').forEach((el) => {{
      const text = (el.getAttribute('data-text') || el.textContent || '').toLowerCase();
      const qOk = !q || text.includes(q);
      el.classList.toggle('hidden-by-filter', !qOk);
    }});
    document.querySelectorAll('.section').forEach((section) => {{
      if (!q) {{
        section.classList.remove('hidden-by-filter');
        return;
      }}
      const visible = section.querySelectorAll('.url-row:not(.hidden-by-filter), .issue:not(.hidden-by-filter), .finding-row:not(.hidden-by-filter), li:not(.hidden-by-filter)');
      const bodyText = (section.textContent || '').toLowerCase();
      const keep = visible.length > 0 || bodyText.includes(q);
      section.classList.toggle('hidden-by-filter', !keep);
      if (keep && q) section.classList.remove('collapsed');
    }});
  }}

  document.querySelectorAll('.sev-filters .chip').forEach((chip) => {{
    chip.addEventListener('click', () => {{
      document.querySelectorAll('.sev-filters .chip').forEach((c) => c.classList.remove('active'));
      chip.classList.add('active');
      activeSeverity = chip.getAttribute('data-sev') || 'all';
      applyFilters();
    }});
  }});

  search.addEventListener('input', applyFilters);

  document.addEventListener('keydown', (ev) => {{
    const tag = (ev.target && ev.target.tagName || '').toLowerCase();
    if (ev.key === '/' && tag !== 'input' && tag !== 'textarea') {{
      ev.preventDefault();
      search.focus();
      search.select();
    }}
    if (ev.key === 'Escape' && document.activeElement === search) {{
      search.blur();
      search.value = '';
      applyFilters();
    }}
  }});

  document.querySelectorAll('.section-head').forEach((head) => {{
    head.addEventListener('click', () => {{
      head.parentElement.classList.toggle('collapsed');
    }});
  }});

  document.getElementById('btn-collapse').addEventListener('click', () => {{
    document.querySelectorAll('.section').forEach((s) => s.classList.add('collapsed'));
    collapsedAll = true;
  }});
  document.getElementById('btn-expand').addEventListener('click', () => {{
    document.querySelectorAll('.section').forEach((s) => s.classList.remove('collapsed'));
    collapsedAll = false;
  }});

  document.body.addEventListener('click', (ev) => {{
    const copyBtn = ev.target.closest('.copy-btn');
    if (copyBtn) {{
      const value = copyBtn.getAttribute('data-copy') || '';
      if (navigator.clipboard && navigator.clipboard.writeText) {{
        navigator.clipboard.writeText(value).then(() => showToast('URL copied'));
      }} else {{
        const ta = document.createElement('textarea');
        ta.value = value; document.body.appendChild(ta); ta.select();
        document.execCommand('copy'); ta.remove();
        showToast('URL copied');
      }}
      return;
    }}
    const expandBtn = ev.target.closest('.expand-btn');
    if (expandBtn) {{
      const full = expandBtn.parentElement.querySelector('.url-full');
      if (full) full.classList.toggle('hidden');
    }}
  }});

  document.getElementById('btn-export').addEventListener('click', () => {{
    const rows = [];
    rows.push(['severity', 'category', 'url', 'detail']);
    document.querySelectorAll('.finding-row:not(.hidden-by-filter)').forEach((tr) => {{
      const cells = tr.querySelectorAll('td');
      rows.push([
        (cells[0] && cells[0].innerText || '').trim(),
        (cells[1] && cells[1].innerText || '').trim(),
        (cells[2] && (cells[2].querySelector('a') || {{}}).href || cells[2].innerText || '').trim(),
        (cells[3] && cells[3].innerText || '').trim(),
      ]);
    }});
    document.querySelectorAll('.issue:not(.hidden-by-filter)').forEach((issue) => {{
      const sev = issue.getAttribute('data-severity') || '';
      const title = (issue.querySelector('h3') || {{}}).innerText || '';
      issue.querySelectorAll('.url-row:not(.hidden-by-filter)').forEach((tr) => {{
        rows.push([sev, title, tr.getAttribute('data-text') || '', 'issue path']);
      }});
    }});
    document.querySelectorAll('.url-row:not(.hidden-by-filter)').forEach((tr) => {{
      const text = tr.getAttribute('data-text') || '';
      if (text.startsWith('http') || text.includes('://')) {{
        rows.push(['', 'url', text, '']);
      }}
    }});
    // de-dupe
    const seen = new Set();
    const unique = [];
    rows.forEach((r, idx) => {{
      const key = r.join('\\t');
      if (idx === 0 || !seen.has(key)) {{ seen.add(key); unique.push(r); }}
    }});
    const csv = unique.map((r) => r.map((c) => {{
      const s = String(c).replace(/"/g, '""');
      return '"' + s + '"';
    }}).join(',')).join('\\n');
    const blob = new Blob([csv], {{ type: 'text/csv;charset=utf-8' }});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'vantacrawl_visible_export.csv';
    a.click();
    URL.revokeObjectURL(a.href);
    showToast('Exported ' + Math.max(unique.length - 1, 0) + ' row(s)');
  }});
}})();
</script>
</body>
</html>"""
