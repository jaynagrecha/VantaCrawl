"""Professional dual-audience assessment HTML (client exec + engineer detail)."""

from __future__ import annotations

from html import escape
from typing import Any, Dict, List


def _sev_class(severity: str) -> str:
    return escape((severity or "info").lower())


def _url_list(urls: List[str], *, limit: int = 12) -> str:
    items = list(urls or [])[:limit]
    if not items:
        return "<p class='muted'>No sample URLs captured for this issue.</p>"
    lis = "".join(
        f'<li><a href="{escape(u)}" target="_blank" rel="noopener">{escape(u)}</a></li>' for u in items
    )
    more = ""
    if len(urls) > limit:
        more = f"<p class='muted'>Showing {limit} of {len(urls)} URL(s).</p>"
    return f"<ul class='url-list'>{lis}</ul>{more}"


def render_assessment_html(doc: Dict[str, Any], *, technical_report_name: str = "") -> str:
    sev = doc.get("severity_counts") or {}
    metrics = doc.get("metrics") or {}
    findings = doc.get("findings") or []
    roadmap = doc.get("roadmap") or []
    protections = doc.get("protections") or []
    defense = doc.get("defense") or {}

    exec_points = "".join(f"<li>{escape(p)}</li>" for p in (doc.get("top_executive_points") or []))
    methodology = "".join(f"<li>{escape(m)}</li>" for m in (doc.get("methodology") or []))
    limitations = "".join(f"<li>{escape(m)}</li>" for m in (doc.get("limitations") or []))
    recommendations = "".join(f"<li>{escape(r)}</li>" for r in (doc.get("recommendations") or []))

    roadmap_rows = "".join(
        "<tr>"
        f"<td>{escape(r.get('priority', ''))}</td>"
        f"<td>{escape(r.get('item', ''))}</td>"
        f"<td>{escape(r.get('fix', ''))}</td>"
        "</tr>"
        for r in roadmap
    ) or "<tr><td colspan='3' class='muted'>No remediation items queued.</td></tr>"

    def _render_finding(f: Dict[str, Any]) -> str:
        sev_l = _sev_class(str(f.get("severity")))
        evidence = f.get("evidence") or []
        kind = str(f.get("finding_kind") or "")
        kind_badge = (
            "<span class='pill'>Hardening</span>"
            if kind == "hardening"
            else "<span class='pill'>Vulnerability</span>"
            if kind == "vulnerability"
            else ""
        )
        if evidence:
            try:
                from security_scan import secret_reveal_html

                secret_type = ""
                title = str(f.get("title") or "")
                if title.lower().startswith("exposed "):
                    secret_type = title[8:].strip()
                detail = str(f.get("detail") or "")
                if not secret_type and detail.lower().startswith("exposed "):
                    secret_type = detail[8:].split(" in response", 1)[0].strip()
                chips = []
                for e in evidence[:10]:
                    chip = secret_reveal_html(
                        str(e),
                        secret_type=secret_type if f.get("category") == "secrets_exposure" else "",
                    )
                    if chip:
                        chips.append(chip)
                if f.get("category") == "secrets_exposure" and chips:
                    type_note = (
                        f"<p><strong>Credential type:</strong> {escape(secret_type)}</p>"
                        if secret_type
                        else ""
                    )
                    ev_html = (
                        f"{type_note}"
                        "<p class='muted'>Masked by default — expand to reveal the full value.</p>"
                        f"<ul class='chips secret-list'>{''.join(chips)}</ul>"
                    )
                else:
                    ev_html = (
                        "<p class='muted'>Exact matched pattern(s) that triggered this finding:</p>"
                        "<ul class='chips'>"
                        + "".join(f"<li><code>{escape(str(e))}</code></li>" for e in evidence[:10])
                        + "</ul>"
                    )
            except Exception:
                ev_html = (
                    "<p class='muted'>Exact matched pattern(s) that triggered this finding:</p>"
                    "<ul class='chips'>"
                    + "".join(f"<li><code>{escape(str(e))}</code></li>" for e in evidence[:10])
                    + "</ul>"
                )
        else:
            ev_html = "<p class='muted'>No matched pattern / evidence snippet stored for this finding.</p>"
        impact_meta = ""
        if f.get("impact") or f.get("role") or f.get("verification"):
            impact_meta = (
                f" · <strong>Kind:</strong> {escape(kind or 'n/a')}"
                f" · <strong>Impact:</strong> {escape(str(f.get('impact') or 'n/a'))}"
                f" · <strong>Role:</strong> {escape(str(f.get('role') or 'n/a'))}"
            )
            if f.get("verification"):
                impact_meta += (
                    f" · <strong>Verification:</strong> {escape(str(f.get('verification')).upper())}"
                )
            if f.get("confidence"):
                conf = escape(str(f.get("confidence")))
                reason = escape(str(f.get("confidence_reason") or ""))
                impact_meta += f" · <strong>Confidence:</strong> {conf}"
                if reason:
                    impact_meta += f" ({reason})"
        proof = f.get("proof") if isinstance(f.get("proof"), dict) else {}
        proof_bits = []
        for label, key in (
            ("Request", "request"),
            ("Response", "response"),
            ("Evidence", "evidence"),
            ("Impact", "impact"),
        ):
            val = (proof.get(key) or "").strip()
            if val:
                proof_bits.append(
                    f"<div><h6>{label}</h6><pre class='proof'>{escape(val)}</pre></div>"
                )
        proof_html = (
            "<h5>Proof</h5><div class='proof-grid'>" + "".join(proof_bits) + "</div>"
            if proof_bits
            else ""
        )
        ver = str(f.get("verification") or "").upper()
        ver_badge = f"<span class='pill'>{escape(ver)}</span>" if ver else ""
        return f"""
<article class="finding sev-{sev_l}" id="{escape(str(f.get('id')))}">
  <header>
    <span class="badge sev-{sev_l}">{escape(str(f.get('severity', '')).upper())}</span>
    {kind_badge}
    {ver_badge}
    <span class="fid">{escape(str(f.get('id')))}</span>
    <h3>{escape(str(f.get('title')))}</h3>
  </header>
  <section class="audience client">
    <h4>For decision makers</h4>
    <p>{escape(str(f.get('executive')))}</p>
  </section>
  <section class="audience eng">
    <h4>For security engineers</h4>
    <p class="meta"><strong>Category:</strong> {escape(str(f.get('category')))}
       · <strong>Signal:</strong> {escape(str(f.get('detail')))}
       · <strong>Occurrences:</strong> {escape(str(f.get('count')))}
       · <strong>Hosts:</strong> {escape(str(f.get('unique_hosts')))}{impact_meta}</p>
    <div class="grid3">
      <div><h5>What this means</h5><p>{escape(str(f.get('what')))}</p></div>
      <div><h5>Attacker use</h5><p>{escape(str(f.get('attacker')))}</p></div>
      <div><h5>How to fix</h5><p>{escape(str(f.get('fix')))}</p></div>
    </div>
    <h5>Matched pattern / evidence</h5>
    {ev_html}
    {proof_html}
    <h5>Affected URL(s)</h5>
    {_url_list(list(f.get('urls') or []))}
  </section>
</article>
"""

    vulns = list(doc.get("vulnerabilities") or [])
    hardening = list(doc.get("hardening_issues") or [])
    if not vulns and not hardening:
        # Backward compatible: classify from flat findings list
        for f in findings:
            if str(f.get("finding_kind") or "") == "hardening":
                hardening.append(f)
            else:
                vulns.append(f)

    vuln_html = "\n".join(_render_finding(f) for f in vulns) or (
        "<p class='empty'>No demonstrated vulnerabilities in this run.</p>"
    )
    hard_html = "\n".join(_render_finding(f) for f in hardening) or (
        "<p class='empty'>No hardening / misconfiguration observations in this run.</p>"
    )
    findings_html = f"""
    <h3>4a. Vulnerabilities</h3>
    <p class="muted">Demonstrated or high-confidence attack classes (XSS, injection, auth issues, proven secret abuse, …).</p>
    {vuln_html}
    <h3>4b. Hardening issues</h3>
    <p class="muted">Security misconfigurations and hygiene — not the same as exploitable vulnerabilities unless impact is proven.</p>
    {hard_html}
    """

    enum_hits = doc.get("enum_hits") or []
    enum_html = _url_list(list(enum_hits), limit=30)
    prot_html = (
        "".join(f"<li>{escape(p)}</li>" for p in protections) or "<li class='muted'>None clearly fingerprinted</li>"
    )
    status_counts = doc.get("block_status_counts") or defense.get("block_status_counts") or {}
    status_html = (
        "".join(
            f"<li>HTTP {escape(str(code))}: {escape(str(count))}</li>"
            for code, count in sorted(status_counts.items(), key=lambda x: -int(x[1]))
        )
        or "<li class='muted'>No block status codes recorded</li>"
    )
    forensic_items = doc.get("block_events_forensic") or defense.get("block_events_forensic") or []
    forensic_rows = []
    for item in list(forensic_items)[:25]:
        headers = item.get("headers") or {}
        header_bits = ", ".join(f"{k}={v}" for k, v in list(headers.items())[:5])
        forensic_rows.append(
            "<tr>"
            f"<td>{escape(str(item.get('status')))}</td>"
            f"<td>{escape(str(item.get('signal')))}</td>"
            f"<td>{escape(', '.join(item.get('protections') or []))}</td>"
            f"<td class='url'>{escape(str(item.get('url')))}</td>"
            f"<td>{escape(str(item.get('reason')))}</td>"
            f"<td><code>{escape(header_bits)}</code></td>"
            "</tr>"
        )
    forensic_table = (
        "<table><thead><tr><th>Status</th><th>Signal</th><th>Protections</th>"
        "<th>URL</th><th>Why</th><th>Headers</th></tr></thead><tbody>"
        + ("".join(forensic_rows) or "<tr><td colspan='6' class='muted'>No forensic block events.</td></tr>")
        + "</tbody></table>"
    )
    tech_note = ""
    if technical_report_name:
        tech_note = (
            f"<p>Detailed interactive technical appendix: "
            f"<strong>{escape(technical_report_name)}</strong></p>"
        )

    risk = escape(str(doc.get("risk_level") or "Clear")).lower()
    elapsed = float(metrics.get("elapsed_seconds") or 0)
    if elapsed >= 3600:
        duration = f"{int(elapsed // 3600)}h {int((elapsed % 3600) // 60)}m"
    elif elapsed >= 60:
        duration = f"{int(elapsed // 60)}m {int(elapsed % 60)}s"
    else:
        duration = f"{int(elapsed)}s"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{escape(str(doc.get('document_title')))} — {escape(str(doc.get('host')))}</title>
<style>
:root {{
  --bg: #0b1220;
  --panel: #121a2b;
  --line: #24304a;
  --text: #e8eefc;
  --muted: #8b9bb8;
  --accent: #3dd6c6;
  --critical: #ff5d6c;
  --high: #ff8b4a;
  --medium: #f0c14a;
  --low: #7db7ff;
  --info: #9aa8c7;
  --ok: #7dffa8;
  --serif: "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
  --sans: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, "Cascadia Mono", Consolas, monospace;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; color: var(--text); background:
    radial-gradient(1200px 500px at 10% -10%, rgba(61,214,198,.12), transparent 55%),
    radial-gradient(900px 400px at 90% 0%, rgba(125,183,255,.08), transparent 50%),
    var(--bg);
  font-family: var(--sans); line-height: 1.55;
}}
.wrap {{ max-width: 1080px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }}
.cover {{
  border: 1px solid var(--line); border-radius: 18px; padding: 2rem 1.75rem;
  background: linear-gradient(145deg, rgba(61,214,198,.1), transparent 45%), var(--panel);
  margin-bottom: 1.5rem;
}}
.brand {{ letter-spacing: .14em; text-transform: uppercase; color: var(--accent); font-size: .72rem; font-weight: 800; }}
h1 {{ font-family: var(--serif); font-weight: 600; font-size: clamp(1.8rem, 3vw, 2.4rem); margin: .4rem 0 .6rem; }}
h2 {{ font-family: var(--serif); font-size: 1.45rem; margin: 0 0 .75rem; }}
h3 {{ margin: .2rem 0; font-size: 1.1rem; }}
h4 {{ margin: .8rem 0 .35rem; color: var(--accent); font-size: .82rem; text-transform: uppercase; letter-spacing: .06em; }}
h5 {{ margin: .55rem 0 .25rem; font-size: .9rem; }}
.muted {{ color: var(--muted); }}
.mono {{ font-family: var(--mono); font-size: .86rem; word-break: break-all; }}
.pill-row {{ display: flex; flex-wrap: wrap; gap: .5rem; margin: .9rem 0 0; }}
.pill {{
  border: 1px solid var(--line); border-radius: 999px; padding: .25rem .7rem;
  font-size: .78rem; color: var(--muted); background: rgba(0,0,0,.18);
}}
.proof-grid {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: .65rem; margin: .4rem 0 .9rem;
}}
.proof-grid h6 {{ margin: 0 0 .25rem; font-size: .75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }}
pre.proof {{
  margin: 0; padding: .55rem .7rem; border-radius: 10px; border: 1px solid var(--line);
  background: rgba(0,0,0,.28); font-family: var(--mono); font-size: .78rem;
  white-space: pre-wrap; word-break: break-word; max-height: 160px; overflow: auto;
}}
.risk {{
  display: inline-block; margin-top: .85rem; padding: .45rem .9rem; border-radius: 999px;
  font-weight: 800; letter-spacing: .04em; border: 1px solid;
}}
.risk.critical {{ color: var(--critical); border-color: rgba(255,93,108,.5); }}
.risk.high {{ color: var(--high); border-color: rgba(255,139,74,.5); }}
.risk.medium {{ color: var(--medium); border-color: rgba(240,193,74,.5); }}
.risk.low {{ color: var(--low); border-color: rgba(125,183,255,.5); }}
.risk.clear {{ color: var(--ok); border-color: rgba(125,255,168,.45); }}
.section {{
  border: 1px solid var(--line); border-radius: 16px; padding: 1.25rem 1.35rem;
  background: var(--panel); margin: 1rem 0;
}}
.stats {{
  display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: .65rem;
}}
.stat {{
  text-align: center; background: rgba(0,0,0,.22); border: 1px solid var(--line);
  border-radius: 12px; padding: .75rem .4rem;
}}
.stat b {{ display: block; color: var(--accent); font-size: 1.25rem; }}
.stat span {{ font-size: .72rem; color: var(--muted); }}
.sev-board {{ display: flex; flex-wrap: wrap; gap: .5rem; margin-top: .75rem; }}
.badge {{
  display: inline-block; padding: .15rem .55rem; border-radius: 999px; font-size: .7rem; font-weight: 800;
  border: 1px solid var(--line);
}}
.badge.sev-critical {{ color: var(--critical); border-color: rgba(255,93,108,.45); }}
.badge.sev-high {{ color: var(--high); border-color: rgba(255,139,74,.45); }}
.badge.sev-medium {{ color: var(--medium); border-color: rgba(240,193,74,.45); }}
.badge.sev-low {{ color: var(--low); border-color: rgba(125,183,255,.45); }}
.badge.sev-info {{ color: var(--info); }}
.finding {{
  border: 1px solid var(--line); border-radius: 14px; padding: 1rem 1.1rem; margin: .9rem 0;
  background: rgba(0,0,0,.16);
}}
.finding header {{ display: flex; flex-wrap: wrap; gap: .55rem; align-items: center; margin-bottom: .35rem; }}
.fid {{ color: var(--muted); font-family: var(--mono); font-size: .78rem; }}
.audience.client {{
  border-left: 3px solid var(--accent); padding-left: .85rem; margin: .7rem 0;
}}
.audience.eng {{
  border-left: 3px solid rgba(125,183,255,.7); padding-left: .85rem; margin: .7rem 0;
}}
.grid3 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: .75rem; }}
.url-list {{ padding-left: 1.1rem; font-family: var(--mono); font-size: .78rem; }}
.chips {{ list-style: none; padding: 0; display: flex; flex-wrap: wrap; gap: .35rem; }}
.chips li {{ border: 1px solid var(--line); border-radius: 8px; padding: .2rem .45rem; background: rgba(0,0,0,.25); }}
.secret-reveal {{ margin: .25rem 0; max-width: 100%; }}
.secret-type {{
  display: inline-block; font-size: .72rem; font-weight: 700;
  color: var(--accent); margin-right: .35rem;
}}
.secret-details {{ display: inline; margin-left: .35rem; }}
.secret-details summary {{ cursor: pointer; color: var(--accent); font-size: .78rem; display: inline; }}
.secret-full {{ display: block; margin-top: .35rem; word-break: break-all; }}
table {{ width: 100%; border-collapse: collapse; font-size: .88rem; }}
th, td {{ border-bottom: 1px solid var(--line); padding: .55rem .4rem; text-align: left; vertical-align: top; }}
th {{ color: var(--muted); font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; }}
.toc a {{ color: var(--accent); text-decoration: none; }}
.toc li {{ margin: .25rem 0; }}
.empty {{ color: var(--muted); }}
footer {{ margin-top: 2rem; color: var(--muted); font-size: .8rem; }}
@media print {{
  body {{ background: #fff; color: #111; }}
  .cover, .section, .finding {{ break-inside: avoid; background: #fff; border-color: #ccc; }}
  .brand, h4, .stat b, a {{ color: #0a5; }}
}}
</style>
</head>
<body>
<div class="wrap">
  <header class="cover">
    <div class="brand">{escape(str(doc.get('product') or 'VantaCrawl'))}</div>
    <h1>{escape(str(doc.get('document_title') or 'Security Assessment Report'))}</h1>
    <p class="mono muted">{escape(str(doc.get('start_url')))}</p>
    <p class="muted">{escape(str(doc.get('job_title')))} · Mode: {escape(str(doc.get('mode')))} · Generated {escape(str(doc.get('generated_at')))}</p>
    <div class="risk {risk}">Overall risk: {escape(str(doc.get('risk_level')))}</div>
    <div class="pill-row">
      <span class="pill">Dual audience: executives + security engineers</span>
      <span class="pill">Authorized testing assumed</span>
      <span class="pill">Duration {escape(duration)}</span>
    </div>
  </header>

  <nav class="section toc">
    <h2>Contents</h2>
    <ol>
      <li><a href="#exec">Executive summary</a></li>
      <li><a href="#scope">Scope &amp; methodology</a></li>
      <li><a href="#metrics">Assessment metrics</a></li>
      <li><a href="#findings">Findings — vulnerabilities vs hardening</a></li>
      <li><a href="#surface">Attack surface notes</a></li>
      <li><a href="#roadmap">Remediation roadmap</a></li>
      <li><a href="#limits">Limitations &amp; confidence</a></li>
    </ol>
  </nav>

  <section class="section" id="exec">
    <h2>1. Executive summary</h2>
    <p><strong>{escape(str(doc.get('exec_headline')))}</strong></p>
    <p>{escape(str(doc.get('verdict_body')))}</p>
    <div class="sev-board">
      <span class="badge sev-critical">CRITICAL {int(sev.get('critical') or 0)}</span>
      <span class="badge sev-high">HIGH {int(sev.get('high') or 0)}</span>
      <span class="badge sev-medium">MEDIUM {int(sev.get('medium') or 0)}</span>
      <span class="badge sev-low">LOW {int(sev.get('low') or 0)}</span>
      <span class="badge sev-info">INFO {int(sev.get('info') or 0)}</span>
    </div>
    <h4>Priority talking points</h4>
    <ul>{exec_points}</ul>
    <h4>Recommended focus</h4>
    <ul>{recommendations or '<li class="muted">No urgent actions listed.</li>'}</ul>
  </section>

  <section class="section" id="scope">
    <h2>2. Scope &amp; methodology</h2>
    <p><strong>Target:</strong> <span class="mono">{escape(str(doc.get('start_url')))}</span></p>
    <p class="muted">{escape(str(doc.get('authorization_note')))}</p>
    <h4>What this assessment did</h4>
    <ol>{methodology}</ol>
  </section>

  <section class="section" id="metrics">
    <h2>3. Assessment metrics</h2>
    <div class="stats">
      <div class="stat"><b>{int(metrics.get('pages_crawled') or 0)}</b><span>Pages crawled</span></div>
      <div class="stat"><b>{int(metrics.get('enum_hits') or 0)}</b><span>Enum hits</span></div>
      <div class="stat"><b>{int(metrics.get('findings') or 0)}</b><span>Raw findings</span></div>
      <div class="stat"><b>{int(metrics.get('errors') or 0)}</b><span>Fetch errors</span></div>
      <div class="stat"><b>{int(metrics.get('enum_words_tested') or 0)}</b><span>Enum words tested</span></div>
      <div class="stat"><b>{escape(duration)}</b><span>Duration</span></div>
    </div>
  </section>

  <section class="section" id="findings">
    <h2>4. Findings</h2>
    <p class="muted">Security misconfiguration is not the same as a security vulnerability. Overall risk is driven by section 4a.</p>
    <p class="muted">Each issue includes a short business-facing summary, then technical detail for engineers.</p>
    {findings_html}
  </section>

  <section class="section" id="surface">
    <h2>5. Attack surface notes</h2>
    <h4>Protections observed</h4>
    <ul>{prot_html}</ul>
    <p class="muted">Catch rate: {escape(str(defense.get('catch_rate_percent', 'n/a')))}% ·
      Gap rate: {escape(str(defense.get('gap_rate_percent', 'n/a')))}%</p>
    <h4>Block HTTP status codes</h4>
    <ul>{status_html}</ul>
    <h4>Forensic block / challenge log</h4>
    <p class="muted">URL, status, protection family, reason, and key response headers. Full body snippets are in the defense report JSON/HTML.</p>
    {forensic_table}
    <h4>Interesting / enum paths</h4>
    {enum_html}
  </section>

  <section class="section" id="roadmap">
    <h2>6. Remediation roadmap</h2>
    <table>
      <thead><tr><th>Priority</th><th>Item</th><th>Fix direction</th></tr></thead>
      <tbody>{roadmap_rows}</tbody>
    </table>
  </section>

  <section class="section" id="limits">
    <h2>7. Limitations &amp; confidence</h2>
    <ul>{limitations}</ul>
    {tech_note}
  </section>

  <footer>
    Generated by {escape(str(doc.get('product') or 'VantaCrawl'))}.
    This document is a point-in-time automated assessment aid — validate findings on authorized systems before production changes.
  </footer>
</div>
</body>
</html>
"""
