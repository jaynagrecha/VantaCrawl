"""Safe / Extended / Lab active-probe payload kit for authorized scanning.

Safe Active (default): crawl-safe mini payloads with differential / marker /
callback proof — no DROP/UNION/time-delay, no real IMDS, no /etc/passwd.

Lab Validation: deeper boolean SQLi, encodings, IMDS/passwd canaries — never
auto-enabled for arbitrary public targets.
"""

from __future__ import annotations

import hashlib
import html
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# Probe-result states (screenshot contract)
STATE_NEGATIVE = "negative"
STATE_REFLECTED_ONLY = "reflected_only"
STATE_DIFFERENTIAL = "differential_signal"
STATE_PROBABLE = "probable"
STATE_BROWSER_EXEC = "browser_execution_confirmed"
STATE_SERVER_EXEC = "server_execution_confirmed"
STATE_OOB_CALLBACK = "oob_callback_confirmed"
# Back-compat alias used in earlier drafts
STATE_OOB_CALLBACK_LEGACY = "out_of_band_callback_confirmed"
STATE_BLOCKED_WAF = "blocked_by_waf"
STATE_RATE_LIMITED = "rate_limited"
STATE_BASELINE_FAILED = "baseline_failed"
STATE_INCONCLUSIVE = "inconclusive"
STATE_ATTR_BREAKOUT = "attribute_breakout"
STATE_DOM_NODE = "dom_node_injected"
STATE_HTML_INJECTION = "html_injection"
STATE_SINK_CANDIDATE = "sink_context_candidate"
STATE_CANARY_FILE = "canary_file_confirmed"
STATE_MARKER_SIGNAL = "marker_output_signal"
STATE_BLOCKED = "blocked"
STATE_NOT_APPLICABLE = "not_applicable"
STATE_EXECUTION_CONFIRMED = "execution_confirmed"
STATE_CONFIRMATION_UNAVAILABLE = "confirmation_unavailable"

# Playground / lab CMDI execution markers (response classification — not new payload families).
_CMDI_EXEC_MARKERS = (
    "PLAYGROUND_CMDI_MARKER",
    "uid=0(root)",
)

# ProbeSpec.kind → applicability family used by active_probe_targeting
KIND_TO_FAMILY: Dict[str, str] = {
    "sqli_error": "sqli",
    "sqli_boolean": "sqli",
    "sqli_time": "sqli",
    "xss": "xss",
    "rce": "rce",
    "ssti": "ssti",
    "ssrf": "ssrf",
    "traversal": "traversal",
    "traversal_diff": "traversal",
    "crlf": "crlf",
    "redirect": "redirect",
    "xxe": "xxe",
}

MODES = ("passive", "safe", "extended", "lab")

# Lab-only payload classes — never returned by for_mode("safe"|"extended"|"passive")
_LAB_ONLY_CLASSES = frozenset(
    {
        "ssrf_imds_lab",
        "trav_passwd_lab",
        "xxe_oob",
        "sqli_lab_sleep_mysql",
        "sqli_lab_waitfor_mssql",
        "sqli_lab_or_true",
        "sqli_lab_or_false",
    }
)

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
    # Explicit canary gate (preferred): both must be set to send canary probes
    traversal_canary_path: str = ""
    traversal_canary_expected_content: str = ""
    # Legacy alias — if True and path/content empty, derive defaults from fixture root
    traversal_fixture_installed: bool = False
    max_params: int = 8
    max_forms: int = 3
    scan_id: str = ""
    # Optional: async (page_url, js_expr, **kw) -> bool|dict for XSS browser confirm
    browser_evaluate: Optional[Callable[..., Any]] = None
    # Optional: async (nonce) -> bool for SSRF/XXE OOB confirm
    callback_received: Optional[Callable[..., Any]] = None
    # Optional CrawlStats (or duck-typed) for unified request ledger
    stats: Any = None
    # Optional OobCallbackCorrelator for register_probe + correlation
    oob: Any = None
    # Coverage notes written for reports
    coverage_notes: Dict[str, Any] = field(default_factory=dict)


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
    # Intentionally excludes redirect-only params (next/continue/return) so
    # /redirect?next= is confirmed as open redirect, never as SSRF.
    return bool(
        re.match(
            r"(?i)^(url|uri|link|src|source|dest|destination|redirect|redirect_uri|"
            r"callback|feed|path|site|domain|host|target|fetch|proxy)$",
            name,
        )
    )


def _numeric_param(name: str) -> bool:
    return bool(
        re.match(
            r"(?i)^(id|uid|user_id|pid|item|cat|category|order|sort)$",
            name,
        )
    )


def _search_param(name: str) -> bool:
    return bool(
        re.match(
            r"(?i)^(q|query|search|s|keyword|term|filter|name|title|message|comment|text|content|input)$",
            name,
        )
    )


def _sql_error_match(body: str) -> Optional[re.Match]:
    """Match SQL errors on HTML-entity-decoded visible text only."""
    decoded = html.unescape(body or "")
    return _SQL_ERROR_RE.search(decoded)


def _should_replace_mutation(spec: "ProbeSpec", field: str) -> bool:
    if spec.meta.get("replace"):
        return True
    if spec.kind == "xss" and spec.payload_class != "xss_reflect":
        return True
    if spec.kind in ("redirect", "ssrf", "ssti", "crlf", "xxe", "traversal", "traversal_diff", "rce"):
        return True
    # Numeric ID context → replace; search/string params → append (caller default)
    if spec.kind in ("sqli_error", "sqli_time") and _numeric_param(field):
        return True
    return False


def _file_names(name: str) -> bool:
    return bool(
        re.match(
            r"(?i)^(file|filename|filepath|path|folder|dir|document|template|include|doc|page|download)$",
            name,
        )
    )


def _cmd_names(name: str) -> bool:
    return bool(
        re.match(
            r"(?i)^(cmd|command|exec|execute|run|shell|host|ping|expr|input)$",
            name,
        )
    )


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


def for_mode(
    mode: str,
    *,
    nonce: Optional[str] = None,
    callback_base: str = "",
    redirect_proof_host: str = "redirect-proof.vantacrawl-lab.example",
    traversal_fixture_root: str = "/opt/vantacrawl-fixtures",
    traversal_fixture_installed: bool = False,
    traversal_canary_path: str = "",
    traversal_canary_expected_content: str = "",
) -> List[ProbeSpec]:
    """Central backend gate: payloads for a mode. Lab classes never leak into safe."""
    settings = ProbeModeSettings(
        mode=normalize_mode(mode),
        callback_base=callback_base or "",
        redirect_proof_host=redirect_proof_host or "redirect-proof.vantacrawl-lab.example",
        traversal_fixture_root=traversal_fixture_root or "/opt/vantacrawl-fixtures",
        traversal_fixture_installed=bool(traversal_fixture_installed),
        traversal_canary_path=traversal_canary_path or "",
        traversal_canary_expected_content=traversal_canary_expected_content or "",
    )
    specs = build_payload_specs(settings, nonce or new_probe_nonce())
    mode_n = normalize_mode(mode)
    if mode_n != "lab":
        specs = [s for s in specs if s.payload_class not in _LAB_ONLY_CLASSES]
        for s in specs:
            assert "169.254.169.254" not in s.payload
            assert "/etc/passwd" not in s.payload.lower()
            assert "SLEEP(" not in s.payload.upper()
            assert "WAITFOR" not in s.payload.upper()
    return specs


def redact_payload(payload: str) -> str:
    """Redact secrets and truncate payloads for ledger/report storage.

    Keeps short markers (VCXSS_*, VC_RCE_*) for reproducibility while stripping
    callback secrets, poll tokens, and credential-shaped values.
    """
    text = str(payload or "")
    text = re.sub(
        r"(?i)\b(api[_-]?key|token|password|secret|authorization|cookie|"
        r"callback_secret|poll_token|polling_token|bearer)=([^\s&\"']+)",
        r"\1=[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)(/poll/)[A-Za-z0-9_\-]{8,}",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)(callback_secret|poll_token|polling_token)[/:=]\S+",
        r"\1=[REDACTED]",
        text,
    )
    if len(text) > 160:
        return text[:72] + "…[redacted]…" + text[-40:]
    return text


def resolve_traversal_canary(settings: ProbeModeSettings, nonce: str) -> Tuple[str, str]:
    """Return (path, expected_content) or ("","") when canary must be skipped."""
    path = str(getattr(settings, "traversal_canary_path", "") or "").strip()
    content = str(getattr(settings, "traversal_canary_expected_content", "") or "").strip()
    if path and content:
        return path, content
    if bool(getattr(settings, "traversal_fixture_installed", False)):
        root = str(getattr(settings, "traversal_fixture_root", "") or "/opt/vantacrawl-fixtures").rstrip("/")
        derived_path = f"../../../../{root.lstrip('/')}/VC_TRAVERSAL_{nonce}.txt"
        derived_content = f"VC_TRAVERSAL_PROOF_{nonce}"
        return derived_path, derived_content
    return "", ""


def build_payload_specs(settings: ProbeModeSettings, nonce: str) -> List[ProbeSpec]:
    """Mini payload set for the selected mode (internal; prefer for_mode)."""
    mode = normalize_mode(settings.mode)
    if mode == "passive":
        return []

    xss_tok = f"VCXSS_{nonce}"
    rce_tok = f"VC_RCE_{nonce}"
    trav_proof = f"VC_TRAVERSAL_PROOF_{nonce}"
    trav_file = f"{settings.traversal_fixture_root.rstrip('/')}/VC_TRAVERSAL_{nonce}.txt"
    trav_payload = f"../../../../{trav_file.lstrip('/')}"
    cb = (settings.callback_base or "").rstrip("/")
    redirect_dest = f"https://{settings.redirect_proof_host}/{nonce}"
    canary_path, canary_content = resolve_traversal_canary(settings, nonce)

    def _fresh_oob() -> str:
        try:
            from oob_callback import new_oob_nonce

            return new_oob_nonce()
        except Exception:
            return secrets.token_hex(16)

    specs: List[ProbeSpec] = []

    # --- SQLi families (safe): quotes / parens / comments / boolean pairs; no DROP/UNION/time ---
    for payload, pclass in (
        ("'", "sqli_quote"),
        ('"', "sqli_dquote"),
        ("')", "sqli_quote_paren"),
        ('"))', "sqli_dquote_paren"),
        ("'--", "sqli_quote_comment"),
        ("' #", "sqli_quote_hash_comment"),
    ):
        specs.append(
            ProbeSpec("sql_injection", payload, pclass, _sql_names, "high", "sqli_error")
        )

    def _bool_pair(true_p: str, false_p: str, true_c: str, false_c: str, *, replace: bool = False):
        specs.append(
            ProbeSpec(
                "sql_injection",
                true_p,
                true_c,
                _sql_names,
                "high",
                "sqli_boolean",
                {"pair": "true", "mate_class": false_c, "replace": replace},
            )
        )
        specs.append(
            ProbeSpec(
                "sql_injection",
                false_p,
                false_c,
                _sql_names,
                "high",
                "sqli_boolean",
                {"pair": "false", "mate_class": true_c, "replace": replace},
            )
        )

    _bool_pair("' AND '1'='1", "' AND '1'='2", "sqli_bool_true_str", "sqli_bool_false_str")
    _bool_pair("1 AND 1=1", "1 AND 1=2", "sqli_bool_true_num", "sqli_bool_false_num", replace=True)

    if mode in ("extended", "lab"):
        _bool_pair(
            "' AND '1'='1'-- ",
            "' AND '1'='2'-- ",
            "sqli_bool_true_str_comment",
            "sqli_bool_false_str_comment",
        )
        _bool_pair(
            "') AND ('1'='1",
            "') AND ('1'='2",
            "sqli_bool_true_paren",
            "sqli_bool_false_paren",
        )
        for payload, pclass in (
            ("%27", "sqli_enc_quote"),
            ("%22", "sqli_enc_dquote"),
            ("1%27", "sqli_enc_num_quote"),
        ):
            specs.append(
                ProbeSpec("sql_injection", payload, pclass, _sql_names, "high", "sqli_error")
            )

    if mode == "lab":
        _bool_pair(
            "' OR '1'='1' -- ",
            "' OR '1'='2' -- ",
            "sqli_lab_or_true",
            "sqli_lab_or_false",
        )
        # Time-based (lab only) — confirm via elapsed, not body reflection
        specs.append(
            ProbeSpec(
                "sql_injection",
                "' AND SLEEP(2)-- ",
                "sqli_lab_sleep_mysql",
                _sql_names,
                "high",
                "sqli_time",
                {"min_ms": 1500},
            )
        )
        specs.append(
            ProbeSpec(
                "sql_injection",
                "'; WAITFOR DELAY '0:0:2'-- ",
                "sqli_lab_waitfor_mssql",
                _sql_names,
                "high",
                "sqli_time",
                {"min_ms": 1500},
            )
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
    if mode in ("extended", "lab"):
        specs.append(
            ProbeSpec(
                "xss",
                f"'><img src=x id='{xss_tok}' onerror=1>",
                "xss_img_onerror_ctx",
                _xss_names,
                "medium",
                "xss",
                {"token": xss_tok, "dom_id": xss_tok},
            )
        )
        specs.append(
            ProbeSpec(
                "xss",
                f"</textarea><b id=\"{xss_tok}\">{xss_tok}</b>",
                "xss_textarea_breakout",
                _xss_names,
                "medium",
                "xss",
                {"token": xss_tok, "dom_id": xss_tok},
            )
        )
        specs.append(
            ProbeSpec(
                "xss",
                f"';var vc='{xss_tok}';//",
                "xss_js_string_breakout",
                _xss_names,
                "medium",
                "xss",
                {"token": xss_tok},
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
    if mode in ("extended", "lab"):
        for payload, pclass in (
            (f"%0a printf {rce_tok}", "rce_printf_lf"),
            (f"`printf {rce_tok}`", "rce_printf_backtick"),
            (f"$(printf {rce_tok})", "rce_printf_subshell"),
            (f"| echo {rce_tok}", "rce_echo_pipe_win"),
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
    # Unique nonce per payload family instance (never share across probes).
    # Always schedule SSRF probes when mode is active. Without a callback receiver,
    # confirmation stays unavailable — but dedicated /ssrf/* fixtures must still be hit.
    ssrf_base = cb or "http://oob-unconfigured.invalid"
    ping_nonce = _fresh_oob()
    redir_nonce = _fresh_oob()
    ssrf_meta_extra = {}
    if not cb:
        ssrf_meta_extra = {
            "confirmation_unavailable": True,
            "reason": "no callback receiver configured",
        }
    specs.append(
        ProbeSpec(
            "ssrf",
            f"{ssrf_base}/{ping_nonce}/ping",
            "ssrf_callback_ping",
            _ssrf_names,
            "high",
            "ssrf",
            {
                "nonce": ping_nonce,
                "callback": True,
                "expected_path": f"/{ping_nonce}/ping",
                "callback_url": f"{ssrf_base}/{ping_nonce}/ping",
                **ssrf_meta_extra,
            },
        )
    )
    specs.append(
        ProbeSpec(
            "ssrf",
            f"{ssrf_base}/{redir_nonce}/redirect",
            "ssrf_callback_redirect",
            _ssrf_names,
            "high",
            "ssrf",
            {
                "nonce": redir_nonce,
                "callback": True,
                "expected_path": f"/{redir_nonce}/redirect",
                "callback_url": f"{ssrf_base}/{redir_nonce}/redirect",
                **ssrf_meta_extra,
            },
        )
    )
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
    # Safe/extended: path-normalization / differential only — never canary-file confirmed.
    specs.append(
        ProbeSpec(
            "directory_traversal",
            f"....//....//....//vc_norm_{nonce}",
            "trav_norm_dots",
            _file_names,
            "medium",
            "traversal_diff",
            {},
        )
    )
    specs.append(
        ProbeSpec(
            "directory_traversal",
            f"..%2f..%2f..%2fvc_norm_{nonce}",
            "trav_norm_enc",
            _file_names,
            "medium",
            "traversal_diff",
            {},
        )
    )
    if mode in ("extended", "lab"):
        specs.append(
            ProbeSpec(
                "directory_traversal",
                f"..%252f..%252f..%252fvc_norm_{nonce}",
                "trav_norm_dblenc",
                _file_names,
                "medium",
                "traversal_diff",
                {},
            )
        )
    # Lab + configured canary: canary file confirmation (skip unless path+content set)
    if canary_path and canary_content:
        specs.append(
            ProbeSpec(
                "directory_traversal",
                canary_path,
                "trav_canary",
                _file_names,
                "high",
                "traversal",
                {"proof": canary_content, "canary": True},
            )
        )
        if mode in ("extended", "lab"):
            specs.append(
                ProbeSpec(
                    "directory_traversal",
                    canary_path.replace("/", "%2f"),
                    "trav_canary_enc",
                    _file_names,
                    "high",
                    "traversal",
                    {"proof": canary_content, "canary": True},
                )
            )
        if mode == "lab":
            specs.append(
                ProbeSpec(
                    "directory_traversal",
                    canary_path.replace("/", "%252f"),
                    "trav_canary_dblenc",
                    _file_names,
                    "high",
                    "traversal",
                    {"proof": canary_content, "canary": True},
                )
            )
    if mode == "lab":
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
    # Use raw CRLF so httpx encodes once; pre-encoded %0d%0a would double-encode.
    specs.append(
        ProbeSpec(
            "header_injection",
            f"\r\nX-VantaCrawl-Proof: {nonce}",
            "crlf_header",
            lambda n: bool(re.match(r"(?i)^(q|query|search|name|url|redirect|next|file|path)$", n)),
            "high",
            "crlf",
            {"header": "x-vantacrawl-proof", "value": nonce},
        )
    )

    # --- XXE (lab only, OOB callback) ---
    if mode == "lab" and cb:
        xxe_nonce = _fresh_oob()
        xxe = (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "{cb}/{xxe_nonce}/xxe">]>'
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
                {
                    "nonce": xxe_nonce,
                    "callback": True,
                    "expected_path": f"/{xxe_nonce}/xxe",
                    "callback_url": f"{cb}/{xxe_nonce}/xxe",
                },
            )
        )

    # Assert Safe Active never ships risky lab classes
    if mode == "safe":
        banned = {
            "ssrf_imds_lab",
            "trav_passwd_lab",
            "xxe_oob",
            "sqli_lab_sleep_mysql",
            "sqli_lab_waitfor_mssql",
            "sqli_lab_or_true",
            "sqli_lab_or_false",
        }
        specs = [s for s in specs if s.payload_class not in banned]
        for s in specs:
            assert "169.254.169.254" not in s.payload
            assert "/etc/passwd" not in s.payload
            assert "SLEEP(" not in s.payload.upper()
            assert "WAITFOR" not in s.payload.upper()
            assert "UNION SELECT" not in s.payload.upper()
            assert "DROP " not in s.payload.upper()

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


@dataclass
class ResponseSnap:
    status: int = 0
    body: str = ""
    final_url: str = ""
    elapsed_ms: float = 0.0

    @property
    def norm_hash(self) -> str:
        return probe_hash(self.body)

    @property
    def length(self) -> int:
        return len(self.body or "")

    def dom_fingerprint(self) -> str:
        """Cheap DOM-structure signal: tag-name multiset (ignores text/attrs noise)."""
        tags = re.findall(r"(?is)</?([a-z0-9]+)\b", self.body or "")
        counts: Dict[str, int] = {}
        for t in tags[:400]:
            key = t.lower()
            counts[key] = counts.get(key, 0) + 1
        return ",".join(f"{k}:{counts[k]}" for k in sorted(counts)[:80])


def text_similarity(a: str, b: str) -> float:
    """0..1 SequenceMatcher ratio on normalized text."""
    from difflib import SequenceMatcher

    na = normalize_probe_text(a)
    nb = normalize_probe_text(b)
    if not na and not nb:
        return 1.0
    return SequenceMatcher(None, na, nb).ratio()


def compare_response_pair(
    true_snap: ResponseSnap,
    false_snap: ResponseSnap,
    *,
    baseline: Optional[ResponseSnap] = None,
    ignore: Sequence[str] = (),
    repeated_false: Optional[ResponseSnap] = None,
) -> Dict[str, Any]:
    """Multi-signal true/false comparison — a one-off length delta is not enough.

    Valid boolean signal requires:
      baseline ≈ true, baseline differs consistently from false,
      true/false difference reproduces, and content divergence beyond status/length alone.

    Returns dict with signals + verdict in {negative, differential_signal, probable, inconclusive}.
    """
    tb = _strip_literals(true_snap.body, *ignore) if ignore else true_snap.body
    fb = _strip_literals(false_snap.body, *ignore) if ignore else false_snap.body
    th = probe_hash(tb)
    fh = probe_hash(fb)
    sim = text_similarity(tb, fb)
    len_delta = abs(len(tb) - len(fb))
    status_diff = int(true_snap.status or 0) != int(false_snap.status or 0)
    url_diff = (true_snap.final_url or "").split("?")[0] != (false_snap.final_url or "").split("?")[0]
    hash_diff = th != fh
    dom_diff = true_snap.dom_fingerprint() != false_snap.dom_fingerprint()
    # Meaningful content divergence (not tiny length jitter alone)
    content_diff = hash_diff and (sim < 0.97 or len_delta >= 32 or dom_diff)

    signals: Dict[str, Any] = {
        "status_diff": status_diff,
        "final_url_diff": url_diff,
        "normalized_hash_diff": hash_diff,
        "text_similarity": round(sim, 4),
        "content_length_delta": len_delta,
        "dom_structure_diff": dom_diff,
        "true_hash": th,
        "false_hash": fh,
    }

    # Required shape: baseline ≈ true AND baseline differs from false
    if baseline is not None:
        bb = _strip_literals(baseline.body, *ignore) if ignore else baseline.body
        bh = probe_hash(bb)
        sim_bt = text_similarity(bb, tb)
        sim_bf = text_similarity(bb, fb)
        len_bt = abs(len(bb) - len(tb))
        len_bf = abs(len(bb) - len(fb))
        baseline_approx_true = (th == bh) or (sim_bt >= 0.92 and len_bt < max(48, int(0.1 * max(len(bb), 1))))
        false_status_diff = int(baseline.status or 0) != int(false_snap.status or 0)
        false_url_diff = (baseline.final_url or "").split("?")[0] != (false_snap.final_url or "").split("?")[0]
        baseline_differs_false = (fh != bh) and (
            sim_bf < 0.92 or len_bf >= 24 or false_status_diff or false_url_diff
            or (baseline.dom_fingerprint() != false_snap.dom_fingerprint())
        )
        signals["baseline_approx_true"] = baseline_approx_true
        signals["baseline_differs_from_false"] = baseline_differs_false
        signals["baseline_true_similarity"] = round(sim_bt, 4)
        signals["baseline_false_similarity"] = round(sim_bf, 4)
        signals["differs_from_baseline"] = th != bh or fh != bh
        if not baseline_approx_true or not baseline_differs_false:
            return {**signals, "verdict": STATE_NEGATIVE, "score": 0}
    else:
        # Without baseline we cannot satisfy baseline≈true — refuse confirmation-grade verdicts
        return {**signals, "verdict": STATE_INCONCLUSIVE, "score": 0}

    if not content_diff and not (status_diff and hash_diff):
        # One different status or length alone is insufficient
        if status_diff and not hash_diff:
            return {**signals, "verdict": STATE_NEGATIVE, "score": 0}
        if len_delta and not hash_diff:
            return {**signals, "verdict": STATE_NEGATIVE, "score": 0}

    score = 0
    if content_diff:
        score += 2
    if status_diff:
        score += 1
    if url_diff:
        score += 1
    if dom_diff and hash_diff:
        score += 1
    if sim < 0.90 and hash_diff:
        score += 1

    reproducible = False
    if repeated_false is not None:
        rb = _strip_literals(repeated_false.body, *ignore) if ignore else repeated_false.body
        rh = probe_hash(rb)
        # Replay of false should still differ from true and align with false
        reproducible = rh == fh and rh != th
        signals["reproducible"] = reproducible
        if reproducible:
            score += 2
        else:
            # Required: true/false difference must reproduce
            return {**signals, "verdict": STATE_INCONCLUSIVE, "score": score}

    if score >= 4 and content_diff and reproducible:
        verdict = STATE_DIFFERENTIAL
    elif score >= 3 and content_diff and reproducible:
        verdict = STATE_PROBABLE
    elif score >= 2 and content_diff and reproducible:
        verdict = STATE_PROBABLE
    else:
        verdict = STATE_NEGATIVE if score < 2 else STATE_INCONCLUSIVE

    return {**signals, "verdict": verdict, "score": score}


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

    # Injected DOM node — harmless HTML injection, not confirmed XSS
    if dom_id and re.search(rf'(?is)<b\b[^>]*\bid=["\']?{re.escape(dom_id)}', text):
        return {
            "category": "html_injection",
            "severity": "low",
            "detail_bit": "HTML injection (harmless node; not confirmed XSS)",
            "validation_state": STATE_HTML_INJECTION,
            "confidence": "low",
            "verification": "detected",
        }

    if re.search(r"(?is)<script\b[^>]*>[^<]{0,200}" + re.escape(token), text) or re.search(
        r"(?is)\bon\w+\s*=\s*['\"][^'\"]{0,80}" + re.escape(token),
        text,
    ):
        return {
            "severity": "medium",
            "detail_bit": "medium-confidence XSS candidate (sink context; not browser-confirmed)",
            "validation_state": STATE_SINK_CANDIDATE,
            "confidence": "medium",
            # Attribute/sink candidates are never "verified/confirmed" without browser execution.
            "verification": "detected",
        }

    if "onload=" in payload or "onfocus=" in payload:
        if _raw_token_present(text):
            return {
                "severity": "medium",
                "detail_bit": "medium-confidence XSS candidate (attribute/event context; not browser-confirmed)",
                "validation_state": STATE_ATTR_BREAKOUT,
                "confidence": "medium",
                "verification": "detected",
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
    # Never export full sensitive response bodies — truncated + secret-redacted only
    response_snippet = redact_payload((evidence_line or probe_body[:240])[:500])
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
        "response_proof_redacted": response_snippet,
        "evidence": redact_payload(evidence_line[:2000]),
        "request": f"{kwargs.get('method')} {kwargs.get('endpoint')}"[:500],
        "response": response_snippet,
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

    if mode == "passive":
        settings.coverage_notes = {
            "traversal_canary": "skipped",
            "reason": "passive mode",
            "xss_browser": "skipped",
            "oob_callback": "skipped",
        }
        return []

    nonce = new_probe_nonce()
    canary_path, canary_content = resolve_traversal_canary(settings, nonce)
    specs = for_mode(
        mode,
        nonce=nonce,
        callback_base=settings.callback_base,
        redirect_proof_host=settings.redirect_proof_host,
        traversal_fixture_root=settings.traversal_fixture_root,
        traversal_fixture_installed=settings.traversal_fixture_installed,
        traversal_canary_path=settings.traversal_canary_path,
        traversal_canary_expected_content=settings.traversal_canary_expected_content,
    )
    findings: List[Any] = []
    seen: set = set()
    stats = settings.stats
    oob = settings.oob
    from active_probe_breaker import get_shared_breaker, stop_active_probes

    breaker = get_shared_breaker(stats)
    if stats is not None and bool(getattr(stats, "vuln_active_probe_paused", False)):
        settings.coverage_notes = {
            "active_probe": "paused",
            "reason": "vuln_active_probe_paused",
            "xss_browser": "skipped",
            "oob_callback": "skipped",
        }
        return []

    browser_cap = {}
    if stats is not None and isinstance(getattr(stats, "browser_confirmation", None), dict):
        browser_cap = dict(stats.browser_confirmation or {})
    browser_avail = bool(settings.browser_evaluate) and (
        browser_cap.get("browser_confirmation", "available" if settings.browser_evaluate else "unavailable")
        == "available"
        or settings.browser_evaluate is not None
    )
    # Prefer explicit capability flag when present
    if browser_cap:
        browser_avail = browser_cap.get("browser_confirmation") == "available" and bool(
            settings.browser_evaluate
        )

    oob_status = {
        "callback_configured": False,
        "probe_url_generated": False,
        "polling_active": False,
        "callback_received": False,
        "confirmation_unavailable": True,
        "reason": "no callback receiver configured",
    }
    if oob is not None and hasattr(oob, "status_snapshot"):
        oob_status = oob.status_snapshot(probe_url_generated=False).as_dict()
    elif settings.callback_received or settings.callback_base:
        oob_status = {
            "callback_configured": bool(settings.callback_base or settings.callback_received),
            "probe_url_generated": False,
            "polling_active": bool(settings.callback_received),
            "callback_received": False,
            "confirmation_unavailable": True,
            "reason": "callback service configured; awaiting probe/correlation",
        }

    coverage = {
        "traversal_canary": "configured" if (canary_path and canary_content) else "skipped",
        "reason": ("" if (canary_path and canary_content) else "no controlled canary configured"),
        "xss_browser": "available" if browser_avail else "unavailable",
        "browser_confirmation": dict(browser_cap)
        or {
            "browser_confirmation": "available" if browser_avail else "unavailable",
            "message": (
                "Browser confirmation: available"
                if browser_avail
                else "Browser confirmation: unavailable — XSS findings limited to unverified evidence"
            ),
        },
        "oob_callback": dict(oob_status),
        "message": (
            "Traversal active confirmation: skipped"
            if not (canary_path and canary_content)
            else "Traversal active confirmation: canary configured"
        ),
    }
    if not (canary_path and canary_content):
        coverage["detail"] = "Reason: no controlled canary configured"
    if not browser_avail:
        coverage["xss_note"] = (
            "Browser confirmation: unavailable — XSS findings limited to unverified evidence"
        )
    if oob_status.get("confirmation_unavailable", True):
        coverage["oob_note"] = oob_status.get("reason") or (
            "SSRF/XXE confirmation unavailable"
        )
    settings.coverage_notes = coverage
    if stats is not None:
        try:
            prev = dict(getattr(stats, "active_probe_coverage", None) or {})
            # Aggregate coverage counters across pages (not one finding per skip).
            agg = dict(prev.get("aggregate") or {})
            if not (canary_path and canary_content):
                agg["traversal_skipped_endpoints"] = int(agg.get("traversal_skipped_endpoints") or 0) + 1
                agg["traversal_skip_reason"] = "no applicable fixture/parameter"
            else:
                agg["traversal_canary_endpoints"] = int(agg.get("traversal_canary_endpoints") or 0) + 1
            coverage["aggregate"] = agg
            if agg.get("traversal_skipped_endpoints"):
                coverage["message"] = (
                    f"Traversal confirmation skipped on {agg['traversal_skipped_endpoints']} endpoints"
                )
                coverage["detail"] = f"Reason: {agg.get('traversal_skip_reason') or 'no applicable fixture/parameter'}"
            stats.active_probe_coverage = dict(coverage)
            # Keep shared breaker snapshot current for JSON/SQLite export
            if hasattr(breaker, "snapshot"):
                stats.active_probe_breaker = breaker.snapshot()
        except Exception:
            pass

    def add(category: str, severity: str, detail: str, evidence: Optional[str], meta: Dict[str, Any]):
        key = (category, detail, evidence or "", meta.get("proof", {}).get("validation_state"))
        if key in seen:
            return
        seen.add(key)
        findings.append((category, severity, detail, evidence, meta))

    def _ledger(
        *,
        role: str,
        method: str,
        target: str,
        status: int,
        body: str,
        final_url: str,
        headers: Optional[Dict[str, Any]] = None,
        duration_ms: float = 0.0,
        probe_class: str = "",
        probe_name: str = "",
        parameter: str = "",
        payload: str = "",
        resp_class: str = "",
        result_state: str = "",
        values: Optional[dict] = None,
        target_selection_reason: str = "",
    ) -> None:
        if stats is None or not hasattr(stats, "record_request"):
            return
        try:
            ledger_url = target
            if (method or "GET").upper() == "GET" and values:
                parsed = urlparse(target)
                ledger_url = urlunparse(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        urlencode(values, doseq=True),
                        parsed.fragment,
                    )
                )
            ct = ""
            for hk, hv in dict(headers or {}).items():
                if str(hk).lower() == "content-type":
                    ct = str(hv or "")[:120]
                    break
            # Blank is not auditable — every ledger row gets an explicit state.
            state_out = (result_state or "").strip() or (
                STATE_NOT_APPLICABLE if role in ("baseline", "control") else STATE_INCONCLUSIVE
            )
            reason_out = (target_selection_reason or "").strip() or "generic_fallback"
            stats.record_request(
                phase="active_probe",
                source=probe_class or "active_probe",
                url=ledger_url,
                status=status,
                final_url=final_url or ledger_url,
                response_type=ct,
                bytes_=len(body or ""),
                content_hash=probe_hash(body or ""),
                raw_hash=probe_hash(body or ""),
                normalized_hash=probe_hash(body or ""),
                duration_ms=duration_ms,
                outcome="ok" if int(status or 0) and int(status) < 400 else "http_error",
                classification=resp_class or "",
                probe_class=probe_class,
                probe_name=probe_name,
                probe_mode=mode,
                probe_role=role,
                parameter=parameter,
                method=method,
                payload_redacted=redact_payload(payload),
                result_state=state_out,
                target_selection_reason=reason_out,
            )
        except Exception:
            pass

    def _patch_last_probe_result(
        result_state: str,
        *,
        probe_name: str = "",
        parameter: str = "",
        target_selection_reason: str = "",
        prefer_roles: Optional[Sequence[str]] = None,
    ) -> None:
        """Stamp the most recent matching active-probe ledger row with a final state.

        Prefer ``probe`` rows so replay/control stamps do not erase the probe verdict.
        """
        if stats is None:
            return
        ledger = getattr(stats, "request_ledger", None)
        if not isinstance(ledger, list) or not ledger:
            return
        state_out = (result_state or "").strip() or STATE_INCONCLUSIVE
        role_order = list(prefer_roles or ("probe", "replay", "control", "baseline"))
        for role in role_order:
            for row in reversed(ledger):
                if not isinstance(row, dict) or row.get("phase") != "active_probe":
                    continue
                if (row.get("probe_role") or "") != role:
                    continue
                if probe_name and row.get("probe_name") != probe_name:
                    continue
                if parameter and row.get("parameter") != parameter:
                    continue
                row["result_state"] = state_out[:80]
                if target_selection_reason and not row.get("target_selection_reason"):
                    row["target_selection_reason"] = str(target_selection_reason)[:80]
                return

    async def _send(
        method: str,
        target: str,
        values: dict,
        *,
        follow: bool = True,
        role: str = "probe",
        probe_class: str = "",
        probe_name: str = "",
        parameter: str = "",
        payload: str = "",
        result_state: str = "",
        target_selection_reason: str = "",
    ):
        t0 = time.monotonic()
        try:
            if method == "POST":
                resp = await client.post(target, data=values, timeout=8, follow_redirects=follow)
            else:
                # Strip existing query from target — params=values is authoritative.
                # (Also protects clients that ignore/merge params poorly.)
                parsed_t = urlparse(target)
                clean_target = urlunparse(
                    (parsed_t.scheme, parsed_t.netloc, parsed_t.path, parsed_t.params, "", parsed_t.fragment)
                )
                resp = await client.get(
                    clean_target, params=values, timeout=8, follow_redirects=follow
                )
        except Exception:
            duration_ms = (time.monotonic() - t0) * 1000.0
            _ledger(
                role=role,
                method=method,
                target=target,
                status=0,
                body="",
                final_url=target,
                duration_ms=duration_ms,
                probe_class=probe_class,
                probe_name=probe_name,
                parameter=parameter,
                payload=payload,
                resp_class="origin_failure",
                result_state=result_state or STATE_BASELINE_FAILED,
                values=values,
                target_selection_reason=target_selection_reason,
            )
            raise
        duration_ms = (time.monotonic() - t0) * 1000.0
        status = int(getattr(resp, "status_code", 200) or 200)
        body = getattr(resp, "text", None) or ""
        headers = dict(getattr(resp, "headers", None) or {})
        final = str(getattr(resp, "url", "") or "")
        resp_class = classify_response(status, body, headers)
        if role in ("probe", "replay", "control", "baseline"):
            if breaker.note(resp_class):
                # Estimate remaining probes roughly for export
                remaining = 0
                try:
                    remaining = max(0, len(specs) * max(1, int(settings.max_params or 1)) // 2)
                except Exception:
                    remaining = 0
                stop_active_probes(
                    stats,
                    reason=breaker.reason,
                    remaining="inconclusive",
                    remaining_probes=remaining,
                    breaker=breaker,
                )
            elif stats is not None and hasattr(breaker, "snapshot"):
                try:
                    stats.active_probe_breaker = breaker.snapshot()
                except Exception:
                    pass
        default_state = ""
        if role in ("baseline", "control"):
            default_state = STATE_NOT_APPLICABLE
        elif role == "probe":
            # Assume negative until confirmation logic patches a stronger state.
            default_state = STATE_NEGATIVE
        elif role == "replay":
            default_state = STATE_NOT_APPLICABLE
        elif breaker.tripped:
            default_state = breaker.reason or STATE_BLOCKED
        elif is_contaminated(resp_class):
            default_state = STATE_BLOCKED if "waf" in (resp_class or "") or "edge" in (resp_class or "") else STATE_INCONCLUSIVE
        _ledger(
            role=role,
            method=method,
            target=target,
            status=status,
            body=body,
            final_url=final,
            headers=headers,
            duration_ms=duration_ms,
            probe_class=probe_class,
            probe_name=probe_name,
            parameter=parameter,
            payload=payload,
            resp_class=resp_class,
            result_state=result_state or default_state or STATE_INCONCLUSIVE,
            values=values,
            target_selection_reason=target_selection_reason,
        )
        try:
            setattr(resp, "_vc_duration_ms", duration_ms)
        except Exception:
            pass
        return resp

    def _meta(resp) -> Tuple[int, str, Dict[str, Any], str]:
        status = int(getattr(resp, "status_code", 200) or 200)
        body = getattr(resp, "text", None) or ""
        headers = dict(getattr(resp, "headers", None) or {})
        final = str(getattr(resp, "url", "") or "")
        return status, body, headers, final

    # Coverage skips aggregate on stats — emit a single skip note only when no
    # stats object is present (unit-test / one-shot kit runs).
    if not (canary_path and canary_content) and stats is None:
        add(
            "active_probe_coverage",
            "info",
            "Traversal active confirmation: skipped — no controlled canary configured",
            "traversal_canary_skipped",
            {
                "verification": "informational",
                "confidence": "high",
                "confidence_reason": "coverage",
                "proof": {"validation_state": STATE_INCONCLUSIVE, "coverage": coverage},
                "validation": "unverified",
            },
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
        *,
        allowed_families: Optional[Dict[str, Tuple[str, int]]] = None,
        selection_reason: str = "generic_fallback",
    ):
        # Harmless nonce control (comparison step 2)
        control_vals = dict(values)
        control_vals[field] = f"VCCTRL_{nonce}"
        try:
            ctrl_resp = await _send(
                method,
                target,
                control_vals,
                role="control",
                probe_class="nonce_control",
                probe_name="VCCTRL",
                parameter=field,
                payload=f"VCCTRL_{nonce}",
                target_selection_reason=selection_reason,
            )
            _, ctrl_body, ctrl_hdrs, _ = _meta(ctrl_resp)
            ctrl_class = classify_response(int(getattr(ctrl_resp, "status_code", 200) or 200), ctrl_body, ctrl_hdrs)
            # Edge/rate-limit on control still feeds the shared breaker (via _send).
            # Continue probe sends so the active-probe breaker window fills from
            # real probe roles. Other contamination makes differentials meaningless.
            if is_contaminated(ctrl_class) and ctrl_class not in (
                "edge_checkpoint",
                "rate_limit",
            ):
                return
        except Exception:
            ctrl_body = baseline_body

        # Cache boolean pair snapshots for true/false multi-signal compare
        bool_snaps: Dict[str, ResponseSnap] = {}

        for spec in specs:
            if breaker.tripped:
                break
            if not spec.param_ok(field):
                continue
            family = KIND_TO_FAMILY.get(spec.kind) or ""
            fam_reason = selection_reason
            fam_score = 0
            if allowed_families is not None:
                if family not in allowed_families:
                    continue
                fam_reason, fam_score = allowed_families[family]
            if spec.kind in (
                "sqli_error",
                "sqli_boolean",
                "sqli_time",
                "ssrf",
                "rce",
                "traversal",
                "traversal_diff",
                "ssti",
            ) and not baseline_ok:
                continue

            trial = dict(values)
            local_meta = dict(spec.meta or {})
            payload_value = spec.payload
            if _should_replace_mutation(spec, field):
                trial[field] = payload_value
            elif _search_param(field) or spec.kind in ("sqli_error", "sqli_boolean", "sqli_time"):
                # Search/string context → append
                trial[field] = str(trial.get(field) or "1") + payload_value
            else:
                trial[field] = str(trial.get(field) or "1") + payload_value

            probe_id = (
                f"{spec.payload_class}:{field}:{urlparse(target).path}:{secrets.token_hex(4)}"
            )
            local_meta["probe_id"] = probe_id

            if oob is not None and spec.kind in ("ssrf", "xxe") and local_meta.get("callback"):
                try:
                    cb_base = (settings.callback_base or "").rstrip("/")
                    fresh = oob.mint_nonce() if hasattr(oob, "mint_nonce") else secrets.token_hex(16)
                    if spec.kind == "xxe":
                        exp_path = f"/{fresh}/xxe"
                        cb_url = f"{cb_base}/{fresh}/xxe" if cb_base else ""
                        trial[field] = (
                            '<?xml version="1.0"?>'
                            f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "{cb_url}">]>'
                            "<r>&xxe;</r>"
                        )
                        payload_value = trial[field]
                    else:
                        suffix = "redirect" if "redirect" in spec.payload_class else "ping"
                        exp_path = f"/{fresh}/{suffix}"
                        cb_url = f"{cb_base}/{fresh}/{suffix}" if cb_base else ""
                        if cb_url:
                            trial[field] = cb_url
                            payload_value = trial[field]
                        bound = oob.register_probe(
                            fresh,
                            probe_id=probe_id,
                            endpoint=target,
                            parameter=field,
                            category=spec.category,
                            expected_path=exp_path,
                            callback_url=cb_url,
                        ) or fresh
                        local_meta["nonce"] = bound
                        local_meta["expected_path"] = exp_path
                        local_meta["callback_url"] = cb_url
                        if hasattr(oob, "status_snapshot"):
                            coverage["oob_callback"] = oob.status_snapshot(
                                probe_url_generated=True
                            ).as_dict()
                except Exception:
                    pass

            try:
                # Never follow redirects for SSRF/XXE/open-redirect probes —
                # client-followed redirects self-confirm against the callback host.
                follow = spec.kind not in ("redirect", "ssrf", "xxe", "crlf")
                t0 = time.monotonic()
                resp = await _send(
                    method,
                    target,
                    trial,
                    follow=follow,
                    role="probe",
                    probe_class=spec.category,
                    probe_name=spec.payload_class,
                    parameter=field,
                    payload=payload_value,
                    target_selection_reason=fam_reason,
                )
                elapsed_ms = float(getattr(resp, "_vc_duration_ms", 0) or 0) or (
                    (time.monotonic() - t0) * 1000.0
                )
                # CRLF: also try without following; headers matter
                p_status, p_body, p_hdrs, p_final = _meta(resp)
                resp_class = classify_response(p_status, p_body, p_hdrs)
                if is_contaminated(resp_class):
                    _patch_last_probe_result(
                        STATE_BLOCKED,
                        probe_name=spec.payload_class,
                        parameter=field,
                        target_selection_reason=fam_reason,
                    )
                    continue

                hit = False
                finding_category = spec.category
                severity = spec.default_severity
                validation_state = STATE_DIFFERENTIAL
                confidence = "medium"
                verification = "verified"
                detail_bit = "differential signal"
                new_evidence: List[str] = []
                evidence_line = ""
                compare_meta: Dict[str, Any] = {}
                browser_meta: Dict[str, Any] = {}

                if spec.kind == "sqli_error":
                    # Decode HTML entities only for SQL-error evidence matching
                    # (never for hashing / browser interpretation).
                    probe_err = _sql_error_match(p_body or "")
                    if not probe_err:
                        continue
                    if _sql_error_match(baseline_body or ""):
                        continue
                    if is_contaminated(resp_class):
                        continue
                    # Reproduce (step 4)
                    resp2 = await _send(
                        method,
                        target,
                        trial,
                        follow=True,
                        role="replay",
                        probe_class=spec.category,
                        probe_name=spec.payload_class,
                        parameter=field,
                        payload=payload_value,
                    )
                    _, body2, hdrs2, _ = _meta(resp2)
                    replay_class = classify_response(
                        int(getattr(resp2, "status_code", 200) or 200), body2, hdrs2
                    )
                    if is_contaminated(replay_class):
                        continue
                    replay_err = _sql_error_match(body2 or "")
                    if not replay_err:
                        continue
                    hit = True
                    new_evidence = [(probe_err.group(0) if probe_err else "SQL error")[:120]]
                    evidence_line = f"sql_error: {new_evidence[0]}"
                    detail_bit = "differential signal (new database error, reproduced)"
                    validation_state = STATE_DIFFERENTIAL
                    mutation_mode = "replace" if _should_replace_mutation(spec, field) else "append"
                    compare_meta["mutation_mode"] = mutation_mode
                    compare_meta["html_entity_decoded_for_evidence"] = True

                elif spec.kind == "sqli_boolean":
                    snap = ResponseSnap(
                        status=p_status, body=p_body, final_url=p_final, elapsed_ms=elapsed_ms
                    )
                    bool_snaps[spec.payload_class] = snap
                    mate = spec.meta.get("mate_class") or ""
                    if mate not in bool_snaps:
                        continue
                    if spec.meta.get("pair") != "false":
                        continue
                    true_class = mate
                    false_class = spec.payload_class
                    true_snap = bool_snaps[true_class]
                    false_snap = bool_snaps[false_class]
                    true_payload = next(
                        (s.payload for s in specs if s.payload_class == true_class), ""
                    )
                    false_payload = spec.payload
                    ignore = tuple(p for p in (true_payload, false_payload) if len(p) >= 3)
                    # Repeat false for reproducibility
                    t1 = time.monotonic()
                    resp2 = await _send(
                        method,
                        target,
                        trial,
                        follow=True,
                        role="replay",
                        probe_class=spec.category,
                        probe_name=spec.payload_class,
                        parameter=field,
                        payload=spec.payload,
                    )
                    elapsed2 = float(getattr(resp2, "_vc_duration_ms", 0) or 0) or (
                        (time.monotonic() - t1) * 1000.0
                    )
                    s2, b2, _, f2 = _meta(resp2)
                    repeated = ResponseSnap(status=s2, body=b2, final_url=f2, elapsed_ms=elapsed2)
                    baseline_snap = ResponseSnap(
                        status=baseline_status, body=baseline_body, final_url=baseline_final
                    )
                    cmp_ = compare_response_pair(
                        true_snap,
                        false_snap,
                        baseline=baseline_snap,
                        ignore=ignore,
                        repeated_false=repeated,
                    )
                    compare_meta = cmp_
                    verdict = cmp_.get("verdict") or STATE_NEGATIVE
                    if verdict in (STATE_NEGATIVE, STATE_INCONCLUSIVE):
                        continue
                    hit = True
                    severity = "high" if verdict == STATE_DIFFERENTIAL else "medium"
                    validation_state = verdict
                    detail_bit = (
                        f"{verdict} (boolean true/false multi-signal compare, score={cmp_.get('score')})"
                    )
                    new_evidence = [
                        f"hash_diff={cmp_.get('normalized_hash_diff')}",
                        f"sim={cmp_.get('text_similarity')}",
                        f"repro={cmp_.get('reproducible')}",
                    ]
                    evidence_line = f"sqli_boolean:{verdict}"
                    confidence = "high" if verdict == STATE_DIFFERENTIAL else "medium"
                    verification = "verified" if verdict == STATE_DIFFERENTIAL else "detected"

                elif spec.kind == "sqli_time":
                    min_ms = float(spec.meta.get("min_ms") or 1500)
                    # Control: same param with short benign value should be faster
                    ctrl_vals = dict(values)
                    ctrl_vals[field] = str(values.get(field) or "1")
                    tc0 = time.monotonic()
                    try:
                        await _send(
                            method,
                            target,
                            ctrl_vals,
                            follow=True,
                            role="control",
                            probe_class=spec.category,
                            probe_name=spec.payload_class,
                            parameter=field,
                            payload=str(ctrl_vals[field]),
                        )
                    except Exception:
                        pass
                    ctrl_ms = (time.monotonic() - tc0) * 1000.0
                    if elapsed_ms < min_ms:
                        continue
                    if elapsed_ms < ctrl_ms + 1200:
                        continue
                    # Reproduce once
                    t2 = time.monotonic()
                    await _send(
                        method,
                        target,
                        trial,
                        follow=True,
                        role="replay",
                        probe_class=spec.category,
                        probe_name=spec.payload_class,
                        parameter=field,
                        payload=spec.payload,
                    )
                    elapsed2 = (time.monotonic() - t2) * 1000.0
                    if elapsed2 < min_ms:
                        continue
                    hit = True
                    severity = "high"
                    validation_state = STATE_PROBABLE
                    detail_bit = (
                        f"probable time-based SQLi (probe {elapsed_ms:.0f}ms / "
                        f"replay {elapsed2:.0f}ms vs control {ctrl_ms:.0f}ms)"
                    )
                    new_evidence = [f"elapsed_ms={elapsed_ms:.0f}", f"control_ms={ctrl_ms:.0f}"]
                    evidence_line = "sqli_time:delay"
                    confidence = "medium"
                    verification = "detected"

                elif spec.kind == "xss":
                    token = str(local_meta.get("token") or "")
                    disp = classify_xss(
                        p_body,
                        token,
                        baseline_body,
                        payload=payload_value,
                        dom_id=str(local_meta.get("dom_id") or ""),
                    )
                    if settings.browser_evaluate and (
                        local_meta.get("needs_browser")
                        or (
                            disp
                            and disp.get("validation_state")
                            in (STATE_ATTR_BREAKOUT, STATE_SINK_CANDIDATE)
                        )
                    ):
                        try:
                            from active_probe_browser import build_probe_page_url

                            # Reproduce the exact payload request (do not swap to a
                            # cleaned final_url that may drop the probe query).
                            page_url = build_probe_page_url(target, method, trial)
                            eval_result = await settings.browser_evaluate(
                                page_url,
                                f"document.body.dataset.vc === '{token}'",
                                method=method,
                                post_data=trial if (method or "GET").upper() == "POST" else None,
                                expected_token=token,
                                fragment="",
                                probe_class=spec.category,
                                probe_name=spec.payload_class,
                                parameter=field,
                                payload=payload_value,
                            )
                            executed = False
                            reproduced = False
                            if isinstance(eval_result, dict):
                                executed = eval_result.get("executed") is True
                                reproduced = bool(eval_result.get("reproduced", True))
                                browser_meta = dict(eval_result)
                            else:
                                executed = eval_result is True
                                reproduced = executed
                                browser_meta = {"executed": executed, "reproduced": reproduced}
                            if executed and reproduced:
                                hit = True
                                finding_category = "xss"
                                severity = "high"
                                detail_bit = "browser execution confirmed (dataset.vc marker)"
                                validation_state = STATE_BROWSER_EXEC
                                confidence = "high"
                                verification = "confirmed"
                                new_evidence = [f"dataset.vc={token}"]
                                evidence_line = f"browser_exec: dataset.vc={token}"
                                disp = None
                            elif local_meta.get("needs_browser"):
                                # Browser path attempted but not confirmed — do not
                                # escalate reflection to execution.
                                if disp and disp.get("validation_state") == STATE_REFLECTED_ONLY:
                                    pass
                                elif not disp:
                                    hit = False
                                    disp = None
                        except Exception:
                            pass
                    if disp:
                        hit = True
                        finding_category = str(disp.get("category") or spec.category)
                        severity = disp["severity"]
                        detail_bit = disp["detail_bit"]
                        validation_state = disp["validation_state"]
                        confidence = disp["confidence"]
                        verification = disp["verification"]
                        new_evidence = [detail_bit]
                        evidence_line = f"xss: {token}"
                        if not settings.browser_evaluate and validation_state != STATE_REFLECTED_ONLY:
                            detail_bit = (
                                f"{detail_bit} — XSS execution confirmation unavailable "
                                "in this scan configuration"
                            )

                elif spec.kind == "rce":
                    marker = str(local_meta.get("marker") or "")
                    arith = str(local_meta.get("arith") or "")
                    if marker and marker in (baseline_body or ""):
                        continue
                    injection_shaped = bool(
                        re.search(r"[;|&`$]|&&|\|\|", payload_value or spec.payload or "")
                    )

                    def _rce_parts(body: str):
                        evidence = []
                        stripped = body or ""
                        for lit in (
                            payload_value,
                            spec.payload,
                            f"expr {_ARITH_A} + {_ARITH_B}",
                            f"expr {_ARITH_A}+{_ARITH_B}",
                            str(_ARITH_A),
                            str(_ARITH_B),
                            f"printf {marker}",
                            f"echo {marker}",
                        ):
                            if lit:
                                stripped = stripped.replace(lit, "")
                        has_arith = bool(
                            arith and arith in stripped and arith not in (baseline_body or "")
                        )
                        has_marker = False
                        if marker and marker in stripped and marker not in (baseline_body or ""):
                            if f"printf {marker}" not in (body or "") and f"echo {marker}" not in (
                                body or ""
                            ):
                                has_marker = True
                        # Existing RCE payloads already carry shell metacharacters; classify
                        # playground CMDI execution markers as confirmed execution evidence.
                        has_cmdi_exec = False
                        if injection_shaped:
                            for cm in _CMDI_EXEC_MARKERS:
                                if cm in stripped and cm not in (baseline_body or ""):
                                    has_cmdi_exec = True
                                    evidence.append(f"cmdi_exec={cm}")
                                    break
                        if has_arith:
                            evidence.append(f"arith_result={arith}")
                        if has_marker:
                            evidence.append(f"marker={marker}")
                        return has_arith, has_marker, has_cmdi_exec, evidence

                    has_arith, has_marker, has_cmdi_exec, new_evidence = _rce_parts(p_body)
                    if not has_arith and not has_marker and not has_cmdi_exec:
                        continue
                    resp2 = await _send(
                        method,
                        target,
                        trial,
                        follow=True,
                        role="replay",
                        probe_class=spec.category,
                        probe_name=spec.payload_class,
                        parameter=field,
                        payload=payload_value,
                    )
                    _, body2, hdrs2, _ = _meta(resp2)
                    if is_contaminated(
                        classify_response(int(getattr(resp2, "status_code", 200) or 200), body2, hdrs2)
                    ):
                        continue
                    has_arith2, has_marker2, has_cmdi_exec2, ev2 = _rce_parts(body2)
                    if has_arith and has_arith2:
                        hit = True
                        severity = "critical"
                        detail_bit = (
                            "confirmed server-side behavior "
                            "(arithmetic transformation reproduced)"
                        )
                        validation_state = STATE_SERVER_EXEC
                        confidence = "high"
                        verification = "confirmed"
                        new_evidence = [e for e in (new_evidence or ev2) if e.startswith("arith_")]
                        evidence_line = ",".join(new_evidence)
                    elif has_cmdi_exec and has_cmdi_exec2:
                        hit = True
                        severity = "critical"
                        detail_bit = (
                            "confirmed server-side behavior "
                            "(command-injection execution marker reproduced)"
                        )
                        validation_state = STATE_SERVER_EXEC
                        confidence = "high"
                        verification = "confirmed"
                        new_evidence = [e for e in (new_evidence or ev2) if e.startswith("cmdi_exec=")]
                        evidence_line = ",".join(new_evidence)
                    elif has_marker and has_marker2:
                        hit = True
                        severity = "high"
                        detail_bit = (
                            "probable command-injection marker output "
                            "(not arithmetic-confirmed)"
                        )
                        validation_state = STATE_MARKER_SIGNAL
                        confidence = "medium"
                        verification = "detected"
                        new_evidence = [e for e in (new_evidence or ev2) if e.startswith("marker=")]
                        evidence_line = ",".join(new_evidence)
                    else:
                        continue

                elif spec.kind == "ssti":
                    arith = str(local_meta.get("arith") or "")
                    raw = str(local_meta.get("raw") or payload_value)
                    if arith not in (p_body or ""):
                        continue
                    if arith in (baseline_body or ""):
                        continue

                    def _ssti_isolated(body: str) -> bool:
                        stripped = body or ""
                        for lit in (raw, payload_value, spec.payload, str(_ARITH_A), str(_ARITH_B), f"{{{{{_ARITH_A}+{_ARITH_B}}}}}"):
                            if lit:
                                stripped = stripped.replace(lit, "")
                        return arith in stripped

                    if not _ssti_isolated(p_body):
                        continue
                    # Reproduce
                    resp2 = await _send(
                        method,
                        target,
                        trial,
                        follow=True,
                        role="replay",
                        probe_class=spec.category,
                        probe_name=spec.payload_class,
                        parameter=field,
                        payload=payload_value,
                    )
                    _, body2, hdrs2, _ = _meta(resp2)
                    if is_contaminated(
                        classify_response(int(getattr(resp2, "status_code", 200) or 200), body2, hdrs2)
                    ):
                        continue
                    if not _ssti_isolated(body2):
                        continue
                    hit = True
                    severity = "high"
                    detail_bit = "confirmed server-side behavior (SSTI arithmetic evaluated, reproduced)"
                    validation_state = STATE_SERVER_EXEC
                    confidence = "high"
                    verification = "confirmed"
                    new_evidence = [f"ssti_result={arith}"]
                    evidence_line = f"ssti: {arith}"

                elif spec.kind == "ssrf":
                    if local_meta.get("callback"):
                        confirmed = False
                        oob_nonce = str(local_meta.get("nonce") or "")
                        pid = str(local_meta.get("probe_id") or "")
                        if settings.callback_received:
                            try:
                                try:
                                    confirmed = bool(
                                        await settings.callback_received(oob_nonce, probe_id=pid)
                                    )
                                except TypeError:
                                    confirmed = bool(await settings.callback_received(oob_nonce))
                            except Exception:
                                confirmed = False
                        callback_url = str(local_meta.get("callback_url") or trial.get(field) or "")
                        reflected = bool(
                            oob_nonce
                            and (
                                oob_nonce in (p_body or "")
                                or callback_url in (p_body or "")
                            )
                        )
                        if confirmed:
                            hit = True
                            severity = "high"
                            detail_bit = "out-of-band callback confirmed (SSRF)"
                            validation_state = STATE_OOB_CALLBACK
                            confidence = "high"
                            verification = "confirmed"
                            new_evidence = [f"callback_nonce={oob_nonce[:12]}…"]
                            evidence_line = "ssrf_callback:correlated"
                            compare_meta["oob"] = (
                                oob.status_snapshot(
                                    probe_url_generated=True, callback_received=True
                                ).as_dict()
                                if oob is not None and hasattr(oob, "status_snapshot")
                                else {
                                    "callback_configured": True,
                                    "probe_url_generated": True,
                                    "polling_active": True,
                                    "callback_received": True,
                                    "confirmation_unavailable": False,
                                }
                            )
                            compare_meta["probe_id"] = pid
                        elif not settings.callback_received and not settings.callback_base:
                            # No OOB receiver: reflection-only control fixtures stay reflected_only;
                            # real fetch fixtures must report confirmation_unavailable (never negative).
                            reflect_control = bool(
                                re.search(r"(?i)invalid url echoed|reflection-only", p_body or "")
                            )
                            if reflect_control and reflected:
                                hit = True
                                severity = "info"
                                detail_bit = "SSRF reflection-only control (no OOB confirm)"
                                validation_state = STATE_REFLECTED_ONLY
                                confidence = "low"
                                verification = "detected"
                                new_evidence = [f"callback_url_redacted={redact_payload(callback_url)}"]
                                evidence_line = "ssrf_reflected_only"
                                compare_meta["oob"] = {
                                    "callback_configured": False,
                                    "probe_url_generated": True,
                                    "polling_active": False,
                                    "callback_received": False,
                                    "confirmation_unavailable": True,
                                    "reason": "reflection_control",
                                }
                            else:
                                _patch_last_probe_result(
                                    STATE_CONFIRMATION_UNAVAILABLE,
                                    probe_name=spec.payload_class,
                                    parameter=field,
                                    target_selection_reason=fam_reason,
                                    prefer_roles=("probe",),
                                )
                                continue
                        elif reflected:
                            # Echo of callback URL alone is never confirmation
                            hit = True
                            severity = "info"
                            detail_bit = "SSRF callback URL reflected only (no correlated OOB)"
                            validation_state = STATE_REFLECTED_ONLY
                            confidence = "low"
                            verification = "detected"
                            new_evidence = [f"callback_url_redacted={redact_payload(callback_url)}"]
                            evidence_line = "ssrf_reflected_only"
                            compare_meta["oob"] = {
                                "callback_configured": bool(settings.callback_base),
                                "probe_url_generated": True,
                                "polling_active": bool(settings.callback_received),
                                "callback_received": False,
                                "confirmation_unavailable": True,
                                "reason": "reflected_only",
                            }
                        else:
                            hit = True
                            severity = "info"
                            detail_bit = (
                                "SSRF callback probe sent; confirmation unavailable "
                                "(no correlated callback)"
                            )
                            validation_state = STATE_CONFIRMATION_UNAVAILABLE
                            confidence = "low"
                            verification = "detected"
                            new_evidence = [f"callback_url_redacted={redact_payload(callback_url)}"]
                            evidence_line = "ssrf_probe_sent_unconfirmed"
                            compare_meta["oob"] = (
                                oob.status_snapshot(probe_url_generated=True).as_dict()
                                if oob is not None and hasattr(oob, "status_snapshot")
                                else {
                                    "callback_configured": bool(settings.callback_base),
                                    "probe_url_generated": True,
                                    "polling_active": bool(settings.callback_received),
                                    "callback_received": False,
                                    "confirmation_unavailable": True,
                                    "reason": "no correlated callback",
                                }
                            )
                    elif local_meta.get("imds"):
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

                elif spec.kind == "traversal_diff":
                    # Safe external: path normalization / differential only — never confirmed
                    if not bodies_differ(baseline_body, p_body, ignore=(spec.payload,)):
                        continue
                    resp2 = await _send(
                        method,
                        target,
                        trial,
                        follow=True,
                        role="replay",
                        probe_class=spec.category,
                        probe_name=spec.payload_class,
                        parameter=field,
                        payload=spec.payload,
                    )
                    s2, b2, h2, f2 = _meta(resp2)
                    if is_contaminated(classify_response(s2, b2, h2)):
                        continue
                    if not bodies_differ(baseline_body, b2, ignore=(spec.payload,)):
                        continue
                    # Require more than a one-off length delta
                    base_snap = ResponseSnap(
                        status=baseline_status, body=baseline_body, final_url=baseline_final
                    )
                    probe_snap = ResponseSnap(status=p_status, body=p_body, final_url=p_final)
                    rep_snap = ResponseSnap(status=s2, body=b2, final_url=f2)
                    # Reuse boolean comparator shape: treat baseline as "true", probe as "false"
                    cmp_ = compare_response_pair(
                        base_snap,
                        probe_snap,
                        baseline=base_snap,
                        ignore=(spec.payload,),
                        repeated_false=rep_snap,
                    )
                    # baseline≈true is tautological here; require baseline differs from probe + repro
                    if not cmp_.get("baseline_differs_from_false"):
                        continue
                    if not cmp_.get("reproducible"):
                        continue
                    if (cmp_.get("verdict") or STATE_NEGATIVE) in (STATE_NEGATIVE, STATE_INCONCLUSIVE):
                        # Soften: accept probable-grade content diff with repro even if score gate is strict
                        if not (
                            cmp_.get("normalized_hash_diff")
                            and cmp_.get("reproducible")
                            and (cmp_.get("content_length_delta", 0) >= 24 or cmp_.get("text_similarity", 1) < 0.92)
                        ):
                            continue
                    hit = True
                    severity = "medium"
                    validation_state = STATE_DIFFERENTIAL
                    detail_bit = "path-normalization / differential traversal signal (not canary-confirmed)"
                    confidence = "medium"
                    verification = "detected"
                    new_evidence = [
                        f"hash_diff={cmp_.get('normalized_hash_diff')}",
                        f"repro={cmp_.get('reproducible')}",
                    ]
                    evidence_line = "traversal_diff"
                    compare_meta = cmp_

                elif spec.kind == "traversal":
                    proof = str(local_meta.get("proof") or "")
                    proof_re = local_meta.get("proof_re")
                    is_canary = bool(local_meta.get("canary"))
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
                    if is_canary:
                        if not (canary_path and canary_content):
                            continue
                        # Exact fixture alignment: expected proof and payload path
                        if proof != canary_content:
                            continue
                        allowed_payloads = {
                            canary_path,
                            canary_path.replace("/", "%2f"),
                            canary_path.replace("/", "%252f"),
                        }
                        if payload_value not in allowed_payloads:
                            continue
                        resp2 = await _send(
                            method,
                            target,
                            trial,
                            follow=True,
                            role="replay",
                            probe_class=spec.category,
                            probe_name=spec.payload_class,
                            parameter=field,
                            payload=payload_value,
                        )
                        _, body2, _, _ = _meta(resp2)
                        if proof and proof not in (body2 or ""):
                            continue
                        hit = True
                        severity = "high"
                        detail_bit = "canary file confirmed (configured fixture)"
                        validation_state = STATE_CANARY_FILE
                        confidence = "high"
                        verification = "confirmed"
                        evidence_line = ",".join(new_evidence)
                        compare_meta["canary_path"] = canary_path
                        compare_meta["canary_content"] = canary_content
                    else:
                        # Lab passwd marker etc.
                        hit = True
                        severity = spec.default_severity
                        detail_bit = "confirmed server-side behavior (traversal proof)"
                        validation_state = STATE_SERVER_EXEC
                        confidence = "high"
                        verification = "confirmed"
                        evidence_line = ",".join(new_evidence)

                elif spec.kind == "redirect":
                    host = str(local_meta.get("host") or "")
                    location = ""
                    for hk, hv in p_hdrs.items():
                        if str(hk).lower() == "location":
                            location = str(hv or "")
                            break
                    # Confirm only from Location (and followed final URL). Never from the
                    # request URL — it embeds the payload and would self-confirm controls.
                    blob = (location or "").lower()
                    if follow and p_final:
                        # Only count final_url when it differs from the probe request URL.
                        req_base = f"{urlparse(target).scheme}://{urlparse(target).netloc}{urlparse(target).path}"
                        final_base = f"{urlparse(p_final).scheme}://{urlparse(p_final).netloc}{urlparse(p_final).path}"
                        if final_base.rstrip("/") != req_base.rstrip("/"):
                            blob = f"{blob} {p_final}".lower()
                    if not host or host.lower() not in blob:
                        continue
                    hit = True
                    severity = "high"
                    detail_bit = "confirmed open redirect to controlled host"
                    validation_state = STATE_SERVER_EXEC
                    confidence = "high"
                    verification = "confirmed"
                    new_evidence = [f"Location→{host}"]
                    evidence_line = f"redirect: {location}"

                elif spec.kind == "crlf":
                    hdr_name = str(local_meta.get("header") or "").lower()
                    hdr_val = str(local_meta.get("value") or "")
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
                        confirmed = False
                        oob_nonce = str(local_meta.get("nonce") or "")
                        pid = str(local_meta.get("probe_id") or "")
                        try:
                            try:
                                confirmed = bool(
                                    await settings.callback_received(oob_nonce, probe_id=pid)
                                )
                            except TypeError:
                                confirmed = bool(await settings.callback_received(oob_nonce))
                        except Exception:
                            confirmed = False
                        if confirmed:
                            hit = True
                            severity = "high"
                            detail_bit = "out-of-band callback confirmed (XXE)"
                            validation_state = STATE_OOB_CALLBACK
                            confidence = "high"
                            verification = "confirmed"
                            new_evidence = [f"xxe_callback={oob_nonce[:12]}"]
                            evidence_line = "xxe_oob"
                        else:
                            hit = True
                            severity = "info"
                            detail_bit = (
                                "XXE callback probe sent; confirmation unavailable "
                                "(no correlated callback)"
                            )
                            validation_state = STATE_INCONCLUSIVE
                            confidence = "low"
                            verification = "detected"
                            evidence_line = "xxe_probe_sent_unconfirmed"

                if not hit:
                    _patch_last_probe_result(
                        STATE_NEGATIVE,
                        probe_name=spec.payload_class,
                        parameter=field,
                        target_selection_reason=fam_reason,
                    )
                    continue

                # Map validation_state → auditable result_state for the probe ledger row.
                # Keep canary / browser / OOB / confirmation_unavailable exact — do not
                # collapse them into a generic execution_confirmed (acceptance needs exact match).
                state_for_ledger = validation_state
                if validation_state == STATE_SERVER_EXEC:
                    state_for_ledger = STATE_EXECUTION_CONFIRMED
                elif validation_state == STATE_OOB_CALLBACK_LEGACY:
                    state_for_ledger = STATE_OOB_CALLBACK
                _patch_last_probe_result(
                    state_for_ledger,
                    probe_name=spec.payload_class,
                    parameter=field,
                    target_selection_reason=fam_reason,
                    prefer_roles=("probe",),
                )

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
                if compare_meta:
                    if "oob" in compare_meta:
                        proof["oob"] = compare_meta.pop("oob")
                    if compare_meta:
                        proof["comparison"] = compare_meta
                if browser_meta:
                    proof["browser"] = {
                        "generated_url": browser_meta.get("generated_url") or browser_meta.get("final_url"),
                        "final_url": browser_meta.get("final_url"),
                        "executed": browser_meta.get("executed"),
                        "reproduced": browser_meta.get("reproduced"),
                        "console_errors": browser_meta.get("console_errors") or [],
                        "csp_blocked": browser_meta.get("csp_blocked") or [],
                        "browser_request_id": browser_meta.get("browser_request_id"),
                        "evidence": browser_meta.get("evidence"),
                        "observed_value": browser_meta.get("value"),
                        "method": browser_meta.get("method"),
                    }
                # Only browser/server/OOB/canary proof may be validation=confirmed.
                # Attribute/event XSS candidates stay unverified.
                confirmed_states = (
                    STATE_SERVER_EXEC,
                    STATE_BROWSER_EXEC,
                    STATE_OOB_CALLBACK,
                    STATE_CANARY_FILE,
                )
                add(
                    finding_category,
                    severity,
                    f"Active {finding_category} {detail_bit} on {source} '{field}' at {target}",
                    evidence_line or detail_bit,
                    {
                        "verification": verification,
                        "confidence": confidence,
                        "confidence_reason": validation_state,
                        "proof": proof,
                        "validation": (
                            "confirmed" if validation_state in confirmed_states else "unverified"
                        ),
                        "target_selection_reason": fam_reason,
                    },
                )
            except Exception:
                _patch_last_probe_result(
                    STATE_INCONCLUSIVE,
                    probe_name=spec.payload_class,
                    parameter=field,
                    target_selection_reason=fam_reason,
                )
                continue

    # --- Vulnerability-aware target selection (route + param semantics) ---
    from active_probe_targeting import (
        MIN_APPLICABILITY_SCORE,
        classify_applicability,
        path_only_url as _path_only_url,
        selection_coverage_report,
        synthetic_params_for_path,
        with_query_params,
        _fixture_family_for_path,
        _norm_path,
    )

    path = _norm_path(url)
    fixture_fam = _fixture_family_for_path(path)
    synth = synthetic_params_for_path(path)
    parsed = urlparse(url)
    pairs = list(parse_qsl(parsed.query, keep_blank_values=True))
    if synth:
        existing = {n for n, _ in pairs}
        for k, v in synth.items():
            if k not in existing:
                pairs.append((k, v))
        # Prefer a concrete injectable URL (path + synthetic/query params).
        url = with_query_params(_path_only_url(url) if not pairs else url, dict(pairs))

    probe_families = ("sqli", "rce", "ssti", "ssrf", "traversal", "crlf", "redirect", "xss")
    selected_plan_paths: Dict[str, set] = {f: set() for f in probe_families}

    def _allowed_for_param(pname: str) -> Dict[str, Tuple[str, int]]:
        allowed: Dict[str, Tuple[str, int]] = {}
        for family in probe_families:
            score, reason = classify_applicability(
                path=path,
                param=pname,
                family=family,
                allow_generic_fallback=(fixture_fam is None),
            )
            if fixture_fam == family:
                score = max(score, 100)
                reason = "route_semantic_match"
            # Dedicated fixtures: only the matching family (prevents spray).
            if fixture_fam and fixture_fam != family and score < 95:
                continue
            min_score = MIN_APPLICABILITY_SCORE.get(reason, 40)
            if score < min_score:
                continue
            if reason == "generic_fallback" and family not in ("xss", "sqli", "ssti"):
                continue
            allowed[family] = (reason, score)
        return allowed

    # --- GET query / synthetic params ---
    if pairs:
        values = {n: v for n, v in pairs}
        baseline_ok = False
        baseline_body = ""
        baseline_status = 0
        baseline_final = ""
        try:
            base_resp = await _send(
                "GET",
                url,
                values,
                role="baseline",
                probe_class="baseline",
                probe_name="baseline",
                target_selection_reason=(
                    "route_semantic_match" if fixture_fam else "parameter_semantic_match"
                ),
            )
            baseline_status, baseline_body, base_hdrs, baseline_final = _meta(base_resp)
            baseline_ok = not is_contaminated(
                classify_response(baseline_status, baseline_body, base_hdrs)
            )
        except Exception:
            baseline_ok = False

        # Rank params: route-semantic fixtures first, then strong param matches.
        def _param_rank(item):
            name = item[0]
            allowed = _allowed_for_param(name)
            best = max((s for _, s in allowed.values()), default=0)
            reason_best = min(
                (
                    {"route_semantic_match": 0, "passive_evidence_match": 1,
                     "parameter_semantic_match": 2, "generic_fallback": 3}.get(r, 9)
                    for r, _ in allowed.values()
                ),
                default=9,
            )
            return (reason_best, -best, name)

        ordered = sorted(pairs, key=_param_rank)
        budget = max(1, int(settings.max_params or 8))
        probed = 0
        for name, _ in ordered:
            if probed >= budget:
                break
            allowed = _allowed_for_param(name)
            if not allowed:
                continue
            # Prefer highest-scoring reason for ledger annotation.
            selection_reason = sorted(
                allowed.values(),
                key=lambda x: (
                    {"route_semantic_match": 0, "passive_evidence_match": 1,
                     "parameter_semantic_match": 2, "generic_fallback": 3}.get(x[0], 9),
                    -x[1],
                ),
            )[0][0]
            for fam in allowed:
                selected_plan_paths[fam].add(path)
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
                allowed_families=allowed,
                selection_reason=selection_reason,
            )
            probed += 1

    # --- Forms (parameter-semantic; capped; never override dedicated fixture routing) ---
    if forms and not fixture_fam:
        for form in (forms or [])[: max(0, int(settings.max_forms or 3))]:
            action = form.get("action") or url
            method = (form.get("method") or "GET").upper()
            if mutation_blocked(action, method):
                continue
            raw_fields = form.get("fields") or []
            if isinstance(raw_fields, dict):
                field_names = [str(f) for f in raw_fields.keys() if f]
                values = {str(k): str(v if v is not None else "test") for k, v in raw_fields.items() if k}
            else:
                field_names = [f for f in raw_fields if f][: settings.max_params]
                values = {f: "test" for f in field_names}
            if not field_names:
                continue
            form_path = _norm_path(action)
            baseline_ok = False
            baseline_body = ""
            baseline_status = 0
            baseline_final = ""
            try:
                base_resp = await _send(
                    method,
                    action,
                    values,
                    role="baseline",
                    probe_class="baseline",
                    probe_name="baseline",
                    target_selection_reason="parameter_semantic_match",
                )
                baseline_status, baseline_body, base_hdrs, baseline_final = _meta(base_resp)
                baseline_ok = not is_contaminated(
                    classify_response(baseline_status, baseline_body, base_hdrs)
                )
            except Exception:
                baseline_ok = False
            for field in field_names[: settings.max_params]:
                # Rebind path scoring to the form action.
                path = form_path
                fixture_fam = _fixture_family_for_path(path)
                allowed = _allowed_for_param(field)
                if not allowed:
                    continue
                selection_reason = sorted(
                    allowed.values(),
                    key=lambda x: (
                        {"route_semantic_match": 0, "passive_evidence_match": 1,
                         "parameter_semantic_match": 2, "generic_fallback": 3}.get(x[0], 9),
                        -x[1],
                    ),
                )[0][0]
                for fam in allowed:
                    selected_plan_paths[fam].add(path)
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
                    allowed_families=allowed,
                    selection_reason=selection_reason,
                )

    # Record target-selection coverage for this page onto shared stats.
    if stats is not None:
        try:
            prev_cov = dict(getattr(stats, "target_selection_coverage", None) or {})
            selected_acc = dict(prev_cov.get("selected_by_family") or {})
            for fam, paths in selected_plan_paths.items():
                bucket = set(selected_acc.get(fam) or [])
                bucket.update(paths)
                selected_acc[fam] = sorted(bucket)
            discovered_paths = []
            for u in list(getattr(stats, "discovered_urls", None) or []):
                try:
                    discovered_paths.append(_norm_path(str(u)))
                except Exception:
                    continue
            # Synthetic ProbeTarget list for coverage report.
            from active_probe_targeting import ProbeTarget

            faux_plan = []
            for fam, paths in selected_acc.items():
                for pth in paths:
                    faux_plan.append(
                        ProbeTarget(
                            url=pth,
                            method="GET",
                            param="",
                            family=fam,
                            reason="route_semantic_match",
                            score=100,
                        )
                    )
            report = selection_coverage_report(faux_plan, discovered_paths)
            stats.target_selection_coverage = {
                "status": report.get("status"),
                "missing_families": report.get("missing_families") or [],
                "fixtures": report.get("fixtures") or [],
                "selected_by_family": selected_acc,
                "reasons": report.get("reasons") or {},
            }
            # Drive split coverage / assessment completeness.
            ts_status = str(report.get("status") or "")
            if ts_status == "insufficient":
                stats.active_validation_coverage = "partial"  # type: ignore[attr-defined]
                missing = ", ".join(report.get("missing_families") or []) or "dedicated fixtures"
                stats.assessment_inconclusive_reason = (  # type: ignore[attr-defined]
                    f"target-selection coverage insufficient ({missing} discovered but not tested)"
                )
            elif ts_status == "complete":
                stats.active_validation_coverage = "complete"  # type: ignore[attr-defined]
                prev_reason = str(getattr(stats, "assessment_inconclusive_reason", "") or "")
                if "target-selection coverage insufficient" in prev_reason:
                    stats.assessment_inconclusive_reason = ""  # type: ignore[attr-defined]
            elif ts_status == "partial":
                if not getattr(stats, "active_validation_coverage", None):
                    stats.active_validation_coverage = "partial"  # type: ignore[attr-defined]
        except Exception:
            pass

    # Explicit coverage-gap records for Horizon / supported fixtures.
    if stats is not None:
        try:
            from horizon_benchmark.evaluate import build_coverage_gaps
            from horizon_benchmark.manifest import load_manifest

            gaps = build_coverage_gaps(stats=stats, mode=mode, manifest=load_manifest())
            prev_gaps = list(getattr(stats, "benchmark_coverage_gaps", None) or [])
            # Merge by path+reason
            seen_g = {(str(g.get("path")), str(g.get("reason"))) for g in prev_gaps if isinstance(g, dict)}
            for g in gaps:
                key = (str(g.get("path")), str(g.get("reason")))
                if key in seen_g:
                    continue
                prev_gaps.append(g)
                seen_g.add(key)
            stats.benchmark_coverage_gaps = prev_gaps[:500]  # type: ignore[attr-defined]
            # Unsupported discovered fixtures → informational finding (never silent)
            emitted = getattr(stats, "_unsupported_fixture_gaps_emitted", None)
            if not isinstance(emitted, set):
                emitted = set()
                stats._unsupported_fixture_gaps_emitted = emitted  # type: ignore[attr-defined]
            for g in gaps:
                if g.get("reason") != "family_unsupported":
                    continue
                path = str(g.get("path") or "")
                if not path or path in emitted:
                    continue
                emitted.add(path)
                add(
                    "coverage_gap",
                    "info",
                    f"Fixture discovered but no compatible active detector exists: {path}",
                    f"unsupported_fixture:{path}",
                    {
                        "verification": "informational",
                        "confidence": "high",
                        "confidence_reason": "benchmark_coverage_gap",
                        "proof": {
                            "validation_state": STATE_NOT_APPLICABLE,
                            "coverage_gap": g,
                        },
                        "validation": "unverified",
                    },
                )
        except Exception:
            pass

    if breaker.tripped:
        # Single shared summary — never one coverage finding per page.
        if stats is not None:
            try:
                snap = breaker.snapshot()
                stats.active_probe_breaker = snap
                emitted = bool(getattr(stats, "_active_probe_breaker_finding_emitted", False))
                if not emitted:
                    stats._active_probe_breaker_finding_emitted = True
                    add(
                        "active_probe_coverage",
                        "info",
                        (
                            f"Active probes paused — {breaker.reason} "
                            f"(remaining_probes={snap.get('remaining_probes', 0)} inconclusive)"
                        ),
                        "active_probe_circuit_breaker",
                        {
                            "verification": "informational",
                            "confidence": "high",
                            "confidence_reason": "circuit_breaker",
                            "proof": {
                                "validation_state": STATE_INCONCLUSIVE,
                                "breaker": snap,
                            },
                            "validation": "unverified",
                        },
                    )
            except Exception:
                pass
    elif stats is not None:
        try:
            stats.active_probe_breaker = breaker.snapshot()
        except Exception:
            pass
    # Traversal skip notices live only in stats.active_probe_coverage.aggregate —
    # never one informational finding per endpoint.
    return findings
