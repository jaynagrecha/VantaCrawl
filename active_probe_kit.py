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
STATE_SINK_CANDIDATE = "sink_context_candidate"
STATE_CANARY_FILE = "canary_file_confirmed"

MODES = ("passive", "safe", "extended", "lab")

# Lab-only payload classes — never returned by for_mode("safe"|"extended"|"passive")
_LAB_ONLY_CLASSES = frozenset(
    {
        "ssrf_imds_lab",
        "trav_passwd_lab",
        "trav_canary",
        "trav_canary_enc",
        "trav_canary_dblenc",
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
    # Owned-lab only: set True when VC_TRAVERSAL_* fixtures are installed on the target
    traversal_fixture_installed: bool = False
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


def for_mode(
    mode: str,
    *,
    nonce: Optional[str] = None,
    callback_base: str = "",
    redirect_proof_host: str = "redirect-proof.vantacrawl-lab.example",
    traversal_fixture_root: str = "/opt/vantacrawl-fixtures",
    traversal_fixture_installed: bool = False,
) -> List[ProbeSpec]:
    """Central backend gate: payloads for a mode. Lab classes never leak into safe."""
    settings = ProbeModeSettings(
        mode=normalize_mode(mode),
        callback_base=callback_base or "",
        redirect_proof_host=redirect_proof_host or "redirect-proof.vantacrawl-lab.example",
        traversal_fixture_root=traversal_fixture_root or "/opt/vantacrawl-fixtures",
        traversal_fixture_installed=bool(traversal_fixture_installed),
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


def build_payload_specs(settings: ProbeModeSettings, nonce: str) -> List[ProbeSpec]:
    """Mini payload set for the selected mode (internal; prefer for_mode)."""
    mode = normalize_mode(settings.mode)
    if mode == "passive":
        return []

    xss_tok = f"VCXSS_{nonce}"
    rce_tok = f"VC_RCE_{nonce}"
    trav_proof = f"VC_TRAVERSAL_PROOF_{nonce}"
    trav_file = f"{settings.traversal_fixture_root.rstrip('/')}/VC_TRAVERSAL_{nonce}.txt"
    # Relative traversal toward fixture (lab + fixture installed only)
    trav_payload = f"../../../../{trav_file.lstrip('/')}"
    cb = (settings.callback_base or "").rstrip("/")
    redirect_dest = f"https://{settings.redirect_proof_host}/{nonce}"

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
    # Lab + installed fixture: canary file confirmation (never for safe external)
    if mode == "lab" and settings.traversal_fixture_installed:
        specs.append(
            ProbeSpec(
                "directory_traversal",
                trav_payload,
                "trav_canary",
                _file_names,
                "high",
                "traversal",
                {"proof": trav_proof, "canary": True},
            )
        )
        specs.append(
            ProbeSpec(
                "directory_traversal",
                trav_payload.replace("/", "%2f"),
                "trav_canary_enc",
                _file_names,
                "high",
                "traversal",
                {"proof": trav_proof, "canary": True},
            )
        )
        specs.append(
            ProbeSpec(
                "directory_traversal",
                trav_payload.replace("/", "%252f"),
                "trav_canary_dblenc",
                _file_names,
                "high",
                "traversal",
                {"proof": trav_proof, "canary": True},
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

    # Assert Safe Active never ships risky classes
    if mode == "safe":
        banned = {
            "ssrf_imds_lab",
            "trav_passwd_lab",
            "trav_canary",
            "trav_canary_enc",
            "trav_canary_dblenc",
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
            assert "VC_TRAVERSAL_PROOF" not in s.payload
            assert "/opt/vantacrawl-fixtures" not in s.payload

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
    specs = for_mode(
        mode,
        nonce=nonce,
        callback_base=settings.callback_base,
        redirect_proof_host=settings.redirect_proof_host,
        traversal_fixture_root=settings.traversal_fixture_root,
        traversal_fixture_installed=settings.traversal_fixture_installed,
    )
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

        # Cache boolean pair snapshots for true/false multi-signal compare
        bool_snaps: Dict[str, ResponseSnap] = {}

        for spec in specs:
            if not spec.param_ok(field):
                continue
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
            if spec.meta.get("replace"):
                trial[field] = spec.payload
            elif spec.kind == "xss" and spec.payload_class != "xss_reflect":
                trial[field] = spec.payload
            elif spec.kind in ("redirect", "ssrf", "ssti", "crlf", "xxe", "traversal", "traversal_diff"):
                trial[field] = spec.payload
            else:
                trial[field] = str(trial.get(field) or "1") + spec.payload

            try:
                follow = spec.kind != "redirect"
                t0 = time.monotonic()
                resp = await _send(method, target, trial, follow=follow)
                elapsed_ms = (time.monotonic() - t0) * 1000.0
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
                compare_meta: Dict[str, Any] = {}

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
                    resp2 = await _send(method, target, trial, follow=True)
                    elapsed2 = (time.monotonic() - t1) * 1000.0
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
                        await _send(method, target, ctrl_vals, follow=True)
                    except Exception:
                        pass
                    ctrl_ms = (time.monotonic() - tc0) * 1000.0
                    if elapsed_ms < min_ms:
                        continue
                    if elapsed_ms < ctrl_ms + 1200:
                        continue
                    # Reproduce once
                    t2 = time.monotonic()
                    await _send(method, target, trial, follow=True)
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

                    def _rce_isolated(body: str) -> Tuple[bool, List[str]]:
                        """Calculated output / marker must be isolated from reflected operands."""
                        evidence: List[str] = []
                        stripped = body or ""
                        for lit in (
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
                        if arith and arith in stripped and arith not in (baseline_body or ""):
                            evidence.append(f"arith_result={arith}")
                        if marker and marker in stripped and marker not in (baseline_body or ""):
                            if f"printf {marker}" not in (body or "") and f"echo {marker}" not in (body or ""):
                                evidence.append(f"marker={marker}")
                        return bool(evidence), evidence

                    ok, new_evidence = _rce_isolated(p_body)
                    if not ok:
                        continue
                    # Reproduce
                    resp2 = await _send(method, target, trial, follow=True)
                    _, body2, hdrs2, _ = _meta(resp2)
                    if is_contaminated(
                        classify_response(int(getattr(resp2, "status_code", 200) or 200), body2, hdrs2)
                    ):
                        continue
                    ok2, ev2 = _rce_isolated(body2)
                    if not ok2:
                        continue
                    hit = True
                    severity = "critical"
                    detail_bit = "confirmed server-side behavior (command output / arith, reproduced)"
                    validation_state = STATE_SERVER_EXEC
                    confidence = "high"
                    verification = "confirmed"
                    new_evidence = new_evidence or ev2
                    evidence_line = ",".join(new_evidence)

                elif spec.kind == "ssti":
                    arith = str(spec.meta.get("arith") or "")
                    raw = str(spec.meta.get("raw") or spec.payload)
                    if arith not in (p_body or ""):
                        continue
                    if arith in (baseline_body or ""):
                        continue

                    def _ssti_isolated(body: str) -> bool:
                        stripped = body or ""
                        for lit in (raw, spec.payload, str(_ARITH_A), str(_ARITH_B), f"{{{{{_ARITH_A}+{_ARITH_B}}}}}"):
                            if lit:
                                stripped = stripped.replace(lit, "")
                        return arith in stripped

                    if not _ssti_isolated(p_body):
                        continue
                    # Reproduce
                    resp2 = await _send(method, target, trial, follow=True)
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

                elif spec.kind == "traversal_diff":
                    # Safe external: path normalization / differential only — never confirmed
                    if not bodies_differ(baseline_body, p_body, ignore=(spec.payload,)):
                        continue
                    resp2 = await _send(method, target, trial, follow=True)
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
                    proof = str(spec.meta.get("proof") or "")
                    proof_re = spec.meta.get("proof_re")
                    is_canary = bool(spec.meta.get("canary"))
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
                    # Canary file confirmation only for owned lab with installed fixture
                    if is_canary:
                        if mode != "lab" or not settings.traversal_fixture_installed:
                            continue
                        # Reproduce canary once
                        resp2 = await _send(method, target, trial, follow=True)
                        _, body2, _, _ = _meta(resp2)
                        if proof and proof not in (body2 or ""):
                            continue
                        hit = True
                        severity = "high"
                        detail_bit = "canary file confirmed (lab fixture)"
                        validation_state = STATE_CANARY_FILE
                        confidence = "high"
                        verification = "confirmed"
                        evidence_line = ",".join(new_evidence)
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
                if compare_meta:
                    proof["comparison"] = compare_meta
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
                            in (
                                STATE_SERVER_EXEC,
                                STATE_BROWSER_EXEC,
                                STATE_OOB_CALLBACK,
                                STATE_CANARY_FILE,
                            )
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
