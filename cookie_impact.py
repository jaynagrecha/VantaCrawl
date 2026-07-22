"""Capture Set-Cookie responses and assess whether cookies are stealable credentials."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

# JWT-shaped cookie values (stealable if JS-readable)
_JWT_RE = re.compile(
    r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,})?$"
)

# Session / auth cookies — stealing these can hijack an account
_AUTH_NAME_RE = re.compile(
    r"(?i)^(?:"
    r"session(?:id|_id)?|sess(?:ion)?(?:id)?|sid|ssid|jsessionid|phpsessid|"
    r"asp\.?net_sessionid|aspxauth|auth(?:entication|oriz)?(?:_?token|_?session)?|"
    r"access[_-]?token|id[_-]?token|refresh[_-]?token|bearer|jwt|saml(?:token)?|"
    r"sso(?:_?token|_?session)?|remember(?:_?me)?|connect\.sid|"
    r"user[_-]?(?:token|session|auth)|login[_-]?(?:token|session)|"
    r"__session|__Host-session|__Secure-session|mw_session|rack\.session|"
    r"laravel_session|ci_session|symfony|wordpress_logged_in|"
    r"wordpress_sec|wp_?auth|okta[_-]?session|auth0|cognito|"
    r"x-auth"
    r")$"
)

# CSRF tokens — useful for forged requests, but not account credentials by themselves
_CSRF_NAME_RE = re.compile(
    r"(?i)^(csrf(?:_?token)?|xsrf(?:_?token)?|_csrf|authenticity_token|"
    r"__requestverificationtoken|anti[_-]?forgery|X-CSRF-Token)$"
)

# Analytics / marketing — no stealable login credential
_ANALYTICS_NAME_RE = re.compile(
    r"(?i)^(?:"
    r"_ga(?:_[A-Za-z0-9]+)?|_gid|_gat|_gcl_[a-z]+|_fbp|_fbc|__utm[a-z]|"
    r"amp_.*|optimizely.*|ajs_.*|_hj(?:Session|Absolute|Included).*|"
    r"hubspotutk|__hstc|__hssc|__hssrc|mp_.*_mixpanel|ajs_anonymous_id|"
    r"intercom-.*|__cfruid|__cf_bm|_cfuvid|cf_clearance|"
    r"_clck|_clsk|CLID|MR|MUID|SRM_B|ANONCHK|"
    r"NID|1P_JAR|AEC|CONSENT|SOCS|"
    r"bm_sz|ak_bmsc|bm_sv|bm_mi|abck|_abck|akamai.*"
    r")$"
)

# Preferences / consent — no credential impact
_PREFERENCE_NAME_RE = re.compile(
    r"(?i)^(?:"
    r"lang|locale|language|tz|timezone|theme|color[_-]?scheme|cookieconsent|"
    r"cookie[_-]?consent|cookies[_-]?accepted|OptanonConsent|OptanonAlertBoxClosed|"
    r"notice_preferences|usprivacy|GPC|preferences?|display|sidebar|"
    r"has_js|js_enabled|cookie_test|test_cookie"
    r")$"
)

_ATTR_RE = re.compile(
    r"(?i)^\s*(Expires|Max-Age|Domain|Path|SameSite|Secure|HttpOnly|Partitioned)\s*(?:=(.*))?$"
)


def _split_set_cookie(value: str) -> List[str]:
    if not value:
        return []
    parts = re.split(r",(?=\s*[A-Za-z0-9_\-]+=)", value)
    return [p.strip() for p in parts if p.strip()]


def _mask_value(value: str, *, keep_start: int = 4, keep_end: int = 4) -> str:
    val = (value or "").strip()
    if not val:
        return ""
    if len(val) <= keep_start + keep_end + 2:
        return val[:2] + "***" + (val[-1:] if len(val) > 3 else "")
    return f"{val[:keep_start]}…{val[-keep_end:]}"


def parse_set_cookie(part: str) -> Dict[str, Any]:
    """Parse one Set-Cookie segment into structured fields."""
    text = (part or "").strip()
    if not text:
        return {}
    pieces = [p.strip() for p in text.split(";") if p.strip()]
    if not pieces:
        return {}
    name_value = pieces[0]
    if "=" in name_value:
        name, value = name_value.split("=", 1)
    else:
        name, value = name_value, ""
    name = name.strip()
    value = value.strip().strip('"')
    attrs: Dict[str, str] = {}
    flags: List[str] = []
    httponly = False
    secure = False
    samesite = ""
    for piece in pieces[1:]:
        m = _ATTR_RE.match(piece)
        if not m:
            continue
        key = m.group(1)
        raw_val = (m.group(2) or "").strip()
        key_l = key.lower()
        if key_l == "httponly":
            httponly = True
            flags.append("HttpOnly")
        elif key_l == "secure":
            secure = True
            flags.append("Secure")
        elif key_l == "samesite":
            samesite = raw_val or "Lax"
            flags.append(f"SameSite={samesite}")
        elif key_l == "partitioned":
            flags.append("Partitioned")
        else:
            attrs[key] = raw_val
            if key_l in ("domain", "path", "max-age", "expires") and raw_val:
                flags.append(f"{key}={raw_val}" if key_l != "expires" else "Expires")
    return {
        "name": name,
        "value": value,
        "value_masked": _mask_value(value),
        "httponly": httponly,
        "secure": secure,
        "samesite": samesite,
        "domain": attrs.get("Domain", ""),
        "path": attrs.get("Path", ""),
        "flags": ",".join(flags) if flags else "(none)",
        "snippet": text[:160],
        "raw": text,
    }


def classify_cookie(name: str, value: str = "") -> str:
    """Return role: auth_session | csrf | analytics | preference | jwt | unknown.

    Analytics/preference exact matches run before auth substrings so names like
    ``intercom-session-*`` / ``_ga`` are not misclassified as session credentials.
    """
    n = (name or "").strip()
    v = (value or "").strip()
    if v and _JWT_RE.match(v):
        return "jwt"
    if _ANALYTICS_NAME_RE.match(n):
        return "analytics"
    if _PREFERENCE_NAME_RE.match(n):
        return "preference"
    if _CSRF_NAME_RE.match(n) or re.search(r"(?i)csrf|xsrf|forgery", n):
        return "csrf"
    if _AUTH_NAME_RE.match(n):
        return "auth_session"
    # Prefix + entropy only — bare substring (cart_token, device_sid, ab_test_session)
    # is too noisy and is intentionally not treated as auth.
    if re.search(r"(?i)^(sess|auth|jwt|sid)[_-]?", n) and len(v) >= 16 and _entropy_hint(v):
        return "auth_session"
    return "unknown"


def _entropy_hint(value: str) -> bool:
    """True when value looks like a high-entropy opaque token (not a keyword)."""
    v = (value or "").strip()
    if len(v) < 16:
        return False
    if re.fullmatch(r"[0-9a-fA-F]{16,}", v):
        return True
    if re.fullmatch(r"[A-Za-z0-9_\-+/=]{20,}", v) and len(set(v)) >= 8:
        return True
    return False


def assess_cookie_impact(
    cookie: Dict[str, Any],
    *,
    page_url: str = "",
) -> Dict[str, Any]:
    """Decide whether this cookie is a stealable credential and how severe."""
    name = str(cookie.get("name") or "")
    value = str(cookie.get("value") or "")
    role = classify_cookie(name, value)
    httponly = bool(cookie.get("httponly"))
    secure = bool(cookie.get("secure"))
    samesite = str(cookie.get("samesite") or "")
    scheme = (urlparse(page_url).scheme or "").lower()

    issues: List[str] = []
    stealable = False
    impact = "no_credential_impact"
    severity = "info"
    summary = ""

    if role in ("analytics", "preference"):
        impact = "no_credential_impact"
        severity = "info"
        summary = (
            f"`{name}` looks like a {role} cookie — not a login/session credential. "
            "Stealing it does not grant account access."
        )
    elif role == "csrf":
        impact = "limited_impact"
        severity = "info"
        summary = (
            f"`{name}` is a CSRF/anti-forgery token. Alone it is not a session credential; "
            "impact is limited unless combined with a stolen session."
        )
        if not httponly:
            issues.append("Readable by JavaScript (no HttpOnly) — expected for many CSRF designs")
    elif role in ("auth_session", "jwt") or (
        role == "unknown" and _entropy_hint(value) and re.search(r"(?i)(sess|auth|token|sid|jwt)", name)
    ):
        if role == "unknown":
            role = "auth_session"
        # Credential-bearing cookie
        if not httponly:
            stealable = True
            issues.append("Missing HttpOnly — XSS or injected script can read this cookie")
        if scheme == "https" and not secure:
            stealable = True
            issues.append("Missing Secure on HTTPS — cookie may leak on HTTP requests")
        if samesite.lower() == "none" and not secure:
            stealable = True
            issues.append("SameSite=None without Secure — browser may reject or widen exposure")
        if not samesite:
            issues.append("No SameSite attribute — broader CSRF cross-site send risk")

        if stealable:
            impact = "stealable_credential"
            severity = "high" if (not httponly or (scheme == "https" and not secure)) else "medium"
            summary = (
                f"`{name}` appears to be a session/auth credential. "
                "If an attacker obtains it (XSS, network, malware), they can likely impersonate the user."
            )
        else:
            impact = "mitigated_credential"
            severity = "info"
            summary = (
                f"`{name}` is a session/auth cookie, but HttpOnly"
                + (" + Secure" if secure else "")
                + (f" + SameSite={samesite}" if samesite else "")
                + " reduce theft via JavaScript. Residual risk remains (malware, physical access, XSS→request)."
            )
        if role == "jwt":
            summary += " Value is JWT-shaped (bearer-like identity)."
    else:
        # Unknown cookie — only raise when flags are weak AND value looks secret-like
        if _entropy_hint(value) and not httponly:
            impact = "possible_credential"
            severity = "low"
            stealable = True
            issues.append("Opaque high-entropy value without HttpOnly — verify it is not a session token")
            summary = (
                f"`{name}` is unclassified but looks like an opaque token readable by JavaScript. "
                "Confirm whether it grants access; if not, no credential impact."
            )
        else:
            impact = "no_credential_impact"
            severity = "info"
            summary = (
                f"`{name}` does not match known session/auth cookie patterns and shows no clear "
                "stealable-credential signal."
            )

    return {
        "role": role,
        "impact": impact,
        "severity": severity,
        "stealable": stealable,
        "summary": summary,
        "issues": issues,
    }


def cookie_to_inventory_row(cookie: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, str]:
    """Flatten parse + assessment into the report inventory row."""
    return {
        "name": str(cookie.get("name") or ""),
        "flags": str(cookie.get("flags") or "(none)"),
        "snippet": str(cookie.get("snippet") or "")[:120],
        "value_masked": str(cookie.get("value_masked") or ""),
        "role": str(assessment.get("role") or ""),
        "impact": str(assessment.get("impact") or ""),
        "severity": str(assessment.get("severity") or "info"),
        "summary": str(assessment.get("summary") or "")[:300],
        "issues": "; ".join(assessment.get("issues") or [])[:240],
        "domain": str(cookie.get("domain") or ""),
        "path": str(cookie.get("path") or ""),
    }


def analyze_set_cookie_headers(
    headers: Optional[dict],
    *,
    page_url: str = "",
) -> Tuple[List[Dict[str, str]], List[Tuple[str, str, str, Optional[str]]]]:
    """Parse response Set-Cookie headers → inventory rows + impact findings.

    Findings are (category, severity, detail, evidence) where evidence is the
    masked cookie value (full raw only kept when clearly stealable JWT/session).
    """
    inventory: List[Dict[str, str]] = []
    findings: List[Tuple[str, str, str, Optional[str]]] = []
    if not headers:
        return inventory, findings

    raw_parts: List[str] = []
    for key, value in headers.items():
        if str(key).lower() != "set-cookie":
            continue
        if isinstance(value, (list, tuple)):
            for item in value:
                raw_parts.extend(_split_set_cookie(str(item)))
        else:
            raw_parts.extend(_split_set_cookie(str(value)))

    seen_names: set = set()
    for part in raw_parts:
        parsed = parse_set_cookie(part)
        if not parsed.get("name"):
            continue
        assessment = assess_cookie_impact(parsed, page_url=page_url)
        row = cookie_to_inventory_row(parsed, assessment)
        inventory.append(row)

        name = row["name"]
        role = str(assessment.get("role") or "")
        impact = str(assessment.get("impact") or "")
        # Stealable auth/jwt = high-confidence TP; possible_credential = precise low TP
        emit = (
            impact == "stealable_credential" and role in ("auth_session", "jwt")
        ) or (impact == "possible_credential" and bool(assessment.get("stealable")))
        if emit:
            dedupe = f"{name}|{impact}|{row['flags']}"
            if dedupe in seen_names:
                continue
            seen_names.add(dedupe)
            issues = assessment.get("issues") or []
            issue_txt = f" Issues: {'; '.join(issues)}." if issues else ""
            detail = (
                f"Cookie `{name}` — {assessment['summary']}{issue_txt} "
                f"Flags: {row['flags']}. Impact: {impact}."
            )
            evidence = row.get("value_masked") or None
            if assessment.get("stealable") and parsed.get("value") and impact == "stealable_credential":
                evidence = str(parsed["value"])
            findings.append(("authentication", str(assessment["severity"]), detail, evidence))
        # mitigated / analytics / preference → inventory only

    return inventory, findings


def analyze_cookie_request_header(
    headers: Optional[dict],
    *,
    page_url: str = "",
) -> Tuple[List[Dict[str, str]], List[Tuple[str, str, str, Optional[str]]]]:
    """Also inspect outbound Cookie request header (captured on the response exchange)."""
    inventory: List[Dict[str, str]] = []
    findings: List[Tuple[str, str, str, Optional[str]]] = []
    if not headers:
        return inventory, findings
    raw = ""
    for key, value in headers.items():
        if str(key).lower() == "cookie":
            raw = str(value)
            break
    if not raw:
        return inventory, findings

    for piece in raw.split(";"):
        piece = piece.strip()
        if not piece or "=" not in piece:
            continue
        name, value = piece.split("=", 1)
        fake = {
            "name": name.strip(),
            "value": value.strip(),
            "value_masked": _mask_value(value.strip()),
            "httponly": False,  # request Cookie header is always JS-visible historically if set without HttpOnly
            "secure": (urlparse(page_url).scheme or "").lower() == "https",
            "samesite": "",
            "domain": "",
            "path": "",
            "flags": "(request Cookie — flags unknown)",
            "snippet": piece[:120],
            "raw": piece,
        }
        # Request header does not include flags; only flag JWT / clear auth names as notable
        role = classify_cookie(fake["name"], fake["value"])
        if role not in ("auth_session", "jwt") and not (
            role == "unknown" and _entropy_hint(fake["value"]) and re.search(r"(?i)(sess|auth|token|jwt)", fake["name"])
        ):
            assessment = assess_cookie_impact({**fake, "httponly": True, "secure": True, "samesite": "Lax"}, page_url=page_url)
            row = cookie_to_inventory_row(fake, assessment)
            row["summary"] = (
                f"`{fake['name']}` seen on request Cookie header ({role}). "
                "Flags unknown from request; no Set-Cookie flags to evaluate."
            )
            inventory.append(row)
            continue
        assessment = assess_cookie_impact(fake, page_url=page_url)
        # Request Cookie cannot prove missing HttpOnly — inventory only, never a finding
        if assessment["impact"] == "stealable_credential":
            assessment["impact"] = "possible_credential"
            assessment["severity"] = "info"
            assessment["stealable"] = False
            assessment["summary"] = (
                f"`{fake['name']}` auth-like cookie present on the request. "
                "Flags unknown here — confirm Set-Cookie on the issuing response."
            )
            assessment["issues"] = [
                "Observed on Cookie request header — verify HttpOnly/Secure on Set-Cookie"
            ]
        row = cookie_to_inventory_row(fake, assessment)
        inventory.append(row)
        # No findings from request Cookie alone (Set-Cookie path emits stealable ones)
    return inventory, findings


def analyze_response_cookies(
    headers: Optional[dict],
    *,
    page_url: str = "",
    include_request_cookie: bool = True,
) -> Tuple[List[Dict[str, str]], List[Tuple[str, str, str, Optional[str]]]]:
    """Full cookie capture for a response: Set-Cookie (+ optional request Cookie)."""
    inv, findings = analyze_set_cookie_headers(headers, page_url=page_url)
    if include_request_cookie:
        inv2, find2 = analyze_cookie_request_header(headers, page_url=page_url)
        # Prefer Set-Cookie rows when the same name exists
        have = {r.get("name") for r in inv}
        for row in inv2:
            if row.get("name") not in have:
                inv.append(row)
        findings.extend(find2)
    return inv, findings
