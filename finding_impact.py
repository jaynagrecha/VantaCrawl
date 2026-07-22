"""Finding impact checkers — verify / classify real impact for scanner findings.

Mirrors the cookie impact model for every category we can assess:

  classify (role) → assess (impact) → optional live verify → enrich or suppress

Impact vocabulary (shared with cookie_impact where applicable):
  confirmed              — actively verified or high-confidence proof
  stealable_credential   — credential that can be stolen / replayed
  possible               — heuristic hit; not live-confirmed
  possible_credential    — opaque token that may be a credential
  mitigated              — real surface but protective controls present
  limited_impact         — real artifact, limited attacker value alone
  informational          — hardening / hygiene, not an exploit
  no_impact              — verified non-issue (invalid secret, analytics, etc.)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence


@dataclass
class ImpactResult:
    role: str = "finding"
    impact: str = "possible"
    severity: Optional[str] = None  # override original severity when set
    summary: str = ""
    validation: str = "n/a"  # active|invalid|confirmed|unverified|skipped|n/a|error
    proof: Optional[Any] = None
    suppress: bool = False
    detail_suffix: str = ""
    issues: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "role": self.role,
            "impact": self.impact,
            "validation": self.validation,
            "summary": self.summary,
        }
        if self.severity:
            out["severity_override"] = self.severity
        if self.proof:
            out["proof"] = self.proof
        if self.issues:
            out["issues"] = list(self.issues)
        return out


# --- Header audit: real hardening vs informational hygiene --------------------

_HARDENING_HEADERS = re.compile(
    r"(?i)(missing hsts|strict-transport-security|missing csp|content-security-policy|"
    r"missing x-frame|x-frame-options|outdated server)"
)
_INFO_HEADERS = re.compile(
    r"(?i)(referrer-policy|permissions-policy|x-content-type-options|"
    r"x-powered-by|server banner)"
)

# --- Helpers ------------------------------------------------------------------

def _detail_l(detail: str) -> str:
    return (detail or "").lower()


def _is_active_confirmed(detail: str) -> bool:
    d = _detail_l(detail)
    return d.startswith("active ") or " confirmed" in d or "actively confirmed" in d


def assess_header_audit(detail: str, severity: str) -> ImpactResult:
    d = _detail_l(detail)
    # Hygiene (Referrer-Policy, Permissions-Policy, X-Powered-By) → inventory only
    if _INFO_HEADERS.search(d):
        return ImpactResult(
            role="hygiene",
            impact="informational",
            severity="info",
            summary="Header hygiene / disclosure — tracked in inventory, not raised as a finding.",
            validation="confirmed",
            suppress=True,
        )
    # HSTS / CSP / X-Frame — hardening misconfigurations, not demonstrated vulns
    if _HARDENING_HEADERS.search(d):
        sev = severity if severity in ("info", "low") else "info"
        if "csp" in d or "content-security" in d:
            summary = (
                "Missing CSP — hardening only unless XSS/script injection is also demonstrated."
            )
        elif "hsts" in d or "strict-transport" in d:
            summary = (
                "Missing HSTS — usually informational on HTTPS-only hosts unless HTTP "
                "downgrade is proven."
            )
        elif "x-frame" in d:
            summary = (
                "Missing X-Frame-Options — hardening only without a clickjacking PoC "
                "(frameable page + sensitive authenticated action)."
            )
        else:
            summary = "Missing transport/framing control — hardening gap, not an active exploit."
        return ImpactResult(
            role="hardening",
            impact="informational",
            severity=sev,
            summary=summary,
            validation="confirmed",
        )
    return ImpactResult(
        role="hardening",
        impact="informational",
        severity=severity if severity in ("info", "low") else "info",
        summary="Security header finding — verify against your policy baseline.",
        validation="confirmed",
    )


def assess_authentication(detail: str, severity: str, evidence: str = "") -> ImpactResult:
    d = _detail_l(detail)
    if "password-reset deep-link" in d or "deep-link flow" in d:
        return ImpactResult(
            role="flow_identifier",
            impact="informational",
            severity="info",
            summary=(
                "Password-reset deep-link flow identifier observed — attack-surface only; "
                "not an exposed credential."
            ),
            validation="unverified",
            proof=evidence or None,
        )
    if "reset token arrives via url" in d or "reset token referenced from url" in d:
        return ImpactResult(
            role="auth_token_in_url",
            impact="limited_impact" if "replaceState" in d or "address bar" in d else "informational",
            severity=severity if severity in ("info", "low") else "low",
            summary=(
                "Reset token in URL query is a leakage risk (history, Referer, analytics) unless "
                "single-use, short-lived, and cleared via replaceState."
            ),
            validation="unverified",
            proof=evidence or None,
        )
    if "stealable_credential" in d or "missing httponly" in d:
        return ImpactResult(
            role="auth_session",
            impact="stealable_credential",
            severity=severity if severity in ("critical", "high", "medium") else "high",
            summary="Session/auth cookie appears stealable (missing protective flags).",
            validation="confirmed",
            proof=evidence or None,
        )
    if "mitigated_credential" in d or "protective flags" in d or "no practical js cookie-theft" in d:
        return ImpactResult(
            role="auth_session",
            impact="mitigated",
            severity="info",
            summary="Session cookie present with protective flags — residual non-JS theft risk only.",
            validation="confirmed",
        )
    if "no_credential_impact" in d or "analytics" in d or "not a login/session" in d:
        return ImpactResult(
            role="cookie",
            impact="no_impact",
            severity="info",
            summary="Cookie is not a login credential.",
            validation="confirmed",
            suppress=True,  # do not treat as a security finding in reports
        )
    if "possible_credential" in d:
        # Request-Cookie possibles stay suppressed; Set-Cookie possibles are low TPs
        if "request" in d:
            return ImpactResult(
                role="cookie",
                impact="possible_credential",
                severity="info",
                summary="Auth-like cookie on request — flags unknown; inventory only.",
                validation="unverified",
                suppress=True,
                proof=evidence or None,
            )
        return ImpactResult(
            role="cookie",
            impact="possible_credential",
            severity=severity or "low",
            summary="Opaque high-entropy cookie without HttpOnly — verify it is not a session token.",
            validation="unverified",
            proof=evidence or None,
        )
    if "limited_impact" in d or "csrf" in d:
        return ImpactResult(
            role="csrf",
            impact="limited_impact",
            severity="info",
            summary="CSRF/anti-forgery token — not a reusable session credential alone.",
            validation="confirmed",
        )
    if "credential-like value in url" in d or "credentials or tokens appear in url" in d:
        return ImpactResult(
            role="credential_in_url",
            impact="possible_credential",
            severity=severity if severity in ("critical", "high") else "high",
            summary="Credential-shaped value in the URL can leak via logs, Referer, and history.",
            validation="unverified",
            proof=evidence or None,
        )
    if "http" in d and ("login" in d or "password" in d or "auth" in d):
        return ImpactResult(
            role="login_surface",
            impact="confirmed",
            severity=severity or "high",
            summary="Login/password surface on cleartext HTTP — credentials can be intercepted.",
            validation="confirmed",
        )
    return ImpactResult(
        role="login_surface",
        impact="possible",
        severity=severity or "medium",
        summary="Authentication-related surface — review hardening.",
        validation="unverified",
    )


def assess_secrets_static(detail: str, severity: str, evidence: str = "") -> ImpactResult:
    try:
        from secret_classify import (
            is_browser_rum_telemetry_key,
            is_client_public_key,
            is_google_browser_api_key,
        )
    except Exception:
        is_client_public_key = lambda *_a, **_k: False  # type: ignore
        is_browser_rum_telemetry_key = lambda *_a, **_k: False  # type: ignore
        is_google_browser_api_key = lambda *_a, **_k: False  # type: ignore

    # Deep-link / flow identifiers must never enter credential remediation
    try:
        from security_scan import _KNOWN_FLOW_IDENTIFIERS, classify_secret_candidate

        ev = (evidence or "").strip()
        if ev:
            role = classify_secret_candidate("", ev, detail or "")
            if role or re.sub(r"[^a-z0-9]+", "", ev.lower()) in _KNOWN_FLOW_IDENTIFIERS:
                return ImpactResult(
                    role="flow_identifier",
                    impact="no_impact",
                    severity="info",
                    summary=(
                        f"`{ev}` is a frontend flow/deep-link identifier — "
                        "not an exposed password or credential."
                    ),
                    validation="invalid",
                    proof=evidence or None,
                    suppress=True,
                )
        # Detail title like "Exposed Reset Password" with R3ResetPass in text
        if re.search(r"(?i)\br3reset[-_]?pass\b", f"{detail or ''}\n{ev}"):
            return ImpactResult(
                role="flow_identifier",
                impact="no_impact",
                severity="info",
                summary="R3ResetPass is a password-reset deep-link flow id — not a secret.",
                validation="invalid",
                proof=evidence or None,
                suppress=True,
            )
    except Exception:
        pass
    # Pure RUM/analytics keys (Boomr, mPulse, …) — intentional in browser, no report value
    if is_browser_rum_telemetry_key(detail):
        return ImpactResult(
            role="client_public_key",
            impact="no_impact",
            severity="info",
            summary="Browser RUM/analytics client key — intentional in front-end bundles; not a stealable credential.",
            validation="skipped",
            proof=evidence or None,
            suppress=True,
        )
    # Maps/Firebase AIza keys are designed to ship in browsers — suppress unless live
    # validation later proves unrestricted abuse (assess_secrets_live).
    if is_google_browser_api_key(detail, evidence):
        return ImpactResult(
            role="client_public_key",
            impact="no_impact",
            severity="info",
            summary="Google/Firebase browser API key — expected in client bundles; report only if live check proves unrestricted use.",
            validation="skipped",
            proof=evidence or None,
            suppress=True,
        )
    if is_client_public_key(detail, evidence):
        sev = severity if severity in ("info", "low", "medium") else "low"
        return ImpactResult(
            role="client_public_key",
            impact="limited_impact",
            severity=sev,
            summary="Client/publishable key observed — often intentional in browser apps; verify API restrictions.",
            validation="unverified",
            proof=evidence or None,
        )
    return ImpactResult(
        role="credential",
        impact="possible_credential",
        severity=severity or "high",
        summary="Credential-shaped value found in a response. Live validation not run yet.",
        validation="unverified",
        proof=evidence or None,
    )


async def assess_secrets_live(
    *,
    label: str,
    detail: str,
    severity: str,
    evidence: str,
    client: Any = None,
) -> ImpactResult:
    """Run read-only vendor identity check when possible."""
    from secret_validate import format_validation_suffix, validate_secret

    # Prefer typed label from detail ("Exposed Boomr API Key…")
    typed = label
    m = re.search(r"(?i)^exposed\s+(.+?)\s+in\s+response\b", detail or "")
    if m:
        typed = m.group(1).strip()
    elif detail and ":" in detail and not detail.lower().startswith("missing "):
        typed = detail.split(":", 1)[0].strip()

    try:
        from secret_classify import (
            is_browser_rum_telemetry_key,
            is_client_public_key,
            is_google_browser_api_key,
        )
    except Exception:
        is_client_public_key = lambda *_a, **_k: False  # type: ignore
        is_browser_rum_telemetry_key = lambda *_a, **_k: False  # type: ignore
        is_google_browser_api_key = lambda *_a, **_k: False  # type: ignore

    # Drop pure RUM/telemetry noise before spending a live probe
    if is_browser_rum_telemetry_key(typed) or is_browser_rum_telemetry_key(detail):
        return ImpactResult(
            role="client_public_key",
            impact="no_impact",
            severity="info",
            summary="Browser RUM/analytics client key — intentional in front-end bundles; not a stealable credential.",
            validation="skipped",
            proof=evidence or None,
            suppress=True,
        )

    google_browser = is_google_browser_api_key(typed, evidence) or is_google_browser_api_key(
        detail, evidence
    )

    result = await validate_secret(typed, evidence or "", client=client)
    suffix = format_validation_suffix(result)

    if result.status == "active":
        # Never promote intentional client/publishable keys to critical
        if is_client_public_key(typed, evidence) or is_client_public_key(detail, evidence):
            return ImpactResult(
                role="client_public_key",
                impact="limited_impact",
                severity="medium",
                summary=result.summary + " (client/publishable key — verify API restrictions)",
                validation="active",
                proof=evidence or None,
                detail_suffix=suffix,
                issues=["Live check: vendor accepted this client/publishable key"],
            )
        return ImpactResult(
            role="credential",
            impact="stealable_credential",
            severity="critical" if severity in ("high", "critical", "medium") else severity,
            summary=result.summary,
            validation="active",
            proof=evidence or None,
            detail_suffix=suffix,
            issues=["Live check: vendor accepted this credential"],
        )
    client_key = is_client_public_key(typed, evidence) or is_client_public_key(detail, evidence)

    # Google Maps/Firebase: suppress unless proven unrestricted (active above).
    if google_browser:
        return ImpactResult(
            role="client_public_key",
            impact="no_impact",
            severity="info",
            summary=(
                result.summary
                + " — Google/Firebase browser key not proven unrestricted; suppressed from report."
            ),
            validation="skipped" if result.status in ("skipped", "invalid") else "unverified",
            proof=evidence or None,
            detail_suffix=suffix,
            suppress=True,
            issues=["Live check: browser Google key not unrestricted"],
        )

    if result.status == "invalid":
        return ImpactResult(
            role="client_public_key" if client_key else "credential",
            impact="no_impact",
            severity="info",
            summary=result.summary,
            validation="invalid",
            proof=evidence or None,
            detail_suffix=suffix,
            suppress=False,  # keep as info so analysts see it was checked
            issues=["Live check: vendor rejected this credential"],
        )
    if result.status in ("skipped", "unknown"):
        # Restricted / unverified browser Google keys are informational — not stealable creds
        if client_key:
            summary_l = (result.summary or "").lower()
            restricted = any(
                x in summary_l
                for x in ("restrict", "referer", "referrer", "denied", "http 400", "http 403")
            )
            return ImpactResult(
                role="client_public_key",
                impact="limited_impact",
                severity="info" if restricted else "low",
                summary=result.summary
                + (
                    " — typically acceptable when HTTP referrer / API restrictions are in place"
                    if restricted
                    else " — verify key restrictions (HTTP referrers + API allow-list)"
                ),
                validation="unverified" if result.status == "unknown" else "skipped",
                proof=evidence or None,
                detail_suffix=suffix,
                issues=["Live check: client/publishable key not proven unrestricted"],
            )
        return ImpactResult(
            role="credential",
            impact="possible_credential",
            severity=severity or "high",
            summary=result.summary,
            validation="unverified" if result.status == "unknown" else "skipped",
            proof=evidence or None,
            detail_suffix=suffix,
        )
    if client_key:
        return ImpactResult(
            role="client_public_key",
            impact="limited_impact",
            severity="low",
            summary=result.summary,
            validation="error" if result.status == "error" else "unverified",
            proof=evidence or None,
            detail_suffix=suffix,
        )
    return ImpactResult(
        role="credential",
        impact="possible_credential",
        severity=severity or "high",
        summary=result.summary,
        validation="error" if result.status == "error" else "unverified",
        proof=evidence or None,
        detail_suffix=suffix,
    )


def _cors_proof_status(proof: Any) -> Optional[int]:
    """Extract HTTP status from stored CORS proof response lines, if present."""
    if not isinstance(proof, dict):
        return None
    blob = str(proof.get("response") or "")
    m = re.search(r"(?i)^HTTP/\d(?:\.\d)?\s+(\d{3})", blob, re.M)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


def assess_cors(
    detail: str,
    severity: str,
    *,
    url: str = "",
    cookies: Optional[Sequence[Dict[str, Any]]] = None,
    login_surfaces: Optional[Sequence[str]] = None,
    proof: Optional[Any] = None,
) -> ImpactResult:
    """CORS impact considering observed cookies + endpoint nature — not just ACAO/ACAC.

    Confirmation requires raw request/response proof (ACAO/ACAC headers). Without it the
    finding is an unverified configuration signal only.
    Non-2xx / sitemap-style public probes stay informational — header reflection ≠ data exposure.
    """
    from urllib.parse import urlparse

    from finding_proof import proof_has_http_exchange

    d = _detail_l(detail)
    creds = "credential" in d
    has_proof = proof_has_http_exchange(proof)
    if not has_proof:
        return ImpactResult(
            role="cors",
            impact="limited_impact" if creds else "informational",
            severity="info",
            summary="CORS configuration signal — impact unverified (no raw ACAO/ACAC proof stored).",
            validation="unverified",
            proof=None,
        )
    if not creds:
        return ImpactResult(
            role="cors",
            impact="possible",
            severity="info",
            summary="CORS configuration may be overly open (no credentials flag observed).",
            validation="unverified",
            proof=proof if isinstance(proof, (str, dict)) else None,
        )

    path = (urlparse(url).path or "/").lower()
    host = (urlparse(url).netloc or "").lower()
    proof_status = _cors_proof_status(proof)
    # Header reflection on 4xx/5xx (e.g. sitemap 403) confirms config, not readable data.
    if proof_status is not None and not (200 <= proof_status < 300):
        return ImpactResult(
            role="cors",
            impact="informational",
            severity="info",
            summary=(
                f"CORS reflects Origin with credentials, but the probed response was "
                f"HTTP {proof_status} — confirms header behavior only, not sensitive data exposure. "
                "Keep informational until a sensitive authenticated 2xx body is readable cross-origin."
            ),
            validation="confirmed",
            proof=proof if isinstance(proof, (str, dict)) else None,
        )

    auth_like_path = bool(
        re.search(
            r"(?i)/(?:login|signin|sign-in|auth|oauth|account|user|profile|dashboard|"
            r"portal|member|session|settings|wallet|transfer|send-money|api(?:/|$)|graphql)",
            path,
        )
    )
    static_like_path = bool(
        re.search(
            r"(?i)\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp|avif|"
            r"xml|txt|json|csv|pdf)(?:$|\?)",
            path,
        )
    ) or path.startswith(("/static/", "/assets/", "/cdn/", "/_next/static/", "/dist/")) or bool(
        re.search(r"(?i)/(?:sitemap|robots\.txt|favicon)", path)
    )

    auth_cookies: List[str] = []
    tracking_cookies: List[str] = []
    other_cookies: List[str] = []
    for row in cookies or []:
        if not isinstance(row, dict):
            continue
        # Prefer same-host cookies when page_url/host was recorded
        row_host = str(row.get("host") or "")
        row_page = str(row.get("page_url") or "")
        if row_host and host and row_host != host:
            continue
        if row_page and host and host not in row_page.lower():
            continue
        name = str(row.get("name") or "")
        role = str(row.get("role") or "")
        impact = str(row.get("impact") or "")
        if not role:
            try:
                from cookie_impact import classify_cookie

                role = classify_cookie(name, "")
            except Exception:
                role = "unknown"
        if role in ("auth_session", "jwt") or impact in (
            "stealable_credential",
            "mitigated_credential",
        ):
            auth_cookies.append(name)
        elif role in ("analytics", "preference", "cdn", "edge_protection") or impact in (
            "possible_credential",
            "no_credential_impact",
        ):
            tracking_cookies.append(name)
        else:
            other_cookies.append(name)

    login_on_host = False
    for surface in login_surfaces or []:
        try:
            if host and host in str(surface).lower():
                login_on_host = True
                break
        except Exception:
            continue

    issues: List[str] = []
    if auth_cookies:
        issues.append(
            "Observed session/auth cookie(s) on this origin: "
            + ", ".join(auth_cookies[:8])
            + ("…" if len(auth_cookies) > 8 else "")
        )
    if tracking_cookies and not auth_cookies:
        issues.append(
            "So far only tracking/preference cookies observed "
            f"({', '.join(tracking_cookies[:6])}{'…' if len(tracking_cookies) > 6 else ''}) — "
            "that does not mean logged-in users lack session cookies"
        )
    if auth_like_path:
        issues.append(f"Endpoint path looks auth-sensitive ({path or '/'})")
    if login_on_host:
        issues.append("Login/auth surfaces were discovered on this host")
    if static_like_path and not auth_cookies and not auth_like_path:
        issues.append("Path looks like a static asset — credential impact may be lower here")

    def _cors_proof_out():
        """Keep raw HTTP exchange when provided; attach cookie/path context as evidence."""
        ctx = "; ".join(issues[:4]) if issues else ""
        if isinstance(proof, dict) and proof_has_http_exchange(proof):
            out = dict(proof)
            if ctx:
                prev = str(out.get("evidence") or "")
                out["evidence"] = f"{prev}; {ctx}".strip("; ") if prev else ctx
            return out
        return ctx or None

    # Credentialed CORS is always a real misconfig; severity depends on likely session cookies.
    if auth_cookies or auth_like_path or login_on_host:
        summary = (
            "CORS reflects Origin with credentials, and this origin likely carries session/auth "
            "cookies (observed auth cookies and/or auth-sensitive endpoint). A malicious site can "
            "read authenticated responses from a logged-in victim."
        )
        return ImpactResult(
            role="cors",
            impact="stealable_credential",
            severity="high",
            summary=summary,
            validation="confirmed",
            issues=issues,
            proof=_cors_proof_out(),
        )

    if static_like_path and tracking_cookies and not other_cookies:
        summary = (
            "CORS allows credentials, but this URL looks like a static/public asset and only "
            "tracking/CDN cookies were observed here. Reading a public sitemap/asset cross-origin "
            "has limited credential impact — verify origin-wide session cookies before raising severity."
        )
        return ImpactResult(
            role="cors",
            impact="informational",
            severity="info",
            summary=summary,
            validation="confirmed",
            issues=issues,
            proof=_cors_proof_out(),
        )

    if static_like_path and not auth_cookies and not auth_like_path:
        summary = (
            "CORS reflects Origin with credentials on a public/static resource. "
            "Without observed session cookies on an auth-sensitive endpoint, keep this informational."
        )
        return ImpactResult(
            role="cors",
            impact="informational",
            severity="info",
            summary=summary,
            validation="unverified",
            issues=issues,
            proof=_cors_proof_out(),
        )

    # No auth cookies / auth path / login surface observed → do not default to high.
    # Credentialed CORS is still a misconfig, but without session evidence keep it medium.
    if tracking_cookies and not other_cookies:
        summary = (
            "CORS allows credentials, but only tracking/preference cookies were observed and "
            "no auth-sensitive path or login surface was found. Verify origin-wide session cookies "
            "before treating as high impact."
        )
        return ImpactResult(
            role="cors",
            impact="limited_impact",
            severity="medium",
            summary=summary,
            validation="confirmed",
            issues=issues,
            proof=_cors_proof_out(),
        )

    summary = (
        "CORS reflects Origin with credentials. No session/auth cookies or auth endpoints were "
        "observed on this pass — medium until session cookies or login surfaces are confirmed."
    )
    return ImpactResult(
        role="cors",
        impact="possible",
        severity="medium",
        summary=summary,
        # Misconfig itself is confirmed by the Origin probe (ACAO reflect + ACAC);
        # "unverified" here previously confused report readers about probe status.
        validation="confirmed",
        issues=issues,
        proof=_cors_proof_out(),
    )


def assess_sensitive_path(detail: str, severity: str, evidence: str = "") -> ImpactResult:
    if evidence:
        return ImpactResult(
            role="sensitive_file",
            impact="confirmed",
            severity=severity or "high",
            summary="Sensitive path content verified (not a soft-404).",
            validation="confirmed",
            proof=evidence,
        )
    # Unverified path matches are inventory-only — suppress if emitted
    return ImpactResult(
        role="sensitive_file",
        impact="no_impact",
        severity="info",
        summary="Sensitive path pattern matched without body proof — suppressed.",
        validation="unverified",
        suppress=True,
    )


def assess_mixed_content(detail: str, severity: str) -> ImpactResult:
    d = _detail_l(detail)
    if any(x in d for x in (".js", "script", "iframe")):
        return ImpactResult(
            role="mixed_content",
            impact="possible",
            severity="medium",
            summary="HTTPS page references active HTTP content (script/iframe) — MITM can inject code.",
            validation="confirmed",
        )
    # Stylesheets / images / other passive mixed content — inventory noise
    return ImpactResult(
        role="mixed_content",
        impact="limited_impact",
        severity="info",
        summary="Passive mixed content (non-script) — suppressed as a finding.",
        validation="confirmed",
        suppress=True,
    )


def assess_open_redirect(detail: str, severity: str) -> ImpactResult:
    if _is_active_confirmed(detail):
        return ImpactResult(
            role="open_redirect",
            impact="confirmed",
            severity=severity or "medium",
            summary="Open redirect confirmed via Location response on probe.",
            validation="confirmed",
        )
    return ImpactResult(
        role="open_redirect",
        impact="possible",
        severity=severity or "low",
        summary="Off-site URL in a redirect-style parameter (precise passive) — verify allow-list.",
        validation="unverified",
    )


def assess_active_vuln(category: str, detail: str, severity: str) -> ImpactResult:
    role = category or "vuln"
    d = _detail_l(detail)
    if role == "idor" and "candidate" in d and "active" not in d:
        return ImpactResult(
            role="idor",
            impact="informational",
            severity="info",
            summary="Object-id parameter is an IDOR candidate — not confirmed until mutation proof.",
            validation="unverified",
        )
    if _is_active_confirmed(detail) or (role == "idor" and "active idor" in d):
        return ImpactResult(
            role=role,
            impact="confirmed",
            severity=severity or "high",
            summary=f"{category} actively confirmed against a baseline response.",
            validation="confirmed",
        )
    # form_probe status codes are not vulns
    if role == "form_probe":
        return ImpactResult(
            role=role,
            impact="no_impact",
            severity="info",
            summary="Form probe HTTP status — inventory only.",
            validation="unverified",
            suppress=True,
        )
    # Precise passive hits stay as possible at the scanner's severity
    precise = "precise" in _detail_l(detail)
    return ImpactResult(
        role=role,
        impact="possible",
        severity=severity or ("medium" if precise else "low"),
        summary=(
            f"{category} precise passive signal — not actively confirmed yet."
            if precise
            else f"{category} heuristic hit — not actively confirmed."
        ),
        validation="unverified",
    )


def assess_api_leak(detail: str, severity: str) -> ImpactResult:
    d = _detail_l(detail)
    if "firebase" in d and ("storage" in d or "identity toolkit" in d or "listable" in d):
        return ImpactResult(
            role="api_leak",
            impact="confirmed",
            severity=severity if severity in ("medium", "high") else "medium",
            summary="Firebase surface confirmed readable/listable with client API key.",
            validation="confirmed",
        )
    if "sensitive route referenced" in d:
        return ImpactResult(
            role="api_leak",
            impact="possible",
            severity=severity or "low",
            summary="Sensitive client-side route reference — verify authz on the live endpoint.",
            validation="unverified",
        )
    if "client-side api route reference" in d or (
        "graphql" in d and "schema not disclosed" in d
    ):
        return ImpactResult(
            role="api_leak",
            impact="informational",
            severity="info",
            summary="Client-side GraphQL/API route reference — not information disclosure without schema proof.",
            validation="unverified",
        )
    if "graphql" in d and ("schema json" in d or "__schema" in d or "querytype" in d):
        return ImpactResult(
            role="api_leak",
            impact="confirmed",
            severity=severity or "high",
            summary="GraphQL schema JSON disclosed on a GraphQL path.",
            validation="confirmed",
        )
    if "graphql" in d and ("playground" in d or "unverified" in d or "graphiql" in d):
        return ImpactResult(
            role="api_leak",
            impact="possible",
            severity=severity or "medium",
            summary="GraphQL playground/UI indicators — introspection not proven from schema JSON.",
            validation="unverified",
        )
    if "graphql" in d and ("introspection" in d or "playground" in d):
        return ImpactResult(
            role="api_leak",
            impact="possible",
            severity=severity or "medium",
            summary="GraphQL introspection/playground indicators on a GraphQL path.",
            validation="unverified",
        )
    if "json field" in d and "secret" in d:
        return ImpactResult(
            role="api_leak",
            impact="possible_credential",
            severity=severity or "high",
            summary="JSON response field may expose a secret value.",
            validation="unverified",
        )
    if "confirmed" in d or "body proof" in d or "exposed at" in d:
        return ImpactResult(
            role="api_leak",
            impact="confirmed" if "confirmed" in d or "body proof" in d else "possible",
            severity=severity or "medium",
            summary="Sensitive API/debug surface with content evidence.",
            validation="confirmed" if "confirmed" in d or "body proof" in d else "unverified",
        )
    # Path-only leftovers without proof
    return ImpactResult(
        role="api_leak",
        impact="no_impact",
        severity="info",
        summary="API/debug path pattern without body proof — suppressed.",
        validation="unverified",
        suppress=True,
    )


def assess_csrf(detail: str, severity: str) -> ImpactResult:
    d = _detail_l(detail)
    # Redirect-only / 3xx canaries are not confirmation
    if "http 301" in d or "http 302" in d or "http 303" in d or "http 307" in d or "http 308" in d:
        return ImpactResult(
            role="hardening",
            impact="informational",
            severity="info",
            summary="CSRF probe saw only a redirect — that does not prove request acceptance or state change.",
            validation="unverified",
        )
    if "csrf canary accepted" in d or "forged origin" in d:
        return ImpactResult(
            role="csrf",
            impact="possible",
            severity=severity if severity in ("medium", "high") else "medium",
            summary="Safe CSRF canary POST with forged Origin was accepted without a CSRF token.",
            validation="confirmed",
            issues=["Active canary: cross-site Origin/Referer accepted with dummy fields only"],
        )
    # Avoid contradictory summaries: detail saying no session cookie must not claim one is present
    if "no session cookie" in d:
        return ImpactResult(
            role="hardening",
            impact="informational",
            severity="info",
            summary="State-changing form without CSRF token — no session cookie observed.",
            validation="unverified",
        )
    if "session cookie present" in d or "precise csrf" in d:
        return ImpactResult(
            role="csrf",
            impact="possible",
            severity=severity if severity in ("medium", "high") else "medium",
            summary="State-changing form lacks CSRF token while a session cookie is present.",
            validation="unverified",
        )
    return ImpactResult(
        role="hardening",
        impact="informational",
        severity="info",
        summary="State-changing form without CSRF token — hardening until session cookie + exploit path is shown.",
        validation="unverified",
    )


def assess_http_methods(detail: str, severity: str) -> ImpactResult:
    d = _detail_l(detail)
    if "trace" in d:
        return ImpactResult(
            role="http_methods",
            impact="possible",
            severity="medium",
            summary="TRACE enabled — can assist cross-site tracing attacks.",
            validation="confirmed",
        )
    return ImpactResult(
        role="http_methods",
        impact="informational",
        severity="info",
        summary="HTTP method surface (OPTIONS/Allow) — inventory, usually low impact.",
        validation="confirmed",
    )


def assess_file_upload(detail: str, severity: str) -> ImpactResult:
    return ImpactResult(
        role="file_upload",
        impact="informational",
        severity="info",
        summary="File-upload surface discovered; server-side validation not assessed.",
        validation="unverified",
    )


def assess_well_known(detail: str, severity: str, evidence: str = "") -> ImpactResult:
    return ImpactResult(
        role="well_known",
        impact="informational",
        severity="info",
        summary="Well-known endpoint observed with content proof." if evidence else "Well-known endpoint observed.",
        validation="confirmed" if evidence else "unverified",
        proof=evidence or None,
    )


def assess_cloud_url(detail: str, severity: str) -> ImpactResult:
    return ImpactResult(
        role="cloud_url",
        impact="informational",
        severity=severity or "info",
        summary="Third-party cloud backend URL referenced — verify it is intentional and locked down.",
        validation="unverified",
    )


def assess_tier_category(category: str, detail: str, severity: str, evidence: str = "") -> ImpactResult:
    """Impact for Tier 2–6 categories (OAuth/JWT/GraphQL/mass-assignment/etc.)."""
    d = _detail_l(detail)
    cat = (category or "").lower()
    if cat == "cloud" and (
        "cloudfront" in d or "cdn dependency" in d or "security status not assessed" in d
    ):
        return ImpactResult(
            role="cloud_cdn",
            impact="informational",
            severity="info",
            summary=(
                "Cloud/CDN dependency observed — intentionally public CDN resources are not "
                "misconfigurations until anonymous list/read of private objects is proven."
            ),
            validation="unverified",
            proof=evidence or None,
        )
    if cat == "mass_assignment":
        # HTML shell / non-API handlers are never confirmed high
        if "html" in d and ("shell" in d or "doctype" in d or "application content" in d):
            return ImpactResult(
                role="mass_assignment",
                impact="no_impact",
                severity="info",
                summary="Mass-assignment probe hit a generic HTML response — not an API handler.",
                validation="invalid",
                suppress=True,
            )
        if "persisted in json" in d or "privilege field persisted" in d:
            return ImpactResult(
                role="mass_assignment",
                impact="confirmed",
                severity="high",
                summary="Privilege-shaped field persisted in a structured JSON API response.",
                validation="confirmed",
                proof=evidence or None,
            )
        # Client-side parameter name inventory only
        return ImpactResult(
            role="mass_assignment",
            impact="informational",
            severity="info",
            summary=(
                "Privilege/debug field names observed in client code — unconfirmed until a "
                "mutating API response shows persistence or authorization change."
            ),
            validation="unverified",
            proof=evidence or None,
        )
    if cat == "rate_limit":
        return ImpactResult(
            role="rate_limit",
            impact="informational",
            severity="info",
            summary=(
                "Authentication surface candidate requiring rate-limit assessment — "
                "redirect-only bursts do not prove missing rate limiting."
            ),
            validation="unverified",
            proof=evidence or None,
        )
    if cat == "business_logic" and ("race" in d or "identical" in d):
        if "html" in d or "static" in d:
            return ImpactResult(
                role="business_logic",
                impact="no_impact",
                severity="info",
                summary="Identical HTML responses under parallel POST do not demonstrate a race condition.",
                validation="invalid",
                suppress=True,
            )
    confirmed = (
        "confirmed" in d
        or "introspection confirmed" in d
        or "publicly listable" in d
        or "reflected privilege" in d
        or "probe accepted" in d
        or "persisted in json" in d
    )
    verified = (
        confirmed
        or "missing state" in d
        or "token leakage" in d
        or "alg=none" in d
    )
    if cat == "js_intel":
        # Inventory leftovers (should rarely emit after scanner tighten)
        if "network helpers" in d or re.search(r"\bfetch\(\)|\baxios\(\)", d):
            return ImpactResult(
                role="js_intel",
                impact="no_impact",
                severity="info",
                summary="Client network helper usage is normal for SPAs — not a finding.",
                validation="skipped",
                suppress=True,
            )
        if "access denied" in d or "http 403" in d or "http 401" in d or "http 400" in d:
            return ImpactResult(
                role="js_intel",
                impact="informational",
                severity="info",
                summary="Internal/non-prod host referenced in JS but anonymous access was denied — not exposed.",
                validation="confirmed",
                proof=evidence or None,
            )
        if "feature-flag" in d or "feature flag" in d:
            # SDK mention alone is recon inventory; keep only when we still emit
            return ImpactResult(
                role="js_intel",
                impact="informational",
                severity="info",
                summary="Feature-flag SDK string in bundle — recon only, not a vulnerability.",
                validation="unverified",
                proof=evidence or None,
                suppress=True,
            )
        return ImpactResult(
            role="js_intel",
            impact="informational",
            severity="info" if (severity or "info") in ("info", "low") else severity,
            summary="Frontend intelligence from JS mining — useful for recon, not a standalone vuln.",
            validation="unverified",
            proof=evidence or None,
        )
    if confirmed:
        return ImpactResult(
            role=cat,
            impact="confirmed",
            severity=severity or "medium",
            summary=f"{cat.replace('_', ' ').title()} issue actively confirmed with response evidence.",
            validation="confirmed",
            proof=evidence or None,
        )
    if verified and (severity or "info") in ("medium", "high", "critical"):
        return ImpactResult(
            role=cat,
            impact="possible",
            severity=severity,
            summary=f"{cat.replace('_', ' ').title()} signal verified enough for triage — confirm exploitability.",
            validation="active",
            proof=evidence or None,
        )
    return ImpactResult(
        role=cat or "finding",
        impact="informational" if (severity or "info") in ("info", "low") else "possible",
        severity=severity or "info",
        summary=f"{cat.replace('_', ' ').title()} observation — severity rises only after verification.",
        validation="unverified",
        proof=evidence or None,
    )


def assess_bot_management(detail: str, severity: str, evidence: str = "") -> ImpactResult:
    d = _detail_l(detail)
    if "gap" in d or "unchallenged" in d or "without a challenge" in d:
        return ImpactResult(
            role="hardening",
            impact="possible",
            severity=severity if severity in ("info", "low", "medium") else "medium",
            summary=(
                "Bot Manager is present but a meaningful share of automation completed without "
                "challenge — owners should tighten edge bot rules (network-side)."
            ),
            validation="confirmed",
            proof=evidence or None,
        )
    return ImpactResult(
        role="hardening",
        impact="informational",
        severity="info",
        summary="Akamai Bot Manager signals observed — inventory for owners; not a forge/bypass finding.",
        validation="confirmed",
        proof=evidence or None,
    )


def assess_file_metadata(detail: str, severity: str, evidence: str = "") -> ImpactResult:
    d = _detail_l(detail)
    if "gps" in d or "author" in d or "email" in d:
        return ImpactResult(
            role="file_metadata",
            impact="limited_impact",
            severity=severity or "low",
            summary="Embedded metadata may leak PII or internal details.",
            validation="confirmed",
            proof=evidence or None,
        )
    return ImpactResult(
        role="file_metadata",
        impact="informational",
        severity="info",
        summary="File metadata inventory.",
        validation="confirmed",
        proof=evidence or None,
    )


def assess_generic(category: str, detail: str, severity: str, evidence: str = "") -> ImpactResult:
    return ImpactResult(
        role=category or "finding",
        impact="possible",
        severity=severity or "info",
        summary="Finding recorded — review for real-world impact.",
        validation="unverified",
        proof=evidence or None,
    )


async def assess_finding(
    *,
    category: str,
    severity: str,
    detail: str,
    evidence: str = "",
    url: str = "",
    client: Any = None,
    validate_secrets_live: bool = False,
    cookies: Optional[Sequence[Dict[str, Any]]] = None,
    login_surfaces: Optional[Sequence[str]] = None,
    proof: Optional[Any] = None,
) -> ImpactResult:
    """Route a finding through the matching impact checker."""
    cat = (category or "").strip().lower()
    ev = evidence or ""

    if cat == "header_audit":
        return assess_header_audit(detail, severity)
    if cat == "authentication":
        return assess_authentication(detail, severity, ev)
    if cat == "secrets_exposure":
        if validate_secrets_live and ev:
            return await assess_secrets_live(
                label=detail,
                detail=detail,
                severity=severity,
                evidence=ev,
                client=client,
            )
        return assess_secrets_static(detail, severity, ev)
    if cat == "cors":
        return assess_cors(
            detail,
            severity,
            url=url,
            cookies=cookies,
            login_surfaces=login_surfaces,
            proof=proof,
        )
    if cat == "sensitive_path":
        return assess_sensitive_path(detail, severity, ev)
    if cat == "mixed_content":
        return assess_mixed_content(detail, severity)
    if cat == "open_redirect":
        return assess_open_redirect(detail, severity)
    if cat in ("sql_injection", "xss", "ssrf", "directory_traversal", "path_traversal", "rce", "form_probe", "idor"):
        return assess_active_vuln(cat, detail, severity)
    if cat == "csrf":
        return assess_csrf(detail, severity)
    if cat == "api_leak":
        return assess_api_leak(detail, severity)
    if cat == "http_methods":
        return assess_http_methods(detail, severity)
    if cat == "file_upload":
        return assess_file_upload(detail, severity)
    if cat == "well_known":
        return assess_well_known(detail, severity, ev)
    if cat == "cloud_url":
        return assess_cloud_url(detail, severity)
    if cat == "cloud":
        return assess_tier_category(cat, detail, severity, ev)
    if cat == "bot_management":
        return assess_bot_management(detail, severity, ev)
    if cat == "file_metadata":
        return assess_file_metadata(detail, severity, ev)
    if cat in (
        "oauth",
        "jwt",
        "graphql",
        "mass_assignment",
        "rate_limit",
        "business_logic",
        "js_intel",
        "websocket",
    ):
        return assess_tier_category(cat, detail, severity, ev)

    return assess_generic(cat, detail, severity, ev)


def apply_impact_to_finding(
    category: str,
    severity: str,
    detail: str,
    evidence: Optional[str],
    impact: ImpactResult,
) -> Dict[str, Any]:
    """Build kwargs / row fields after impact assessment."""
    out_detail = detail or ""
    if impact.detail_suffix and impact.detail_suffix not in out_detail:
        out_detail = f"{out_detail}{impact.detail_suffix}"
    if impact.summary and "Impact:" not in out_detail:
        out_detail = f"{out_detail} Impact: {impact.impact}."
    if impact.issues:
        note = " Cookie/endpoint context: " + "; ".join(impact.issues[:3]) + "."
        if note.strip() not in out_detail:
            out_detail = f"{out_detail}{note}"
    from report_status import assessment_state_for_finding

    sev_out = impact.severity or severity
    return {
        "category": category,
        "severity": sev_out,
        "detail": out_detail,
        "evidence": evidence,
        "impact": impact.impact,
        "role": impact.role,
        "validation": impact.validation,
        "impact_summary": impact.summary,
        "suppress": impact.suppress,
        "proof": impact.proof,
        "assessment_state": assessment_state_for_finding(
            category=category,
            severity=sev_out or "",
            validation=impact.validation,
            impact=impact.impact,
            detail=out_detail,
        ),
    }


def impact_badge(impact: str, validation: str = "") -> str:
    """Short label for UI/reports."""
    parts = [impact or "possible"]
    if validation and validation not in ("n/a", ""):
        parts.append(validation)
    return " / ".join(parts)
