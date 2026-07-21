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
    proof: Optional[str] = None
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
    if _HARDENING_HEADERS.search(d):
        return ImpactResult(
            role="hardening",
            impact="informational",
            severity=severity if severity in ("high", "medium") else "medium",
            summary="Missing transport/framing control — real hardening gap, not an active exploit by itself.",
            validation="confirmed",
        )
    if _INFO_HEADERS.search(d):
        return ImpactResult(
            role="hygiene",
            impact="informational",
            severity="info",
            summary="Header hygiene / disclosure — low direct exploit impact.",
            validation="confirmed",
        )
    return ImpactResult(
        role="hardening",
        impact="informational",
        severity=severity or "low",
        summary="Security header finding — verify against your policy baseline.",
        validation="confirmed",
    )


def assess_authentication(detail: str, severity: str, evidence: str = "") -> ImpactResult:
    d = _detail_l(detail)
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
        return ImpactResult(
            role="cookie",
            impact="possible_credential",
            severity=severity or "low",
            summary="Opaque cookie may be a credential — verify Set-Cookie flags and purpose.",
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
    if "credentials or tokens appear in url" in d:
        return ImpactResult(
            role="credential_in_url",
            impact="stealable_credential",
            severity="critical",
            summary="Credentials in the URL can leak via logs, Referer, and history.",
            validation="confirmed",
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

    result = await validate_secret(typed, evidence or "", client=client)
    suffix = format_validation_suffix(result)

    if result.status == "active":
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
    if result.status == "invalid":
        return ImpactResult(
            role="credential",
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
        return ImpactResult(
            role="credential",
            impact="possible_credential",
            severity=severity or "high",
            summary=result.summary,
            validation="unverified" if result.status == "unknown" else "skipped",
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


def assess_cors(detail: str, severity: str) -> ImpactResult:
    d = _detail_l(detail)
    if "credential" in d:
        return ImpactResult(
            role="cors",
            impact="confirmed",
            severity=severity if severity in ("high", "critical") else "high",
            summary="CORS allows credentialed cross-origin reads — session theft / data exfil risk.",
            validation="confirmed",
        )
    return ImpactResult(
        role="cors",
        impact="possible",
        severity=severity or "medium",
        summary="CORS configuration may be overly open.",
        validation="confirmed",
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
    return ImpactResult(
        role="sensitive_file",
        impact="possible",
        severity=severity or "medium",
        summary="Sensitive path pattern matched — content not verified.",
        validation="unverified",
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
    return ImpactResult(
        role="mixed_content",
        impact="limited_impact",
        severity=severity or "low",
        summary="Mixed content detected (likely passive assets). Lower direct exploit impact than scripts.",
        validation="confirmed",
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
        severity=severity or "medium",
        summary="Off-site URL in a redirect-style parameter — verify allow-list behavior.",
        validation="unverified",
    )


def assess_active_vuln(category: str, detail: str, severity: str) -> ImpactResult:
    role = category or "vuln"
    if _is_active_confirmed(detail):
        return ImpactResult(
            role=role,
            impact="confirmed",
            severity=severity or "high",
            summary=f"{category} actively confirmed against a baseline response.",
            validation="confirmed",
        )
    return ImpactResult(
        role=role,
        impact="possible",
        severity=severity or "medium",
        summary=f"{category} heuristic hit — not actively confirmed.",
        validation="unverified",
    )


def assess_api_leak(detail: str, severity: str) -> ImpactResult:
    d = _detail_l(detail)
    if "graphql" in d and ("introspection" in d or "playground" in d):
        return ImpactResult(
            role="api_leak",
            impact="confirmed",
            severity=severity or "high",
            summary="GraphQL introspection/playground indicators on a GraphQL path.",
            validation="confirmed",
        )
    if "json field" in d and "secret" in d:
        return ImpactResult(
            role="api_leak",
            impact="possible_credential",
            severity=severity or "high",
            summary="JSON response field may expose a secret value.",
            validation="unverified",
        )
    return ImpactResult(
        role="api_leak",
        impact="possible",
        severity=severity or "medium",
        summary="Sensitive API/debug surface pattern — verify exposure is intentional.",
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
        impact="possible",
        severity=severity or "low",
        summary="Upload form surface detected — verify extension/MIME validation server-side.",
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
        return assess_cors(detail, severity)
    if cat == "sensitive_path":
        return assess_sensitive_path(detail, severity, ev)
    if cat == "mixed_content":
        return assess_mixed_content(detail, severity)
    if cat == "open_redirect":
        return assess_open_redirect(detail, severity)
    if cat in ("sql_injection", "xss", "ssrf", "directory_traversal", "path_traversal", "rce", "form_probe"):
        return assess_active_vuln(cat, detail, severity)
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
    if cat == "file_metadata":
        return assess_file_metadata(detail, severity, ev)

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
    return {
        "category": category,
        "severity": impact.severity or severity,
        "detail": out_detail,
        "evidence": evidence,
        "impact": impact.impact,
        "role": impact.role,
        "validation": impact.validation,
        "impact_summary": impact.summary,
        "suppress": impact.suppress,
        "proof": impact.proof,
    }


def impact_badge(impact: str, validation: str = "") -> str:
    """Short label for UI/reports."""
    parts = [impact or "possible"]
    if validation and validation not in ("n/a", ""):
        parts.append(validation)
    return " / ".join(parts)
