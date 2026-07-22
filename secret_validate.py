"""Read-only live checks for discovered credentials (authorized lab use only).

Uses vendor identity / metadata endpoints — never creates, updates, or deletes resources.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import Any, Optional

import httpx

log = logging.getLogger("vantacrawl.secret_validate")

_TIMEOUT = 8.0


@dataclass
class ValidationResult:
    status: str  # active | inactive | invalid | unknown | skipped | error
    summary: str

    @property
    def is_active(self) -> bool:
        return self.status == "active"


def _result(status: str, summary: str) -> ValidationResult:
    return ValidationResult(status=status, summary=summary)


async def validate_secret(label: str, value: str, *, client: Any = None) -> ValidationResult:
    """Probe whether a credential appears active. Best-effort; never raises."""
    label_l = (label or "").lower()
    token = (value or "").strip()
    if not token or len(token) < 8:
        return _result("skipped", "value too short to validate")

    owns_client = client is None
    http = client
    try:
        if owns_client:
            http = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True)
        assert http is not None

        # Prefix / label routing — read-only identity endpoints only
        if token.startswith("AKIA") or token.startswith("ASIA") or "aws access key" in label_l:
            return _result(
                "unknown",
                "AWS Access Key ID alone cannot be validated without the matching Secret Access Key",
            )
        if token.startswith("sk_live_") or token.startswith("rk_live_") or (
            "stripe" in label_l and token.startswith("sk_")
        ):
            return await _stripe(http, token)
        if token.startswith("sk-") or "openai" in label_l:
            return await _openai(http, token)
        if token.startswith(("ghp_", "gho_", "ghu_", "github_pat_")) or "github" in label_l:
            return await _github(http, token)
        if token.startswith("glpat-") or "gitlab" in label_l:
            return await _gitlab(http, token)
        if token.startswith("xox") or "slack" in label_l:
            return await _slack(http, token)
        if token.startswith("SG.") or "sendgrid" in label_l:
            return await _sendgrid(http, token)
        if "virustotal" in label_l or "virus total" in label_l:
            return await _virustotal(http, token)
        if "shodan" in label_l:
            return await _shodan(http, token)
        if token.startswith("AIza") or "google" in label_l:
            return await _google_api_key(http, token)
        if "twilio" in label_l and len(token) == 32:
            return _result("unknown", "Twilio Auth Token needs Account SID for a live check")
        if token.startswith("npm_") or "npm" in label_l:
            return await _npm(http, token)

        return _result(
            "skipped",
            f"no safe read-only validator for '{label or 'credential'}' — treated as unverified",
        )
    except Exception as exc:
        log.debug("validate_secret failed: %s", exc, exc_info=True)
        return _result("error", f"live check error: {exc}")
    finally:
        if owns_client and http is not None:
            try:
                await http.aclose()
            except Exception:
                pass


async def _stripe(http, token: str) -> ValidationResult:
    resp = await http.get(
        "https://api.stripe.com/v1/balance",
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp.status_code == 200:
        return _result("active", "Stripe accepted key (balance readable) — likely live production credential")
    if resp.status_code in (401, 403):
        return _result("invalid", f"Stripe rejected key (HTTP {resp.status_code})")
    return _result("unknown", f"Stripe returned HTTP {resp.status_code}")


async def _openai(http, token: str) -> ValidationResult:
    resp = await http.get(
        "https://api.openai.com/v1/models",
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp.status_code == 200:
        return _result("active", "OpenAI accepted key (models list) — active credential")
    if resp.status_code in (401, 403):
        return _result("invalid", f"OpenAI rejected key (HTTP {resp.status_code})")
    return _result("unknown", f"OpenAI returned HTTP {resp.status_code}")


async def _github(http, token: str) -> ValidationResult:
    resp = await http.get(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "VantaCrawl-SecretCheck",
        },
    )
    if resp.status_code == 200:
        login = ""
        try:
            login = str((resp.json() or {}).get("login") or "")
        except Exception:
            pass
        who = f" as @{login}" if login else ""
        return _result("active", f"GitHub accepted token{who} — active credential")
    if resp.status_code in (401, 403):
        return _result("invalid", f"GitHub rejected token (HTTP {resp.status_code})")
    return _result("unknown", f"GitHub returned HTTP {resp.status_code}")


async def _gitlab(http, token: str) -> ValidationResult:
    resp = await http.get(
        "https://gitlab.com/api/v4/user",
        headers={"PRIVATE-TOKEN": token},
    )
    if resp.status_code == 200:
        return _result("active", "GitLab accepted token — active credential")
    if resp.status_code in (401, 403):
        return _result("invalid", f"GitLab rejected token (HTTP {resp.status_code})")
    return _result("unknown", f"GitLab returned HTTP {resp.status_code}")


async def _slack(http, token: str) -> ValidationResult:
    resp = await http.get(
        "https://slack.com/api/auth.test",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        data = resp.json() or {}
    except Exception:
        data = {}
    if data.get("ok"):
        team = data.get("team") or data.get("user") or ""
        extra = f" ({team})" if team else ""
        return _result("active", f"Slack auth.test ok{extra} — active credential")
    if resp.status_code in (401, 403) or data.get("error") in ("invalid_auth", "not_authed", "token_revoked"):
        return _result("invalid", f"Slack rejected token ({data.get('error') or resp.status_code})")
    return _result("unknown", f"Slack returned HTTP {resp.status_code}")


async def _sendgrid(http, token: str) -> ValidationResult:
    resp = await http.get(
        "https://api.sendgrid.com/v3/user/profile",
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp.status_code == 200:
        return _result("active", "SendGrid accepted key — active credential")
    if resp.status_code in (401, 403):
        return _result("invalid", f"SendGrid rejected key (HTTP {resp.status_code})")
    return _result("unknown", f"SendGrid returned HTTP {resp.status_code}")


async def _virustotal(http, token: str) -> ValidationResult:
    resp = await http.get(
        "https://www.virustotal.com/api/v3/users/me",
        headers={"x-apikey": token},
    )
    if resp.status_code == 200:
        return _result("active", "VirusTotal accepted API key — active credential")
    if resp.status_code in (401, 403):
        return _result("invalid", f"VirusTotal rejected key (HTTP {resp.status_code})")
    return _result("unknown", f"VirusTotal returned HTTP {resp.status_code}")


async def _shodan(http, token: str) -> ValidationResult:
    resp = await http.get(f"https://api.shodan.io/api-info?key={token}")
    if resp.status_code == 200:
        return _result("active", "Shodan accepted API key — active credential")
    if resp.status_code in (401, 403):
        return _result("invalid", f"Shodan rejected key (HTTP {resp.status_code})")
    return _result("unknown", f"Shodan returned HTTP {resp.status_code}")


async def _google_api_key(http, token: str) -> ValidationResult:
    # Minimal metadata call; many keys are restricted by API/referrer so 403 ≠ dead key
    resp = await http.get(
        "https://www.googleapis.com/oauth2/v1/tokeninfo",
        params={"access_token": token},
    )
    # tokeninfo is for OAuth access tokens; for API keys try a light discovery call
    if resp.status_code == 200:
        return _result("active", "Google tokeninfo accepted value — appears active")
    resp2 = await http.get(
        "https://maps.googleapis.com/maps/api/geocode/json",
        params={"address": "test", "key": token},
    )
    try:
        data = resp2.json() or {}
    except Exception:
        data = {}
    status = str(data.get("status") or "")
    if status == "OK" or status == "ZERO_RESULTS":
        return _result("active", "Google Maps API key accepted — active (possibly production)")
    err = str(data.get("error_message") or "")
    if status in ("REQUEST_DENIED", "INVALID_REQUEST"):
        # Could be referrer/API-restricted but still a real browser key
        msg = err or status
        low = msg.lower()
        if "invalid" in low and "referer" not in low and "referrer" not in low:
            if "not authorized" not in low and "not permitted" not in low:
                return _result("invalid", f"Google rejected key ({msg[:120]})")
        return _result(
            "unknown",
            f"Google key present but restricted ({msg[:120]})",
        )
    if resp2.status_code in (400, 403):
        return _result(
            "unknown",
            f"Google returned HTTP {resp2.status_code} — key may be restricted "
            f"(referrer/API allow-list)",
        )
    return _result("unknown", f"Google returned status={status or resp2.status_code}")


async def _npm(http, token: str) -> ValidationResult:
    resp = await http.get(
        "https://registry.npmjs.org/-/whoami",
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp.status_code == 200:
        return _result("active", "npm accepted token — active credential")
    if resp.status_code in (401, 403):
        return _result("invalid", f"npm rejected token (HTTP {resp.status_code})")
    return _result("unknown", f"npm returned HTTP {resp.status_code}")


def format_validation_suffix(result: Optional[ValidationResult]) -> str:
    if result is None:
        return ""
    tag = {
        "active": "ACTIVE",
        "invalid": "INVALID",
        "inactive": "INACTIVE",
        "unknown": "UNVERIFIED",
        "skipped": "UNCHECKED",
        "error": "CHECK_ERROR",
    }.get(result.status, result.status.upper())
    return f" [live: {tag} — {result.summary}]"
