"""Content-aware validation for sensitive enum/crawl hits (cuts soft-404 FPs)."""

from __future__ import annotations

import re
from typing import Optional, Tuple
from urllib.parse import urlparse

GIT_PATH_RE = re.compile(r"(?i)/(?:\.git(?:/|$)|\.git/HEAD|\.git/config)")
ENV_PATH_RE = re.compile(r"(?i)/(?:\.env(?:\.[a-z0-9_-]+)?|env\.local)(?:$|\?)")
BACKUP_PATH_RE = re.compile(
    r"(?i)/(?:(?:backup|dump|site-backup|db-backup|www-backup)\.(?:zip|tar|gz|tgz|sql|bak|7z|rar)|"
    r"[^/]+\.(?:zip|tar|gz|tgz|sql|bak|7z|rar))$"
)
CONFIG_PATH_RE = re.compile(
    r"(?i)/(?:web\.config|wp-config\.php|config\.php|\.htpasswd|id_rsa)(?:$|\?)"
)
PHPINFO_PATH_RE = re.compile(r"(?i)/phpinfo(?:\.php)?(?:$|/|\?)")
AWS_PATH_RE = re.compile(r"(?i)/\.aws(?:/|$)")

GIT_HEAD_RE = re.compile(r"(?i)^ref:\s+refs/")
GIT_CONFIG_RE = re.compile(r"(?i)\[core\]|\[remote\s+\"origin\"\]")
ENV_LINE_RE = re.compile(r"(?im)^[A-Z][A-Z0-9_]{1,64}\s*=\s*.+$")
HTMLISH_RE = re.compile(r"(?i)<!doctype\s+html|<html[\s>]|<head[\s>]")
CONFIG_HINT_RE = re.compile(
    r"(?i)(DB_|password|connectionstring|<configuration|wp-settings|BEGIN (?:RSA |OPENSSH )?PRIVATE KEY)"
)
PHPINFO_BODY_RE = re.compile(r"(?i)(?:phpinfo\s*\(|PHP Version\s*\d|PHP Credits)")
AWS_CREDS_RE = re.compile(r"(?i)(?:\[default\]|aws_access_key_id|aws_secret_access_key)")


def classify_bucket_response(
    status: int, body: bytes | str, *, provider: str = "s3"
) -> Tuple[bool, str]:
    """Return (is_real_bucket, note). Filters NoSuchBucket-style 403s."""
    text = (
        body.decode("utf-8", errors="replace")
        if isinstance(body, (bytes, bytearray))
        else (body or "")
    )
    lowered = text.lower()
    if status in (200, 204):
        return True, f"{provider} listing/access HTTP {status}"
    if status in (301, 302, 307, 308):
        return True, f"{provider} redirect HTTP {status} (bucket likely exists)"
    if status == 403:
        if "nosuchbucket" in lowered or "the specified bucket does not exist" in lowered:
            return False, "NoSuchBucket"
        if "nosuchkey" in lowered:
            return False, "NoSuchKey"
        if "accessdenied" in lowered or "access denied" in lowered or "forbidden" in lowered:
            return True, f"{provider} exists but listing denied (403 AccessDenied)"
        return True, f"{provider} HTTP 403 (ambiguous; may exist)"
    return False, f"ignored HTTP {status}"


def needs_content_gate(url: str) -> bool:
    """True when a sensitive-path finding must be body-proven before emit."""
    path = urlparse(url).path or ""
    return bool(
        GIT_PATH_RE.search(path)
        or ENV_PATH_RE.search(path)
        or BACKUP_PATH_RE.search(path)
        or CONFIG_PATH_RE.search(path)
        or PHPINFO_PATH_RE.search(path)
        or AWS_PATH_RE.search(path)
    )


def validate_sensitive_content(
    url: str,
    *,
    status: int,
    body: bytes | str,
    content_type: str = "",
) -> Optional[str]:
    """
    For gated sensitive paths, require body proof.
    Returns confirmation detail, "ok" if no gate applies, or None to reject as FP.
    """
    path = urlparse(url).path or ""
    if isinstance(body, (bytes, bytearray)):
        raw = bytes(body)
        text = raw.decode("utf-8", errors="replace")
    else:
        text = body or ""
        raw = text.encode("latin-1", errors="ignore")

    if not needs_content_gate(url):
        return "ok"

    ct = (content_type or "").lower()
    looks_html = "text/html" in ct or bool(HTMLISH_RE.search(text[:2000]))

    if GIT_PATH_RE.search(path):
        if status >= 500:
            return None
        if GIT_HEAD_RE.search(text[:200]) or GIT_CONFIG_RE.search(text[:4000]):
            return "Confirmed .git content in response body"
        if looks_html or status == 404:
            return None
        if status in (200, 401, 403) and text.strip() and not looks_html:
            return f".git path returned non-HTML HTTP {status} (likely real)"
        return None

    if ENV_PATH_RE.search(path):
        env_hits = ENV_LINE_RE.findall(text[:8000])
        if len(env_hits) >= 2:
            return f"Confirmed .env-style content ({len(env_hits)} KEY= lines)"
        if looks_html or status == 404:
            return None
        if status in (200, 401, 403) and text.strip() and not looks_html:
            return f".env path returned non-HTML HTTP {status}"
        return None

    if BACKUP_PATH_RE.search(path):
        if raw[:2] == b"PK" or raw[:2] == b"\x1f\x8b" or raw[:6] == b"7z\xbc\xaf'\x1c":
            return "Confirmed archive magic bytes"
        if text.startswith("SQLite format"):
            return "Confirmed SQLite database header"
        if looks_html and status == 200 and HTMLISH_RE.search(text[:1500]):
            return None
        if status in (200, 401, 403) and not looks_html and len(raw) > 64:
            return f"Backup-like path returned non-HTML HTTP {status} ({len(raw)} bytes)"
        return None

    if CONFIG_PATH_RE.search(path):
        if looks_html and status == 404:
            return None
        if CONFIG_HINT_RE.search(text[:6000]):
            return "Confirmed config-like content in response"
        if status in (200, 401, 403) and text.strip() and not looks_html:
            return f"Config path returned non-HTML HTTP {status}"
        return None

    if PHPINFO_PATH_RE.search(path):
        if PHPINFO_BODY_RE.search(text[:12000]):
            return "Confirmed phpinfo() output in response body"
        return None

    if AWS_PATH_RE.search(path):
        if AWS_CREDS_RE.search(text[:8000]):
            return "Confirmed AWS credentials/config content"
        if looks_html or status == 404:
            return None
        if status in (200, 401, 403) and text.strip() and not looks_html:
            return f".aws path returned non-HTML HTTP {status}"
        return None

    return "ok"
