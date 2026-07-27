"""Cloud/exposure/misc protocol: .env, IMDS flavors, Elasticsearch, method override, cache deception."""

from __future__ import annotations

import html
from typing import Dict

from http_util import json_bytes, page, send
from registry import register


@register(
    "/.env",
    title="Exposed .env file",
    family="dotenv",
    expected="dotenv secrets in HTTP response",
    tags=["passive", "secrets"],
    linked=True,
)
def dotenv_file(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    text = (
        "APP_ENV=production\n"
        "DATABASE_URL=postgres://app:SuperSecretDbPass@db:5432/horizon\n"
        "AWS_ACCESS_KEY_ID=AKIAPLAYGROUNDENV\n"
        "AWS_SECRET_ACCESS_KEY=env/secret/playground/notreal\n"
        "STRIPE_SECRET_KEY=sk_live_playgroundenv\n"
    )
    send(
        handler,
        200,
        text.encode(),
        headers={"Content-Type": "text/plain; charset=utf-8"},
        head_only=head_only,
    )


@register(
    "/.git/config",
    title="Exposed .git/config",
    family="git",
    expected="git config disclosure",
    tags=["passive"],
)
def git_config(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    text = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/horizon/catalog.git\n"
    send(handler, 200, text.encode(), headers={"Content-Type": "text/plain"}, head_only=head_only)


@register(
    "/server-status",
    title="Apache server-status",
    family="server_status",
    expected="mod_status style process list",
    tags=["passive"],
)
def server_status(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    body = page(
        "Apache Status",
        "<pre>Server Version: Apache/2.4.49\nServer Built: playground\n"
        "Current Time: Mon Jul 27 12:00:00\n"
        "CPU Usage: 12%\n"
        "1 requests currently being processed\n"
        "GET /admin/users HTTP/1.1</pre>",
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/_cat/indices",
    title="Elasticsearch unauthenticated",
    family="elasticsearch",
    expected="open Elastic/_cat endpoint",
    tags=["passive"],
)
def elastic_cat(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    text = "yellow open customers 1 1 10000 0 12mb 12mb\nyellow open orders 1 1 5000 0 8mb 8mb\n"
    send(handler, 200, text.encode(), headers={"Content-Type": "text/plain"}, head_only=head_only)


@register(
    "/redis/info",
    title="Redis INFO exposure tease",
    family="redis",
    expected="redis info leaked via debug proxy",
    tags=["passive"],
)
def redis_info(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    text = "# Server\nredis_version:6.2.6\n# Keyspace\ndb0:keys=42,expires=1\nrequirepass:playground-redis\n"
    send(handler, 200, page("Redis INFO", f"<pre>{html.escape(text)}</pre>"), head_only=head_only)


@register(
    "/meta/azure",
    title="Azure IMDS tease",
    family="ssrf",
    expected="Azure metadata path pattern",
    tags=["active"],
)
def meta_azure(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    data = {
        "compute": {"name": "horizon-vm", "subscriptionId": "00000000-playground"},
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.azure_playground",
    }
    send(handler, 200, json_bytes(data), headers={"Content-Type": "application/json"}, head_only=head_only)


@register(
    "/meta/gcp",
    title="GCP metadata tease",
    family="ssrf",
    expected="GCP metadata service path pattern",
    tags=["active"],
)
def meta_gcp(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    text = "horizon-sa@playground.iam.gserviceaccount.com\n"
    send(handler, 200, text.encode(), headers={"Content-Type": "text/plain", "Metadata-Flavor": "Google"}, head_only=head_only)


@register(
    "/method/override",
    title="HTTP method override tunnel",
    family="method_override",
    expected="POST + X-HTTP-Method-Override performs DELETE",
    tags=["active", "post"],
)
def method_override(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    override = (
        handler.headers.get("X-HTTP-Method-Override")
        or handler.headers.get("X-Method-Override")
        or params.get("_method")
        or handler.command
    )
    if str(override).upper() == "DELETE":
        msg = "resource deleted via method override"
        status = 200
    else:
        msg = f"noop method={handler.command} override={override}"
        status = 200
    send(handler, status, page("Method override", f"<pre>{html.escape(msg)}</pre>"), head_only=head_only)


@register(
    "/cache/deception",
    title="Web cache deception path",
    family="cache",
    expected="non-cacheable account page with .css suffix may be stored",
    tags=["active"],
)
def cache_deception(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    # Path still handled by exact route; also register prefix style below
    body = page("Account", "<p>email: victim@horizon.local</p><p>session=secret-session-cookie-value</p>")
    send(
        handler,
        200,
        body,
        headers={"Cache-Control": "public, max-age=600", "Content-Type": "text/html"},
        head_only=head_only,
    )


@register(
    "/account/",
    title="Web cache deception prefix",
    family="cache",
    expected="/account/profile.css style path returns private HTML",
    tags=["active"],
    prefix=True,
    linked=False,
)
def cache_deception_prefix(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    path = handler.path.split("?", 1)[0]
    body = page("Account", f"<p>path={html.escape(path)}</p><p>email: victim@horizon.local</p>")
    send(
        handler,
        200,
        body,
        headers={"Cache-Control": "public, max-age=600"},
        head_only=head_only,
    )


@register(
    "/cors/jsonp-steal",
    title="JSON hijacking / array response",
    family="json_hijacking",
    expected="sensitive JSON array returned without protection",
    tags=["active"],
)
def json_hijack(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    data = '[{"email":"alice@horizon.local","role":"admin"},{"email":"bob@horizon.local","role":"user"}]'
    send(handler, 200, data.encode(), headers={"Content-Type": "application/json"}, head_only=head_only)


@register(
    "/websocket/cswh",
    title="Cross-site WebSocket hijacking tease",
    family="websocket",
    expected="WS endpoint trusts Origin reflection",
    tags=["active"],
)
def ws_cswh(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    origin = handler.headers.get("Origin", "*")
    body = page(
        "CSWH",
        f"<pre>Upgrade: websocket\nOrigin accepted: {html.escape(origin)}\n"
        "Sec-WebSocket-Protocol: session\nNo origin allowlist.</pre>",
    )
    send(handler, 200, body, headers={"Access-Control-Allow-Origin": origin}, head_only=head_only)


@register(
    "/put/upload",
    title="HTTP PUT verb upload",
    family="put_upload",
    expected="unauthenticated PUT writes content",
    tags=["active"],
    methods=("GET", "PUT", "POST"),
)
def put_upload(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    if handler.command == "PUT":
        msg = "PUT ok — content stored at /uploads/raw.bin"
        return send(handler, 201, page("PUT upload", f"<pre>{msg}</pre>"), head_only=head_only)
    body = page("PUT upload", "<p>Send PUT with body to store file (no auth).</p>")
    send(handler, 200, body, head_only=head_only)


@register(
    "/backup/www.zip",
    title="Full site ZIP backup",
    family="backup",
    expected="downloadable source/backup archive",
    tags=["passive"],
)
def backup_zip(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    # Minimal zip bytes (empty archive PK header)
    data = (
        b"PK\x05\x06" + b"\x00" * 18
        + b"# playground backup placeholder with AWS_SECRET_ACCESS_KEY=backupzip/notreal\n"
    )
    send(
        handler,
        200,
        data,
        headers={"Content-Type": "application/zip", "Content-Disposition": "attachment; filename=www.zip"},
        head_only=head_only,
    )


@register(
    "/wp-config.php.bak",
    title="WordPress config backup",
    family="backup",
    expected="wp-config credentials in .bak",
    tags=["passive", "secrets"],
)
def wp_config_bak(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    text = (
        "<?php\ndefine('DB_NAME', 'horizon');\ndefine('DB_USER', 'wp');\n"
        "define('DB_PASSWORD', 'wp-backup-secret');\ndefine('AUTH_KEY', 'playground-auth-key');\n"
    )
    send(handler, 200, text.encode(), headers={"Content-Type": "text/plain"}, head_only=head_only)


@register(
    "/debug/django",
    title="Django debug page",
    family="debug",
    expected="DEBUG=True style traceback with settings",
    tags=["passive"],
)
def django_debug(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    body = page(
        "DisallowedHost at /",
        "<pre>Django Version: 4.2.1\nException Type: DisallowedHost\n"
        "SECRET_KEY = 'django-insecure-playground-key'\n"
        "DATABASES = {'default': {'PASSWORD': 'django-db-pass'}}</pre>",
    )
    send(handler, 500, body, head_only=head_only)
