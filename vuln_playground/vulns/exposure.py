"""Exposure: backups, source maps, actuators, keys, git, directory listing."""

from __future__ import annotations

import html
from typing import Dict

from http_util import json_bytes, page, send
from registry import register


@register(
    "/backup/site.sql",
    title="SQL dump backup exposed",
    family="backup",
    expected="database dump content publicly readable",
    tags=["passive", "enum"],
    linked=True,
)
def backup_sql(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    dump = (
        "-- MySQL dump\n"
        "CREATE TABLE users(id INT, email TEXT, password TEXT);\n"
        "INSERT INTO users VALUES (1,'admin@example.com','$2b$10$playgroundhashadmin');\n"
        "INSERT INTO users VALUES (2,'user@example.com','P@ssw0rd123!');\n"
    )
    send(handler, 200, dump.encode(), headers={"Content-Type": "application/sql"}, head_only=head_only)


@register(
    "/static/app.js.map",
    title="Source map exposure",
    family="sourcemap",
    expected="JS source map with original sources",
    tags=["passive"],
)
def sourcemap(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    data = {
        "version": 3,
        "file": "app.js",
        "sources": ["webpack:///src/secrets.ts", "webpack:///src/admin/Panel.tsx"],
        "sourcesContent": [
            'export const STRIPE_KEY = "sk_live_sourcemap_example_do_not_use";\n',
            "export function AdminPanel(){ return null }\n",
        ],
        "mappings": "AAAA",
    }
    send(handler, 200, json_bytes(data), headers={"Content-Type": "application/json"}, head_only=head_only)


@register(
    "/actuator/env",
    title="Spring Actuator env",
    family="actuator",
    expected="env endpoint leaks properties/secrets",
    tags=["passive", "enum"],
)
def actuator_env(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    data = {
        "activeProfiles": ["prod"],
        "propertySources": [
            {
                "name": "systemEnvironment",
                "properties": {
                    "DATABASE_PASSWORD": {"value": "ActuatorDBPassword!"},
                    "AWS_SECRET_ACCESS_KEY": {"value": "wJalrXUtnFEMI/K7MDENG/actuator"},
                },
            }
        ],
    }
    send(handler, 200, json_bytes(data), headers={"Content-Type": "application/json"}, head_only=head_only)


@register(
    "/.git/HEAD",
    title="Git metadata exposure",
    family="git",
    expected=".git/HEAD readable",
    tags=["passive", "enum"],
    linked=False,
)
def git_head(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    send(handler, 200, b"ref: refs/heads/main\n", headers={"Content-Type": "text/plain"}, head_only=head_only)


@register(
    "/.git/config",
    title="Git config exposure",
    family="git",
    expected=".git/config readable",
    tags=["passive", "enum"],
    linked=False,
)
def git_config(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    body = b"[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/acme/private-app.git\n"
    send(handler, 200, body, headers={"Content-Type": "text/plain"}, head_only=head_only)


@register(
    "/keys/private.pem",
    title="Private key file exposure",
    family="crypto",
    expected="PEM private key disclosed",
    tags=["passive"],
)
def private_pem(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/PLAYGROUNDONLYNOTREALKEY00000000\n"
        "AQABAoIBAQC7PLAYGROUND_PRIVATE_KEY_MATERIAL_NOT_REAL_000000000000\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    send(handler, 200, pem.encode(), headers={"Content-Type": "application/x-pem-file"}, head_only=head_only)


@register(
    "/config/firebase.json",
    title="Firebase config exposure",
    family="firebase",
    expected="apiKey / appId in client config",
    tags=["passive"],
)
def firebase_config(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    data = {
        "apiKey": "AIzaSyPlaygroundFirebaseExample000001",
        "authDomain": "playground.firebaseapp.com",
        "projectId": "playground-app",
        "storageBucket": "playground-app.appspot.com",
        "messagingSenderId": "123456789012",
        "appId": "1:123456789012:web:abcdef123456",
    }
    send(handler, 200, json_bytes(data), headers={"Content-Type": "application/json"}, head_only=head_only)


@register(
    "/listing",
    title="Directory listing",
    family="listing",
    expected="autoindex style file listing",
    tags=["passive"],
    prefix=True,
)
def listing(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    body = page(
        "Index of /listing/",
        "<ul>"
        "<li><a href='/listing/notes.txt'>notes.txt</a></li>"
        "<li><a href='/listing/backup.zip'>backup.zip</a></li>"
        "<li><a href='/backup/site.sql'>../backup/site.sql</a></li>"
        "</ul>",
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/listing/notes.txt",
    title="Listing notes file",
    family="listing",
    expected="readable file from listing",
    tags=["passive"],
    linked=False,
)
def listing_notes(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    send(handler, 200, b"todo: rotate prod vpn password Summer2024!\n", headers={"Content-Type": "text/plain"}, head_only=head_only)


@register(
    "/phpinfo",
    title="PHPInfo-style diagnostics",
    family="info_leak",
    expected="environment / path disclosure page",
    tags=["passive"],
)
def phpinfo(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    body = page(
        "phpinfo()",
        "<pre>PHP Version => 5.6.40\nDOCUMENT_ROOT => /var/www/html\n"
        "HOSTNAME => ip-10-0-1-22\nAWS_ACCESS_KEY_ID => AKIAPHPINFOPLAYGROUND\n"
        "DB_PASSWORD => PhpInfoSecret!</pre>",
    )
    send(handler, 200, body, head_only=head_only)


@register(
    "/k8s/token",
    title="K8s service account token tease",
    family="cloud",
    expected="service account JWT-like token leaked",
    tags=["passive"],
)
def k8s_token(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    tok = "eyJhbGciOiJSUzI1NiIsImtpZCI6InBsYXlncm91bmQifQ.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDp2YW50YSJ9.sig"
    send(handler, 200, page("Token", f"<pre>{html.escape(tok)}</pre>"), head_only=head_only)
