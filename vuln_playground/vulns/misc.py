"""Info leak, headers, weak auth, upload, XXE-ish, hidden paths."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Dict

from http_util import json_bytes, page, send
from registry import register

ROOT = Path(__file__).resolve().parents[1]
SECRETS = ROOT / "fixtures" / "fake_credentials.env.example"


@register(
    "/headers/verbose",
    title="Verbose / revealing headers",
    family="headers",
    expected="passive tech/fingerprint or info disclosure signals",
    tags=["passive"],
)
def headers_verbose(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    headers = {
        "Server": "Apache/2.4.49 (Unix) OpenSSL/1.0.2k PHP/5.6.40",
        "X-Powered-By": "PHP/5.6.40",
        "X-Debug-Token": "playground-debug-token",
        "X-Backend-Server": "ip-10-0-0-5",
    }
    send(handler, 200, page("Verbose headers", "<p>legacy stack headers</p>"), headers=headers, head_only=head_only)


@register(
    "/leak/env",
    title="Env / secrets leak",
    family="info_leak",
    expected="secret / key finding from body",
    tags=["passive", "secrets"],
)
def leak_env(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    text = SECRETS.read_text(encoding="utf-8") if SECRETS.exists() else "AWS_ACCESS_KEY_ID=AKIAPLAYGROUND"
    # Serve as plain-ish HTML wrapping pre
    send(handler, 200, page("Env leak", f"<pre>{html.escape(text)}</pre>"), head_only=head_only)


@register(
    "/leak/stack",
    title="Stack trace dump",
    family="info_leak",
    expected="error disclosure / verbose exception",
    tags=["passive"],
)
def leak_stack(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    trace = (
        "Traceback (most recent call last):\n"
        '  File "/app/server.py", line 88, in handle\n'
        "    return db.query(user_input)\n"
        "psycopg2.errors.SyntaxError: password=playground-db-secret host=db.internal\n"
    )
    send(handler, 500, page("Boom", f"<pre>{html.escape(trace)}</pre>"), head_only=head_only)


@register(
    "/auth/login",
    title="Weak login (user=admin pass=admin)",
    family="auth",
    expected="weak auth / default creds signal if probed; form for crawl",
    tags=["active", "post"],
)
def auth_login(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    if handler.command == "GET" and not params.get("user"):
        body = page(
            "Login",
            '<form method="POST" action="/auth/login">'
            '<input name="user" value=""><input name="pass" type="password" value="">'
            '<button type="submit">Login</button></form>',
        )
        return send(handler, 200, body, head_only=head_only)
    user = params.get("user", "")
    password = params.get("pass", "") or params.get("password", "")
    if user == "admin" and password == "admin":
        headers = {"Set-Cookie": "session=admin-playground; Path=/"}
        return send(
            handler,
            200,
            page("Login OK", "<p>Welcome admin</p>"),
            headers=headers,
            head_only=head_only,
        )
    send(handler, 401, page("Login fail", "<p>Invalid credentials</p>"), head_only=head_only)


@register(
    "/upload",
    title="Unrestricted upload form",
    family="upload",
    expected="upload surface discovery; content echoed",
    tags=["passive", "post"],
)
def upload(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    if handler.command == "GET":
        body = page(
            "Upload",
            '<form method="POST" action="/upload" enctype="application/x-www-form-urlencoded">'
            '<input name="filename" value="shell.php">'
            '<textarea name="content"><?php echo 1; ?></textarea>'
            '<button type="submit">Upload</button></form>',
        )
        return send(handler, 200, body, head_only=head_only)
    name = params.get("filename", "file.txt")
    content = params.get("content", "")
    send(
        handler,
        200,
        page("Uploaded", f"<p>Saved {html.escape(name)}</p><pre>{html.escape(content[:500])}</pre>"),
        head_only=head_only,
    )


@register(
    "/xxe/parse",
    title="XXE-ish XML echo",
    family="xxe",
    expected="xxe/oob candidate when DOCTYPE/entity present (simulated)",
    tags=["active", "lab"],
    notes="Does not parse real XML entities; echoes ENTITY/SYSTEM markers for kit signals.",
)
def xxe_parse(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    xml = params.get("xml", "")
    if not xml and handler.command == "GET":
        body = page(
            "XXE parse",
            '<form method="POST" action="/xxe/parse">'
            '<textarea name="xml" rows="8" cols="60">'
            "&lt;?xml version=&quot;1.0&quot;?&gt;&lt;root&gt;test&lt;/root&gt;"
            "</textarea><button type=\"submit\">Parse</button></form>",
        )
        return send(handler, 200, body, head_only=head_only)
    if "ENTITY" in xml or "SYSTEM" in xml or "<!DOCTYPE" in xml:
        text = "parsed with external entity hooks enabled\n" + xml[:400]
    else:
        text = "parsed ok\n" + xml[:200]
    send(handler, 200, page("XXE result", f"<pre>{html.escape(text)}</pre>"), head_only=head_only)


@register(
    "/secret-admin-panel",
    title="Hidden admin panel",
    family="discovery",
    expected="enum / hidden directory discovery",
    tags=["enum"],
    linked=False,
)
def hidden_admin(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    send(
        handler,
        200,
        page("Secret admin", "<p>Internal admin panel (not linked from index).</p>"),
        head_only=head_only,
    )


@register(
    "/api/user",
    title="JSON API without auth",
    family="api",
    expected="unauthenticated API / PII exposure",
    tags=["passive", "api"],
)
def api_user(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    data = {
        "id": 1,
        "email": "victim@example.com",
        "ssn": "219-09-9999",
        "api_key": "pk_live_playground_example",
    }
    send(
        handler,
        200,
        json_bytes(data),
        headers={"Content-Type": "application/json"},
        head_only=head_only,
    )


@register(
    "/robots.txt",
    title="robots.txt",
    family="discovery",
    expected="disallow hints toward hidden paths",
    tags=["passive"],
    linked=False,
)
def robots(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    body = (
        b"User-agent: *\n"
        b"Disallow: /secret-admin-panel\n"
        b"Disallow: /leak/\n"
        b"Disallow: /actuator/\n"
        b"Disallow: /.git/\n"
        b"Disallow: /backup/\n"
        b"Disallow: /keys/\n"
        b"Disallow: /bac/\n"
    )
    send(handler, 200, body, headers={"Content-Type": "text/plain"}, head_only=head_only)
