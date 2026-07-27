"""SQL injection sinks (simulated error / boolean differentials)."""

from __future__ import annotations

import html
from typing import Dict

from http_util import page, send
from registry import register


@register(
    "/sqli/error",
    title="SQLi error-based",
    family="sqli",
    expected="sql_injection differential_signal on id",
    tags=["active", "safe"],
    notes="Emits MySQL-style syntax errors when quotes/comments appear.",
)
def sqli_error(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    val = params.get("id", "1")
    if any(tok in val for tok in ("'", '"', "--", "/*", " OR ", " or ", " AND ", " and ")):
        text = (
            "You have an error in your SQL syntax; check the manual that corresponds "
            f"to your MySQL server version for the right syntax to use near '{val}' at line 1"
        )
    else:
        text = f"row id={val} name=widget price=9.99"
    send(handler, 200, page("SQLi error", f"<pre>{html.escape(text)}</pre>"), head_only=head_only)


@register(
    "/sqli/search",
    title="SQLi search append",
    family="sqli",
    expected="sql_injection differential on q",
    tags=["active", "safe"],
)
def sqli_search(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    q = params.get("q", "")
    if "'" in q or '"' in q or "--" in q:
        text = f"SQLSTATE[42000]: Syntax error near '{q}'"
    else:
        text = f"Found 3 results for {q}" if q else "Enter a search term"
    send(handler, 200, page("SQLi search", f"<pre>{html.escape(text)}</pre>"), head_only=head_only)


@register(
    "/sqli/safe",
    title="SQLi safe control",
    family="sqli",
    expected="no sql_injection confirmation",
    tags=["control"],
    notes="Identical response regardless of payload — negative control.",
)
def sqli_safe(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    send(handler, 200, page("SQLi safe", "<pre>catalog entry</pre>"), head_only=head_only)
