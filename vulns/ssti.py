"""SSTI evaluation vs reflection controls."""

from __future__ import annotations

import html
import re
from typing import Dict

from http_util import page, send
from registry import register


def _eval_ssti(name: str) -> str:
    patterns = [
        r"\{\{(\d+)\s*\+\s*(\d+)\}\}",
        r"\$\{(\d+)\s*\+\s*(\d+)\}",
        r"#\{(\d+)\s*\+\s*(\d+)\}",
        r"<%=\s*(\d+)\s*\+\s*(\d+)\s*%>",
    ]
    for pat in patterns:
        m = re.search(pat, name)
        if m:
            return str(int(m.group(1)) + int(m.group(2)))
    return name


@register(
    "/ssti/eval",
    title="SSTI evaluation",
    family="ssti",
    expected="ssti confirmed on name",
    tags=["active", "safe"],
)
def ssti_eval(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    name = params.get("name", "World")
    out = _eval_ssti(name)
    send(handler, 200, page("SSTI eval", f"<p>Hello {html.escape(out)}</p>"), head_only=head_only)


@register(
    "/ssti/reflect",
    title="SSTI reflection-only",
    family="ssti",
    expected="no ssti confirmation",
    tags=["control"],
)
def ssti_reflect(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    name = params.get("name", "World")
    send(handler, 200, page("SSTI reflect", f"<p>Hello {html.escape(name)}</p>"), head_only=head_only)
