"""RCE-style confirmation sinks (simulated — no real shell)."""

from __future__ import annotations

import html
import re
from typing import Dict

from http_util import page, send
from registry import register


@register(
    "/rce/arith",
    title="RCE arithmetic / marker echo",
    family="rce",
    expected="rce confirmed on cmd",
    tags=["active", "safe"],
    notes="Evaluates expr a+b and echoes VC_RCE_* markers from printf/echo style payloads.",
)
def rce_arith(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    cmd = params.get("cmd", "")
    m = re.search(r"expr\s+(\d+)\s*\+\s*(\d+)", cmd)
    if m:
        text = f"value={int(m.group(1)) + int(m.group(2))}"
    else:
        m2 = re.search(r"(VC_RCE_[0-9a-fA-F]+)", cmd)
        if m2 and ("printf" in cmd or "echo" in cmd):
            text = f"output:\n{m2.group(1)}\ndone"
        else:
            text = "ok"
    send(handler, 200, page("RCE arith", f"<pre>{html.escape(text)}</pre>"), head_only=head_only)


@register(
    "/rce/reflect",
    title="RCE reflection-only",
    family="rce",
    expected="no rce confirmation",
    tags=["control"],
)
def rce_reflect(handler, params: Dict[str, str], *, head_only: bool = False) -> None:
    cmd = params.get("cmd", "")
    send(handler, 200, page("RCE reflect", f"<pre>cmd={html.escape(cmd)}</pre>"), head_only=head_only)
