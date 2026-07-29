"""Dynamic DOM-clobber source-to-sink verification package."""

from __future__ import annotations

from dom_clobber.contract import (
    CONFIRMED_VULN_STATES,
    STATE_BLOCKED_BY_CSP,
    STATE_BROWSER_EXECUTION_CONFIRMED,
    STATE_CLOBBER_WITHOUT_SINK,
    STATE_CLOBBERED_VALUE_CONSUMED,
    STATE_CONTROLLED_REQUEST_CONFIRMED,
    STATE_HTML_INJECTION_CONFIRMED,
    STATE_INCONCLUSIVE,
    STATE_NAMED_PROPERTY_CLOBBERED,
    STATE_NEGATIVE,
    STATE_REFLECTED_ONLY,
    STATE_SINK_CONTEXT_CANDIDATE,
)
from dom_clobber.limitations import limitations_list
from dom_clobber.verify import verify_dom_clobber_on_url

CLAIM = (
    "Dynamic DOM-clobber source-to-sink verification for supported "
    "browser and injection contexts."
)

__all__ = [
    "CLAIM",
    "CONFIRMED_VULN_STATES",
    "STATE_BLOCKED_BY_CSP",
    "STATE_BROWSER_EXECUTION_CONFIRMED",
    "STATE_CLOBBER_WITHOUT_SINK",
    "STATE_CLOBBERED_VALUE_CONSUMED",
    "STATE_CONTROLLED_REQUEST_CONFIRMED",
    "STATE_HTML_INJECTION_CONFIRMED",
    "STATE_INCONCLUSIVE",
    "STATE_NAMED_PROPERTY_CLOBBERED",
    "STATE_NEGATIVE",
    "STATE_REFLECTED_ONLY",
    "STATE_SINK_CONTEXT_CANDIDATE",
    "limitations_list",
    "verify_dom_clobber_on_url",
]
