"""Browser-dependent limitations for DOM-clobber verification."""

from __future__ import annotations

LIMITATIONS = [
    "Named-property clobber semantics differ across Chrome, Firefox, and Safari.",
    "Nested HTMLFormElement named-property collections are browser- and version-dependent.",
    "CSP script-src/default-src may block proof script execution after script.src assignment.",
    "Closed Shadow DOM and some custom elements hide live injection from inventory.",
    "Static script analysis misses obfuscated, eval-built, or WASM-only property reads.",
    "Stored / multi-step render sinks require a later crawl of the rendering URL.",
    "Without callback_base/proof service, Extended/Lab cannot mint scanner-owned proof URLs.",
    "Safe mode never executes proof JavaScript by design.",
    "Request initiator stacks from CDP are best-effort and may be unavailable.",
    "iframe sandbox / COOP / COEP can prevent cross-origin proof script effects.",
]


def limitations_list() -> list:
    return list(LIMITATIONS)
