"""Public verifiers package API."""

from __future__ import annotations

from verifiers.contract import PRODUCT_CLAIM, CONFIRMED_ACTIVE_STATES, map_fixture_status
from verifiers.registry import (
    all_verifiers,
    capability_registry,
    get_verifier,
    supported_families,
)

# Load Phase-1 registrations
from verifiers import phase1 as _phase1  # noqa: F401
# Load Phase-2 CORS verifier registration
from verifiers import cors as _cors  # noqa: F401

__all__ = [
    "PRODUCT_CLAIM",
    "CONFIRMED_ACTIVE_STATES",
    "map_fixture_status",
    "all_verifiers",
    "capability_registry",
    "get_verifier",
    "supported_families",
]
