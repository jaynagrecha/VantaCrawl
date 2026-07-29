"""Neutral production policy helpers (no target-lab fixture coupling)."""

from __future__ import annotations

from verifiers.policy.catalog_inventory import (
    catalog_entry_demotion_reason,
    inventory_eligible_from_catalog_entry,
)

__all__ = [
    "catalog_entry_demotion_reason",
    "inventory_eligible_from_catalog_entry",
]
