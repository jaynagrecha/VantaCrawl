"""Production-neutral Phase-1 verification runtime.

Shared by the SaaS worker path and the Horizon benchmark. Contains no Horizon
routes, fixture IDs, or catalog assumptions.
"""

from verifiers.runtime.execution_plan import (
    ATTEMPTED,
    CandidateSurface,
    DependencyAvailability,
    MODE_EXCLUDED,
    PlanItem,
    build_execution_plan,
    normalize_family,
    plan_summary,
)
from verifiers.runtime.finalize import finalize_phase1_runtime
from verifiers.runtime.lifecycle import (
    OUTCOME_NONTERMINAL,
    OUTCOME_TERMINAL_CONFIRMED,
    OUTCOME_TERMINAL_INCONCLUSIVE,
    OUTCOME_TERMINAL_NEGATIVE,
    apply_probe_outcome,
    classify_lifecycle_outcome,
    compute_published_metrics,
    empty_lifecycle_row,
)

__all__ = [
    "ATTEMPTED",
    "CandidateSurface",
    "DependencyAvailability",
    "MODE_EXCLUDED",
    "OUTCOME_NONTERMINAL",
    "OUTCOME_TERMINAL_CONFIRMED",
    "OUTCOME_TERMINAL_INCONCLUSIVE",
    "OUTCOME_TERMINAL_NEGATIVE",
    "PlanItem",
    "apply_probe_outcome",
    "build_execution_plan",
    "classify_lifecycle_outcome",
    "compute_published_metrics",
    "empty_lifecycle_row",
    "finalize_phase1_runtime",
    "normalize_family",
    "plan_summary",
]
