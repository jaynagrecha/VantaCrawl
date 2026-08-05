"""Write Phase-1 runtime artifacts into a report directory (redacted)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


_SECRET_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "cookie",
        "set-cookie",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "nonce_raw",
        "callback_secret",
    }
)


def _redact_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in _SECRET_KEYS or any(s in lk for s in ("password", "secret", "cookie", "token", "auth")):
                out[k] = "[REDACTED]"
            else:
                out[k] = _redact_obj(v)
        return out
    if isinstance(obj, list):
        return [_redact_obj(x) for x in obj]
    if isinstance(obj, str):
        # Strip obvious bearer/cookie fragments
        s = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+", r"\1[REDACTED]", obj)
        s = re.sub(r"(?i)(cookie[=:]\s*)[^;\s]+", r"\1[REDACTED]", s)
        return s
    return obj


def write_json(path: Path, payload: Any) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_redact_obj(payload), indent=2, default=str) + "\n", encoding="utf-8")
    return str(path)


def write_phase1_artifacts(
    report_dir: str,
    *,
    execution_plan: List[Dict[str, Any]],
    lifecycle_rows: List[Dict[str, Any]],
    published_metrics: Dict[str, Any],
    capability_inventory: Dict[str, Any],
    unresolved_gaps: List[Dict[str, Any]],
    evidence_provenance: List[Dict[str, Any]],
    runtime_status: Dict[str, Any],
    request_ledger: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, str]:
    root = Path(report_dir)
    paths = {
        "execution_plan": write_json(root / "execution_plan.json", execution_plan),
        "lifecycle_rows": write_json(root / "lifecycle_rows.json", lifecycle_rows),
        "lifecycle_summary": write_json(
            root / "lifecycle_summary.json",
            {
                "runtime_status": runtime_status,
                "row_count": len(lifecycle_rows),
                "outcome_counts": (published_metrics or {}).get("outcome_class_counts_attempted") or {},
                "published_metric_keys": sorted((published_metrics or {}).keys()),
            },
        ),
        "published_metrics": write_json(root / "published_metrics.json", published_metrics),
        "capability_inventory": write_json(root / "capability_inventory.json", capability_inventory),
        "unresolved_coverage_gaps": write_json(root / "unresolved_coverage_gaps.json", unresolved_gaps),
        "evidence_provenance": write_json(root / "evidence_provenance.json", evidence_provenance),
        "phase1_runtime_status": write_json(root / "phase1_runtime_status.json", runtime_status),
    }
    if request_ledger is not None:
        # Cap export size; full ledger may already live in the main JSON report.
        capped = list(request_ledger)[:8000]
        paths["request_ledger"] = write_json(root / "request_ledger.json", capped)
    return paths
