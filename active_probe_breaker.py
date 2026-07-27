"""Active-probe circuit breaker — pause probes on uniform edge/WAF blocking."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


_BLOCK = frozenset(
    {
        "edge_checkpoint",
        "generic_waf_deny",
        "rate_limit",
        "captcha",
        "origin_failure",
    }
)


@dataclass
class ActiveProbeBreaker:
    """Rolling window over active-probe response classifications."""

    window_size: int = 12
    block_ratio_threshold: float = 0.8
    min_samples: int = 8
    classifications: List[str] = field(default_factory=list)
    tripped: bool = False
    reason: str = ""

    def note(self, classification: str) -> bool:
        """Record classification; return True if breaker just tripped."""
        if self.tripped:
            return False
        c = (classification or "application_response").strip() or "application_response"
        self.classifications.append(c)
        if len(self.classifications) > self.window_size:
            self.classifications = self.classifications[-self.window_size :]
        if len(self.classifications) < self.min_samples:
            return False
        blocked = sum(1 for x in self.classifications if x in _BLOCK)
        ratio = blocked / float(len(self.classifications))
        if ratio >= self.block_ratio_threshold:
            # Prefer a specific dominant block class for the reason
            counts: Dict[str, int] = {}
            for x in self.classifications:
                if x in _BLOCK:
                    counts[x] = counts.get(x, 0) + 1
            top = max(counts, key=counts.get) if counts else "uniform_edge_checkpoint"
            self.tripped = True
            self.reason = top if top != "generic_waf_deny" else "uniform_waf_deny"
            if top == "edge_checkpoint":
                self.reason = "uniform_edge_checkpoint"
            elif top == "rate_limit":
                self.reason = "uniform_rate_limit"
            return True
        return False

    def snapshot(self) -> Dict[str, Any]:
        blocked = sum(1 for x in self.classifications if x in _BLOCK)
        n = len(self.classifications) or 1
        return {
            "tripped": self.tripped,
            "reason": self.reason,
            "samples": len(self.classifications),
            "block_ratio": round(blocked / float(n), 3),
            "window": list(self.classifications[-self.window_size :]),
        }


def stop_active_probes(stats: Any, *, reason: str, remaining: str = "inconclusive") -> None:
    """Mark scan-level pause so later pages skip active injection."""
    if stats is None:
        return
    try:
        stats.vuln_active_probe_paused = True
        stats.active_probe_breaker = {
            "tripped": True,
            "reason": reason,
            "remaining": remaining,
        }
    except Exception:
        pass
