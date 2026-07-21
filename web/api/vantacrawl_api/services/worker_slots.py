"""Pure slot policy for concurrent scan workers (no I/O)."""

from __future__ import annotations

from typing import Dict, Tuple


def can_start_job(
    user_id: str,
    *,
    active_job_count: int,
    active_by_user: Dict[str, int],
    max_concurrent: int,
    max_per_user: int,
) -> Tuple[bool, str]:
    """Decide whether a popped job may occupy a worker slot now."""
    if active_job_count >= max_concurrent:
        return False, "global_full"
    if user_id and active_by_user.get(user_id, 0) >= max_per_user:
        return False, "user_full"
    return True, "ok"
