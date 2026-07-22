"""Report / journal timestamps — IST primary, UTC alongside (no ambiguous labels).

Operators often run in India; journals historically labeled IST as ``time_utc``.
We keep IST as the primary human stamp and always pair it with a real UTC value
so duration math and stakeholder reports stay unambiguous.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

try:
    from zoneinfo import ZoneInfo

    _IST = ZoneInfo("Asia/Kolkata")
except Exception:  # pragma: no cover
    _IST = timezone(timedelta(hours=5, minutes=30))

_UTC = timezone.utc


def _dt(ts: Optional[float] = None) -> datetime:
    return datetime.fromtimestamp(float(ts if ts is not None else time.time()), tz=_UTC)


def format_ist(ts: Optional[float] = None, *, with_date: bool = True) -> str:
    dt = _dt(ts).astimezone(_IST)
    if with_date:
        return dt.strftime("%Y-%m-%d %H:%M:%S IST")
    return dt.strftime("%H:%M:%S IST")


def format_utc(ts: Optional[float] = None, *, with_date: bool = True) -> str:
    dt = _dt(ts)
    if with_date:
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    return dt.strftime("%H:%M:%S UTC")


def format_dual(ts: Optional[float] = None) -> str:
    """Primary IST with UTC in parentheses — for report headers and executive text."""
    return f"{format_ist(ts)} ({format_utc(ts)})"


def timestamp_fields(ts: Optional[float] = None) -> Dict[str, Any]:
    """Structured stamps for JSON / defense journals / snapshots."""
    unix = float(ts if ts is not None else time.time())
    return {
        "time_unix": unix,
        "time_ist": format_ist(unix, with_date=True),
        "time_utc": format_utc(unix, with_date=True),
        "time_display": format_dual(unix),
    }
