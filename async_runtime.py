"""Helpers for cooperative pause / stop checks in async crawl paths."""

from __future__ import annotations

import inspect
from typing import Awaitable, Callable, Union

RunningFn = Callable[[], Union[bool, Awaitable[bool]]]


async def is_running(running: RunningFn) -> bool:
    """Await async running callables; support legacy sync ``() -> bool`` too."""
    result = running()
    if inspect.isawaitable(result):
        return bool(await result)
    return bool(result)
