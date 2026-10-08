"""Concurrent twin-run guard (R3.5 resource safety)."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator

from twin.bounds import MAX_CONCURRENT_TWIN_RUNS
from twin.validate import TwinValidationError

_lock = threading.Lock()
_active = 0


def active_twin_runs() -> int:
    with _lock:
        return _active


@contextmanager
def acquire_twin_run_slot() -> Iterator[None]:
    """Prevent unlimited concurrent Twin experiment spawns."""
    global _active
    with _lock:
        if _active >= MAX_CONCURRENT_TWIN_RUNS:
            raise TwinValidationError(
                f"concurrent twin run limit exceeded "
                f"(max={MAX_CONCURRENT_TWIN_RUNS}, active={_active})"
            )
        _active += 1
    try:
        yield
    finally:
        with _lock:
            _active = max(0, _active - 1)


def reset_twin_run_slots_for_tests() -> None:
    """Test-only reset."""
    global _active
    with _lock:
        _active = 0
