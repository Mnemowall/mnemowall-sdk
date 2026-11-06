"""Process-wide diagnostic counters read by ``mnemowall doctor`` (e.g. writes without a session)."""

from __future__ import annotations

import threading
from collections import Counter

_lock = threading.Lock()
_counts: Counter[str] = Counter()


def record(event: str, n: int = 1) -> None:
    with _lock:
        _counts[event] += n


def counters() -> dict[str, int]:
    with _lock:
        return dict(_counts)


def reset() -> None:
    with _lock:
        _counts.clear()
