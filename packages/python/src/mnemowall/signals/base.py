"""Signal result type. Results carry ids and identifier-shaped labels only, never content."""

from __future__ import annotations

import dataclasses
import re
from typing import Final

_LABEL: Final = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,63}")  # applied to our own constants only


@dataclasses.dataclass(frozen=True)
class SignalResult:
    """Outcome of one signal. ``risk`` is in [0, 1]; ``labels`` are safe to log."""

    id: str
    fired: bool
    risk: float = 0.0
    labels: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _LABEL.fullmatch(self.id):
            raise ValueError("signal id must be identifier-shaped")
        if not 0.0 <= self.risk <= 1.0:
            raise ValueError("risk must be within [0, 1]")
        if any(not _LABEL.fullmatch(lbl) for lbl in self.labels):
            raise ValueError("signal labels must be identifier-shaped (no content)")
