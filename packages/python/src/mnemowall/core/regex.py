"""The only regex entry point for content checks: RE2 (linear time, no backtracking).

Python's ``re`` backtracks, so attacker-controlled memory content could trigger catastrophic
runtimes (ReDoS). Every pattern that touches content must be compiled here. Features that need
backtracking (backreferences, lookaround) are rejected, never silently emulated (ADR-0017).
"""

from __future__ import annotations

from typing import Any, Final

import re2

ENGINE: Final = "re2"
_MAX_MEM: Final = 8 << 20  # 8 MiB per compiled program


class RegexError(ValueError):
    """Pattern not supported by RE2 (for example, it needs backtracking)."""


def compile(pattern: str) -> Any:  # noqa: A001 - mirrors re.compile on purpose
    """Compile ``pattern`` with RE2. Raises :class:`RegexError` for unsupported syntax."""
    options = re2.Options()
    options.max_mem = _MAX_MEM
    try:
        return re2.compile(pattern, options)
    except re2.error as exc:
        raise RegexError("pattern is not supported by RE2") from exc
