"""Write size caps (§3.5): oversized payloads are quarantined, keeping checks inside budget."""

from __future__ import annotations

from typing import Final

from mnemowall.signals.base import SignalResult

MAX_WRITE_BYTES: Final = 32 * 1024  # D5; lower locally, raise only via signed policy


def oversized(content: str, limit: int = MAX_WRITE_BYTES) -> bool:
    """True if ``content`` exceeds ``limit`` UTF-8 bytes. Cheap check first: <= 4 bytes/char."""
    if len(content) * 4 <= limit:
        return False
    return len(content.encode("utf-8", "surrogatepass")) > limit


def size_signal(content: str) -> SignalResult:
    fired = oversized(content)
    return SignalResult("S0.oversize", fired=fired, risk=1.0 if fired else 0.0)
