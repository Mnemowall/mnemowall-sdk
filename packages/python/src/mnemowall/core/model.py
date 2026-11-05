"""Memory types and policy outcomes (§3.4, §3.5)."""

from __future__ import annotations

import enum


class MemoryType(enum.StrEnum):
    """What a write claims to be (classified by S2; never trusted from the caller)."""

    FACT = "fact"
    PREFERENCE = "preference"
    STANDING_INSTRUCTION = "standing_instruction"
    PROCEDURE = "procedure"


class EffectiveType(enum.StrEnum):
    """What a committed memory is treated as on read. Tainted commits become ``data`` (I3)."""

    FACT = "fact"
    PREFERENCE = "preference"
    STANDING_INSTRUCTION = "standing_instruction"
    PROCEDURE = "procedure"
    DATA = "data"


class Outcome(enum.StrEnum):
    """Policy decision for a write. ``shadow_would_*`` are recorded in shadow mode only."""

    ALLOW = "allow"
    ALLOW_AS_DATA = "allow_as_data"
    QUARANTINE = "quarantine"
    DENY = "deny"
    SHADOW_WOULD_ALLOW = "shadow_would_allow"
    SHADOW_WOULD_ALLOW_AS_DATA = "shadow_would_allow_as_data"
    SHADOW_WOULD_QUARANTINE = "shadow_would_quarantine"
    SHADOW_WOULD_DENY = "shadow_would_deny"
