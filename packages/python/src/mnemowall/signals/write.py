"""Facts about a write, and the structural signals S1, S5, S7 (§3.5).

These signals look only at provenance and target metadata, never at content, so they are
cheap (§3.8 budget: provenance + S1, S5, S7 <= 0.5 ms p99) and cannot be fooled by wording.
They report risk; the policy engine and invariants decide outcomes.
"""

from __future__ import annotations

import dataclasses
import enum
from typing import Final

from mnemowall.core.model import MemoryType
from mnemowall.core.trust import TrustLevel, is_tainted
from mnemowall.signals.base import SignalResult


class Op(enum.StrEnum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"


class ScopeKind(enum.StrEnum):
    USER = "user"
    SHARED = "shared"
    ORG = "org"


@dataclasses.dataclass(frozen=True)
class Scope:
    kind: ScopeKind
    owner: str | None = dataclasses.field(default=None, repr=False)  # user id; never in output


@dataclasses.dataclass(frozen=True)
class WriteFacts:
    """Everything the signals and policy know about one write. ``content`` is never printed."""

    content: str = dataclasses.field(repr=False)
    write_trust: TrustLevel
    op: Op
    target_scope: Scope
    principal_scope: Scope
    grants: frozenset[str] = frozenset()
    target_protected: bool = False
    target_type: MemoryType | None = None


_GRANT_FOR: Final = {
    ScopeKind.SHARED: "memory:write:shared",
    ScopeKind.ORG: "memory:write:org",
    ScopeKind.USER: "memory:write:other_user",
}


def s1_taint(f: WriteFacts) -> SignalResult:
    """S1: the write's provenance trust is below ``user`` (TAINTED)."""
    fired = is_tainted(f.write_trust)
    return SignalResult(
        "S1", fired=fired, risk=1.0 if fired else 0.0, labels=(f.write_trust.label,)
    )


def s5_scope(f: WriteFacts) -> SignalResult:
    """S5: write outside the principal's scope without ``verified_user`` + explicit grant (I5)."""
    if f.target_scope == f.principal_scope:
        return SignalResult("S5", fired=False)
    allowed = (
        f.write_trust >= TrustLevel.VERIFIED_USER and _GRANT_FOR[f.target_scope.kind] in f.grants
    )
    return SignalResult(
        "S5",
        fired=not allowed,
        risk=0.0 if allowed else 1.0,
        labels=("cross_scope", str(f.target_scope.kind)),
    )


def s7_protected_mutation(f: WriteFacts) -> SignalResult:
    """S7: an update or delete that targets a protected memory or a standing instruction (I4)."""
    mutating = f.op in (Op.UPDATE, Op.DELETE)
    sensitive = f.target_protected or f.target_type is MemoryType.STANDING_INSTRUCTION
    fired = mutating and sensitive
    return SignalResult(
        "S7", fired=fired, risk=1.0 if fired else 0.0, labels=(str(f.op),) if fired else ()
    )
