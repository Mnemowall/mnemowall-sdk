"""Pieces every adapter shares: errors, the scope prefix, the signed-content serializer (D21, D26).

Framework-free, so the Mem0 adapter doesn't import LangGraph and vice versa.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Iterator, Mapping
from typing import Any, Final

from mnemowall.core.trust import TrustLevel
from mnemowall.ledger import Ledger, VersionRecord
from mnemowall.quarantine import Quarantine, QuarantineError
from mnemowall.signals.write import ScopeKind

ROOT: Final = "mnemowall"
TRUST_BY_LABEL: Final = {t.label: t for t in TrustLevel}


class MemoryWriteDenied(PermissionError):
    """The policy denied the operation (for example I5 cross-scope, or a tenant mismatch)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class MemoryWriteRefused(RuntimeError):
    """The write couldn't be made safely (probe failure, quarantine full or unavailable)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class RollbackRefused(RuntimeError):
    """A rollback target can't be restored (I7): unknown, unverified, purged or out of scope."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclasses.dataclass(frozen=True)
class RollbackResult:
    outcome: str  # committed | quarantined | deleted
    memory_id: str
    to_version: int
    new_version: int | None


@dataclasses.dataclass(frozen=True)
class ProbeResult:
    ok: bool
    reasons: tuple[str, ...]


def hash_label(prefix: str, value: str) -> str:
    return prefix + hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def scope_prefix(tenant_id: str, scope: ScopeKind, principal: str) -> tuple[str, ...]:
    """``("mnemowall", "t-<h>", <scope>[, "p-<h>"])`` (D21)."""
    prefix: tuple[str, ...] = (ROOT, hash_label("t-", tenant_id), scope.value)
    if scope is ScopeKind.USER:
        prefix += (hash_label("p-", principal),)
    return prefix


def serialize(value: Mapping[str, Any]) -> str:
    """The signed content of a stored value (D26)."""
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    )


REVIEWED: Final = frozenset({"approved_as_data", "promoted"})


@dataclasses.dataclass(frozen=True)
class ReviewedHead:
    item_id: str
    namespace: tuple[str, ...] = dataclasses.field(repr=False)
    key: str = dataclasses.field(repr=False)
    head: VersionRecord = dataclasses.field(repr=False)
    provenance: dict[str, object] = dataclasses.field(repr=False)


def reviewed_heads(
    ledger: Ledger, quarantine: Quarantine, base: tuple[str, ...], counts: dict[str, int]
) -> Iterator[ReviewedHead]:
    """Approved/promoted items under ``base`` whose ledger head is still that review's commit.

    Counts ``superseded`` (a newer version exists) and ``skipped`` (payload gone after
    retention, or the head does not verify). Shared by every adapter's ``deliver_reviewed``.
    """
    for summary in quarantine.list(include_resolved=True):
        if summary.status not in REVIEWED:
            continue
        try:
            detail = quarantine.show(summary.item_id)
        except QuarantineError:
            counts["skipped"] += 1
            continue
        ns, key = tuple(detail.namespace), detail.key
        if ns[: len(base)] != base:
            continue
        memory_id = ledger.find(ns, key)
        head = ledger.head(memory_id) if memory_id is not None else None
        if head is None or not head.verified or head.purged:
            counts["skipped"] += 1
            continue
        prov = ledger.provenance(head.memory_id, head.version_no) or {}
        if prov.get("quarantine_item") != summary.item_id:
            counts["superseded"] += 1
            continue
        yield ReviewedHead(summary.item_id, ns, key, head, prov)
