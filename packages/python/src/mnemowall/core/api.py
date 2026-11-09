"""Raw core API for custom stores (M1b-05, §3.3): ``MemoryGuard``.

For memory that lives somewhere Mnemowall has no adapter for. The guard decides and signs; the
caller persists exactly what it returns, and passes stored rows back through
:meth:`MemoryGuard.guard_read` before a model sees them. See ``docs/custom-stores.md``.

* Writes: :meth:`guard_write` / :meth:`guard_delete` run the full policy with trust from the
  provenance context (I9), sign committed versions in the ledger first, and return a
  :class:`WriteDecision`: ``store`` (persist ``value`` at ``namespace``/``key``), ``delete``, or
  ``quarantined`` (persist nothing). A denial raises ``MemoryWriteDenied``.
* Reads: :meth:`guard_read` drops rows outside the session's scope, verifies the rest against the
  ledger (including where they are stored), wraps them for the model, logs the read and
  registers it in the provenance context, like every adapter.
* Rows live under ``(scope prefix, "_raw", store, *labels)``; the store label keeps several
  custom stores apart in one ledger, for :meth:`deliver_reviewed`.

Errors carry fixed reason codes only (M1a-22).
"""

from __future__ import annotations

import dataclasses
import json
import unicodedata
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any, Final, Literal

from mnemowall._log import get_logger
from mnemowall.adapters._common import (
    ROOT,
    TRUST_BY_LABEL,
    MemoryWriteDenied,
    MemoryWriteRefused,
    RollbackRefused,
    RollbackResult,
    hash_label,
    reviewed_heads,
    scope_prefix,
    serialize,
)
from mnemowall.core import diagnostics, regex
from mnemowall.core.forgery import strip_returned
from mnemowall.core.model import MemoryType, Outcome
from mnemowall.core.provenance import ProvenanceSession, current_session
from mnemowall.core.trust import TrustLevel
from mnemowall.ledger import Ledger, VersionRecord
from mnemowall.policy import CompiledPolicy, WriteRequest, load_engine, load_policy
from mnemowall.quarantine import Quarantine, QuarantineRefused
from mnemowall.read import BackendItem, MemoryRef, read_memories
from mnemowall.signals.write import Op as WriteOp
from mnemowall.signals.write import Scope, ScopeKind

__all__ = [
    "InvalidLabel",
    "MemoryGuard",
    "ReadView",
    "StoredItem",
    "WriteDecision",
]

RAW: Final = "_raw"
REF_KEY: Final = "_mnemowall_ref"
LABEL_KEY: Final = "mnemowall"
_STORE: Final = regex.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_BAD_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
_log = get_logger("api")


class InvalidLabel(ValueError):
    """A namespace label or key is not acceptable (fixed reason code, no content)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclasses.dataclass(frozen=True)
class WriteDecision:
    outcome: Literal["store", "delete", "quarantined"]
    namespace: tuple[str, ...] = dataclasses.field(repr=False)  # where to persist (full)
    key: str = dataclasses.field(repr=False)
    value: dict[str, Any] | None = dataclasses.field(repr=False)  # persist exactly this
    memory_id: str | None = None
    version_no: int | None = None
    item_id: str | None = None  # quarantine item, when quarantined


@dataclasses.dataclass(frozen=True)
class StoredItem:
    """A row as your store holds it: the full namespace and the value exactly as persisted."""

    namespace: tuple[str, ...]
    key: str
    value: Mapping[str, Any] = dataclasses.field(repr=False)
    created_ms: int | None = None
    relevance: float | None = None


@dataclasses.dataclass(frozen=True)
class ReadView:
    namespace: tuple[str, ...]  # relative to the session's scope
    key: str = dataclasses.field(repr=False)
    value: dict[str, Any] = dataclasses.field(repr=False)  # without the reference
    text: str = dataclasses.field(repr=False)  # what to show the model
    label: str
    trust: str
    verified: bool
    stale: bool
    memory_id: str
    version_no: int


def _label(value: object, *, namespace: bool) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise InvalidLabel("invalid_key" if not namespace else "invalid_label")
    if any(unicodedata.category(c) in _BAD_CATEGORIES for c in value):
        raise InvalidLabel("invalid_key" if not namespace else "invalid_label")
    if namespace and value.startswith("_"):
        raise InvalidLabel("reserved_label")
    return value


def _namespace(labels: object) -> tuple[str, ...]:
    if not isinstance(labels, tuple | list):
        raise InvalidLabel("invalid_namespace")
    return tuple(_label(v, namespace=True) for v in labels)


class MemoryGuard:
    """Policy, signing and verification for a store Mnemowall has no adapter for."""

    def __init__(
        self,
        *,
        ledger: Ledger,
        quarantine: Quarantine,
        tenant_id: str,
        store: str = "default",
        scope: str = "user",
        grants: Iterable[str] = (),
        policy: CompiledPolicy | None = None,
    ) -> None:
        if not isinstance(store, str) or _STORE.search(store) is None:
            raise ValueError("store must be 1-32 characters of a-z, 0-9 and '-'")
        self._ledger = ledger
        self._quarantine = quarantine
        self._tenant_id = tenant_id
        self._store = store
        self._scope = ScopeKind(scope)
        self._grants = frozenset(grants)
        self._policy = policy or load_policy()
        # The caller persists, so interception is not guaranteed by an adapter probe; policy
        # treats the guard as the integration point (D71).
        self._engine = load_engine(self._policy, interception_guaranteed=True)

    def __repr__(self) -> str:
        return f"MemoryGuard(store={self._store!r}, scope={self._scope.value!r})"

    # --- scope ---------------------------------------------------------------------------

    def _context(self) -> tuple[ProvenanceSession | None, str, tuple[str, ...]]:
        session = current_session()
        if session is not None and session.tenant != self._tenant_id:
            diagnostics.record("tenant_mismatch")
            _log.error("tenant_mismatch", extra={"adapter": "raw"})
            raise MemoryWriteDenied("tenant_mismatch")
        principal = session.principal if session is not None else "anonymous"
        base = (*scope_prefix(self._tenant_id, self._scope, principal), RAW, self._store)
        return session, principal, base

    def location(self, namespace: Sequence[str]) -> tuple[str, ...]:
        """The full namespace for ``namespace`` in the current session's scope."""
        _, _, base = self._context()
        return (*base, *_namespace(namespace))

    # --- writes --------------------------------------------------------------------------

    def guard_write(
        self, namespace: Sequence[str], key: str, value: Mapping[str, Any]
    ) -> WriteDecision:
        """Check and sign a write. Persist ``decision.value`` when the outcome is ``store``."""
        if not isinstance(value, Mapping):
            raise InvalidLabel("invalid_value")
        return self._write(namespace, key, dict(value), None)

    def guard_delete(self, namespace: Sequence[str], key: str) -> WriteDecision:
        """Check a delete. Remove the row when the outcome is ``delete``."""
        return self._write(namespace, key, None, None)

    def _write(
        self,
        namespace: Sequence[str],
        key: str,
        value: dict[str, Any] | None,
        claimed_type: MemoryType | None,
    ) -> WriteDecision:
        labels = _namespace(namespace)
        key = _label(key, namespace=False)
        _, principal, base = self._context()
        ns = (*base, *labels)
        memory_id = self._ledger.find(ns, key)
        head = self._ledger.head(memory_id) if memory_id else None
        live = head is not None and head.status == "active"
        if value is not None and LABEL_KEY in value:
            del value[LABEL_KEY]
            diagnostics.record("forgery_attempt")
            _log.warning("forgery_attempt", extra={"count": 1, "op": "label_key"})
        target_type: MemoryType | None = None
        protected = False
        if head is not None and head.verified and head.signed_fields is not None:
            target_type = MemoryType(head.fields.memory_type)
            protected = head.fields.protected
        request = WriteRequest(
            value=value,
            op=WriteOp.DELETE if value is None else (WriteOp.UPDATE if live else WriteOp.CREATE),
            target_scope=Scope(
                self._scope, None if self._scope is not ScopeKind.USER else principal
            ),
            principal_scope=Scope(ScopeKind.USER, principal),
            grants=self._grants,
            target_protected=protected,
            target_type=target_type,
            claimed_type=claimed_type,
        )
        result = self._engine.evaluate(request)
        decision, stripped = result.decision, result.value
        if decision.action is Outcome.DENY:
            raise MemoryWriteDenied(",".join(decision.rule_ids) or "denied")
        provenance: dict[str, object] = {
            "policy_id": decision.policy_id,
            "outcome": decision.outcome.value,
            "rule_ids": list(decision.rule_ids),
            "fired_signals": list(decision.fired_signals),
            "backend": "raw",
        }
        if decision.action is Outcome.QUARANTINE:
            try:
                submitted = self._quarantine.submit(
                    decision=decision,
                    namespace=ns,
                    key=key,
                    content=serialize(stripped) if stripped is not None else "",
                    scope=self._scope.value,
                    protected=protected,
                    bundle_id=decision.policy_id,
                    provenance=provenance,
                    op="delete" if value is None else "write",
                )
            except QuarantineRefused as exc:
                raise MemoryWriteRefused(exc.reason) from None
            return WriteDecision("quarantined", ns, key, None, item_id=submitted.item_id)
        if value is None:
            record = None
            if head is not None and live:
                record = self._ledger.append_version(
                    namespace=ns,
                    key=key,
                    content=None,
                    scope=self._scope.value,
                    trust_level=decision.write_trust,
                    effective_type=head.fields.effective_type,
                    memory_type=head.fields.memory_type,
                    protected=protected,
                    status="deleted",
                    bundle_id=decision.policy_id,
                    provenance=provenance,
                )
            return WriteDecision(
                "delete",
                ns,
                key,
                None,
                record.memory_id if record else None,
                record.version_no if record else None,
            )
        effective = decision.effective_type
        record = self._ledger.append_version(
            namespace=ns,
            key=key,
            content=serialize(stripped),
            scope=self._scope.value,
            trust_level=decision.write_trust,
            effective_type=effective.value if effective else "data",
            memory_type=decision.memory_type.value,
            protected=protected,
            status="active",
            bundle_id=decision.policy_id,
            provenance=provenance,
        )
        return WriteDecision(
            "store", ns, key, self._stored(stripped, record), record.memory_id, record.version_no
        )

    @staticmethod
    def _stored(value: Mapping[str, Any], record: VersionRecord) -> dict[str, Any]:
        return {
            **value,
            REF_KEY: {
                "memory_id": record.memory_id,
                "version_no": record.version_no,
                "signature": record.signature,
            },
        }

    # --- reads ---------------------------------------------------------------------------

    def guard_read(
        self, items: Sequence[StoredItem], *, query: str | None = None
    ) -> list[ReadView]:
        """Verify, wrap, log and register rows before a model sees them."""
        session, _, base = self._context()
        mine = [i for i in items if tuple(i.namespace[: len(base)]) == base]
        if len(mine) != len(items):
            diagnostics.record("foreign_namespace_filtered", len(items) - len(mine))
            _log.error("foreign_namespace_filtered", extra={"count": len(items) - len(mine)})
        backend, values = [], []
        for item in mine:
            value = dict(item.value)
            raw_ref = value.get(REF_KEY)
            value, _ = strip_returned(value, None)  # drops the reference and any forgeries
            values.append(value)
            ref = None
            if isinstance(raw_ref, Mapping):
                mid, ver, sig = (raw_ref.get(k) for k in ("memory_id", "version_no", "signature"))
                if isinstance(mid, str) and type(ver) is int and isinstance(sig, str):
                    ref = MemoryRef(mid, ver, sig)
            try:
                content = serialize(value)
            except (TypeError, ValueError):
                content, ref = repr(sorted(value)), None
            backend.append(
                BackendItem(
                    content=content,
                    ref=ref,
                    created_ms=item.created_ms,
                    relevance=item.relevance,
                    location=(tuple(item.namespace), item.key),
                )
            )
        read = read_memories(
            self._ledger, backend, session=session, policy=self._policy, query=query
        )
        wrapped = {w.index: w for w in read.wrapped.items}
        return [
            ReadView(
                namespace=tuple(item.namespace[len(base) :]),
                key=item.key,
                value=value,
                text=wrapped[i].text,
                label=wrapped[i].label,
                trust=check.trust.label,
                verified=check.verified,
                stale=check.stale,
                memory_id=check.memory_id,
                version_no=check.version_no,
            )
            for i, (item, value, check) in enumerate(zip(mine, values, read.checks, strict=True))
        ]

    # --- rollback (I7) -------------------------------------------------------------------

    def rollback(
        self, memory_id: str, to_version: int
    ) -> tuple[RollbackResult, WriteDecision | None]:
        """Restore ``to_version`` as a new write through full policy, at its stored trust (I7).

        Returns the result and the decision to apply (``None`` if nothing is to be persisted).
        """
        session, _, base = self._context()
        record = self._ledger.version(memory_id, to_version)
        if record is None:
            raise RollbackRefused("unknown_version")
        if not record.verified or record.signed_fields is None:
            raise RollbackRefused("unverified")
        if record.purged:
            raise RollbackRefused("content_purged")
        fields = record.fields
        if tuple(fields.namespace[: len(base)]) != base or record.key is None:
            raise RollbackRefused("not_in_scope")
        head = self._ledger.head(memory_id)
        before = head.version_no if head is not None else 0
        if session is not None:
            session.register_memory_read(
                memory_id,
                stored_trust=TRUST_BY_LABEL.get(fields.trust_level, TrustLevel.UNKNOWN),
                verified=True,
                stale=False,
            )
        labels = tuple(fields.namespace[len(base) :])
        if record.status != "active" or record.content is None:
            decision = self._write(labels, record.key, None, None)
            outcome = "deleted"
        else:
            decision = self._write(
                labels,
                record.key,
                dict(json.loads(record.content)),
                MemoryType(fields.memory_type),
            )
            outcome = "committed" if decision.outcome == "store" else "quarantined"
        after = self._ledger.head(memory_id)
        new_version = after.version_no if after is not None and after.version_no > before else None
        event: dict[str, object] = {
            "memory_id": memory_id,
            "to_version": to_version,
            "outcome": outcome,
        }
        if new_version is not None:
            event["new_version"] = new_version
        self._ledger.append_event("rollback", event)
        _log.info("rollback", extra={"outcome": outcome, "version_no": to_version})
        applied = None if decision.outcome == "quarantined" else decision
        return RollbackResult(outcome, memory_id, to_version, new_version), applied

    # --- review delivery (M1b-14) --------------------------------------------------------

    def deliver_reviewed(
        self, lookup: Callable[[tuple[str, ...], str], Mapping[str, Any] | None]
    ) -> tuple[list[WriteDecision], dict[str, int]]:
        """Decisions that bring approved or promoted items into the store (D45).

        ``lookup(namespace, key)`` returns the row your store holds there, or ``None``. Apply
        every returned decision. Idempotent; a newer write wins; this store's items only.
        """
        counts = {"delivered": 0, "already": 0, "superseded": 0, "skipped": 0}
        base = (ROOT, hash_label("t-", self._tenant_id), self._scope.value)
        width = len(base) + (1 if self._scope is ScopeKind.USER else 0)
        out: list[WriteDecision] = []
        for target in reviewed_heads(self._ledger, self._quarantine, base, counts):
            ns, key, head = target.namespace, target.key, target.head
            if ns[width : width + 2] != (RAW, self._store):
                continue  # another adapter's or store's items
            current = lookup(ns, key)
            ref = current.get(REF_KEY) if current is not None else None
            if head.status != "active" or head.content is None:
                if current is None:
                    counts["already"] += 1
                    continue
                out.append(WriteDecision("delete", ns, key, None, head.memory_id, head.version_no))
            elif isinstance(ref, Mapping) and ref.get("signature") == head.signature:
                counts["already"] += 1
                continue
            else:
                value = self._stored(json.loads(head.content), head)
                out.append(WriteDecision("store", ns, key, value, head.memory_id, head.version_no))
            counts["delivered"] += 1
            _log.info("review_delivered", extra={"adapter": "raw"})
        return out, counts
