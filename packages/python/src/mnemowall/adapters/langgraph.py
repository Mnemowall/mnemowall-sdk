"""LangGraph adapter: ``GuardedStore(BaseStore)`` and a tool-output callback (M1a-17/18).

Install with ``pip install 'mnemowall[langgraph]'``. See the test spec
``M1a-17-18-19-langgraph-adapter`` (D21-D31) and ADR-0022.

``GuardedStore`` wraps any LangGraph ``BaseStore`` and overrides only ``batch``/``abatch``, which
every store operation goes through (§3.3):

* **Namespaces.** Every op is confined to ``("mnemowall", "t-<tenant hash>", <scope>[,
  "p-<principal hash>"])`` + the caller's namespace. Caller labels that are empty or contain
  ``.``, ``%``, ``_``, control or format characters are rejected on every op type.
* **Writes** go through the policy engine with trust from the provenance context only (I9).
  Allowed writes are signed into the ledger first, then stored with a ``_mnemowall_ref``;
  quarantined writes go to the quarantine store and never reach the inner store; denials raise.
* **Reads** are verified against the ledger, registered in the session, logged, and returned
  with ``value["mnemowall"]`` labels and the wrapped text (§3.7). Honest limit: code that reads
  individual fields and ignores ``value["mnemowall"]["text"]`` bypasses wrapping.
* **Capability probe.** If the inner store's ``batch``/``abatch`` can't be confirmed, writes are
  refused (§1.3) and reads still pass through verification.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final, cast

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langgraph.store.base import (
        BaseStore,
        GetOp,
        InvalidNamespaceError,
        Item,
        ListNamespacesOp,
        MatchCondition,
        Op,
        PutOp,
        Result,
        SearchItem,
        SearchOp,
    )
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError("install the LangGraph extra: pip install 'mnemowall[langgraph]'") from exc

from mnemowall._log import get_logger
from mnemowall.adapters._common import (
    ROOT,
    TRUST_BY_LABEL,
    MemoryWriteDenied,
    MemoryWriteRefused,
    ProbeResult,
    RollbackRefused,
    RollbackResult,
    hash_label,
    reviewed_heads,
    scope_prefix,
    serialize,
)
from mnemowall.core import diagnostics
from mnemowall.core.forgery import strip_returned
from mnemowall.core.model import MemoryType, Outcome
from mnemowall.core.provenance import ProvenanceSession, current_session
from mnemowall.core.trust import Source, TrustLevel
from mnemowall.ledger import Ledger
from mnemowall.policy import CompiledPolicy, WriteRequest, load_engine, load_policy
from mnemowall.quarantine import Quarantine, QuarantineRefused
from mnemowall.read import BackendItem, MemoryRef, read_memories
from mnemowall.signals.write import Op as WriteOp
from mnemowall.signals.write import Scope, ScopeKind

REF_KEY: Final = "_mnemowall_ref"
LABEL_KEY: Final = "mnemowall"
_FORBIDDEN_CHARS: Final = frozenset(".%_")
_BAD_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})

_log = get_logger("langgraph")
_TRUST_BY_LABEL: Final = TRUST_BY_LABEL
_hash_label = hash_label


class NamespaceError(InvalidNamespaceError):
    """A caller namespace label or key is not allowed (D22). ``reason`` is a fixed code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _one_param(fn: Any) -> bool:
    try:
        params = list(inspect.signature(fn).parameters.values())
    except (TypeError, ValueError):
        return False
    positional = [p for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
    others = [p for p in params if p not in positional]
    return len(positional) == 1 and not others


def probe(inner: object) -> ProbeResult:
    """Can every operation on ``inner`` be intercepted through ``batch``/``abatch``? (D29)"""
    reasons = []
    if not isinstance(inner, BaseStore):
        reasons.append("not_a_base_store")
    else:
        if not _one_param(getattr(inner, "batch", None)):
            reasons.append("batch_signature")
        abatch = getattr(inner, "abatch", None)
        if not _one_param(abatch) or not inspect.iscoroutinefunction(abatch):
            reasons.append("abatch_signature")
    return ProbeResult(not reasons, tuple(reasons))


def _check_label(label: object, *, allow_wildcard: bool = False) -> str:
    if not isinstance(label, str) or not label:
        raise NamespaceError("invalid_label")
    if allow_wildcard and label == "*":
        return label
    if any(c in _FORBIDDEN_CHARS or unicodedata.category(c) in _BAD_CATEGORIES for c in label):
        raise NamespaceError("invalid_label")
    return label


def _check_namespace(ns: Sequence[object], *, allow_wildcard: bool = False) -> tuple[str, ...]:
    if not isinstance(ns, tuple):
        raise NamespaceError("invalid_namespace")
    return tuple(_check_label(label, allow_wildcard=allow_wildcard) for label in ns)


def _check_list_args(kwargs: Mapping[str, Any]) -> None:
    for name in ("prefix", "suffix"):
        if kwargs.get(name) is not None:
            _check_namespace(tuple(kwargs[name]), allow_wildcard=True)


class GuardedStore(BaseStore):
    """A LangGraph store that enforces Mnemowall policy around an inner store."""

    def __init__(
        self,
        inner: BaseStore,
        *,
        ledger: Ledger,
        quarantine: Quarantine,
        tenant_id: str,
        scope: str = "user",
        grants: Iterable[str] = (),
        policy: CompiledPolicy | None = None,
    ) -> None:
        if isinstance(inner, GuardedStore):
            raise TypeError("inner store is already a GuardedStore")
        self._inner = inner
        self._ledger = ledger
        self._quarantine = quarantine
        self._tenant_id = tenant_id
        self._scope = ScopeKind(scope)
        self._grants = frozenset(grants)
        self._policy = policy or load_policy()
        self.probe_result = probe(inner)
        self._engine = load_engine(self._policy, interception_guaranteed=self.probe_result.ok)

    def __repr__(self) -> str:
        return f"GuardedStore(tenant_id={self._tenant_id!r}, scope={self._scope.value!r})"

    @property
    def supports_ttl(self) -> bool:  # type: ignore[override]
        return bool(getattr(self._inner, "supports_ttl", False))

    # --- context -----------------------------------------------------------------------

    def _context(self) -> tuple[ProvenanceSession | None, tuple[str, ...]]:
        session = current_session()
        if session is not None and session.tenant != self._tenant_id:
            diagnostics.record("tenant_mismatch")
            _log.error("tenant_mismatch", extra={"adapter": "langgraph"})
            raise MemoryWriteDenied("tenant_mismatch")
        principal = session.principal if session is not None else "anonymous"
        return session, scope_prefix(self._tenant_id, self._scope, principal)

    # --- pre-validation ----------------------------------------------------------------
    # BaseStore.put / list_namespaces validate labels themselves *before* calling batch, and
    # LangGraph's InvalidNamespaceError echoes the labels. Check first with our own
    # content-free NamespaceError (M1a-22), then delegate unchanged.

    def put(
        self, namespace: tuple[str, ...], key: str, value: Any, *args: Any, **kwargs: Any
    ) -> None:
        _check_namespace(namespace)
        super().put(namespace, key, value, *args, **kwargs)

    async def aput(
        self, namespace: tuple[str, ...], key: str, value: Any, *args: Any, **kwargs: Any
    ) -> None:
        _check_namespace(namespace)
        await super().aput(namespace, key, value, *args, **kwargs)

    def get(self, namespace: tuple[str, ...], *args: Any, **kwargs: Any) -> Item | None:
        _check_namespace(namespace)
        return super().get(namespace, *args, **kwargs)

    async def aget(self, namespace: tuple[str, ...], *args: Any, **kwargs: Any) -> Item | None:
        _check_namespace(namespace)
        return await super().aget(namespace, *args, **kwargs)

    def search(
        self, namespace_prefix: tuple[str, ...], /, *args: Any, **kwargs: Any
    ) -> list[SearchItem]:
        _check_namespace(namespace_prefix)
        return super().search(namespace_prefix, *args, **kwargs)

    async def asearch(
        self, namespace_prefix: tuple[str, ...], /, *args: Any, **kwargs: Any
    ) -> list[SearchItem]:
        _check_namespace(namespace_prefix)
        return await super().asearch(namespace_prefix, *args, **kwargs)

    def delete(self, namespace: tuple[str, ...], key: str) -> None:
        _check_namespace(namespace)
        super().delete(namespace, key)

    async def adelete(self, namespace: tuple[str, ...], key: str) -> None:
        _check_namespace(namespace)
        await super().adelete(namespace, key)

    def list_namespaces(self, **kwargs: Any) -> list[tuple[str, ...]]:
        _check_list_args(kwargs)
        return super().list_namespaces(**kwargs)

    async def alist_namespaces(self, **kwargs: Any) -> list[tuple[str, ...]]:
        _check_list_args(kwargs)
        return await super().alist_namespaces(**kwargs)

    # --- batch -------------------------------------------------------------------------

    def batch(self, ops: Iterable[Op]) -> list[Result]:
        session, prefix = self._context()
        results: list[Result] = []
        for op in list(ops):
            if isinstance(op, PutOp):
                self._put(op, session, prefix)
                results.append(None)
            elif isinstance(op, GetOp):
                results.append(self._get(op, session, prefix))
            elif isinstance(op, SearchOp):
                results.append(self._search(op, session, prefix))
            elif isinstance(op, ListNamespacesOp):
                results.append(self._list(op, prefix))
            else:
                raise TypeError("unsupported store operation")
        return results

    async def abatch(self, ops: Iterable[Op]) -> list[Result]:
        return await asyncio.to_thread(self.batch, list(ops))

    # --- writes ------------------------------------------------------------------------

    def _put(
        self,
        op: PutOp,
        session: ProvenanceSession | None,
        prefix: tuple[str, ...],
        claimed_type: MemoryType | None = None,
    ) -> None:
        ns = prefix + _check_namespace(op.namespace)
        if not isinstance(op.key, str) or not op.key:
            raise NamespaceError("invalid_key")
        memory_id = self._ledger.find(ns, op.key)
        head = self._ledger.head(memory_id) if memory_id else None
        live = head is not None and head.status == "active"
        value: dict[str, Any] | None = None
        if op.value is not None:
            value = dict(op.value)
            if LABEL_KEY in value:
                del value[LABEL_KEY]
                diagnostics.record("forgery_attempt")
                _log.warning("forgery_attempt", extra={"count": 1, "op": "label_key"})
        target_type = target_protected = None
        if head is not None and head.verified and head.signed_fields is not None:
            target_type = MemoryType(head.fields.memory_type)
            target_protected = head.fields.protected
        principal = session.principal if session is not None else "anonymous"
        request = WriteRequest(
            value=value,
            op=WriteOp.DELETE if value is None else (WriteOp.UPDATE if live else WriteOp.CREATE),
            target_scope=Scope(
                self._scope, None if self._scope is not ScopeKind.USER else principal
            ),
            principal_scope=Scope(ScopeKind.USER, principal),
            grants=self._grants,
            target_protected=bool(target_protected),
            target_type=target_type,
            claimed_type=claimed_type,
        )
        result = self._engine.evaluate(request)
        decision = result.decision
        stripped = result.value
        if decision.action is Outcome.DENY:
            reason = "adapter_probe_failure" if not self.probe_result.ok else "denied"
            if not self.probe_result.ok:
                raise MemoryWriteRefused(reason)
            raise MemoryWriteDenied(",".join(decision.rule_ids) or reason)
        provenance = {
            "policy_id": decision.policy_id,
            "outcome": decision.outcome.value,
            "rule_ids": list(decision.rule_ids),
            "fired_signals": list(decision.fired_signals),
        }
        if decision.action is Outcome.QUARANTINE:
            try:
                self._quarantine.submit(
                    decision=decision,
                    namespace=ns,
                    key=op.key,
                    content=serialize(stripped) if stripped is not None else "",
                    scope=self._scope.value,
                    protected=bool(target_protected),
                    bundle_id=decision.policy_id,
                    provenance=provenance,
                    op="delete" if value is None else "write",
                )
            except QuarantineRefused as exc:
                raise MemoryWriteRefused(exc.reason) from None
            return None
        if value is None:
            if memory_id is not None and head is not None and live:
                self._ledger.append_version(
                    namespace=ns,
                    key=op.key,
                    content=None,
                    scope=self._scope.value,
                    trust_level=decision.write_trust,
                    effective_type=head.fields.effective_type,
                    memory_type=head.fields.memory_type,
                    protected=bool(target_protected),
                    status="deleted",
                    bundle_id=decision.policy_id,
                    provenance=provenance,
                )
            self._inner.batch([PutOp(ns, op.key, None)])
            return None
        content = serialize(stripped)
        effective = decision.effective_type
        record = self._ledger.append_version(
            namespace=ns,
            key=op.key,
            content=content,
            scope=self._scope.value,
            trust_level=decision.write_trust,
            effective_type=effective.value if effective else "data",
            memory_type=decision.memory_type.value,
            protected=bool(target_protected),
            status="active",
            bundle_id=decision.policy_id,
            provenance=provenance,
        )
        stored = {
            **stripped,
            REF_KEY: {
                "memory_id": record.memory_id,
                "version_no": record.version_no,
                "signature": record.signature,
            },
        }
        index = op.index
        if isinstance(index, list):
            _, kept = strip_returned({}, index)
            index = kept or []
        self._inner.batch([PutOp(ns, op.key, stored, index=index, ttl=op.ttl)])
        return None

    # --- rollback (I7) ------------------------------------------------------------------

    def rollback(self, memory_id: str, to_version: int) -> RollbackResult:
        """Restore ``to_version`` as a **new write through the full policy** (I7).

        The restored version is first registered in the provenance context at its stored trust,
        so a rollback can never raise trust: restoring a version that came from an email is
        written at email trust, and a poisoned instruction is quarantined again by I1. Purged,
        unverified (tampered or shredded) and out-of-scope versions are refused.
        """
        session, prefix = self._context()
        record = self._ledger.version(memory_id, to_version)
        if record is None:
            raise RollbackRefused("unknown_version")
        if not record.verified or record.signed_fields is None:
            raise RollbackRefused("unverified")
        if record.purged:
            raise RollbackRefused("content_purged")
        fields = record.fields
        if tuple(fields.namespace[: len(prefix)]) != prefix or record.key is None:
            raise RollbackRefused("not_in_scope")
        head = self._ledger.head(memory_id)
        before = head.version_no if head is not None else 0
        if session is not None:
            session.register_memory_read(
                memory_id,
                stored_trust=_TRUST_BY_LABEL.get(fields.trust_level, TrustLevel.UNKNOWN),
                verified=True,
                stale=False,  # a deliberate restore of a genuine version, not a replay
            )
        caller_ns = tuple(fields.namespace[len(prefix) :])
        if record.status != "active" or record.content is None:
            self._put(PutOp(caller_ns, record.key, None), session, prefix)
            outcome = "deleted"
        else:
            value = json.loads(record.content)
            self._put(
                PutOp(caller_ns, record.key, value),
                session,
                prefix,
                claimed_type=MemoryType(fields.memory_type),
            )
            after = self._ledger.head(memory_id)
            committed = after is not None and after.version_no > before
            outcome = "committed" if committed else "quarantined"
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
        return RollbackResult(outcome, memory_id, to_version, new_version)

    # --- review delivery (M1b-14) -------------------------------------------------------

    def deliver_reviewed(self) -> dict[str, int]:
        """Write approved or promoted quarantine items into the inner store (D45).

        The ledger is the source of truth: for each reviewed item whose ledger head is still
        that review's commit, the inner store is made to hold exactly that version. Idempotent
        (an item already holding the head's signature is left alone), and a newer write always
        wins (``superseded``). Runs without a session, for this store's tenant and scope only.
        """
        counts = {"delivered": 0, "already": 0, "superseded": 0, "skipped": 0}
        base = (ROOT, hash_label("t-", self._tenant_id), self._scope.value)
        for target in reviewed_heads(self._ledger, self._quarantine, base, counts):
            ns, key, head = target.namespace, target.key, target.head
            if any(label.startswith("_") for label in ns[len(base) :]):
                continue  # another adapter's namespace (LangGraph labels never contain "_")
            current = cast("Item | None", self._inner.batch([GetOp(ns, key)])[0])
            ref = current.value.get(REF_KEY) if current is not None else None
            if head.status != "active" or head.content is None:
                if current is None:
                    counts["already"] += 1
                    continue
                self._inner.batch([PutOp(ns, key, None)])
            elif isinstance(ref, Mapping) and ref.get("signature") == head.signature:
                counts["already"] += 1
                continue
            else:
                value = json.loads(head.content)
                stored = {
                    **value,
                    REF_KEY: {
                        "memory_id": head.memory_id,
                        "version_no": head.version_no,
                        "signature": head.signature,
                    },
                }
                self._inner.batch([PutOp(ns, key, stored)])
            counts["delivered"] += 1
            _log.info("review_delivered", extra={"adapter": "langgraph"})
        return counts

    # --- reads -------------------------------------------------------------------------

    def _read(
        self,
        items: Sequence[Item],
        session: ProvenanceSession | None,
        prefix: tuple[str, ...],
        query: str | None,
    ) -> list[Item]:
        mine = [i for i in items if tuple(i.namespace[: len(prefix)]) == prefix]
        if len(mine) != len(items):
            diagnostics.record("foreign_namespace_filtered", len(items) - len(mine))
            _log.error("foreign_namespace_filtered", extra={"count": len(items) - len(mine)})
        backend = []
        values = []
        for item in mine:
            value = dict(item.value)
            raw_ref = value.get(REF_KEY)
            value, _ = strip_returned(value, None)  # also removes REF_KEY and any _prov
            values.append(value)
            ref = None
            if isinstance(raw_ref, Mapping):
                mid, ver, sig = (
                    raw_ref.get("memory_id"),
                    raw_ref.get("version_no"),
                    raw_ref.get("signature"),
                )
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
                    created_ms=int(item.created_at.timestamp() * 1000),
                    relevance=getattr(item, "score", None),
                    location=(tuple(item.namespace), item.key),
                )
            )
        read = read_memories(
            self._ledger, backend, session=session, policy=self._policy, query=query
        )
        text_by_index = {w.index: w for w in read.wrapped.items}
        out: list[Item] = []
        for i, (item, value, check) in enumerate(zip(mine, values, read.checks, strict=True)):
            w = text_by_index[i]
            value[LABEL_KEY] = {
                "label": w.label,
                "trust": check.trust.label,
                "verified": check.verified,
                "stale": check.stale,
                "memory_id": check.memory_id,
                "version_no": check.version_no,
                "text": w.text,
            }
            namespace = tuple(item.namespace[len(prefix) :])
            if isinstance(item, SearchItem):
                out.append(
                    SearchItem(
                        namespace=namespace,
                        key=item.key,
                        value=value,
                        created_at=item.created_at,
                        updated_at=item.updated_at,
                        score=item.score,
                    )
                )
            else:
                out.append(
                    Item(
                        value=value,
                        key=item.key,
                        namespace=namespace,
                        created_at=item.created_at,
                        updated_at=item.updated_at,
                    )
                )
        return out

    def _get(
        self, op: GetOp, session: ProvenanceSession | None, prefix: tuple[str, ...]
    ) -> Item | None:
        ns = prefix + _check_namespace(op.namespace)
        if not isinstance(op.key, str) or not op.key:
            raise NamespaceError("invalid_key")
        found = cast(
            "Item | None", self._inner.batch([GetOp(ns, op.key, refresh_ttl=op.refresh_ttl)])[0]
        )
        if found is None:
            return None
        items = self._read([found], session, prefix, None)
        return items[0] if items else None

    def _search(
        self, op: SearchOp, session: ProvenanceSession | None, prefix: tuple[str, ...]
    ) -> list[SearchItem]:
        ns = prefix + _check_namespace(op.namespace_prefix)
        results = self._inner.batch(
            [
                SearchOp(
                    ns,
                    filter=op.filter,
                    limit=op.limit,
                    offset=op.offset,
                    query=op.query,
                    refresh_ttl=op.refresh_ttl,
                )
            ]
        )
        found = cast("list[SearchItem]", results[0])
        return cast("list[SearchItem]", self._read(found, session, prefix, op.query))

    def _list(self, op: ListNamespacesOp, prefix: tuple[str, ...]) -> list[tuple[str, ...]]:
        conditions = []
        has_prefix = False
        for cond in op.match_conditions or ():
            path = _check_namespace(tuple(cond.path), allow_wildcard=True)
            if cond.match_type == "prefix":
                has_prefix = True
                conditions.append(MatchCondition(match_type="prefix", path=prefix + path))
            else:
                conditions.append(MatchCondition(match_type=cond.match_type, path=path))
        if not has_prefix:
            conditions.insert(0, MatchCondition(match_type="prefix", path=prefix))
        max_depth = None if op.max_depth is None else op.max_depth + len(prefix)
        listed = self._inner.batch(
            [
                ListNamespacesOp(
                    match_conditions=tuple(conditions),
                    max_depth=max_depth,
                    limit=op.limit,
                    offset=op.offset,
                )
            ]
        )
        found = cast("list[tuple[str, ...]]", listed[0])
        out = []
        for ns in found:
            if tuple(ns[: len(prefix)]) == prefix and len(ns) > len(prefix):
                out.append(tuple(ns[len(prefix) :]))
        return out


class MnemowallCallbackHandler(BaseCallbackHandler):
    """Observe LangChain/LangGraph tool outputs into the active provenance session (D30)."""

    def __init__(self, source: Source = Source.TOOL_OUTPUT) -> None:
        super().__init__()
        self._source = source

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        session = current_session()
        if session is None:
            diagnostics.record("observe_without_session")
            _log.warning("observe_without_session", extra={"source_type": self._source.value})
            return
        content = getattr(output, "content", output)
        ref = getattr(output, "tool_call_id", None)
        text = content if isinstance(content, str) else json.dumps(content, default=str)
        session.observe(text, source=self._source, ref=ref if isinstance(ref, str) else None)


__all__ = [
    "LABEL_KEY",
    "REF_KEY",
    "ROOT",
    "GuardedStore",
    "MemoryWriteDenied",
    "MemoryWriteRefused",
    "MnemowallCallbackHandler",
    "NamespaceError",
    "ProbeResult",
    "RollbackRefused",
    "RollbackResult",
    "probe",
    "serialize",
]
