"""Mem0 OSS adapter: ``GuardedMemory`` / ``GuardedAsyncMemory`` (M1b-02, M1b-03).

Install with ``pip install 'mnemowall[mem0]'``. See the test spec ``M1b-01-04`` (V1-V7,
D34-D43) and ADR-0025.

A composition wrapper around ``mem0.Memory`` / ``mem0.AsyncMemory`` (D34). Only ``add``, ``get``,
``get_all``, ``search``, ``update``, ``delete``, ``delete_all`` and ``rollback`` are exposed;
nothing else of the inner object is reachable through the wrapper.

* **Strict mode (default, preventive).** ``add`` stores each non-system message's content
  verbatim (``infer=False``), so the text policy sees is exactly the text stored. Every message
  goes through the policy engine with trust from the provenance context only (I9); Mem0's
  ``role`` and ``name`` are never read as trust.
* **Infer mode (beta, detective; ``mode="infer"``).** Mem0's LLM extracts and stores first; each
  result is then checked, and anything policy would not commit is removed and quarantined
  (D40). Between those two steps the extracted text sits in Mem0 without a reference, so any
  read in that window shows it ``unverified``.
* **Scope.** The Mem0 ``user_id`` is derived from tenant, scope and session principal (D35);
  id-based calls check ownership themselves, because Mem0's ``get``/``update``/``delete`` don't
  (V3). Filters are plain equality only (D39).
* **Reads** are verified against the ledger, located (D32), logged, registered, and returned
  with ``memory`` replaced by the model-facing text and ``mnemowall`` labels added (D38).

Honest limits: Mem0 itself logs memory text at INFO/DEBUG (keep the ``mem0`` logger at WARNING),
and its telemetry is on unless ``MEM0_TELEMETRY=False`` is set before import (V5, V6).
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import inspect
import json
import threading
import unicodedata
import uuid
from collections.abc import Iterator, Mapping, Sequence
from datetime import datetime
from typing import Any, Final, Literal

try:
    import mem0.memory.telemetry as _mem0_telemetry
    from mem0 import AsyncMemory, Memory
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError("install the Mem0 extra: pip install 'mnemowall[mem0]'") from exc

from mnemowall._log import get_logger
from mnemowall.adapters._common import (
    TRUST_BY_LABEL,
    MemoryWriteDenied,
    MemoryWriteRefused,
    ProbeResult,
    RollbackRefused,
    RollbackResult,
    hash_label,
    scope_prefix,
    serialize,
)
from mnemowall.core import diagnostics
from mnemowall.core.forgery import ForgeryError, is_reserved_key, strip_returned, strip_value
from mnemowall.core.model import MemoryType, Outcome
from mnemowall.core.provenance import ProvenanceSession, current_session
from mnemowall.core.trust import TrustLevel
from mnemowall.ledger import Ledger, VersionRecord
from mnemowall.policy import CompiledPolicy, WriteRequest, load_engine, load_policy
from mnemowall.policy.engine import Decision
from mnemowall.quarantine import Quarantine, QuarantineRefused
from mnemowall.read import BackendItem, MemoryRef, read_memories, verify_item
from mnemowall.signals.write import Op as WriteOp
from mnemowall.signals.write import Scope, ScopeKind

MEM0: Final = "mem0"
KEY_FIELD: Final = "_mnemowall_key"
REF_FIELD: Final = "_mnemowall_ref"
LABEL_KEY: Final = "mnemowall"
MAX_SCAN: Final = 10_000  # rollback / delete_all page size
# Mem0 identity, promoted and core payload keys: never caller metadata (D37, V4).
_MEM0_RESERVED: Final = frozenset(
    {
        "user_id",
        "agent_id",
        "run_id",
        "actor_id",
        "role",
        "attributed_to",
        "expiration_date",
        "data",
        "hash",
        "created_at",
        "updated_at",
        "id",
        "text_lemmatized",
        "memory",
        "score",
        "metadata",
        LABEL_KEY,
    }
)
_LOGICAL: Final = frozenset({"AND", "OR", "NOT"})
_BAD_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
_SCALARS: Final = (str, int, float, bool)

_log = get_logger("mem0")


class NamespaceError(ValueError):
    """A caller id, filter or metadata key is not allowed (D35, D39). ``reason`` is a fixed code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class MemoryNotFound(LookupError):
    """No such memory in the caller's scope (another principal's id looks the same, D41)."""

    def __init__(self) -> None:
        super().__init__("not_found")
        self.reason = "not_found"


class InvalidMessage(ValueError):
    """``messages`` is not a string, a message dict, or a list of message dicts."""

    def __init__(self) -> None:
        super().__init__("invalid_message")
        self.reason = "invalid_message"


def derive_user_id(tenant_id: str, scope: str, principal: str) -> str:
    """The Mem0 ``user_id`` the wrapper uses for a tenant, scope and principal (D35)."""
    who = principal if scope == ScopeKind.USER.value else ""
    material = "\0".join((tenant_id, scope, who)).encode("utf-8", "surrogatepass")
    return "mw" + hashlib.sha256(material).hexdigest()[:32]


def telemetry_enabled() -> bool:
    """Is Mem0's PostHog telemetry on in this process? (V5)"""
    return bool(getattr(_mem0_telemetry, "MEM0_TELEMETRY", False))


def probe(inner: object, *, flavour: type) -> ProbeResult:
    """Is ``inner`` a Mem0 memory of the expected flavour with the methods we wrap?"""
    reasons = []
    if isinstance(inner, GuardedMemory | GuardedAsyncMemory):
        reasons.append("already_guarded")
    elif not isinstance(inner, flavour):
        reasons.append("not_mem0")
    else:
        try:
            names = set(inspect.signature(getattr(type(inner), "add")).parameters)  # noqa: B009
        except (AttributeError, TypeError, ValueError):
            names = set()
        if not {"user_id", "agent_id", "run_id", "metadata", "infer"} <= names:
            reasons.append("add_signature")
        for name in ("get", "get_all", "search", "update", "delete"):
            if not callable(getattr(inner, name, None)):
                reasons.append(f"missing_{name}")
    return ProbeResult(not reasons, tuple(reasons))


def _check_id(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 256:
        raise NamespaceError("invalid_label")
    if any(c.isspace() or unicodedata.category(c) in _BAD_CATEGORIES for c in value):
        raise NamespaceError("invalid_label")
    return value


def _is_reserved_meta(key: str) -> bool:
    return key in _MEM0_RESERVED or key.startswith("_") or is_reserved_key(key, top_level=True)


def _clean_metadata(metadata: object) -> dict[str, Any]:
    """Drop reserved keys (D37), counting each as a forgery attempt; deep-strip ``_prov``."""
    if metadata is None:
        return {}
    if not isinstance(metadata, Mapping):
        raise NamespaceError("invalid_metadata")
    out: dict[str, Any] = {}
    removed = 0
    for key, value in metadata.items():
        if not isinstance(key, str):
            raise NamespaceError("invalid_metadata")
        if _is_reserved_meta(key):
            removed += 1
            continue
        out[key] = value
    if removed:
        diagnostics.record("forgery_attempt", removed)
        _log.warning("forgery_attempt", extra={"count": removed, "op": "mem0_metadata"})
    try:
        cleaned = strip_value(out).value
        serialize(cleaned)
    except (ForgeryError, TypeError, ValueError):
        raise NamespaceError("invalid_metadata") from None
    return dict(cleaned)


def _filters(filters: object) -> tuple[dict[str, Any], str | None, str | None]:
    """Plain equality on caller metadata, plus ``agent_id``/``run_id`` (D39)."""
    if filters is None:
        return {}, None, None
    if not isinstance(filters, Mapping):
        raise NamespaceError("unsupported_filter")
    eq: dict[str, Any] = {}
    agent = run = None
    for key, value in filters.items():
        if key in ("agent_id", "run_id"):
            try:
                checked = _check_id(value)
            except NamespaceError:
                raise NamespaceError("unsupported_filter") from None
            if checked is None:
                raise NamespaceError("unsupported_filter")
            if key == "agent_id":
                agent = checked
            else:
                run = checked
        elif (
            not isinstance(key, str)
            or key in _LOGICAL
            or _is_reserved_meta(key)
            or not isinstance(value, _SCALARS)
            or value == "*"
        ):
            raise NamespaceError("unsupported_filter")
        else:
            eq[key] = value
    return eq, agent, run


def _messages(messages: object) -> list[dict[str, str]]:
    if isinstance(messages, str):
        messages = [{"role": "user", "content": messages}]
    elif isinstance(messages, Mapping):
        messages = [messages]
    if not isinstance(messages, list) or not messages:
        raise InvalidMessage
    out = []
    for m in messages:
        if not isinstance(m, Mapping):
            raise InvalidMessage
        role, content, name = m.get("role"), m.get("content"), m.get("name")
        if not isinstance(role, str) or not isinstance(content, str) or not content:
            raise InvalidMessage
        if name is not None and not isinstance(name, str):
            raise InvalidMessage
        msg = {"role": role, "content": content}
        if name:
            msg["name"] = name
        out.append(msg)
    return out


def _created_ms(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        return int(datetime.fromisoformat(value).timestamp() * 1000)
    except ValueError:
        return None


@dataclasses.dataclass(frozen=True)
class _Ctx:
    session: ProvenanceSession | None
    principal: str
    prefix: tuple[str, ...]
    user_id: str


@dataclasses.dataclass(frozen=True)
class _Tracked:
    """A Mem0 item in scope, with what the ledger says about it."""

    item: dict[str, Any]
    text: str
    metadata: dict[str, Any]
    key: str | None
    agent_id: str | None
    run_id: str | None
    head: VersionRecord | None  # set only when the item verifies as the current head


class _Core:
    """All policy, ledger and read logic. Subclasses supply ``_call`` (sync or bridged async)."""

    def __init__(
        self,
        inner: Any,
        *,
        ledger: Ledger,
        quarantine: Quarantine,
        tenant_id: str,
        scope: str,
        grants: Sequence[str],
        policy: CompiledPolicy | None,
        mode: Literal["strict", "infer"],
        flavour: type,
    ) -> None:
        if mode not in ("strict", "infer"):
            raise ValueError("mode must be 'strict' or 'infer'")
        if mode == "infer":  # M1b-03 (beta, detective) is not built yet
            raise ValueError("infer mode is not available in this version")
        self._inner = inner
        self._ledger = ledger
        self._quarantine = quarantine
        self._tenant_id = tenant_id
        self._scope = ScopeKind(scope)
        self._grants = frozenset(grants)
        self._policy = policy or load_policy()
        self._mode: Literal["strict", "infer"] = mode
        self.probe_result = probe(inner, flavour=flavour)
        self._engine = load_engine(self._policy, interception_guaranteed=self.probe_result.ok)
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        if not self.probe_result.ok:
            diagnostics.record("adapter_probe_failure")
            _log.error("adapter_probe_failure", extra={"adapter": MEM0})
        if telemetry_enabled():
            diagnostics.record("mem0_telemetry_enabled")
            _log.warning("mem0_telemetry_enabled", extra={"adapter": MEM0})

    def _call(self, name: str, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    # --- context -----------------------------------------------------------------------

    def _context(self) -> _Ctx:
        session = current_session()
        if session is not None and session.tenant != self._tenant_id:
            diagnostics.record("tenant_mismatch")
            _log.error("tenant_mismatch", extra={"adapter": MEM0})
            raise MemoryWriteDenied("tenant_mismatch")
        principal = session.principal if session is not None else "anonymous"
        return _Ctx(
            session,
            principal,
            scope_prefix(self._tenant_id, self._scope, principal),
            derive_user_id(self._tenant_id, self._scope.value, principal),
        )

    def _ns(self, ctx: _Ctx, agent_id: str | None, run_id: str | None) -> tuple[str, ...]:
        ns = (*ctx.prefix, MEM0)
        if agent_id is not None:
            ns += (hash_label("a-", agent_id),)
        if run_id is not None:
            ns += (hash_label("r-", run_id),)
        return ns

    @contextlib.contextmanager
    def _user_lock(self, user_id: str) -> Iterator[None]:
        with self._locks_guard:
            lock = self._locks.setdefault(user_id, threading.Lock())
        with lock:
            yield

    # --- policy ------------------------------------------------------------------------

    def _evaluate(
        self,
        ctx: _Ctx,
        value: dict[str, Any] | None,
        op: WriteOp,
        head: VersionRecord | None,
        claimed_type: MemoryType | None = None,
    ) -> tuple[Decision, Any, bool]:
        target_type = None
        protected = False
        if head is not None and head.verified and head.signed_fields is not None:
            target_type = MemoryType(head.fields.memory_type)
            protected = head.fields.protected
        request = WriteRequest(
            value=value,
            op=op,
            target_scope=Scope(
                self._scope, None if self._scope is not ScopeKind.USER else ctx.principal
            ),
            principal_scope=Scope(ScopeKind.USER, ctx.principal),
            grants=self._grants,
            target_protected=protected,
            target_type=target_type,
            claimed_type=claimed_type,
        )
        result = self._engine.evaluate(request)
        decision = result.decision
        if decision.action is Outcome.DENY:
            if not self.probe_result.ok:
                raise MemoryWriteRefused("adapter_probe_failure")
            raise MemoryWriteDenied(",".join(decision.rule_ids) or "denied")
        return decision, result.value, protected

    @staticmethod
    def _provenance(
        decision: Decision, agent_id: str | None, run_id: str | None
    ) -> dict[str, object]:
        prov: dict[str, object] = {
            "policy_id": decision.policy_id,
            "outcome": decision.outcome.value,
            "rule_ids": list(decision.rule_ids),
            "fired_signals": list(decision.fired_signals),
            "backend": MEM0,
        }
        if agent_id is not None:
            prov["agent_id"] = agent_id
        if run_id is not None:
            prov["run_id"] = run_id
        return prov

    def _quarantine_submit(
        self,
        decision: Decision,
        ns: tuple[str, ...],
        key: str,
        content: str,
        protected: bool,
        prov: dict[str, object],
    ) -> str:
        try:
            res = self._quarantine.submit(
                decision=decision,
                namespace=ns,
                key=key,
                content=content,
                scope=self._scope.value,
                protected=protected,
                bundle_id=decision.policy_id,
                provenance=prov,
            )
        except QuarantineRefused as exc:
            raise MemoryWriteRefused(exc.reason) from None
        return res.item_id

    def _sign(
        self,
        ns: tuple[str, ...],
        key: str,
        value: dict[str, Any] | None,
        decision: Decision,
        protected: bool,
        prov: dict[str, object],
        *,
        deleted_from: VersionRecord | None = None,
    ) -> VersionRecord:
        if deleted_from is not None:
            return self._ledger.append_version(
                namespace=ns,
                key=key,
                content=None,
                scope=self._scope.value,
                trust_level=decision.write_trust,
                effective_type=deleted_from.fields.effective_type,
                memory_type=deleted_from.fields.memory_type,
                protected=protected,
                status="deleted",
                bundle_id=decision.policy_id,
                provenance=prov,
            )
        effective = decision.effective_type
        return self._ledger.append_version(
            namespace=ns,
            key=key,
            content=serialize(value or {}),
            scope=self._scope.value,
            trust_level=decision.write_trust,
            effective_type=effective.value if effective else "data",
            memory_type=decision.memory_type.value,
            protected=protected,
            status="active",
            bundle_id=decision.policy_id,
            provenance=prov,
        )

    @staticmethod
    def _ref(record: VersionRecord) -> dict[str, object]:
        return {
            "memory_id": record.memory_id,
            "version_no": record.version_no,
            "signature": record.signature,
        }

    @staticmethod
    def _summary(record: VersionRecord, decision: Decision) -> dict[str, object]:
        return {
            "outcome": "committed",
            "memory_id": record.memory_id,
            "version_no": record.version_no,
            "trust": decision.write_trust.label,
        }

    # --- add ---------------------------------------------------------------------------

    def add(
        self,
        messages: Any,
        *,
        user_id: str | None = None,
        agent_id: str | None = None,
        run_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        infer: bool = False,
    ) -> dict[str, Any]:
        ctx = self._context()
        if user_id is not None and user_id != ctx.principal:
            diagnostics.record("principal_mismatch")
            _log.warning("principal_mismatch", extra={"adapter": MEM0})
            raise MemoryWriteDenied("principal_mismatch")
        agent, run = _check_id(agent_id), _check_id(run_id)
        md = _clean_metadata(metadata)
        msgs = _messages(messages)
        if infer:
            if self._mode != "infer":
                raise MemoryWriteDenied("infer_mode_disabled")
            return self._add_infer(ctx, msgs, md, agent, run)
        ns = self._ns(ctx, agent, run)
        plans = []
        for msg in msgs:
            if msg["role"] == "system":
                continue
            value = {"memory": msg["content"], "metadata": md}
            decision, stripped, _ = self._evaluate(ctx, value, WriteOp.CREATE, None)
            plans.append((msg, decision, stripped))  # every message is checked before any write
        results: list[dict[str, Any]] = []
        for msg, decision, stripped in plans:
            key = "k-" + uuid.uuid4().hex
            prov = self._provenance(decision, agent, run)
            if decision.action is Outcome.QUARANTINE:
                item_id = self._quarantine_submit(
                    decision, ns, key, serialize(stripped), False, prov
                )
                results.append(
                    {
                        "id": None,
                        "memory": None,
                        "event": "QUARANTINED",
                        "mnemowall": {"outcome": "quarantined", "item_id": item_id},
                    }
                )
                continue
            record = self._sign(ns, key, stripped, decision, False, prov)
            stored = self._store_new(ctx, msg, stripped, key, record, agent, run, decision, prov)
            results.append(
                {
                    "id": stored,
                    "memory": stripped["memory"],
                    "event": "ADD",
                    "mnemowall": self._summary(record, decision),
                }
            )
        return {"results": results}

    def _store_new(
        self,
        ctx: _Ctx,
        msg: Mapping[str, str],
        value: dict[str, Any],
        key: str,
        record: VersionRecord,
        agent: str | None,
        run: str | None,
        decision: Decision,
        prov: dict[str, object],
    ) -> str:
        outgoing = {"role": msg.get("role", "user"), "content": value["memory"]}
        if msg.get("name"):
            outgoing["name"] = msg["name"]
        meta = {**value["metadata"], KEY_FIELD: key, REF_FIELD: self._ref(record)}
        mem_id = self._backend(
            "add",
            [outgoing],
            user_id=ctx.user_id,
            agent_id=agent,
            run_id=run,
            metadata=meta,
            infer=False,
        )
        if not isinstance(mem_id, str):
            self._sign(
                self._ns(ctx, agent, run), key, None, decision, False, prov, deleted_from=record
            )
            raise MemoryWriteRefused("backend_error")
        return mem_id

    def _backend(self, name: str, *args: Any, **kwargs: Any) -> Any:
        """Call Mem0 for a write. Its errors may quote content, so none of them escapes (M1a-22):
        the outcome is decided inside ``except`` and raised outside it, with no context attached.
        For ``add`` the new Mem0 id is returned, or ``None`` on failure.
        """
        failed = False
        result: Any = None
        try:
            result = self._call(name, *args, **kwargs)
            if name == "add":
                (res,) = result["results"]
                result = res["id"]
        except Exception:  # noqa: BLE001 - deliberately broad: nothing from Mem0 is re-raised
            failed = True
        if failed:
            diagnostics.record("backend_error")
            _log.error("backend_error", extra={"adapter": MEM0, "op": name})
            if name == "add":
                return None
            raise MemoryWriteRefused("backend_error")
        return result

    # --- infer mode (beta, detective; D40) -----------------------------------------------

    def _add_infer(
        self,
        ctx: _Ctx,
        msgs: list[dict[str, str]],
        md: dict[str, Any],
        agent: str | None,
        run: str | None,
    ) -> dict[str, Any]:  # pragma: no cover - unreachable until M1b-03 enables infer mode
        raise MemoryWriteDenied("infer_mode_disabled")

    # --- reads -------------------------------------------------------------------------

    def _owned(self, ctx: _Ctx, items: Sequence[Any]) -> list[dict[str, Any]]:
        mine = [
            dict(i) for i in items if isinstance(i, Mapping) and i.get("user_id") == ctx.user_id
        ]
        if len(mine) != len(items):
            diagnostics.record("foreign_namespace_filtered", len(items) - len(mine))
            _log.error("foreign_namespace_filtered", extra={"count": len(items) - len(mine)})
        return mine

    def _parse(self, item: Mapping[str, Any]) -> tuple[str, dict[str, Any], str | None, Any]:
        raw_md = item.get("metadata")
        md = dict(raw_md) if isinstance(raw_md, Mapping) else {}
        key = md.pop(KEY_FIELD, None)
        ref = md.pop(REF_FIELD, None)
        md, _ = strip_returned(md, None)
        text = item.get("memory")
        return (
            (text if isinstance(text, str) else ""),
            md,
            (key if isinstance(key, str) else None),
            ref,
        )

    def _backend_item(
        self, ctx: _Ctx, item: Mapping[str, Any]
    ) -> tuple[BackendItem, str, dict[str, Any]]:
        text, md, key, raw_ref = self._parse(item)
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
            content = serialize({"memory": text, "metadata": md})
        except (TypeError, ValueError):
            content, ref = repr(sorted(md)), None
        try:
            ns = self._ns(ctx, _check_id(item.get("agent_id")), _check_id(item.get("run_id")))
        except NamespaceError:
            ns = (*ctx.prefix, MEM0, "invalid")
        score = item.get("score")
        backend = BackendItem(
            content=content,
            ref=ref,
            created_ms=_created_ms(item.get("created_at")),
            relevance=float(score) if isinstance(score, int | float) else None,
            location=(ns, key or ""),
            text=text,
        )
        return backend, text, md

    def _read(self, ctx: _Ctx, items: Sequence[Any], query: str | None) -> list[dict[str, Any]]:
        mine = self._owned(ctx, items)
        prepared = [self._backend_item(ctx, i) for i in mine]
        read = read_memories(
            self._ledger,
            [b for b, _, _ in prepared],
            session=ctx.session,
            policy=self._policy,
            query=query,
        )
        by_index = {w.index: w for w in read.wrapped.items}
        out = []
        for i, (item, (_, text, md), check) in enumerate(
            zip(mine, prepared, read.checks, strict=True)
        ):
            res = {k: v for k, v in item.items() if k not in ("metadata", "memory", "hash")}
            res["memory"] = by_index[i].text
            if md:
                res["metadata"] = md
            res[LABEL_KEY] = {
                "label": by_index[i].label,
                "trust": check.trust.label,
                "verified": check.verified,
                "stale": check.stale,
                "memory_id": check.memory_id,
                "version_no": check.version_no,
                "raw": text,
            }
            out.append(res)
        return out

    def _fetch(self, ctx: _Ctx, memory_id: object) -> dict[str, Any] | None:
        if not isinstance(memory_id, str) or not memory_id:
            return None
        found = None
        with contextlib.suppress(ValueError):
            found = self._call("get", memory_id)
        if not isinstance(found, Mapping):
            return None
        if found.get("user_id") != ctx.user_id:
            # Mem0's id lookup is unscoped (V3), so this is the caller probing an id outside its
            # scope, not the backend misbehaving: counted separately, reported as not found.
            diagnostics.record("foreign_id_lookup")
            _log.warning("foreign_id_lookup", extra={"adapter": MEM0})
            return None
        return dict(found)

    def _track(self, ctx: _Ctx, item: dict[str, Any]) -> _Tracked:
        backend, text, md = self._backend_item(ctx, item)
        _, _, key, _ = self._parse(item)
        check = verify_item(self._ledger, backend)
        head = None
        if check.verified and not check.stale:
            head = self._ledger.head(check.memory_id)
        return _Tracked(
            item,
            text,
            md,
            key if head is not None else None,
            _check_id(item.get("agent_id")),
            _check_id(item.get("run_id")),
            head,
        )

    def get(self, memory_id: str) -> dict[str, Any] | None:
        ctx = self._context()
        item = self._fetch(ctx, memory_id)
        if item is None:
            return None
        return self._read(ctx, [item], None)[0]

    def _scoped(self, ctx: _Ctx, filters: Any) -> dict[str, Any]:
        eq, agent, run = _filters(filters)
        scoped: dict[str, Any] = {**eq, "user_id": ctx.user_id}
        if agent is not None:
            scoped["agent_id"] = agent
        if run is not None:
            scoped["run_id"] = run
        return scoped

    def get_all(
        self, *, filters: Mapping[str, Any] | None = None, top_k: int = 100
    ) -> dict[str, Any]:
        ctx = self._context()
        found = self._call("get_all", filters=self._scoped(ctx, filters), top_k=top_k)
        return {"results": self._read(ctx, list(found.get("results", [])), None)}

    def search(
        self,
        query: str,
        *,
        top_k: int = 20,
        filters: Mapping[str, Any] | None = None,
        threshold: float = 0.1,
    ) -> dict[str, Any]:
        ctx = self._context()
        if not isinstance(query, str) or not query.strip():
            raise NamespaceError("invalid_query")
        found = self._call(
            "search", query, top_k=top_k, filters=self._scoped(ctx, filters), threshold=threshold
        )
        return {"results": self._read(ctx, list(found.get("results", [])), query)}

    # --- update / delete ---------------------------------------------------------------

    def update(
        self,
        memory_id: str,
        text: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        ctx = self._context()
        item = self._fetch(ctx, memory_id)
        if item is None:
            raise MemoryNotFound
        if text is not None and (not isinstance(text, str) or not text):
            raise InvalidMessage
        tracked = self._track(ctx, item)
        merged = {**tracked.metadata, **_clean_metadata(metadata)}
        return self._update_tracked(ctx, memory_id, tracked, text or tracked.text, merged, None)

    def _update_tracked(
        self,
        ctx: _Ctx,
        mem_id: str,
        tracked: _Tracked,
        text: str,
        metadata: dict[str, Any],
        claimed_type: MemoryType | None,
    ) -> dict[str, Any]:
        live = tracked.head is not None and tracked.head.status == "active"
        value = {"memory": text, "metadata": metadata}
        decision, stripped, protected = self._evaluate(
            ctx, value, WriteOp.UPDATE if live else WriteOp.CREATE, tracked.head, claimed_type
        )
        key = tracked.key or "k-" + uuid.uuid4().hex
        ns = self._ns(ctx, tracked.agent_id, tracked.run_id)
        prov = self._provenance(decision, tracked.agent_id, tracked.run_id)
        if decision.action is Outcome.QUARANTINE:
            item_id = self._quarantine_submit(
                decision, ns, key, serialize(stripped), protected, prov
            )
            return {
                "message": "Memory update quarantined for review.",
                LABEL_KEY: {"outcome": "quarantined", "item_id": item_id},
            }
        record = self._sign(ns, key, stripped, decision, protected, prov)
        meta = {**stripped["metadata"], KEY_FIELD: key, REF_FIELD: self._ref(record)}
        self._backend("update", mem_id, text=stripped["memory"], metadata=meta)
        return {
            "message": "Memory updated successfully!",
            LABEL_KEY: self._summary(record, decision),
        }

    def delete(self, memory_id: str) -> dict[str, Any]:
        ctx = self._context()
        item = self._fetch(ctx, memory_id)
        if item is None:
            raise MemoryNotFound
        return self._delete_tracked(ctx, memory_id, self._track(ctx, item))

    def _delete_tracked(self, ctx: _Ctx, mem_id: str, tracked: _Tracked) -> dict[str, Any]:
        decision, _, protected = self._evaluate(ctx, None, WriteOp.DELETE, tracked.head)
        ns = self._ns(ctx, tracked.agent_id, tracked.run_id)
        prov = self._provenance(decision, tracked.agent_id, tracked.run_id)
        key = tracked.key or "k-" + uuid.uuid4().hex
        if decision.action is Outcome.QUARANTINE:
            item_id = self._quarantine_submit(decision, ns, key, "", protected, prov)
            return {
                "message": "Memory deletion quarantined for review.",
                LABEL_KEY: {"outcome": "quarantined", "item_id": item_id},
            }
        if tracked.head is not None and tracked.head.status == "active" and tracked.key:
            self._sign(ns, key, None, decision, protected, prov, deleted_from=tracked.head)
        self._backend("delete", mem_id)
        return {"message": "Memory deleted successfully!", LABEL_KEY: {"outcome": "deleted"}}

    def delete_all(
        self, *, agent_id: str | None = None, run_id: str | None = None
    ) -> dict[str, int]:
        ctx = self._context()
        filters: dict[str, Any] = {}
        if agent_id is not None:
            filters["agent_id"] = agent_id
        if run_id is not None:
            filters["run_id"] = run_id
        found = self._call("get_all", filters=self._scoped(ctx, filters), top_k=MAX_SCAN)
        counts = {"deleted": 0, "quarantined": 0, "denied": 0}
        for item in self._owned(ctx, list(found.get("results", []))):
            try:
                out = self._delete_tracked(ctx, item["id"], self._track(ctx, item))
            except MemoryWriteDenied:
                counts["denied"] += 1
                continue
            counts["quarantined" if out[LABEL_KEY]["outcome"] == "quarantined" else "deleted"] += 1
        return counts

    # --- rollback (I7) -----------------------------------------------------------------

    def rollback(self, memory_id: str, to_version: int) -> RollbackResult:
        """Restore ``to_version`` as a new write through full policy, at its stored trust (I7)."""
        ctx = self._context()
        record = self._ledger.version(memory_id, to_version)
        if record is None:
            raise RollbackRefused("unknown_version")
        if not record.verified or record.signed_fields is None:
            raise RollbackRefused("unverified")
        if record.purged:
            raise RollbackRefused("content_purged")
        fields = record.fields
        ns = tuple(fields.namespace)
        base = (*ctx.prefix, MEM0)
        if ns[: len(base)] != base or record.key is None:
            raise RollbackRefused("not_in_scope")
        head = self._ledger.head(memory_id)
        before = head.version_no if head is not None else 0
        prov = self._ledger_provenance(head)
        agent, run = prov.get("agent_id"), prov.get("run_id")
        agent = agent if isinstance(agent, str) else None
        run = run if isinstance(run, str) else None
        if self._ns(ctx, agent, run) != ns:
            raise RollbackRefused("not_in_scope")
        if ctx.session is not None:
            ctx.session.register_memory_read(
                memory_id,
                stored_trust=TRUST_BY_LABEL.get(fields.trust_level, TrustLevel.UNKNOWN),
                verified=True,
                stale=False,
            )
        live = self._live_items(ctx, record.key, agent, run)
        if record.status != "active" or record.content is None:
            for item in live:
                self._delete_tracked(ctx, item["id"], self._track(ctx, item))
            outcome = "deleted"
        else:
            value = json.loads(record.content)
            claimed = MemoryType(fields.memory_type)
            if live:
                tracked = self._track(ctx, live[0])
                if tracked.head is None:  # the live copy is unverified: restore over it
                    tracked = dataclasses.replace(tracked, key=record.key, head=head)
                self._update_tracked(
                    ctx, live[0]["id"], tracked, value["memory"], dict(value["metadata"]), claimed
                )
            else:
                self._restore_new(ctx, record.key, value, agent, run, head, claimed)
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

    def _ledger_provenance(self, head: VersionRecord | None) -> dict[str, object]:
        if head is None:
            return {}
        return self._ledger.provenance(head.memory_id, head.version_no) or {}

    def _live_items(
        self, ctx: _Ctx, key: str, agent: str | None, run: str | None
    ) -> list[dict[str, Any]]:
        filters: dict[str, Any] = {"user_id": ctx.user_id, KEY_FIELD: key}
        if agent is not None:
            filters["agent_id"] = agent
        if run is not None:
            filters["run_id"] = run
        found = self._call("get_all", filters=filters, top_k=MAX_SCAN)
        return self._owned(ctx, list(found.get("results", [])))

    def _restore_new(
        self,
        ctx: _Ctx,
        key: str,
        value: Mapping[str, Any],
        agent: str | None,
        run: str | None,
        head: VersionRecord | None,
        claimed: MemoryType,
    ) -> None:
        stored = {"memory": value["memory"], "metadata": dict(value["metadata"])}
        live = head is not None and head.status == "active"
        decision, stripped, protected = self._evaluate(
            ctx, stored, WriteOp.UPDATE if live else WriteOp.CREATE, head, claimed
        )
        ns = self._ns(ctx, agent, run)
        prov = self._provenance(decision, agent, run)
        if decision.action is Outcome.QUARANTINE:
            self._quarantine_submit(decision, ns, key, serialize(stripped), protected, prov)
            return
        record = self._sign(ns, key, stripped, decision, protected, prov)
        self._store_new(ctx, {"role": "user"}, stripped, key, record, agent, run, decision, prov)


class GuardedMemory(_Core):
    """A Mem0 ``Memory`` behind Mnemowall policy (strict by default)."""

    def __init__(
        self,
        inner: Memory,
        *,
        ledger: Ledger,
        quarantine: Quarantine,
        tenant_id: str,
        scope: str = "user",
        grants: Sequence[str] = (),
        policy: CompiledPolicy | None = None,
        mode: Literal["strict", "infer"] = "strict",
    ) -> None:
        super().__init__(
            inner,
            ledger=ledger,
            quarantine=quarantine,
            tenant_id=tenant_id,
            scope=scope,
            grants=grants,
            policy=policy,
            mode=mode,
            flavour=Memory,
        )

    def __repr__(self) -> str:
        return (
            f"GuardedMemory(tenant_id={self._tenant_id!r}, scope={self._scope.value!r},"
            f" mode={self._mode!r})"
        )

    def _call(self, name: str, *args: Any, **kwargs: Any) -> Any:
        return getattr(self._inner, name)(*args, **kwargs)


class _AsyncBridge(_Core):
    """Runs the shared core in a worker thread; inner coroutines run on the caller's loop."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._local = threading.local()

    def _call(self, name: str, *args: Any, **kwargs: Any) -> Any:
        loop: asyncio.AbstractEventLoop = self._local.loop
        coro = getattr(self._inner, name)(*args, **kwargs)
        return asyncio.run_coroutine_threadsafe(coro, loop).result()

    async def run(self, method: str, *args: Any, **kwargs: Any) -> Any:
        loop = asyncio.get_running_loop()

        def work() -> Any:
            self._local.loop = loop
            try:
                return getattr(self, method)(*args, **kwargs)
            finally:
                self._local.loop = None

        return await asyncio.to_thread(work)


class GuardedAsyncMemory:
    """A Mem0 ``AsyncMemory`` behind Mnemowall policy. Same behaviour as :class:`GuardedMemory`."""

    def __init__(
        self,
        inner: AsyncMemory,
        *,
        ledger: Ledger,
        quarantine: Quarantine,
        tenant_id: str,
        scope: str = "user",
        grants: Sequence[str] = (),
        policy: CompiledPolicy | None = None,
        mode: Literal["strict", "infer"] = "strict",
    ) -> None:
        self._core = _AsyncBridge(
            inner,
            ledger=ledger,
            quarantine=quarantine,
            tenant_id=tenant_id,
            scope=scope,
            grants=grants,
            policy=policy,
            mode=mode,
            flavour=AsyncMemory,
        )

    def __repr__(self) -> str:
        return "GuardedAsyncMemory()"

    @property
    def probe_result(self) -> ProbeResult:
        return self._core.probe_result

    async def add(self, messages: Any, **kwargs: Any) -> dict[str, Any]:
        return dict(await self._core.run("add", messages, **kwargs))

    async def get(self, memory_id: str) -> dict[str, Any] | None:
        out = await self._core.run("get", memory_id)
        return None if out is None else dict(out)

    async def get_all(self, **kwargs: Any) -> dict[str, Any]:
        return dict(await self._core.run("get_all", **kwargs))

    async def search(self, query: str, **kwargs: Any) -> dict[str, Any]:
        return dict(await self._core.run("search", query, **kwargs))

    async def update(self, memory_id: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return dict(await self._core.run("update", memory_id, *args, **kwargs))

    async def delete(self, memory_id: str) -> dict[str, Any]:
        return dict(await self._core.run("delete", memory_id))

    async def delete_all(self, **kwargs: Any) -> dict[str, int]:
        return dict(await self._core.run("delete_all", **kwargs))

    async def rollback(self, memory_id: str, to_version: int) -> RollbackResult:
        out: RollbackResult = await self._core.run("rollback", memory_id, to_version)
        return out


__all__ = [
    "KEY_FIELD",
    "LABEL_KEY",
    "REF_FIELD",
    "GuardedAsyncMemory",
    "GuardedMemory",
    "InvalidMessage",
    "MemoryNotFound",
    "MemoryWriteDenied",
    "MemoryWriteRefused",
    "NamespaceError",
    "ProbeResult",
    "RollbackRefused",
    "RollbackResult",
    "derive_user_id",
    "probe",
    "telemetry_enabled",
]
