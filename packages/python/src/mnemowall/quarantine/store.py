"""Quarantine store, encrypted pending buffer and review (M1a-14).

Spec: §1.3, §3.4 and I8; ADR-0020 D19 and D20.

**Where quarantined writes live.** In ``quarantine.db``, a SQLite file separate from the ledger
and from any memory backend; nothing in the read path opens it. Each item's payload (namespace,
key, content, provenance) is encrypted with AES-256-GCM under the ``quarantine-enc`` key. The
AAD binds the store id, the item id, its timestamps and its content-free metadata (trust, types,
rules), so editing any of them makes the item unusable rather than more trusted.

**When the store can't be written** (§1.3): :func:`mnemowall.policy.route_quarantine` decides.
By default the item goes to ``pending.buf``, an append-only file of records encrypted under the
``buffer-enc`` key, capped at 512 items or 8 MiB (caps can only be lowered). Full -> the write is
refused (:class:`QuarantineRefused`); it is never dropped. The buffer drains into the store
exactly once per item. A record that fails authentication is discarded and counted.

**Review (I8).** ``approve`` commits the stored value to the ledger as ``effective_type = data``
with its original trust. ``promote`` is the only path to an instruction or procedure type: it
starts a delay of at least 24 h (one-admin path, D20), during which every SDK start warns, and
it can be cancelled. Expiry (7 days by default) always wins: an expired item is denied and never
commits. Every review action is appended to the ledger, and the ledger is checked before acting,
so rolling back a status in ``quarantine.db`` can't resurrect a rejected item.

The reviewer is the OS user unless given, recorded with ``actor_verified = False``: a local CLI
can't verify a person, and an agent with shell access could run it. The delay and the
notification are the control (D20).
"""

from __future__ import annotations

import base64
import builtins
import contextlib
import dataclasses
import getpass
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mnemowall._log import get_logger
from mnemowall.core import diagnostics
from mnemowall.core.files import PrivatePathError, private_dir, private_file
from mnemowall.core.jcs import JCSError, canonicalize
from mnemowall.core.model import EffectiveType, Outcome
from mnemowall.keys import KeyProvider, KeyUnavailable, Purpose
from mnemowall.ledger import Ledger, LedgerError, VersionRecord
from mnemowall.policy import CompiledPolicy, Decision, route_quarantine

SCHEMA_VERSION: Final = 1
DEFAULT_BUFFER_MAX_ITEMS: Final = 512
DEFAULT_BUFFER_MAX_BYTES: Final = 8 * 1024 * 1024
MIN_PROMOTION_DELAY_S: Final = 86_400
DEFAULT_RETENTION_DAYS: Final = 90
RESOLVED: Final = frozenset({"approved_as_data", "promoted", "rejected", "expired"})
_TERMINAL_ACTIONS: Final = {
    "approve": "approved_as_data",
    "promote": "promoted",
    "reject": "rejected",
    "expire": "expired",
}
_BUFFER_DOMAIN: Final = b"mnemowall/pending-buffer/v1\x00"
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_DAY_MS: Final = 86_400_000

_SCHEMA: Final = (
    "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS items ("
    " item_id TEXT PRIMARY KEY, created_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL,"
    " status TEXT NOT NULL, meta TEXT NOT NULL, promotion_due_ms INTEGER, resolved_ms INTEGER,"
    " nonce BLOB, ct BLOB)",
)

_log = get_logger("quarantine")

try:  # POSIX advisory lock for the pending buffer
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows
    _fcntl = None  # type: ignore[assignment]


class QuarantineError(Exception):
    """A quarantine or review action was refused. ``reason`` is a fixed code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class QuarantineExpired(QuarantineError):
    """The item passed its expiry: on_expiry is ``deny``, so it can never commit."""

    def __init__(self) -> None:
        super().__init__("expired")


class QuarantineRefused(QuarantineError):
    """Neither the store nor the pending buffer could take the write; the caller must refuse it."""


@dataclass(frozen=True, slots=True)
class SubmitResult:
    item_id: str
    route: str  # "quarantine_store" or "pending_buffer"
    decision: Decision = field(repr=False)


@dataclass(frozen=True, slots=True)
class ItemSummary:
    """What ``review list`` shows. No content, no identifiers."""

    item_id: str
    status: str
    created_ms: int
    expires_ms: int
    age_s: int
    trust_level: str
    memory_type: str
    rule_ids: tuple[str, ...]
    fired_signals: tuple[str, ...]
    promotion_due_ms: int | None


@dataclass(frozen=True)
class ItemDetail:
    """What ``review show`` decrypts. Render with :func:`mnemowall.core.render.render_untrusted`."""

    summary: ItemSummary
    namespace: tuple[str, ...] = field(repr=False)
    key: str = field(repr=False)
    content: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class _Item:
    item_id: str
    created_ms: int
    expires_ms: int
    status: str
    meta: str
    promotion_due_ms: int | None
    resolved_ms: int | None
    nonce: bytes | None
    ct: bytes | None


def _actor(value: str | None) -> str:
    if value is None:
        try:
            value = getpass.getuser()
        except Exception:  # noqa: BLE001 - no user database entry; fall back to a fixed label
            value = "unknown"
    return value if _ID.fullmatch(value) else "unknown"


class Quarantine:
    """The local quarantine store and review actions for one tenant. Thread-safe."""

    @classmethod
    def open(
        cls,
        directory: Path | str,
        provider: KeyProvider,
        *,
        ledger: Ledger,
        policy: CompiledPolicy,
        tenant_id: str,
        clock: Callable[[], float] = time.time,
        actor: str | None = None,
        promotion_delay_s: int = MIN_PROMOTION_DELAY_S,
        buffer_max_items: int = DEFAULT_BUFFER_MAX_ITEMS,
        buffer_max_bytes: int = DEFAULT_BUFFER_MAX_BYTES,
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> Quarantine:
        """Open (or create) the store in ``directory`` and drain any buffered items."""
        return cls(
            directory,
            provider,
            ledger=ledger,
            policy=policy,
            tenant_id=tenant_id,
            clock=clock,
            actor=actor,
            promotion_delay_s=promotion_delay_s,
            buffer_max_items=buffer_max_items,
            buffer_max_bytes=buffer_max_bytes,
            retention_days=retention_days,
        )

    def __init__(
        self,
        directory: Path | str,
        provider: KeyProvider,
        *,
        ledger: Ledger,
        policy: CompiledPolicy,
        tenant_id: str,
        clock: Callable[[], float] = time.time,
        actor: str | None = None,
        promotion_delay_s: int = MIN_PROMOTION_DELAY_S,
        buffer_max_items: int = DEFAULT_BUFFER_MAX_ITEMS,
        buffer_max_bytes: int = DEFAULT_BUFFER_MAX_BYTES,
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> None:
        directory = Path(directory)
        try:
            private_dir(directory)
            private_file(directory / "quarantine.db")
            private_file(directory / "pending.buf")
        except PrivatePathError as exc:
            raise QuarantineError(exc.reason) from None
        self._dir = directory
        self._ledger = ledger
        self._policy = policy
        self._tenant_id = tenant_id
        self._clock = clock
        self._actor = _actor(actor)
        self._lock = threading.RLock()
        self._delay_ms = (
            _stricter_or_default(
                promotion_delay_s, MIN_PROMOTION_DELAY_S, "promotion_delay", larger_is_stricter=True
            )
            * 1000
        )
        self._max_items = _stricter_or_default(
            buffer_max_items, DEFAULT_BUFFER_MAX_ITEMS, "buffer_max_items", larger_is_stricter=False
        )
        self._max_bytes = _stricter_or_default(
            buffer_max_bytes, DEFAULT_BUFFER_MAX_BYTES, "buffer_max_bytes", larger_is_stricter=False
        )
        if type(retention_days) is not int or not 1 <= retention_days <= 3650:
            raise QuarantineError("retention_out_of_range")
        self._retention_ms = retention_days * _DAY_MS
        con = sqlite3.connect(
            directory / "quarantine.db", timeout=30.0, isolation_level=None, check_same_thread=False
        )
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=NORMAL")
            con.execute("PRAGMA secure_delete=ON")
            self._store_id = _init_schema(con, tenant_id)
        except BaseException:
            con.close()
            raise
        self._con = con
        try:
            keys = provider.load()
        except KeyUnavailable:
            self._store_aead: AESGCM | None = None
            self._buffer_aead: AESGCM | None = None
            diagnostics.record("quarantine_keys_unavailable")
            _log.warning("quarantine_keys_unavailable", extra={"reason": "keys_unavailable"})
        else:
            self._store_aead = AESGCM(keys.derive(Purpose.QUARANTINE_ENC))
            self._buffer_aead = AESGCM(keys.derive(Purpose.BUFFER_ENC))
        if not self.locked:
            self.drain()
        pending = self.pending_promotions()
        if pending:
            diagnostics.record("promotion_pending", len(pending))
            _log.warning("promotion_pending", extra={"count": len(pending)})

    @property
    def locked(self) -> bool:
        """True when keys couldn't be loaded: submissions are refused, content can't be shown."""
        return self._store_aead is None

    @property
    def directory(self) -> Path:
        return self._dir

    @property
    def buffer_limits(self) -> tuple[int, int]:
        return self._max_items, self._max_bytes

    def close(self) -> None:
        with self._lock:
            self._con.close()

    def __repr__(self) -> str:
        return f"Quarantine(tenant_id={self._tenant_id!r}, locked={self.locked})"

    # --- helpers ---------------------------------------------------------------------------

    def _now_ms(self) -> int:
        return int(self._clock() * 1000)

    def _aad(self, item_id: str, created_ms: int, expires_ms: int, meta: str) -> bytes:
        return canonicalize(
            {
                "store": self._store_id,
                "item_id": item_id,
                "created_ms": created_ms,
                "expires_ms": expires_ms,
                "meta": meta,
            }
        )

    @contextlib.contextmanager
    def _txn(self) -> Iterator[None]:
        with self._lock:
            self._con.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self._con.execute("ROLLBACK")
                raise
            self._con.execute("COMMIT")

    def _store_insert(self, row: Sequence[object]) -> int:
        with self._txn():
            cur = self._con.execute(
                "INSERT OR IGNORE INTO items (item_id, created_ms, expires_ms, status, meta,"
                " promotion_due_ms, resolved_ms, nonce, ct) VALUES (?, ?, ?, 'pending', ?, NULL,"
                " NULL, ?, ?)",
                tuple(row),
            )
            return cur.rowcount

    def _load(self, item_id: str) -> _Item:
        row = self._con.execute(
            "SELECT item_id, created_ms, expires_ms, status, meta, promotion_due_ms, resolved_ms,"
            " nonce, ct FROM items WHERE item_id = ?",
            (item_id,),
        ).fetchone()
        if row is None:
            raise QuarantineError("not_found")
        return _Item(*row)

    def _summary(self, item: _Item) -> ItemSummary:
        meta = json.loads(item.meta)
        return ItemSummary(
            item_id=item.item_id,
            status=item.status,
            created_ms=item.created_ms,
            expires_ms=item.expires_ms,
            age_s=max(0, (self._now_ms() - item.created_ms) // 1000),
            trust_level=str(meta["trust_level"]),
            memory_type=str(meta["memory_type"]),
            rule_ids=tuple(meta["rule_ids"]),
            fired_signals=tuple(meta["fired_signals"]),
            promotion_due_ms=item.promotion_due_ms,
        )

    def _payload(self, item: _Item) -> dict[str, Any]:
        if self._store_aead is None:
            raise QuarantineError("keys_unavailable")
        if item.ct is None or item.nonce is None:
            raise QuarantineError("content_purged")
        try:
            raw = self._store_aead.decrypt(
                item.nonce,
                item.ct,
                self._aad(item.item_id, item.created_ms, item.expires_ms, item.meta),
            )
        except (InvalidTag, ValueError):
            diagnostics.record("quarantine_item_corrupt")
            _log.error("quarantine_item_corrupt", extra={"op": "decrypt"})
            raise QuarantineError("item_corrupt") from None
        doc: dict[str, Any] = json.loads(raw)
        return doc

    def _event(self, action: str, item_id: str, **extra: object) -> None:
        self._ledger.append_event(
            "review",
            {"item_id": item_id, "action": action, "actor": self._actor, "actor_verified": False}
            | dict(extra),
        )

    def _ledger_resolution(self, item_id: str) -> str | None:
        for _, kind, fields in self._ledger.events():
            if kind == "review" and fields.get("item_id") == item_id:
                action = fields.get("action")
                if isinstance(action, str) and action in _TERMINAL_ACTIONS:
                    return _TERMINAL_ACTIONS[action]
        return None

    def _set_status(self, item_id: str, status: str, *, at_ms: int | None = None) -> None:
        with self._txn():
            self._con.execute(
                "UPDATE items SET status = ?, resolved_ms = ?, promotion_due_ms = NULL"
                " WHERE item_id = ?",
                (status, at_ms if at_ms is not None else self._now_ms(), item_id),
            )

    def _expire(self, item: _Item) -> None:
        self._set_status(item.item_id, "expired", at_ms=item.expires_ms)
        diagnostics.record("quarantine_expired")
        try:
            self._ledger.append_event(
                "review",
                {
                    "item_id": item.item_id,
                    "action": "expire",
                    "actor": "system",
                    "actor_verified": False,
                },
            )
        except LedgerError:
            _log.warning("quarantine_expiry_unlogged", extra={"reason": "ledger_unavailable"})

    def _sweep(self) -> None:
        now = self._now_ms()
        due = self._con.execute(
            "SELECT item_id, created_ms, expires_ms, status, meta, promotion_due_ms, resolved_ms,"
            " nonce, ct FROM items WHERE status = 'pending' AND expires_ms <= ?",
            (now,),
        ).fetchall()
        for row in due:
            self._expire(_Item(*row))

    def _actionable(self, item_id: str) -> _Item:
        """Load an item that can still be acted on; expiry always wins (D20, UT-PROMOTE-002)."""
        item = self._load(item_id)
        resolved = self._ledger_resolution(item_id)
        if resolved is not None and item.status != resolved:
            self._set_status(item_id, resolved)  # the ledger is the source of truth
            item = self._load(item_id)
        if item.status == "expired":
            raise QuarantineExpired
        if item.status in RESOLVED:
            raise QuarantineError("already_resolved")
        if self._now_ms() >= item.expires_ms:
            self._expire(item)
            raise QuarantineExpired
        return item

    # --- intake ----------------------------------------------------------------------------

    def submit(
        self,
        *,
        decision: Decision,
        namespace: Sequence[str],
        key: str,
        content: str,
        scope: str,
        protected: bool = False,
        bundle_id: str,
        provenance: Mapping[str, object],
        op: str = "write",
    ) -> SubmitResult:
        """Store a write the engine quarantined. Raises :class:`QuarantineRefused` if it can't.

        ``op="delete"`` marks a quarantined deletion: approving it commits a ``deleted`` version
        (M1b-14, D46), and it can't be promoted.
        """
        if decision.action is not Outcome.QUARANTINE:
            raise QuarantineError("not_quarantined")
        if op not in ("write", "delete"):
            raise QuarantineError("payload_invalid")
        if self._store_aead is None or self._buffer_aead is None:
            diagnostics.record("quarantine_refused")
            _log.error("quarantine_refused", extra={"reason": "keys_unavailable"})
            raise QuarantineRefused("keys_unavailable")
        if not isinstance(content, str) or not isinstance(key, str):
            raise QuarantineError("payload_invalid")
        try:
            payload = canonicalize(
                {
                    "namespace": list(namespace),
                    "key": key,
                    "content": content,
                    "provenance": dict(provenance),
                }
            )
        except (JCSError, TypeError):
            raise QuarantineError("payload_invalid") from None
        meta_doc: dict[str, object] = {
            "trust_level": decision.write_trust.label,
            "memory_type": decision.memory_type.value,
            "rule_ids": list(decision.rule_ids),
            "fired_signals": list(decision.fired_signals),
            "scope": scope,
            "protected": bool(protected),
            "bundle_id": bundle_id,
            "policy_id": decision.policy_id,
            "outcome": decision.outcome.value,
        }
        if op == "delete":
            meta_doc["op"] = "delete"
        meta = canonicalize(meta_doc).decode("utf-8")
        item_id = "q-" + uuid.uuid4().hex
        created = self._now_ms()
        expires = created + self._policy.quarantine_ttl_s * 1000
        nonce = os.urandom(12)
        ct = self._store_aead.encrypt(nonce, payload, self._aad(item_id, created, expires, meta))
        row = (item_id, created, expires, meta, nonce, ct)
        self.drain()
        failure_mode: str | None = None
        try:
            self._store_insert(row)
            route = "quarantine_store"
        except sqlite3.Error:
            diagnostics.record("quarantine_store_down")
            route, failure_mode = route_quarantine(
                self._policy,
                store_available=False,
                buffer_has_room=self._buffer_has_room(len(payload) + 512),
            )
            if route == "pending_buffer":
                route, failure_mode = self._buffer_append(row, failure_mode)
            if route == "refuse":
                diagnostics.record("quarantine_refused")
                _log.error("quarantine_refused", extra={"reason": failure_mode})
                raise QuarantineRefused(failure_mode or "refused") from None
        if failure_mode and failure_mode not in decision.failure_modes:
            decision = dataclasses.replace(
                decision, failure_modes=(*decision.failure_modes, failure_mode)
            )
        fields: dict[str, object] = {
            "item_id": item_id,
            "route": route,
            "trust_level": decision.write_trust.label,
            "memory_type": decision.memory_type.value,
            "expires_ms": expires,
        }
        if failure_mode:
            fields["failure_mode"] = failure_mode
        self._ledger.append_event("quarantine", fields)
        _log.info("quarantined", extra={"outcome": route, "failure_mode": failure_mode})
        return SubmitResult(item_id, route, decision)

    # --- pending buffer --------------------------------------------------------------------

    @property
    def _buffer_path(self) -> Path:
        return self._dir / "pending.buf"

    @contextlib.contextmanager
    def _buffer_locked(self, mode: str) -> Iterator[Any]:
        with self._lock, open(self._buffer_path, mode) as fh:
            if _fcntl is not None:
                _fcntl.flock(fh.fileno(), _fcntl.LOCK_EX)
            try:
                yield fh
            finally:
                if _fcntl is not None:
                    _fcntl.flock(fh.fileno(), _fcntl.LOCK_UN)

    def _buffer_records(self, data: bytes) -> tuple[list[bytes], int]:
        """Split the buffer into records; returns (records, rejected_tail_count)."""
        out: list[bytes] = []
        pos = 0
        while pos < len(data):
            if pos + 4 > len(data):
                return out, 1
            n = int.from_bytes(data[pos : pos + 4], "big")
            if n < 28 or pos + 4 + n > len(data):
                return out, 1
            out.append(data[pos + 4 : pos + 4 + n])
            pos += 4 + n
        return out, 0

    def _buffer_has_room(self, size: int) -> bool:
        data = self._buffer_path.read_bytes()
        records, _ = self._buffer_records(data)
        return len(records) < self._max_items and len(data) + size + 32 <= self._max_bytes

    def _buffer_append(
        self, row: tuple[Any, ...], failure_mode: str | None
    ) -> tuple[str, str | None]:
        if self._buffer_aead is None:
            return "refuse", "keys_unavailable"
        item_id, created, expires, meta, nonce, ct = row
        plain = canonicalize(
            {
                "item_id": item_id,
                "created_ms": created,
                "expires_ms": expires,
                "meta": meta,
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ct": base64.b64encode(ct).decode("ascii"),
            }
        )
        outer_nonce = os.urandom(12)
        record = outer_nonce + self._buffer_aead.encrypt(
            outer_nonce, plain, _BUFFER_DOMAIN + self._store_id.encode("ascii")
        )
        with self._buffer_locked("ab") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            records, _ = self._buffer_records(self._buffer_path.read_bytes())
            if len(records) >= self._max_items or size + 4 + len(record) > self._max_bytes:
                return "refuse", "pending_buffer_full"
            fh.write(len(record).to_bytes(4, "big") + record)
            fh.flush()
            os.fsync(fh.fileno())
        diagnostics.record("pending_buffer_write")
        return "pending_buffer", failure_mode

    def buffered(self) -> int:
        """How many items are waiting in the pending buffer (``doctor``)."""
        records, _ = self._buffer_records(self._buffer_path.read_bytes())
        return len(records)

    def drain(self) -> int:
        """Move buffered items into the store (exactly once per item). Returns how many."""
        if self._buffer_aead is None:
            return 0
        inserted = 0
        with self._buffer_locked("r+b") as fh:
            data = fh.read()
            if not data:
                return 0
            records, rejected = self._buffer_records(data)
            for record in records:
                try:
                    plain = self._buffer_aead.decrypt(
                        record[:12], record[12:], _BUFFER_DOMAIN + self._store_id.encode("ascii")
                    )
                    doc = json.loads(plain)
                    row = (
                        doc["item_id"],
                        doc["created_ms"],
                        doc["expires_ms"],
                        doc["meta"],
                        base64.b64decode(doc["nonce"]),
                        base64.b64decode(doc["ct"]),
                    )
                except (InvalidTag, ValueError, KeyError, TypeError):
                    rejected += 1
                    continue
                try:
                    inserted += self._store_insert(row)
                except sqlite3.Error:
                    return inserted  # store still down: keep the buffer for the next drain
            if rejected:
                diagnostics.record("buffer_record_rejected", rejected)
                _log.error("buffer_record_rejected", extra={"count": rejected})
            fh.seek(0)
            fh.truncate()
            fh.flush()
            os.fsync(fh.fileno())
        return inserted

    # --- review ----------------------------------------------------------------------------

    def list(self, *, include_resolved: bool = False) -> builtins.list[ItemSummary]:
        """Items for review, oldest first. Pending only unless ``include_resolved``. No content."""
        with self._lock:
            self.drain()
            self._sweep()
            where = "" if include_resolved else " WHERE status = 'pending'"
            rows = self._con.execute(
                "SELECT item_id, created_ms, expires_ms, status, meta, promotion_due_ms,"  # noqa: S608
                f" resolved_ms, nonce, ct FROM items{where} ORDER BY created_ms, item_id"
            ).fetchall()
            return [self._summary(_Item(*r)) for r in rows]

    def get(self, item_id: str) -> ItemSummary | None:
        with self._lock:
            self._sweep()
            try:
                return self._summary(self._load(item_id))
            except QuarantineError:
                return None

    def show(self, item_id: str) -> ItemDetail:
        """Decrypt an item for a human reviewer. Render the content with ``render_untrusted``."""
        with self._lock:
            self._sweep()
            item = self._load(item_id)
            payload = self._payload(item)
            return ItemDetail(
                summary=self._summary(item),
                namespace=tuple(payload["namespace"]),
                key=str(payload["key"]),
                content=str(payload["content"]),
            )

    def _commit(self, item: _Item, effective_type: str, action: str) -> VersionRecord:
        payload = self._payload(item)
        meta = json.loads(item.meta)
        deletion = meta.get("op") == "delete"
        record = self._ledger.append_version(
            namespace=tuple(payload["namespace"]),
            key=payload["key"],
            content=None if deletion else payload["content"],
            scope=meta["scope"],
            trust_level=meta["trust_level"],  # never raised by review (I8)
            effective_type=effective_type,
            memory_type=meta["memory_type"],
            protected=bool(meta["protected"]),
            status="deleted" if deletion else "active",
            bundle_id=meta["bundle_id"],
            provenance={**payload["provenance"], "quarantine_item": item.item_id, "review": action},
        )
        self._event(action, item.item_id, version_seq=record.seq)
        return record

    def approve(self, item_id: str) -> VersionRecord:
        """Commit the item as ``data`` with its original trust (I8). Returns the new version."""
        with self._lock:
            item = self._actionable(item_id)
            record = self._commit(item, EffectiveType.DATA.value, "approve")
            self._set_status(item_id, "approved_as_data")
            return record

    def reject(self, item_id: str) -> None:
        with self._lock:
            self._actionable(item_id)
            self._event("reject", item_id)
            self._set_status(item_id, "rejected")

    def promote(self, item_id: str) -> int:
        """Request promotion to the item's own type. Returns when it can be completed (ms)."""
        with self._lock:
            item = self._actionable(item_id)
            if json.loads(item.meta).get("op") == "delete":
                raise QuarantineError("not_promotable")
            if item.promotion_due_ms is not None:
                raise QuarantineError("promotion_already_pending")
            due = self._now_ms() + self._delay_ms
            self._event("promote_requested", item_id, due_ms=due)
            with self._txn():
                self._con.execute(
                    "UPDATE items SET promotion_due_ms = ? WHERE item_id = ?", (due, item_id)
                )
            diagnostics.record("promotion_pending")
            _log.warning("promotion_pending", extra={"count": 1})
            return due

    def cancel_promotion(self, item_id: str) -> None:
        with self._lock:
            item = self._actionable(item_id)
            if item.promotion_due_ms is None:
                raise QuarantineError("no_pending_promotion")
            self._event("promote_cancelled", item_id)
            with self._txn():
                self._con.execute(
                    "UPDATE items SET promotion_due_ms = NULL WHERE item_id = ?", (item_id,)
                )

    def complete_promotion(self, item_id: str) -> VersionRecord:
        """Commit with ``effective_type = memory_type`` once the delay has passed."""
        with self._lock:
            item = self._actionable(item_id)
            if item.promotion_due_ms is None:
                raise QuarantineError("no_pending_promotion")
            if self._now_ms() < item.promotion_due_ms:
                raise QuarantineError("promotion_delay_not_elapsed")
            meta = json.loads(item.meta)
            record = self._commit(item, str(meta["memory_type"]), "promote")
            self._set_status(item_id, "promoted")
            return record

    def pending_promotions(self) -> builtins.list[ItemSummary]:
        with self._lock:
            self._sweep()
            rows = self._con.execute(
                "SELECT item_id, created_ms, expires_ms, status, meta, promotion_due_ms,"
                " resolved_ms, nonce, ct FROM items WHERE status = 'pending'"
                " AND promotion_due_ms IS NOT NULL ORDER BY promotion_due_ms"
            ).fetchall()
            return [self._summary(_Item(*r)) for r in rows]

    def apply_retention(self) -> int:
        """Delete the payload of resolved items older than the retention TTL (D18)."""
        with self._lock:
            self._sweep()
            cutoff = self._now_ms() - self._retention_ms
            with self._txn():
                cur = self._con.execute(
                    "UPDATE items SET nonce = NULL, ct = NULL WHERE status != 'pending'"
                    " AND created_ms <= ? AND ct IS NOT NULL",
                    (cutoff,),
                )
            return cur.rowcount


def _stricter_or_default(value: int, default: int, name: str, *, larger_is_stricter: bool) -> int:
    if type(value) is not int or value <= 0:
        raise QuarantineError(f"{name}_invalid")
    stricter = value >= default if larger_is_stricter else value <= default
    if stricter:
        return value
    diagnostics.record("loosening_ignored")
    _log.warning("loosening_ignored", extra={"failure_mode": name})
    return default


def _init_schema(con: sqlite3.Connection, tenant_id: str) -> str:
    tables = {
        name
        for (name,) in con.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    if "meta" not in tables:
        if tables:
            raise QuarantineError("not_a_quarantine_store")
        con.execute("BEGIN IMMEDIATE")
        try:
            for statement in _SCHEMA:
                con.execute(statement)
            con.execute(
                "INSERT OR IGNORE INTO meta (k, v) VALUES ('schema_version', ?), ('tenant_id', ?),"
                " ('store_id', ?)",
                (str(SCHEMA_VERSION), tenant_id, uuid.uuid4().hex),
            )
        except BaseException:
            con.execute("ROLLBACK")
            raise
        con.execute("COMMIT")
    meta = dict(con.execute("SELECT k, v FROM meta").fetchall())
    try:
        version = int(meta["schema_version"])
        store_id = str(meta["store_id"])
        stored_tenant = meta["tenant_id"]
    except (KeyError, ValueError):
        raise QuarantineError("not_a_quarantine_store") from None
    if version != SCHEMA_VERSION:
        raise QuarantineError(
            "schema_too_new" if version > SCHEMA_VERSION else "schema_unsupported"
        )
    if stored_tenant != tenant_id:
        raise QuarantineError("tenant_mismatch")
    return store_id
