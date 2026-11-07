"""The local SQLite ledger (M1a-13; §3.6, §3.10, §3.12; ADR-0020 D15-D18).

**Layout.** One ``entries`` table holds every ledger event in a single global hash chain:

    hash = SHA-256(LEDGER_DOMAIN || JCS({seq, kind, ts_ms, memory_id, version_no, ref_hmac, body})
                   || prev_hash)

``body`` is canonical JSON that never contains content or identifiers. Content, namespaces,
memory keys, provenance records and read details live in ``blobs``, encrypted with AES-256-GCM.
Each ciphertext's AAD binds the ledger id, the table, the column and the entry's ``seq``, and the
entry body records ``SHA-256(nonce || ciphertext)``. A purge (erasure or retention) deletes a
blob and appends a ``purge`` entry, so the chain still verifies. Lookups use HMACs (D15).

**Signatures.** Each version carries an Ed25519 signature over its 14 signed fields
(:mod:`mnemowall.ledger.signing`), chained per memory through ``prev_version_signature``. The
global head (``seq``, ``hash``) is re-signed on every append.

**Honest limit (D17):** someone who deletes the newest entries *and* restores an older signed
head (for example from a backup) is detected only against an exported head
(``verify(expected_head=...)``).

**Durability (D17):** WAL with ``synchronous=NORMAL``; appends are serialized with
``BEGIN IMMEDIATE``. A power cut can lose the last few entries; the matching backend items then
read back ``unverified``.

Errors carry fixed reason codes only (§3.14).
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import itertools
import json
import os
import re
import sqlite3
import stat
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
from mnemowall.core.jcs import JCSError, canonicalize
from mnemowall.core.trust import TrustLevel
from mnemowall.keys import KeyProvider, KeySet, KeyUnavailable, Purpose
from mnemowall.ledger.signing import (
    Signature,
    SigningError,
    VersionFields,
    sign_version,
    verify_version,
)

SCHEMA_VERSION: Final = 1
LEDGER_DOMAIN: Final = b"mnemowall/ledger/v1\x00"
HEAD_DOMAIN: Final = b"mnemowall/ledger-head/v1\x00"
GENESIS_HASH: Final = "0" * 64
EVENT_KINDS: Final = frozenset({"quarantine", "review"})
PURGE_REASONS: Final = frozenset({"erasure", "retention"})
MIN_RETENTION_DAYS: Final = 1
MAX_RETENTION_DAYS: Final = 3650
DEFAULT_RETENTION_DAYS: Final = 90

_CONTENT_DOMAIN: Final = b"mnemowall/content/v1\x00"
_PROVENANCE_DOMAIN: Final = b"mnemowall/provenance/v1\x00"
_REF_DOMAIN: Final = b"mnemowall/ref/v1\x00"
_QUERY_DOMAIN: Final = b"mnemowall/query/v1\x00"
_DAY_MS: Final = 86_400_000
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_FIELD: Final = re.compile(r"[a-z][a-z0-9_]{0,31}")
_COLUMNS: Final = "seq, kind, ts_ms, memory_id, version_no, ref_hmac, body, prev_hash, hash"

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS entries (
    seq INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    ts_ms INTEGER NOT NULL,
    memory_id TEXT,
    version_no INTEGER,
    ref_hmac TEXT,
    body TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS entries_version_unique
    ON entries (memory_id, version_no) WHERE kind = 'version';
CREATE INDEX IF NOT EXISTS entries_ref ON entries (ref_hmac) WHERE kind = 'version';
CREATE TABLE IF NOT EXISTS blobs (
    seq INTEGER NOT NULL,
    col TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ct BLOB NOT NULL,
    PRIMARY KEY (seq, col)
);
CREATE TABLE IF NOT EXISTS head (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    seq INTEGER NOT NULL,
    hash TEXT NOT NULL,
    signature TEXT NOT NULL
);
"""

_log = get_logger("ledger")


class LedgerError(Exception):
    """A ledger operation was refused. ``reason`` is a fixed code, safe to log and show."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class LedgerUnavailable(LedgerError):
    """Keys are unavailable, so the ledger fails closed for writes (§1.3)."""


@dataclass(frozen=True, slots=True)
class ReadItem:
    """One memory version returned by a read, with the labels it was returned under."""

    memory_id: str
    version_no: int
    verified: bool
    stale: bool
    wrap_label: str


@dataclass(frozen=True, slots=True)
class ReadEvent:
    seq: int
    ts_ms: int
    session_id: str | None
    items: tuple[ReadItem, ...]
    query_hmac: str | None
    purged: bool


@dataclass(frozen=True)
class VersionRecord:
    """A stored version. ``verified`` means every blob decrypted and the signature is valid."""

    seq: int
    memory_id: str
    version_no: int
    ts_ms: int
    signature: str
    verified: bool
    problem: str | None
    purged: bool
    status: str
    key: str | None = field(repr=False)
    content: str | None = field(repr=False)
    signed_fields: VersionFields | None = field(repr=False)

    @property
    def fields(self) -> VersionFields:
        if self.signed_fields is None:
            raise LedgerError("fields_unavailable")
        return self.signed_fields


@dataclass(frozen=True, slots=True)
class VerifyReport:
    ok: bool
    checked: int
    failed_at: int | None
    reason: str


@dataclass(frozen=True, slots=True)
class _Row:
    seq: int
    kind: str
    ts_ms: int
    memory_id: str | None
    version_no: int | None
    ref_hmac: str | None
    body: str
    prev_hash: str
    hash: str


def entry_hash(row: _Row | Sequence[Any]) -> str:
    """The chain hash of an entry (see the module docstring)."""
    r = row if isinstance(row, _Row) else _Row(*row)
    doc = {
        "seq": r.seq,
        "kind": r.kind,
        "ts_ms": r.ts_ms,
        "memory_id": r.memory_id,
        "version_no": r.version_no,
        "ref_hmac": r.ref_hmac,
        "body": r.body,
    }
    prev = bytes.fromhex(r.prev_hash)
    return hashlib.sha256(LEDGER_DOMAIN + canonicalize(doc) + prev).hexdigest()


def _text(value: object, reason: str) -> str:
    if not isinstance(value, str) or not value:
        raise LedgerError(reason)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise LedgerError(reason) from None
    return value


def _ident(value: object, reason: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise LedgerError(reason)
    return value


def _label(value: object) -> str:
    if isinstance(value, TrustLevel):
        return value.label
    if isinstance(value, str):
        return str.__str__(value)
    raise LedgerError("field_invalid")


class Ledger:
    """A per-tenant local ledger. Open with :meth:`open`; safe to share between threads."""

    def __init__(
        self,
        con: sqlite3.Connection,
        keys: KeySet | None,
        *,
        ledger_id: str,
        tenant_id: str,
        clock: Callable[[], float],
        retention_days: int,
    ) -> None:
        self._con = con
        self._keys = keys
        self._ledger_id = ledger_id
        self._tenant_id = tenant_id
        self._clock = clock
        self._retention_days = retention_days
        self._lock = threading.RLock()
        self._aead = AESGCM(keys.derive(Purpose.LEDGER_ENC)) if keys else None
        self._hkey = keys.derive(Purpose.CONTENT_HMAC) if keys else None

    def __repr__(self) -> str:
        return f"Ledger(tenant_id={self._tenant_id!r}, locked={self.locked})"

    # --- opening ---------------------------------------------------------------------------

    @classmethod
    def open(
        cls,
        path: Path | str,
        provider: KeyProvider,
        *,
        tenant_id: str,
        clock: Callable[[], float] = time.time,
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> Ledger:
        if (
            type(retention_days) is not int
            or not MIN_RETENTION_DAYS <= retention_days <= MAX_RETENTION_DAYS
        ):
            raise LedgerError("retention_out_of_range")
        _ident(tenant_id, "tenant_id_invalid")
        path = Path(path)
        _prepare_file(path)
        con = sqlite3.connect(path, timeout=30.0, isolation_level=None, check_same_thread=False)
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=NORMAL")
            con.execute("PRAGMA secure_delete=ON")
            ledger_id = _init_schema(con, tenant_id)
        except BaseException:
            con.close()
            raise
        try:
            keys: KeySet | None = provider.load()
        except KeyUnavailable:
            keys = None
            diagnostics.record("ledger_keys_unavailable")
            _log.warning("ledger_keys_unavailable", extra={"reason": "keys_unavailable"})
        return cls(
            con,
            keys,
            ledger_id=ledger_id,
            tenant_id=tenant_id,
            clock=clock,
            retention_days=retention_days,
        )

    @property
    def locked(self) -> bool:
        """True when keys couldn't be loaded: writes are refused and nothing decrypts."""
        return self._keys is None

    def close(self) -> None:
        with self._lock:
            self._con.close()

    # --- crypto helpers --------------------------------------------------------------------

    def _require_keys(self, op: str) -> KeySet:
        if self._keys is None:
            diagnostics.record("ledger_append_refused")
            _log.warning("ledger_append_refused", extra={"reason": "keys_unavailable", "op": op})
            raise LedgerUnavailable("keys_unavailable")
        return self._keys

    def _hmac(self, domain: bytes, data: bytes) -> str:
        if self._hkey is None:
            raise LedgerUnavailable("keys_unavailable")
        return hmac.new(self._hkey, domain + data, hashlib.sha256).hexdigest()

    def _content_hash(self, content: str | None) -> str:
        data = b"\x00" if content is None else b"\x01" + content.encode("utf-8")
        return self._hmac(_CONTENT_DOMAIN, data)

    def _ref(self, namespace: tuple[str, ...], key: str) -> str:
        return self._hmac(_REF_DOMAIN, canonicalize([list(namespace), key]))

    def _aad(self, seq: int, col: str) -> bytes:
        return canonicalize({"db": self._ledger_id, "table": "blobs", "col": col, "seq": seq})

    def _encrypt(self, seq: int, col: str, data: bytes) -> tuple[bytes, bytes, str]:
        if self._aead is None:
            raise LedgerUnavailable("keys_unavailable")
        nonce = os.urandom(12)
        ct = self._aead.encrypt(nonce, data, self._aad(seq, col))
        return nonce, ct, hashlib.sha256(nonce + ct).hexdigest()

    def _blob_exists(self, seq: int, col: str) -> bool:
        found = self._con.execute(
            "SELECT 1 FROM blobs WHERE seq = ? AND col = ?", (seq, col)
        ).fetchone()
        return found is not None

    def _decrypt(self, seq: int, col: str) -> bytes | None:
        if self._aead is None:
            return None
        row = self._con.execute(
            "SELECT nonce, ct FROM blobs WHERE seq = ? AND col = ?", (seq, col)
        ).fetchone()
        if row is None:
            return None
        try:
            return self._aead.decrypt(row[0], row[1], self._aad(seq, col))
        except (InvalidTag, ValueError):
            diagnostics.record("ledger_decrypt_failed")
            _log.warning("ledger_decrypt_failed", extra={"op": col})
            return None

    # --- writing ---------------------------------------------------------------------------

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

    def _now_ms(self) -> int:
        return int(self._clock() * 1000)

    def _append(
        self,
        keys: KeySet,
        *,
        kind: str,
        body: Mapping[str, object],
        memory_id: str | None = None,
        version_no: int | None = None,
        ref_hmac: str | None = None,
        blobs: Mapping[str, tuple[bytes, bytes, str]] | None = None,
        seq: int,
        prev_hash: str,
    ) -> int:
        row = _Row(
            seq=seq,
            kind=kind,
            ts_ms=self._now_ms(),
            memory_id=memory_id,
            version_no=version_no,
            ref_hmac=ref_hmac,
            body=canonicalize(dict(body)).decode("utf-8"),
            prev_hash=prev_hash,
            hash="",
        )
        digest = entry_hash(row)
        self._con.execute(
            f"INSERT INTO entries ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",  # noqa: S608
            (
                row.seq,
                kind,
                row.ts_ms,
                memory_id,
                version_no,
                ref_hmac,
                row.body,
                prev_hash,
                digest,
            ),
        )
        for col, (nonce, ct, _) in (blobs or {}).items():
            self._con.execute(
                "INSERT INTO blobs (seq, col, nonce, ct) VALUES (?, ?, ?, ?)", (seq, col, nonce, ct)
            )
        key_id, raw = keys.sign(HEAD_DOMAIN + self._head_message(seq, digest))
        self._con.execute(
            "INSERT OR REPLACE INTO head (id, seq, hash, signature) VALUES (1, ?, ?, ?)",
            (seq, digest, Signature(key_id, raw).encode()),
        )
        return seq

    def _head_message(self, seq: int, digest: str) -> bytes:
        return canonicalize(
            {"ledger_id": self._ledger_id, "tenant_id": self._tenant_id, "seq": seq, "hash": digest}
        )

    def _tail(self) -> tuple[int, str]:
        row = self._con.execute(
            "SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return (1, GENESIS_HASH) if row is None else (row[0] + 1, row[1])

    def append_version(
        self,
        *,
        namespace: Sequence[str],
        key: str,
        content: str | None,
        scope: str,
        trust_level: TrustLevel | str,
        effective_type: str,
        memory_type: str,
        protected: bool = False,
        status: str = "active",
        bundle_id: str,
        provenance: Mapping[str, object],
    ) -> VersionRecord:
        """Append a signed version. ``content`` is required for ``active`` and absent otherwise."""
        keys = self._require_keys("append_version")
        if not isinstance(namespace, tuple | list) or not namespace:
            raise LedgerError("namespace_invalid")
        ns = tuple(namespace)
        for segment in ns:
            if not isinstance(segment, str):
                raise LedgerError("namespace_invalid")
            if segment:
                _text(segment, "namespace_invalid")
        key = _text(key, "key_invalid")
        if status == "active" and content is None:
            raise LedgerError("content_required")
        if status != "active" and content is not None:
            raise LedgerError("content_not_allowed")
        if content is not None:
            if not isinstance(content, str):
                raise LedgerError("content_invalid")
            if content:
                _text(content, "content_invalid")
        if not isinstance(provenance, Mapping):
            raise LedgerError("provenance_invalid")
        try:
            prov = canonicalize(dict(provenance))
        except JCSError:
            raise LedgerError("provenance_invalid") from None
        ref = self._ref(ns, key)
        with self._txn():
            found = self._con.execute(
                "SELECT memory_id FROM entries WHERE kind = 'version' AND ref_hmac = ?"
                " ORDER BY seq LIMIT 1",
                (ref,),
            ).fetchone()
            prev_sig: str | None = None
            if found is None:
                memory_id = "mem-" + uuid.uuid4().hex
                version_no = 1
            else:
                memory_id = found[0]
                last = self._con.execute(
                    "SELECT version_no, body FROM entries WHERE kind = 'version' AND memory_id = ?"
                    " ORDER BY version_no DESC LIMIT 1",
                    (memory_id,),
                ).fetchone()
                version_no = last[0] + 1
                prev_sig = json.loads(last[1])["signature"]
            fields = VersionFields(
                tenant_id=self._tenant_id,
                scope=_label(scope),
                namespace=ns,
                memory_id=memory_id,
                version_no=version_no,
                prev_version_signature=prev_sig,
                content_hash=self._content_hash(content),
                provenance_hash=self._hmac(_PROVENANCE_DOMAIN, prov),
                trust_level=_label(trust_level),
                effective_type=_label(effective_type),
                memory_type=_label(memory_type),
                protected=protected,
                status=_label(status),
                bundle_id=_label(bundle_id),
            )
            signature = sign_version(fields, keys).encode()
            seq, prev_hash = self._tail()
            plain: dict[str, bytes] = {
                "namespace": canonicalize(list(ns)),
                "key": key.encode("utf-8"),
                "provenance": prov,
            }
            if content is not None:
                plain["content"] = content.encode("utf-8")
            enc = {col: self._encrypt(seq, col, data) for col, data in plain.items()}
            signed = {k: v for k, v in fields.as_dict().items() if k != "namespace"}
            body = {
                "fields": signed,
                "signature": signature,
                "blobs": {col: e[2] for col, e in enc.items()},
            }
            self._append(
                keys,
                kind="version",
                body=body,
                memory_id=memory_id,
                version_no=version_no,
                ref_hmac=ref,
                blobs=enc,
                seq=seq,
                prev_hash=prev_hash,
            )
            ts_ms = self._con.execute("SELECT ts_ms FROM entries WHERE seq = ?", (seq,)).fetchone()
        return VersionRecord(
            seq=seq,
            memory_id=memory_id,
            version_no=version_no,
            ts_ms=ts_ms[0],
            signature=signature,
            verified=True,
            problem=None,
            purged=False,
            status=fields.status,
            key=key,
            content=content,
            signed_fields=fields,
        )

    def record_read(self, *, session_id: str, items: Sequence[ReadItem], query: str | None) -> int:
        """Log a read: session, versions and labels, and an HMAC of the query. No content."""
        keys = self._require_keys("record_read")
        _ident(session_id, "session_id_invalid")
        packed = []
        for item in items:
            if not isinstance(item, ReadItem):
                raise LedgerError("read_item_invalid")
            _ident(item.memory_id, "read_item_invalid")
            if type(item.version_no) is not int or item.version_no < 1:
                raise LedgerError("read_item_invalid")
            if type(item.verified) is not bool or type(item.stale) is not bool:
                raise LedgerError("read_item_invalid")
            _ident(item.wrap_label, "read_item_invalid")
            packed.append(
                [item.memory_id, item.version_no, item.verified, item.stale, item.wrap_label]
            )
        query_hmac = None
        if query is not None:
            query_hmac = self._hmac(_QUERY_DOMAIN, _text(query, "query_invalid").encode("utf-8"))
        payload = canonicalize(
            {"session_id": session_id, "items": packed, "query_hmac": query_hmac}
        )
        with self._txn():
            seq, prev_hash = self._tail()
            enc = {"read": self._encrypt(seq, "read", payload)}
            return self._append(
                keys,
                kind="read",
                body={"blobs": {"read": enc["read"][2]}},
                blobs=enc,
                seq=seq,
                prev_hash=prev_hash,
            )

    def append_event(self, kind: str, fields: Mapping[str, object]) -> int:
        """Append a quarantine or review event. Values must be ids, numbers, booleans or null."""
        keys = self._require_keys("append_event")
        if kind not in EVENT_KINDS:
            raise LedgerError("event_kind_invalid")
        clean: dict[str, object] = {}
        for name, value in fields.items():
            if not isinstance(name, str) or not _FIELD.fullmatch(name):
                raise LedgerError("event_field_invalid")
            scalar = value is None or type(value) in (bool, int)
            if not scalar and not (isinstance(value, str) and _ID.fullmatch(value)):
                raise LedgerError("event_field_invalid")
            clean[name] = value
        try:
            canonicalize(clean)
        except JCSError:
            raise LedgerError("event_field_invalid") from None
        with self._txn():
            seq, prev_hash = self._tail()
            return self._append(
                keys, kind=kind, body={"fields": clean}, seq=seq, prev_hash=prev_hash
            )

    def purge(self, memory_id: str, version_no: int, *, reason: str = "erasure") -> bool:
        """Delete a version's content ciphertext, leaving its hash. False if nothing to purge."""
        keys = self._require_keys("purge")
        if reason not in PURGE_REASONS:
            raise LedgerError("purge_reason_invalid")
        with self._txn():
            row = self._con.execute(
                "SELECT seq FROM entries WHERE kind = 'version' AND memory_id = ?"
                " AND version_no = ?",
                (memory_id, version_no),
            ).fetchone()
            if row is None:
                raise LedgerError("not_found")
            return self._purge_blob(keys, row[0], "content", reason)

    def _purge_blob(self, keys: KeySet, target: int, col: str, reason: str) -> bool:
        cur = self._con.execute("DELETE FROM blobs WHERE seq = ? AND col = ?", (target, col))
        if cur.rowcount == 0:
            return False
        seq, prev_hash = self._tail()
        self._append(
            keys,
            kind="purge",
            body={"target_seq": target, "cols": [col], "reason": reason},
            seq=seq,
            prev_hash=prev_hash,
        )
        return True

    def apply_retention(self) -> dict[str, int]:
        """Purge superseded content and read details older than the retention TTL (D18)."""
        keys = self._require_keys("apply_retention")
        cutoff = self._now_ms() - self._retention_days * _DAY_MS
        versions = reads = 0
        with self._txn():
            rows = self._con.execute(
                "SELECT seq, memory_id, version_no, ts_ms FROM entries WHERE kind = 'version'"
                " ORDER BY memory_id, version_no"
            ).fetchall()
            for cur, nxt in itertools.pairwise(rows):
                same_memory = cur[1] == nxt[1]
                if (
                    same_memory
                    and nxt[3] <= cutoff
                    and self._purge_blob(keys, cur[0], "content", "retention")
                ):
                    versions += 1
            for (seq,) in self._con.execute(
                "SELECT seq FROM entries WHERE kind = 'read' AND ts_ms <= ?", (cutoff,)
            ).fetchall():
                if self._purge_blob(keys, seq, "read", "retention"):
                    reads += 1
        return {"versions_purged": versions, "reads_purged": reads}

    # --- reading ---------------------------------------------------------------------------

    def _row(self, where: str, params: Sequence[object]) -> _Row | None:
        found = self._con.execute(
            f"SELECT {_COLUMNS} FROM entries WHERE {where}",  # noqa: S608 - fixed fragments
            tuple(params),
        ).fetchone()
        return None if found is None else _Row(*found)

    def _record(self, row: _Row) -> VersionRecord:
        body = json.loads(row.body)
        signature = body["signature"]
        signed = body["fields"]
        status = signed.get("status", "")
        listed = body.get("blobs", {})
        if row.memory_id is None or row.version_no is None:
            raise LedgerError("entry_invalid")
        problem: str | None = None
        ns_raw = self._decrypt(row.seq, "namespace")
        key_raw = self._decrypt(row.seq, "key")
        content: str | None = None
        purged = False
        if "content" in listed:
            if not self._blob_exists(row.seq, "content"):
                purged = True
            else:
                raw = self._decrypt(row.seq, "content")
                if raw is None:
                    problem = "decrypt_failed"
                else:
                    content = raw.decode("utf-8")
        fields: VersionFields | None = None
        if self._keys is None:
            problem = "keys_unavailable"
        elif ns_raw is None or key_raw is None:
            problem = "decrypt_failed"
        else:
            try:
                fields = VersionFields.from_mapping({**signed, "namespace": json.loads(ns_raw)})
            except (SigningError, TypeError, ValueError):
                problem = problem or "fields_invalid"
        if fields is not None and problem is None:
            if not verify_version(fields, signature, self._keys.public_keys if self._keys else {}):
                problem = "bad_signature"
            elif content is not None and self._content_hash(content) != fields.content_hash:
                problem = "content_hash_mismatch"
                content = None
        if problem is not None:
            diagnostics.record("ledger_unverified")
        return VersionRecord(
            seq=row.seq,
            memory_id=row.memory_id,
            version_no=row.version_no,
            ts_ms=row.ts_ms,
            signature=signature,
            verified=problem is None,
            problem=problem,
            purged=purged,
            status=status,
            key=key_raw.decode("utf-8") if key_raw is not None and problem is None else None,
            content=content if problem is None else None,
            signed_fields=fields,
        )

    def find(self, namespace: Sequence[str], key: str) -> str | None:
        """The memory id for ``(namespace, key)``, or None (also None when keys are unavailable)."""
        if self._hkey is None:
            return None
        ref = self._ref(tuple(namespace), key)
        with self._lock:
            row = self._con.execute(
                "SELECT memory_id FROM entries WHERE kind = 'version' AND ref_hmac = ?"
                " ORDER BY seq LIMIT 1",
                (ref,),
            ).fetchone()
        return None if row is None else str(row[0])

    def version(self, memory_id: str, version_no: int) -> VersionRecord | None:
        with self._lock:
            row = self._row(
                "kind = 'version' AND memory_id = ? AND version_no = ?", (memory_id, version_no)
            )
            return None if row is None else self._record(row)

    def head(self, memory_id: str) -> VersionRecord | None:
        with self._lock:
            row = self._row(
                "kind = 'version' AND memory_id = ? ORDER BY version_no DESC LIMIT 1", (memory_id,)
            )
            return None if row is None else self._record(row)

    def versions(self, memory_id: str) -> list[VersionRecord]:
        with self._lock:
            found = self._con.execute(
                f"SELECT {_COLUMNS} FROM entries WHERE kind = 'version' AND memory_id = ?"  # noqa: S608
                " ORDER BY version_no",
                (memory_id,),
            ).fetchall()
            return [self._record(_Row(*r)) for r in found]

    def is_head(self, memory_id: str, version_no: int) -> bool:
        """False for any version that is not the ledger head (``stale`` on read, M1a-16)."""
        with self._lock:
            row = self._con.execute(
                "SELECT max(version_no) FROM entries WHERE kind = 'version' AND memory_id = ?",
                (memory_id,),
            ).fetchone()
        return row is not None and row[0] is not None and row[0] == version_no

    def reads(self) -> list[ReadEvent]:
        out = []
        with self._lock:
            found = self._con.execute(
                "SELECT seq, ts_ms FROM entries WHERE kind = 'read' ORDER BY seq"
            ).fetchall()
            for seq, ts_ms in found:
                raw = self._decrypt(seq, "read")
                if raw is None:
                    gone = not self._blob_exists(seq, "read")
                    out.append(ReadEvent(seq, ts_ms, None, (), None, purged=gone))
                    continue
                doc = json.loads(raw)
                items = tuple(ReadItem(*i) for i in doc["items"])
                out.append(
                    ReadEvent(seq, ts_ms, doc["session_id"], items, doc["query_hmac"], False)
                )
        return out

    def sessions_that_read(self, memory_id: str, version_no: int) -> list[str]:
        found = {
            e.session_id
            for e in self.reads()
            if e.session_id is not None
            and any(i.memory_id == memory_id and i.version_no == version_no for i in e.items)
        }
        return sorted(found)

    def events(self) -> list[tuple[int, str, dict[str, object]]]:
        with self._lock:
            found = self._con.execute(
                "SELECT seq, kind, body FROM entries WHERE kind IN ('quarantine', 'review')"
                " ORDER BY seq"
            ).fetchall()
        return [(seq, kind, json.loads(body)["fields"]) for seq, kind, body in found]

    def export_head(self) -> tuple[int, str]:
        """``(seq, hash)`` of the signed head, for safekeeping outside this file (D17)."""
        with self._lock:
            row = self._con.execute("SELECT seq, hash FROM head WHERE id = 1").fetchone()
        return (0, GENESIS_HASH) if row is None else (int(row[0]), str(row[1]))

    # --- verification ----------------------------------------------------------------------

    def verify(self, *, expected_head: tuple[int, str] | None = None) -> VerifyReport:
        """Check the global chain, blobs, per-memory chains, signatures and the signed head."""
        keys = self._require_keys("verify")
        with self._lock:
            report = self._verify(keys, expected_head)
        if not report.ok:
            diagnostics.record("ledger_verify_failed")
            _log.error(
                "ledger_verify_failed", extra={"reason": report.reason, "seq": report.failed_at}
            )
        return report

    def _verify(self, keys: KeySet, expected_head: tuple[int, str] | None) -> VerifyReport:
        rows = [
            _Row(*r)
            for r in self._con.execute(f"SELECT {_COLUMNS} FROM entries ORDER BY seq").fetchall()  # noqa: S608
        ]
        blobs: dict[int, dict[str, tuple[bytes, bytes]]] = {}
        for seq, col, nonce, ct in self._con.execute("SELECT seq, col, nonce, ct FROM blobs"):
            blobs.setdefault(seq, {})[col] = (nonce, ct)
        purged: set[tuple[int, str]] = set()
        for r in rows:
            if r.kind == "purge":
                with contextlib.suppress(ValueError, KeyError, TypeError):
                    doc = json.loads(r.body)
                    purged.update((doc["target_seq"], c) for c in doc["cols"])

        def fail(at: int, reason: str) -> VerifyReport:
            return VerifyReport(False, len(rows), at, reason)

        # Pass 1: the chain itself, so structural tampering is reported at the row it touched.
        prev = GENESIS_HASH
        for i, r in enumerate(rows, start=1):
            if r.seq != i:
                return fail(i, "missing_entry")
            if r.prev_hash != prev:
                return fail(i, "prev_hash_mismatch")
            if entry_hash(r) != r.hash:
                return fail(i, "hash_mismatch")
            prev = r.hash
        n = len(rows)
        head = self._con.execute("SELECT seq, hash, signature FROM head WHERE id = 1").fetchone()
        if head is None:
            if n:
                return fail(n, "head_missing")
        else:
            if head[0] > n:
                return fail(head[0], "missing_entry")
            if head[0] < n:
                return fail(head[0] + 1, "entry_after_head")
            if head[1] != rows[-1].hash:
                return fail(n, "head_hash_mismatch")
        # Pass 2: what each authentic-looking row says (blobs, version chains, signatures).
        memories: dict[str, tuple[int, str]] = {}
        for i, r in enumerate(rows, start=1):
            try:
                body = json.loads(r.body)
                listed = dict(body.get("blobs", {}))
            except (ValueError, TypeError, AttributeError):
                return fail(i, "body_invalid")
            present = blobs.get(i, {})
            if set(present) - set(listed):
                return fail(i, "blob_unexpected")
            for col, digest in listed.items():
                if col not in present:
                    if (i, col) not in purged:
                        return fail(i, "blob_missing")
                elif hashlib.sha256(present[col][0] + present[col][1]).hexdigest() != digest:
                    return fail(i, "blob_hash_mismatch")
            if r.kind == "version":
                problem = self._verify_version(r, body, keys, memories)
                if problem:
                    return fail(i, problem)
            elif r.kind == "purge":
                target = body.get("target_seq")
                if type(target) is not int or not 1 <= target < i:
                    return fail(i, "purge_invalid")
            elif r.kind not in {"read", *EVENT_KINDS}:
                return fail(i, "unknown_kind")
        # Pass 3: the head signature (needs the key; catches a recomputed chain).
        if head is not None:
            hseq, hhash, hsig = head
            try:
                sig = Signature.decode(hsig)
                public = keys.public_keys[sig.key_id]
                public.verify(sig.value, HEAD_DOMAIN + self._head_message(hseq, hhash))
            except Exception:  # noqa: BLE001 - any failure here means "head signature invalid"
                return fail(hseq, "bad_head_signature")
        if expected_head is not None:
            eseq, ehash = expected_head
            if not 1 <= eseq <= n or rows[eseq - 1].hash != ehash:
                return fail(eseq, "expected_head_missing")
        return VerifyReport(True, n, None, "ok")

    def _verify_version(
        self, r: _Row, body: Mapping[str, Any], keys: KeySet, memories: dict[str, tuple[int, str]]
    ) -> str | None:
        ns_raw = self._decrypt(r.seq, "namespace")
        if ns_raw is None:
            return "blob_undecryptable"
        try:
            fields = VersionFields.from_mapping({**body["fields"], "namespace": json.loads(ns_raw)})
        except (SigningError, KeyError, TypeError, ValueError):
            return "fields_invalid"
        if fields.memory_id != r.memory_id or fields.version_no != r.version_no:
            return "column_mismatch"
        state = memories.get(fields.memory_id)
        if fields.version_no != (1 if state is None else state[0] + 1):
            return "version_gap"
        if fields.prev_version_signature != (None if state is None else state[1]):
            return "prev_signature_mismatch"
        signature = body.get("signature")
        if not verify_version(fields, signature, keys.public_keys):
            return "bad_version_signature"
        listed = body.get("blobs", {})
        if "content" in listed:
            if self._blob_exists(r.seq, "content"):
                raw = self._decrypt(r.seq, "content")
                if raw is None:
                    return "blob_undecryptable"
                if self._content_hash(raw.decode("utf-8")) != fields.content_hash:
                    return "content_hash_mismatch"
        elif self._content_hash(None) != fields.content_hash:
            return "content_hash_mismatch"
        prov = self._decrypt(r.seq, "provenance")
        if prov is None or self._hmac(_PROVENANCE_DOMAIN, prov) != fields.provenance_hash:
            return "provenance_hash_mismatch"
        memories[fields.memory_id] = (fields.version_no, str(signature))
        return None

    # --- maintenance -----------------------------------------------------------------------

    def pragmas(self) -> dict[str, object]:
        with self._lock:
            return {
                "journal_mode": self._con.execute("PRAGMA journal_mode").fetchone()[0],
                "synchronous": self._con.execute("PRAGMA synchronous").fetchone()[0],
                "secure_delete": self._con.execute("PRAGMA secure_delete").fetchone()[0],
            }

    def checkpoint(self) -> None:
        with self._lock:
            self._con.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def vacuum(self) -> None:
        with self._lock:
            self._con.execute("VACUUM")


def _prepare_file(path: Path) -> None:
    """Create the database file 0600, or check an existing one (no symlink, no loose bits)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return _prepare_file(path)
        except OSError:
            raise LedgerError("create_failed") from None
        os.close(fd)
        return None
    if stat.S_ISLNK(st.st_mode):
        raise LedgerError("symlink")
    if not stat.S_ISREG(st.st_mode):
        raise LedgerError("not_a_regular_file")
    if os.name == "posix" and stat.S_IMODE(st.st_mode) & 0o077:
        raise LedgerError("insecure_permissions")
    return None


def _init_schema(con: sqlite3.Connection, tenant_id: str) -> str:
    tables = {
        name
        for (name,) in con.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    if "meta" not in tables:
        if tables:
            raise LedgerError("not_a_ledger")
        con.execute("BEGIN IMMEDIATE")
        try:
            for statement in _SCHEMA.split(";"):
                if statement.strip():
                    con.execute(statement)
            con.execute(
                "INSERT OR IGNORE INTO meta (k, v) VALUES ('schema_version', ?), ('tenant_id', ?),"
                " ('ledger_id', ?)",
                (str(SCHEMA_VERSION), tenant_id, uuid.uuid4().hex),
            )
        except BaseException:
            con.execute("ROLLBACK")
            raise
        con.execute("COMMIT")
    meta = dict(con.execute("SELECT k, v FROM meta").fetchall())
    try:
        version = int(meta["schema_version"])
        ledger_id = meta["ledger_id"]
        stored_tenant = meta["tenant_id"]
    except (KeyError, ValueError):
        raise LedgerError("not_a_ledger") from None
    if version > SCHEMA_VERSION:
        raise LedgerError("schema_too_new")
    if version < SCHEMA_VERSION:
        raise LedgerError("schema_unsupported")
    if stored_tenant != tenant_id:
        raise LedgerError("tenant_mismatch")
    return str(ledger_id)
