"""Verify on read (M1a-16; §3.6, §3.5, §1.3).

Each item a backend returns is checked against the ledger before the model sees it:

* no Mnemowall reference, unknown version, signature mismatch, a ledger row that fails its own
  signature, content that doesn't match the signed content HMAC, or a version the ledger marks
  deleted -> ``unverified``;
* a genuine version found somewhere other than the namespace and key it was signed for (a
  copy into another key, namespace or principal) -> ``unverified`` (``location_mismatch``,
  M1b-01). Adapters pass ``location``; without it this check is skipped (raw core API, weaker);
* a genuine version that is not the ledger head (a replay) -> ``stale``.

Unverified and stale items are still returned (never dropped), wrapped, alerted on (counter and
log, reason code only), registered in the session at ``unknown`` trust (so they taint later
writes), and recorded in the ledger's read log. If keys are unavailable, every item reads back
``unverified`` and the read still succeeds (§1.3: reads fail open, wrapped).
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Final

from mnemowall._log import get_logger
from mnemowall.core import diagnostics
from mnemowall.core.provenance import ProvenanceSession, current_session
from mnemowall.core.trust import TrustLevel
from mnemowall.ledger import Ledger, LedgerError, ReadItem, VersionRecord
from mnemowall.policy import CompiledPolicy
from mnemowall.read.wrap import MemoryView, WrappedRead, _token, wrap_read

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_TRUST: Final = {t.label: t for t in TrustLevel}
_log = get_logger("read")


@dataclass(frozen=True, slots=True)
class MemoryRef:
    """What an adapter stored next to the value at write time (M1a-17)."""

    memory_id: str
    version_no: int
    signature: str


@dataclass(frozen=True, slots=True)
class BackendItem:
    """One item as the backend returned it."""

    content: str = field(repr=False)
    ref: MemoryRef | None
    source: str = "memory"
    created_ms: int | None = None
    relevance: float | None = None
    location: tuple[tuple[str, ...], str] | None = None  # (namespace, key) where it was found


@dataclass(frozen=True, slots=True)
class ReadCheck:
    memory_id: str
    version_no: int  # 0 when the item has no usable reference
    verified: bool
    stale: bool
    reason: str  # ok | stale | an unverified reason code
    trust: TrustLevel  # stored trust if verified and current, else unknown
    effective_type: str


@dataclass(frozen=True, slots=True)
class ReadResult:
    checks: tuple[ReadCheck, ...]  # in backend order
    wrapped: WrappedRead


def _unverified(item: BackendItem, reason: str) -> ReadCheck:
    ref = item.ref
    if ref is not None and isinstance(ref.memory_id, str) and _ID.fullmatch(ref.memory_id):
        mid = ref.memory_id
        version = ref.version_no if type(ref.version_no) is int and ref.version_no > 0 else 0
    else:
        mid, version = "unverified-" + uuid.uuid4().hex[:16], 0
    diagnostics.record("read_unverified")
    _log.warning("read_unverified", extra={"reason": reason})
    return ReadCheck(mid, version, False, False, reason, TrustLevel.UNKNOWN, "data")


def _located(ledger: Ledger, record: VersionRecord, location: tuple[tuple[str, ...], str]) -> bool:
    """Was this version signed for the namespace and key the item was found at? (D32)

    The namespace is an Ed25519-signed field; the key is bound through the ledger's
    hash-chained ``ref_hmac`` lookup, which maps one (namespace, key) to one memory id.
    """
    namespace, key = location
    try:
        signed = tuple(record.fields.namespace) == tuple(namespace)
        return signed and ledger.find(namespace, key) == record.memory_id
    except (LedgerError, TypeError, ValueError, UnicodeEncodeError):
        return False


def verify_item(ledger: Ledger, item: BackendItem) -> ReadCheck:
    """Check one backend item against the ledger. Never raises for bad data."""
    if ledger.locked:
        return _unverified(item, "keys_unavailable")
    ref = item.ref
    if ref is None:
        return _unverified(item, "missing_reference")
    if type(ref.version_no) is not int or not isinstance(ref.memory_id, str):
        return _unverified(item, "unknown_version")
    try:
        record = ledger.version(ref.memory_id, ref.version_no)
    except LedgerError:
        return _unverified(item, "ledger_error")
    if record is None:
        return _unverified(item, "unknown_version")
    if not record.verified:
        return _unverified(item, record.problem or "bad_signature")
    if ref.signature != record.signature:
        return _unverified(item, "signature_mismatch")
    if record.status != "active":
        return _unverified(item, "deleted_in_ledger")
    try:
        matches = ledger.content_hash(item.content) == record.fields.content_hash
    except (LedgerError, AttributeError, UnicodeEncodeError):
        matches = False
    if not matches:
        return _unverified(item, "content_mismatch")
    if item.location is not None and not _located(ledger, record, item.location):
        return _unverified(item, "location_mismatch")
    if not ledger.is_head(record.memory_id, record.version_no):
        diagnostics.record("read_stale")
        _log.warning("read_stale", extra={"version_no": record.version_no})
        return ReadCheck(
            record.memory_id, record.version_no, True, True, "stale", TrustLevel.UNKNOWN, "data"
        )
    fields = record.fields
    return ReadCheck(
        record.memory_id,
        record.version_no,
        True,
        False,
        "ok",
        _TRUST.get(fields.trust_level, TrustLevel.UNKNOWN),
        fields.effective_type,
    )


def read_memories(
    ledger: Ledger,
    items: Sequence[BackendItem],
    *,
    session: ProvenanceSession | None = None,
    policy: CompiledPolicy | None = None,
    query: str | None = None,
    token: Callable[[], str] = _token,
) -> ReadResult:
    """Verify, register, log and wrap a backend read. Every item is returned."""
    checks = tuple(verify_item(ledger, it) for it in items)
    views = [
        MemoryView(
            memory_id=check.memory_id,
            content=it.content,
            trust=check.trust,
            verified=check.verified,
            stale=check.stale,
            source=it.source,
            effective_type=check.effective_type,
            created_ms=it.created_ms,
            relevance=it.relevance,
        )
        for check, it in zip(checks, items, strict=True)
    ]
    wrapped = wrap_read(views, policy, token=token)
    sess = session if session is not None else current_session()
    if sess is not None:
        for check in checks:
            sess.register_memory_read(
                check.memory_id,
                stored_trust=check.trust,
                verified=check.verified,
                stale=check.stale,
            )
    log_items = [
        ReadItem(
            checks[w.index].memory_id,
            checks[w.index].version_no,
            checks[w.index].verified,
            checks[w.index].stale,
            w.label,
        )
        for w in wrapped.items
    ]
    session_id = "no-session"
    if sess is not None and _ID.fullmatch(sess.session_id):
        session_id = sess.session_id
    try:
        ledger.record_read(session_id=session_id, items=log_items, query=query)
    except LedgerError:
        diagnostics.record("read_log_failed")
        _log.warning("read_log_failed", extra={"reason": "ledger_unavailable"})
    return ReadResult(checks=checks, wrapped=wrapped)
