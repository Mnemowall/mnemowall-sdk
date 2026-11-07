"""Ledger export (``export --jsonl``) and offline verification (M1a-21; §3.12).

The export holds the chain entries (content-free bodies), the signed head, the ledger identity
and the verification keys, one JSON object per line. Content, namespaces and keys stay in the
encrypted ``blobs`` table and are never exported.

:func:`verify_export` checks the chain (sequence, links, hashes) and the head signature with
**keys the verifier supplies** (pin them; keys inside the export are only a hint). Version
signatures cover encrypted fields, so they are checked by ``verify-ledger`` on the live ledger,
not offline. Keep exported heads somewhere else: that is what catches deleted newest entries (D17).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterable, Iterator, Mapping
from typing import Any, Final

from mnemowall.ledger.signing import Signature
from mnemowall.ledger.store import (
    GENESIS_HASH,
    HEAD_DOMAIN,
    Ledger,
    VerifyReport,
    entry_hash,
    head_message,
)

FORMAT: Final = "mnemowall/ledger-export/v1"
_ENTRY_FIELDS: Final = (
    "seq",
    "kind",
    "ts_ms",
    "memory_id",
    "version_no",
    "ref_hmac",
    "body",
    "prev_hash",
    "hash",
)


def export_jsonl(ledger: Ledger) -> Iterator[str]:
    ledger_id, tenant_id = ledger.identity
    yield json.dumps(
        {"type": "meta", "format": FORMAT, "ledger_id": ledger_id, "tenant_id": tenant_id}
    )
    for entry in ledger.entries():
        yield json.dumps({"type": "entry", **entry}, ensure_ascii=False)
    head = ledger.signed_head()
    if head is not None:
        yield json.dumps({"type": "head", "seq": head[0], "hash": head[1], "signature": head[2]})
    keys = {
        kid: base64.b64encode(pub.public_bytes_raw()).decode("ascii")
        for kid, pub in ledger.public_keys.items()
    }
    yield json.dumps({"type": "public_keys", "keys": keys})


def verify_export(
    lines: Iterable[str],
    public_keys: Mapping[str, Any],
    *,
    expected_head: tuple[int, str] | None = None,
) -> VerifyReport:
    entries: list[dict[str, Any]] = []
    meta: dict[str, Any] | None = None
    head: dict[str, Any] | None = None
    try:
        for raw in lines:
            if not raw.strip():
                continue
            doc = json.loads(raw)
            kind = doc.get("type")
            if kind == "meta":
                meta = doc
            elif kind == "entry":
                entries.append(doc)
            elif kind == "head":
                head = doc
    except (ValueError, AttributeError):
        return VerifyReport(False, len(entries), None, "malformed_export")
    if meta is None or meta.get("format") != FORMAT:
        return VerifyReport(False, 0, None, "malformed_export")

    def fail(at: int | None, reason: str) -> VerifyReport:
        return VerifyReport(False, len(entries), at, reason)

    prev = GENESIS_HASH
    for i, e in enumerate(entries, start=1):
        try:
            row = tuple(e[f] for f in _ENTRY_FIELDS)
        except KeyError:
            return fail(i, "malformed_entry")
        if e["seq"] != i:
            return fail(i, "missing_entry")
        if e["prev_hash"] != prev:
            return fail(i, "prev_hash_mismatch")
        try:
            digest = entry_hash(row)
        except (ValueError, TypeError):
            return fail(i, "malformed_entry")
        if digest != e["hash"]:
            return fail(i, "hash_mismatch")
        prev = e["hash"]
    n = len(entries)
    if head is None:
        if n:
            return fail(n, "head_missing")
    else:
        hseq, hhash = head.get("seq"), head.get("hash")
        if not isinstance(hseq, int) or hseq > n:
            return fail(hseq if isinstance(hseq, int) else None, "missing_entry")
        if hseq < n:
            return fail(hseq + 1, "entry_after_head")
        if n and hhash != entries[-1]["hash"]:
            return fail(n, "head_hash_mismatch")
        try:
            sig = Signature.decode(head.get("signature"))
            public = public_keys[sig.key_id]
            public.verify(
                sig.value,
                HEAD_DOMAIN
                + head_message(str(meta["ledger_id"]), str(meta["tenant_id"]), hseq, str(hhash)),
            )
        except Exception:  # noqa: BLE001 - any failure here means "head signature invalid"
            return fail(hseq, "bad_head_signature")
    if expected_head is not None:
        eseq, ehash = expected_head
        if not 1 <= eseq <= n or entries[eseq - 1]["hash"] != ehash:
            return fail(eseq, "expected_head_missing")
    return VerifyReport(True, n, None, "ok")
