"""M1a-13: SQLite ledger. UT-LEDGER-001..009, PT-LEDGER-CHAIN, CAN-LEDGER-AT-REST (ledger paths).

Design: ADR-0020 D15-D18. The quarantine store and pending buffer join CAN-LEDGER-AT-REST in
M1a-14.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import itertools
import json
import logging
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from mnemowall.core import diagnostics
from mnemowall.core.jcs import canonicalize
from mnemowall.keys import (
    EphemeralKeyProvider,
    FileKeyProvider,
    KeychainKeyProvider,
    KeyProvider,
    Purpose,
)
from mnemowall.ledger import (
    GENESIS_HASH,
    LEDGER_DOMAIN,
    Ledger,
    LedgerError,
    LedgerUnavailable,
    ReadItem,
    VersionRecord,
    verify_version,
)

CANARY = "CANARY-7f3a91"
CANARY_EMAIL = "canary.person.7f3a91@example.org"
CANARY_URL = "https://canary-7f3a91.example.net/x?q=7f3a91"
CANARY_ITEM = "canary-item-7f3a91"
CANARY_NS = "canary-ns-7f3a91"
CANARY_SOURCE = "canary-source-ref-7f3a91"
CANARY_QUERY = "canary query 7f3a91 text"
CANARIES = [CANARY, CANARY_EMAIL, CANARY_URL, CANARY_ITEM, CANARY_NS, CANARY_SOURCE, CANARY_QUERY]

PROVIDER = EphemeralKeyProvider()
PROVIDER.init()
KEYS = PROVIDER.load()


@pytest.fixture(autouse=True)
def _reset() -> None:
    diagnostics.reset()


def open_ledger(path: Path, provider: KeyProvider = PROVIDER, **kw: Any) -> Ledger:
    return Ledger.open(path, provider, tenant_id="tenant-a", **kw)


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    return open_ledger(tmp_path / "ledger.db")


def put(
    led: Ledger,
    *,
    ns: tuple[str, ...] = ("users", "u-1"),
    key: str = "k1",
    content: str | None = "hello",
    **over: Any,
) -> VersionRecord:
    args: dict[str, Any] = {
        "namespace": ns,
        "key": key,
        "content": content,
        "scope": "user",
        "trust_level": "user",
        "effective_type": "fact",
        "memory_type": "fact",
        "protected": False,
        "status": "active",
        "bundle_id": "builtin-default",
        "provenance": {"decision_id": "dec-1", "source_types": ["user_msg"]},
    }
    args.update(over)
    return led.append_version(**args)


def raw(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(path, isolation_level=None)
    con.execute("DROP INDEX IF EXISTS entries_version_unique")
    return con


def rows(path: Path) -> list[tuple[Any, ...]]:
    con = sqlite3.connect(path)
    try:
        return con.execute(
            "SELECT seq, kind, ts_ms, memory_id, version_no, ref_hmac, body, prev_hash, hash"
            " FROM entries ORDER BY seq"
        ).fetchall()
    finally:
        con.close()


def entry_hash(row: tuple[Any, ...]) -> str:
    seq, kind, ts_ms, memory_id, version_no, ref_hmac, body, prev_hash, _ = row
    doc = {
        "seq": seq,
        "kind": kind,
        "ts_ms": ts_ms,
        "memory_id": memory_id,
        "version_no": version_no,
        "ref_hmac": ref_hmac,
        "body": body,
    }
    return hashlib.sha256(LEDGER_DOMAIN + canonicalize(doc) + bytes.fromhex(prev_hash)).hexdigest()


# --- UT-LEDGER-001 -------------------------------------------------------------------------


def test_ut_ledger_001_versions_chain_and_sign(tmp_path: Path) -> None:
    led = open_ledger(tmp_path / "ledger.db")
    r1 = put(led, content="first")
    r2 = put(led, content="second")
    other = put(led, key="k2", content="other")
    assert r1.memory_id == r2.memory_id != other.memory_id
    assert (r1.version_no, r2.version_no, other.version_no) == (1, 2, 1)
    assert r1.fields.prev_version_signature is None
    assert r2.fields.prev_version_signature == r1.signature
    assert other.fields.prev_version_signature is None
    for r in (r1, r2, other):
        assert r.verified
        assert verify_version(r.fields, r.signature, KEYS.public_keys).valid
    assert (r1.seq, r2.seq, other.seq) == (1, 2, 3)
    assert r2.content == "second"
    assert r2.fields.namespace == ("users", "u-1")
    expected = hmac.new(
        KEYS.derive(Purpose.CONTENT_HMAC), b"mnemowall/content/v1\x00\x01second", "sha256"
    ).hexdigest()
    assert r2.fields.content_hash == expected
    assert led.find(("users", "u-1"), "k1") == r1.memory_id
    assert led.find(("users", "u-1"), "missing") is None
    assert led.find(("users", "u-2"), "k1") is None
    table = rows(tmp_path / "ledger.db")
    assert table[0][7] == GENESIS_HASH == "0" * 64
    for prev, row in itertools.pairwise(table):
        assert row[7] == prev[8]
    for row in table:
        assert entry_hash(row) == row[8]
    report = led.verify()
    assert report.ok
    assert report.checked == 3


def test_ut_ledger_001_trust_and_types_are_signed_as_given(ledger: Ledger) -> None:
    r = put(
        ledger,
        trust_level="web",
        effective_type="data",
        memory_type="standing_instruction",
        protected=True,
    )
    assert (r.fields.trust_level, r.fields.effective_type, r.fields.memory_type) == (
        "web",
        "data",
        "standing_instruction",
    )
    assert r.fields.protected is True
    assert r.fields.tenant_id == "tenant-a"
    assert r.fields.bundle_id == "builtin-default"


@pytest.mark.parametrize(
    "over",
    [
        {"content": None},
        {"status": "deleted", "content": "x"},
        {"trust_level": "root"},
        {"namespace": ()},
        {"key": ""},
        {"provenance": {"bad": 1.5}},
        {"provenance": {"bad": b"x"}},
    ],
)
def test_ut_ledger_001_invalid_appends_rejected(ledger: Ledger, over: dict[str, Any]) -> None:
    with pytest.raises((LedgerError, ValueError)) as exc:
        put(ledger, **over)
    assert CANARY not in str(exc.value)
    assert ledger.verify().checked == 0


def test_version_record_repr_hides_content_and_identifiers(ledger: Ledger) -> None:
    r = put(ledger, ns=("users", CANARY_NS), key=CANARY_ITEM, content=CANARY)
    text = repr(r) + str(r)
    for c in (CANARY, CANARY_NS, CANARY_ITEM):
        assert c not in text


# --- UT-LEDGER-002 -------------------------------------------------------------------------


def test_ut_ledger_002_read_log(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    led = open_ledger(path)
    r1 = put(led, content=CANARY)
    r2 = put(led, content="v2")
    seq = led.record_read(
        session_id="sess-1",
        items=[
            ReadItem(r1.memory_id, 1, verified=True, stale=True, wrap_label="data"),
            ReadItem(r2.memory_id, 2, verified=False, stale=False, wrap_label="unverified"),
        ],
        query=CANARY_QUERY,
    )
    led.record_read(session_id="sess-2", items=[], query=None)
    events = led.reads()
    assert [e.seq for e in events] == [seq, seq + 1]
    first = events[0]
    assert first.session_id == "sess-1"
    assert [
        (i.memory_id, i.version_no, i.verified, i.stale, i.wrap_label) for i in first.items
    ] == [
        (r1.memory_id, 1, True, True, "data"),
        (r2.memory_id, 2, False, False, "unverified"),
    ]
    q = hmac.new(
        KEYS.derive(Purpose.CONTENT_HMAC),
        b"mnemowall/query/v1\x00" + CANARY_QUERY.encode(),
        "sha256",
    ).hexdigest()
    assert first.query_hmac == q
    assert events[1].query_hmac is None
    assert r1.memory_id == r2.memory_id
    assert led.sessions_that_read(r1.memory_id, 1) == ["sess-1"]
    assert led.sessions_that_read(r1.memory_id, 2) == ["sess-1"]
    assert led.sessions_that_read(r1.memory_id, 3) == []
    assert led.sessions_that_read("mem-other", 1) == []
    assert led.verify().ok
    con = sqlite3.connect(path)
    read_rows = con.execute("SELECT body FROM entries WHERE kind = 'read'").fetchall()
    con.close()
    for (body,) in read_rows:
        assert CANARY not in body
        assert CANARY_QUERY not in body
        assert "sess-1" not in body


@pytest.mark.parametrize(
    "item",
    [
        {"wrap_label": "has space"},
        {"wrap_label": ""},
        {"version_no": -1},
        {"memory_id": ""},
        {"verified": 1},
    ],
)
def test_ut_ledger_002_read_items_validated(ledger: Ledger, item: dict[str, Any]) -> None:
    base: dict[str, Any] = {
        "memory_id": "mem-1",
        "version_no": 1,
        "verified": True,
        "stale": False,
        "wrap_label": "data",
    }
    base.update(item)
    with pytest.raises(LedgerError):
        ledger.record_read(session_id="s", items=[ReadItem(**base)], query=None)
    with pytest.raises(LedgerError):
        ledger.record_read(session_id="has space", items=[], query=None)


# --- PT-LEDGER-CHAIN -----------------------------------------------------------------------

OPS = st.lists(
    st.one_of(
        st.tuples(st.just("put"), st.integers(0, 3)),
        st.tuples(st.just("delete"), st.integers(0, 3)),
        st.tuples(st.just("purge"), st.integers(0, 3)),
        st.tuples(st.just("read"), st.integers(0, 3)),
        st.tuples(st.just("event"), st.integers(0, 1)),
    ),
    max_size=10,
)
COLUMNS = ["kind", "ts_ms", "memory_id", "version_no", "ref_hmac", "body", "prev_hash", "hash"]


def run_ops(led: Ledger, ops: list[tuple[str, int]]) -> None:
    put(led, key="m0", content="c0")
    put(led, key="m1", content="c1")
    for op, arg in [("put", 0), *ops]:
        key = f"m{arg}"
        mid = led.find(("users", "u-1"), key)
        if op == "put":
            put(led, key=key, content=f"content {arg}")
        elif op == "delete" and mid is not None:
            put(led, key=key, content=None, status="deleted")
        elif op == "purge" and mid is not None:
            head = led.head(mid)
            assert head is not None
            led.purge(mid, 1)
        elif op == "read" and mid is not None:
            head = led.head(mid)
            assert head is not None
            led.record_read(
                session_id=f"s-{arg}",
                items=[
                    ReadItem(mid, head.version_no, verified=True, stale=False, wrap_label="data")
                ],
                query=f"q {arg}",
            )
        elif op == "event":
            led.append_event(
                "quarantine" if arg == 0 else "review",
                {"item_id": f"q-{arg}", "action": "approve", "count": arg},
            )


def changed(column: str, value: Any) -> Any:
    if column == "ts_ms":
        return value + 1
    if column == "version_no":
        return 10**6 if value is None else value + 10**6
    if column in ("prev_hash", "hash"):
        return ("1" if value[0] == "0" else "0") + value[1:]
    if column == "body":
        return value + " "
    return "x" if value is None else value + "x"


@given(OPS, st.sampled_from(["mutate", "delete", "swap", "insert", "blob"]), st.data())
def test_pt_ledger_chain(ops: list[tuple[str, int]], tamper: str, data: st.DataObject) -> None:
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "ledger.db"
        led = open_ledger(path)
        run_ops(led, ops)
        report = led.verify()
        assert report.ok, report
        n = report.checked
        assert n >= 3
        assert led.export_head()[0] == n
        con = raw(path)
        blob_rows = con.execute("SELECT seq, col FROM blobs").fetchall()
        if tamper == "blob" and not blob_rows:
            tamper = "mutate"
        if tamper == "mutate":
            k = data.draw(st.integers(1, n))
            column = data.draw(st.sampled_from(COLUMNS))
            (value,) = con.execute(f"SELECT {column} FROM entries WHERE seq = ?", (k,)).fetchone()  # noqa: S608
            update = f"UPDATE entries SET {column} = ? WHERE seq = ?"  # noqa: S608
            con.execute(update, (changed(column, value), k))
        elif tamper == "delete":
            k = data.draw(st.integers(1, n))
            con.execute("DELETE FROM entries WHERE seq = ?", (k,))
        elif tamper == "swap":
            k = data.draw(st.integers(1, n - 1))
            cols = ", ".join(COLUMNS)
            a = con.execute(f"SELECT {cols} FROM entries WHERE seq = ?", (k,)).fetchone()  # noqa: S608
            b = con.execute(f"SELECT {cols} FROM entries WHERE seq = ?", (k + 1,)).fetchone()  # noqa: S608
            sets = ", ".join(f"{c} = ?" for c in COLUMNS)
            con.execute(f"UPDATE entries SET {sets} WHERE seq = ?", (*b, k))  # noqa: S608
            con.execute(f"UPDATE entries SET {sets} WHERE seq = ?", (*a, k + 1))  # noqa: S608
        elif tamper == "insert":
            k = data.draw(st.integers(1, n))
            j = data.draw(st.integers(1, n).filter(lambda x: x != k))
            cols = ", ".join(COLUMNS)
            copy = con.execute(f"SELECT {cols} FROM entries WHERE seq = ?", (j,)).fetchone()  # noqa: S608
            for table in ("entries", "blobs"):
                con.execute(f"UPDATE {table} SET seq = -(seq + 1) WHERE seq >= ?", (k,))  # noqa: S608
                con.execute(f"UPDATE {table} SET seq = -seq WHERE seq < 0")  # noqa: S608
            con.execute(
                f"INSERT INTO entries (seq, {cols}) VALUES (?, {', '.join('?' * len(COLUMNS))})",  # noqa: S608
                (k, *copy),
            )
        else:
            k, col = data.draw(st.sampled_from(blob_rows))
            (ct,) = con.execute(
                "SELECT ct FROM blobs WHERE seq = ? AND col = ?", (k, col)
            ).fetchone()
            flipped = bytes([ct[0] ^ 1]) + ct[1:]
            con.execute("UPDATE blobs SET ct = ? WHERE seq = ? AND col = ?", (flipped, k, col))
        con.close()
        result = led.verify()
        assert not result.ok
        assert result.failed_at == k, (tamper, result)
        led.close()


def test_pt_ledger_chain_tail_truncation_needs_exported_head(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    led = open_ledger(path)
    for i in range(3):
        put(led, content=f"v{i}")
    con = raw(path)
    saved_head = con.execute("SELECT seq, hash, signature FROM head").fetchone()
    con.close()
    later = [put(led, content=f"later {i}") for i in range(2)]
    exported = led.export_head()
    assert exported[0] == later[-1].seq == 5
    # Attacker deletes the newest rows and restores the older signed head (e.g. from a backup).
    con = raw(path)
    con.execute("DELETE FROM entries WHERE seq > 3")
    con.execute("DELETE FROM blobs WHERE seq > 3")
    con.execute("UPDATE head SET seq = ?, hash = ?, signature = ?", saved_head)
    con.close()
    assert led.verify().ok  # honest limit (D17): undetectable without an exported head
    report = led.verify(expected_head=exported)
    assert not report.ok
    assert report.failed_at == 5
    assert report.reason == "expected_head_missing"


def test_pt_ledger_chain_recomputed_chain_still_fails(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    led = open_ledger(path)
    put(led, trust_level="web", effective_type="data", content="poison")
    put(led, key="k2")
    led.record_read(session_id="s1", items=[], query=None)
    # Raise trust in row 1 and recompute every hash after it (no key needed for hashes).
    con = raw(path)
    body = json.loads(con.execute("SELECT body FROM entries WHERE seq = 1").fetchone()[0])
    body["fields"]["trust_level"] = "operator"
    con.execute("UPDATE entries SET body = ? WHERE seq = 1", (canonicalize(body).decode(),))
    recompute(con)
    con.close()
    report = led.verify()
    assert (report.ok, report.failed_at, report.reason) == (False, 1, "bad_version_signature")
    # A rewritten non-version row with a recomputed chain is caught by the head signature.
    path2 = tmp_path / "l2.db"
    led2 = open_ledger(path2)
    put(led2)
    led2.record_read(session_id="s1", items=[], query=None)
    con = raw(path2)
    con.execute("UPDATE entries SET ts_ms = ts_ms + 5 WHERE seq = 2")
    recompute(con)
    con.close()
    report = led2.verify()
    assert (report.ok, report.failed_at, report.reason) == (False, 2, "bad_head_signature")


def recompute(con: sqlite3.Connection) -> None:
    prev = GENESIS_HASH
    for row in con.execute(
        "SELECT seq, kind, ts_ms, memory_id, version_no, ref_hmac, body, prev_hash, hash"
        " FROM entries ORDER BY seq"
    ).fetchall():
        new = (*row[:7], prev, "")
        h = entry_hash(new)
        con.execute("UPDATE entries SET prev_hash = ?, hash = ? WHERE seq = ?", (prev, h, row[0]))
        prev = h
    con.execute("UPDATE head SET hash = ?", (prev,))


def test_pt_ledger_chain_transplanted_row_fails_on_link(tmp_path: Path) -> None:
    # A self-consistent row from another ledger at the same seq passes its own hash check;
    # only the link to the previous row catches it.
    a, b = tmp_path / "a.db", tmp_path / "b.db"
    la, lb = open_ledger(a), open_ledger(b)
    for led in (la, lb):
        put(led, content="one")
        led.record_read(session_id="s1", items=[], query=None)
        put(led, key="k2", content="three")
    donor = rows(b)[1]
    con = raw(a)
    sets = ", ".join(f"{c} = ?" for c in COLUMNS)
    con.execute(f"UPDATE entries SET {sets} WHERE seq = 2", donor[1:])  # noqa: S608
    con.close()
    report = la.verify()
    assert (report.ok, report.failed_at, report.reason) == (False, 2, "prev_hash_mismatch")


def test_read_path_rejects_edited_signed_field(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    led = open_ledger(path)
    r = put(led, trust_level="web", effective_type="data")
    con = raw(path)
    body = json.loads(con.execute("SELECT body FROM entries WHERE seq = 1").fetchone()[0])
    body["fields"]["trust_level"] = "operator"
    body["fields"]["effective_type"] = "fact"
    con.execute("UPDATE entries SET body = ? WHERE seq = 1", (canonicalize(body).decode(),))
    con.close()
    rec = led.version(r.memory_id, 1)
    assert rec is not None
    assert (rec.verified, rec.problem, rec.content) == (False, "bad_signature", None)
    head = led.head(r.memory_id)
    assert head is not None
    assert not head.verified


@pytest.mark.parametrize("target", [0, 2, 3, "1"])
def test_forged_purge_entry_with_bad_target_fails(tmp_path: Path, target: Any) -> None:
    # Even a key holder can't make verify() accept a purge that points nowhere or forward.
    led = open_ledger(tmp_path / "ledger.db")
    put(led)
    with led._txn():
        seq, prev = led._tail()
        led._append(
            KEYS,
            kind="purge",
            body={"target_seq": target, "cols": ["content"], "reason": "erasure"},
            seq=seq,
            prev_hash=prev,
        )
    report = led.verify()
    assert (report.ok, report.failed_at, report.reason) == (False, 2, "purge_invalid")


def test_unsigned_column_change_keeps_signature_but_breaks_chain(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    led = open_ledger(path)
    r = put(led)
    con = raw(path)
    con.execute("UPDATE entries SET ts_ms = ts_ms + 1000 WHERE seq = ?", (r.seq,))
    con.close()
    again = led.version(r.memory_id, 1)
    assert again is not None
    assert again.verified  # ts_ms is not a signed field (documents PT-SIGN-FIELDS coverage)
    report = led.verify()
    assert (report.ok, report.failed_at, report.reason) == (False, 1, "hash_mismatch")


# --- UT-LEDGER-003 -------------------------------------------------------------------------


def test_ut_ledger_003_head_and_stale(ledger: Ledger) -> None:
    r1 = put(ledger, content="a")
    assert ledger.is_head(r1.memory_id, 1)
    r2 = put(ledger, content="b")
    head = ledger.head(r1.memory_id)
    assert head is not None
    assert head.version_no == 2
    assert head.signature == r2.signature
    assert not ledger.is_head(r1.memory_id, 1)
    assert ledger.is_head(r1.memory_id, 2)
    assert not ledger.is_head(r1.memory_id, 3)
    assert not ledger.is_head("mem-unknown", 1)
    assert ledger.head("mem-unknown") is None
    old = ledger.version(r1.memory_id, 1)
    assert old is not None
    assert old.content == "a"
    assert ledger.version(r1.memory_id, 9) is None
    deleted = put(ledger, content=None, status="deleted")
    head = ledger.head(r1.memory_id)
    assert head is not None
    assert head.version_no == deleted.version_no == 3
    assert head.fields.status == "deleted"
    assert head.content is None
    assert [v.version_no for v in ledger.versions(r1.memory_id)] == [1, 2, 3]


# --- UT-LEDGER-004 -------------------------------------------------------------------------

CHILD = """
import sys
from pathlib import Path
from mnemowall.keys import FileKeyProvider
from mnemowall.ledger import Ledger
led = Ledger.open(Path(sys.argv[1]), FileKeyProvider(Path(sys.argv[2])), tenant_id="tenant-a")
for i in range(50):
    led.append_version(
        namespace=("users", "u-1"), key=f"k{i % 3}", content=f"p{sys.argv[3]}-{i}", scope="user",
        trust_level="user", effective_type="fact", memory_type="fact", protected=False,
        status="active", bundle_id="builtin-default", provenance={"n": i},
    )
led.close()
"""


@pytest.mark.skipif(os.name != "posix", reason="file key provider is POSIX-only")
def test_ut_ledger_004_concurrent_writers(tmp_path: Path) -> None:
    key_file = tmp_path / "keys" / "keys.json"
    provider = FileKeyProvider(key_file)
    provider.init()
    path = tmp_path / "ledger.db"
    open_ledger(path, provider).close()
    errors: list[BaseException] = []

    def worker(n: int) -> None:
        try:
            led = open_ledger(path, provider)
            for i in range(50):
                put(led, key=f"k{i % 3}", content=f"t{n}-{i}")
            led.close()
        except BaseException as exc:  # noqa: BLE001 - surfaced through the assertion below
            errors.append(exc)

    shared = open_ledger(path, provider)

    def shared_worker() -> None:
        try:
            for i in range(25):
                put(shared, key=f"k{i % 3}", content=f"s-{i}")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    procs = [
        subprocess.Popen([sys.executable, "-c", CHILD, str(path), str(key_file), str(p)])  # noqa: S603
        for p in range(4)
    ]
    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    threads += [threading.Thread(target=shared_worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert [p.wait(timeout=120) for p in procs] == [0, 0, 0, 0]
    assert not errors, errors
    expected = 8 * 50 + 4 * 50 + 2 * 25
    report = shared.verify()
    assert report.ok, report
    assert report.checked == expected
    versions = [(r[3], r[4]) for r in rows(path) if r[1] == "version"]
    assert len(versions) == len(set(versions)) == expected
    by_memory: dict[str, list[int]] = {}
    for mid, v in versions:
        by_memory.setdefault(mid, []).append(v)
    assert len(by_memory) == 3
    for vs in by_memory.values():
        assert sorted(vs) == list(range(1, len(vs) + 1))
    shared.close()


# --- UT-LEDGER-005 -------------------------------------------------------------------------


def test_ut_ledger_005_delete_and_purge(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    led = open_ledger(path)
    r1 = put(led, content=CANARY)
    put(led, content=None, status="deleted")
    assert led.purge(r1.memory_id, 1, reason="erasure")
    assert not led.purge(r1.memory_id, 1, reason="erasure")  # already purged: no-op
    with pytest.raises(LedgerError):
        led.purge(r1.memory_id, 7, reason="erasure")
    with pytest.raises(LedgerError):
        led.purge(r1.memory_id, 1, reason="because")
    v1 = led.version(r1.memory_id, 1)
    assert v1 is not None
    assert v1.content is None
    assert v1.purged
    assert v1.verified  # the signature covers the content HMAC, which is kept
    assert v1.fields.content_hash == r1.fields.content_hash
    con = sqlite3.connect(path)
    assert con.execute(
        "SELECT count(*) FROM blobs WHERE seq = 1 AND col = 'content'"
    ).fetchone() == (0,)
    kinds = [k for (k,) in con.execute("SELECT kind FROM entries ORDER BY seq")]
    con.close()
    assert kinds == ["version", "version", "purge"]
    report = led.verify()
    assert report.ok, report
    assert report.checked == 3


def test_ut_ledger_005_missing_blob_without_purge_fails(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    led = open_ledger(path)
    put(led)
    put(led, key="k2")
    con = raw(path)
    con.execute("DELETE FROM blobs WHERE seq = 2 AND col = 'content'")
    con.close()
    report = led.verify()
    assert (report.ok, report.failed_at, report.reason) == (False, 2, "blob_missing")


# --- UT-LEDGER-006 -------------------------------------------------------------------------


class Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def test_ut_ledger_006_retention(tmp_path: Path) -> None:
    day = 86_400.0
    clock = Clock(1_800_000_000.0)
    led = open_ledger(tmp_path / "ledger.db", clock=clock)
    r1 = put(led, content="old")
    clock.t += day
    put(led, content="current")
    lonely = put(led, key="k2", content="ancient head")
    led.record_read(session_id="s1", items=[], query="q")
    clock.t += 89 * day
    assert led.apply_retention() == {"versions_purged": 0, "reads_purged": 0}
    clock.t += 2 * day
    assert led.apply_retention() == {"versions_purged": 1, "reads_purged": 1}
    assert led.apply_retention() == {"versions_purged": 0, "reads_purged": 0}
    v1 = led.version(r1.memory_id, 1)
    assert v1 is not None
    assert v1.content is None
    assert v1.purged
    head = led.head(r1.memory_id)
    assert head is not None
    assert head.content == "current"
    clock.t += 1000 * day
    led.apply_retention()
    still = led.head(lonely.memory_id)
    assert still is not None
    assert still.content == "ancient head"
    assert led.reads()[0].items == ()
    assert led.reads()[0].purged
    assert led.verify().ok


@pytest.mark.parametrize("days", [0, -1, 3651, 1.5, True])
def test_ut_ledger_006_retention_range(tmp_path: Path, days: Any) -> None:
    with pytest.raises(LedgerError) as exc:
        open_ledger(tmp_path / "ledger.db", retention_days=days)
    assert exc.value.reason == "retention_out_of_range"


def test_ut_ledger_006_retention_bounds_accepted(tmp_path: Path) -> None:
    open_ledger(tmp_path / "a.db", retention_days=1).close()
    open_ledger(tmp_path / "b.db", retention_days=3650).close()


# --- UT-LEDGER-007 -------------------------------------------------------------------------


class BrokenKeyring:
    def get_password(self, service: str, account: str) -> str | None:
        raise RuntimeError("locked")

    def set_password(self, service: str, account: str, password: str) -> None:
        raise RuntimeError("locked")


def test_ut_ledger_007_keys_unavailable_fails_closed(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "ledger.db"
    with caplog.at_level(logging.WARNING, logger="mnemowall"):
        led = open_ledger(path, KeychainKeyProvider(backend=BrokenKeyring()))
        assert led.locked
        with pytest.raises(LedgerUnavailable) as exc:
            put(led, content=CANARY)
        assert exc.value.reason == "keys_unavailable"
        with pytest.raises(LedgerUnavailable):
            led.record_read(session_id="s", items=[], query=None)
        with pytest.raises(LedgerUnavailable):
            led.append_event("review", {"item_id": "q-1"})
        with pytest.raises(LedgerUnavailable):
            led.verify()
    assert diagnostics.counters().get("ledger_append_refused", 0) >= 3
    assert any(r.getMessage() == "ledger_append_refused" for r in caplog.records)
    assert CANARY not in caplog.text
    con = sqlite3.connect(path)
    assert con.execute("SELECT count(*) FROM entries").fetchone() == (0,)
    con.close()


@pytest.mark.parametrize("where", ["sign_version", "head_signature"])
def test_ut_ledger_007_failure_mid_append_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    path = tmp_path / "ledger.db"
    led = open_ledger(path)
    put(led)
    import mnemowall.ledger.store as store

    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("crashed")

    if where == "sign_version":  # before anything is written
        monkeypatch.setattr(store, "sign_version", boom)
    else:  # after the entry and its blobs are inserted, before the head is re-signed
        monkeypatch.setattr(store.Ledger, "_head_message", boom)
    with pytest.raises(RuntimeError):
        put(led, content="second")
    if where == "head_signature":
        with pytest.raises(RuntimeError):
            led.record_read(session_id="s1", items=[], query=None)
    monkeypatch.undo()
    con = sqlite3.connect(path)
    assert con.execute("SELECT count(*) FROM entries").fetchone() == (1,)
    assert con.execute("SELECT count(*) FROM blobs WHERE seq > 1").fetchone() == (0,)
    assert con.execute("SELECT seq FROM head").fetchone() == (1,)
    con.close()
    assert led.verify().ok
    assert put(led, content="third").version_no == 2
    assert led.verify().ok


# --- UT-LEDGER-008 -------------------------------------------------------------------------


def test_ut_ledger_008_swapped_ciphertext_never_decrypts(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    led = open_ledger(path)
    a = put(led, key="a", content="content A")
    b = put(led, key="b", content="content B")
    con = raw(path)
    blob_a = con.execute(
        "SELECT nonce, ct FROM blobs WHERE seq = ? AND col = 'content'", (a.seq,)
    ).fetchone()
    blob_b = con.execute(
        "SELECT nonce, ct FROM blobs WHERE seq = ? AND col = 'content'", (b.seq,)
    ).fetchone()
    con.execute(
        "UPDATE blobs SET nonce = ?, ct = ? WHERE seq = ? AND col = 'content'", (*blob_b, a.seq)
    )
    con.execute(
        "UPDATE blobs SET nonce = ?, ct = ? WHERE seq = ? AND col = 'content'", (*blob_a, b.seq)
    )
    con.close()
    for rec in (led.version(a.memory_id, 1), led.version(b.memory_id, 1)):
        assert rec is not None
        assert rec.content is None
        assert not rec.verified
        assert rec.problem == "decrypt_failed"


def test_ut_ledger_008_column_swap_within_row(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    led = open_ledger(path)
    r = put(led, content="secret")
    con = raw(path)
    ns = con.execute("SELECT nonce, ct FROM blobs WHERE seq = 1 AND col = 'namespace'").fetchone()
    con.execute("UPDATE blobs SET nonce = ?, ct = ? WHERE seq = 1 AND col = 'content'", ns)
    con.close()
    rec = led.version(r.memory_id, 1)
    assert rec is not None
    assert (rec.content, rec.verified, rec.problem) == (None, False, "decrypt_failed")


def test_ut_ledger_008_wrong_storage_key(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    r = put(open_ledger(path), content="secret")
    other = EphemeralKeyProvider()
    other.init()
    led = open_ledger(path, other)
    assert led.find(("users", "u-1"), "k1") is None  # lookups use the HMAC key
    rec = led.version(r.memory_id, 1)
    assert rec is not None
    assert rec.content is None
    assert not rec.verified


# --- UT-LEDGER-009 -------------------------------------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_ut_ledger_009_file_permissions_and_pragmas(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    led = open_ledger(path)
    put(led)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    wal = Path(str(path) + "-wal")
    assert wal.exists()
    assert stat.S_IMODE(wal.stat().st_mode) & 0o077 == 0
    assert led.pragmas() == {"journal_mode": "wal", "synchronous": 1, "secure_delete": 1}


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_ut_ledger_009_missing_parent_created_private(tmp_path: Path) -> None:
    path = tmp_path / "new" / "dir" / "ledger.db"
    open_ledger(path).close()
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_ut_ledger_009_loose_existing_file_refused(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    open_ledger(path).close()
    path.chmod(0o644)
    with pytest.raises(LedgerError) as exc:
        open_ledger(path)
    assert exc.value.reason == "insecure_permissions"


def test_ut_ledger_009_schema_and_identity_checks(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    open_ledger(path).close()
    con = sqlite3.connect(path)
    con.execute("UPDATE meta SET v = '99' WHERE k = 'schema_version'")
    con.commit()
    con.close()
    with pytest.raises(LedgerError) as exc:
        open_ledger(path)
    assert exc.value.reason == "schema_too_new"
    other = tmp_path / "other.db"
    other.touch(mode=0o600)
    con = sqlite3.connect(other)
    con.execute("CREATE TABLE t (x)")
    con.commit()
    con.close()
    with pytest.raises(LedgerError) as exc:
        open_ledger(other)
    assert exc.value.reason == "not_a_ledger"
    path2 = tmp_path / "l2.db"
    open_ledger(path2).close()
    with pytest.raises(LedgerError) as exc:
        Ledger.open(path2, PROVIDER, tenant_id="tenant-b")
    assert exc.value.reason == "tenant_mismatch"


# --- events --------------------------------------------------------------------------------


def test_append_event_accepts_identifiers_only(ledger: Ledger) -> None:
    seq = ledger.append_event("review", {"item_id": "q-1", "action": "approve", "n": 2, "ok": True})
    assert ledger.events()[0] == (
        seq,
        "review",
        {"item_id": "q-1", "action": "approve", "n": 2, "ok": True},
    )
    for bad in (
        {"note": CANARY + " free text"},
        {"item_id": 1.5},
        {"x": ["a"]},
        {"Bad Key": "a"},
    ):
        with pytest.raises(LedgerError) as exc:
            ledger.append_event("review", bad)
        assert CANARY not in str(exc.value)
    with pytest.raises(LedgerError):
        ledger.append_event("version", {"a": "b"})


def test_ledger_infer_events_and_recent_query(ledger: Ledger) -> None:
    """M1b-03 (D54): signed ``infer`` events, queried newest first per scope."""
    for i, trust in enumerate(("email", "user", "verified_user")):
        ledger.append_event("infer", {"scope": "s-a", "trust": trust, "n": i})
    ledger.append_event("infer", {"scope": "s-b", "trust": "web"})
    ledger.append_event("review", {"item_id": "q-1", "scope": "s-a"})
    got = ledger.recent_events("infer", "scope", "s-a", 2)
    assert [e["trust"] for e in got] == ["verified_user", "user"]
    assert [e["trust"] for e in ledger.recent_events("infer", "scope", "s-a", 10)] == [
        "verified_user",
        "user",
        "email",
    ]
    assert ledger.recent_events("infer", "scope", "s-c", 10) == []
    assert [k for _, k, _ in ledger.events()] == ["infer"] * 4 + ["review"]
    assert ledger.verify().ok
    for args in (
        ("version", "scope", "s-a", 1),
        ("infer", "Bad", "s-a", 1),
        ("infer", "scope", "s-a", 0),
    ):
        with pytest.raises(LedgerError, match="event_query_invalid"):
            ledger.recent_events(*args)


# --- CAN-LEDGER-AT-REST --------------------------------------------------------------------


def encodings(s: str) -> list[bytes]:
    out = [s.encode("utf-8"), s.encode("utf-16-le"), s.encode("utf-16-be")]
    raw_bytes = s.encode("utf-8")
    for pad in range(3):
        b64 = base64.b64encode(b"\x00" * pad + raw_bytes)
        out.append(b64[4:-4])
        out.append(base64.urlsafe_b64encode(b"\x00" * pad + raw_bytes)[4:-4])
    out.append(raw_bytes.hex().encode())
    return out


def scan(paths: list[Path]) -> list[str]:
    found = []
    for p in paths:
        if not p.exists():
            continue
        data = p.read_bytes()
        for c in CANARIES:
            if any(e in data for e in encodings(c)):
                found.append(f"{p.name}:{c}")
    return found


def test_can_ledger_at_rest(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    led = open_ledger(path)
    ns = ("users", CANARY_EMAIL, CANARY_NS)
    r = put(
        led,
        ns=ns,
        key=CANARY_ITEM,
        content=f"{CANARY} {CANARY_URL} {CANARY_EMAIL}",
        provenance={"source_ref": CANARY_SOURCE, "decision_id": "dec-1"},
    )
    put(led, ns=ns, key=CANARY_ITEM, content=f"update {CANARY}")
    led.record_read(
        session_id="sess-1",
        items=[ReadItem(r.memory_id, 1, verified=True, stale=True, wrap_label="data")],
        query=CANARY_QUERY,
    )
    led.append_event("review", {"item_id": "q-1", "action": "approve"})
    put(led, ns=ns, key=CANARY_ITEM, content=None, status="deleted")
    led.purge(r.memory_id, 1, reason="erasure")
    files = [path, Path(str(path) + "-wal"), Path(str(path) + "-shm")]
    assert scan(files) == []
    assert led.find(ns, CANARY_ITEM) == r.memory_id
    led.checkpoint()
    assert scan(files) == []
    led.vacuum()
    assert scan(files) == []
    led.close()
    assert scan(files) == []
    # The scanner itself works: a plaintext canary written into the file is found.
    with path.open("ab") as fh:
        fh.write(CANARY.encode("utf-16-le"))
    assert scan([path]) == [f"ledger.db:{CANARY}"]


def test_ut_ledger_provenance_record(tmp_path: Path) -> None:
    """M1b-02: the decrypted provenance of a verified version, checked against its signed hash."""
    led = open_ledger(tmp_path / "ledger.db")
    rec = led.append_version(
        namespace=("u",),
        key="k",
        content="x",
        scope="user",
        trust_level="user",
        effective_type="fact",
        memory_type="fact",
        bundle_id="b",
        provenance={"backend": "mem0", "agent_id": "travel"},
    )
    assert led.provenance(rec.memory_id, 1) == {"backend": "mem0", "agent_id": "travel"}
    assert led.provenance(rec.memory_id, 2) is None
    assert led.provenance("nope", 1) is None
    with sqlite3.connect(tmp_path / "ledger.db") as con:
        con.execute("UPDATE blobs SET ct = ? WHERE col = 'provenance'", (b"\x00" * 40,))
    assert led.provenance(rec.memory_id, 1) is None
