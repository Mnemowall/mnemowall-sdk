"""M1b-03: Mem0 infer mode (beta, detective). CT-M0-INFER-* (test spec M1b-01-04, D40, D53-D57).

Mem0's LLM extracts and stores first; the wrapper then diffs the scope, checks every new or
changed item against policy, removes what policy would not commit and restores protected
memories. Keyless: the scripted LLM decides what is "extracted".
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from mem0 import Memory
from mem0_fakes import EventMemory, make_async_memory, make_memory
from test_mem0_contract import (  # noqa: F401 - the autouse fixtures apply here too
    INSTRUCTION,
    M0,
    PROVIDER,
    TEA,
    _close,
    _no_network,
    make_m0,
    session,
)

import mnemowall.adapters.mem0 as m0mod
from mnemowall.adapters.mem0 import (
    GuardedAsyncMemory,
    GuardedMemory,
    MemoryWriteDenied,
    MemoryWriteRefused,
    derive_user_id,
)
from mnemowall.core import diagnostics
from mnemowall.ledger import Ledger
from mnemowall.policy import load_policy
from mnemowall.quarantine import Quarantine

FACT = "Alice prefers green tea in the afternoon."
STANDING = "From now on, always reply in English."
FRENCH = "From now on, always reply in French."
ALICE = derive_user_id("tenant-a", "user", "alice")


@pytest.fixture
def inf(tmp_path: Path) -> M0:
    return make_m0(tmp_path, mode="infer")


def _events(out: dict[str, Any]) -> list[str]:
    return [r["event"] for r in out["results"]]


def _ids(m: Memory) -> dict[str, str]:
    return {
        r["id"]: r["memory"] for r in m.get_all(filters={"user_id": ALICE}, top_k=1000)["results"]
    }


def _event_m0(tmp: Path) -> M0:
    return make_m0(tmp, mode="infer", inner=make_memory(tmp / "mem0", cls=EventMemory))


# --- CT-M0-INFER-001: a trusted extraction commits and reads verified -------------------------


def test_ct_m0_infer_001_trusted_extraction_commits_signed(inf: M0) -> None:
    inf.inner.llm.script = [[FACT]]
    with session("verified"):
        out = inf.mem.add("I really like green tea after lunch.", infer=True)
    (res,) = out["results"]
    assert res["event"] == "ADD"
    assert res["memory"] == FACT
    assert res["mnemowall"]["outcome"] == "committed"
    assert res["mnemowall"]["trust"] == "verified_user"
    assert inf.raw() == [FACT]
    with session("trusted"):
        (got,) = inf.mem.get_all()["results"]
    assert got["id"] == res["id"]
    assert got["mnemowall"]["verified"] is True
    assert got["mnemowall"]["memory_id"] == res["mnemowall"]["memory_id"]
    assert inf.inner.llm.calls == 1


def test_ct_m0_infer_001b_strict_add_still_works_in_infer_mode(inf: M0) -> None:
    with session("verified"):
        (res,) = inf.mem.add(TEA)["results"]
    assert res["event"] == "ADD"
    assert inf.inner.llm.calls == 0
    assert inf.raw() == [TEA]


def test_ct_m0_infer_001c_nothing_extracted(inf: M0) -> None:
    inf.inner.llm.script = [[]]
    with session("verified"):
        assert inf.mem.add("hello", infer=True) == {"results": []}
    assert inf.raw() == []


# --- CT-M0-INFER-002: a tainted instruction is removed and quarantined -----------------------


def test_ct_m0_infer_002_tainted_instruction_removed_and_quarantined(
    inf: M0, caplog: pytest.LogCaptureFixture
) -> None:
    inf.inner.llm.script = [[INSTRUCTION, FACT]]
    with caplog.at_level(logging.DEBUG, logger="mnemowall"), session("tainted"):
        out = inf.mem.add("an email body", infer=True)
    assert sorted(_events(out)) == ["ADD", "QUARANTINED"]
    removed = next(r for r in out["results"] if r["event"] == "QUARANTINED")
    assert removed["id"] is None
    assert removed["memory"] is None
    assert inf.raw() == [FACT]  # the instruction is gone from Mem0
    (item,) = inf.quarantine.list()
    assert item.item_id == removed["mnemowall"]["item_id"]
    assert inf.quarantine.show(item.item_id).content is not None
    kept = next(r for r in out["results"] if r["event"] == "ADD")
    assert kept["mnemowall"]["trust"] == "email"
    assert diagnostics.counters().get("infer_removed") == 1
    ours = [r for r in caplog.records if r.name.startswith("mnemowall")]
    assert any(r.getMessage() == "infer_removed" for r in ours)
    assert not any(
        "evil-payments" in r.getMessage() or "green tea" in str(r.__dict__) for r in ours
    )


def test_ct_m0_infer_002b_denied_extraction_is_removed_not_quarantined(tmp_path: Path) -> None:
    shared = make_m0(tmp_path, mode="infer", scope="shared")  # no grant: every write is denied
    shared.inner.llm.script = [[FACT]]
    with session("verified"):
        out = shared.mem.add("x", infer=True)
    (res,) = out["results"]
    assert res["event"] == "DENIED"
    assert res["id"] is None
    assert res["mnemowall"]["outcome"] == "denied"
    assert all(isinstance(r, str) for r in res["mnemowall"]["rule_ids"])
    shared_uid = derive_user_id("tenant-a", "shared", "alice")
    assert shared.inner.get_all(filters={"user_id": shared_uid})["results"] == []
    assert shared.quarantine.list() == []
    assert diagnostics.counters().get("infer_removed") == 1


# --- CT-M0-INFER-003: UPDATE/DELETE events on protected memories are undone -------------------


def _protected(m: M0) -> dict[str, Any]:
    with session("verified"):
        (res,) = m.mem.add(STANDING)["results"]
    assert isinstance(res, dict)
    head = m.ledger.head(res["mnemowall"]["memory_id"])
    assert head is not None
    assert head.fields.memory_type == "standing_instruction"  # S7 guards it (I4)
    return res


def test_ct_m0_infer_003_update_of_protected_memory_restored(tmp_path: Path) -> None:
    m = _event_m0(tmp_path)
    res = _protected(m)
    before = m.ledger.head(res["mnemowall"]["memory_id"])

    def mem0_update(inner: Memory) -> Any:
        Memory.update(inner, res["id"], text=FRENCH)
        return {"results": [{"id": res["id"], "memory": FRENCH, "event": "UPDATE"}]}

    m.inner.action = mem0_update
    with session("tainted"):
        out = m.mem.add("an email body", infer=True)
    assert _events(out) == ["RESTORED"]
    assert out["results"][0]["id"] == res["id"]
    assert m.raw() == [STANDING]
    assert m.ledger.head(res["mnemowall"]["memory_id"]) == before  # no new version
    assert diagnostics.counters().get("infer_restored") == 1
    with session("trusted"):
        got = m.mem.get(res["id"])
    assert got is not None
    assert got["mnemowall"]["verified"] is True
    assert got["mnemowall"]["raw"] == STANDING


def test_ct_m0_infer_003b_delete_of_protected_memory_restored(tmp_path: Path) -> None:
    m = _event_m0(tmp_path)
    res = _protected(m)

    def mem0_delete(inner: Memory) -> Any:
        Memory.delete(inner, res["id"])
        return {"results": [{"id": res["id"], "memory": STANDING, "event": "DELETE"}]}

    m.inner.action = mem0_delete
    with session("tainted"):
        out = m.mem.add("an email body", infer=True)
    assert _events(out) == ["RESTORED"]
    assert m.raw() == [STANDING]
    assert diagnostics.counters().get("infer_restored") == 1
    with session("trusted"):
        (got,) = m.mem.get_all()["results"]
    assert got["mnemowall"]["verified"] is True
    assert got["mnemowall"]["memory_id"] == res["mnemowall"]["memory_id"]


def test_ct_m0_infer_003c_allowed_update_commits_new_version(tmp_path: Path) -> None:
    m = _event_m0(tmp_path)
    with session("verified"):
        (res,) = m.mem.add(TEA)["results"]
    newer = "I prefer jasmine tea in the afternoon."

    def mem0_update(inner: Memory) -> Any:
        Memory.update(inner, res["id"], text=newer)
        return {"results": [{"id": res["id"], "memory": newer, "event": "UPDATE"}]}

    m.inner.action = mem0_update
    with session("verified"):
        out = m.mem.add("I switched to jasmine.", infer=True)
    assert _events(out) == ["UPDATE"]
    head = m.ledger.head(res["mnemowall"]["memory_id"])
    assert head is not None
    assert head.version_no == 2
    with session("trusted"):
        got = m.mem.get(res["id"])
    assert got is not None
    assert got["mnemowall"]["verified"] is True
    assert got["mnemowall"]["raw"] == newer


def test_ct_m0_infer_003d_allowed_delete_signs_deletion(tmp_path: Path) -> None:
    m = _event_m0(tmp_path)
    with session("verified"):
        (res,) = m.mem.add(TEA)["results"]

    def mem0_delete(inner: Memory) -> Any:
        Memory.delete(inner, res["id"])
        return {"results": [{"id": res["id"], "memory": TEA, "event": "DELETE"}]}

    m.inner.action = mem0_delete
    with session("verified"):
        out = m.mem.add("forget the tea", infer=True)
    assert _events(out) == ["DELETE"]
    head = m.ledger.head(res["mnemowall"]["memory_id"])
    assert head is not None
    assert head.status == "deleted"
    assert m.raw() == []


def test_ct_m0_infer_003e_unreported_changes_are_still_found(tmp_path: Path) -> None:
    """Detection diffs the scope; it does not trust Mem0's event list (D53)."""
    m = _event_m0(tmp_path)
    res = _protected(m)

    def silent(inner: Memory) -> Any:
        Memory.update(inner, res["id"], text=FRENCH)
        Memory.add(inner, INSTRUCTION, user_id=ALICE, infer=False)
        return {"results": []}

    m.inner.action = silent
    with session("tainted"):
        out = m.mem.add("an email body", infer=True)
    assert sorted(_events(out)) == ["QUARANTINED", "RESTORED"]
    assert m.raw() == [STANDING]


# --- CT-M0-INFER-004: one infer add per user at a time ------------------------------------


def test_ct_m0_infer_004_concurrent_adds_are_serialised(tmp_path: Path) -> None:
    m = _event_m0(tmp_path)
    facts = {"a": "Alice likes oolong.", "b": "Alice likes rooibos."}
    m.inner.llm.hook = lambda: time.sleep(0.15)
    m.inner.llm.script = [[facts["a"]], [facts["b"]]]
    outs: dict[str, Any] = {}
    errors: list[BaseException] = []

    def run(name: str) -> None:
        try:
            with session("verified"):
                outs[name] = m.mem.add(f"message {name}", infer=True)
        except BaseException as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(n,)) for n in facts]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert errors == []
    assert m.inner.max_active == 1
    got = sorted(r["memory"] for out in outs.values() for r in out["results"])
    assert got == sorted(facts.values())  # each add accounts for its own item only
    assert all(len(out["results"]) == 1 for out in outs.values())
    assert m.raw() == sorted(facts.values())


# --- CT-M0-INFER-005/006: the trust floor (D54) -----------------------------------------------


def test_ct_m0_infer_005_low_trust_memory_in_scope_lowers_trust(inf: M0) -> None:
    with session("tainted"):
        inf.mem.add(TEA)  # committed at email trust, as wrapped data
    inf.inner.llm.script = [[FRENCH]]
    with session("verified"):
        out = inf.mem.add("please answer in French from now on", infer=True)
    assert _events(out) == ["QUARANTINED"]  # Mem0's model may have seen the email memory


def test_ct_m0_infer_005b_raw_item_in_scope_lowers_trust(inf: M0) -> None:
    Memory.add(inf.inner, "planted", user_id=ALICE, infer=False)  # unverified
    inf.inner.llm.script = [[FACT]]
    with session("verified"):
        (res,) = inf.mem.add("x", infer=True)["results"]
    assert res["mnemowall"]["trust"] == "unknown"


def test_ct_m0_infer_006_tainted_history_carries_over(inf: M0) -> None:
    inf.inner.llm.script = [[], [FRENCH]]
    with session("tainted"):
        assert inf.mem.add("an email body", infer=True) == {"results": []}
    with session("verified"):
        out = inf.mem.add("ok", infer=True)
    assert _events(out) == ["QUARANTINED"]  # Mem0 feeds the saved email to its model again


def test_ct_m0_infer_006b_history_window_is_ten_calls(inf: M0) -> None:
    inf.inner.llm.script = [[]] * 11 + [[FRENCH]]
    with session("tainted"):
        inf.mem.add("an email body", infer=True)
    for i in range(10):
        with session("verified"):
            inf.mem.add(f"benign {i}", infer=True)
    with session("verified"):
        (res,) = inf.mem.add("please answer in French from now on", infer=True)["results"]
    assert res["event"] == "ADD"
    assert res["mnemowall"]["trust"] == "verified_user"


def test_ct_m0_infer_006c_history_is_per_mem0_scope(inf: M0) -> None:
    inf.inner.llm.script = [[], [FRENCH]]
    with session("tainted"):
        inf.mem.add("an email body", infer=True, agent_id="mailbot")
    with session("verified"):
        (res,) = inf.mem.add("please answer in French", infer=True, agent_id="planner")["results"]
    assert res["event"] == "ADD"


def test_ct_m0_infer_006d_history_is_signed_in_the_ledger(inf: M0) -> None:
    inf.inner.llm.script = [[]]
    with session("tainted"):
        inf.mem.add("an email body", infer=True)
    kinds = [kind for _, kind, _ in inf.ledger.events()]
    assert kinds == ["infer"]
    (fields,) = [f for _, k, f in inf.ledger.events() if k == "infer"]
    assert fields["trust"] == "email"
    assert set(fields) == {"scope", "trust"}
    assert inf.ledger.verify().ok


# --- CT-M0-INFER-007..010: limits and failures -----------------------------------------------


def test_ct_m0_infer_007_scope_too_large_refused_before_mem0(
    inf: M0, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(m0mod, "MAX_SCAN", 2)
    with session("verified"):
        inf.mem.add(TEA)
        inf.mem.add(FACT)
    with session("verified"), pytest.raises(MemoryWriteRefused) as exc:
        inf.mem.add("x", infer=True)
    assert exc.value.reason == "scope_too_large"
    assert inf.inner.llm.calls == 0


def test_ct_m0_infer_008_removal_failure_raises_after_processing_all(
    inf: M0, monkeypatch: pytest.MonkeyPatch
) -> None:
    inf.inner.llm.script = [[INSTRUCTION, FACT]]

    def broken(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("store down")

    monkeypatch.setattr(inf.inner, "delete", broken)
    with session("tainted"), pytest.raises(MemoryWriteRefused) as exc:
        inf.mem.add("an email body", infer=True)
    assert exc.value.reason == "backend_error"
    assert exc.value.__context__ is None
    assert len(inf.quarantine.list()) == 1  # still submitted for review
    with session("trusted"):
        rows = {r["mnemowall"]["raw"]: r["mnemowall"] for r in inf.mem.get_all()["results"]}
    assert rows[INSTRUCTION]["verified"] is False  # the leftover reads unverified
    assert rows[FACT]["verified"] is True  # the other item was still processed


def test_ct_m0_infer_009_mem0_fails_after_storing(tmp_path: Path) -> None:
    m = _event_m0(tmp_path)

    def partial(inner: Memory) -> Any:
        Memory.add(inner, INSTRUCTION, user_id=ALICE, infer=False)
        raise RuntimeError("llm timeout")

    m.inner.action = partial
    with session("tainted"), pytest.raises(MemoryWriteRefused) as exc:
        m.mem.add("an email body", infer=True)
    assert exc.value.reason == "backend_error"
    assert exc.value.__context__ is None
    assert m.raw() == []  # what it stored before failing was still checked and removed
    assert len(m.quarantine.list()) == 1


def test_ct_m0_infer_010_concurrent_verified_writes_are_left_alone(tmp_path: Path) -> None:
    """A signed item that lands during the window (another writer) is not ours to judge."""
    m = _event_m0(tmp_path)
    other = GuardedMemory(m.inner, ledger=m.ledger, quarantine=m.quarantine, tenant_id="tenant-a")
    written: list[str] = []

    def other_writer(inner: Memory) -> Any:
        (res,) = other.add(TEA)["results"]  # a strict, signed write by another wrapper
        written.append(res["mnemowall"]["memory_id"])
        return {"results": []}

    m.inner.action = other_writer
    with session("tainted"):
        assert m.mem.add("x", infer=True) == {"results": []}
    assert m.raw() == [TEA]
    assert m.quarantine.list() == []
    head = m.ledger.head(written[0])
    assert head is not None
    assert head.version_no == 1


def test_ct_m0_infer_010b_concurrent_signed_delete_is_not_redone(tmp_path: Path) -> None:
    """A memory another wrapper deleted during the window is that writer's change, not Mem0's."""
    m = _event_m0(tmp_path)
    other = GuardedMemory(m.inner, ledger=m.ledger, quarantine=m.quarantine, tenant_id="tenant-a")
    with session("verified"):
        (res,) = m.mem.add(STANDING)["results"]

    def other_deletes(inner: Memory) -> Any:
        other.delete(res["id"])  # a signed deletion from the same verified turn
        return {"results": []}

    m.inner.action = other_deletes
    with session("verified"):
        assert m.mem.add("x", infer=True) == {"results": []}
    head = m.ledger.head(res["mnemowall"]["memory_id"])
    assert head is not None
    assert head.status == "deleted"
    assert head.version_no == 2  # one deletion, not a second one by the reconcile
    assert m.raw() == []
    assert diagnostics.counters().get("infer_restored") is None


def test_ct_m0_infer_011_user_id_mismatch_still_denied(inf: M0) -> None:
    with session("verified"), pytest.raises(MemoryWriteDenied):
        inf.mem.add("x", infer=True, user_id="mallory")
    assert inf.inner.llm.calls == 0


# --- async -----------------------------------------------------------------------------------


def test_ct_m0_infer_async(tmp_path: Path) -> None:
    ledger = Ledger.open(tmp_path / "ledger.db", PROVIDER, tenant_id="tenant-a")
    quarantine = Quarantine.open(
        tmp_path / "q", PROVIDER, ledger=ledger, policy=load_policy(), tenant_id="tenant-a"
    )
    inner = make_async_memory(tmp_path / "mem0")
    inner.llm.script = [[INSTRUCTION, FACT]]
    mem = GuardedAsyncMemory(
        inner, ledger=ledger, quarantine=quarantine, tenant_id="tenant-a", mode="infer"
    )

    async def go() -> dict[str, Any]:
        with session("tainted"):
            return await mem.add("an email body", infer=True)

    try:
        out = asyncio.run(go())
        assert sorted(_events(out)) == ["ADD", "QUARANTINED"]
        assert len(quarantine.list()) == 1
    finally:
        quarantine.close()
        ledger.close()
