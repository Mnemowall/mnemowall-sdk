"""M1a-21: export --jsonl, verify-ledger, doctor. UT-EXPORT-*, UT-VERIFY-LEDGER-*, UT-DOCTOR-*."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any

import pytest
from langgraph.store.memory import InMemoryStore

from mnemowall import cli
from mnemowall.adapters.langgraph import GuardedStore
from mnemowall.core import diagnostics
from mnemowall.doctor import Finding, run_checks
from mnemowall.keys import EphemeralKeyProvider, FileKeyProvider
from mnemowall.ledger import Ledger, ReadItem, Signature
from mnemowall.ledger.export import verify_export
from mnemowall.policy import apply_local_overrides, load_policy
from mnemowall.quarantine import Quarantine

CANARY = "CANARY-7f3a91"
posix_only = pytest.mark.skipif(os.name != "posix", reason="file key provider is POSIX-only")


@pytest.fixture(autouse=True)
def _reset() -> None:
    diagnostics.reset()


def fill(led: Ledger) -> None:
    for i in range(3):
        led.append_version(
            namespace=("users", CANARY),
            key=f"k{i % 2}",
            content=f"{CANARY} content {i}",
            scope="user",
            trust_level="user",
            effective_type="fact",
            memory_type="fact",
            bundle_id="builtin-default",
            provenance={"source_ref": CANARY},
        )
    led.record_read(
        session_id="sess-1", items=[ReadItem("mem-x", 1, True, False, "plain")], query=CANARY
    )
    led.append_event("review", {"item_id": "q-1", "action": "reject"})


@pytest.fixture
def setup(tmp_path: Path) -> dict[str, Any]:
    keys = tmp_path / "keys" / "keys.json"
    provider = FileKeyProvider(keys)
    provider.init()
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    led = Ledger.open(data / "ledger.db", provider, tenant_id="default")
    fill(led)
    led.close()
    args = ["--data-dir", str(data), "--provider", "file", "--path", str(keys)]
    return {"keys": keys, "data": data, "provider": provider, "args": args, "tmp": tmp_path}


# --- UT-EXPORT -----------------------------------------------------------------------------


@posix_only
def test_ut_export_001_jsonl_has_entries_head_and_keys_but_no_content(
    setup: dict[str, Any],
) -> None:
    out = setup["tmp"] / "evidence.jsonl"
    assert cli.main(["export", "--jsonl", "--out", str(out), *setup["args"]]) == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    text = out.read_text()
    assert CANARY not in text
    lines = [json.loads(line) for line in text.splitlines()]
    assert [line["type"] for line in lines[:1]] == ["meta"]
    entries = [line for line in lines if line["type"] == "entry"]
    assert [e["seq"] for e in entries] == [1, 2, 3, 4, 5]
    assert {e["kind"] for e in entries} == {"version", "read", "review"}
    (head,) = [line for line in lines if line["type"] == "head"]
    assert head["seq"] == 5
    assert head["hash"] == entries[-1]["hash"]
    (keys,) = [line for line in lines if line["type"] == "public_keys"]
    assert len(keys["keys"]) == 1


@posix_only
def test_ut_export_002_refuses_to_overwrite(
    setup: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    out = setup["tmp"] / "evidence.jsonl"
    out.write_text("keep me")
    assert cli.main(["export", "--jsonl", "--out", str(out), *setup["args"]]) == 1
    assert out.read_text() == "keep me"
    assert "exists" in capsys.readouterr().err


# --- UT-VERIFY-LEDGER ----------------------------------------------------------------------


@posix_only
def test_ut_verify_ledger_001_cli_clean_and_tampered(
    setup: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["verify-ledger", *setup["args"]]) == 0
    assert "ok: 5 entries" in capsys.readouterr().out
    con = sqlite3.connect(setup["data"] / "ledger.db")
    con.execute("UPDATE entries SET ts_ms = ts_ms + 1 WHERE seq = 3")
    con.commit()
    con.close()
    assert cli.main(["verify-ledger", *setup["args"]]) == 1
    out = capsys.readouterr().out
    assert "FAILED at entry 3" in out
    assert "hash_mismatch" in out


@posix_only
def test_ut_verify_ledger_002_offline_export(setup: dict[str, Any]) -> None:
    out = setup["tmp"] / "evidence.jsonl"
    assert cli.main(["export", "--jsonl", "--out", str(out), *setup["args"]]) == 0
    lines = out.read_text().splitlines()
    keys = setup["provider"].load().public_keys
    assert verify_export(lines, keys).ok
    for k in range(1, 6):
        tampered = list(lines)
        idx = next(
            i
            for i, raw in enumerate(tampered)
            if json.loads(raw).get("seq") == k and json.loads(raw)["type"] == "entry"
        )
        doc = json.loads(tampered[idx])
        doc["ts_ms"] += 1
        tampered[idx] = json.dumps(doc)
        report = verify_export(tampered, keys)
        assert (report.ok, report.failed_at) == (False, k)
    dropped = [
        raw
        for raw in lines
        if not (json.loads(raw)["type"] == "entry" and json.loads(raw)["seq"] == 2)
    ]
    report = verify_export(dropped, keys)
    assert (report.failed_at, report.reason) == (2, "missing_entry")
    # A valid key id with a corrupted head signature.
    head_idx = next(i for i, raw in enumerate(lines) if json.loads(raw)["type"] == "head")
    head = json.loads(lines[head_idx])
    sig = Signature.decode(head["signature"])
    flipped = bytes([sig.value[0] ^ 1]) + sig.value[1:]
    head["signature"] = Signature(sig.key_id, flipped).encode()  # well-formed, wrong
    bad_sig = list(lines)
    bad_sig[head_idx] = json.dumps(head)
    report = verify_export(bad_sig, keys)
    assert (report.ok, report.reason) == (False, "bad_head_signature")
    # An exported head kept elsewhere catches a truncated export.
    head = json.loads(lines[head_idx])
    assert verify_export(lines, keys, expected_head=(head["seq"], head["hash"])).ok
    report = verify_export(lines, keys, expected_head=(9, head["hash"]))
    assert (report.ok, report.failed_at, report.reason) == (False, 9, "expected_head_missing")
    other = EphemeralKeyProvider()
    other.init()
    report = verify_export(lines, other.load().public_keys)
    assert (report.ok, report.reason) == (False, "bad_head_signature")


@posix_only
def test_ut_verify_ledger_003_expected_head_and_offline_cli(
    setup: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    out = setup["tmp"] / "evidence.jsonl"
    cli.main(["export", "--jsonl", "--out", str(out), *setup["args"]])
    head = next(
        json.loads(line)
        for line in out.read_text().splitlines()
        if json.loads(line)["type"] == "head"
    )
    capsys.readouterr()
    assert (
        cli.main(
            ["verify-ledger", "--expected-head", f"{head['seq']}:{head['hash']}", *setup["args"]]
        )
        == 0
    )
    assert cli.main(["verify-ledger", "--expected-head", f"9:{head['hash']}", *setup["args"]]) == 1
    assert "expected_head_missing" in capsys.readouterr().out
    assert cli.main(["verify-ledger", "--export", str(out), *setup["args"]]) == 0
    assert "ok: 5 entries" in capsys.readouterr().out


# --- UT-DOCTOR -----------------------------------------------------------------------------


def codes(findings: list[Finding]) -> dict[str, str]:
    return {f.code: f.severity for f in findings}


def test_ut_doctor_001_flags_risky_setups(tmp_path: Path) -> None:
    provider = EphemeralKeyProvider()
    provider.init()
    led = Ledger.open(tmp_path / "ledger.db", provider, tenant_id="t")
    q = Quarantine.open(tmp_path / "q", provider, ledger=led, policy=load_policy(), tenant_id="t")
    shadow = apply_local_overrides(load_policy(), {"mode": "shadow"})
    stores = [
        InMemoryStore(),
        GuardedStore(InMemoryStore(), ledger=led, quarantine=q, tenant_id="t"),
    ]
    diagnostics.record("write_without_session", 3)
    diagnostics.record("read_unverified", 2)
    found = codes(
        run_checks(provider=provider, ledger=led, quarantine=q, policy=shadow, stores=stores)
    )
    assert found["ephemeral_keys"] == "warning"
    assert found["shadow_mode"] == "warning"
    assert found["unwrapped_store"] == "warning"
    assert found["writes_without_session"] == "warning"
    assert found["read_unverified"] == "warning"
    assert found["in_process_signing"] == "info"
    assert found["ledger_ok"] == "info"


def test_ut_doctor_002_errors(tmp_path: Path) -> None:
    provider = EphemeralKeyProvider()
    provider.init()
    led = Ledger.open(tmp_path / "ledger.db", provider, tenant_id="t")
    fill(led)
    con = sqlite3.connect(tmp_path / "ledger.db")
    con.execute("UPDATE entries SET ts_ms = ts_ms + 1 WHERE seq = 2")
    con.commit()
    con.close()

    class Odd(InMemoryStore):
        def batch(self, ops: Any, extra: Any = None) -> Any:
            return super().batch(ops)

    q = Quarantine.open(tmp_path / "q", provider, ledger=led, policy=load_policy(), tenant_id="t")
    probe_failed = GuardedStore(Odd(), ledger=led, quarantine=q, tenant_id="t")
    findings = run_checks(
        provider=provider, ledger=led, quarantine=q, policy=load_policy(), stores=[probe_failed]
    )
    found = codes(findings)
    assert found["ledger_tampered"] == "error"
    assert found["adapter_probe_failure"] == "error"
    tampered = next(f for f in findings if f.code == "ledger_tampered")
    assert "entry 2" in tampered.message


def test_ut_doctor_003_clean_setup_has_no_warnings(tmp_path: Path) -> None:
    provider = FileKeyProvider(tmp_path / "keys" / "keys.json")
    provider.init()
    led = Ledger.open(tmp_path / "ledger.db", provider, tenant_id="t")
    q = Quarantine.open(tmp_path / "q", provider, ledger=led, policy=load_policy(), tenant_id="t")
    store = GuardedStore(InMemoryStore(), ledger=led, quarantine=q, tenant_id="t")
    findings = run_checks(
        provider=provider, ledger=led, quarantine=q, policy=load_policy(), stores=[store]
    )
    assert [f for f in findings if f.severity != "info"] == []
    assert CANARY not in repr(findings)


@posix_only
def test_ut_doctor_004_cli(setup: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["doctor", *setup["args"]])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ledger_ok" in out
    assert "in_process_signing" in out
    assert "in-process counters" in out
    con = sqlite3.connect(setup["data"] / "ledger.db")
    con.execute("DELETE FROM entries WHERE seq = 2")
    con.commit()
    con.close()
    assert cli.main(["doctor", *setup["args"]]) == 2
    assert "ledger_tampered" in capsys.readouterr().out


def found_codes(store: Any, *, level: int) -> set[str]:
    mem0_log = logging.getLogger("mem0")
    before = mem0_log.level
    mem0_log.setLevel(level)
    try:
        return {f.code for f in run_checks(stores=[store] if store else [], counters={})}
    finally:
        mem0_log.setLevel(before)


def test_ut_doctor_005_mem0_wrappers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """M1b-02: doctor covers Mem0 wrappers: probe failure, telemetry on, backend errors."""
    import mem0.memory.telemetry as telemetry
    from mem0_fakes import make_memory

    from mnemowall.adapters.mem0 import GuardedMemory

    provider = EphemeralKeyProvider()
    provider.init()
    led = Ledger.open(tmp_path / "l.db", provider, tenant_id="t")
    q = Quarantine.open(tmp_path / "q", provider, ledger=led, policy=load_policy(), tenant_id="t")
    good = GuardedMemory(make_memory(tmp_path / "m"), ledger=led, quarantine=q, tenant_id="t")
    bad = GuardedMemory(object(), ledger=led, quarantine=q, tenant_id="t")
    found = {f.code: f.severity for f in run_checks(stores=[good], counters={})}
    assert "adapter_probe_failure" not in found
    assert "unwrapped_store" not in found
    found = {f.code: f.severity for f in run_checks(stores=[bad], counters={})}
    assert found["adapter_probe_failure"] == "error"
    assert found_codes(good, level=logging.WARNING) >= {"mem0_logs_content"}
    assert "mem0_logs_content" not in found_codes(good, level=logging.CRITICAL)
    assert "mem0_logs_content" not in found_codes(None, level=logging.WARNING)
    monkeypatch.setattr(telemetry, "MEM0_TELEMETRY", True)
    found = {f.code: f.severity for f in run_checks(stores=[good], counters={})}
    assert found["mem0_telemetry_enabled"] == "warning"
    counted = {f.code for f in run_checks(counters={"backend_error": 2, "principal_mismatch": 1})}
    assert {"backend_error", "principal_mismatch"} <= counted
    infer = {
        f.code: f.severity for f in run_checks(counters={"infer_removed": 1, "infer_restored": 1})
    }
    assert infer == {"infer_removed": "warning", "infer_restored": "warning"} | {
        k: v for k, v in infer.items() if k not in ("infer_removed", "infer_restored")
    }
    assert {"infer_removed", "infer_restored"} <= set(infer)
    q.close()
    led.close()
