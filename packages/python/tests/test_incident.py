"""M1a-20: incident view. UT-INCIDENT-001..004."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from mnemowall import cli
from mnemowall.core.provenance import Guard
from mnemowall.incident import IncidentError, incident_report
from mnemowall.keys import EphemeralKeyProvider, FileKeyProvider
from mnemowall.ledger import Ledger, VersionRecord
from mnemowall.read import BackendItem, MemoryRef, read_memories

CANARY = "CANARY-7f3a91"
PROVIDER = EphemeralKeyProvider()
PROVIDER.init()


class Clock:
    def __init__(self) -> None:
        self.t = 1_800_000_000.0

    def __call__(self) -> float:
        return self.t


def put(led: Ledger, content: str, **kw: Any) -> VersionRecord:
    return led.append_version(
        namespace=("users", "u1"),
        key="k",
        content=content,
        scope="user",
        trust_level=kw.get("trust_level", "user"),
        effective_type="fact",
        memory_type="fact",
        bundle_id="builtin-default",
        provenance={},
    )


def read_as(led: Ledger, session_id: str, rec: VersionRecord, content: str) -> None:
    g = Guard()
    with g.session(tenant="t", principal="p", agent="a", session_id=session_id) as s:
        read_memories(
            led,
            [
                BackendItem(
                    content=content, ref=MemoryRef(rec.memory_id, rec.version_no, rec.signature)
                )
            ],
            session=s,
        )


def test_ut_incident_001_lists_every_session_that_read_a_version(tmp_path: Path) -> None:
    clock = Clock()
    led = Ledger.open(tmp_path / "ledger.db", PROVIDER, tenant_id="tenant-a", clock=clock)
    bad = put(led, f"poison {CANARY}", trust_level="web")
    for sid in ("sess-a", "sess-b"):
        clock.t += 60
        read_as(led, sid, bad, f"poison {CANARY}")
    good = put(led, "clean")
    clock.t += 60
    read_as(led, "sess-c", good, "clean")
    clock.t += 60
    read_as(led, "sess-d", bad, f"poison {CANARY}")  # a replay, read back stale
    report = incident_report(led, bad.memory_id, 1)
    assert [r.session_id for r in report.reads] == ["sess-a", "sess-b", "sess-d"]
    assert [r.label for r in report.reads] == ["low_trust", "low_trust", "stale"]
    assert report.reads[0].ts_ms < report.reads[1].ts_ms < report.reads[2].ts_ms
    assert report.sessions == ("sess-a", "sess-b", "sess-d")
    assert report.trust_level == "web"
    assert report.later_versions == (2,)
    assert report.head_version == 2
    assert report.purged_read_events == 0
    assert CANARY not in repr(report)


def test_ut_incident_002_unknown_version(tmp_path: Path) -> None:
    led = Ledger.open(tmp_path / "ledger.db", PROVIDER, tenant_id="tenant-a")
    rec = put(led, "x")
    with pytest.raises(IncidentError) as exc:
        incident_report(led, rec.memory_id, 5)
    assert exc.value.reason == "unknown_version"


def test_ut_incident_003_purged_read_details_are_counted(tmp_path: Path) -> None:
    clock = Clock()
    led = Ledger.open(
        tmp_path / "ledger.db", PROVIDER, tenant_id="tenant-a", clock=clock, retention_days=1
    )
    rec = put(led, "x")
    read_as(led, "sess-a", rec, "x")
    clock.t += 3 * 86_400
    led.apply_retention()
    report = incident_report(led, rec.memory_id, 1)
    assert report.reads == ()
    assert report.purged_read_events == 1


@pytest.mark.skipif(os.name != "posix", reason="file key provider is POSIX-only")
def test_ut_incident_004_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    keys = tmp_path / "keys" / "keys.json"
    provider = FileKeyProvider(keys)
    provider.init()
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    led = Ledger.open(data / "ledger.db", provider, tenant_id="default")
    rec = put(led, f"poison {CANARY}")
    read_as(led, "sess-a", rec, f"poison {CANARY}")
    led.close()
    common = ["--data-dir", str(data), "--provider", "file", "--path", str(keys)]
    assert cli.main(["incident", rec.memory_id, "1", *common]) == 0
    out = capsys.readouterr().out
    assert "sess-a" in out
    assert "1 session" in out
    assert CANARY not in out
    assert cli.main(["incident", rec.memory_id, "7", *common]) == 1
    assert "unknown_version" in capsys.readouterr().err
