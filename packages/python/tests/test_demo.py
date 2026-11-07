"""M1a-25: the 8-step scripted demo (§9.2). IT-DEMO: no network, no keys, every step holds."""

from __future__ import annotations

import socket
from typing import Any

import pytest

from mnemowall.demo import run_demo


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_a: Any, **_k: Any) -> None:
        raise AssertionError("the demo must not use the network")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def test_it_demo_every_step_holds(no_network: None, capsys: pytest.CaptureFixture[str]) -> None:
    result = run_demo()
    out = capsys.readouterr().out
    assert result["ok"], result
    assert [s["step"] for s in result["steps"]] == list(range(1, 9))
    assert all(s["ok"] for s in result["steps"]), result["steps"]
    for marker in (
        "1. ",
        "quarantined",
        "2. ",
        "UNPROTECTED",
        "3. ",
        'type="data"',
        "4. ",
        "unverified",
        "5. ",
        "incident",
        "6. ",
        "rollback",
        "7. ",
        "verify-ledger",
        "FAILED at entry",
        "8. ",
        "red-team",
    ):
        assert marker in out, marker


def test_it_demo_is_deterministic_in_outcome(no_network: None) -> None:
    first = run_demo(quiet=True)
    second = run_demo(quiet=True)
    assert [s["ok"] for s in first["steps"]] == [s["ok"] for s in second["steps"]]
