"""CAN-LOG-*: memory content must never reach log output (§1.6, §3.14).

The capture handler serializes the *entire* LogRecord (every attribute), the way a structured
logging pipeline would, so anything left on the record counts as leaked.
"""

from __future__ import annotations

import io
import json
import logging
import pathlib
from collections.abc import Iterator

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from mnemowall import _log

CANARY = "CANARY-memory content: wire $9,400 to IBAN GB33BUKB20201555555555"


class _DumpEverything(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()
        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.stack_info:
            record.stack_info = self.formatStack(record.stack_info)
        return json.dumps({k: repr(v) for k, v in vars(record).items()})


@pytest.fixture
def captured() -> Iterator[io.StringIO]:
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(_DumpEverything())
    root = logging.getLogger(_log.LOGGER_NAME)
    root.addHandler(handler)
    old_level = root.level
    root.setLevel(logging.DEBUG)
    try:
        yield buf
    finally:
        root.removeHandler(handler)
        root.setLevel(old_level)


def _boom(payload: str) -> None:
    raise ValueError("bad memory: " + payload)


def test_can_log_001_message_and_args(captured: io.StringIO) -> None:
    log = _log.get_logger("policy")
    log.info(CANARY)
    log.info("write_quarantined %s", CANARY)
    log.warning("write_quarantined", extra={"outcome": CANARY})
    out = captured.getvalue()
    assert out, "nothing was logged"
    assert "CANARY" not in out


def test_can_log_002_non_allowlisted_extra_dropped(captured: io.StringIO) -> None:
    _log.get_logger("ledger").info(
        "version_committed", extra={"content": CANARY, "memory_text": CANARY}
    )
    out = captured.getvalue()
    assert "CANARY" not in out
    assert "dropped_fields" in out


def test_can_log_003_exceptions(captured: io.StringIO) -> None:
    log = _log.get_logger("adapters")
    try:
        _boom(CANARY)
    except ValueError:
        log.exception("adapter_write_failed")
        log.error("adapter_write_failed", exc_info=True, stack_info=True)
    out = captured.getvalue()
    assert "CANARY" not in out
    assert "ValueError" in out  # the type survives so failures stay diagnosable


def test_can_log_004_collections_and_nested(captured: io.StringIO) -> None:
    _log.get_logger("signals").info(
        "signals_fired",
        extra={"signal_ids": ["S3.iban", CANARY], "rule_ids": ("r1", {"x": CANARY})},
    )
    assert "CANARY" not in captured.getvalue()


def test_can_log_005_safe_fields_survive(captured: io.StringIO) -> None:
    _log.get_logger("policy").info(
        "write_decision",
        extra={
            "decision": "quarantine",
            "rule_ids": ["I1", "no-external-payment-sinks"],
            "latency_us": 812,
        },
    )
    out = captured.getvalue()
    for expected in ("write_decision", "quarantine", "no-external-payment-sinks", "812"):
        assert expected in out


@settings(max_examples=200, deadline=None)
@given(text=st.text(min_size=1, max_size=200))
def test_can_log_006_property_arbitrary_text_never_logged(text: str) -> None:
    payload = "CANARY ⟨" + text  # contains a space, so it is never identifier-shaped
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(_DumpEverything())
    log = _log.get_logger("property")
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)
    try:
        log.info(payload)
        log.info("event %s %r", payload, payload)
        log.info("event", extra={"outcome": payload, "content": payload, "signal_ids": [payload]})
        try:
            _boom(payload)
        except ValueError:
            log.exception("event")
    finally:
        log.removeHandler(handler)
    assert payload not in buf.getvalue()
    assert "CANARY ⟨" not in buf.getvalue()


def test_get_logger_rejects_bad_component() -> None:
    with pytest.raises(ValueError, match="component"):
        _log.get_logger("bad name")


def test_no_direct_getlogger_in_sdk_source() -> None:
    """Logger filters skip child loggers, so every SDK logger must come from _log."""
    src = pathlib.Path(_log.__file__).resolve().parent
    offenders = [
        str(p.relative_to(src))
        for p in src.rglob("*.py")
        if p.name != "_log.py" and "getLogger(" in p.read_text(encoding="utf-8")
    ]
    assert offenders == []
