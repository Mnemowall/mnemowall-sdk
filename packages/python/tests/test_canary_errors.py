"""M1a-22: error-path canaries. CAN-POLICY, CAN-LEDGER, CAN-ADAPTER (§1.6, §3.14).

Every error raised by policy, ledger, quarantine and adapter code (message, args, repr, and the
whole ``__cause__``/``__context__`` chain) and every log line must be free of the content,
identifiers and keys that caused it.
"""

from __future__ import annotations

import functools
import logging
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from langgraph.store.memory import InMemoryStore

from mnemowall.adapters.langgraph import GuardedStore
from mnemowall.core.provenance import Guard
from mnemowall.keys import EphemeralKeyProvider
from mnemowall.ledger import Ledger, ReadItem, VersionFields
from mnemowall.policy import (
    WriteRequest,
    apply_local_overrides,
    builtin_policy_document,
    compile_policy,
    load_engine,
    load_policy,
)
from mnemowall.quarantine import Quarantine

CANARY = "CANARY7f3a91"
PROVIDER = EphemeralKeyProvider()
PROVIDER.init()


def texts(exc: BaseException) -> Iterator[str]:
    seen: set[int] = set()
    stack: list[BaseException | None] = [exc]
    while stack:
        e = stack.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        yield str(e)
        yield repr(e)
        yield repr(e.args)
        yield repr(getattr(e, "__notes__", ""))
        yield (
            repr({k: v for k, v in vars(e).items() if not k.startswith("__")})
            if hasattr(e, "__dict__")
            else ""
        )
        stack += [e.__cause__, e.__context__]


def assert_clean(call: Callable[[], Any], caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger="mnemowall"), pytest.raises(Exception) as info:  # noqa: PT011 - every type is checked
        call()
    for text in texts(info.value):
        assert CANARY not in text, f"{type(info.value).__name__} leaks content: {text[:200]}"
    assert CANARY not in caplog.text


# --- the check itself works ----------------------------------------------------------------


def test_seeded_leak_is_caught(caplog: pytest.LogCaptureFixture) -> None:
    def leaky() -> None:
        try:
            raise KeyError(CANARY)
        except KeyError as inner:
            raise ValueError("wrapped") from inner

    with pytest.raises(AssertionError):
        assert_clean(leaky, caplog)


# --- CAN-POLICY ----------------------------------------------------------------------------


def _bad_policy(kind: str) -> Any:
    doc = builtin_policy_document()
    if kind == "unknown_key":
        doc[CANARY] = 1
    elif kind == "bad_value":
        doc["defaults"]["mode"] = CANARY
    elif kind == "bad_rule":
        doc["rules"].append({"id": CANARY, "when": {"signals_any": [CANARY]}, "then": CANARY})
    elif kind == "nested":
        doc["read"]["wrap"]["below_trust"] = {CANARY: [CANARY]}
    return doc


@pytest.mark.parametrize("kind", ["unknown_key", "bad_value", "bad_rule", "nested"])
def test_can_policy_compile_errors(kind: str, caplog: pytest.LogCaptureFixture) -> None:
    assert_clean(lambda: compile_policy(_bad_policy(kind)), caplog)


@pytest.mark.parametrize(
    "overrides",
    [
        {CANARY: 1},
        {"failure_modes": {CANARY: "x"}},
        {"failure_modes": {"tainted_write": CANARY}},
        {"mode": CANARY},
    ],
)
def test_can_policy_override_errors(overrides: Any, caplog: pytest.LogCaptureFixture) -> None:
    assert_clean(lambda: apply_local_overrides(load_policy(), overrides), caplog)


def test_can_policy_engine_errors(caplog: pytest.LogCaptureFixture) -> None:
    cyclic: dict[str, Any] = {"text": CANARY}
    cyclic["self"] = cyclic
    engine = load_engine()

    def go() -> None:
        result = engine.evaluate(WriteRequest(value=cyclic))
        raise RuntimeError(result.decision.outcome.value)  # surface the decision for the check

    assert_clean(go, caplog)


# --- CAN-LEDGER ----------------------------------------------------------------------------


def _ledger(tmp: Path) -> Ledger:
    return Ledger.open(tmp / "ledger.db", PROVIDER, tenant_id="tenant-a")


def _put(led: Ledger, **over: Any) -> Any:
    args: dict[str, Any] = {
        "namespace": ("users", CANARY),
        "key": CANARY,
        "content": CANARY,
        "scope": "user",
        "trust_level": "user",
        "effective_type": "fact",
        "memory_type": "fact",
        "bundle_id": "builtin-default",
        "provenance": {"source_ref": CANARY},
    }
    args.update(over)
    return led.append_version(**args)


@pytest.mark.parametrize(
    "over",
    [
        {"namespace": ("users", CANARY + "\ud800")},
        {"key": CANARY + "\udfff"},
        {"content": CANARY + "\ud800"},
        {"provenance": {CANARY: 1.5}},
        {"provenance": {"x": {CANARY}}},
        {"trust_level": CANARY},
        {"scope": CANARY + "\ud800"},
        {"bundle_id": ""},
        {"status": CANARY},
        {"effective_type": CANARY},
    ],
)
def test_can_ledger_append_errors(
    over: dict[str, Any], tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    led = _ledger(tmp_path)
    assert_clean(lambda: _put(led, **over), caplog)


def test_can_ledger_other_errors(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    led = _ledger(tmp_path)
    assert_clean(lambda: led.record_read(session_id=f"{CANARY} x", items=[], query=None), caplog)
    assert_clean(
        lambda: led.record_read(
            session_id="s", items=[ReadItem(CANARY + " x", 1, True, False, "plain")], query=None
        ),
        caplog,
    )
    assert_clean(lambda: led.record_read(session_id="s", items=[], query=CANARY + "\ud800"), caplog)
    assert_clean(lambda: led.append_event("review", {"note": f"{CANARY} free text"}), caplog)
    assert_clean(lambda: led.append_event(CANARY, {}), caplog)
    assert_clean(lambda: led.purge(CANARY, 1), caplog)
    assert_clean(lambda: led.purge("mem-1", 1, reason=CANARY), caplog)
    assert_clean(lambda: Ledger.open(tmp_path / "x.db", PROVIDER, tenant_id=f"{CANARY} x"), caplog)
    assert_clean(lambda: Ledger.open(tmp_path / "ledger.db", PROVIDER, tenant_id=CANARY), caplog)
    assert_clean(lambda: VersionFields.from_mapping({CANARY: 1}), caplog)


# --- CAN-QUARANTINE ------------------------------------------------------------------------


def test_can_quarantine_errors(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    led = _ledger(tmp_path)
    q = Quarantine.open(
        tmp_path / "q", PROVIDER, ledger=led, policy=load_policy(), tenant_id="tenant-a"
    )
    for action in (
        q.approve,
        q.reject,
        q.promote,
        q.show,
        q.cancel_promotion,
        q.complete_promotion,
    ):
        assert_clean(functools.partial(action, f"q-{CANARY}"), caplog)
    decision = load_engine().evaluate(WriteRequest(value="I like tea.")).decision

    def submit(**over: Any) -> Any:
        args: dict[str, Any] = {
            "decision": decision,
            "namespace": ("u", CANARY),
            "key": CANARY,
            "content": CANARY,
            "scope": "user",
            "bundle_id": "b",
            "provenance": {CANARY: 1.5},
        }
        args.update(over)
        return q.submit(**args)

    assert_clean(submit, caplog)  # not_quarantined
    assert_clean(
        lambda: Quarantine.open(
            tmp_path / "q", PROVIDER, ledger=led, policy=load_policy(), tenant_id=CANARY
        ),
        caplog,
    )


# --- CAN-ADAPTER ---------------------------------------------------------------------------


@contextmanager
def _session(**kw: Any) -> Iterator[None]:
    g = Guard()
    with g.session(
        tenant=kw.get("tenant", "tenant-a"),
        principal=kw.get("principal", "alice"),
        agent="a",
        session_id="s",
    ) as s:
        s.system_prompt()
        s.user_turn()
        yield


def test_can_adapter_errors(caplog: pytest.LogCaptureFixture) -> None:
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        led = _ledger(tmp)
        q = Quarantine.open(
            tmp / "q", PROVIDER, ledger=led, policy=load_policy(), tenant_id="tenant-a"
        )
        store = GuardedStore(InMemoryStore(), ledger=led, quarantine=q, tenant_id="tenant-a")
        shared = GuardedStore(
            InMemoryStore(), ledger=led, quarantine=q, tenant_id="tenant-a", scope="shared"
        )
        with _session():
            for ns in (
                (f"{CANARY}.x",),
                (f"{CANARY}_x",),
                (f"{CANARY}%",),
                ("ok", ""),
                (CANARY, ""),
            ):
                assert_clean(functools.partial(store.put, ns, "k", {"text": CANARY}), caplog)
                assert_clean(functools.partial(store.get, ns, "k"), caplog)
                assert_clean(functools.partial(store.search, ns), caplog)
                assert_clean(functools.partial(store.delete, ns, "k"), caplog)
                assert_clean(functools.partial(store.list_namespaces, prefix=ns), caplog)
            assert_clean(lambda: store.put(("ok",), "", {"text": CANARY}), caplog)
            assert_clean(lambda: store.put(("ok",), "k", {"text": CANARY, "bad": {CANARY}}), caplog)
            assert_clean(
                lambda: store.put(("ok",), "k", {"text": CANARY, "n": float("nan")}), caplog
            )
            assert_clean(lambda: shared.put(("ok",), "k", {"text": CANARY}), caplog)
            assert_clean(lambda: store.rollback(CANARY, 1), caplog)
        with _session(tenant="other"):
            assert_clean(lambda: store.put(("ok",), "k", {"text": CANARY}), caplog)


# --- CAN-ADAPTER: Mem0 (M1b-02) ------------------------------------------------------------


def test_can_adapter_mem0_errors(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    from mem0_fakes import make_memory

    from mnemowall.adapters.mem0 import GuardedMemory

    led = _ledger(tmp_path)
    q = Quarantine.open(
        tmp_path / "q", PROVIDER, ledger=led, policy=load_policy(), tenant_id="tenant-a"
    )
    inner = make_memory(tmp_path / "m")
    mem = GuardedMemory(inner, ledger=led, quarantine=q, tenant_id="tenant-a")
    with _session():
        assert_clean(lambda: mem.add(CANARY, metadata={"x": {CANARY}}), caplog)
        assert_clean(lambda: mem.add(CANARY, metadata={"x": float("nan"), CANARY: 1}), caplog)
        assert_clean(lambda: mem.add(CANARY, metadata={1: CANARY}), caplog)  # type: ignore[dict-item]
        assert_clean(lambda: mem.add([{"role": "user", "content": 7, "x": CANARY}]), caplog)
        assert_clean(lambda: mem.add(CANARY, user_id=CANARY), caplog)
        assert_clean(lambda: mem.add(CANARY, agent_id=f"{CANARY} x"), caplog)
        assert_clean(lambda: mem.add(CANARY, infer=True), caplog)
        assert_clean(lambda: mem.get_all(filters={"OR": [{CANARY: CANARY}]}), caplog)
        assert_clean(lambda: mem.search(CANARY, filters={CANARY: {"ne": CANARY}}), caplog)
        assert_clean(lambda: mem.update(CANARY, text=CANARY), caplog)
        assert_clean(lambda: mem.delete(CANARY), caplog)
        assert_clean(lambda: mem.rollback(CANARY, 1), caplog)

        def boom(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError(f"backend failed on {CANARY}")

        inner.add = boom
        assert_clean(lambda: mem.add(CANARY), caplog)
    with _session(tenant="other"):
        assert_clean(lambda: mem.add(CANARY), caplog)
    q.close()
    led.close()
