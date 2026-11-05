"""M1a-04: signals S1 (provenance taint), S5 (scope violation), S7 (protected mutation)."""

from __future__ import annotations

import time

import pytest

from mnemowall.core.model import MemoryType
from mnemowall.core.trust import TrustLevel
from mnemowall.signals.base import SignalResult
from mnemowall.signals.write import (
    Op,
    Scope,
    ScopeKind,
    WriteFacts,
    s1_taint,
    s5_scope,
    s7_protected_mutation,
)

T = TrustLevel
ME = Scope(ScopeKind.USER, "p1")


def facts(**over: object) -> WriteFacts:
    base: dict[str, object] = {
        "content": "x",
        "write_trust": T.USER,
        "op": Op.CREATE,
        "target_scope": ME,
        "principal_scope": ME,
        "grants": frozenset(),
        "target_protected": False,
        "target_type": None,
    }
    base.update(over)
    return WriteFacts(**base)  # type: ignore[arg-type]


# S1 ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("trust", list(T))
def test_ut_sig_s1_fires_exactly_when_tainted(trust: TrustLevel) -> None:
    r = s1_taint(facts(write_trust=trust))
    assert r.id == "S1"
    assert r.fired is (trust < T.USER)
    assert r.risk == (1.0 if r.fired else 0.0)
    assert trust.label in r.labels


# S5 ---------------------------------------------------------------------------------------
def test_ut_sig_s5_own_scope_never_fires() -> None:
    assert not s5_scope(facts(write_trust=T.UNKNOWN)).fired


@pytest.mark.parametrize(
    ("target", "grant"),
    [
        (Scope(ScopeKind.SHARED, None), "memory:write:shared"),
        (Scope(ScopeKind.ORG, None), "memory:write:org"),
        (Scope(ScopeKind.USER, "someone-else"), "memory:write:other_user"),
    ],
)
def test_ut_sig_s5_cross_scope_needs_verified_user_and_grant(target: Scope, grant: str) -> None:
    assert s5_scope(facts(target_scope=target)).fired  # user trust, no grant
    assert s5_scope(
        facts(target_scope=target, grants=frozenset({grant}))
    ).fired  # grant, but only `user`
    assert s5_scope(
        facts(target_scope=target, write_trust=T.VERIFIED_USER)
    ).fired  # verified, no grant
    ok = facts(target_scope=target, write_trust=T.VERIFIED_USER, grants=frozenset({grant}))
    assert not s5_scope(ok).fired
    wrong_grant = facts(
        target_scope=target, write_trust=T.OPERATOR, grants=frozenset({"memory:write:nothing"})
    )
    assert s5_scope(wrong_grant).fired


def test_ut_sig_s5_labels_are_safe() -> None:
    r = s5_scope(facts(target_scope=Scope(ScopeKind.USER, "victim@example.com")))
    assert r.fired
    assert "victim" not in repr(r)  # owner ids never leak into signal output
    assert "cross_scope" in r.labels


# S7 ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("op", [Op.UPDATE, Op.DELETE])
def test_ut_sig_s7_mutating_protected_or_instruction_fires(op: Op) -> None:
    assert s7_protected_mutation(facts(op=op, target_protected=True)).fired
    assert s7_protected_mutation(facts(op=op, target_type=MemoryType.STANDING_INSTRUCTION)).fired
    assert not s7_protected_mutation(facts(op=op, target_type=MemoryType.FACT)).fired


def test_ut_sig_s7_create_never_fires() -> None:
    assert not s7_protected_mutation(facts(op=Op.CREATE, target_protected=True)).fired


def test_write_facts_never_show_content() -> None:
    f = facts(content="CANARY secret memory body")
    assert "CANARY" not in repr(f)
    assert "CANARY" not in str(f)


def test_write_facts_never_show_scope_owner_ids() -> None:
    f = facts(
        target_scope=Scope(ScopeKind.USER, "victim@example.com"),
        principal_scope=Scope(ScopeKind.USER, "me@x.io"),
    )
    text = repr(f) + str(f) + repr(f.target_scope)
    assert "victim" not in text
    assert "me@x.io" not in text


def test_signals_return_signal_results() -> None:
    for fn in (s1_taint, s5_scope, s7_protected_mutation):
        assert isinstance(fn(facts()), SignalResult)


def test_latency_budget_s1_s5_s7() -> None:
    """§3.8: provenance + S1, S5, S7 <= 0.5 ms p99 (measured here with a wide safety margin)."""
    f = facts(
        write_trust=T.EMAIL,
        target_scope=Scope(ScopeKind.SHARED, None),
        op=Op.UPDATE,
        target_protected=True,
    )
    samples = []
    for _ in range(2000):
        t0 = time.perf_counter()
        s1_taint(f)
        s5_scope(f)
        s7_protected_mutation(f)
        samples.append(time.perf_counter() - t0)
    samples.sort()
    assert samples[int(len(samples) * 0.99)] < 0.0005
