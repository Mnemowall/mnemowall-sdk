"""M1a-01: core trust types (test spec docs/test-specs/M1a-01-02, signed off 2026-11-05)."""

from __future__ import annotations

import dataclasses
import itertools

import pytest
from hypothesis import given
from hypothesis import strategies as st

from mnemowall.core.model import EffectiveType, MemoryType, Outcome
from mnemowall.core.trust import (
    EXTERNAL_SOURCES_TRUST,
    Source,
    TrustLevel,
    default_trust,
    is_tainted,
    trust_min,
)

T = TrustLevel


def test_ut_trust_001_order() -> None:
    chain = [T.OPERATOR, T.VERIFIED_USER, T.USER, T.AGENT_DERIVED, T.TOOL_OUTPUT, T.UNKNOWN]
    for hi, lo in itertools.pairwise(chain):
        assert lo < hi
        assert hi > lo
        assert not hi < lo
    for ext in EXTERNAL_SOURCES_TRUST:
        assert T.AGENT_DERIVED > ext > T.UNKNOWN


def test_ut_trust_002_external_sources_equal_rank() -> None:
    ext = [T.TOOL_OUTPUT, T.DOCUMENT, T.EMAIL, T.WEB, T.OTHER_AGENT]
    assert set(ext) == set(EXTERNAL_SOURCES_TRUST)
    for a, b in itertools.product(ext, repeat=2):
        assert a <= b
        assert b <= a
        assert not a < b
        assert not a > b
    # min is stable among equal ranks: first one wins
    assert trust_min([T.EMAIL, T.WEB]) is T.EMAIL
    assert trust_min([T.WEB, T.EMAIL]) is T.WEB


def test_ut_trust_003_tainted_boundary() -> None:
    tainted = {T.AGENT_DERIVED, T.TOOL_OUTPUT, T.DOCUMENT, T.EMAIL, T.WEB, T.OTHER_AGENT, T.UNKNOWN}
    assert {t for t in T if is_tainted(t)} == tainted
    assert {t for t in T if not is_tainted(t)} == {T.USER, T.VERIFIED_USER, T.OPERATOR}


def test_ut_trust_004_default_source_map() -> None:
    assert default_trust(Source.USER_MSG) is T.USER
    for src, trust in [
        (Source.TOOL_OUTPUT, T.TOOL_OUTPUT),
        (Source.DOCUMENT, T.DOCUMENT),
        (Source.EMAIL, T.EMAIL),
        (Source.WEB, T.WEB),
        (Source.OTHER_AGENT, T.OTHER_AGENT),
    ]:
        assert default_trust(src) is trust
    assert default_trust(Source.SYSTEM) is T.OPERATOR  # D1
    assert default_trust(Source.OPERATOR) is T.OPERATOR
    assert default_trust(None) is T.UNKNOWN
    assert default_trust(Source.MEMORY_READ, stored=T.WEB) is T.WEB
    with pytest.raises(ValueError, match="stored"):
        default_trust(Source.MEMORY_READ)


def test_ut_trust_005_enums() -> None:
    assert {m.value for m in MemoryType} == {
        "fact",
        "preference",
        "standing_instruction",
        "procedure",
    }
    assert {e.value for e in EffectiveType} == {m.value for m in MemoryType} | {"data"}
    assert {o.value for o in Outcome} == {
        "allow",
        "allow_as_data",
        "quarantine",
        "deny",
        "shadow_would_allow",
        "shadow_would_allow_as_data",
        "shadow_would_quarantine",
        "shadow_would_deny",
    }


def test_ut_trust_006_immutable() -> None:
    with pytest.raises(AttributeError):
        T.USER.rank = 99
    for cls in (MemoryType, EffectiveType, Outcome, Source, TrustLevel):
        assert not dataclasses.is_dataclass(cls)  # enums: members are fixed singletons


def test_trust_min_rejects_empty() -> None:
    with pytest.raises(ValueError, match="empty"):
        trust_min([])


levels = st.sampled_from(list(T))


@given(st.lists(levels, min_size=1, max_size=12), st.lists(levels, min_size=1, max_size=12))
def test_pt_trust_min_lattice_laws(xs: list[TrustLevel], ys: list[TrustLevel]) -> None:
    m = trust_min(xs)
    assert all(m <= x for x in xs)  # lower bound
    assert trust_min([m, m]) is m  # idempotent
    assert trust_min(xs).rank == trust_min(list(reversed(xs))).rank  # commutative (by rank)
    both = trust_min([trust_min(xs), trust_min(ys)])
    assert both.rank == trust_min(xs + ys).rank  # associative
