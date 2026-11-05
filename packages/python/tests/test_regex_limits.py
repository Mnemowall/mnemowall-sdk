"""M1a-06: linear-time regex (RE2) and write size caps. UT-REDOS-*, UT-SIZECAP-*."""

from __future__ import annotations

import time

import pytest

from mnemowall.core import limits, regex

# Classic catastrophic-backtracking shapes. Under Python's `re` these take exponential time.
PATHOLOGICAL = [
    (r"(a+)+$", "a" * 32_000 + "!"),
    (r"(a|aa)+$", "a" * 32_000 + "!"),
    (r"(.*a){20}", "a" * 32_000),
    (r"^(\w+\s?)*$", "word " * 6_000 + "!"),
]


@pytest.mark.parametrize(("pattern", "text"), PATHOLOGICAL)
def test_ut_redos_001_pathological_inputs_stay_linear(pattern: str, text: str) -> None:
    rx = regex.compile(pattern)
    start = time.process_time()
    rx.search(text)
    assert time.process_time() - start < 0.05  # §5.2: < 50 ms CPU per write


@pytest.mark.parametrize("pattern", [r"(a)\1", r"(?=x)y", r"(?<=x)y", r"(?!x)y"])
def test_ut_redos_002_backtracking_only_features_are_rejected(pattern: str) -> None:
    """No silent fallback to a backtracking engine."""
    with pytest.raises(regex.RegexError):
        regex.compile(pattern)


def test_ut_redos_003_engine_is_re2() -> None:
    assert regex.ENGINE == "re2"
    assert regex.compile(r"(?i)\bfrom now on\b").search("FROM NOW ON, do x") is not None


def test_ut_sizecap_001_boundary_in_utf8_bytes() -> None:
    assert limits.MAX_WRITE_BYTES == 32 * 1024
    assert not limits.oversized("a" * limits.MAX_WRITE_BYTES)
    assert limits.oversized("a" * (limits.MAX_WRITE_BYTES + 1))
    # multi-byte characters count by encoded size, not by code points
    euro = "€"  # 3 bytes in UTF-8
    n = limits.MAX_WRITE_BYTES // 3
    assert not limits.oversized(euro * n)
    assert limits.oversized(euro * (n + 1))


def test_ut_sizecap_002_oversize_is_a_risk_signal_without_content() -> None:
    sig = limits.size_signal("x" * (limits.MAX_WRITE_BYTES + 10))
    assert sig.fired
    assert sig.id == "S0.oversize"
    assert "x" * 20 not in repr(sig)
    assert not limits.size_signal("small").fired
