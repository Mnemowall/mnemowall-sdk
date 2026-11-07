"""M1a-12: JCS (RFC 8785) canonical form for the signed subset. UT-JCS-001/002, PT-JCS-DIFF."""

from __future__ import annotations

import json
import math
from typing import Any

import pytest
import rfc8785
from hypothesis import given
from hypothesis import strategies as st

from mnemowall.core.jcs import MAX_DEPTH, MAX_SAFE_INT, JCSError, canonicalize

CANARY = "CANARY-7f3a91"


def test_ut_jcs_001_rfc8785_sorting_vector() -> None:
    # RFC 8785 §3.2.3: keys sort by UTF-16 code units, so the emoji (a surrogate pair starting
    # 0xD83D) sorts before U+FB33 even though its code point is larger.
    value = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }
    expected = (
        '{"\\r":"Carriage Return","1":"One","\u0080":"Control",'
        '"ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign",'
        '"\U0001f600":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}'
    )
    assert canonicalize(value) == expected.encode("utf-8")


def test_ut_jcs_001_rfc8785_string_and_literals_vector() -> None:
    # RFC 8785 §3.2.2.2 example, minus the numbers array (floats are outside the subset, D12).
    value = {"string": '€$\x0f\nA\'B"\\\\"/', "literals": [None, True, False]}
    expected = r"""{"literals":[null,true,false],"string":"€$\u000f\nA'B\"\\\\\"/"}"""
    assert canonicalize(value) == expected.encode("utf-8")


def test_ut_jcs_001_control_characters_and_literals() -> None:
    short = {"\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}
    for cp in range(0x20):
        ch = chr(cp)
        want = short.get(ch, f"\\u{cp:04x}")
        assert canonicalize(ch) == f'"{want}"'.encode()
    # DEL and the line/paragraph separators are not escaped (ECMAScript JSON.stringify).
    for ch in ("\x7f", "\u2028", "\u2029", "/"):
        assert canonicalize(ch) == f'"{ch}"'.encode()
    assert canonicalize(None) == b"null"
    assert canonicalize(True) == b"true"
    assert canonicalize(False) == b"false"
    assert canonicalize({}) == b"{}"
    assert canonicalize([]) == b"[]"
    assert canonicalize(()) == b"[]"
    assert canonicalize(("a", 1)) == b'["a",1]'
    assert canonicalize("") == b'""'


def test_ut_jcs_001_integers() -> None:
    for n in (0, 1, -1, 42, MAX_SAFE_INT, -MAX_SAFE_INT):
        assert canonicalize(n) == str(n).encode()
    assert MAX_SAFE_INT == 2**53 - 1
    assert canonicalize({"b": [1, True], "a": None}) == b'{"a":null,"b":[1,true]}'


def _nested(depth: int) -> Any:
    v: Any = 0
    for _ in range(depth):
        v = [v]
    return v


@pytest.mark.parametrize(
    "bad",
    [
        1.0,
        0.5,
        float("nan"),
        math.inf,
        -math.inf,
        2**53,
        -(2**53),
        10**30,
        {1: "a"},
        {("a",): "b"},
        b"bytes",
        bytearray(b"x"),
        object(),
        {1, 2},
        "\ud800",
        {"k": "\udfff"},
        {"\ud83d": 1},
    ],
    ids=lambda v: type(v).__name__,
)
def test_ut_jcs_002_unsupported_values_rejected(bad: object) -> None:
    with pytest.raises(JCSError):
        canonicalize(bad)


def test_ut_jcs_002_depth_limit() -> None:
    assert canonicalize(_nested(MAX_DEPTH)).startswith(b"[")
    with pytest.raises(JCSError):
        canonicalize(_nested(MAX_DEPTH + 1))


def test_ut_jcs_002_cycle_rejected() -> None:
    loop: list[Any] = []
    loop.append(loop)
    with pytest.raises(JCSError) as exc:
        canonicalize(loop)
    assert exc.value.kind == "cycle"
    shared: list[Any] = [1]
    assert canonicalize([shared, shared]) == b"[[1],[1]]"  # repeated, not cyclic


@pytest.mark.parametrize(
    "bad",
    [
        {CANARY: 1.5},
        {"outer": {CANARY: [1, 2, float("nan")]}},
        [CANARY, b"x"],
        {CANARY: "\ud800" + CANARY},
        {"a": CANARY, "b": 2**60},
    ],
)
def test_ut_jcs_002_errors_never_contain_values_or_keys(bad: object) -> None:
    with pytest.raises(JCSError) as exc:
        canonicalize(bad)
    text = str(exc.value) + repr(exc.value) + repr(exc.value.args)
    assert CANARY not in text
    assert exc.value.path.startswith("$")
    assert exc.value.kind


JSON_SUBSET = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-MAX_SAFE_INT, max_value=MAX_SAFE_INT)
    | st.text(),
    lambda children: (
        st.lists(children, max_size=5) | st.dictionaries(st.text(max_size=12), children, max_size=5)
    ),
    max_leaves=30,
)


@given(JSON_SUBSET)
def test_pt_jcs_diff_matches_reference_implementation(value: Any) -> None:
    out = canonicalize(value)
    assert out == rfc8785.dumps(value)
    assert json.loads(out.decode("utf-8")) == value
