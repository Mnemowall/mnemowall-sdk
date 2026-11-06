"""Forged-provenance stripping (I9, §3.3, D4).

Trust comes only from the provenance context. Anything in a memory value or in tool arguments
that *claims* trust is removed before storage and counted as a forgery attempt:

* ``_prov`` and any ``_mnemowall*`` key, at any nesting depth;
* ``trust``, ``trust_level``, ``source``, ``source_type``, ``provenance``, ``verified`` at the top
  level of a value or of tool arguments.

Keys are compared by skeleton: NFKC, invisible characters removed, casefolded, common Cyrillic and
Greek look-alikes mapped to Latin, and separators (``_``, ``-``, ``.``, spaces, dashes) ignored.
So ``Trust-Level``, ``_PROV`` spelled with a Cyrillic O, and ``_prov`` with a fullwidth underscore
are all reserved.

Mem0-style message ``role`` fields are left in place (they carry conversation structure) but are
never read as trust. Only ``dict``/``Mapping``, ``list`` and ``tuple`` are walked; other objects
pass through unchanged, so adapters convert framework objects to plain data first.
Logs carry counts only, never keys or values.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable, Mapping
from typing import Any, Final

from mnemowall import _log
from mnemowall.core import diagnostics
from mnemowall.signals.s4_obfuscation import normalize

_LOG: Final = _log.get_logger("forgery")
MAX_DEPTH: Final = 100

_CONFUSABLES: Final = str.maketrans(
    # look-alike -> Latin, by script: Cyrillic, Greek, Latin variants NFKC keeps
    "\u0430\u0432\u0441\u0501\u0435\u0451\u04bb\u0456\u0457\u0458\u043a\u04cf\u043c\u043f"
    "\u043e\u0440\u051b\u0433\u0455\u0442\u0446\u0475\u051d\u0445\u0443\u0437"
    "\u03b1\u03b2\u03b5\u03b7\u03b9\u03ba\u03bd\u03bf\u03c1\u03c4\u03c5\u03c7\u03b3\u03b6"
    "\u03c9"
    "\u0131\u0237\u0261\u0251\u1d20\u0280\ua731",
    "abcdeehiijklmnopqrstuvwxyzabenikvoptuxyzwijgavrs",
)
_SEPARATORS: Final = frozenset("_-. :/\t\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufe58\ufe63")
_TOP_LEVEL: Final = frozenset(
    {"trust", "trustlevel", "source", "sourcetype", "provenance", "verified"}
)


class ForgeryError(ValueError):
    """The value cannot be checked (too deeply nested or cyclic). Callers must refuse the write."""


@dataclasses.dataclass(frozen=True)
class StripResult:
    value: Any = dataclasses.field(repr=False)
    removed: int


def _skeleton(key: str) -> str:
    return normalize(key).translate(_CONFUSABLES).strip()


def is_reserved_key(key: object, *, top_level: bool) -> bool:
    """True if ``key`` claims provenance.

    The deep rule (``_prov``/``_mnemowall*``) always applies; trust/source names only at top level.
    """
    if not isinstance(key, str):
        return False
    s = _skeleton(key)
    core = "".join(c for c in s if c not in _SEPARATORS)
    if s.startswith("_") and (
        core == "prov" or core.startswith("provenance") or core.startswith("mnemowall")
    ):
        return True
    return top_level and core in _TOP_LEVEL


def _walk(value: Any, *, top: bool, depth: int, path: set[int], count: list[int]) -> Any:
    if not isinstance(value, Mapping | list | tuple):
        return value
    if depth > MAX_DEPTH:
        raise ForgeryError("value is nested too deeply to check")
    if id(value) in path:
        raise ForgeryError("value contains a reference cycle")
    path.add(id(value))
    try:
        if isinstance(value, Mapping):
            out: dict[Any, Any] = {}
            for k, v in value.items():
                if is_reserved_key(k, top_level=top):
                    count[0] += 1
                    continue
                out[k] = _walk(v, top=False, depth=depth + 1, path=path, count=count)
            return out
        items = [_walk(v, top=False, depth=depth + 1, path=path, count=count) for v in value]
        return tuple(items) if isinstance(value, tuple) else items
    finally:
        path.discard(id(value))


def _strip(value: Any, what: str) -> StripResult:
    count = [0]
    out = _walk(value, top=True, depth=0, path=set(), count=count)
    if count[0]:
        diagnostics.record("forgery_attempt", count[0])
        _LOG.warning("forgery_attempt", extra={"count": count[0], "op": what})
    return StripResult(out, count[0])


def strip_value(value: Any) -> StripResult:
    """Remove forged provenance from a memory value. The input is not mutated."""
    return _strip(value, "strip_value")


def strip_tool_args(args: Any) -> StripResult:
    """Remove forged provenance from LLM-generated tool arguments. The input is not mutated."""
    return _strip(args, "strip_tool_args")


def _path_segments(field: str) -> Iterable[str]:
    seg: list[str] = []
    for ch in field:
        if ch in ".[]":
            yield "".join(seg)
            seg = []
        else:
            seg.append(ch)
    yield "".join(seg)


def strip_returned(value: Any, index_fields: list[str] | None) -> tuple[Any, list[str] | None]:
    """Remove ``_prov``/``_mnemowall*`` from a read result and from embedding/index field paths.

    This is our own metadata leaving the store, not an attack, so nothing is counted.
    """
    out = _walk(value, top=False, depth=0, path=set(), count=[0])
    if index_fields is None:
        return out, None
    kept = [
        f
        for f in index_fields
        if not any(is_reserved_key(s, top_level=False) for s in _path_segments(f))
    ]
    return out, kept
