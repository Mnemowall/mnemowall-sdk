"""RFC 8785 (JCS) canonical JSON for the subset Mnemowall signs and hashes (ADR-0020, D12).

Supported: ``str``, ``int`` within ±(2**53 - 1), ``bool``, ``None``, ``list``/``tuple`` and
``dict`` with ``str`` keys. Floats are rejected rather than serialized: ECMAScript number
formatting is the hard part of JCS and no signed field needs it. Output is UTF-8 bytes with
object keys sorted by UTF-16 code units and strings escaped as ECMAScript ``JSON.stringify``
does. Lone surrogates are rejected (I-JSON, RFC 7493).

Errors carry a structural path (``$``, ``{}`` for an object member, ``[i]`` for an array
index) and a kind, never a key or a value, so they are safe to log (§3.14).
"""

from __future__ import annotations

from typing import Final, cast

MAX_SAFE_INT: Final = 2**53 - 1
MAX_DEPTH: Final = 64

_SHORT_ESCAPES: Final = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}
_ESCAPES: Final = {cp: _SHORT_ESCAPES.get(cp, f"\\u{cp:04x}") for cp in range(0x20)} | {
    0x22: '\\"',
    0x5C: "\\\\",
}


class JCSError(ValueError):
    """A value outside the canonicalizable subset. Carries a structural path and a kind only."""

    def __init__(self, path: str, kind: str) -> None:
        super().__init__(f"{path}: {kind}")
        self.path = path
        self.kind = kind


def _string(s: str, path: str) -> str:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        raise JCSError(path, "lone_surrogate") from None
    return '"' + s.translate(_ESCAPES) + '"'


def _utf16_key(k: str) -> bytes:
    return k.encode("utf-16-be")


def _emit(value: object, path: str, depth: int, active: set[int], out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif type(value) is int:
        if not -MAX_SAFE_INT <= value <= MAX_SAFE_INT:
            raise JCSError(path, "integer_out_of_range")
        out.append(str(value))
    elif type(value) is str:
        out.append(_string(value, path))
    elif type(value) in (list, tuple, dict):
        if depth >= MAX_DEPTH:
            raise JCSError(path, "too_deep")
        ident = id(value)
        if ident in active:
            raise JCSError(path, "cycle")
        active.add(ident)
        if isinstance(value, dict):
            for k in value:
                if type(k) is not str:
                    raise JCSError(path + "{}", "non_string_key")
            keys = [(_string(k, path + "{}"), k) for k in value]
            keys.sort(key=lambda pair: _utf16_key(pair[1]))
            out.append("{")
            for n, (encoded, k) in enumerate(keys):
                if n:
                    out.append(",")
                out.append(encoded)
                out.append(":")
                _emit(value[k], path + "{}", depth + 1, active, out)
            out.append("}")
        else:
            out.append("[")
            for i, item in enumerate(cast("list[object] | tuple[object, ...]", value)):
                if i:
                    out.append(",")
                _emit(item, f"{path}[{i}]", depth + 1, active, out)
            out.append("]")
        active.discard(ident)
    else:
        raise JCSError(path, f"unsupported_type:{type(value).__name__}")


def canonicalize(value: object) -> bytes:
    """Return the RFC 8785 canonical UTF-8 encoding of ``value`` (see module docstring)."""
    out: list[str] = []
    _emit(value, "$", 0, set(), out)
    return "".join(out).encode("utf-8")
