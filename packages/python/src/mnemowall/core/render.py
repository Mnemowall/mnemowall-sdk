"""Showing untrusted text to a human without letting it act on the terminal (§3.13).

:func:`render_untrusted` keeps printable text and newlines, and replaces every other control,
format, private-use, surrogate, unassigned or line/paragraph-separator character with a visible
``\\u{hex}`` escape. That covers ANSI escape sequences, bidi overrides (Trojan Source), zero-width
characters and Unicode tag characters. A literal backslash becomes ``\\\\`` so content can't
fake an escape.
"""

from __future__ import annotations

import unicodedata
from typing import Final

_ESCAPED_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def render_untrusted(text: str) -> str:
    out: list[str] = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\n")
        elif unicodedata.category(ch) in _ESCAPED_CATEGORIES:
            out.append(f"\\u{{{ord(ch):x}}}")
        else:
            out.append(ch)
    return "".join(out)
