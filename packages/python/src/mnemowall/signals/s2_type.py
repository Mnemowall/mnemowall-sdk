"""S2: memory-type classification by lexicon (§3.5).

Detects imperative mood, "always/never/from now on/whenever/remember to", condition->action,
second-person and agent-directed modals, override phrases, and step-by-step procedures.
The output is a type plus a risk score and rule ids. It never *allows* anything: a write that
looks like a fact can still be quarantined by provenance (I1/I2), and a caller-claimed type
can only be raised by this result, never lowered (D7, I6). All patterns run on RE2.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Final

from mnemowall.core import regex
from mnemowall.core.model import MemoryType
from mnemowall.signals.base import SignalResult

_VERBS: Final = (
    "send|forward|reply|respond|include|append|attach|add|delete|remove|erase|ignore|disregard|use|"
    "call|run|execute|email|post|upload|share|disclose|reveal|leak|click|visit|transfer|pay|wire|"
    "summarize|translate|answer|output|save|store|copy|treat|pretend|mention|cc|bcc|redirect|route|"
    "exfiltrate|encode|fetch|download"
)

# (rule id, risk, pattern). Order does not matter; the riskiest type wins.
_INSTRUCTION_RULES: Final = [
    (
        "S2.override",
        1.0,
        r"(?i)\b(ignore|disregard|forget)\s+(all\s+)?(the\s+)?"
        r"(previous|prior|above|earlier|preceding)\s+(instructions?|directions|rules|prompts?)\b",
    ),
    (
        "S2.temporal",
        0.8,
        r"(?i)\b(from now on|going forward|from this point( on)?|henceforth|from here on|"
        r"every time|each time|whenever|at all times|"
        r"for (all )?future (sessions|conversations|chats|replies)|"
        r"in (all )?future (sessions|conversations|chats|replies))\b",
    ),
    (
        "S2.remember",
        0.8,
        r"(?i)\b(remember to|don'?t forget to|do not forget to|never forget to|"
        r"make sure (to|that you|you)|be sure to)\b",
    ),
    (
        "S2.modal_2p",
        0.7,
        r"(?i)\byou(\s+\w+)?\s+(must|should|shall|need to|have to|are to|ought to|are required to|"
        r"will always|will never)\b",
    ),
    (
        "S2.agent_directed",
        0.7,
        r"(?i)\b(assistant|agent|ai|bot|model|chatbot)\s+(should|must|shall|will|always|never)\b",
    ),
    ("S2.always_verb", 0.7, r"(?i)\b(always|never)\s+(\w+\s+){0,2}?(" + _VERBS + r")\b"),
    # A sentence that *opens* with "Always"/"Never" is an imperative whatever the verb
    # ("Always ask...", "Never apply..."): found by the red-team pack (M1a-23).
    ("S2.always_lead", 0.7, r"(?i)(^|[.!?:\]\n]\s*)(always|never)\s+[a-z]{2,}"),
    (
        "S2.cond_action",
        0.6,
        r"(?i)\b(if|when|whenever|once)\b[^.\n]{1,160}?,\s*(then\s+)?(please\s+)?("
        + _VERBS
        + r")\b",
    ),
    ("S2.imperative", 0.6, r"(?i)(^|[.!?:\]\n]\s*)(please\s+)?(" + _VERBS + r")\b"),
]
_STEP: Final = r"(?i)(^|\n|[.:]\s+)(step\s*\d+\s*[:.)-]|\d+[.)]\s+[a-z])"
_FIRST_THEN: Final = r"(?i)\bfirst\b[^.\n]{0,160}\bthen\b"
_PREFERENCE: Final = (
    r"(?i)\b(prefers?|preferred|prefer to|likes?|loves?|hates?|dislikes?|enjoys?|"
    r"favou?rite|would rather)\b"
)


@dataclasses.dataclass(frozen=True)
class S2Result:
    memory_type: MemoryType
    risk: float
    rules: tuple[str, ...]

    def signal(self) -> SignalResult:
        fired = self.memory_type in (MemoryType.STANDING_INSTRUCTION, MemoryType.PROCEDURE)
        return SignalResult(
            "S2", fired=fired, risk=self.risk, labels=(str(self.memory_type), *self.rules)
        )


_compiled: list[tuple[str, float, Any]] | None = None


def _rules() -> list[tuple[str, float, Any]]:
    global _compiled
    if _compiled is None:
        _compiled = [(rid, risk, regex.compile(p)) for rid, risk, p in _INSTRUCTION_RULES]
        _compiled += [
            ("S2.steps", 0.6, regex.compile(_STEP)),
            ("S2.first_then", 0.5, regex.compile(_FIRST_THEN)),
            ("S2.preference", 0.1, regex.compile(_PREFERENCE)),
        ]
    return _compiled


_SPACED: Final = r"(?i)\b(?:[a-z][ .*_-]){1,40}[a-z]\b"
_LEET: Final = str.maketrans("013457@$", "oieastas")
_spaced: Any = None


def _despace(text: str) -> str:
    """Join letter-spaced words ("f r o m", "a-l-w-a-y-s") back together."""
    global _spaced
    if _spaced is None:
        _spaced = regex.compile(_SPACED)
    out, last = [], 0
    for m in _spaced.finditer(text):
        out += [text[last : m.start()], "".join(c for c in m.group(0) if c.isalpha())]
        last = m.end()
    return "".join(out) + text[last:] if out else text


def _deleet(text: str) -> str:
    """Map digits used as letters ("fr0m", "alw4ys") back, only inside words with letters."""
    if not any(c in text for c in "013457@$"):  # nothing that could be mapped
        return text
    words = text.split(" ")
    for i, w in enumerate(words):
        if len(w) <= 24 and any(c.isalpha() for c in w) and any(c in "013457@$" for c in w):
            words[i] = w.translate(_LEET)
    return " ".join(words)


def _fire(text: str) -> list[tuple[str, float]]:
    fired: list[tuple[str, float]] = []
    for rid, risk, rx in _rules():
        if rid == "S2.steps":
            if sum(1 for _ in rx.finditer(text)) >= 2:
                fired.append((rid, risk))
        elif rx.search(text) is not None:
            fired.append((rid, risk))
    return fired


def classify(text: str) -> S2Result:
    """Classify ``text`` (callers enforce the size cap first). Riskiest type wins.

    A de-spaced, de-leeted copy is classified too (M1b-09 red-team finding); its rules are
    added, never subtracted, and ``S2.deobfuscated`` marks that the copy found more.
    """
    fired = _fire(text)
    variant = "\n".join(" ".join(line.split()) for line in _deleet(_despace(text)).split("\n"))
    if variant != text:
        have = {rid for rid, _ in fired}
        extra = [(rid, risk) for rid, risk in _fire(variant) if rid not in have]
        if extra:
            fired += [*extra, ("S2.deobfuscated", 0.0)]
    ids = tuple(rid for rid, _ in fired)
    risk = max((r for _, r in fired), default=0.0)
    if "S2.steps" in ids or "S2.first_then" in ids:
        kind = MemoryType.PROCEDURE
    elif any(rid in ids for rid, _, _ in _INSTRUCTION_RULES):
        kind = MemoryType.STANDING_INSTRUCTION
    elif "S2.preference" in ids:
        kind = MemoryType.PREFERENCE
    else:
        kind = MemoryType.FACT
    return S2Result(kind, risk, ids)
