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


def classify(text: str) -> S2Result:
    """Classify ``text`` (callers enforce the size cap first). Riskiest type wins."""
    fired: list[tuple[str, float]] = []
    steps = 0
    for rid, risk, rx in _rules():
        if rid == "S2.steps":
            steps = sum(1 for _ in rx.finditer(text))
            if steps >= 2:
                fired.append((rid, risk))
        elif rx.search(text) is not None:
            fired.append((rid, risk))
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
