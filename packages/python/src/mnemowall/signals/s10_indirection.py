"""S10: mutable-location indirection and destructive verbs (§3.5).

Indirection: content that tells the agent to take instructions or data from a location whose
contents can change later ("do whatever the newest email says", "follow the steps at <url>").
Destructive: broad delete/wipe/purge requests and destructive shell or SQL commands.
Callers pass normalized text (``s4_obfuscation.normalize``) so width and zero-width tricks fail.
All patterns run on RE2. Output is labels only.
"""

from __future__ import annotations

from typing import Final

from mnemowall.core import regex
from mnemowall.signals.base import SignalResult

# One filler word; may contain apostrophes or hyphens ("the vendor's latest email").
_W: Final = r"([\w'\x{2019}-]+\s+)"
_FRESH: Final = r"(newest|latest|most recent|last|next|incoming|current)"
_LOCATION: Final = (
    r"(email|e-mail|message|mail|dm|ticket|comment|issue|post|file|document|doc|page|note|reply|"
    r"response|instructions?)"
)
_DEFER_VERB: Final = (
    r"(use|follow|do|apply|obey|execute|run|treat|take|read|check|consult|fetch|load|pull|get)"
)
_REMOTE: Final = (
    r"(https?://|www\.|the (linked|attached|shared|pinned|following)\b|this (link|url|page|doc)\b)"
)
_SAYS: Final = r"(says|said|asks|requests|instructs|tells)"
_WIPE_VERB: Final = (
    r"(delete|erase|wipe|purge|drop|truncate|destroy|remove|shred|overwrite|reset|format|clear)"
)
_WIPE_OBJECT: Final = (
    r"(all|every|entire|everything|any|whole|database|db|tables?|memories|memory|records?|files|"
    r"backups?|logs?|history|account|repository|repo|inbox|emails|disk)"
)
_SHELL: Final = (
    r"(\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r|\bdrop\s+(table|database|schema)\b|"
    r"\btruncate\s+table\b|\bgit\s+push\s+(-f\b|--force\b)|\bmkfs\b|:\(\)\s*\{\s*:\|:&\s*\};:)"
)

_RULES: Final = [
    (
        "S10.indirection",
        0.6,
        rf"(?i)\b{_DEFER_VERB}\s+{_W}{{0,3}}?{_FRESH}\s+{_W}{{0,2}}?{_LOCATION}\b",
    ),
    ("S10.indirection", 0.6, rf"(?i)\b(whatever|do (exactly )?what)\s+{_W}{{0,5}}?{_SAYS}\b"),
    (
        "S10.indirection",
        0.7,
        rf"(?i)\b(follow|obey|run|execute|apply|get|take)\s+{_W}{{0,3}}?"
        rf"(instructions?|steps|commands?|rules|directions)\s+{_W}{{0,2}}?(at|from|in|on)\s+{_REMOTE}",
    ),
    (
        "S10.indirection",
        0.7,
        r"(?i)\bget\s+(your|the)\s+(instructions?|rules|commands?|steps)\s+from\b",
    ),
    ("S10.destructive", 0.7, rf"(?i)\b{_WIPE_VERB}\s+{_W}{{0,2}}?{_WIPE_OBJECT}\b"),
    ("S10.destructive_shell", 0.9, rf"(?i){_SHELL}"),
]

_compiled: list[tuple[str, float, object]] | None = None


def _rules() -> list[tuple[str, float, object]]:
    global _compiled
    if _compiled is None:
        _compiled = [(label, risk, regex.compile(p)) for label, risk, p in _RULES]
    return _compiled


def s10_indirection(text: str) -> SignalResult:
    fired: dict[str, float] = {}
    for label, risk, rx in _rules():
        if rx.search(text) is not None:  # type: ignore[attr-defined]
            fired[label] = max(risk, fired.get(label, 0.0))
    return SignalResult(
        "S10",
        fired=bool(fired),
        risk=max(fired.values(), default=0.0),
        labels=tuple(sorted(fired)),
    )
