"""Trust lattice and input sources (§3.5).

``operator > verified_user > user > agent_derived >
tool_output = document = email = web = other_agent > unknown``

``TAINTED := trust < user`` is the single boundary used by every invariant, signal and test.
Comparisons use rank only, so the five external sources compare equal: none of ``<``, ``>``
holds between them and ``<=`` holds both ways. Enum identity (``==``) is left untouched.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable
from typing import Final


class TrustLevel(enum.Enum):
    """Ordered trust levels. Compare with ``<``/``<=``/``>``/``>=`` (by rank)."""

    OPERATOR = ("operator", 6)
    VERIFIED_USER = ("verified_user", 5)
    USER = ("user", 4)
    AGENT_DERIVED = ("agent_derived", 3)
    TOOL_OUTPUT = ("tool_output", 2)
    DOCUMENT = ("document", 2)
    EMAIL = ("email", 2)
    WEB = ("web", 2)
    OTHER_AGENT = ("other_agent", 2)
    UNKNOWN = ("unknown", 0)

    def __init__(self, label: str, rank: int) -> None:
        self.label = label
        self.rank = rank

    def __setattr__(self, name: str, value: object) -> None:
        if name in ("label", "rank") and name in self.__dict__:
            raise AttributeError("TrustLevel is immutable")
        super().__setattr__(name, value)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, TrustLevel):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, TrustLevel):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, TrustLevel):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, TrustLevel):
            return NotImplemented
        return self.rank >= other.rank

    def __str__(self) -> str:
        return self.label


EXTERNAL_SOURCES_TRUST: Final = frozenset(
    {
        TrustLevel.TOOL_OUTPUT,
        TrustLevel.DOCUMENT,
        TrustLevel.EMAIL,
        TrustLevel.WEB,
        TrustLevel.OTHER_AGENT,
    }
)


def is_tainted(trust: TrustLevel) -> bool:
    """``TAINTED := trust < user``."""
    return trust < TrustLevel.USER


def trust_min(levels: Iterable[TrustLevel]) -> TrustLevel:
    """Lowest trust; among equal ranks the first occurrence wins (stable)."""
    result: TrustLevel | None = None
    for level in levels:
        if result is None or level < result:
            result = level
    if result is None:
        raise ValueError("trust_min of an empty collection")
    return result


class Source(enum.StrEnum):
    """What put an item into the context window (provenance ``source_type``)."""

    USER_MSG = "user_msg"
    TOOL_OUTPUT = "tool_output"
    WEB = "web"
    EMAIL = "email"
    DOCUMENT = "document"
    OTHER_AGENT = "other_agent"
    SYSTEM = "system"
    OPERATOR = "operator"
    MEMORY_READ = "memory_read"


_DEFAULT: Final = {
    Source.USER_MSG: TrustLevel.USER,
    Source.TOOL_OUTPUT: TrustLevel.TOOL_OUTPUT,
    Source.WEB: TrustLevel.WEB,
    Source.EMAIL: TrustLevel.EMAIL,
    Source.DOCUMENT: TrustLevel.DOCUMENT,
    Source.OTHER_AGENT: TrustLevel.OTHER_AGENT,
    Source.SYSTEM: TrustLevel.OPERATOR,  # D1: deployer-configured system prompt
    Source.OPERATOR: TrustLevel.OPERATOR,
}


def default_trust(source: Source | None, stored: TrustLevel | None = None) -> TrustLevel:
    """Trust for an input from ``source``. No label means ``unknown``.

    ``memory_read`` items carry the trust they were stored with, which the caller must pass.
    """
    if source is None:
        return TrustLevel.UNKNOWN
    if source is Source.MEMORY_READ:
        if stored is None:
            raise ValueError("memory_read requires the stored trust")
        return stored
    return _DEFAULT[source]
