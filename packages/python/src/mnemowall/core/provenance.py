"""Provenance context: what is in the agent's context window, and what a write may be trusted with.

Normative API (§3.5)::

    with guard.session(tenant=..., principal=..., agent=..., session_id=...) as s:
        s.system_prompt()                         # operator by default (D1)
        s.user_turn(verified=False)               # verified=True needs a guard-issued token (D2)
        s.observe(content, source=Source.EMAIL, ref=msg_id)
        s.register_memory_read(memory_id, stored_trust=..., verified=..., stale=...)
        s.evict(item_ids) / s.compacted(kept_ids) # unknown ids raise (D3)
        s.write_trust()

Write trust = min(the current turn's principal trust, the trust of every item in the window).
Taint does **not** reset at user turns; it falls only when the item leaves the window.
With no active session, :func:`current_write_trust` returns ``unknown``.

Content passed in is kept in memory only, for the signals. It is never in ``repr``, logs or storage.
The in-process SDK is not a security boundary against an agent with code execution (§3.1): such
an agent could call these methods itself. Use the gate for those deployments.
"""

from __future__ import annotations

import contextvars
import dataclasses
import hashlib
import hmac
import secrets
import threading
import time
import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from typing import Final

from mnemowall import _log
from mnemowall.core import diagnostics
from mnemowall.core.trust import Source, TrustLevel, default_trust, trust_min

_LOG: Final = _log.get_logger("provenance")
_CURRENT: contextvars.ContextVar[ProvenanceSession | None] = contextvars.ContextVar(
    "mnemowall_provenance_session", default=None
)
_TOKEN_TTL_S: Final = 300.0
_OBSERVE_FORBIDDEN: Final = {
    Source.USER_MSG: "use user_turn()",
    Source.SYSTEM: "use system_prompt()",
    Source.OPERATOR: "use an operator-attested elevation in a signed policy",
    Source.MEMORY_READ: "use register_memory_read()",
}


class SessionError(Exception):
    """Misuse of the provenance session API (nesting, invalid confirmation token, ...)."""


class UnknownContextItemError(KeyError):
    """``evict``/``compacted`` referenced an item this session never registered (D3)."""


@dataclasses.dataclass(frozen=True)
class ContextItem:
    """One item in the context window. ``content`` is held in memory only and never printed."""

    id: str
    source: Source | None
    trust: TrustLevel
    content: str | None = dataclasses.field(default=None, repr=False, compare=False)
    ref: str | None = dataclasses.field(default=None, repr=False, compare=False)

    def __str__(self) -> str:
        return f"ContextItem({self.id}, {self.source}, {self.trust})"


@dataclasses.dataclass(frozen=True)
class ConfirmationToken:
    """Proof from the harness that a user turn was re-authenticated or explicitly confirmed (D2)."""

    session_id: str
    nonce: str
    expires_at: float
    mac: str = dataclasses.field(repr=False)


def _check_id(name: str, value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError(f"{name} must be a non-empty string of at most 256 characters")
    return value


class Guard:
    """Entry point: opens provenance sessions and issues confirmation tokens."""

    def __init__(self) -> None:
        self._key = secrets.token_bytes(32)
        self._used: set[str] = set()
        self._lock = threading.Lock()

    def _mac(self, session_id: str, nonce: str, expires_at: float) -> str:
        msg = f"{session_id}\x00{nonce}\x00{expires_at!r}".encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def issue_confirmation(self, session_id: str) -> ConfirmationToken:
        """Called by the harness after re-auth or an explicit 'save as instruction' confirmation."""
        nonce = secrets.token_hex(16)
        expires = time.time() + _TOKEN_TTL_S
        return ConfirmationToken(session_id, nonce, expires, self._mac(session_id, nonce, expires))

    def _redeem(self, token: ConfirmationToken | None, session_id: str) -> None:
        if not isinstance(token, ConfirmationToken):
            raise SessionError("verified user turn requires a confirmation token")
        expected = self._mac(token.session_id, token.nonce, token.expires_at)
        with self._lock:
            if (
                not hmac.compare_digest(expected, token.mac)
                or token.session_id != session_id
                or token.expires_at < time.time()
                or token.nonce in self._used
            ):
                raise SessionError("invalid, expired, reused or foreign confirmation token")
            self._used.add(token.nonce)

    @contextmanager
    def session(
        self, *, tenant: str, principal: str, agent: str, session_id: str
    ) -> Iterator[ProvenanceSession]:
        if _CURRENT.get() is not None:
            raise SessionError("nested sessions are not allowed")
        sess = ProvenanceSession(
            self,
            _check_id("tenant", tenant),
            _check_id("principal", principal),
            _check_id("agent", agent),
            _check_id("session_id", session_id),
        )
        token = _CURRENT.set(sess)
        try:
            yield sess
        finally:
            _CURRENT.reset(token)


class ProvenanceSession:
    """The active context window for one agent session. Obtain it via :meth:`Guard.session`."""

    def __init__(
        self, guard: Guard, tenant: str, principal: str, agent: str, session_id: str
    ) -> None:
        self._guard = guard
        self.tenant = tenant
        self.principal = principal
        self.agent = agent
        self.session_id = session_id
        self._items: dict[str, ContextItem] = {}
        self._turn_trust: TrustLevel | None = None  # None: no user turn yet -> agent_derived

    def __repr__(self) -> str:
        return f"ProvenanceSession(items={len(self._items)}, write_trust={self.write_trust()})"

    __str__ = __repr__

    @property
    def items(self) -> tuple[ContextItem, ...]:
        return tuple(self._items.values())

    def _add(
        self, source: Source | None, trust: TrustLevel, content: str | None, ref: str | None
    ) -> ContextItem:
        item = ContextItem(uuid.uuid4().hex, source, trust, content, ref)
        self._items[item.id] = item
        _LOG.debug(
            "context_item_added", extra={"source_type": str(source), "trust_level": trust.label}
        )
        return item

    def system_prompt(
        self, content: str | None = None, trust: TrustLevel = TrustLevel.OPERATOR
    ) -> ContextItem:
        return self._add(Source.SYSTEM, trust, content, None)

    def user_turn(
        self,
        content: str | None = None,
        *,
        verified: bool = False,
        token: ConfirmationToken | None = None,
    ) -> ContextItem:
        if verified:
            self._guard._redeem(token, self.session_id)
        trust = TrustLevel.VERIFIED_USER if verified else TrustLevel.USER
        self._turn_trust = trust
        return self._add(Source.USER_MSG, trust, content, None)

    def observe(
        self, content: str | None, source: Source | None = None, ref: str | None = None
    ) -> ContextItem:
        if source in _OBSERVE_FORBIDDEN:
            raise ValueError(f"observe() cannot take source={source}: {_OBSERVE_FORBIDDEN[source]}")
        return self._add(source, default_trust(source), content, ref)

    def register_memory_read(
        self,
        memory_id: str,
        *,
        stored_trust: TrustLevel,
        verified: bool,
        stale: bool,
        content: str | None = None,
    ) -> ContextItem:
        trust = stored_trust if verified and not stale else TrustLevel.UNKNOWN
        return self._add(Source.MEMORY_READ, trust, content, _check_id("memory_id", memory_id))

    def _require_known(self, ids: Iterable[str]) -> list[str]:
        wanted = list(ids)
        unknown = [i for i in wanted if i not in self._items]
        if unknown:
            raise UnknownContextItemError(f"{len(unknown)} unknown context item id(s)")
        return wanted

    def evict(self, item_ids: Iterable[str]) -> None:
        for i in self._require_known(item_ids):
            del self._items[i]

    def compacted(self, kept_ids: Iterable[str]) -> None:
        keep = set(self._require_known(kept_ids))
        self._items = {i: it for i, it in self._items.items() if i in keep}

    def write_trust(self) -> TrustLevel:
        principal = self._turn_trust if self._turn_trust is not None else TrustLevel.AGENT_DERIVED
        return trust_min([principal, *(it.trust for it in self._items.values())])


def current_write_trust() -> TrustLevel:
    """Trust for a write happening now. No active session -> ``unknown`` (and a doctor warning)."""
    sess = _CURRENT.get()
    if sess is None:
        diagnostics.record("write_without_session")
        _LOG.warning("write_without_session", extra={"trust_level": TrustLevel.UNKNOWN.label})
        return TrustLevel.UNKNOWN
    return sess.write_trust()
