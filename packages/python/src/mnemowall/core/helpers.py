"""Provenance helpers for tool code (M1a-18, D30).

``@mnemowall.source("email")`` marks a function whose return value is third-party input: each
call's result is observed into the active provenance session at that source's trust, so any
memory write influenced by it is computed at that trust (§3.5). Sync and async functions are
supported; return values are passed through unchanged. With no active session nothing is
observed and the ``observe_without_session`` counter increments (``doctor`` reports it).
"""

from __future__ import annotations

import functools
import inspect
import json
from collections.abc import Callable
from typing import Any, Final, TypeVar

from mnemowall._log import get_logger
from mnemowall.core import diagnostics
from mnemowall.core.provenance import current_session
from mnemowall.core.trust import Source

F = TypeVar("F", bound=Callable[..., Any])
_NOT_DECORATABLE: Final = frozenset(
    {Source.USER_MSG, Source.SYSTEM, Source.OPERATOR, Source.MEMORY_READ}
)
_log = get_logger("helpers")


def _observe(result: Any, src: Source) -> None:
    session = current_session()
    if session is None:
        diagnostics.record("observe_without_session")
        _log.warning("observe_without_session", extra={"source_type": src.value})
        return
    if isinstance(result, str):
        text = result
    else:
        text = json.dumps(result, default=str, ensure_ascii=False)
    session.observe(text, source=src)


def source(name: str) -> Callable[[F], F]:
    """Decorate a function whose return value comes from ``name`` (e.g. ``"email"``, ``"web"``)."""
    try:
        src = Source(name)
    except ValueError:
        raise ValueError(f"unknown source; use one of {sorted(s.value for s in Source)}") from None
    if src in _NOT_DECORATABLE:
        raise ValueError("this source can't be set by a decorator; it comes from the harness")

    def decorate(fn: F) -> F:
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                result = await fn(*args, **kwargs)
                _observe(result, src)
                return result

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = fn(*args, **kwargs)
            _observe(result, src)
            return result

        return wrapper  # type: ignore[return-value]

    return decorate
