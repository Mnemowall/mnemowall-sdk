"""Content-safe logging for the mnemowall SDK (§1.6, §3.14).

Memory content, prompts and tool outputs must never reach logs, traces or error output. Every
record from an SDK logger passes through :class:`ContentSafeFilter`, which:

* replaces the message with a fixed, identifier-shaped event name and drops ``args``;
* keeps only allowlisted ``extra`` fields, and only numeric, boolean, ``None`` or
  identifier-shaped string values (or short lists of identifiers); anything else becomes
  ``"<redacted>"``;
* drops exception messages, tracebacks and stack info, keeping only the exception type name.

Logger filters do not apply to records from child loggers, so SDK code must obtain loggers
only through :func:`get_logger` (enforced by a test). Identifier-shaped values in allowlisted
fields can still be data the caller chose to log; the allowlist keeps those fields to
SDK-controlled identifiers such as rule IDs and outcomes.
"""

from __future__ import annotations

import logging
import re
from typing import Final

LOGGER_NAME: Final = "mnemowall"

_IDENT: Final = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,63}")
_REDACTED: Final = "<redacted>"
_MAX_LIST: Final = 32

ALLOWED_FIELDS: Final = frozenset(
    {
        "adapter",
        "count",
        "decision",
        "dropped_fields",
        "effective_type",
        "error_type",
        "failure_mode",
        "latency_us",
        "memory_type",
        "mode",
        "op",
        "outcome",
        "rule_ids",
        "signal_ids",
        "source_type",
        "trust_level",
        "version_no",
    }
)

# Attributes logging itself sets on every record. msg, args, exc_info, exc_text and stack_info
# can carry caller content and are sanitized explicitly; the rest are logger metadata.
_STANDARD_ATTRS: Final = frozenset(
    vars(logging.LogRecord("x", logging.INFO, "x", 0, "x", None, None))
) | {"message", "asctime"}


def _safe_value(value: object) -> object:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return value
    if isinstance(value, str):
        return value if _IDENT.fullmatch(value) else _REDACTED
    if isinstance(value, list | tuple | set | frozenset):
        items = list(value)
        if len(items) <= _MAX_LIST and all(
            isinstance(i, str) and _IDENT.fullmatch(i) for i in items
        ):
            return items
        return [
            i if isinstance(i, str) and _IDENT.fullmatch(i) else _REDACTED
            for i in items[:_MAX_LIST]
        ]
    return _REDACTED


class ContentSafeFilter(logging.Filter):
    """Rewrites a record in place so that only allowlisted, identifier-shaped data remains."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.msg
        record.msg = msg if isinstance(msg, str) and _IDENT.fullmatch(msg) else "unnamed_event"
        record.args = ()
        attrs = record.__dict__
        if record.exc_info:
            exc = record.exc_info[1]
            attrs["error_type"] = type(exc).__name__ if exc is not None else "unknown"
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        dropped = 0
        for key in list(attrs):
            if key in _STANDARD_ATTRS:
                continue
            if key not in ALLOWED_FIELDS:
                del attrs[key]
                dropped += 1
                continue
            attrs[key] = _safe_value(attrs[key])
        if dropped:
            attrs["dropped_fields"] = dropped
        return True


_FILTER: Final = ContentSafeFilter()
logging.getLogger(LOGGER_NAME).addHandler(logging.NullHandler())


def get_logger(component: str) -> logging.Logger:
    """Return the SDK logger for ``component`` with the content-safe filter attached."""
    if not _IDENT.fullmatch(component):
        raise ValueError("invalid logger component name")
    logger = logging.getLogger(f"{LOGGER_NAME}.{component}")
    if _FILTER not in logger.filters:
        logger.addFilter(_FILTER)
    return logger
