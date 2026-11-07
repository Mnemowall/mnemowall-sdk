"""Incident view (M1a-20): who read a memory version, and what came after it.

``incident_report`` lists every session whose read included the version, with the time and
the label the item was shown under (``plain``, ``low_trust``, ``unverified``, ``stale``), plus
later versions of the memory. Read details removed by retention are counted, not guessed.
No content is included.
"""

from __future__ import annotations

from dataclasses import dataclass

from mnemowall.ledger import Ledger


class IncidentError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class IncidentRead:
    session_id: str
    ts_ms: int
    label: str
    verified: bool
    stale: bool


@dataclass(frozen=True, slots=True)
class IncidentReport:
    memory_id: str
    version_no: int
    trust_level: str
    effective_type: str
    verified: bool
    reads: tuple[IncidentRead, ...]
    sessions: tuple[str, ...]
    later_versions: tuple[int, ...]
    head_version: int
    purged_read_events: int


def incident_report(ledger: Ledger, memory_id: str, version_no: int) -> IncidentReport:
    record = ledger.version(memory_id, version_no)
    if record is None:
        raise IncidentError("unknown_version")
    reads: list[IncidentRead] = []
    purged = 0
    for event in ledger.reads():
        if event.session_id is None:
            if event.ts_ms >= record.ts_ms:
                purged += 1
            continue
        for item in event.items:
            if item.memory_id == memory_id and item.version_no == version_no:
                reads.append(
                    IncidentRead(
                        event.session_id, event.ts_ms, item.wrap_label, item.verified, item.stale
                    )
                )
    sessions = tuple(dict.fromkeys(r.session_id for r in reads))
    versions = [v.version_no for v in ledger.versions(memory_id)]
    fields = record.signed_fields
    return IncidentReport(
        memory_id=memory_id,
        version_no=version_no,
        trust_level=fields.trust_level if fields is not None else "unknown",
        effective_type=fields.effective_type if fields is not None else "unknown",
        verified=record.verified,
        reads=tuple(reads),
        sessions=sessions,
        later_versions=tuple(v for v in versions if v > version_no),
        head_version=max(versions),
        purged_read_events=purged,
    )
