"""Write-path decisions: invariants I1-I6 and I9, policy rules, failure modes, shadow mode.

Order of work for one write (§3.5, §1.3):

1. Strip forged provenance from the value and tool arguments (I9). Trust comes only from the
   provenance context (:func:`current_write_trust`); nothing in the request can raise it.
2. Structural signals S1, S5, S7 and the size cap (S0). Oversized content is not scanned.
3. Content signals: S2 type (D7: the riskier of claimed and classified wins), S3, S4, S10, and
   caller-supplied filter verdicts (S6; ``unknown`` is never ``clean``, I6).
4. :func:`decide` combines invariants and rules. It is pure and monotone: more signals, lower
   trust or fewer grants can only keep or raise strictness (PT-I6).
5. Failure modes from the active policy apply when a step errors, and are recorded.
6. Shadow mode records ``shadow_would_*`` and commits instead of quarantining, but still stores
   tainted writes as data (I3). Scope denials (I5) and failure-mode outcomes stay enforced.

Decisions carry ids, labels and counts only. No memory content reaches logs, reprs or records.
"""

from __future__ import annotations

import dataclasses
import enum
import json
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any, Final

from mnemowall import _log
from mnemowall.core import diagnostics
from mnemowall.core.forgery import ForgeryError, strip_tool_args, strip_value
from mnemowall.core.limits import oversized
from mnemowall.core.model import EffectiveType, MemoryType, Outcome
from mnemowall.core.provenance import current_session, current_write_trust
from mnemowall.core.trust import TrustLevel, is_tainted
from mnemowall.policy.schema import CompiledPolicy, Rule
from mnemowall.signals import s3_sinks
from mnemowall.signals.base import SignalResult
from mnemowall.signals.s2_type import classify
from mnemowall.signals.s4_obfuscation import normalize, s4_obfuscation
from mnemowall.signals.s10_indirection import s10_indirection
from mnemowall.signals.write import (
    Op,
    Scope,
    ScopeKind,
    WriteFacts,
    s1_taint,
    s5_scope,
    s7_protected_mutation,
)

_LOG: Final = _log.get_logger("policy")

_STRICTNESS: Final = {
    Outcome.ALLOW: 0,
    Outcome.ALLOW_AS_DATA: 1,
    Outcome.QUARANTINE: 2,
    Outcome.DENY: 3,
    Outcome.SHADOW_WOULD_ALLOW: 0,
    Outcome.SHADOW_WOULD_ALLOW_AS_DATA: 1,
    Outcome.SHADOW_WOULD_QUARANTINE: 2,
    Outcome.SHADOW_WOULD_DENY: 3,
}
_SHADOW: Final = {
    Outcome.ALLOW: Outcome.SHADOW_WOULD_ALLOW,
    Outcome.ALLOW_AS_DATA: Outcome.SHADOW_WOULD_ALLOW_AS_DATA,
    Outcome.QUARANTINE: Outcome.SHADOW_WOULD_QUARANTINE,
    Outcome.DENY: Outcome.SHADOW_WOULD_DENY,
}
_TYPE_RANK: Final = {
    MemoryType.FACT: 0,
    MemoryType.PREFERENCE: 1,
    MemoryType.PROCEDURE: 2,
    MemoryType.STANDING_INSTRUCTION: 3,
}
_RISKY_TYPES: Final = frozenset({MemoryType.STANDING_INSTRUCTION, MemoryType.PROCEDURE})
_CONTENT_RISK_PREFIXES: Final = ("S3.", "S4.", "S10.", "S6.")
_ENFORCED_IN_SHADOW: Final = frozenset({"I5"})
_OWN_SCOPE: Final = Scope(ScopeKind.USER)


def strictness(outcome: Outcome) -> int:
    return _STRICTNESS[outcome]


def riskier_type(a: MemoryType, b: MemoryType | None) -> MemoryType:
    """D7: the riskier of two types (claimed vs classified)."""
    return a if b is None or _TYPE_RANK[a] >= _TYPE_RANK[b] else b


class FilterVerdict(enum.StrEnum):
    """An external or local filter's answer (S6). ``UNKNOWN`` covers timeouts and errors."""

    CLEAN = "clean"
    FLAGGED = "flagged"
    UNKNOWN = "unknown"


@dataclasses.dataclass(frozen=True)
class WriteRequest:
    """A memory write as the adapter sees it. Nothing here can raise trust (I9)."""

    value: Any = dataclasses.field(repr=False)
    op: Op = Op.CREATE
    target_scope: Scope = _OWN_SCOPE
    principal_scope: Scope = _OWN_SCOPE
    grants: frozenset[str] = frozenset()
    target_protected: bool = False
    target_type: MemoryType | None = None
    claimed_type: MemoryType | None = None
    tool_args: Any = dataclasses.field(default=None, repr=False)


@dataclasses.dataclass(frozen=True)
class DecisionInputs:
    """Everything :func:`decide` looks at. ``fired`` holds signal ids/labels only."""

    trust: TrustLevel
    memory_type: MemoryType
    op: Op
    scope: ScopeKind
    grants: frozenset[str]
    protected: bool
    fired: frozenset[str]


@dataclasses.dataclass(frozen=True)
class Decision:
    """Record of one write decision (UT-DECISION). No content."""

    outcome: Outcome  # what is recorded; ``shadow_would_*`` in shadow mode
    action: Outcome  # what the adapter must do: allow, allow_as_data, quarantine or deny
    effective_type: EffectiveType | None  # None unless committed
    memory_type: MemoryType  # D7 type used by the invariants
    classified_type: MemoryType | None
    claimed_type: MemoryType | None
    write_trust: TrustLevel
    rule_ids: tuple[str, ...]
    signals: tuple[SignalResult, ...]
    fired_signals: tuple[str, ...]
    failure_modes: tuple[str, ...]
    alerts: tuple[str, ...]
    policy_id: str
    policy_digest: str
    mode: str
    latency_us: int
    forgery_removed: int

    @property
    def committed(self) -> bool:
        return self.action in (Outcome.ALLOW, Outcome.ALLOW_AS_DATA)

    def as_record(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "action": self.action.value,
            "effective_type": self.effective_type.value if self.effective_type else None,
            "memory_type": self.memory_type.value,
            "classified_type": self.classified_type.value if self.classified_type else None,
            "claimed_type": self.claimed_type.value if self.claimed_type else None,
            "write_trust": self.write_trust.label,
            "rule_ids": list(self.rule_ids),
            "signals": [
                {"id": s.id, "fired": s.fired, "risk": s.risk, "labels": list(s.labels)}
                for s in self.signals
            ],
            "fired_signals": list(self.fired_signals),
            "failure_modes": list(self.failure_modes),
            "alerts": list(self.alerts),
            "policy_id": self.policy_id,
            "policy_digest": self.policy_digest,
            "mode": self.mode,
            "latency_us": self.latency_us,
            "forgery_removed": self.forgery_removed,
        }


@dataclasses.dataclass(frozen=True)
class WriteResult:
    decision: Decision
    value: Any = dataclasses.field(repr=False)  # forgery-stripped; store this, not the input
    tool_args: Any = dataclasses.field(repr=False)


# --- Pure decision --------------------------------------------------------------------------


def _rule_matches(rule: Rule, i: DecisionInputs) -> bool:
    w = rule.when
    if w.tainted and not is_tainted(i.trust):
        return False
    if w.protected and not i.protected:
        return False
    if w.signals_any is not None and not any(
        s in i.fired or any(f.startswith(s + ".") for f in i.fired) for s in w.signals_any
    ):
        return False
    if w.types is not None and i.memory_type not in w.types:
        return False
    if w.ops is not None and i.op not in w.ops:
        return False
    if w.scope is not None and i.scope not in w.scope:
        return False
    if w.principal_lacks_grant is not None and w.principal_lacks_grant in i.grants:
        return False
    return not (w.trust_below is not None and not i.trust < w.trust_below)


def decide(policy: CompiledPolicy, i: DecisionInputs) -> tuple[Outcome, tuple[str, ...]]:
    """Invariants first, then policy rules; the strictest outcome wins. Pure and monotone."""
    tainted = is_tainted(i.trust)
    hits: list[tuple[Outcome, str]] = []
    if tainted:
        hits.append((Outcome.ALLOW_AS_DATA, "I3"))
        if i.memory_type in _RISKY_TYPES:
            hits.append((Outcome.QUARANTINE, "I1"))
        elif any(f.startswith(_CONTENT_RISK_PREFIXES) for f in i.fired):
            hits.append((Outcome.QUARANTINE, "I2"))
    if "S7" in i.fired and i.trust < TrustLevel.VERIFIED_USER:
        hits.append((Outcome.QUARANTINE, "I4"))
    if "S5" in i.fired:
        hits.append((Outcome.DENY, "I5"))
    if "S0.oversize" in i.fired:
        hits.append((Outcome.QUARANTINE, "size_cap"))
    hits.extend((r.then, r.id) for r in policy.rules if _rule_matches(r, i))
    action = max((o for o, _ in hits), key=strictness, default=Outcome.ALLOW)
    return action, tuple(rid for _, rid in hits)


# --- Signals (module-level so tests can inject failures) ------------------------------------


def _text_of(value: Any) -> str:
    """Serialized size form (D5 cap)."""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, default=str)


def _scan_text(value: Any, depth: int = 0) -> str:
    """What the signals read: every string in the value on its own line, keys included.

    Scanning the JSON form hid sentence starts behind quotes (``{"text": "Never ...``), so
    sentence-initial rules missed them (found by the red-team pack, M1a-23). Values are already
    forgery-stripped and depth-checked; the depth guard here is defensive.
    """
    if isinstance(value, str):
        return value
    if depth > 100:
        return ""
    if isinstance(value, dict):
        lines: list[str] = []
        for k, v in value.items():
            key = k if isinstance(k, str) else ""
            if isinstance(v, str):
                lines.append(f"{key}: {v}" if key else v)
            else:
                lines += [key, _scan_text(v, depth + 1)]
        return "\n".join(line for line in lines if line)
    if isinstance(value, list | tuple):
        return "\n".join(t for t in (_scan_text(v, depth + 1) for v in value) if t)
    return "" if value is None else str(value)


def _classify(normalized: str) -> MemoryType:
    return classify(normalized).memory_type


def _content_signals(raw: str, normalized: str, known: s3_sinks.KnownSinks) -> list[SignalResult]:
    s3_raw = s3_sinks.s3_new_sinks(raw, known)
    s3_norm = s3_sinks.s3_new_sinks(normalized, known)
    labels = tuple(sorted(set(s3_raw.labels) | set(s3_norm.labels)))
    s3 = SignalResult("S3", bool(labels), max(s3_raw.risk, s3_norm.risk), labels)
    return [s3, s4_obfuscation(raw), s10_indirection(normalized)]


def _fired_labels(signals: Iterable[SignalResult]) -> set[str]:
    out: set[str] = set()
    for s in signals:
        if not s.fired:
            continue
        if s.id in ("S1", "S5", "S7"):
            out.add(s.id)
        else:
            out.update(s.labels or (s.id,))
    return out


def _known_sinks(
    allow_domains: tuple[str, ...], allow_emails: tuple[str, ...]
) -> s3_sinks.KnownSinks:
    sess = current_session()
    trusted = (
        [it.content for it in sess.items if it.trust >= TrustLevel.USER] if sess is not None else []
    )
    return s3_sinks.known_sinks(allow_domains, allow_emails, trusted)


# --- Engine ---------------------------------------------------------------------------------


class PolicyEngine:
    """Applies a compiled policy to writes. Obtain one with :func:`load_engine`."""

    def __init__(
        self,
        policy: CompiledPolicy,
        *,
        allow_domains: Iterable[str] = (),
        allow_emails: Iterable[str] = (),
        interception_guaranteed: bool = True,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.policy = policy
        self._allow_domains = tuple(allow_domains)
        self._allow_emails = tuple(allow_emails)
        self._intercepts = interception_guaranteed
        self._clock = clock
        self._shadow_expired_logged = False
        _LOG.info(
            "policy_loaded",
            extra={
                "policy_id": policy.id,
                "mode": policy.mode,
                "failure_mode": [f"{k}:{v}" for k, v in policy.failure_modes.as_dict().items()],
            },
        )
        if policy.fallback:
            _LOG.warning("policy_fallback_active", extra={"failure_mode": policy.fallback})
        if not interception_guaranteed:
            diagnostics.record("adapter_probe_failure")
            _LOG.warning("adapter_probe_failure", extra={"failure_mode": "adapter_probe_failure"})

    def _mode(self) -> str:
        p = self.policy
        if p.mode != "shadow":
            return "enforce"
        if p.shadow_expires_at is not None and self._clock() < p.shadow_expires_at:
            return "shadow"
        if not self._shadow_expired_logged:
            self._shadow_expired_logged = True
            diagnostics.record("shadow_expired")
            _LOG.warning("shadow_expired", extra={"mode": "enforce"})
        return "enforce"

    def evaluate(
        self,
        request: WriteRequest,
        *,
        filter_verdicts: Mapping[str, FilterVerdict] | None = None,
    ) -> WriteResult:
        t0 = time.perf_counter_ns()
        p = self.policy
        mode = self._mode()
        failures: list[str] = [p.fallback] if p.fallback else []
        alerts: list[str] = []
        trust = current_write_trust()
        tainted = is_tainted(trust)
        claimed = request.claimed_type

        def finish(
            action: Outcome,
            rule_ids: Iterable[str],
            signals: Iterable[SignalResult],
            fired: Iterable[str],
            memory_type: MemoryType,
            classified: MemoryType | None,
            removed: int,
            value: Any,
            args: Any,
            *,
            enforced: bool = False,
        ) -> WriteResult:
            rule_ids = tuple(rule_ids)
            outcome = action
            if mode == "shadow" and not enforced and not _ENFORCED_IN_SHADOW & set(rule_ids):
                outcome = _SHADOW[action]
                action = Outcome.ALLOW_AS_DATA if tainted else Outcome.ALLOW
            if action is Outcome.ALLOW:
                eff: EffectiveType | None = EffectiveType(memory_type.value)
            elif action is Outcome.ALLOW_AS_DATA:
                eff = EffectiveType.DATA
            else:
                eff = None
            d = Decision(
                outcome=outcome,
                action=action,
                effective_type=eff,
                memory_type=memory_type,
                classified_type=classified,
                claimed_type=claimed,
                write_trust=trust,
                rule_ids=rule_ids,
                signals=tuple(signals),
                fired_signals=tuple(sorted(set(fired))),
                failure_modes=tuple(dict.fromkeys(failures)),
                alerts=tuple(dict.fromkeys(alerts)),
                policy_id=p.id,
                policy_digest=p.digest,
                mode=mode,
                latency_us=(time.perf_counter_ns() - t0) // 1000,
                forgery_removed=removed,
            )
            _LOG.info(
                "policy_decision",
                extra={
                    "outcome": d.outcome.value,
                    "decision": d.action.value,
                    "rule_ids": list(d.rule_ids),
                    "signal_ids": list(d.fired_signals),
                    "failure_mode": list(d.failure_modes),
                    "mode": d.mode,
                    "trust_level": trust.label,
                    "memory_type": memory_type.value,
                    "effective_type": eff.value if eff else None,
                    "policy_id": p.id,
                    "latency_us": d.latency_us,
                    "count": removed,
                },
            )
            return WriteResult(d, value, args)

        # 1. I9: strip forged provenance.
        try:
            v = strip_value(request.value)
            a = strip_tool_args(request.tool_args)
        except ForgeryError:
            fallback_type = riskier_type(MemoryType.STANDING_INSTRUCTION, claimed)
            return finish(Outcome.DENY, ["malformed_value"], [], [], fallback_type, None, 0,
                          None, None, enforced=True)  # fmt: skip
        removed = v.removed + a.removed

        # 2. Adapter capability probe (§1.3).
        if not self._intercepts:
            failures.append("adapter_probe_failure")
            alerts.append("adapter_probe_failure")
            if p.failure_modes.adapter_probe_failure == "refuse_writes":
                return finish(Outcome.DENY, ["adapter_probe_failure"], [], [],
                              riskier_type(MemoryType.FACT, claimed), None, removed,
                              v.value, a.value, enforced=True)  # fmt: skip

        # 3. Structural signals (no content).
        facts = WriteFacts(
            content="",
            write_trust=trust,
            op=request.op,
            target_scope=request.target_scope,
            principal_scope=request.principal_scope,
            grants=request.grants,
            target_protected=request.target_protected,
            target_type=request.target_type,
        )
        signals: list[SignalResult] = [
            s1_taint(facts),
            s5_scope(facts),
            s7_protected_mutation(facts),
        ]

        def inputs(memory_type: MemoryType, fired: set[str]) -> DecisionInputs:
            return DecisionInputs(
                trust=trust,
                memory_type=memory_type,
                op=request.op,
                scope=request.target_scope.kind,
                grants=request.grants,
                protected=request.target_protected,
                fired=frozenset(fired),
            )

        classified: MemoryType | None = None
        try:
            raw = _text_of(v.value)
            if oversized(raw, p.max_write_bytes):
                signals.append(SignalResult("S0.oversize", fired=True, risk=1.0))
                memory_type = riskier_type(MemoryType.STANDING_INSTRUCTION, claimed)  # unscanned
                fired = _fired_labels(signals)
                action, rules = decide(p, inputs(memory_type, fired))
                return finish(action, rules, signals, fired, memory_type, None, removed,
                              v.value, a.value)  # fmt: skip
            scanned = _scan_text(v.value)
            normalized = normalize(scanned)
            classified = _classify(normalized)
        except Exception:  # noqa: BLE001 - any engine error must map to a failure mode
            return self._on_error(finish, signals, claimed, None, tainted, failures, alerts,
                                  removed, v.value, a.value, inputs)  # fmt: skip
        memory_type = riskier_type(classified, claimed)

        # 4. Content signals and filter verdicts (S6).
        try:
            signals.extend(_content_signals(scanned, normalized, self._known_sinks()))
            fired = _fired_labels(signals)
            for verdict in (filter_verdicts or {}).values():
                if verdict is FilterVerdict.FLAGGED:
                    fired.add("S6.flagged")
                elif verdict is FilterVerdict.UNKNOWN:
                    failures.append("filter_failure")
                    if tainted or p.failure_modes.filter_failure == "unknown_risk_always":
                        fired.add("S6.unknown")
            action, rules = decide(p, inputs(memory_type, fired))
        except Exception:  # noqa: BLE001
            return self._on_error(finish, signals, claimed, classified, tainted, failures, alerts,
                                  removed, v.value, a.value, inputs)  # fmt: skip
        return finish(action, rules, signals, fired, memory_type, classified, removed,
                      v.value, a.value)  # fmt: skip

    def _known_sinks(self) -> s3_sinks.KnownSinks:
        return _known_sinks(self._allow_domains, self._allow_emails)

    def _on_error(
        self,
        finish: Callable[..., WriteResult],
        signals: list[SignalResult],
        claimed: MemoryType | None,
        classified: MemoryType | None,
        tainted: bool,
        failures: list[str],
        alerts: list[str],
        removed: int,
        value: Any,
        args: Any,
        inputs: Callable[[MemoryType, set[str]], DecisionInputs],
    ) -> WriteResult:
        """§1.3 rows for an engine error. Structural invariants (I4, I5) still apply."""
        diagnostics.record("policy_engine_error")
        _LOG.error("policy_engine_error", extra={"failure_mode": "engine_error"})
        fm = self.policy.failure_modes
        structural = {s.id for s in signals if s.fired and s.id in ("S1", "S5", "S7")}
        if classified is None:
            memory_type = riskier_type(MemoryType.STANDING_INSTRUCTION, claimed)
        else:
            memory_type = riskier_type(classified, claimed)
        base, rules = decide(self.policy, inputs(memory_type, structural))
        if memory_type in _RISKY_TYPES:
            failures.append("instruction_write_on_engine_error")
            floor = Outcome.QUARANTINE
        elif tainted:
            failures.append("tainted_write")
            floor = Outcome.DENY if fm.tainted_write == "refuse" else Outcome.QUARANTINE
        else:
            failures.append("trusted_fact_write_on_dependency_outage")
            if fm.trusted_fact_write_on_dependency_outage == "closed":
                floor = Outcome.QUARANTINE
            else:
                floor = Outcome.ALLOW
                alerts.append("dependency_outage")
                diagnostics.record("fail_open_alert")
        action = max(base, floor, key=strictness)
        enforced = floor is not Outcome.ALLOW
        return finish(action, (*rules, "engine_error"), signals, structural, memory_type,
                      classified, removed, value, args, enforced=enforced)  # fmt: skip


def route_quarantine(
    policy: CompiledPolicy, *, store_available: bool, buffer_has_room: bool
) -> tuple[str, str | None]:
    """Where a quarantined write goes (§1.3): the store, the encrypted pending buffer, or refused.

    Never dropped. The buffer itself ships with the quarantine store (M1a-14).
    """
    if store_available:
        return "quarantine_store", None
    if policy.failure_modes.quarantine_store_down == "refuse":
        return "refuse", "quarantine_store_down"
    if buffer_has_room:
        return "pending_buffer", "quarantine_store_down"
    return "refuse", "pending_buffer_full"
