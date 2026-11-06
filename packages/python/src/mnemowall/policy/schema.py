"""Policy validation and compilation (§3.5 "Policy format", D10).

A policy document is plain data (dicts, lists, strings, ints, bools). It is checked against a
strict schema written in code and compiled into an immutable rule table. Nothing in a document is
ever evaluated: no expressions, no code, no dynamic lookups. Errors carry field locations and a
reason code only, never input values (§3.14). Unknown keys are reported at their parent's
location, so an attacker-chosen key name never reaches an error message or a log.

Rules can only *tighten*: ``then`` is ``quarantine`` or ``deny``, and every condition is monotone
(more signals, lower trust or fewer grants can only make a rule match more often). Built-in
invariants I1-I6 and I9 live in the engine and cannot be switched off by policy.

Local overrides (:func:`apply_local_overrides`) may only be stricter. A looser override is
ignored, logged and counted (``loosening_ignored``). The one logged loosening allowed locally is
shadow mode, capped at 30 days.
"""

from __future__ import annotations

import calendar
import dataclasses
import hashlib
import json
import re
import time
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Final

from mnemowall import _log
from mnemowall.core import diagnostics
from mnemowall.core.limits import MAX_WRITE_BYTES
from mnemowall.core.model import MemoryType, Outcome
from mnemowall.core.trust import TrustLevel
from mnemowall.signals.write import Op, ScopeKind

_LOG: Final = _log.get_logger("policy")

API_VERSION: Final = "mnemowall/policy/v1"
SHADOW_MAX_S: Final = 30 * 86_400
MAX_RULES: Final = 256
MAX_LIST: Final = 64
MAX_STR: Final = 256

_RULE_ID: Final = re.compile(r"[a-z][a-z0-9-]{0,63}")
_TTL: Final = re.compile(r"([0-9]{1,4})([hd])")
_ISO: Final = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")

KNOWN_SIGNALS: Final = frozenset(
    {
        "S0.oversize",
        "S1",
        "S3", "S3.new_domain", "S3.ip_literal", "S3.new_email", "S3.md_image_query", "S3.iban",
        "S4", "S4.tag_chars", "S4.bidi", "S4.invisible", "S4.mixed_script", "S4.punycode",
        "S4.base64_run", "S4.hex_run",
        "S5",
        "S6", "S6.flagged", "S6.unknown",
        "S7",
        "S10", "S10.indirection", "S10.destructive", "S10.destructive_shell",
    }
)  # fmt: skip
GRANTS: Final = frozenset({"memory:write:shared", "memory:write:org", "memory:write:other_user"})
_TRUST_BY_LABEL: Final = MappingProxyType({t.label: t for t in TrustLevel})
_READ_ORDER: Final = frozenset({"trust_desc", "recency_desc", "relevance_desc"})
_WRAP_STYLES: Final = frozenset({"spotlight"})
_THEN: Final = MappingProxyType({"quarantine": Outcome.QUARANTINE, "deny": Outcome.DENY})


class PolicyError(ValueError):
    """Invalid policy or override. ``locations`` holds ``"<path>: <code>"`` strings only."""

    def __init__(self, locations: list[str]) -> None:
        self.locations: tuple[str, ...] = tuple(dict.fromkeys(locations))
        shown = "; ".join(self.locations[:20])
        super().__init__(f"invalid policy ({len(self.locations)} problem(s)): {shown}")


# --- Failure modes (§1.3) -------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class FailureModeSpec:
    values: tuple[str, ...]  # loosest -> strictest
    default: str

    def rank(self, value: str) -> int:
        return self.values.index(value)


FAILURE_MODES: Final[Mapping[str, FailureModeSpec]] = MappingProxyType(
    {
        "tainted_write": FailureModeSpec(("quarantine", "refuse"), "quarantine"),
        "quarantine_store_down": FailureModeSpec(
            ("encrypted_pending_buffer", "refuse"), "encrypted_pending_buffer"
        ),
        "pending_buffer_full": FailureModeSpec(("refuse",), "refuse"),
        "instruction_write_on_engine_error": FailureModeSpec(("fail_closed",), "fail_closed"),
        "trusted_fact_write_on_dependency_outage": FailureModeSpec(
            ("open_with_alert", "closed"), "open_with_alert"
        ),
        "read_failure": FailureModeSpec(
            ("open_wrapped_unverified", "closed"), "open_wrapped_unverified"
        ),
        "filter_failure": FailureModeSpec(
            ("unknown_risk_if_tainted", "unknown_risk_always"), "unknown_risk_if_tainted"
        ),
        "policy_bundle_invalid": FailureModeSpec(("strict_default",), "strict_default"),
        "adapter_probe_failure": FailureModeSpec(("warn_only", "refuse_writes"), "refuse_writes"),
        "effect_probe_failure": FailureModeSpec(("hold_for_review",), "hold_for_review"),
        "control_plane_auth_error": FailureModeSpec(("deny",), "deny"),
        "audit_write_failure": FailureModeSpec(("fail_state_change",), "fail_state_change"),
        "kms_unavailable_content_mode": FailureModeSpec(("fail_closed",), "fail_closed"),
    }
)


@dataclasses.dataclass(frozen=True)
class FailureModes:
    tainted_write: str
    quarantine_store_down: str
    pending_buffer_full: str
    instruction_write_on_engine_error: str
    trusted_fact_write_on_dependency_outage: str
    read_failure: str
    filter_failure: str
    policy_bundle_invalid: str
    adapter_probe_failure: str
    effect_probe_failure: str
    control_plane_auth_error: str
    audit_write_failure: str
    kms_unavailable_content_mode: str

    def as_dict(self) -> dict[str, str]:
        return dataclasses.asdict(self)


# --- Compiled table -------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class When:
    tainted: bool | None = None
    signals_any: tuple[str, ...] | None = None
    types: tuple[MemoryType, ...] | None = None
    ops: tuple[Op, ...] | None = None
    scope: tuple[ScopeKind, ...] | None = None
    principal_lacks_grant: str | None = None
    trust_below: TrustLevel | None = None
    protected: bool | None = None


@dataclasses.dataclass(frozen=True)
class Rule:
    id: str
    when: When
    then: Outcome


@dataclasses.dataclass(frozen=True)
class ReadPolicy:
    order_by: tuple[str, ...]
    wrap_below_trust: str
    wrap_style: str


@dataclasses.dataclass(frozen=True)
class CompiledPolicy:
    id: str
    digest: str
    mode: str
    shadow_expires_at: float | None
    quarantine_ttl_s: int
    on_expiry: str
    max_write_bytes: int
    failure_modes: FailureModes
    rules: tuple[Rule, ...]
    read: ReadPolicy
    loosenings: tuple[str, ...] = ()
    fallback: str | None = None


def _canonical(p: CompiledPolicy) -> str:
    body = {
        "id": p.id,
        "mode": p.mode,
        "shadow_expires_at": p.shadow_expires_at,
        "quarantine_ttl_s": p.quarantine_ttl_s,
        "on_expiry": p.on_expiry,
        "max_write_bytes": p.max_write_bytes,
        "failure_modes": p.failure_modes.as_dict(),
        "rules": [
            {
                "id": r.id,
                "then": r.then.value,
                "when": {
                    k: (v.label if isinstance(v, TrustLevel) else v)
                    for k, v in dataclasses.asdict(r.when).items()
                    if v is not None
                },
            }
            for r in p.rules
        ],
        "read": dataclasses.asdict(p.read),
        "loosenings": list(p.loosenings),
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)


def _with_digest(p: CompiledPolicy) -> CompiledPolicy:
    digest = hashlib.sha256(_canonical(dataclasses.replace(p, digest="")).encode()).hexdigest()
    return dataclasses.replace(p, digest=digest)


# --- Validation -----------------------------------------------------------------------------


class _Checker:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def err(self, path: str, code: str) -> None:
        self.errors.append(f"{path}: {code}")

    @staticmethod
    def join(path: str, key: str) -> str:
        return key if path == "$" else f"{path}.{key}"

    def obj(self, data: Any, path: str, allowed: Mapping[str, bool]) -> dict[str, Any] | None:
        """Check ``data`` is a mapping with string keys from ``allowed`` (key -> required)."""
        if not isinstance(data, Mapping):
            self.err(path, "wrong_type")
            return None
        for key in data:
            if not isinstance(key, str) or key not in allowed:
                self.err(path, "unknown_key")
        for key, required in allowed.items():
            if required and key not in data:
                self.err(self.join(path, key), "required")
        return {k: v for k, v in data.items() if isinstance(k, str) and k in allowed}

    def string(self, v: Any, path: str) -> str | None:
        if not isinstance(v, str):
            self.err(path, "wrong_type")
            return None
        if len(v) > MAX_STR:
            self.err(path, "too_long")
            return None
        return v

    def enum(self, v: Any, path: str, allowed: frozenset[str] | Mapping[str, Any]) -> str | None:
        s = self.string(v, path)
        if s is None:
            return None
        if s not in allowed:
            self.err(path, "invalid_value")
            return None
        return s

    def true_flag(self, v: Any, path: str) -> bool | None:
        if type(v) is not bool:
            self.err(path, "wrong_type")
            return None
        if v is not True:
            self.err(path, "invalid_value")  # only `true` is allowed: rules can only tighten
            return None
        return True

    def integer(self, v: Any, path: str, lo: int, hi: int) -> int | None:
        if type(v) is not int:
            self.err(path, "wrong_type")
            return None
        if not lo <= v <= hi:
            self.err(path, "out_of_range")
            return None
        return v

    def enum_list(self, v: Any, path: str, allowed: frozenset[str]) -> tuple[str, ...] | None:
        if not isinstance(v, list | tuple):
            self.err(path, "wrong_type")
            return None
        if not v:
            self.err(path, "empty")
            return None
        if len(v) > MAX_LIST:
            self.err(path, "too_long")
            return None
        out = [self.enum(item, f"{path}[{i}]", allowed) for i, item in enumerate(v)]
        if any(o is None for o in out):
            return None
        return tuple(dict.fromkeys(o for o in out if o is not None))

    def iso_time(self, v: Any, path: str) -> float | None:
        s = self.string(v, path)
        if s is None:
            return None
        m = _ISO.fullmatch(s)
        if m is None:
            self.err(path, "invalid_value")
            return None
        try:
            parts = time.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            self.err(path, "invalid_value")
            return None
        return float(calendar.timegm(parts))

    def ttl(self, v: Any, path: str) -> int | None:
        s = self.string(v, path)
        if s is None:
            return None
        m = _TTL.fullmatch(s)
        if m is None:
            self.err(path, "invalid_value")
            return None
        n, unit = int(m.group(1)), m.group(2)
        seconds = n * (3600 if unit == "h" else 86_400)
        if not 3600 <= seconds <= 90 * 86_400:
            self.err(path, "out_of_range")
            return None
        return seconds

    def failure_modes(self, data: Any, path: str) -> dict[str, str]:
        out = {k: spec.default for k, spec in FAILURE_MODES.items()}
        obj = self.obj(data, path, dict.fromkeys(FAILURE_MODES, False))
        if obj is None:
            return out
        for key, value in obj.items():
            v = self.enum(value, self.join(path, key), frozenset(FAILURE_MODES[key].values))
            if v is not None:
                out[key] = v
        return out

    def rule(self, data: Any, path: str) -> Rule | None:
        obj = self.obj(data, path, {"id": True, "when": True, "then": True})
        if obj is None:
            return None
        rule_id = self.string(obj.get("id"), f"{path}.id") if "id" in obj else None
        if rule_id is not None and not _RULE_ID.fullmatch(rule_id):
            self.err(f"{path}.id", "invalid_value")
            rule_id = None
        then = self.enum(obj["then"], f"{path}.then", _THEN) if "then" in obj else None
        when = self.when(obj["when"], f"{path}.when") if "when" in obj else None
        if rule_id is None or then is None or when is None:
            return None
        return Rule(rule_id, when, _THEN[then])

    def when(self, data: Any, path: str) -> When | None:
        keys = (
            "tainted", "signals_any", "types", "ops", "scope",
            "principal_lacks_grant", "trust_below", "protected",
        )  # fmt: skip
        obj = self.obj(data, path, dict.fromkeys(keys, False))
        if obj is None:
            return None
        if not obj:
            self.err(path, "empty")
            return None
        before = len(self.errors)
        p = self.join
        w = When(
            tainted=self.true_flag(obj["tainted"], p(path, "tainted"))
            if "tainted" in obj
            else None,
            signals_any=(
                self.enum_list(obj["signals_any"], p(path, "signals_any"), KNOWN_SIGNALS)
                if "signals_any" in obj
                else None
            ),
            types=_as(
                MemoryType, self.enum_list(obj["types"], p(path, "types"), _values(MemoryType))
            )
            if "types" in obj
            else None,
            ops=_as(Op, self.enum_list(obj["ops"], p(path, "ops"), _values(Op)))
            if "ops" in obj
            else None,
            scope=_as(ScopeKind, self.enum_list(obj["scope"], p(path, "scope"), _values(ScopeKind)))
            if "scope" in obj
            else None,
            principal_lacks_grant=(
                self.enum(obj["principal_lacks_grant"], p(path, "principal_lacks_grant"), GRANTS)
                if "principal_lacks_grant" in obj
                else None
            ),
            trust_below=(
                _TRUST_BY_LABEL.get(
                    self.enum(obj["trust_below"], p(path, "trust_below"), _TRUST_BY_LABEL) or ""
                )
                if "trust_below" in obj
                else None
            ),
            protected=self.true_flag(obj["protected"], p(path, "protected"))
            if "protected" in obj
            else None,
        )
        return w if len(self.errors) == before else None

    def rules(self, data: Any, path: str, taken: set[str]) -> tuple[Rule, ...]:
        if not isinstance(data, list | tuple):
            self.err(path, "wrong_type")
            return ()
        if len(data) > MAX_RULES:
            self.err(path, "too_long")
            return ()
        out = []
        for i, item in enumerate(data):
            r = self.rule(item, f"{path}[{i}]")
            if r is None:
                continue
            if r.id in taken:
                self.err(f"{path}[{i}].id", "duplicate")
                continue
            taken.add(r.id)
            out.append(r)
        return tuple(out)


def _values(enum_cls: Any) -> frozenset[str]:
    return frozenset(m.value for m in enum_cls)


def _as(enum_cls: Any, values: tuple[str, ...] | None) -> Any:
    return None if values is None else tuple(enum_cls(v) for v in values)


# --- Public API -----------------------------------------------------------------------------


def compile_policy(doc: Any) -> CompiledPolicy:
    """Validate and compile a policy document. Raises :class:`PolicyError` and nothing else."""
    c = _Checker()
    top = c.obj(
        doc,
        "$",
        {
            "apiVersion": True,
            "id": False,
            "defaults": True,
            "failure_modes": False,
            "elevations": False,
            "rules": True,
            "read": True,
        },
    )
    if top is None:
        raise PolicyError(c.errors)
    if (
        "apiVersion" in top
        and c.enum(top["apiVersion"], "apiVersion", frozenset({API_VERSION})) is None
    ):
        pass
    policy_id = "unnamed"
    if "id" in top:
        pid = c.string(top["id"], "id")
        if pid is not None and not _RULE_ID.fullmatch(pid):
            c.err("id", "invalid_value")
        elif pid is not None:
            policy_id = pid
    if "elevations" in top:
        if not isinstance(top["elevations"], list | tuple):
            c.err("elevations", "wrong_type")
        elif top["elevations"]:
            c.err("elevations", "not_supported")  # operator elevations need signed bundles (M1b)

    mode, expires, ttl, on_expiry, max_bytes = "enforce", None, 7 * 86_400, "deny", MAX_WRITE_BYTES
    d = c.obj(
        top.get("defaults", {}),
        "defaults",
        {"mode": False, "shadow_expires_at": False, "quarantine_ttl": False, "on_expiry": False,
         "max_write_bytes": False},
    )  # fmt: skip
    if d is not None:
        if "mode" in d:
            mode = c.enum(d["mode"], "defaults.mode", frozenset({"enforce", "shadow"})) or mode
        if "shadow_expires_at" in d:
            expires = c.iso_time(d["shadow_expires_at"], "defaults.shadow_expires_at")
        elif mode == "shadow":
            c.err("defaults.shadow_expires_at", "required")
        if "quarantine_ttl" in d:
            ttl = c.ttl(d["quarantine_ttl"], "defaults.quarantine_ttl") or ttl
        if "on_expiry" in d:
            on_expiry = (
                c.enum(d["on_expiry"], "defaults.on_expiry", frozenset({"deny"})) or on_expiry
            )
        if "max_write_bytes" in d:
            mb = c.integer(d["max_write_bytes"], "defaults.max_write_bytes", 1, MAX_WRITE_BYTES)
            max_bytes = mb if mb is not None else max_bytes
    fm = c.failure_modes(top.get("failure_modes", {}), "failure_modes")
    rules = c.rules(top["rules"], "rules", set()) if "rules" in top else ()

    read = None
    r = c.obj(top["read"], "read", {"order_by": True, "wrap": True}) if "read" in top else None
    if r is not None:
        order = (
            c.enum_list(r["order_by"], "read.order_by", _READ_ORDER) if "order_by" in r else None
        )
        w = (
            c.obj(r["wrap"], "read.wrap", {"below_trust": True, "style": True})
            if "wrap" in r
            else None
        )
        below = style = None
        if w is not None:
            below = (
                c.enum(w["below_trust"], "read.wrap.below_trust", _TRUST_BY_LABEL)
                if "below_trust" in w
                else None
            )
            style = c.enum(w["style"], "read.wrap.style", _WRAP_STYLES) if "style" in w else None
        if order is not None and below is not None and style is not None:
            read = ReadPolicy(order, below, style)

    if c.errors or read is None:
        raise PolicyError(c.errors or ["read: invalid_value"])
    compiled = CompiledPolicy(
        id=policy_id,
        digest="",
        mode=mode,
        shadow_expires_at=expires if mode == "shadow" else None,
        quarantine_ttl_s=ttl,
        on_expiry=on_expiry,
        max_write_bytes=max_bytes,
        failure_modes=FailureModes(**fm),
        rules=rules,
        read=read,
        loosenings=("shadow_mode",) if mode == "shadow" else (),
    )
    return _with_digest(compiled)


def _ignored(field: str) -> None:
    diagnostics.record("loosening_ignored")
    _LOG.warning("loosening_ignored", extra={"failure_mode": field})


def apply_local_overrides(
    policy: CompiledPolicy, overrides: Any, *, now: float | None = None
) -> CompiledPolicy:
    """Apply local overrides that are stricter; ignore, log and count looser ones (§1.3).

    ``mode: shadow`` is the one permitted loosening: logged, counted, flagged by ``doctor``, and
    capped at 30 days from ``now``.
    """
    c = _Checker()
    ov = c.obj(
        overrides,
        "$",
        {"failure_modes": False, "max_write_bytes": False, "rules": False, "mode": False,
         "shadow_expires_at": False},
    )  # fmt: skip
    if ov is None:
        raise PolicyError(c.errors)
    requested_fm: dict[str, str] = {}
    if "failure_modes" in ov:
        fm_obj = c.obj(ov["failure_modes"], "failure_modes", dict.fromkeys(FAILURE_MODES, False))
        for key, value in (fm_obj or {}).items():
            v = c.enum(value, f"failure_modes.{key}", frozenset(FAILURE_MODES[key].values))
            if v is not None:
                requested_fm[key] = v
    max_bytes = (
        c.integer(ov["max_write_bytes"], "max_write_bytes", 1, 2**62)
        if "max_write_bytes" in ov
        else None
    )
    taken = {r.id for r in policy.rules}
    extra = c.rules(ov["rules"], "rules", taken) if "rules" in ov else ()
    mode = c.enum(ov["mode"], "mode", frozenset({"enforce", "shadow"})) if "mode" in ov else None
    expires = (
        c.iso_time(ov["shadow_expires_at"], "shadow_expires_at")
        if "shadow_expires_at" in ov
        else None
    )
    if c.errors:
        raise PolicyError(c.errors)

    fm = policy.failure_modes.as_dict()
    for key, value in requested_fm.items():
        spec = FAILURE_MODES[key]
        if spec.rank(value) >= spec.rank(fm[key]):
            fm[key] = value
        else:
            _ignored(key)
    new_max = policy.max_write_bytes
    if max_bytes is not None:
        if max_bytes <= policy.max_write_bytes:
            new_max = max_bytes
        else:
            _ignored("max_write_bytes")

    new_mode, new_expiry, loosenings = (
        policy.mode,
        policy.shadow_expires_at,
        list(policy.loosenings),
    )
    t = time.time() if now is None else now
    if mode == "enforce":
        new_mode, new_expiry = "enforce", None
        loosenings = [x for x in loosenings if x != "shadow_mode"]
    elif mode == "shadow":
        cap = t + SHADOW_MAX_S
        want = cap if expires is None else expires
        if want > cap:
            _ignored("shadow_expires_at")
            want = cap
        if policy.mode == "shadow" and policy.shadow_expires_at is not None:
            want = min(want, policy.shadow_expires_at)
        new_mode, new_expiry = "shadow", want
        if "shadow_mode" not in loosenings:
            loosenings.append("shadow_mode")
        diagnostics.record("shadow_mode_enabled")
        _LOG.warning("loosening_applied", extra={"mode": "shadow"})
    elif expires is not None and policy.mode == "shadow" and policy.shadow_expires_at is not None:
        new_expiry = min(expires, policy.shadow_expires_at)

    return _with_digest(
        dataclasses.replace(
            policy,
            failure_modes=FailureModes(**fm),
            max_write_bytes=new_max,
            rules=policy.rules + extra,
            mode=new_mode,
            shadow_expires_at=new_expiry,
            loosenings=tuple(loosenings),
        )
    )


def clamp_shadow(policy: CompiledPolicy, now: float) -> CompiledPolicy:
    """Cap a document-level shadow expiry at 30 days from ``now`` (load time)."""
    if policy.mode != "shadow" or policy.shadow_expires_at is None:
        return policy
    cap = now + SHADOW_MAX_S
    if policy.shadow_expires_at <= cap:
        return policy
    _ignored("shadow_expires_at")
    return _with_digest(dataclasses.replace(policy, shadow_expires_at=cap))
