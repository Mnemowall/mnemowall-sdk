"""Policy: compiler, built-in default, and the write-decision engine (§3.5, M1a-10/11)."""

from __future__ import annotations

import dataclasses
import functools
import time
from typing import Any

from mnemowall import _log
from mnemowall.core import diagnostics
from mnemowall.policy.default import BUILTIN_POLICY, builtin_policy_document
from mnemowall.policy.engine import (
    Decision,
    DecisionInputs,
    FilterVerdict,
    PolicyEngine,
    WriteRequest,
    WriteResult,
    decide,
    riskier_type,
    route_quarantine,
    strictness,
)
from mnemowall.policy.schema import (
    API_VERSION,
    FAILURE_MODES,
    CompiledPolicy,
    FailureModes,
    PolicyError,
    Rule,
    apply_local_overrides,
    clamp_shadow,
    compile_policy,
)

__all__ = [
    "API_VERSION",
    "BUILTIN_POLICY",
    "FAILURE_MODES",
    "CompiledPolicy",
    "Decision",
    "DecisionInputs",
    "FailureModes",
    "FilterVerdict",
    "PolicyEngine",
    "PolicyError",
    "Rule",
    "WriteRequest",
    "WriteResult",
    "apply_local_overrides",
    "builtin_policy_document",
    "compile_policy",
    "decide",
    "load_engine",
    "load_policy",
    "riskier_type",
    "route_quarantine",
    "strictness",
]

_LOG = _log.get_logger("policy")


@functools.cache
def _builtin() -> CompiledPolicy:
    return compile_policy(BUILTIN_POLICY)


def load_policy(
    document: Any = None, local_overrides: Any = None, *, now: float | None = None
) -> CompiledPolicy:
    """The active policy: ``document`` (or the built-in default), then stricter-only overrides.

    An invalid document fails closed to the built-in strict default, with an alert (§1.3).
    Invalid *overrides* raise :class:`PolicyError`: they are local configuration, fixed at startup.
    """
    t = time.time() if now is None else now
    if document is None:
        policy = _builtin()
    else:
        try:
            policy = clamp_shadow(compile_policy(document), t)
        except PolicyError:
            diagnostics.record("policy_fallback")
            _LOG.error("policy_fallback", extra={"failure_mode": "policy_bundle_invalid"})
            policy = _builtin()
            policy = dataclasses.replace(policy, fallback="policy_bundle_invalid")
    if local_overrides is not None:
        policy = apply_local_overrides(policy, local_overrides, now=t)
    return policy


def load_engine(policy: CompiledPolicy | None = None, **kwargs: Any) -> PolicyEngine:
    """An engine for ``policy`` (default: the built-in policy). See :class:`PolicyEngine`."""
    return PolicyEngine(policy if policy is not None else load_policy(), **kwargs)
