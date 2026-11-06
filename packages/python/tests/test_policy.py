"""M1a-10: policy compiler and the built-in default policy. UT-POL-*, FZ-POLICY."""

from __future__ import annotations

import ast
import copy
import dataclasses
import json
import logging
import pathlib
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

import mnemowall.policy
from mnemowall.core import diagnostics
from mnemowall.policy import (
    FAILURE_MODES,
    CompiledPolicy,
    PolicyError,
    apply_local_overrides,
    builtin_policy_document,
    compile_policy,
    load_policy,
)

CANARY = "CANARY-55e1c0"


@pytest.fixture(autouse=True)
def _reset() -> None:
    diagnostics.reset()


def doc() -> dict[str, Any]:
    return builtin_policy_document()


def errors_of(d: Any) -> tuple[str, ...]:
    with pytest.raises(PolicyError) as ei:
        compile_policy(d)
    return ei.value.locations


# --- UT-POL-001 -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda d: d.update({CANARY: 1}), "$: unknown_key"),
        (lambda d: d["defaults"].update({CANARY: 1}), "defaults: unknown_key"),
        (lambda d: d["defaults"].update(mode=CANARY), "defaults.mode: invalid_value"),
        (lambda d: d["defaults"].update(mode=1), "defaults.mode: wrong_type"),
        (
            lambda d: d["defaults"].update(quarantine_ttl=CANARY),
            "defaults.quarantine_ttl: invalid_value",
        ),
        (lambda d: d["defaults"].update(mode="shadow"), "defaults.shadow_expires_at: required"),
        (
            lambda d: d["defaults"].update(mode="shadow", shadow_expires_at=CANARY),
            "defaults.shadow_expires_at: invalid_value",
        ),
        (
            lambda d: d["defaults"].update(shadow_expires_at=True),
            "defaults.shadow_expires_at: wrong_type",
        ),
        (
            lambda d: d["rules"][0]["when"].update(tainted=False),
            "rules[0].when.tainted: invalid_value",
        ),
        (
            lambda d: d["rules"][0]["when"].update(protected=False),
            "rules[0].when.protected: invalid_value",
        ),
        (
            lambda d: d["defaults"].update(quarantine_ttl="0d"),
            "defaults.quarantine_ttl: out_of_range",
        ),
        (
            lambda d: d["rules"][0]["when"].update(tainted="yes"),
            "rules[0].when.tainted: wrong_type",
        ),
        (
            lambda d: d["rules"][0]["when"].update(signals_any=[CANARY]),
            "rules[0].when.signals_any[0]: invalid_value",
        ),
        (lambda d: d["rules"][0].update(then="allow"), "rules[0].then: invalid_value"),
        (lambda d: d["rules"][1].update(id=d["rules"][0]["id"]), "rules[1].id: duplicate"),
        (lambda d: d["rules"][0].update(id="Has Spaces"), "rules[0].id: invalid_value"),
        (lambda d: d["rules"][0].update(when={}), "rules[0].when: empty"),
        (lambda d: d.pop("rules"), "rules: required"),
        (lambda d: d.update(apiVersion="mnemowall/policy/v2"), "apiVersion: invalid_value"),
        (
            lambda d: d["failure_modes"].update(read_failure=CANARY),
            "failure_modes.read_failure: invalid_value",
        ),
        (
            lambda d: d["read"]["wrap"].update(below_trust="root"),
            "read.wrap.below_trust: invalid_value",
        ),
        (
            lambda d: d.update(elevations=[{"source_ref_pattern": "x://*", "trust": "user"}]),
            "elevations: not_supported",
        ),
        (lambda d: d["rules"].extend([d["rules"][0]] * 300), "rules: too_long"),
    ],
)
def test_ut_pol_001_rejects_with_locations_only(mutate: Any, expected: str) -> None:
    d = doc()
    mutate(d)
    locs = errors_of(d)
    assert expected in locs, locs
    with pytest.raises(PolicyError) as ei:
        compile_policy(d)
    assert CANARY not in str(ei.value)
    assert CANARY not in repr(ei.value)
    assert all(CANARY not in loc for loc in ei.value.locations)


def test_ut_pol_001b_non_mapping_and_non_string_keys() -> None:
    assert "$: wrong_type" in errors_of([1, 2])
    d = doc()
    d["defaults"][7] = "x"
    assert "defaults: unknown_key" in errors_of(d)


# --- UT-POL-002 / 003 -----------------------------------------------------------------------


def test_ut_pol_002_immutable_and_deterministic() -> None:
    a, b = compile_policy(doc()), compile_policy(doc())
    assert a == b
    assert a.digest == b.digest
    assert len(a.digest) == 64
    assert isinstance(a.rules, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        a.mode = "shadow"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        a.rules[0].then = "deny"  # type: ignore[misc, assignment]
    d = doc()
    d["rules"][0]["id"] = "renamed-rule"
    assert compile_policy(d).digest != a.digest


def test_ut_pol_002b_compiling_does_not_alias_input() -> None:
    d = doc()
    p = compile_policy(d)
    d["rules"][0]["when"]["signals_any"].append("S4.bidi")
    assert "S4.bidi" not in (p.rules[0].when.signals_any or ())


def test_ut_pol_003_builtin_default_ships_and_compiles() -> None:
    d = doc()
    for key in ("apiVersion", "rules", "read", "defaults", "failure_modes"):
        assert key in d
    p = load_policy()
    assert isinstance(p, CompiledPolicy)
    assert p.mode == "enforce"
    assert p.fallback is None
    assert p.id == "builtin-default"
    assert {r.id for r in p.rules} >= {"no-external-payment-sinks", "shared-scope-requires-grant"}
    assert p.read.wrap_below_trust == "verified_user"
    d["rules"][0]["id"] = "mutated"
    assert builtin_policy_document()["rules"][0]["id"] != "mutated"  # callers get a copy


# --- UT-POL-004 -----------------------------------------------------------------------------

# Copied by hand from §1.3 (docs/spec/01-principles.md). Changing a default means changing the
# spec first.
SECTION_1_3 = {
    "tainted_write": "quarantine",
    "quarantine_store_down": "encrypted_pending_buffer",
    "pending_buffer_full": "refuse",
    "instruction_write_on_engine_error": "fail_closed",
    "trusted_fact_write_on_dependency_outage": "open_with_alert",
    "read_failure": "open_wrapped_unverified",
    "filter_failure": "unknown_risk_if_tainted",
    "policy_bundle_invalid": "strict_default",
    "adapter_probe_failure": "refuse_writes",
    "effect_probe_failure": "hold_for_review",
    "control_plane_auth_error": "deny",
    "audit_write_failure": "fail_state_change",
    "kms_unavailable_content_mode": "fail_closed",
}


def test_ut_pol_004_failure_mode_defaults_match_section_1_3() -> None:
    assert doc()["failure_modes"] == SECTION_1_3
    assert load_policy().failure_modes.as_dict() == SECTION_1_3
    assert {k: v.default for k, v in FAILURE_MODES.items()} == SECTION_1_3


def test_ut_pol_004b_a_document_may_omit_failure_modes_and_gets_section_1_3() -> None:
    d = doc()
    del d["failure_modes"]
    assert compile_policy(d).failure_modes.as_dict() == SECTION_1_3


# --- UT-POL-005 -----------------------------------------------------------------------------


def test_ut_pol_005_stricter_override_applied(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="mnemowall")
    base = load_policy()
    p = apply_local_overrides(
        base,
        {
            "failure_modes": {"trusted_fact_write_on_dependency_outage": "closed"},
            "max_write_bytes": 4096,
            "rules": [
                {"id": "local-no-iban", "when": {"signals_any": ["S3.iban"]}, "then": "deny"}
            ],
        },
    )
    assert p.failure_modes.trusted_fact_write_on_dependency_outage == "closed"
    assert p.max_write_bytes == 4096
    assert p.rules[-1].id == "local-no-iban"
    assert p.digest != base.digest
    assert "loosening_ignored" not in diagnostics.counters()


def test_ut_pol_005_looser_override_ignored_logged_counted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="mnemowall")
    base = load_policy()
    p = apply_local_overrides(
        base,
        {
            "failure_modes": {"adapter_probe_failure": "warn_only", "read_failure": "closed"},
            "max_write_bytes": 10**9,
        },
    )
    assert p.failure_modes.adapter_probe_failure == "refuse_writes"
    assert p.failure_modes.read_failure == "closed"  # the stricter one in the same override sticks
    assert p.max_write_bytes == base.max_write_bytes
    assert diagnostics.counters()["loosening_ignored"] == 2
    events = [r for r in caplog.records if r.getMessage() == "loosening_ignored"]
    assert len(events) == 2


def test_ut_pol_005b_invalid_override_raises_with_locations() -> None:
    with pytest.raises(PolicyError) as ei:
        apply_local_overrides(load_policy(), {"failure_modes": {CANARY: "closed"}})
    assert "failure_modes: unknown_key" in ei.value.locations
    assert CANARY not in str(ei.value)


def test_ut_pol_005c_invalid_document_falls_back_to_strict_default(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="mnemowall")
    bad = doc()
    bad["rules"][0]["then"] = "allow"
    p = load_policy(bad)
    assert p.fallback == "policy_bundle_invalid"
    assert p.rules == load_policy().rules
    assert diagnostics.counters()["policy_fallback"] == 1
    assert any(r.getMessage() == "policy_fallback" for r in caplog.records)


# --- UT-POL-006 -----------------------------------------------------------------------------


def test_ut_pol_006_no_field_is_evaluated() -> None:
    for payload in ["__import__('os').system('true')", "${{ env.X }}", "{{7*7}}", "lambda: 1"]:
        d = doc()
        d["rules"][0]["id"] = payload
        assert "rules[0].id: invalid_value" in errors_of(d)
        d = doc()
        d["rules"][0]["when"]["signals_any"] = [payload]
        assert "rules[0].when.signals_any[0]: invalid_value" in errors_of(d)


def test_ut_pol_006b_policy_package_has_no_dynamic_code() -> None:
    pkg = pathlib.Path(mnemowall.policy.__file__).parent
    banned_names = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "getattr",
        "setattr",
        "globals",
        "locals",
    }
    for path in pkg.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in banned_names, f"{path.name}:{node.lineno}"
            if isinstance(node, ast.Import | ast.ImportFrom):
                names = {a.name for a in node.names} | {getattr(node, "module", None) or ""}
                assert not names & {"importlib", "pickle", "marshal", "yaml", "subprocess"}, (
                    path.name
                )


# --- FZ-POLICY ------------------------------------------------------------------------------

json_leaf = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**70), max_value=2**70),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=12),
    st.sampled_from(["quarantine", "deny", "S3.iban", "shared", "enforce", "shadow", "7d", "user"]),
)
json_any = st.recursive(
    json_leaf,
    lambda inner: st.one_of(
        st.lists(inner, max_size=4),
        st.dictionaries(
            st.one_of(
                st.text(max_size=8), st.sampled_from(["when", "then", "id", "rules", "mode"])
            ),
            inner,
            max_size=4,
        ),
    ),
    max_leaves=20,
)


def _paths(d: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    out = [prefix]
    if isinstance(d, dict):
        for k, v in d.items():
            out += _paths(v, (*prefix, k))
    elif isinstance(d, list):
        for i, v in enumerate(d):
            out += _paths(v, (*prefix, i))
    return out


@st.composite
def mutated_default(draw: st.DrawFn) -> Any:
    d = doc()
    for _ in range(draw(st.integers(1, 4))):
        paths = [p for p in _paths(d) if p]
        if not paths:
            break
        path = draw(st.sampled_from(paths))
        parent: Any = d
        for k in path[:-1]:
            parent = parent[k]
        if draw(st.booleans()) and isinstance(parent, dict):
            del parent[path[-1]]
        else:
            parent[path[-1]] = draw(json_any)
    return d


@given(st.one_of(json_any, mutated_default()))
def test_fz_policy_compiles_or_raises_policy_error(d: Any) -> None:
    snapshot = copy.deepcopy(d) if _deepcopyable(d) else None
    locations: tuple[str, ...] | None = None
    try:
        p = compile_policy(d)
    except PolicyError as e:
        locations = e.locations
    if locations is not None:
        assert locations
        assert all(isinstance(loc, str) and len(loc) <= 200 for loc in locations)
        return
    assert isinstance(p, CompiledPolicy)
    json.dumps(p.digest)
    if snapshot is not None:
        assert compile_policy(snapshot) == p


def _deepcopyable(d: Any) -> bool:
    try:
        copy.deepcopy(d)
    except RecursionError:
        return False
    return True
