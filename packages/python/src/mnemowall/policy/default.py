"""The built-in default policy (M1a, D10): data in code, shipped in the attested wheel.

It is also the strict fallback used whenever a supplied policy is missing or invalid (§1.3).
Invariants I1-I6 and I9 are enforced by the engine whatever this says; these rules only add to
them. Failure-mode values are the §1.3 table; changing one means changing the spec first.
"""

from __future__ import annotations

import copy
from typing import Any, Final

BUILTIN_POLICY: Final[dict[str, Any]] = {
    "apiVersion": "mnemowall/policy/v1",
    "id": "builtin-default",
    "defaults": {
        "mode": "enforce",
        "quarantine_ttl": "7d",
        "on_expiry": "deny",
        "max_write_bytes": 32 * 1024,
    },
    "failure_modes": {
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
    },
    "elevations": [],
    "rules": [
        {
            "id": "no-external-payment-sinks",
            "when": {"tainted": True, "signals_any": ["S3.iban", "S3.new_domain"]},
            "then": "quarantine",
        },
        {
            "id": "shared-scope-requires-grant",
            "when": {"scope": ["shared"], "principal_lacks_grant": "memory:write:shared"},
            "then": "deny",
        },
        {
            "id": "org-scope-requires-grant",
            "when": {"scope": ["org"], "principal_lacks_grant": "memory:write:org"},
            "then": "deny",
        },
        {
            "id": "hidden-characters-in-instructions",
            "when": {
                "types": ["standing_instruction", "procedure"],
                "signals_any": ["S4.tag_chars", "S4.bidi", "S4.invisible"],
            },
            "then": "quarantine",
        },
        {
            "id": "no-image-beacons-in-instructions",
            "when": {
                "types": ["standing_instruction", "procedure"],
                "signals_any": ["S3.md_image_query"],
            },
            "then": "quarantine",
        },
    ],
    "read": {
        "order_by": ["trust_desc", "recency_desc"],
        "wrap": {"below_trust": "verified_user", "style": "spotlight"},
    },
}


def builtin_policy_document() -> dict[str, Any]:
    """A fresh copy of the built-in policy document (callers cannot modify the shipped one)."""
    return copy.deepcopy(BUILTIN_POLICY)
