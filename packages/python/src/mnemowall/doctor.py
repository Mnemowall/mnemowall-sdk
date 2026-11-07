"""``doctor``: what is unsafe or degraded in this setup (§3.3, M1a-21).

Call :func:`run_checks` inside your application to include its in-process counters (writes or
observations without a session, unverified or stale reads, forgery attempts). The CLI runs the
persistent checks (keys, ledger, quarantine, policy) in a fresh process, where those counters
are empty. Findings carry a severity (``info``, ``warning``, ``error``), a code and a message,
never content.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from mnemowall.core import diagnostics
from mnemowall.keys import KeyProvider, KeyUnavailable
from mnemowall.ledger import Ledger, LedgerError
from mnemowall.policy import CompiledPolicy
from mnemowall.quarantine import Quarantine

_COUNTER_FINDINGS: Final = {
    "write_without_session": (
        "warning",
        "writes_without_session",
        "memory writes ran with no provenance session (trust: unknown)",
    ),
    "observe_without_session": (
        "warning",
        "observe_without_session",
        "tool output arrived with no session; it was not observed",
    ),
    "read_unverified": (
        "warning",
        "read_unverified",
        "reads returned unverified items (raw inserts, tampering or missing keys)",
    ),
    "read_stale": ("warning", "read_stale", "reads returned stale items (possible replay)"),
    "backend_error": (
        "warning",
        "backend_error",
        "the memory backend failed during a write; nothing from its error was passed on",
    ),
    "principal_mismatch": (
        "warning",
        "principal_mismatch",
        "a caller passed a user id that differs from the session principal (denied)",
    ),
    "policy_weakened": (
        "warning",
        "policy_weakened",
        "a signed local policy weaker than the built-in default is in effect",
    ),
    "policy_signature_invalid": (
        "error",
        "policy_signature_invalid",
        "a local policy file was refused (unsigned, edited or untrusted key); strict default used",
    ),
    "mem0_telemetry_enabled": (
        "warning",
        "mem0_telemetry_enabled",
        "Mem0 telemetry was on when a wrapper was built; set MEM0_TELEMETRY=False",
    ),
    "tenant_mismatch": (
        "warning",
        "tenant_mismatch",
        "operations were denied for a session from another tenant",
    ),
    "foreign_namespace_filtered": (
        "error",
        "foreign_namespace_filtered",
        "an inner store returned items outside the caller's namespace",
    ),
    "adapter_probe_failure": (
        "error",
        "adapter_probe_failure",
        "an adapter could not guarantee interception; writes refused",
    ),
    "forgery_attempt": ("info", "forgery_attempts", "forged provenance fields were stripped"),
    "loosening_ignored": ("info", "loosening_ignored", "looser local settings were ignored"),
    "read_log_failed": ("warning", "read_log_failed", "reads could not be logged to the ledger"),
}


@dataclass(frozen=True, slots=True)
class Finding:
    severity: str  # info | warning | error
    code: str
    message: str


def run_checks(
    *,
    provider: KeyProvider | None = None,
    ledger: Ledger | None = None,
    quarantine: Quarantine | None = None,
    policy: CompiledPolicy | None = None,
    stores: Iterable[Any] = (),
    counters: Mapping[str, int] | None = None,
) -> list[Finding]:
    out: list[Finding] = []
    add = out.append
    if provider is not None:
        try:
            keys = provider.load()
        except KeyUnavailable as exc:
            add(
                Finding(
                    "error",
                    "keys_unavailable",
                    f"keys unavailable ({exc.reason}); writes fail closed",
                )
            )
        else:
            add(
                Finding(
                    "info", "keys", f"{provider.name} provider, active key {keys.active_key_id}"
                )
            )
            if not provider.production_ready:
                add(Finding("warning", "ephemeral_keys", "ephemeral keys: not for production"))
        add(
            Finding(
                "info",
                "in_process_signing",
                "the signing key is in this process; an agent that can run code here can"
                " read it (ADR-0020 D14)",
            )
        )
    if policy is not None:
        if policy.fallback:
            add(
                Finding(
                    "error",
                    "policy_fallback",
                    f"the supplied policy was invalid; running the"
                    f" strict default ({policy.fallback})",
                )
            )
        if policy.mode == "shadow":
            add(
                Finding(
                    "warning",
                    "shadow_mode",
                    f"shadow mode: most decisions are only recorded"
                    f" (expires at {policy.shadow_expires_at})",
                )
            )
        for name in policy.loosenings:
            if name != "mode":
                add(Finding("warning", "loosening", f"a local setting loosens the policy: {name}"))
    if ledger is not None:
        try:
            report = ledger.verify()
        except LedgerError as exc:
            add(Finding("error", "ledger_unavailable", f"ledger can't be verified ({exc.reason})"))
        else:
            if report.ok:
                add(Finding("info", "ledger_ok", f"ledger verifies ({report.checked} entries)"))
            else:
                add(
                    Finding(
                        "error",
                        "ledger_tampered",
                        f"ledger verification FAILED at entry {report.failed_at}: {report.reason}",
                    )
                )
    if quarantine is not None:
        pending = quarantine.list()
        add(
            Finding(
                "info", "quarantine_pending", f"{len(pending)} quarantined item(s) await review"
            )
        )
        promotions = quarantine.pending_promotions()
        if promotions:
            add(
                Finding(
                    "warning",
                    "promotion_pending",
                    f"{len(promotions)} promotion(s) to instruction are pending",
                )
            )
        if not quarantine.locked and quarantine.buffered():
            add(
                Finding(
                    "warning",
                    "pending_buffer_not_empty",
                    f"{quarantine.buffered()} item(s) wait in the pending"
                    f" buffer (quarantine store was down)",
                )
            )
    for store in stores:
        probe_result = getattr(store, "probe_result", None)
        if probe_result is None:
            add(
                Finding(
                    "warning",
                    "unwrapped_store",
                    f"{type(store).__name__} is not wrapped by a Mnemowall adapter",
                )
            )
        elif not probe_result.ok:
            inner = getattr(store, "_inner", None)
            if inner is None:
                inner = getattr(getattr(store, "_core", None), "_inner", None)
            add(
                Finding(
                    "error",
                    "adapter_probe_failure",
                    f"{type(store).__name__} over {type(inner).__name__}: interception not"
                    f" guaranteed ({', '.join(probe_result.reasons)}); writes refused",
                )
            )
        if type(store).__module__ == "mnemowall.adapters.mem0" and _mem0_telemetry_on():
            add(
                Finding(
                    "warning",
                    "mem0_telemetry_enabled",
                    "Mem0 telemetry is on (memory ids go to PostHog); set MEM0_TELEMETRY=False"
                    " before importing mem0",
                )
            )
    counts = diagnostics.counters() if counters is None else dict(counters)
    for name, (severity, code, message) in _COUNTER_FINDINGS.items():
        n = counts.get(name, 0)
        if n:
            add(Finding(severity, code, f"{message} (x{n})"))
    return out


def _mem0_telemetry_on() -> bool:
    from mnemowall.adapters.mem0 import telemetry_enabled

    return telemetry_enabled()


def exit_code(findings: Iterable[Finding]) -> int:
    severities = {f.severity for f in findings}
    return 2 if "error" in severities else 1 if "warning" in severities else 0
