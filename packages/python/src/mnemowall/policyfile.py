"""Locally signed policy files (M1b-06; §3.5 "local YAML policies are accepted only if signed").

This module sits outside ``mnemowall.policy`` on purpose: that package is pure data and code with
no parsers, I/O or dynamic imports (UT-POL-006b). File reading, YAML (``safe_load`` only, checked
by UT-POLICY-SIGN-011) and signatures live here.

See ADR-0026 and the test spec decisions D48-D52.

* **A separate key (D50).** ``mnemowall policy keygen`` writes an Ed25519 seed to a private file
  (0600, in a private directory, never inside a git worktree). Only its *public* key is given to
  the running process (``trusted_keys``), so an agent that can run code in the SDK process can
  read the policy but can't sign a new one.
* **Detached signature over the exact file bytes (D49).** ``<file>.sig`` holds
  ``{key_id, signed_at, not_before, sha256}`` and an Ed25519 signature over
  ``mnemowall/policy/v1\\0 || JCS(those fields)``. Any byte change fails ``digest_mismatch``.
* **Fail closed (D51).** An unsigned, tampered, unknown-key, not-yet-valid, unparseable or invalid
  policy is never used: :func:`load_policy_file` returns the built-in strict default with
  ``fallback = "policy_signature_invalid"`` and an alert (§1.3 ``policy_bundle_invalid``).
* **Weakening waits 24 h (D52).** A policy that is weaker than the built-in default in any way
  :func:`weakenings` detects only takes effect 24 h after it was signed: ``policy sign`` sets
  ``not_before`` accordingly, and a weakening policy signed with a shorter delay is refused. This
  is the compensating control for "a second approver" until a second human exists.

YAML is parsed with ``yaml.safe_load`` only (extra ``mnemowall[yaml]``); JSON needs no extra.
Errors and logs carry reason codes only, never policy content.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from mnemowall import _log
from mnemowall.core import diagnostics
from mnemowall.core.files import PrivatePathError, private_dir
from mnemowall.core.jcs import JCSError, canonicalize
from mnemowall.core.trust import TrustLevel
from mnemowall.keys import key_id_for
from mnemowall.policy.engine import strictness
from mnemowall.policy.schema import (
    FAILURE_MODES,
    CompiledPolicy,
    PolicyError,
    apply_local_overrides,
    clamp_shadow,
    compile_policy,
)

DOMAIN: Final = b"mnemowall/policy/v1\x00"
SIG_API: Final = "mnemowall/policy-signature/v1"
KEY_API: Final = "mnemowall/policy-key/v1"
PUB_PREFIX: Final = "ed25519:"
DELAY_S: Final = 86_400
_TRUST_RANK: Final = {t.label: t.rank for t in TrustLevel}
_LOG: Final = _log.get_logger("policy")


class PolicySignError(Exception):
    """A key or signing operation failed. ``reason`` is a fixed code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclasses.dataclass(frozen=True)
class PolicyCheck:
    ok: bool
    reason: str
    key_id: str | None = None
    loosenings: tuple[str, ...] = ()
    policy: CompiledPolicy | None = dataclasses.field(default=None, repr=False)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: object, size: int) -> bytes | None:
    if not isinstance(text, str) or not text.isascii():
        return None
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        return None
    return raw if len(raw) == size and _b64(raw) == text else None


def _sig_path(path: Path) -> Path:
    return path.with_name(path.name + ".sig")


# --- keys ---------------------------------------------------------------------------------


def _check_location(path: Path) -> None:
    for ancestor in path.parents:
        if os.path.lexists(ancestor / ".git"):
            raise PolicySignError("inside_git_worktree")
    try:
        private_dir(path.parent)
    except PrivatePathError as exc:
        reason = exc.reason
    else:
        return
    raise PolicySignError(reason)


def _public_spec(public: Ed25519PublicKey) -> str:
    return PUB_PREFIX + _b64(public.public_bytes_raw())


def keygen(path: Path | str) -> str:
    """Create a policy-signing key at ``path`` (0600). Returns the public key to pin."""
    path = Path(path).absolute()
    _check_location(path)
    key = Ed25519PrivateKey.generate()
    doc = {
        "apiVersion": KEY_API,
        "key_id": key_id_for(key.public_key()),
        "seed": _b64(key.private_bytes_raw()),
    }
    failed = False
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        failed = True
    if failed:
        raise PolicySignError("key_exists")
    with os.fdopen(fd, "w") as fh:
        json.dump(doc, fh)
    return _public_spec(key.public_key())


def _load_key(path: Path | str) -> Ed25519PrivateKey:
    path = Path(path).absolute()
    _check_location(path)
    reason = None
    seed = None
    try:
        st = os.lstat(path)
        if os.name == "posix" and (st.st_mode & 0o077 or st.st_uid != os.getuid()):
            reason = "insecure_permissions"
        else:
            doc = json.loads(path.read_text())
            if not isinstance(doc, dict) or doc.get("apiVersion") != KEY_API:
                reason = "key_invalid"
            else:
                seed = _unb64(doc.get("seed"), 32)
    except FileNotFoundError:
        reason = "key_missing"
    except (OSError, ValueError):
        reason = "key_invalid"
    if reason is not None:
        raise PolicySignError(reason)
    if seed is None:
        raise PolicySignError("key_invalid")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_of(path: Path | str) -> str:
    """The public key (to pin as a trusted key) of the signing key at ``path``."""
    return _public_spec(_load_key(path).public_key())


def _parse_public(spec: object) -> tuple[str, Ed25519PublicKey]:
    if not isinstance(spec, str) or not spec.startswith(PUB_PREFIX):
        raise ValueError("trusted_keys entries must be 'ed25519:<base64url>' public keys")
    raw = _unb64(spec[len(PUB_PREFIX) :], 32)
    if raw is None:
        raise ValueError("trusted_keys entries must be 'ed25519:<base64url>' public keys")
    public = Ed25519PublicKey.from_public_bytes(raw)
    return key_id_for(public), public


# --- weakening classification (D52) ---------------------------------------------------------


def _builtin() -> CompiledPolicy:
    from mnemowall.policy import load_policy

    return load_policy()


def weakenings(policy: CompiledPolicy) -> tuple[str, ...]:
    """Every way ``policy`` is looser than the built-in default. Empty means "no weaker"."""
    base = _builtin()
    out: list[str] = []
    if policy.mode == "shadow":
        out.append("mode:shadow")
    if policy.max_write_bytes > base.max_write_bytes:
        out.append("max_write_bytes")
    if policy.quarantine_ttl_s > base.quarantine_ttl_s:
        out.append("quarantine_ttl")
    if policy.on_expiry != base.on_expiry:
        out.append("on_expiry")
    mine, theirs = policy.failure_modes.as_dict(), base.failure_modes.as_dict()
    for name, spec in FAILURE_MODES.items():
        if spec.rank(mine[name]) < spec.rank(theirs[name]):
            out.append(f"failure_modes.{name}")
    if _TRUST_RANK[policy.read.wrap_below_trust] < _TRUST_RANK[base.read.wrap_below_trust]:
        out.append("read.wrap_below_trust")
    rules = {r.id: r for r in policy.rules}
    for rule in base.rules:
        found = rules.get(rule.id)
        if found is None:
            out.append(f"rule_removed:{rule.id}")
        elif strictness(found.then) < strictness(rule.then):
            out.append(f"rule_weakened:{rule.id}")
        elif found.when != rule.when:
            out.append(f"rule_changed:{rule.id}")
    return tuple(out)


# --- parse ------------------------------------------------------------------------------------


def _parse(path: Path, data: bytes) -> tuple[Any, str | None]:
    """The policy document, or a reason. Decides inside ``except``, never raises (M1a-22)."""
    reason = None
    doc: Any = None
    try:
        text = data.decode("utf-8")
        if path.suffix.lower() in (".yaml", ".yml"):
            try:
                import yaml
            except ImportError:
                reason = "yaml_unavailable"
            else:
                doc = yaml.safe_load(text)
        else:
            doc = json.loads(text)
    except Exception:  # noqa: BLE001 - any parser error means "unparseable"; none escapes
        reason = "unparseable"
    return doc, reason


def _compile(doc: Any, now: float) -> CompiledPolicy | None:
    compiled = None
    try:
        compiled = clamp_shadow(compile_policy(doc), now)
    except PolicyError:
        compiled = None
    return compiled


# --- sign / verify ------------------------------------------------------------------------


def _message(key_id: str, signed_at: int, not_before: int, sha256: str) -> bytes:
    fields = {"key_id": key_id, "signed_at": signed_at, "not_before": not_before, "sha256": sha256}
    return DOMAIN + canonicalize(fields)


def sign_policy(
    path: Path | str,
    key_path: Path | str,
    *,
    now: float | None = None,
    _not_before: float | None = None,
) -> Path:
    """Sign the policy file at ``path``; write ``<path>.sig``. A weakening waits 24 h (D52)."""
    path = Path(path)
    key = _load_key(key_path)
    data = path.read_bytes()
    signed_at = int(time.time() if now is None else now)
    doc, reason = _parse(path, data)
    compiled = _compile(doc, signed_at) if reason is None else None
    loose = weakenings(compiled) if compiled is not None else ()
    if _not_before is not None:
        not_before = int(_not_before)
    else:
        not_before = signed_at + DELAY_S if loose else signed_at
    key_id = key_id_for(key.public_key())
    sha256 = hashlib.sha256(data).hexdigest()
    sig = key.sign(_message(key_id, signed_at, not_before, sha256))
    out = {
        "apiVersion": SIG_API,
        "key_id": key_id,
        "signed_at": signed_at,
        "not_before": not_before,
        "sha256": sha256,
        "signature": _b64(sig),
    }
    target = _sig_path(path)
    target.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    return target


def _read_sig(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    sig_path = _sig_path(path)
    if not sig_path.exists():
        return None, "unsigned"
    doc: Any = None
    try:
        doc = json.loads(sig_path.read_text())
    except (OSError, ValueError):
        doc = None
    if not isinstance(doc, dict) or doc.get("apiVersion") != SIG_API:
        return None, "bad_signature_file"
    ints = all(type(doc.get(k)) is int for k in ("signed_at", "not_before"))
    strs = all(isinstance(doc.get(k), str) for k in ("key_id", "sha256", "signature"))
    if not (ints and strs):
        return None, "bad_signature_file"
    return doc, None


def verify_policy(
    path: Path | str, trusted_keys: Iterable[str], *, now: float | None = None
) -> PolicyCheck:
    """Check a signed policy file against pinned public keys. Never raises for bad content."""
    trusted = dict(_parse_public(spec) for spec in trusted_keys)
    if not trusted:
        raise ValueError("trusted_keys must name at least one pinned policy key")
    path = Path(path)
    t = time.time() if now is None else now
    try:
        data = path.read_bytes()
    except OSError:
        return PolicyCheck(False, "unreadable")
    sig, reason = _read_sig(path)
    if sig is None:
        return PolicyCheck(False, reason or "unsigned")
    key_id = sig["key_id"]
    public = trusted.get(key_id)
    if public is None:
        return PolicyCheck(False, "unknown_key")
    raw_sig = _unb64(sig["signature"], 64)
    valid = False
    if raw_sig is not None:
        try:
            msg = _message(key_id, sig["signed_at"], sig["not_before"], sig["sha256"])
            public.verify(raw_sig, msg)
            valid = True
        except (InvalidSignature, JCSError):
            valid = False
    if not valid:
        return PolicyCheck(False, "bad_signature", key_id)
    if hashlib.sha256(data).hexdigest() != sig["sha256"]:
        return PolicyCheck(False, "digest_mismatch", key_id)
    if t < sig["not_before"]:
        return PolicyCheck(False, "not_yet_valid", key_id)
    doc, reason = _parse(path, data)
    if reason is not None:
        return PolicyCheck(False, reason, key_id)
    compiled = _compile(doc, t)
    if compiled is None:
        return PolicyCheck(False, "invalid", key_id)
    loose = weakenings(compiled)
    if loose and sig["not_before"] - sig["signed_at"] < DELAY_S:
        return PolicyCheck(False, "weakening_without_delay", key_id, loose)
    if loose:
        merged = tuple(dict.fromkeys((*compiled.loosenings, *loose)))
        compiled = dataclasses.replace(compiled, loosenings=merged)
    return PolicyCheck(True, "ok", key_id, loose, compiled)


def load_policy_file(
    path: Path | str,
    *,
    trusted_keys: Iterable[str],
    local_overrides: Any = None,
    now: float | None = None,
) -> CompiledPolicy:
    """The policy in a signed file, or the built-in strict default if it can't be trusted."""
    t = time.time() if now is None else now
    check = verify_policy(path, trusted_keys, now=t)
    if check.ok and check.policy is not None:
        policy = check.policy
        if check.loosenings:
            diagnostics.record("policy_weakened")
            _LOG.warning("policy_weakened", extra={"count": len(check.loosenings)})
    else:
        diagnostics.record("policy_signature_invalid")
        diagnostics.record("policy_fallback")
        _LOG.error("policy_signature_invalid", extra={"reason": check.reason})
        policy = dataclasses.replace(_builtin(), fallback="policy_signature_invalid")
    if local_overrides is not None:
        policy = apply_local_overrides(policy, local_overrides, now=t)
    return policy


__all__ = [
    "DELAY_S",
    "PolicyCheck",
    "PolicySignError",
    "keygen",
    "load_policy_file",
    "public_key_of",
    "sign_policy",
    "verify_policy",
    "weakenings",
]
