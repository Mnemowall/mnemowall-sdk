"""Version signatures (§3.6; ADR-0020 D12, D15, D17).

A version is signed with Ed25519 over ``DOMAIN || JCS(fields)``, where ``fields`` is exactly the
14-field set of §3.6. ``content_hash`` and ``provenance_hash`` are keyed HMAC-SHA-256 values
(D15), computed by the ledger. ``prev_version_signature`` chains each version to the one before
it; the first version of a memory has none.

Signatures are encoded as ``<key_id>:<base64url, unpadded>``. Verification never raises: it
returns a :class:`VerifyResult` whose ``reason`` is one of ``ok``, ``missing``, ``malformed``,
``unknown_key`` or ``bad_signature``. Errors name a field and a kind, never a value.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from mnemowall.core.jcs import MAX_SAFE_INT, canonicalize
from mnemowall.core.model import EffectiveType, MemoryType
from mnemowall.core.trust import TrustLevel
from mnemowall.keys import KeySet, is_key_id

DOMAIN: Final = b"mnemowall/version/v1\x00"
SIGNED_FIELDS: Final = (
    "tenant_id",
    "scope",
    "namespace",
    "memory_id",
    "version_no",
    "prev_version_signature",
    "content_hash",
    "provenance_hash",
    "trust_level",
    "effective_type",
    "memory_type",
    "protected",
    "status",
    "bundle_id",
)
STATUSES: Final = frozenset({"active", "deleted", "tombstoned"})
SIGNATURE_BYTES: Final = 64

_TRUST_LABELS: Final = frozenset(t.label for t in TrustLevel)
_EFFECTIVE: Final = frozenset(e.value for e in EffectiveType)
_MEMORY: Final = frozenset(m.value for m in MemoryType)
_HEX: Final = frozenset("0123456789abcdef")
_B64URL: Final = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_SIG_B64_LEN: Final = 86  # 64 bytes, base64url without padding


class SigningError(ValueError):
    """An invalid signed field or signature encoding. Names the field and a kind only."""

    def __init__(self, field_name: str, kind: str) -> None:
        super().__init__(f"{field_name}: {kind}")
        self.field = field_name
        self.kind = kind


def _safe_name(name: object) -> str:
    return name if isinstance(name, str) and name.isidentifier() and len(name) <= 64 else "<key>"


@dataclass(frozen=True, slots=True)
class Signature:
    key_id: str
    value: bytes

    def encode(self) -> str:
        return self.key_id + ":" + base64.urlsafe_b64encode(self.value).decode("ascii").rstrip("=")

    @classmethod
    def decode(cls, text: object) -> Signature:
        if not isinstance(text, str):
            raise SigningError("signature", "malformed")
        key_id, sep, b64 = text.partition(":")
        if not sep or not is_key_id(key_id):
            raise SigningError("signature", "malformed")
        if len(b64) != _SIG_B64_LEN or not set(b64) <= _B64URL:
            raise SigningError("signature", "malformed")
        raw = base64.urlsafe_b64decode(b64 + "==")
        if len(raw) != SIGNATURE_BYTES or cls(key_id, raw).encode() != text:
            raise SigningError("signature", "malformed")
        return cls(key_id, raw)


@dataclass(frozen=True, slots=True)
class VerifyResult:
    valid: bool
    reason: str

    def __bool__(self) -> bool:
        return self.valid


def _plain_str(name: str, value: object, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise SigningError(name, "wrong_type" if not isinstance(value, str) else "empty")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise SigningError(name, "lone_surrogate") from None
    return str.__str__(value)


def _hex64(name: str, value: object) -> str:
    if not isinstance(value, str) or len(value) != 64 or not set(value) <= _HEX:
        raise SigningError(name, "not_lowercase_hex64")
    return str.__str__(value)


def _member(name: str, value: object, allowed: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise SigningError(name, "invalid_value")
    return str.__str__(value)


@dataclass(frozen=True)
class VersionFields:
    """Exactly the §3.6 signed field set, validated on construction."""

    tenant_id: str
    scope: str
    namespace: tuple[str, ...] = field(repr=False)
    memory_id: str
    version_no: int
    prev_version_signature: str | None
    content_hash: str
    provenance_hash: str
    trust_level: str
    effective_type: str
    memory_type: str
    protected: bool
    status: str
    bundle_id: str

    def __post_init__(self) -> None:
        put = object.__setattr__
        for name in ("tenant_id", "scope", "memory_id", "bundle_id"):
            put(self, name, _plain_str(name, getattr(self, name)))
        ns = self.namespace
        if type(ns) is not tuple or not ns:
            raise SigningError("namespace", "wrong_type" if type(ns) is not tuple else "empty")
        put(self, "namespace", tuple(_plain_str("namespace", s, allow_empty=True) for s in ns))
        v = self.version_no
        if type(v) is not int:
            raise SigningError("version_no", "wrong_type")
        if not 1 <= v <= MAX_SAFE_INT:
            raise SigningError("version_no", "out_of_range")
        prev = self.prev_version_signature
        if v == 1 and prev is not None:
            raise SigningError("prev_version_signature", "unexpected_for_first_version")
        if v > 1:
            if prev is None:
                raise SigningError("prev_version_signature", "missing")
            try:
                Signature.decode(prev)
            except SigningError:
                raise SigningError("prev_version_signature", "malformed") from None
            put(self, "prev_version_signature", str.__str__(prev))
        put(self, "content_hash", _hex64("content_hash", self.content_hash))
        put(self, "provenance_hash", _hex64("provenance_hash", self.provenance_hash))
        put(self, "trust_level", _member("trust_level", self.trust_level, _TRUST_LABELS))
        put(self, "effective_type", _member("effective_type", self.effective_type, _EFFECTIVE))
        put(self, "memory_type", _member("memory_type", self.memory_type, _MEMORY))
        if type(self.protected) is not bool:
            raise SigningError("protected", "wrong_type")
        put(self, "status", _member("status", self.status, STATUSES))

    def as_dict(self) -> dict[str, object]:
        out: dict[str, object] = {name: getattr(self, name) for name in SIGNED_FIELDS}
        out["namespace"] = list(self.namespace)
        return out

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> VersionFields:
        """Build from a stored row; a missing or unexpected field is an error naming it."""
        for key in data:
            if key not in SIGNED_FIELDS:
                raise SigningError(_safe_name(key), "unexpected")
        for name in SIGNED_FIELDS:
            if name not in data:
                raise SigningError(name, "missing")
        values = dict(data)
        ns = values["namespace"]
        if type(ns) is list:
            values["namespace"] = tuple(ns)
        return cls(**values)  # type: ignore[arg-type]


def signing_message(fields: VersionFields) -> bytes:
    return DOMAIN + canonicalize(fields.as_dict())


def sign_version(fields: VersionFields, keys: KeySet) -> Signature:
    key_id, raw = keys.sign(signing_message(fields))
    return Signature(key_id, raw)


def verify_version(
    fields: VersionFields,
    signature: object,
    public_keys: Mapping[str, Ed25519PublicKey],
) -> VerifyResult:
    """Check ``signature`` over ``fields``. Never raises; see the module docstring for reasons."""
    if signature is None:
        return VerifyResult(False, "missing")
    if not isinstance(signature, Signature):
        try:
            signature = Signature.decode(signature)
        except SigningError:
            return VerifyResult(False, "malformed")
    public = public_keys.get(signature.key_id)
    if public is None:
        return VerifyResult(False, "unknown_key")
    try:
        public.verify(signature.value, signing_message(fields))
    except (InvalidSignature, ValueError, TypeError):
        return VerifyResult(False, "bad_signature")
    return VerifyResult(True, "ok")
