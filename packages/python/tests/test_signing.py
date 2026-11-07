"""M1a-12: Ed25519 version signing over the JCS form of the §3.6 field set.

UT-SIGN-001..004, PT-SIGN-FIELDS.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from mnemowall.core.jcs import MAX_SAFE_INT, canonicalize
from mnemowall.core.model import EffectiveType, MemoryType
from mnemowall.core.trust import TrustLevel
from mnemowall.keys import EphemeralKeyProvider, KeySet, Purpose
from mnemowall.ledger.signing import (
    DOMAIN,
    SIGNED_FIELDS,
    STATUSES,
    Signature,
    SigningError,
    VersionFields,
    sign_version,
    signing_message,
    verify_version,
)

CANARY = "CANARY-7f3a91"

SPEC_FIELDS = (
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

KEYS: KeySet = EphemeralKeyProvider().init()
OTHER_KEYS: KeySet = EphemeralKeyProvider().init()
TRUST_LABELS = [t.label for t in TrustLevel]
HEX64 = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)


def first_version(**over: Any) -> VersionFields:
    base: dict[str, Any] = {
        "tenant_id": "tenant-a",
        "scope": "user",
        "namespace": ("users", "u-1", "memories"),
        "memory_id": "mem-1",
        "version_no": 1,
        "prev_version_signature": None,
        "content_hash": "a" * 64,
        "provenance_hash": "b" * 64,
        "trust_level": "user",
        "effective_type": "fact",
        "memory_type": "fact",
        "protected": False,
        "status": "active",
        "bundle_id": "builtin-default",
    }
    base.update(over)
    return VersionFields(**base)


PREV_SIG = sign_version(first_version(), KEYS).encode()


def second_version(**over: Any) -> VersionFields:
    base: dict[str, Any] = {"version_no": 2, "prev_version_signature": PREV_SIG}
    base.update(over)
    return first_version(**base)


# --- field set -----------------------------------------------------------------------------


def test_signed_fields_are_exactly_the_spec_set() -> None:
    assert SIGNED_FIELDS == SPEC_FIELDS
    assert tuple(f.name for f in dataclasses.fields(VersionFields)) == SPEC_FIELDS
    assert set(second_version().as_dict()) == set(SPEC_FIELDS)
    assert DOMAIN == b"mnemowall/version/v1\x00"
    assert frozenset({"active", "deleted", "tombstoned"}) == STATUSES


# --- UT-SIGN-001 ---------------------------------------------------------------------------


def test_ut_sign_001_round_trip() -> None:
    f = second_version()
    sig = sign_version(f, KEYS)
    assert sig.key_id == KEYS.active_key_id
    assert len(sig.value) == 64
    assert verify_version(f, sig, KEYS.public_keys).valid
    assert verify_version(f, sig.encode(), KEYS.public_keys).valid
    assert Signature.decode(sig.encode()) == sig
    assert signing_message(f) == DOMAIN + canonicalize(f.as_dict())


def test_ut_sign_001_from_mapping_missing_or_extra_field() -> None:
    good = second_version().as_dict()
    assert VersionFields.from_mapping(good) == second_version()
    for name in SPEC_FIELDS:
        missing = {k: v for k, v in good.items() if k != name}
        with pytest.raises(SigningError) as exc:
            VersionFields.from_mapping(missing)
        assert exc.value.field == name
        assert exc.value.kind == "missing"
    with pytest.raises(SigningError) as exc:
        VersionFields.from_mapping({**good, "created_at": "2026-11-06"})
    assert exc.value.field == "created_at"
    assert exc.value.kind == "unexpected"


@pytest.mark.parametrize(
    ("over", "field"),
    [
        ({"version_no": 0, "prev_version_signature": None}, "version_no"),
        ({"version_no": True}, "version_no"),
        ({"version_no": MAX_SAFE_INT + 1}, "version_no"),
        ({"version_no": "2"}, "version_no"),
        ({"prev_version_signature": None}, "prev_version_signature"),
        ({"prev_version_signature": "not-a-signature"}, "prev_version_signature"),
        ({"content_hash": "A" * 64}, "content_hash"),
        ({"content_hash": "a" * 63}, "content_hash"),
        ({"provenance_hash": CANARY}, "provenance_hash"),
        ({"trust_level": CANARY}, "trust_level"),
        ({"trust_level": TrustLevel.USER}, "trust_level"),
        ({"effective_type": CANARY}, "effective_type"),
        ({"memory_type": "data"}, "memory_type"),
        ({"protected": 1}, "protected"),
        ({"status": CANARY}, "status"),
        ({"tenant_id": ""}, "tenant_id"),
        ({"tenant_id": 7}, "tenant_id"),
        ({"bundle_id": ""}, "bundle_id"),
        ({"namespace": ["users"]}, "namespace"),
        ({"namespace": ()}, "namespace"),
        ({"namespace": ("users", 3)}, "namespace"),
        ({"namespace": ("users", CANARY + "\ud800")}, "namespace"),
        ({"memory_id": CANARY + "\udc00"}, "memory_id"),
    ],
)
def test_ut_sign_001_field_validation_names_field_only(over: dict[str, Any], field: str) -> None:
    with pytest.raises(SigningError) as exc:
        second_version(**over)
    assert exc.value.field == field
    assert CANARY not in str(exc.value) + repr(exc.value)


def test_ut_sign_001_first_version_has_no_previous() -> None:
    with pytest.raises(SigningError) as exc:
        first_version(prev_version_signature=PREV_SIG)
    assert exc.value.field == "prev_version_signature"
    assert exc.value.kind == "unexpected_for_first_version"
    with pytest.raises(SigningError) as exc:
        second_version(prev_version_signature=None)
    assert (exc.value.field, exc.value.kind) == ("prev_version_signature", "missing")
    assert verify_version(first_version(), sign_version(first_version(), KEYS), KEYS.public_keys)


def test_ut_sign_001_enum_values_accepted() -> None:
    f = second_version(effective_type="data", memory_type="standing_instruction", protected=True)
    assert f.effective_type == EffectiveType.DATA.value
    assert f.memory_type == MemoryType.STANDING_INSTRUCTION.value
    assert verify_version(f, sign_version(f, KEYS), KEYS.public_keys)


def test_version_fields_repr_hides_namespace() -> None:
    f = second_version(namespace=("users", CANARY))
    assert CANARY not in repr(f)


# --- PT-SIGN-FIELDS ------------------------------------------------------------------------


@st.composite
def base_fields(draw: st.DrawFn) -> VersionFields:
    return second_version(
        tenant_id=draw(st.text(min_size=1, max_size=12)),
        scope=draw(st.sampled_from(["user", "shared", "org", "session"])),
        namespace=tuple(draw(st.lists(st.text(max_size=8), min_size=1, max_size=4))),
        memory_id=draw(st.text(min_size=1, max_size=12)),
        version_no=draw(st.integers(min_value=2, max_value=MAX_SAFE_INT)),
        content_hash=draw(HEX64),
        provenance_hash=draw(HEX64),
        trust_level=draw(st.sampled_from(TRUST_LABELS)),
        effective_type=draw(st.sampled_from([e.value for e in EffectiveType])),
        memory_type=draw(st.sampled_from([m.value for m in MemoryType])),
        protected=draw(st.booleans()),
        status=draw(st.sampled_from(sorted(STATUSES))),
    )


def other_value(draw: st.DrawFn, name: str, current: Any) -> Any:
    strategies: dict[str, st.SearchStrategy[Any]] = {
        "tenant_id": st.text(min_size=1, max_size=12),
        "scope": st.text(min_size=1, max_size=12),
        "namespace": st.lists(st.text(max_size=8), min_size=1, max_size=4).map(tuple),
        "memory_id": st.text(min_size=1, max_size=12),
        "version_no": st.integers(min_value=2, max_value=MAX_SAFE_INT),
        "prev_version_signature": st.binary(min_size=64, max_size=64).map(
            lambda b: Signature(KEYS.active_key_id, b).encode()
        ),
        "content_hash": HEX64,
        "provenance_hash": HEX64,
        "trust_level": st.sampled_from(TRUST_LABELS),
        "effective_type": st.sampled_from([e.value for e in EffectiveType]),
        "memory_type": st.sampled_from([m.value for m in MemoryType]),
        "protected": st.booleans(),
        "status": st.sampled_from(sorted(STATUSES)),
        "bundle_id": st.text(min_size=1, max_size=12),
    }
    return draw(strategies[name].filter(lambda v: v != current))


@st.composite
def field_change(draw: st.DrawFn) -> tuple[VersionFields, VersionFields, str]:
    f = draw(base_fields())
    name = draw(st.sampled_from(SPEC_FIELDS))
    changed = dataclasses.replace(f, **{name: other_value(draw, name, getattr(f, name))})
    return f, changed, name


@given(field_change())
def test_pt_sign_fields_any_single_field_change_fails(case: tuple[Any, Any, str]) -> None:
    original, changed, _name = case
    sig = sign_version(original, KEYS)
    assert verify_version(original, sig, KEYS.public_keys).valid
    result = verify_version(changed, sig, KEYS.public_keys)
    assert not result.valid
    assert result.reason == "bad_signature"


@given(base_fields(), st.integers(min_value=0, max_value=511))
def test_pt_sign_fields_any_signature_bit_flip_fails(f: VersionFields, bit: int) -> None:
    sig = sign_version(f, KEYS)
    raw = bytearray(sig.value)
    raw[bit // 8] ^= 1 << (bit % 8)
    assert not verify_version(f, Signature(sig.key_id, bytes(raw)), KEYS.public_keys).valid


def test_pt_sign_fields_domain_prefix_is_bound() -> None:
    f = second_version()
    body = canonicalize(f.as_dict())
    for message in (body, b"mnemowall/ledger/v1\x00" + body, b"mnemowall/version/v2\x00" + body):
        key_id, raw = KEYS.sign(message)
        assert not verify_version(f, Signature(key_id, raw), KEYS.public_keys).valid


# --- UT-SIGN-002 ---------------------------------------------------------------------------


def test_ut_sign_002_unknown_key_is_invalid() -> None:
    f = second_version()
    sig = sign_version(f, OTHER_KEYS)
    result = verify_version(f, sig, KEYS.public_keys)
    assert not result.valid
    assert result.reason == "unknown_key"
    assert not result


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "",
        "no-colon",
        ":",
        "ed25519-00:!!!",
        "ed25519-00:" + "A" * 10,
        f"{KEYS.active_key_id}:" + "A" * 10,
        f"{KEYS.active_key_id}:{'A' * 86}:extra",
        CANARY,
        7,
    ],
)
def test_ut_sign_002_malformed_signature_never_raises(bad: Any) -> None:
    result = verify_version(second_version(), bad, KEYS.public_keys)
    assert not result.valid
    assert result.reason in {"missing", "malformed", "unknown_key", "bad_signature"}


def test_ut_sign_002_non_canonical_encoding_rejected() -> None:
    sig = sign_version(second_version(), KEYS)
    text = sig.encode()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(text[-1])
    assert last & 0b1111 == 0  # the low 4 bits of the 86th character are padding
    twin = text[:-1] + alphabet[last | 1]
    with pytest.raises(SigningError):
        Signature.decode(twin)
    assert verify_version(second_version(), twin, KEYS.public_keys).reason == "malformed"
    for bad in (text + "=", text + "==", text.replace(":", "::", 1), " " + text):
        assert not verify_version(second_version(), bad, KEYS.public_keys)


def test_ut_sign_002_decode_errors_hide_input() -> None:
    with pytest.raises(SigningError) as exc:
        Signature.decode(CANARY)
    assert CANARY not in str(exc.value) + repr(exc.value)


# --- UT-SIGN-003 ---------------------------------------------------------------------------


def test_ut_sign_003_rotation_keeps_old_public_keys() -> None:
    provider = EphemeralKeyProvider()
    ks1 = provider.init()
    f1 = first_version()
    s1 = sign_version(f1, ks1)
    ks2 = provider.rotate()
    f2 = second_version(prev_version_signature=s1.encode())
    s2 = sign_version(f2, ks2)
    assert s2.key_id != s1.key_id
    assert s2.key_id == ks2.active_key_id
    assert set(ks2.public_keys) == {s1.key_id, s2.key_id}
    assert verify_version(f1, s1, ks2.public_keys).valid
    assert verify_version(f2, s2, ks2.public_keys).valid
    assert not verify_version(f2, s2, ks1.public_keys).valid
    ks3 = provider.rotate()
    assert len(ks3.public_keys) == 3
    assert provider.load().active_key_id == ks3.active_key_id
    assert verify_version(f1, s1, provider.load().public_keys).valid
    for purpose in Purpose:
        assert ks3.derive(purpose) == ks1.derive(purpose)


# --- UT-SIGN-004 ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "over",
    [{"tenant_id": "tenant-b"}, {"scope": "shared"}, {"namespace": ("users", "u-2", "memories")}],
)
def test_ut_sign_004_tenant_scope_namespace_bound(over: dict[str, Any]) -> None:
    a = second_version()
    b = second_version(**over)
    sa, sb = sign_version(a, KEYS), sign_version(b, KEYS)
    assert sa.value != sb.value
    assert not verify_version(b, sa, KEYS.public_keys).valid
    assert not verify_version(a, sb, KEYS.public_keys).valid


def test_signatures_are_deterministic() -> None:
    assert sign_version(second_version(), KEYS) == sign_version(second_version(), KEYS)
