"""M1a-12: key providers, key ids, derivation and the `mnemowall keys` CLI. UT-KEYS-001..006."""

from __future__ import annotations

import base64
import json
import logging
import os
import pickle
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from mnemowall import cli
from mnemowall.core import diagnostics
from mnemowall.keys import (
    EphemeralKeyProvider,
    FileKeyProvider,
    KeychainKeyProvider,
    KeySet,
    KeysExist,
    KeysNotInitialized,
    KeyUnavailable,
    Purpose,
    default_provider,
    key_id_for,
    status_lines,
)

posix_only = pytest.mark.skipif(os.name != "posix", reason="file provider is POSIX-only")


@pytest.fixture(autouse=True)
def _reset() -> None:
    diagnostics.reset()


@pytest.fixture
def key_path(tmp_path: Path) -> Path:
    return tmp_path / "mnemowall" / "keys.json"


def secrets_in(doc_text: str) -> list[str]:
    """Every encoding of the private material in a stored key document."""
    doc = json.loads(doc_text)
    out: list[str] = []
    for b64 in (doc["signing_key"], doc["storage_secret"]):
        raw = base64.b64decode(b64)
        out += [b64, raw.hex(), base64.urlsafe_b64encode(raw).decode().rstrip("=")]
    return out


class FakeKeyring:
    def __init__(self) -> None:
        self.store: dict[tuple[str, str], str] = {}
        self.fail: Exception | None = None

    def get_password(self, service: str, account: str) -> str | None:
        if self.fail:
            raise self.fail
        return self.store.get((service, account))

    def set_password(self, service: str, account: str, password: str) -> None:
        if self.fail:
            raise self.fail
        self.store[(service, account)] = password


# --- UT-KEYS-001 ---------------------------------------------------------------------------


@posix_only
def test_ut_keys_001_init_then_refuse(key_path: Path) -> None:
    provider = FileKeyProvider(key_path)
    with pytest.raises(KeysNotInitialized):
        provider.load()
    ks = provider.init()
    assert ks.active_key_id.startswith("ed25519-")
    assert len(ks.active_key_id) == len("ed25519-") + 32
    assert provider.load().active_key_id == ks.active_key_id
    with pytest.raises(KeysExist):
        provider.init()
    assert provider.load().active_key_id == ks.active_key_id


@posix_only
def test_ut_keys_001_cli_init_rotate_status(
    key_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = ["--provider", "file", "--path", str(key_path)]
    assert cli.main(["keys", "init", *args]) == 0
    first = capsys.readouterr().out
    key1 = FileKeyProvider(key_path).load().active_key_id
    assert key1 in first
    assert cli.main(["keys", "init", *args]) == 1
    err = capsys.readouterr().err
    assert "mnemowall keys rotate" in err
    assert cli.main(["keys", "rotate", *args]) == 0
    key2 = FileKeyProvider(key_path).load().active_key_id
    assert key2 != key1
    assert key2 in capsys.readouterr().out
    assert cli.main(["keys", "status", *args]) == 0
    out = capsys.readouterr().out
    assert key2 in out
    assert "public keys: 2" in out
    for s in secrets_in(key_path.read_text()):
        assert s not in first + err + out


def test_cli_reports_unavailable_keys(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    missing = tmp_path / "none" / "keys.json"
    assert cli.main(["keys", "status", "--provider", "file", "--path", str(missing)]) == 2
    assert "not_initialized" in capsys.readouterr().err


# --- UT-KEYS-002 ---------------------------------------------------------------------------


@posix_only
def test_ut_keys_002_permissions_and_atomic_write(key_path: Path) -> None:
    FileKeyProvider(key_path).init()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(key_path.parent.stat().st_mode) == 0o700
    assert [p.name for p in key_path.parent.iterdir()] == ["keys.json"]
    FileKeyProvider(key_path).rotate()
    assert [p.name for p in key_path.parent.iterdir()] == ["keys.json"]
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


@posix_only
@pytest.mark.parametrize("git_kind", ["dir", "file"])
def test_ut_keys_002_refuses_git_worktree(tmp_path: Path, git_kind: str) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    if git_kind == "dir":
        (repo / ".git").mkdir()
    else:
        (repo / ".git").write_text("gitdir: ../elsewhere\n")
    path = repo / "deep" / "keys.json"
    with pytest.raises(KeyUnavailable) as exc:
        FileKeyProvider(path).init()
    assert exc.value.reason == "inside_git_worktree"
    assert not path.exists()


@posix_only
def test_ut_keys_002_refuses_symlink(tmp_path: Path, key_path: Path) -> None:
    FileKeyProvider(key_path).init()
    link_dir = tmp_path / "links"
    link_dir.mkdir(mode=0o700)
    link = link_dir / "keys.json"
    link.symlink_to(key_path)
    with pytest.raises(KeyUnavailable) as exc:
        FileKeyProvider(link).load()
    assert exc.value.reason == "symlink"
    dir_link = tmp_path / "dirlink"
    dir_link.symlink_to(key_path.parent)
    with pytest.raises(KeyUnavailable) as exc:
        FileKeyProvider(dir_link / "keys.json").load()
    assert exc.value.reason == "symlink"


@posix_only
@pytest.mark.parametrize(
    ("target", "mode"), [("file", 0o640), ("file", 0o604), ("dir", 0o750), ("dir", 0o705)]
)
def test_ut_keys_002_refuses_loose_permissions(key_path: Path, target: str, mode: int) -> None:
    FileKeyProvider(key_path).init()
    (key_path if target == "file" else key_path.parent).chmod(mode)
    with pytest.raises(KeyUnavailable) as exc:
        FileKeyProvider(key_path).load()
    assert exc.value.reason == "insecure_permissions"
    with pytest.raises(KeyUnavailable):
        FileKeyProvider(key_path).rotate()


@posix_only
def test_ut_keys_002_existing_loose_directory_refused_on_init(tmp_path: Path) -> None:
    d = tmp_path / "shared"
    d.mkdir()
    d.chmod(0o755)
    with pytest.raises(KeyUnavailable) as exc:
        FileKeyProvider(d / "keys.json").init()
    assert exc.value.reason == "insecure_permissions"
    assert not (d / "keys.json").exists()


@posix_only
@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: "not json",
        lambda d: json.dumps({**d, "format": "mnemowall/keys/v0"}),
        lambda d: json.dumps({**d, "storage_secret": base64.b64encode(b"short").decode()}),
        lambda d: json.dumps({**d, "active": "ed25519-" + "0" * 32}),
        lambda d: json.dumps({k: v for k, v in d.items() if k != "public_keys"}),
        lambda d: json.dumps(
            {**d, "public_keys": {d["active"]: base64.b64encode(b"\x01" * 32).decode()}}
        ),
        lambda d: json.dumps({**d, "signing_key": "!!!"}),
        lambda d: json.dumps([d]),
    ],
)
def test_corrupt_key_store_is_unavailable(key_path: Path, mutate: Any) -> None:
    FileKeyProvider(key_path).init()
    doc = json.loads(key_path.read_text())
    key_path.write_text(mutate(doc))
    with pytest.raises(KeyUnavailable) as exc:
        FileKeyProvider(key_path).load()
    assert exc.value.reason == "key_store_corrupt"


@posix_only
def test_mismatched_key_id_is_corrupt(key_path: Path) -> None:
    FileKeyProvider(key_path).init()
    doc = json.loads(key_path.read_text())
    other = EphemeralKeyProvider().init()
    other_id = other.active_key_id
    doc["public_keys"]["ed25519-" + "f" * 32] = base64.b64encode(
        other.public_keys[other_id].public_bytes_raw()
    ).decode()
    key_path.write_text(json.dumps(doc))
    with pytest.raises(KeyUnavailable) as exc:
        FileKeyProvider(key_path).load()
    assert exc.value.reason == "key_store_corrupt"


# --- UT-KEYS-003 ---------------------------------------------------------------------------


def test_ut_keys_003_keychain_round_trip() -> None:
    backend = FakeKeyring()
    provider = KeychainKeyProvider(backend=backend)
    assert provider.production_ready
    with pytest.raises(KeysNotInitialized):
        provider.load()
    ks = provider.init()
    assert list(backend.store) == [("mnemowall", "default")]
    assert provider.load().active_key_id == ks.active_key_id
    with pytest.raises(KeysExist):
        provider.init()
    ks2 = provider.rotate()
    assert set(ks2.public_keys) == {ks.active_key_id, ks2.active_key_id}
    assert KeychainKeyProvider(backend=backend, account="other").load_or_none() is None


def test_ut_keys_003_keychain_locked_is_unavailable(caplog: pytest.LogCaptureFixture) -> None:
    backend = FakeKeyring()
    provider = KeychainKeyProvider(backend=backend)
    provider.init()
    secrets = secrets_in(backend.store[("mnemowall", "default")])
    backend.fail = RuntimeError("keychain locked " + secrets[0])
    with caplog.at_level(logging.WARNING, logger="mnemowall"), pytest.raises(KeyUnavailable) as exc:
        provider.load()
    assert exc.value.reason == "keychain_error"
    assert exc.value.__cause__ is None
    assert exc.value.__suppress_context__
    assert diagnostics.counters().get("key_unavailable", 0) >= 1
    records = [r for r in caplog.records if r.getMessage() == "key_unavailable"]
    assert records
    assert getattr(records[0], "reason", None) == "keychain_error"
    for s in secrets:
        assert s not in caplog.text
        assert s not in str(exc.value) + repr(exc.value)


def test_ut_keys_003_keychain_extra_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "keyring", None)
    with pytest.raises(KeyUnavailable) as exc:
        KeychainKeyProvider().load()
    assert exc.value.reason == "keychain_extra_not_installed"
    assert isinstance(default_provider(), FileKeyProvider)


def test_default_provider_prefers_keychain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "keyring", FakeKeyring())
    assert isinstance(default_provider(), KeychainKeyProvider)


# --- UT-KEYS-004 ---------------------------------------------------------------------------


@posix_only
def test_ut_keys_004_secrets_never_in_repr_logs_or_errors(
    key_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    provider = FileKeyProvider(key_path)
    with caplog.at_level(logging.DEBUG, logger="mnemowall"):
        ks = provider.init()
        ks2 = provider.rotate()
        loaded = provider.load()
    text = key_path.read_text()
    secrets = secrets_in(text)
    rendered = " ".join(
        [
            repr(ks),
            str(ks),
            repr(ks2),
            repr(loaded),
            repr(provider),
            str(vars(provider)),
            caplog.text,
        ]
    )
    for s in secrets:
        assert s not in rendered
    with pytest.raises(TypeError):
        pickle.dumps(ks)


def test_ut_keys_004_key_id_is_public_fingerprint() -> None:
    ks = EphemeralKeyProvider().init()
    pub = ks.public_keys[ks.active_key_id]
    assert key_id_for(pub) == ks.active_key_id


# --- UT-KEYS-005 ---------------------------------------------------------------------------


def test_ut_keys_005_hkdf_purpose_separation() -> None:
    ks = EphemeralKeyProvider().init()
    derived = {p: ks.derive(p) for p in Purpose}
    assert all(len(k) == 32 for k in derived.values())
    assert len(set(derived.values())) == len(Purpose)
    assert all(ks.derive(p) == derived[p] for p in Purpose)
    other = EphemeralKeyProvider().init()
    assert all(other.derive(p) != derived[p] for p in Purpose)
    assert {p.value for p in Purpose} == {
        "ledger-enc",
        "quarantine-enc",
        "buffer-enc",
        "content-hmac",
    }


@posix_only
def test_ut_keys_005_derivation_survives_reload(key_path: Path) -> None:
    ks = FileKeyProvider(key_path).init()
    again = FileKeyProvider(key_path).load()
    assert all(again.derive(p) == ks.derive(p) for p in Purpose)


# --- UT-KEYS-006 ---------------------------------------------------------------------------


def test_ut_keys_006_ephemeral_flagged_not_for_production(key_path: Path) -> None:
    eph = EphemeralKeyProvider()
    eph.init()
    assert not eph.production_ready
    lines = status_lines(eph)
    assert any("not for production" in line for line in lines)
    assert FileKeyProvider(key_path).production_ready
    assert KeychainKeyProvider(backend=FakeKeyring()).production_ready


def test_keyset_sign_uses_active_key_only() -> None:
    provider = EphemeralKeyProvider()
    ks1 = provider.init()
    ks2 = provider.rotate()
    key_id, sig = ks2.sign(b"message")
    assert key_id == ks2.active_key_id != ks1.active_key_id
    ks2.public_keys[key_id].verify(sig, b"message")
    assert isinstance(ks2, KeySet)
