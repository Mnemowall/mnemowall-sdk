"""M1b-06: locally signed policies. UT-POLICY-SIGN-001..011 (§3.5 policy signing, D48-D52)."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from mnemowall import cli
from mnemowall.core import diagnostics
from mnemowall.policy import builtin_policy_document
from mnemowall.policyfile import (
    DELAY_S,
    PolicySignError,
    keygen,
    load_policy_file,
    public_key_of,
    sign_policy,
    verify_policy,
    weakenings,
)

CANARY = "CANARY7f3a91"
T0 = 1_800_000_000.0


@pytest.fixture(autouse=True)
def _reset() -> None:
    diagnostics.reset()


@pytest.fixture
def keydir(tmp_path: Path) -> Path:
    d = tmp_path / "policy-keys"
    d.mkdir(mode=0o700)
    return d


def write_policy(path: Path, doc: Any, *, yaml: bool = False) -> Path:
    if yaml:
        import yaml as pyyaml

        path.write_text(pyyaml.safe_dump(doc, sort_keys=True))
    else:
        path.write_text(json.dumps(doc, indent=2, sort_keys=True))
    return path


def stricter_doc() -> dict[str, Any]:
    doc = builtin_policy_document()
    doc["id"] = "acme-strict"
    doc["defaults"]["max_write_bytes"] = 16 * 1024
    return doc


def weaker_doc() -> dict[str, Any]:
    doc = builtin_policy_document()
    doc["id"] = "acme-weaker"
    doc["rules"] = [r for r in doc["rules"] if r["id"] != "no-external-payment-sinks"]
    return doc


# --- UT-POLICY-SIGN-001: keygen ------------------------------------------------------------


def test_ut_policy_sign_001_keygen_private_file_and_public_key(keydir: Path) -> None:
    key = keydir / "policy.key"
    pub = keygen(key)
    assert pub.startswith("ed25519:")
    assert stat.S_IMODE(os.lstat(key).st_mode) == 0o600
    assert public_key_of(key) == pub
    with pytest.raises(PolicySignError) as exc:
        keygen(key)
    assert exc.value.reason == "key_exists"
    assert pub[len("ed25519:") :] not in key.read_text()  # only the private seed is stored


def test_ut_policy_sign_001_keygen_refuses_unsafe_locations(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    with pytest.raises(PolicySignError) as exc:
        keygen(repo / "keys" / "policy.key")
    assert exc.value.reason == "inside_git_worktree"
    loose = tmp_path / "loose"
    loose.mkdir(mode=0o755)
    with pytest.raises(PolicySignError) as exc:
        keygen(loose / "policy.key")
    assert exc.value.reason == "insecure_permissions"


# --- UT-POLICY-SIGN-002: sign and load ------------------------------------------------------


@pytest.mark.parametrize("yaml", [False, True])
def test_ut_policy_sign_002_signed_policy_loads(keydir: Path, tmp_path: Path, yaml: bool) -> None:
    key = keydir / "policy.key"
    pub = keygen(key)
    path = write_policy(tmp_path / ("p.yaml" if yaml else "p.json"), stricter_doc(), yaml=yaml)
    sig = sign_policy(path, key, now=T0)
    assert sig == path.with_name(path.name + ".sig")
    check = verify_policy(path, [pub], now=T0)
    assert (check.ok, check.reason, check.loosenings) == (True, "ok", ())
    policy = load_policy_file(path, trusted_keys=[pub], now=T0)
    assert policy.id == "acme-strict"
    assert policy.max_write_bytes == 16 * 1024
    assert policy.fallback is None


# --- UT-POLICY-SIGN-003..005: refused -> strict default -----------------------------------


def _assert_fallback(policy: Any, reason: str) -> None:
    assert policy.id == "builtin-default"
    assert policy.fallback == "policy_signature_invalid"
    assert diagnostics.counters()["policy_signature_invalid"] >= 1
    assert diagnostics.counters()["policy_fallback"] >= 1
    del reason


def test_ut_policy_sign_003_one_byte_changed(keydir: Path, tmp_path: Path) -> None:
    key = keydir / "policy.key"
    pub = keygen(key)
    path = write_policy(tmp_path / "p.json", stricter_doc())
    sign_policy(path, key, now=T0)
    path.write_text(path.read_text().replace("16384", "16385"))
    assert verify_policy(path, [pub], now=T0).reason == "digest_mismatch"
    _assert_fallback(load_policy_file(path, trusted_keys=[pub], now=T0), "digest_mismatch")


def test_ut_policy_sign_004_unsigned(tmp_path: Path, keydir: Path) -> None:
    pub = keygen(keydir / "policy.key")
    path = write_policy(tmp_path / "p.json", stricter_doc())
    assert verify_policy(path, [pub], now=T0).reason == "unsigned"
    _assert_fallback(load_policy_file(path, trusted_keys=[pub], now=T0), "unsigned")


def test_ut_policy_sign_005_unpinned_key_or_forged_signature(keydir: Path, tmp_path: Path) -> None:
    pinned = keygen(keydir / "pinned.key")
    other = keydir / "other.key"
    keygen(other)
    path = write_policy(tmp_path / "p.json", stricter_doc())
    sign_policy(path, other, now=T0)
    assert verify_policy(path, [pinned], now=T0).reason == "unknown_key"
    sig_path = path.with_name(path.name + ".sig")
    sign_policy(path, keydir / "pinned.key", now=T0)
    forged = json.loads(sig_path.read_text())
    forged["signed_at"] += 1  # signed fields changed after signing
    sig_path.write_text(json.dumps(forged))
    assert verify_policy(path, [pinned], now=T0).reason == "bad_signature"
    _assert_fallback(load_policy_file(path, trusted_keys=[pinned], now=T0), "bad_signature")
    with pytest.raises(ValueError, match="trusted_keys"):
        load_policy_file(path, trusted_keys=[], now=T0)


# --- UT-POLICY-SIGN-006/007: weakening needs a 24 h delay (D52) ---------------------------


def test_ut_policy_sign_006_weakenings_classified() -> None:
    from mnemowall.policy import compile_policy

    assert weakenings(compile_policy(stricter_doc())) == ()
    assert weakenings(compile_policy(weaker_doc())) == ("rule_removed:no-external-payment-sinks",)
    doc = builtin_policy_document()
    doc["defaults"]["mode"] = "shadow"
    doc["defaults"]["shadow_expires_at"] = "2099-01-01T00:00:00Z"
    doc["defaults"]["quarantine_ttl"] = "14d"
    doc["read"]["wrap"]["below_trust"] = "user"
    doc["rules"][1]["then"] = "quarantine"  # shared-scope-requires-grant: deny -> quarantine
    doc["rules"][0]["when"]["signals_any"] = ["S3.iban"]
    doc["failure_modes"]["adapter_probe_failure"] = "warn_only"
    found = set(weakenings(compile_policy(doc)))
    stricter = builtin_policy_document()
    stricter["failure_modes"]["tainted_write"] = "refuse"
    stricter["read"]["wrap"]["below_trust"] = "operator"
    assert weakenings(compile_policy(stricter)) == ()
    assert found == {
        "mode:shadow",
        "quarantine_ttl",
        "read.wrap_below_trust",
        "rule_weakened:shared-scope-requires-grant",
        "rule_changed:no-external-payment-sinks",
        "failure_modes.adapter_probe_failure",
    }


def test_ut_policy_sign_006_weakening_waits_24h(keydir: Path, tmp_path: Path) -> None:
    key = keydir / "policy.key"
    pub = keygen(key)
    path = write_policy(tmp_path / "p.json", weaker_doc())
    sign_policy(path, key, now=T0)
    early = verify_policy(path, [pub], now=T0 + DELAY_S - 1)
    assert (early.ok, early.reason) == (False, "not_yet_valid")
    _assert_fallback(load_policy_file(path, trusted_keys=[pub], now=T0 + 60), "not_yet_valid")
    later = verify_policy(path, [pub], now=T0 + DELAY_S)
    assert later.ok
    assert later.loosenings == ("rule_removed:no-external-payment-sinks",)
    policy = load_policy_file(path, trusted_keys=[pub], now=T0 + DELAY_S)
    assert policy.id == "acme-weaker"
    assert "rule_removed:no-external-payment-sinks" in policy.loosenings


def test_ut_policy_sign_007_weakening_signed_without_delay_refused(
    keydir: Path, tmp_path: Path
) -> None:
    key = keydir / "policy.key"
    pub = keygen(key)
    path = write_policy(tmp_path / "p.json", weaker_doc())
    sign_policy(path, key, now=T0, _not_before=T0)  # a hand-made signature with no delay
    check = verify_policy(path, [pub], now=T0 + 10 * DELAY_S)
    assert (check.ok, check.reason) == (False, "weakening_without_delay")


# --- UT-POLICY-SIGN-008: parse errors, YAML safety -----------------------------------------


def test_ut_policy_sign_008_unparseable_or_invalid_signed_policy(
    keydir: Path, tmp_path: Path
) -> None:
    key = keydir / "policy.key"
    pub = keygen(key)
    bad = tmp_path / "p.yaml"
    bad.write_text("!!python/object/apply:os.system ['echo pwned']\n")
    sign_policy(bad, key, now=T0)
    assert verify_policy(bad, [pub], now=T0).reason == "unparseable"
    invalid = write_policy(tmp_path / "q.json", {"apiVersion": "nope"})
    sign_policy(invalid, key, now=T0)
    assert verify_policy(invalid, [pub], now=T0).reason == "invalid"
    _assert_fallback(load_policy_file(invalid, trusted_keys=[pub], now=T0), "invalid")


# --- UT-POLICY-SIGN-009: canaries -----------------------------------------------------------


def test_ut_policy_sign_009_errors_carry_no_content(
    keydir: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    key = keydir / "policy.key"
    pub = keygen(key)
    doc = stricter_doc()
    doc[CANARY] = CANARY
    path = write_policy(tmp_path / "p.json", doc)
    sign_policy(path, key, now=T0)
    with caplog.at_level("DEBUG", logger="mnemowall"):
        check = verify_policy(path, [pub], now=T0)
        load_policy_file(path, trusted_keys=[pub], now=T0)
    assert check.reason == "invalid"
    assert CANARY not in repr(check)
    assert CANARY not in caplog.text


# --- UT-POLICY-SIGN-010: CLI ----------------------------------------------------------------


def test_ut_policy_sign_010_cli(
    keydir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key = keydir / "policy.key"
    assert cli.main(["policy", "keygen", "--out", str(key)]) == 0
    pub = capsys.readouterr().out.strip().splitlines()[-1].split()[-1]
    assert pub.startswith("ed25519:")
    path = write_policy(tmp_path / "p.json", stricter_doc())
    assert cli.main(["policy", "sign", str(path), "--key", str(key)]) == 0
    capsys.readouterr()
    assert cli.main(["policy", "verify", str(path), "--trusted-key", pub]) == 0
    assert "ok" in capsys.readouterr().out
    path.write_text(path.read_text() + " ")
    assert cli.main(["policy", "verify", str(path), "--trusted-key", pub]) == 1
    assert "digest_mismatch" in capsys.readouterr().out
    weak = write_policy(tmp_path / "w.json", weaker_doc())
    assert cli.main(["policy", "sign", str(weak), "--key", str(key)]) == 0
    assert "24 h" in capsys.readouterr().out


# --- UT-POLICY-SIGN-011: the only YAML entry point is safe_load ------------------------------


def test_ut_policy_sign_011_yaml_safe_load_only() -> None:
    import ast

    import mnemowall.policyfile

    tree = ast.parse(Path(mnemowall.policyfile.__file__).read_text(encoding="utf-8"))
    used = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "yaml"
    }
    assert used == {"safe_load"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            names = {a.name for a in node.names} | {getattr(node, "module", None) or ""}
            assert not names & {"importlib", "pickle", "marshal", "subprocess"}
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"eval", "exec", "compile", "__import__"}


def test_ut_policy_sign_001_loose_key_file_refused(keydir: Path, tmp_path: Path) -> None:
    key = keydir / "policy.key"
    keygen(key)
    key.chmod(0o644)
    path = write_policy(tmp_path / "p.json", stricter_doc())
    with pytest.raises(PolicySignError) as exc:
        sign_policy(path, key, now=T0)
    assert exc.value.reason == "insecure_permissions"
    assert not path.with_name("p.json.sig").exists()
