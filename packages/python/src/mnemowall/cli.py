"""The ``mnemowall`` command line.

* ``keys init|rotate|status`` (M1a-12)
* ``review list|show|approve|reject|promote|cancel|complete`` (M1a-14)
* ``incident MEMORY_ID VERSION`` (M1a-20)
* ``export --jsonl``, ``verify-ledger``, ``doctor`` (M1a-21)
* ``redteam [--unprotected] [--benign] [--sample N]`` (M1a-23, M1b-09)
* ``policy keygen|sign|verify`` (M1b-06): locally signed policy files

Output never includes key material. ``review list`` shows no content; ``review show`` prints
content through :func:`mnemowall.core.render.render_untrusted`, so terminal escapes, bidi
overrides and invisible characters are shown, not interpreted (§3.13). Errors print fixed reason
codes only.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mnemowall.core.files import PrivatePathError, private_dir
from mnemowall.core.render import render_untrusted
from mnemowall.doctor import exit_code, run_checks
from mnemowall.incident import IncidentError, incident_report
from mnemowall.keys import (
    FileKeyProvider,
    KeychainKeyProvider,
    KeyProvider,
    KeysExist,
    KeyUnavailable,
    default_key_path,
    default_provider,
    status_lines,
)
from mnemowall.ledger import Ledger, LedgerError
from mnemowall.ledger.export import export_jsonl, verify_export
from mnemowall.policy import load_policy
from mnemowall.quarantine import ItemSummary, Quarantine, QuarantineError

_REVIEW = (
    ("list", False, "list pending quarantined writes (no content)"),
    ("show", True, "show one item, with hidden characters made visible"),
    ("approve", True, "commit the item as data, with its original trust (I8)"),
    ("reject", True, "reject the item; it never commits"),
    ("promote", True, "request promotion to an instruction; completes after the delay (>= 24 h)"),
    ("cancel", True, "cancel a pending promotion"),
    ("complete", True, "complete a promotion whose delay has passed"),
)


def _key_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--provider",
        choices=["auto", "file", "keychain"],
        default="auto",
        help="auto = keychain if the 'keychain' extra is installed, else file",
    )
    p.add_argument("--path", type=Path, help="key file (file provider only)")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mnemowall", description="Mnemowall SDK tools.")
    sub = parser.add_subparsers(dest="command", required=True)
    keys = sub.add_parser("keys", help="manage signing and storage keys")
    actions = keys.add_subparsers(dest="action", required=True)
    for action, text in (
        ("init", "create a signing key and a storage secret (refuses if keys exist)"),
        ("rotate", "replace the signing key; old public keys are kept for verification"),
        ("status", "show the provider, active key id and retained public keys"),
    ):
        _key_args(actions.add_parser(action, help=text))
    review = sub.add_parser("review", help="review quarantined writes")
    review_actions = review.add_subparsers(dest="action", required=True)
    for action, needs_id, text in _REVIEW:
        p = review_actions.add_parser(action, help=text)
        if needs_id:
            p.add_argument("item_id")
        _data_args(p)
    inc = sub.add_parser("incident", help="list every session that read a memory version")
    inc.add_argument("memory_id")
    inc.add_argument("version", type=int)
    _data_args(inc)
    exp = sub.add_parser("export", help="export the ledger as tamper-evident evidence")
    exp.add_argument(
        "--jsonl", action="store_true", required=True, help="JSON Lines (the only format)"
    )
    exp.add_argument(
        "--out", type=Path, required=True, help="new file to write (never overwritten)"
    )
    _data_args(exp)
    ver = sub.add_parser("verify-ledger", help="verify the ledger (or an export) end to end")
    ver.add_argument(
        "--expected-head", help="SEQ:HASH from an earlier export; catches deleted entries"
    )
    ver.add_argument(
        "--export", type=Path, help="verify this export offline instead of the live ledger"
    )
    _data_args(ver)
    doc = sub.add_parser("doctor", help="report unsafe or degraded settings")
    _data_args(doc)
    rt = sub.add_parser(
        "redteam", help="run the red-team poisoning pack (needs the langgraph extra)"
    )
    rt.add_argument("--unprotected", action="store_true", help="run against a plain store")
    rt.add_argument("--benign", action="store_true", help="measure false positives instead")
    rt.add_argument("--sample", type=int, default=None, help="first N items per class/category")
    pol = sub.add_parser("policy", help="sign and verify local policy files")
    pol_actions = pol.add_subparsers(dest="action", required=True)
    kg = pol_actions.add_parser("keygen", help="create a policy-signing key (keep it off servers)")
    kg.add_argument("--out", type=Path, required=True, help="where to write the private key")
    sg = pol_actions.add_parser("sign", help="sign a policy file (writes FILE.sig)")
    sg.add_argument("file", type=Path)
    sg.add_argument("--key", type=Path, required=True, help="the policy-signing key")
    vf = pol_actions.add_parser("verify", help="check a signed policy file")
    vf.add_argument("file", type=Path)
    vf.add_argument(
        "--trusted-key", action="append", required=True, help="a pinned public key (repeatable)"
    )
    return parser


def _data_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--data-dir", type=Path, help="local data directory (ledger, quarantine)")
    p.add_argument("--tenant", default="default", help="tenant id (default: default)")
    _key_args(p)


def _provider(args: argparse.Namespace, parser: argparse.ArgumentParser) -> KeyProvider:
    if args.path is not None and args.provider == "keychain":
        parser.error("--path applies to the file provider only")
    if args.provider == "file" or (args.provider == "auto" and args.path is not None):
        return FileKeyProvider(args.path)
    if args.provider == "keychain":
        return KeychainKeyProvider()
    return default_provider()


def _when(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, UTC).strftime("%Y-%m-%d %H:%M UTC")


def _line(item: ItemSummary) -> str:
    promo = f"  promotion due {_when(item.promotion_due_ms)}" if item.promotion_due_ms else ""
    return (
        f"{item.item_id}  {item.status}  age {item.age_s // 3600}h"
        f"  expires {_when(item.expires_ms)}"
        f"  trust {item.trust_level}  type {item.memory_type}"
        f"  rules {','.join(item.rule_ids) or '-'}{promo}"
    )


def _keys(args: argparse.Namespace, provider: KeyProvider) -> int:
    try:
        if args.action == "init":
            keys = provider.init()
            print(f"initialized {provider.name} keys; active key {keys.active_key_id}")
        elif args.action == "rotate":
            keys = provider.rotate()
            print(
                f"rotated; active key {keys.active_key_id};"
                f" {len(keys.public_keys)} public keys kept for verification"
            )
        else:
            print("\n".join(status_lines(provider)))
    except KeysExist:
        print(
            "keys already exist; use `mnemowall keys rotate` to replace the signing key",
            file=sys.stderr,
        )
        return 1
    except KeyUnavailable as exc:
        print(f"keys unavailable: {exc.reason}", file=sys.stderr)
        return 2
    return 0


def _review_action(action: str, item_id: str | None, q: Quarantine) -> int:
    if action == "list":
        items = q.list()
        print("\n".join(_line(i) for i in items) if items else "no pending items")
        return 0
    if item_id is None:  # argparse requires it for every other action
        raise QuarantineError("not_found")
    if action == "show":
        d = q.show(item_id)
        print(_line(d.summary))
        print(f"signals: {', '.join(d.summary.fired_signals) or '-'}")
        print(f"namespace: {render_untrusted(' / '.join(d.namespace))}")
        print(f"key: {render_untrusted(d.key)}")
        print("content (untrusted; hidden characters shown as \\u{hex}):")
        print(render_untrusted(d.content))
    elif action == "approve":
        rec = q.approve(item_id)
        print(f"approved as data; memory {rec.memory_id} version {rec.version_no}")
        print("the store gets it on the adapter's next deliver_reviewed()")
    elif action == "reject":
        q.reject(item_id)
        print("rejected")
    elif action == "promote":
        due = q.promote(item_id)
        print(
            f"promotion requested; it can be completed after {_when(due)}."
            f" Cancel with `mnemowall review cancel {item_id}`."
        )
    elif action == "cancel":
        q.cancel_promotion(item_id)
        print("promotion cancelled")
    else:
        rec = q.complete_promotion(item_id)
        print(
            f"promoted to {rec.fields.effective_type}; memory {rec.memory_id}"
            f" version {rec.version_no}"
        )
    return 0


def _data_dir(args: argparse.Namespace) -> Path:
    data: Path = args.data_dir or default_key_path().parent / "data"
    return data


def _open_ledger(args: argparse.Namespace, provider: KeyProvider) -> Ledger | None:
    try:
        private_dir(_data_dir(args))
        return Ledger.open(_data_dir(args) / "ledger.db", provider, tenant_id=args.tenant)
    except (PrivatePathError, LedgerError) as exc:
        print(f"ledger unavailable: {exc.reason}", file=sys.stderr)
        return None


def _incident(args: argparse.Namespace, provider: KeyProvider) -> int:
    ledger = _open_ledger(args, provider)
    if ledger is None:
        return 2
    try:
        r = incident_report(ledger, args.memory_id, args.version)
    except IncidentError as exc:
        print(f"incident: {exc.reason}", file=sys.stderr)
        return 1
    finally:
        ledger.close()
    print(
        f"memory {r.memory_id} version {r.version_no}: trust {r.trust_level},"
        f" type {r.effective_type}, verified {'yes' if r.verified else 'NO'}"
    )
    print(f"read by {len(r.sessions)} session(s):")
    for read in r.reads:
        flags = (
            ""
            if read.verified and not read.stale
            else " (unverified)"
            if not read.verified
            else " (stale)"
        )
        print(f"  {_when(read.ts_ms)}  {read.session_id}  shown as {read.label}{flags}")
    if r.purged_read_events:
        print(f"  {r.purged_read_events} later read event(s) were removed by retention; not shown")
    later = ", ".join(str(v) for v in r.later_versions) or "none"
    print(f"later versions: {later} (head: {r.head_version})")
    return 0


def _review(args: argparse.Namespace, provider: KeyProvider) -> int:
    data = _data_dir(args)
    ledger = _open_ledger(args, provider)
    if ledger is None:
        return 2
    try:
        q = Quarantine.open(
            data / "quarantine",
            provider,
            ledger=ledger,
            policy=load_policy(),
            tenant_id=args.tenant,
        )
    except QuarantineError as exc:
        ledger.close()
        print(f"quarantine unavailable: {exc.reason}", file=sys.stderr)
        return 2
    try:
        return _review_action(args.action, getattr(args, "item_id", None), q)
    except QuarantineError as exc:
        print(f"review refused: {exc.reason}", file=sys.stderr)
        return 1
    except LedgerError as exc:
        print(f"ledger unavailable: {exc.reason}", file=sys.stderr)
        return 2
    finally:
        q.close()
        ledger.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "redteam":
        return _redteam(args)
    if args.command == "policy":
        return _policy(args)
    provider = _provider(args, parser)
    if args.command == "keys":
        return _keys(args, provider)
    if args.command == "incident":
        return _incident(args, provider)
    if args.command == "export":
        return _export(args, provider)
    if args.command == "verify-ledger":
        return _verify_ledger(args, provider)
    if args.command == "doctor":
        return _doctor(args, provider)
    return _review(args, provider)


def _policy(args: argparse.Namespace) -> int:
    from mnemowall.policyfile import (
        DELAY_S,
        PolicySignError,
        keygen,
        sign_policy,
        verify_policy,
    )

    try:
        if args.action == "keygen":
            pub = keygen(args.out)
            print("policy-signing key written; pin this public key in your app's config:")
            print(f"trusted key: {pub}")
            return 0
        if args.action == "sign":
            sig = sign_policy(args.file, args.key)
            doc = _read_json(sig)
            print(f"signed: {sig.name}")
            if int(doc["not_before"]) - int(doc["signed_at"]) >= DELAY_S:
                print(
                    "this policy is weaker than the built-in default:"
                    " it takes effect 24 h after signing"
                )
            return 0
        check = verify_policy(args.file, args.trusted_key)
    except PolicySignError as exc:
        print(f"error: {exc.reason}", file=sys.stderr)
        return 2
    except ValueError:
        print("error: invalid_trusted_key", file=sys.stderr)
        return 2
    print(f"{check.reason}" + (f" (key {check.key_id})" if check.key_id else ""))
    for item in check.loosenings:
        print(f"  weaker than default: {item}")
    return 0 if check.ok else 1


def _read_json(path: Path) -> dict[str, Any]:
    import json

    doc = json.loads(path.read_text())
    return doc if isinstance(doc, dict) else {}


def _redteam(args: argparse.Namespace) -> int:
    from mnemowall.redteam import run_benign, run_pack  # needs the langgraph extra

    if args.sample is not None and args.sample < 1:
        print("redteam: --sample must be at least 1", file=sys.stderr)
        return 2
    if args.benign:
        print(run_benign(sample=args.sample).render())
        return 0  # a measurement, not a gate
    report = run_pack(protected=not args.unprotected, sample=args.sample)
    print(report.render())
    return 0 if report.passed else 1


def _export(args: argparse.Namespace, provider: KeyProvider) -> int:
    ledger = _open_ledger(args, provider)
    if ledger is None:
        return 2
    try:
        fd = os.open(args.out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        print("export: the output file exists; choose a new path", file=sys.stderr)
        ledger.close()
        return 1
    count = 0
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for line in export_jsonl(ledger):
            fh.write(line + "\n")
            count += 1
    head = ledger.signed_head()
    ledger.close()
    print(f"exported {count} lines to {args.out}")
    if head is not None:
        print(f"head {head[0]}:{head[1]}  (keep this somewhere else; pass it to --expected-head)")
    return 0


def _parse_head(text: str | None) -> tuple[int, str] | None:
    if text is None:
        return None
    seq, _, digest = text.partition(":")
    if not seq.isdigit() or len(digest) != 64:
        raise SystemExit("verify-ledger: --expected-head must be SEQ:HASH")
    return int(seq), digest


def _verify_ledger(args: argparse.Namespace, provider: KeyProvider) -> int:
    expected = _parse_head(args.expected_head)
    if args.export is not None:
        try:
            keys = provider.load().public_keys
        except KeyUnavailable as exc:
            print(f"keys unavailable: {exc.reason}; pin the verification keys", file=sys.stderr)
            return 2
        lines = args.export.read_text(encoding="utf-8").splitlines()
        report = verify_export(lines, keys, expected_head=expected)
    else:
        ledger = _open_ledger(args, provider)
        if ledger is None:
            return 2
        try:
            report = ledger.verify(expected_head=expected)
        except LedgerError as exc:
            print(f"ledger unavailable: {exc.reason}", file=sys.stderr)
            return 2
        finally:
            ledger.close()
    if report.ok:
        print(f"ok: {report.checked} entries verified")
        return 0
    print(f"FAILED at entry {report.failed_at}: {report.reason}")
    return 1


def _doctor(args: argparse.Namespace, provider: KeyProvider) -> int:
    ledger = _open_ledger(args, provider)
    quarantine = None
    if ledger is not None:
        try:
            quarantine = Quarantine.open(
                _data_dir(args) / "quarantine",
                provider,
                ledger=ledger,
                policy=load_policy(),
                tenant_id=args.tenant,
            )
        except QuarantineError as exc:
            print(f"quarantine unavailable: {exc.reason}", file=sys.stderr)
    findings = run_checks(
        provider=provider, ledger=ledger, quarantine=quarantine, policy=load_policy(), counters={}
    )
    for f in findings:
        print(f"{f.severity:7} {f.code}: {f.message}")
    print(
        "note: in-process counters (writes without a session, unverified reads, ...) are only"
        " visible to mnemowall.doctor.run_checks() inside your application"
    )
    if quarantine is not None:
        quarantine.close()
    if ledger is not None:
        ledger.close()
    return exit_code(findings) if ledger is not None else 2
