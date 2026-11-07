"""The ``mnemowall`` command line.

* ``keys init|rotate|status`` (M1a-12)
* ``review list|show|approve|reject|promote|cancel|complete`` (M1a-14)
* ``incident MEMORY_ID VERSION`` (M1a-20)
* ``export --jsonl``, ``verify-ledger``, ``doctor`` (M1a-21)
* ``redteam [--unprotected]`` (M1a-23)

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


def _redteam(args: argparse.Namespace) -> int:
    from mnemowall.redteam import run_pack  # needs the langgraph extra

    report = run_pack(protected=not args.unprotected)
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
