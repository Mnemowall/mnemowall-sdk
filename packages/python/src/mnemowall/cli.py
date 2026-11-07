"""The ``mnemowall`` command line.

* ``keys init|rotate|status`` (M1a-12)
* ``review list|show|approve|reject|promote|cancel|complete`` (M1a-14)

Output never includes key material. ``review list`` shows no content; ``review show`` prints
content through :func:`mnemowall.core.render.render_untrusted`, so terminal escapes, bidi
overrides and invisible characters are shown, not interpreted (§3.13). Errors print fixed reason
codes only.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from mnemowall.core.files import PrivatePathError, private_dir
from mnemowall.core.render import render_untrusted
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
        p.add_argument("--data-dir", type=Path, help="local data directory (ledger, quarantine)")
        p.add_argument("--tenant", default="default", help="tenant id (default: default)")
        _key_args(p)
    return parser


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


def _review(args: argparse.Namespace, provider: KeyProvider) -> int:
    data: Path = args.data_dir or default_key_path().parent / "data"
    try:
        private_dir(data)
        ledger = Ledger.open(data / "ledger.db", provider, tenant_id=args.tenant)
    except (PrivatePathError, LedgerError) as exc:
        print(f"ledger unavailable: {exc.reason}", file=sys.stderr)
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
    provider = _provider(args, parser)
    if args.command == "keys":
        return _keys(args, provider)
    return _review(args, provider)
