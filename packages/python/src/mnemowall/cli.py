"""The ``mnemowall`` command line. M1a-12 adds ``keys init|rotate|status``.

Output never includes key material; errors print fixed reason codes only.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from mnemowall.keys import (
    FileKeyProvider,
    KeychainKeyProvider,
    KeyProvider,
    KeysExist,
    KeyUnavailable,
    default_provider,
    status_lines,
)


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
        p = actions.add_parser(action, help=text)
        p.add_argument(
            "--provider",
            choices=["auto", "file", "keychain"],
            default="auto",
            help="auto = keychain if the 'keychain' extra is installed, else file",
        )
        p.add_argument("--path", type=Path, help="key file (file provider only)")
    return parser


def _provider(args: argparse.Namespace, parser: argparse.ArgumentParser) -> KeyProvider:
    if args.path is not None and args.provider == "keychain":
        parser.error("--path applies to the file provider only")
    if args.provider == "file" or (args.provider == "auto" and args.path is not None):
        return FileKeyProvider(args.path)
    if args.provider == "keychain":
        return KeychainKeyProvider()
    return default_provider()


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    provider = _provider(args, parser)
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
