"""Key material and key providers (§3.6, §3.10; ADR-0020 D13-D15).

A :class:`KeySet` holds one active Ed25519 signing key, every public key ever used (rotation
never deletes one, so old versions keep verifying) and one 256-bit storage secret. Separate
keys for ledger, quarantine and buffer encryption and for content HMACs are derived from the
storage secret with HKDF-SHA-256, one per :class:`Purpose`.

Providers store the key set as one JSON document:

* :class:`KeychainKeyProvider` uses the OS keychain through the optional ``mnemowall[keychain]``
  extra (``keyring``);
* :class:`FileKeyProvider` writes a 0600 file in a 0700 directory and refuses a path inside a git
  worktree, a symlink, or loose permissions;
* :class:`EphemeralKeyProvider` keeps keys in memory, for tests and ``make demo`` only.

**Limitation (D14):** signing happens in the SDK's own process in M1a. An agent that can run code
in that process can read the key and produce valid signatures. A separate signer process ships
with the gate (M2).

Errors carry fixed reason codes only; key bytes never appear in ``repr``, logs or exceptions.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import stat
import sys
import tempfile
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, NoReturn, Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from mnemowall._log import get_logger
from mnemowall.core import diagnostics

FORMAT: Final = "mnemowall/keys/v1"
KEY_ID_PREFIX: Final = "ed25519-"
STORAGE_SECRET_BYTES: Final = 32
_HKDF_SALT: Final = b"mnemowall/storage/v1"
_HEX: Final = frozenset("0123456789abcdef")

_log = get_logger("keys")


class Purpose(StrEnum):
    """What a derived storage key is for. Each purpose gets an independent 256-bit key."""

    LEDGER_ENC = "ledger-enc"
    QUARANTINE_ENC = "quarantine-enc"
    BUFFER_ENC = "buffer-enc"
    CONTENT_HMAC = "content-hmac"


class KeyUnavailable(Exception):
    """Keys can't be loaded. ``reason`` is a fixed code, safe to log and show."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class KeysNotInitialized(KeyUnavailable):
    """No key set exists yet; run ``mnemowall keys init``."""

    def __init__(self) -> None:
        super().__init__("not_initialized")


class KeysExist(Exception):
    """``init`` found an existing key set; replacing the signing key is ``rotate``."""

    def __init__(self) -> None:
        super().__init__("keys_exist")


def key_id_for(public: Ed25519PublicKey) -> str:
    """Public fingerprint: ``ed25519-`` + the first 16 bytes (hex) of SHA-256(raw public key)."""
    return KEY_ID_PREFIX + hashlib.sha256(public.public_bytes_raw()).digest()[:16].hex()


def is_key_id(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith(KEY_ID_PREFIX):
        return False
    tail = value[len(KEY_ID_PREFIX) :]
    return len(tail) == 32 and set(tail) <= _HEX


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: object) -> bytes:
    if not isinstance(text, str):
        raise TypeError("expected base64 text")
    return base64.b64decode(text.encode("ascii"), validate=True)


class KeySet:
    """An active signing key, all retained public keys and the storage secret."""

    __slots__ = ("_active", "_derived", "_public", "_signing", "_storage")

    def __init__(
        self,
        signing: Ed25519PrivateKey,
        public_keys: Mapping[str, Ed25519PublicKey],
        storage_secret: bytes,
    ) -> None:
        if len(storage_secret) != STORAGE_SECRET_BYTES:
            raise ValueError("storage secret must be 32 bytes")
        active = key_id_for(signing.public_key())
        pubs = dict(public_keys)
        pubs.setdefault(active, signing.public_key())
        for kid, pub in pubs.items():
            if key_id_for(pub) != kid:
                raise ValueError("public key does not match its key id")
        self._signing = signing
        self._active = active
        self._public: Mapping[str, Ed25519PublicKey] = MappingProxyType(pubs)
        self._storage = bytes(storage_secret)
        self._derived: dict[Purpose, bytes] = {}

    @classmethod
    def generate(cls) -> KeySet:
        return cls(Ed25519PrivateKey.generate(), {}, os.urandom(STORAGE_SECRET_BYTES))

    def rotated(self) -> KeySet:
        """A new active signing key; every existing public key and the storage secret are kept."""
        return KeySet(Ed25519PrivateKey.generate(), self._public, self._storage)

    @property
    def active_key_id(self) -> str:
        return self._active

    @property
    def public_keys(self) -> Mapping[str, Ed25519PublicKey]:
        """Read-only map of key id to public key, including retired keys."""
        return self._public

    def sign(self, message: bytes) -> tuple[str, bytes]:
        """Sign ``message`` with the active key. Returns ``(key_id, 64-byte signature)``."""
        return self._active, self._signing.sign(message)

    def derive(self, purpose: Purpose) -> bytes:
        """The 32-byte key for ``purpose`` (HKDF-SHA-256 over the storage secret)."""
        key = self._derived.get(purpose)
        if key is None:
            key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=_HKDF_SALT,
                info=b"mnemowall/" + Purpose(purpose).value.encode("ascii"),
            ).derive(self._storage)
            self._derived[purpose] = key
        return key

    def __repr__(self) -> str:
        return f"KeySet(active_key_id={self._active!r}, public_keys={len(self._public)})"

    __str__ = __repr__

    def __reduce__(self) -> NoReturn:
        raise TypeError("KeySet is not serializable")

    def _to_document(self) -> str:
        doc = {
            "format": FORMAT,
            "active": self._active,
            "signing_key": _b64(self._signing.private_bytes_raw()),
            "public_keys": {kid: _b64(p.public_bytes_raw()) for kid, p in self._public.items()},
            "storage_secret": _b64(self._storage),
        }
        return json.dumps(doc, sort_keys=True)

    @classmethod
    def _from_document(cls, text: str) -> KeySet:
        """Parse a stored document; any inconsistency raises ``ValueError`` (no detail)."""
        try:
            doc = json.loads(text)
            if not isinstance(doc, dict) or doc.get("format") != FORMAT:
                raise ValueError("format")
            signing = Ed25519PrivateKey.from_private_bytes(_unb64(doc["signing_key"]))
            raw_pubs = doc["public_keys"]
            if not isinstance(raw_pubs, dict):
                raise ValueError("public_keys")
            pubs = {
                kid: Ed25519PublicKey.from_public_bytes(_unb64(b64))
                for kid, b64 in raw_pubs.items()
            }
            active = doc["active"]
            # The active entry must be this signing key's public key; KeySet() then checks that
            # every key id matches its public key.
            if active not in pubs:
                raise ValueError("active")
            if pubs[active].public_bytes_raw() != signing.public_key().public_bytes_raw():
                raise ValueError("active")
            return cls(signing, pubs, _unb64(doc["storage_secret"]))
        except (ValueError, TypeError, KeyError, AttributeError):  # incl. binascii.Error
            raise ValueError("key_store_corrupt") from None


class KeyProvider(Protocol):
    """Where a :class:`KeySet` is stored. ``production_ready`` is false only for ephemeral keys."""

    name: str
    production_ready: bool

    def load(self) -> KeySet: ...
    def load_or_none(self) -> KeySet | None: ...
    def init(self) -> KeySet: ...
    def rotate(self) -> KeySet: ...


def _unavailable(provider: str, reason: str) -> KeyUnavailable:
    diagnostics.record("key_unavailable")
    _log.warning("key_unavailable", extra={"provider": provider, "reason": reason})
    return KeyUnavailable(reason)


class _DocumentProvider:
    """Shared init/load/rotate over a single stored JSON document."""

    name: str = "base"
    production_ready: bool = True

    def _read(self) -> str | None:  # pragma: no cover - abstract
        raise NotImplementedError

    def _write(self, document: str) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def load_or_none(self) -> KeySet | None:
        text = self._read()
        if text is None:
            return None
        try:
            return KeySet._from_document(text)
        except ValueError:
            raise _unavailable(self.name, "key_store_corrupt") from None

    def load(self) -> KeySet:
        keys = self.load_or_none()
        if keys is None:
            raise KeysNotInitialized
        return keys

    def init(self) -> KeySet:
        if self.load_or_none() is not None:
            raise KeysExist
        keys = KeySet.generate()
        self._write(keys._to_document())
        _log.info("keys_initialized", extra={"provider": self.name, "key_id": keys.active_key_id})
        return keys

    def rotate(self) -> KeySet:
        keys = self.load().rotated()
        self._write(keys._to_document())
        _log.info(
            "keys_rotated",
            extra={
                "provider": self.name,
                "key_id": keys.active_key_id,
                "count": len(keys.public_keys),
            },
        )
        return keys


def default_key_path() -> Path:
    """Per-user data directory: ``~/Library/Application Support`` on macOS, XDG elsewhere."""
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        xdg = os.environ.get("XDG_DATA_HOME")
        base = Path(xdg) if xdg and Path(xdg).is_absolute() else Path.home() / ".local" / "share"
    return base / "mnemowall" / "keys.json"


class FileKeyProvider(_DocumentProvider):
    """Keys in a 0600 file inside a 0700 directory owned by the current user (POSIX only)."""

    name = "file"

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path).absolute() if path is not None else default_key_path()

    def __repr__(self) -> str:
        return f"FileKeyProvider(path={str(self._path)!r})"

    @property
    def path(self) -> Path:
        return self._path

    def _check(self) -> None:
        if os.name != "posix":
            raise _unavailable(self.name, "file_provider_requires_posix")
        parent = self._path.parent
        for ancestor in (parent, *parent.parents):
            if os.path.lexists(ancestor / ".git"):
                raise _unavailable(self.name, "inside_git_worktree")
        uid = os.getuid()
        for target, is_dir in ((parent, True), (self._path, False)):
            try:
                st = os.lstat(target)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(st.st_mode):
                raise _unavailable(self.name, "symlink")
            kind_ok = stat.S_ISDIR(st.st_mode) if is_dir else stat.S_ISREG(st.st_mode)
            if not kind_ok:
                raise _unavailable(self.name, "not_a_regular_path")
            if st.st_uid != uid or stat.S_IMODE(st.st_mode) & 0o077:
                raise _unavailable(self.name, "insecure_permissions")

    def _read(self) -> str | None:
        self._check()
        try:
            fd = os.open(self._path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return None
        except OSError:
            raise _unavailable(self.name, "read_error") from None
        try:
            with os.fdopen(fd, "rb") as fh:
                data = fh.read()
        except OSError:
            raise _unavailable(self.name, "read_error") from None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise _unavailable(self.name, "key_store_corrupt") from None

    def _write(self, document: str) -> None:
        self._check()
        parent = self._path.parent
        try:
            parent.parent.mkdir(parents=True, exist_ok=True)
            with contextlib.suppress(FileExistsError):
                parent.mkdir(mode=0o700)
        except OSError:
            raise _unavailable(self.name, "write_error") from None
        self._check()
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(dir=parent, prefix=".keys.", suffix=".tmp")
            with os.fdopen(fd, "wb") as fh:
                fh.write(document.encode("utf-8"))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
            tmp = None
            dir_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            raise _unavailable(self.name, "write_error") from None
        finally:
            if tmp is not None:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)


class KeychainKeyProvider(_DocumentProvider):
    """Keys in the OS keychain via ``keyring`` (``pip install 'mnemowall[keychain]'``).

    ``backend`` is any object with ``get_password``/``set_password`` (tests pass a fake).
    """

    name = "keychain"

    def __init__(
        self, backend: Any | None = None, *, service: str = "mnemowall", account: str = "default"
    ) -> None:
        self._backend_override = backend
        self._service = service
        self._account = account

    def __repr__(self) -> str:
        return f"KeychainKeyProvider(service={self._service!r}, account={self._account!r})"

    def _backend(self) -> Any:
        if self._backend_override is not None:
            return self._backend_override
        try:
            import keyring  # optional extra, imported only when used
        except ImportError:
            raise _unavailable(self.name, "keychain_extra_not_installed") from None
        return keyring

    def _read(self) -> str | None:
        backend = self._backend()
        try:
            value = backend.get_password(self._service, self._account)
        except Exception:  # noqa: BLE001 - keyring backends raise arbitrary types; none are shown
            raise _unavailable(self.name, "keychain_error") from None
        if value is not None and not isinstance(value, str):
            raise _unavailable(self.name, "key_store_corrupt")
        return value

    def _write(self, document: str) -> None:
        backend = self._backend()
        try:
            backend.set_password(self._service, self._account, document)
        except Exception:  # noqa: BLE001 - see _read
            raise _unavailable(self.name, "keychain_error") from None


class _Sealed:
    """Holds a secret string without exposing it through ``repr`` or ``vars``."""

    __slots__ = ("value",)

    def __init__(self, value: str) -> None:
        self.value = value

    def __repr__(self) -> str:
        return "<sealed>"


class EphemeralKeyProvider(_DocumentProvider):
    """In-memory keys for tests and ``make demo``. Not for production: they vanish on exit."""

    name = "ephemeral"
    production_ready = False

    def __init__(self) -> None:
        self._doc: _Sealed | None = None

    def __repr__(self) -> str:
        return "EphemeralKeyProvider()"

    def _read(self) -> str | None:
        return None if self._doc is None else self._doc.value

    def _write(self, document: str) -> None:
        self._doc = _Sealed(document)


def default_provider() -> KeyProvider:
    """The keychain when the ``keychain`` extra is installed, otherwise the file provider."""
    try:
        import keyring  # noqa: F401 - availability probe only
    except ImportError:
        return FileKeyProvider()
    return KeychainKeyProvider()


def status_lines(provider: KeyProvider) -> list[str]:
    """Human-readable key status for ``mnemowall keys status`` and ``doctor``. No secrets."""
    keys = provider.load()
    lines = [
        f"provider: {provider.name}",
        f"active key: {keys.active_key_id}",
        f"public keys: {len(keys.public_keys)}",
        "note: signing runs in this process; an agent that can run code here can read the key"
        " (ADR-0020 D14)",
    ]
    if not provider.production_ready:
        lines.insert(
            0, "WARNING: ephemeral keys are not for production; they vanish when the process exits"
        )
    return lines
