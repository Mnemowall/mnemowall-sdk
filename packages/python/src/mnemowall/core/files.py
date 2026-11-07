"""Private on-disk files for local stores: 0700 directories, 0600 files, no symlinks.

Errors carry a fixed reason code only.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


class PrivatePathError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _check(st: os.stat_result, *, want_dir: bool) -> None:
    if stat.S_ISLNK(st.st_mode):
        raise PrivatePathError("symlink")
    kind_ok = stat.S_ISDIR(st.st_mode) if want_dir else stat.S_ISREG(st.st_mode)
    if not kind_ok:
        raise PrivatePathError("not_a_regular_path")
    if os.name == "posix" and (stat.S_IMODE(st.st_mode) & 0o077 or st.st_uid != os.getuid()):
        raise PrivatePathError("insecure_permissions")


def private_dir(path: Path) -> Path:
    """Create ``path`` as a 0700 directory, or check that an existing one is private."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            return private_dir(path)
        except OSError:
            raise PrivatePathError("create_failed") from None
        st = os.lstat(path)
    _check(st, want_dir=True)
    return path


def private_file(path: Path) -> Path:
    """Create ``path`` as an empty 0600 file, or check that an existing one is private."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return private_file(path)
        except OSError:
            raise PrivatePathError("create_failed") from None
        os.close(fd)
        st = os.lstat(path)
    _check(st, want_dir=False)
    return path
