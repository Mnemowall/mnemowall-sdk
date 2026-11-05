"""Registrable domain (eTLD+1) from a pinned Public Suffix List snapshot (ADR-0018).

The snapshot ships inside the package and is never fetched at runtime (no default network).
Both the ICANN and PRIVATE sections are used, so ``a.github.io`` and ``b.github.io`` are different
registrable domains. Implements the PSL algorithm: exact, wildcard and exception rules, with the
implicit default rule ``*``.
"""

from __future__ import annotations

import functools
import gzip
import importlib.resources
from typing import Final

SNAPSHOT_COMMIT: Final = "9dfbe81931367b3f0af21035c36ae7eeb830dd88"  # publicsuffix/list, 2026-10-28
SNAPSHOT_SHA256: Final = "d3e6243b51695327984abb3e2a5aa7077096867f75121e031e6a5a3840ca8bcd"
MAX_NAME_LEN: Final = 253  # DNS limits (RFC 1035); longer "hosts" are rejected, not parsed
MAX_LABELS: Final = 127


def snapshot_bytes() -> bytes:
    """The unmodified upstream file (stored gzip-compressed; the pinned hash is of these bytes)."""
    path = importlib.resources.files("mnemowall.signals") / "data" / "public_suffix_list.dat.gz"
    return gzip.decompress(path.read_bytes())


@functools.cache
def _rules() -> tuple[frozenset[str], frozenset[str], frozenset[str], int]:
    exact: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()
    for raw in snapshot_bytes().decode("utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        rule = line.split()[0].lower()
        if rule.startswith("!"):
            exception.add(rule[1:])
        elif rule.startswith("*."):
            wildcard.add(rule[2:])
        else:
            exact.add(rule)
    longest = max(r.count(".") + 1 for r in exact | wildcard | exception) + 1  # +1 for "*."
    return frozenset(exact), frozenset(wildcard), frozenset(exception), longest


def _to_unicode(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            return label
    return label


def registrable_domain(domain: str | None) -> str | None:
    """eTLD+1 of ``domain`` (lowercased, in the input's own encoding), or ``None``."""
    if not domain or domain.startswith(".") or len(domain) > MAX_NAME_LEN:
        return None
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) > MAX_LABELS or any(not lbl for lbl in labels):
        return None
    uni = [_to_unicode(lbl) for lbl in labels]
    exact, wildcard, exception, longest = _rules()
    n = len(uni)
    suffix_len = 1  # default rule "*"
    # Only suffixes as long as the longest rule can match: O(1) work per host, never O(labels^2).
    for i in range(max(0, n - longest), n):
        candidate = ".".join(uni[i:])
        if candidate in exception:
            suffix_len = n - i - 1
            break
        if candidate in exact:
            suffix_len = n - i
            break
        if i + 1 < n and ".".join(uni[i + 1 :]) in wildcard:
            suffix_len = n - i
            break
    if suffix_len >= n:
        return None
    return ".".join(labels[n - suffix_len - 1 :])
