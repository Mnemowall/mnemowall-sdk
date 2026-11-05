"""S3: new sink strings (§3.5), M1a subset: URLs, emails, markdown/HTML image URLs with a query,
and IBANs (mod-97).

"New" means absent from the tenant allowlist and from trusted (>= user) turns in the session.
URLs compare by registrable domain from the pinned PSL snapshot. IP-literal hosts are always
new. Image URLs with a query string fire regardless of domain: they are the classic zero-click
exfiltration channel (SpAIware-style). Output is labels only; no extracted values.
"""

from __future__ import annotations

import dataclasses
import ipaddress
from collections.abc import Iterable
from typing import Any, Final
from urllib.parse import urlsplit

from mnemowall.core import regex
from mnemowall.signals import psl
from mnemowall.signals.base import SignalResult

_URL: Final = regex.compile(r"(?i)\b((?:https?|ftp)://[^\s<>\"'`]+|www\.[^\s<>\"'`]+)")
_MD_IMG: Final = regex.compile(r"!\[[^\]\n]{0,500}\]\(\s*<?([^\s)>]+)")
_HTML_IMG: Final = regex.compile(r"(?i)<img\b[^>\n]{0,500}?\bsrc\s*=\s*[\"']?([^\"'\s>]+)")
_EMAIL: Final = regex.compile(
    r"(?i)\b([a-z0-9._%+-]{1,64})@([a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+)\b"
)
_IBAN: Final = regex.compile(r"\b([A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]){11,30})\b")
_TRAILING: Final = ".,;:!?'\"]}>"
_RISK: Final = {
    "S3.md_image_query": 1.0,
    "S3.iban": 0.9,
    "S3.new_domain": 0.8,
    "S3.new_email": 0.8,
    "S3.ip_literal": 0.8,
}


@dataclasses.dataclass(frozen=True)
class KnownSinks:
    domains: frozenset[str] = dataclasses.field(repr=False)
    emails: frozenset[str] = dataclasses.field(repr=False)
    ibans: frozenset[str] = dataclasses.field(default=frozenset(), repr=False)


def _clean_url(u: str) -> str:
    u = u.rstrip(_TRAILING)
    while u.endswith(")") and u.count(")") > u.count("("):
        u = u[:-1].rstrip(_TRAILING)
    return u


def _host_key(url: str) -> str | None:
    """Registrable domain, or ``ip:<addr>`` for IP literals; ``None`` if no host."""
    try:
        host = urlsplit(url if "://" in url else "http://" + url).hostname
    except ValueError:
        return None
    if not host:
        return None
    if len(host) > psl.MAX_NAME_LEN:
        return "invalid:overlong-host"  # not a real DNS name: always treated as a new sink
    try:
        return "ip:" + str(ipaddress.ip_address(host))
    except ValueError:
        pass
    return psl.registrable_domain(host) or host


def _urls(text: str) -> list[str]:
    return [_clean_url(m.group(1)) for m in _URL.finditer(text)]


def _emails(text: str) -> list[tuple[str, str]]:
    return [(m.group(0).lower(), m.group(2).lower()) for m in _EMAIL.finditer(text)]


def _iban_ok(candidate: str) -> str | None:
    s = candidate.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return None
    digits = "".join(str(int(ch, 36)) for ch in s[4:] + s[:4])
    return s if int(digits) % 97 == 1 else None


def _ibans(text: str) -> list[str]:
    return [i for m in _IBAN.finditer(text) if (i := _iban_ok(m.group(1)))]


def known_sinks(
    allow_domains: Iterable[str] = (),
    allow_emails: Iterable[str] = (),
    trusted_texts: Iterable[str | None] = (),
) -> KnownSinks:
    """Build the 'known' set from the tenant allowlist plus trusted (>= user) context items."""
    domains = {psl.registrable_domain(d.lower()) or d.lower() for d in allow_domains}
    emails = {e.lower() for e in allow_emails}
    ibans: set[str] = set()
    for text in trusted_texts:
        if not text:
            continue
        domains.update(k for u in _urls(text) if (k := _host_key(u)))
        emails.update(addr for addr, _ in _emails(text))
        ibans.update(_ibans(text))
    return KnownSinks(frozenset(domains), frozenset(emails), frozenset(ibans))


def _image_urls(text: str) -> Iterable[Any]:
    yield from _MD_IMG.finditer(text)
    yield from _HTML_IMG.finditer(text)


def s3_new_sinks(text: str, known: KnownSinks) -> SignalResult:
    fired: set[str] = set()
    for u in _urls(text):
        key = _host_key(u)
        if key and key.startswith("ip:"):
            fired.update({"S3.new_domain", "S3.ip_literal"})
        elif key and key not in known.domains:
            fired.add("S3.new_domain")
    for addr, domain in _emails(text):
        dom = psl.registrable_domain(domain) or domain
        if addr not in known.emails and dom not in known.domains:
            fired.add("S3.new_email")
    for m in _image_urls(text):
        try:
            if urlsplit(m.group(1)).query:
                fired.add("S3.md_image_query")
        except ValueError:
            fired.add("S3.md_image_query")
    if any(i not in known.ibans for i in _ibans(text)):
        fired.add("S3.iban")
    risk = max((_RISK[f] for f in fired), default=0.0)
    return SignalResult("S3", fired=bool(fired), risk=risk, labels=tuple(sorted(fired)))
