"""S3: new sink strings (§3.5): URLs, emails, markdown/HTML image URLs with a query, IBANs
(mod-97), phone numbers, crypto addresses (checksummed), credential paths and shell
download-and-run commands. The last four were added in M1b-09.

"New" means absent from the tenant allowlist and from trusted (>= user) turns in the session.
URLs compare by registrable domain from the pinned PSL snapshot. IP-literal hosts are always
new. Image URLs with a query string fire regardless of domain: they are the classic zero-click
exfiltration channel (SpAIware-style). Phone numbers count when written in international form
(``+``/``tel:``) or right after a word like "call" or "WhatsApp"; crypto addresses only when their
checksum is valid (Bech32/Bech32m, Base58Check) or in the ``0x`` + 40 hex form. Credential paths
and shell download-and-run fire regardless of the known set: a trusted turn does not make them
safe to store from a tainted source. Output is labels only; no extracted values.
"""

from __future__ import annotations

import dataclasses
import hashlib
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
_PHONE_INTL: Final = regex.compile(r"(?i)(?:\btel:\s*|\+)(\d[\d ().-]{6,22}\d)")
_PHONE_CUE: Final = regex.compile(
    r"(?i)\b(?:call|phone|text|sms|whatsapp|signal|telegram|fax|tel|mobile|cell|hotline|dial)\b"
    r"[^\n\d+]{0,20}(\(?\d[\d ().-]{5,20}\d)"
)
_DATE_LIKE: Final = regex.compile(r"^\d{4}-\d{2}-\d{2}$|^\d{1,2}[:.]\d{2}")
_BECH32: Final = regex.compile(r"(?i)\b((?:bc|tb|ltc)1[ac-hj-np-z02-9]{8,87})\b")
_BASE58: Final = regex.compile(r"\b([13][1-9A-HJ-NP-Za-km-z]{25,34})\b")
_ETH: Final = regex.compile(r"\b0x[0-9a-fA-F]{40}\b")
_CRED_PATH: Final = regex.compile(
    r"(?i)([/\\]\.(?:ssh|aws|gnupg|kube|docker|azure)[/\\]|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|"
    r"\.(?:netrc|pgpass|npmrc|pypirc|git-credentials)\b|/etc/(?:shadow|passwd|sudoers)\b|"
    r"\bcredentials\.json\b|\bservice[-_]?account[\w.-]*\.json\b|\bwallet\.dat\b)"
)
_SHELL: Final = regex.compile(
    r"(?i)(\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|"
    r"\bbash\s+-i\b|/dev/tcp/|\b(?:nc|ncat|netcat)\b[^\n]{0,60}\s-e\s|"
    r"\bpowershell(?:\.exe)?\b[^\n]{0,80}\s-(?:e|en|enc|encodedcommand)\b|"
    r"\b(?:iex|invoke-expression)\b|\binvoke-webrequest\b|"
    r"\bbase64\s+(?:-d|--decode)\b[^\n]{0,80}\|\s*(?:ba)?sh\b|"
    r"\bcertutil\b[^\n]{0,40}-urlcache\b|\bchmod\s+\+x\b)"
)
_B58: Final = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B32: Final = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_TRAILING: Final = ".,;:!?'\"]}>"
_RISK: Final = {
    "S3.md_image_query": 1.0,
    "S3.iban": 0.9,
    "S3.new_domain": 0.8,
    "S3.new_email": 0.8,
    "S3.ip_literal": 0.8,
    "S3.crypto": 0.9,
    "S3.credential_path": 0.8,
    "S3.shell": 0.8,
    "S3.phone": 0.6,
}


@dataclasses.dataclass(frozen=True)
class KnownSinks:
    domains: frozenset[str] = dataclasses.field(repr=False)
    emails: frozenset[str] = dataclasses.field(repr=False)
    ibans: frozenset[str] = dataclasses.field(default=frozenset(), repr=False)
    phones: frozenset[str] = dataclasses.field(default=frozenset(), repr=False)
    wallets: frozenset[str] = dataclasses.field(default=frozenset(), repr=False)


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


def _phones(text: str) -> list[str]:
    out = []
    for pattern in (_PHONE_INTL, _PHONE_CUE):
        for m in pattern.finditer(text):
            raw = m.group(1)
            digits = "".join(c for c in raw if c.isdigit())
            if 7 <= len(digits) <= 15 and not _DATE_LIKE.search(raw.strip("( ")):
                out.append(digits[-10:])  # compare national significant digits
    return out


def _bech32_ok(addr: str) -> bool:
    addr = addr.lower()
    hrp, _, data = addr.rpartition("1")
    if not hrp or len(data) < 6 or any(c not in _B32 for c in data):
        return False
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    values += [_B32.index(c) for c in data]
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk in (1, 0x2BC830A3)  # Bech32, Bech32m


def _base58check_ok(addr: str) -> bool:
    n = 0
    for c in addr:
        n = n * 58 + _B58.index(c)
    raw = n.to_bytes(25, "big") if n.bit_length() <= 200 else b""
    if len(raw) != 25:
        return False
    digest = hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()
    return raw[21:] == digest[:4]


def _wallets(text: str) -> list[str]:
    out = [m.group(1).lower() for m in _BECH32.finditer(text) if _bech32_ok(m.group(1))]
    out += [m.group(1) for m in _BASE58.finditer(text) if _base58check_ok(m.group(1))]
    out += [m.group(0).lower() for m in _ETH.finditer(text)]
    return out


def known_sinks(
    allow_domains: Iterable[str] = (),
    allow_emails: Iterable[str] = (),
    trusted_texts: Iterable[str | None] = (),
) -> KnownSinks:
    """Build the 'known' set from the tenant allowlist plus trusted (>= user) context items."""
    domains = {psl.registrable_domain(d.lower()) or d.lower() for d in allow_domains}
    emails = {e.lower() for e in allow_emails}
    ibans: set[str] = set()
    phones: set[str] = set()
    wallets: set[str] = set()
    for text in trusted_texts:
        if not text:
            continue
        domains.update(k for u in _urls(text) if (k := _host_key(u)))
        emails.update(addr for addr, _ in _emails(text))
        ibans.update(_ibans(text))
        phones.update(_phones(text))
        wallets.update(_wallets(text))
    return KnownSinks(
        frozenset(domains),
        frozenset(emails),
        frozenset(ibans),
        frozenset(phones),
        frozenset(wallets),
    )


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
    if any(p not in known.phones for p in _phones(text)):
        fired.add("S3.phone")
    if any(w not in known.wallets for w in _wallets(text)):
        fired.add("S3.crypto")
    if _CRED_PATH.search(text):
        fired.add("S3.credential_path")
    if _SHELL.search(text):
        fired.add("S3.shell")
    risk = max((_RISK[f] for f in fired), default=0.0)
    return SignalResult("S3", fired=bool(fired), risk=risk, labels=tuple(sorted(fired)))
