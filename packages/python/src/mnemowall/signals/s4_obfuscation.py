"""S4: obfuscation (§3.5) and the Unicode normalizer used before lexical signals.

Fires on Unicode tag characters (ASCII smuggling), bidi overrides/isolates (Trojan Source),
zero-width characters inside words, mixed-script look-alike words, punycode labels, long
base64/hex runs, and shorter base64/hex blobs that decode to readable text (M1b-09).
Benign forms are excluded: emoji ZWJ sequences, LRM/RLM marks in RTL text,
single-script non-Latin words, and hash-length hex (<= 128 chars). Output is labels only.
"""

from __future__ import annotations

import base64
import binascii
import unicodedata
from typing import Final

from mnemowall.core import regex
from mnemowall.signals.base import SignalResult

_BIDI_CONTROLS: Final = frozenset(
    chr(c) for c in [*range(0x202A, 0x202F), *range(0x2066, 0x206A), 0x061C]
)
_BENIGN_CF: Final = frozenset({"‎", "‏"})  # LRM / RLM: normal in right-to-left text
_ZWJ: Final = "‍"
_CONFUSABLE_SCRIPTS: Final = frozenset({"LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"})
_PUNYCODE: Final = regex.compile(r"(?i)\bxn--[a-z0-9-]{1,59}")
_BASE64: Final = regex.compile(r"[A-Za-z0-9+/_-]{80,}={0,2}")
_HEX: Final = regex.compile(r"[0-9a-fA-F]{129,}")
_B64_CANDIDATE: Final = regex.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_CANDIDATE: Final = regex.compile(r"[0-9a-fA-F]{24,}")
_MAX_CANDIDATES: Final = 20
_MAX_DECODE: Final = 4096
_RISK: Final = {
    "S4.tag_chars": 1.0,
    "S4.bidi": 0.9,
    "S4.invisible": 0.7,
    "S4.mixed_script": 0.6,
    "S4.encoded_text": 0.7,
    "S4.punycode": 0.5,
    "S4.base64_run": 0.4,
    "S4.hex_run": 0.4,
}


def _is_tag(ch: str) -> bool:
    return 0xE0000 <= ord(ch) <= 0xE007F


def _script(ch: str) -> str | None:
    if ch.isascii():
        return "LATIN" if ch.isalpha() else None
    if not ch.isalpha():
        return None
    try:
        return unicodedata.name(ch).split(" ", 1)[0]
    except ValueError:
        return None


def _emoji_part(ch: str) -> bool:
    """A character that can sit on either side of a ZWJ in an emoji sequence."""
    if not ch:
        return False
    cp = ord(ch)
    return (
        unicodedata.category(ch) == "So"
        or cp == 0xFE0F  # emoji presentation selector
        or 0x1F3FB <= cp <= 0x1F3FF  # skin-tone modifiers
    )


def _scan_chars(text: str, fired: set[str]) -> None:
    word_scripts: set[str] = set()
    n = len(text)
    for i, ch in enumerate(text):
        if _is_tag(ch):
            fired.add("S4.tag_chars")
        elif ch in _BIDI_CONTROLS:
            fired.add("S4.bidi")
        elif ch == _ZWJ:
            # Benign only inside an emoji sequence (pictograph, ZWJ, pictograph); a bare or
            # repeated ZWJ is hidden text (found by the red-team pack, M1a-23).
            prev_ch = text[i - 1] if i > 0 else ""
            next_ch = text[i + 1] if i + 1 < n else ""
            if not (_emoji_part(prev_ch) and _emoji_part(next_ch)):
                fired.add("S4.invisible")
        elif ch not in _BENIGN_CF and not ch.isascii() and unicodedata.category(ch) == "Cf":
            fired.add("S4.invisible")
        script = _script(ch)
        if script is not None:
            if script in _CONFUSABLE_SCRIPTS:
                word_scripts.add(script)
        elif not (unicodedata.category(ch) in ("Mn", "Cf") and word_scripts):
            if len(word_scripts) > 1:
                fired.add("S4.mixed_script")
            word_scripts = set()
    if len(word_scripts) > 1:
        fired.add("S4.mixed_script")


def _readable(raw: bytes) -> bool:
    """Decoded bytes that look like a sentence: printable ASCII, mostly letters, some spaces."""
    if len(raw) < 12:
        return False
    try:
        decoded = raw.decode("ascii")
    except UnicodeDecodeError:
        return False
    if not all(c.isprintable() or c in "\n\t" for c in decoded):
        return False
    return decoded.count(" ") >= 2 and sum(c.isalpha() for c in decoded) >= 0.6 * len(decoded)


def _encoded_text(text: str) -> bool:
    for n, m in enumerate(_B64_CANDIDATE.finditer(text)):
        if n >= _MAX_CANDIDATES:
            break
        blob = m.group(0)[:_MAX_DECODE].rstrip("=")
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        if _readable(raw):
            return True
    for n, m in enumerate(_HEX_CANDIDATE.finditer(text)):
        if n >= _MAX_CANDIDATES:
            break
        blob = m.group(0)[:_MAX_DECODE]
        if len(blob) % 2 == 0 and _readable(bytes.fromhex(blob)):
            return True
    return False


def s4_obfuscation(text: str) -> SignalResult:
    fired: set[str] = set()
    _scan_chars(text, fired)
    if _PUNYCODE.search(text) is not None:
        fired.add("S4.punycode")
    if any(
        not all(c in "0123456789abcdefABCDEF" for c in m.group(0)) for m in _BASE64.finditer(text)
    ):
        fired.add("S4.base64_run")
    if _HEX.search(text) is not None:
        fired.add("S4.hex_run")
    if _encoded_text(text):
        fired.add("S4.encoded_text")
    risk = max((_RISK[f] for f in fired), default=0.0)
    return SignalResult("S4", fired=bool(fired), risk=risk, labels=tuple(sorted(fired)))


def _strip(text: str) -> str:
    return "".join(c for c in text if not _is_tag(c) and unicodedata.category(c) != "Cf")


def fold(text: str) -> str:
    """NFKC with format/invisible/tag characters dropped, case kept: for case-sensitive sinks
    (IBANs, Base58 wallets) written in full-width or other compatibility forms (M1b-09)."""
    if text.isascii():  # NFKC and the strip are no-ops on ASCII
        return text
    return _strip(unicodedata.normalize("NFKC", text))


def normalize(text: str) -> str:
    """Matching form: NFKC, drop format/invisible/tag characters, casefold. Idempotent."""
    if text.isascii():  # NFKC and the strip are no-ops on ASCII; casefold is lower()
        return text.lower()
    out = _strip(unicodedata.normalize("NFKC", text)).casefold()
    return _strip(unicodedata.normalize("NFKC", out))
