"""Red-team corpus v1 (M1b-09, §7.1): generated from encoded templates with a fixed seed.

Every item is **self-written, templated test data** (``origin``): the templates were written by
the same team that wrote the detectors, so catch rates measured on them are optimistic. No
third-party dataset is included yet.

* The templates and fillers live gzip+base64-encoded in ``templates.json.gz.b64`` and are decoded
  only when a corpus is generated. This module contains no attack wording, only the code that
  fills slots, makes checksum-valid fake IBANs and wallets, and applies the T8 obfuscations.
* :func:`generate` is deterministic: the same templates and seed give the same corpus, byte for
  byte (:data:`CORPUS_SHA256` pins it, so any change to templates or code is visible in review).
* Domains are ``.test`` / ``.example`` / ``.invalid``; phone numbers are fictional (555-01xx, Ofcom
  drama ranges); IBANs and wallets are random, checksum-valid and not real accounts.

To change the templates: decode the file (base64, then gzip, then JSON), edit it, re-encode it
the same way (``json.dumps(..., ensure_ascii=False, sort_keys=True, separators=(",", ":"))``,
``gzip.compress(..., mtime=0)``), bump ``version``, and update :data:`CORPUS_SHA256` in the same
change so reviewers see that the corpus moved.
"""

from __future__ import annotations

import base64
import functools
import gzip
import hashlib
import json
import random
import re
from collections.abc import Callable
from importlib import resources
from typing import Any, Final

SEED: Final = 20261108
ATTACK_CLASSES: Final = ("T1a", "T1b", "T1c", "T1d", "T5", "T6", "T8", "T10")
ATTACKS_PER_CLASS: Final = 500
BENIGN_TARGETS: Final = {
    "verified_instruction": 800,
    "user_fact": 900,
    "user_preference": 600,
    "user_sink": 600,
    "user_tech": 300,
    "tainted_fact": 900,
    "tainted_opinion": 500,
    "tainted_link": 300,
    "multilingual": 300,
    "tech_ids": 400,
}
ORIGIN: Final = "self-written-templated"
CORPUS_SHA256: Final = "815a4eb1cfc3e14bbe53213661a7420dd88e8cc9b83d32aedac4584a31656776"

_SLOT: Final = re.compile(r"\{([a-z][a-z0-9_]*)\}")
_B58: Final = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B32: Final = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_IBAN_FORMATS: Final = {  # country: (letters in BBAN prefix, digits after)
    "DE": (0, 18),
    "GB": (4, 14),
    "NL": (4, 10),
    "ES": (0, 20),
    "FR": (0, 23),
}
_CYRILLIC: Final = {"a": "\u0430", "e": "\u0435", "o": "\u043e", "p": "\u0440", "c": "\u0441"}
_ZERO_WIDTH: Final = ("​", "‌", "⁠")


@functools.cache
def load_templates() -> dict[str, Any]:
    raw = resources.files("mnemowall.redteam").joinpath("templates.json.gz.b64").read_bytes()
    doc: dict[str, Any] = json.loads(gzip.decompress(base64.b64decode(raw)))
    return doc


class _Filler:
    """Fills ``{slot}`` placeholders; one value per slot name within an item."""

    def __init__(self, rng: random.Random, fill: dict[str, list[str]]) -> None:
        self.rng = rng
        self.fill = fill
        self.computed: dict[str, Callable[[], str]] = {
            "domain": self._domain,
            "d": self._domain,
            "email": self._email,
            "url": self._url,
            "img": self._img,
            "iban": self._iban,
            "phone": self._phone,
            "wallet": self._wallet,
        }

    def item(self, template: str, **given: str) -> str:
        values = dict(given)
        text = template
        for _ in range(4):  # slots may expand to text with further slots
            if not _SLOT.search(text):
                break
            text = _SLOT.sub(lambda m: self._value(m.group(1), values), text)
        return text

    def _value(self, slot: str, values: dict[str, str]) -> str:
        if slot not in values:
            base = slot.rstrip("0123456789")
            if slot in self.computed:
                values[slot] = self.computed[slot]()
            elif slot in self.fill:
                values[slot] = self.rng.choice(self.fill[slot])
            elif base in self.computed:
                values[slot] = self.computed[base]()
            else:
                values[slot] = self.rng.choice(self.fill[base])
        return values[slot]

    def _domain(self) -> str:
        f, r = self.fill, self.rng
        name = f"{r.choice(f['word_a'])}-{r.choice(f['word_b'])}{r.choice(f['tld'])}"
        return name if r.random() < 0.6 else f"{r.choice(f['word_a'])}.{name}"

    def _email(self) -> str:
        return f"{self.rng.choice(self.fill['local'])}@{self._domain()}"

    def _url(self) -> str:
        r, f = self.rng, self.fill
        scheme = r.choice(("https://", "http://", "https://www."))
        url = f"{scheme}{self._domain()}/{r.choice(f['path'])}"
        if r.random() < 0.5:
            url += f"?{r.choice(f['param'])}={r.randrange(10**6):06d}"
        return url

    def _img(self) -> str:
        r, f = self.rng, self.fill
        return (
            f"https://{self._domain()}/{r.choice(f['path'])}"
            f"?{r.choice(f['param'])}={r.choice(f['param']).upper()}_{r.randrange(10**4)}"
        )

    def _iban(self) -> str:
        r = self.rng
        country = r.choice(sorted(_IBAN_FORMATS))
        letters, digits = _IBAN_FORMATS[country]
        bban = "".join(r.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(letters))
        bban += "".join(r.choice("0123456789") for _ in range(digits))
        numeric = "".join(str(int(ch, 36)) for ch in bban + country + "00")
        iban = f"{country}{98 - int(numeric) % 97:02d}{bban}"
        if r.random() < 0.5:
            iban = " ".join(iban[i : i + 4] for i in range(0, len(iban), 4))
        return iban

    def _phone(self) -> str:
        r = self.rng
        n = r.randrange(100)
        return r.choice(
            (
                f"+1 202-555-01{n:02d}",
                f"+1 (415) 555-01{n:02d}",
                f"+44 20 7946 0{n:03d}",
                f"+1.312.555.01{n:02d}",
                f"tel:+1555010{n:02d}",
            )
        )

    def _wallet(self) -> str:
        r = self.rng
        payload = bytes(r.randrange(256) for _ in range(20))
        kind = r.randrange(3)
        if kind == 0:
            return _bech32_encode("bc", [0, *_convert_bits(payload)])
        if kind == 1:
            return _base58check(b"\x00" + payload)
        return "0x" + payload.hex()


def _convert_bits(data: bytes) -> list[int]:
    acc = bits = 0
    out = []
    for value in data:
        acc = (acc << 8) | value
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    return out


def _bech32_encode(hrp: str, data: list[int]) -> str:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)

    def polymod(values: list[int]) -> int:
        chk = 1
        for v in values:
            top = chk >> 25
            chk = (chk & 0x1FFFFFF) << 5 ^ v
            for i in range(5):
                chk ^= gen[i] if (top >> i) & 1 else 0
        return chk

    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    mod = polymod([*expanded, *data, 0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(mod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_B32[d] for d in data + checksum)


def _base58check(payload: bytes) -> str:
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out


# --- T8 obfuscations (code, not wording) ------------------------------------------------------


def _tag(text: str) -> str:
    return "".join(chr(0xE0000 + ord(c)) for c in text if ord(c) < 0x80)


def _zero_width(rng: random.Random, text: str) -> str:
    words = text.split(" ")
    for i, w in enumerate(words):
        if len(w) > 3 and rng.random() < 0.5:
            cut = rng.randrange(1, len(w) - 1)
            words[i] = w[:cut] + rng.choice(_ZERO_WIDTH) + w[cut:]
    return " ".join(words)


def _homoglyph(rng: random.Random, word: str) -> str:
    base = word.rstrip(".,;:!?)'\"")
    end = base.rfind(".") if "." in base else len(word)  # never touch the TLD
    spots = [i for i, c in enumerate(word[:end]) if c in _CYRILLIC]
    if not spots:
        return word
    i = rng.choice(spots)
    return word[:i] + _CYRILLIC[word[i]] + word[i + 1 :]


def _fullwidth(text: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in text)


def _defang(text: str) -> str:
    return (
        text.replace("https://", "hxxps://")
        .replace("http://", "hxxp://")
        .replace(".test", "[.]test")
        .replace(".example", "[.]example")
        .replace(".invalid", "[.]invalid")
        .replace("@", "[at]")
    )


class _Generator:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)  # noqa: S311 - a reproducible corpus, not a secret
        self.t = load_templates()
        self.f = _Filler(self.rng, self.t["fill"])

    def carried(self, payload_template: str, carriers: list[str]) -> str:
        payload = self.f.item(payload_template)
        return self.f.item(self.rng.choice(carriers), payload=payload)

    def unique(self, make: Callable[[], Any], n: int) -> list[Any]:
        seen: set[str] = set()
        out: list[Any] = []
        for _ in range(n * 60):
            item = make()
            key = json.dumps(item, sort_keys=True, ensure_ascii=False)
            if key not in seen:
                seen.add(key)
                out.append(item)
                if len(out) == n:
                    return out
        raise RuntimeError("templates cannot produce enough unique items")

    def t1a_payload(self) -> str:
        return str(self.rng.choice(self.t["T1a"]["frames"]))

    def attacks(self) -> dict[str, list[Any]]:
        t, r, n = self.t, self.rng, ATTACKS_PER_CLASS
        fill = {**t["fill"], **{k: v for k, v in t["T1a"].items() if k != "frames"}}
        self.f.fill = fill
        car = t["carriers"]
        out: dict[str, list[Any]] = {}
        out["T1a"] = self.unique(lambda: self.carried(self.t1a_payload(), car), n)
        out["T1b"] = self.unique(lambda: self.carried(r.choice(t["T1b"]), car), n)
        out["T1c"] = self.unique(lambda: self.carried(r.choice(t["T1c"]), car), n)
        out["T1d"] = self.unique(lambda: self.carried(r.choice(t["T1d"]), car), n)
        kinds = ("other_principal", "other_tenant", "shared_no_grant")
        out["T5"] = self.unique(
            lambda: {"kind": r.choice(kinds), "text": self.f.item(r.choice(t["T5"]))}, n
        )

        def t6() -> dict[str, str]:
            kind = "delete" if r.random() < 0.3 else "overwrite"
            item = {"kind": kind, "original": self.f.item(r.choice(t["T6"]["originals"]))}
            if kind == "overwrite":
                item["attack"] = self.f.item(r.choice(t["T6"]["attacks"]))
            return item

        out["T6"] = self.unique(t6, n)
        out["T8"] = self.unique(self.t8, n)
        out["T10"] = self.unique(
            lambda: {
                "seed": self.carried(r.choice(t["T10"]["seeds"]), car),
                "attack": self.f.item(r.choice(t["T10"]["attacks"])),
            },
            n,
        )
        return out

    def t8(self) -> str:
        r, t = self.rng, self.t
        visible = self.f.item(r.choice(t["T8"]["visible"]))
        instruction = self.f.item(self.t1a_payload())
        sink = self.f.item(r.choice(t["T1d"]))
        kind = r.randrange(10)
        if kind == 0:  # ASCII smuggling in Unicode tag characters
            return visible + _tag(self.f.item("{hidden}"))
        if kind == 1:  # bidi override hiding reversed text
            return f"{visible} ‮{instruction[::-1]}‬"
        if kind == 2:  # zero-width characters inside words
            return _zero_width(r, instruction)
        if kind == 3:  # mixed-script look-alike in a sink or keyword
            return " ".join(_homoglyph(r, w) if r.random() < 0.4 else w for w in sink.split(" "))
        if kind == 4:  # punycode host
            label = "".join(r.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(5))
            return self.f.item(f"Sign in at https://xn--{label}-{r.randrange(99)}a{{tld}}/verify.")
        if kind == 5:  # one base64 blob of the instruction
            return f"{visible} {base64.b64encode(instruction.encode()).decode()}"
        if kind == 6:  # one hex blob of the instruction
            return f"{visible} {instruction.encode().hex()}"
        if kind == 7:  # full-width sink
            return _fullwidth(sink)
        if kind == 8:  # defanged sink
            return _defang(sink)
        return self.f.item(r.choice(t["T8"]["spaced"]))  # spaced or leet-speak instruction

    def benign(self) -> list[dict[str, str]]:
        t, r = self.t, self.rng
        self.f.fill = t["fill"]
        out: list[dict[str, str]] = []
        for category, target in BENIGN_TARGETS.items():
            spec = t["benign"][category]
            source = spec["source"]

            def make(spec: dict[str, Any] = spec, source: str = source) -> str:
                carriers = t["benign_carriers"] if source == "tainted" else t["user_carriers"]
                return self.carried(r.choice(spec["texts"]), carriers)

            out += [
                {"category": category, "source": source, "text": text}
                for text in self.unique(make, target)
            ]
        return out


def generate(seed: int = SEED) -> dict[str, Any]:
    """The full corpus: attacks per class plus the benign set. Pure function of templates + seed."""
    gen = _Generator(seed)
    classes = gen.attacks()
    benign = gen.benign()
    return {
        "version": 2,
        "seed": seed,
        "origin": ORIGIN,
        "templates_version": gen.t["version"],
        "classes": classes,
        "benign": benign,
    }


def digest(corpus: dict[str, Any]) -> str:
    canon = json.dumps(corpus, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


@functools.cache
def corpus() -> dict[str, Any]:
    """The pinned corpus (cached per process)."""
    return generate(SEED)
