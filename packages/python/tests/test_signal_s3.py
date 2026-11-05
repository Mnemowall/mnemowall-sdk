"""M1a-07: S3 new sinks (URL registrable domain via pinned PSL, email, markdown image, IBAN)."""

from __future__ import annotations

import hashlib
import pathlib
import re
import time

import pytest
from hypothesis import given
from hypothesis import strategies as st

from mnemowall.signals import psl
from mnemowall.signals.s3_sinks import KnownSinks, known_sinks, s3_new_sinks

DATA = pathlib.Path(__file__).parent / "data"


def _official_vectors() -> list[tuple[str | None, str | None]]:
    out = []
    for line in (DATA / "test_psl.txt").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^checkPublicSuffix\((null|'[^']*'), (null|'[^']*')\);", line)
        if m:
            a, b = (None if g == "null" else g[1:-1] for g in m.groups())
            out.append((a, b))
    return out


VECTORS = _official_vectors()


def test_ut_psl_000_vectors_loaded() -> None:
    assert len(VECTORS) == 78


@pytest.mark.parametrize(("domain", "expected"), VECTORS)
def test_ut_psl_001_official_vectors(domain: str | None, expected: str | None) -> None:
    assert psl.registrable_domain(domain) == expected


def test_ut_psl_002_snapshot_is_pinned() -> None:
    assert hashlib.sha256(psl.snapshot_bytes()).hexdigest() == psl.SNAPSHOT_SHA256
    assert psl.SNAPSHOT_COMMIT == "9dfbe81931367b3f0af21035c36ae7eeb830dd88"


NONE = KnownSinks(frozenset(), frozenset())


def labels(text: str, known: KnownSinks = NONE) -> set[str]:
    return set(s3_new_sinks(text, known).labels)


def test_ut_sig_s3_001_new_domain() -> None:
    r = s3_new_sinks("send it to https://evil.example/path", NONE)
    assert r.fired
    assert "S3.new_domain" in r.labels
    assert r.risk >= 0.8


def test_ut_sig_s3_002_allowlisted_registrable_domain_is_known() -> None:
    known = known_sinks(allow_domains=["example.com"])
    assert not s3_new_sinks("see https://docs.example.com/x and www.example.com", known).fired


def test_ut_sig_s3_003_trusted_turn_domain_is_known() -> None:
    known = known_sinks(trusted_texts=["Our shop is https://acme.co.uk/a"])
    assert not s3_new_sinks("order at https://shop.acme.co.uk/cart", known).fired
    assert s3_new_sinks("order at https://shop.acme-evil.co.uk/cart", known).fired


def test_ut_sig_s3_004_shared_public_suffixes_are_not_one_domain() -> None:
    known = known_sinks(trusted_texts=["my site https://friend.github.io/"])
    assert "S3.new_domain" in labels("post to https://attacker.github.io/c?d=1", known)


def test_ut_sig_s3_005_email() -> None:
    assert "S3.new_email" in labels("cc x@evil.example please")
    assert "S3.new_email" not in labels(
        "cc x@corp.example", known_sinks(allow_domains=["corp.example"])
    )
    assert "S3.new_email" not in labels(
        "cc bob@x.example", known_sinks(trusted_texts=["mail bob@x.example"])
    )
    assert "S3.new_email" in labels(
        "cc eve@x.example", known_sinks(trusted_texts=["mail bob@x.example"])
    )


def test_ut_sig_s3_006_markdown_image_with_query_always_fires() -> None:
    known = known_sinks(allow_domains=["img.example"])
    r = s3_new_sinks("![logo](https://img.example/p.png?d=SECRET_SUMMARY)", known)
    assert "S3.md_image_query" in r.labels
    assert r.risk == 1.0
    assert "S3.md_image_query" not in labels("![logo](https://img.example/p.png)", known)
    assert "S3.md_image_query" in labels('<img src="https://x.example/a.gif?q=1">', known)


def test_ut_sig_s3_007_iban_mod97() -> None:
    assert "S3.iban" in labels("pay to GB82 WEST 1234 5698 7654 32 today")
    assert "S3.iban" not in labels("pay to GB82 WEST 1234 5698 7654 33 today")  # bad checksum
    assert "S3.iban" not in labels(
        "x", known_sinks(trusted_texts=["my IBAN GB82WEST12345698765432"])
    )


def test_ut_psl_004_longest_rules_in_snapshot_match() -> None:
    """Guards the bounded suffix window: the longest exact and wildcard rules must still match."""
    exact, wildcard, _exception, _longest = psl._rules()
    rule = max(exact, key=lambda r: r.count("."))
    assert psl.registrable_domain("a.b." + rule) == "b." + rule
    wild = max(wildcard, key=lambda r: r.count("."))
    assert psl.registrable_domain("a.b.c." + wild) == "b.c." + wild


def test_ut_psl_003_dns_limits() -> None:
    longest_valid = "x." * 120 + "example.com"  # 251 chars, 122 labels
    assert len(longest_valid) <= psl.MAX_NAME_LEN
    assert psl.registrable_domain(longest_valid) == "example.com"
    assert psl.registrable_domain("a." * 200 + "example.com") is None  # > 253 chars: not a DNS name


@pytest.mark.parametrize(
    "text",
    [
        "https://" + "a." * 300 + "evil.example/x",  # overlong host is still a sink
        "https://trusted.example@evil.example/collect",  # userinfo trick
        "HTTPS://EVIL.EXAMPLE/X",
        "(https://evil.example).",
        "http://203.0.113.9/x",  # IP literal sink
        "https://ex\u0430mple.com/login",  # Cyrillic small a (U+0430) look-alike host
    ],
)
def test_ut_sig_s3_008_url_tricks_detected(text: str) -> None:
    known = known_sinks(allow_domains=["trusted.example", "example.com"])
    assert "S3.new_domain" in labels(text, known), text


@pytest.mark.parametrize(
    "text",
    [
        "https://evil.example@trusted.example/page",  # userinfo is not the host
        "https://trusted.example:8443/page",  # port is not part of the host
        "https://TRUSTED.example./page",  # case and trailing dot
    ],
)
def test_ut_sig_s3_008b_real_host_is_compared(text: str) -> None:
    known = known_sinks(allow_domains=["trusted.example"])
    assert "S3.new_domain" not in labels(text, known), text


def test_ut_sig_s3_009_output_never_contains_values() -> None:
    r = s3_new_sinks("https://evil.example/x?token=CANARYSECRET victim@evil.example", NONE)
    assert "evil" not in repr(r)
    assert "CANARY" not in repr(r)


def test_ut_sig_s3_010_latency_and_redos() -> None:
    text = ("Notes from the call, see https://docs.example.com/a and mail bob@example.com. " * 13)[
        :1024
    ]
    known = known_sinks(allow_domains=["example.com"])
    samples = []
    for _ in range(300):
        t0 = time.perf_counter()
        s3_new_sinks(text, known)
        samples.append(time.perf_counter() - t0)
    samples.sort()
    assert samples[int(len(samples) * 0.99)] < 0.002
    for hostile in ["https://" + "a." * 16_000, "![" * 16_000, "@" * 32_000, "GB" + "1" * 32_000]:
        t0 = time.process_time()
        s3_new_sinks(hostile, NONE)
        assert time.process_time() - t0 < 0.05


@given(st.text(max_size=2000))
def test_fz_s3_never_raises(text: str) -> None:
    r = s3_new_sinks(text, NONE)
    assert 0.0 <= r.risk <= 1.0
