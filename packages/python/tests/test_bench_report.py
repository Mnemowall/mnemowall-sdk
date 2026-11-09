"""M1b-10: benchmark report v0. BENCH-REPORT-* (test spec M1b-09-10).

One run gives red-team catch rates and benign false positives (deterministic, Wilson 95%) plus
hot-path latency (recorded, not asserted), with pins, seed, corpus hash and hardware.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mnemowall import bench_report
from mnemowall.redteam import CLASSES, THRESHOLDS, corpus


@pytest.fixture(scope="module")
def small() -> dict[str, Any]:
    return bench_report.build_report(iterations=20, warmup=2, sizes=(1024,), sample=20)


def test_bench_report_001_structure(small: dict[str, Any]) -> None:
    assert small["schema"] == 1
    assert set(small) >= {"corpus", "pins", "environment", "redteam", "benign", "latency"}
    assert set(small["redteam"]["protected"]) == set(CLASSES)
    assert set(small["redteam"]["unprotected"]) == set(CLASSES)
    row = small["redteam"]["protected"]["T1a"]
    assert set(row) == {
        "total",
        "caught",
        "rate",
        "wilson_95",
        "target",
        "passed",
        "quarantined",
        "assessable",
    }
    assert row["target"] == THRESHOLDS["T1a"]
    lo, hi = row["wilson_95"]
    assert 0.0 <= lo <= row["rate"] <= hi <= 1.0
    assert set(small["benign"]["categories"]) == set(corpus.BENIGN_TARGETS)
    assert set(small["latency"]["results"]["1024"]) >= {"total", "s2"}


def test_bench_report_002_records_pins_seed_and_hardware(small: dict[str, Any]) -> None:
    c = small["corpus"]
    assert c["seed"] == corpus.SEED
    assert c["sha256"] == corpus.CORPUS_SHA256
    assert c["origin"] == "self-written-templated"
    assert c["sample"] == 20
    pins = small["pins"]
    for name in ("mnemowall", "cryptography", "google-re2", "langgraph", "python"):
        assert pins[name], name
    env = small["environment"]
    for key in ("cpu", "cpu_count", "memory_bytes", "platform", "load_average_before"):
        assert key in env, key


def test_bench_report_003_markdown_says_what_it_is(small: dict[str, Any]) -> None:
    md = bench_report.render_markdown(small)
    for cls in CLASSES:
        assert f"| {cls} |" in md, cls
    for text in (
        "Wilson 95%",
        corpus.CORPUS_SHA256,
        str(corpus.SEED),
        "self-written",
        "ceiling",
        "not yet assessable",  # a sample run is not assessable
        "make bench",
        "per 1,000",
        "p99",
    ):
        assert text in md, text


def test_bench_report_004_full_corpus_is_assessable() -> None:
    report = bench_report.build_report(iterations=5, warmup=1, sizes=(1024,), sample=None)
    assert report["corpus"]["sample"] is None
    assert all(r["assessable"] for r in report["redteam"]["protected"].values())
    assert all(r["passed"] for r in report["redteam"]["protected"].values())
    assert not any(r["passed"] for r in report["redteam"]["unprotected"].values())
    assert report["benign"]["total"] >= 5_000
    assert "not yet assessable" not in bench_report.render_markdown(report)


def test_bench_report_005_cli_writes_both_files(tmp_path: Path) -> None:
    out_json, out_md = tmp_path / "r.json", tmp_path / "r.md"
    args = ["--iterations", "5", "--warmup", "1", "--sizes", "1024", "--sample", "10"]
    assert bench_report.main([*args, "--json", str(out_json), "--md", str(out_md)]) == 0
    doc = json.loads(out_json.read_text())
    assert doc["corpus"]["sample"] == 10
    assert out_md.read_text().startswith("# Mnemowall benchmark report v0")
    again = tmp_path / "again.md"
    assert bench_report.main(["--render", str(out_json), "--md", str(again)]) == 0
    assert again.read_text() == out_md.read_text()  # re-rendering needs no new run


def test_bench_report_006_quarantine_column_only_where_it_means_something(
    small: dict[str, Any],
) -> None:
    md = bench_report.render_markdown(small)
    for cls in ("T5", "T6"):
        (row,) = [line for line in md.splitlines() if line.startswith(f"| {cls} |")]
        assert row.split("|")[6].strip() == "n/a", row
    (row,) = [line for line in md.splitlines() if line.startswith("| T1a |")]
    assert row.split("|")[6].strip().endswith("%")
