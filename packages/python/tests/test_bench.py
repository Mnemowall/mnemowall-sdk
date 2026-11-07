"""M1a-24: `make bench` harness. BENCH-HOTPATH structure (timings are recorded, not asserted)."""

from __future__ import annotations

import json
from pathlib import Path

from mnemowall.bench import BUDGETS_MS, STAGES, main, payload, run_bench
from mnemowall.core.model import Outcome
from mnemowall.core.provenance import Guard
from mnemowall.policy import WriteRequest, load_engine


def test_bench_stages_and_budgets_match_the_spec() -> None:
    assert STAGES == ("provenance_s1_s5_s7", "s3_s4_s10", "s2", "policy", "sign_append", "total")
    assert BUDGETS_MS == {
        "provenance_s1_s5_s7": 0.5,
        "s3_s4_s10": 3.0,
        "s2": 1.0,
        "policy": 1.0,
        "sign_append": 3.0,
        "total": 15.0,
    }


def test_bench_payloads_are_sized_and_benign() -> None:
    engine = load_engine()
    g = Guard()
    for size in (1024, 10 * 1024, 32 * 1024):
        text = payload(size)
        assert len(text.encode("utf-8")) == size
        with g.session(tenant="t", principal="p", agent="a", session_id="s") as s:
            s.system_prompt()
            s.user_turn()
            assert engine.evaluate(WriteRequest(value=text)).decision.action is Outcome.ALLOW


def test_bench_report_structure() -> None:
    report = run_bench(sizes=(1024,), iterations=25, warmup=5)
    results = report["results"]["1024"]
    assert set(results) == set(STAGES)
    for stage in STAGES:
        r = results[stage]
        assert r["n"] == 25
        assert 0 <= r["p50_ms"] <= r["p99_ms"] <= r["max_ms"]
    env = report["environment"]
    assert env["python"]
    assert env["machine"]
    assert env["mnemowall"]
    assert report["iterations"] == 25
    assert report["verdict"]["1024"] in {"within_budget", "over_budget"}


def test_bench_cli_writes_json(tmp_path: Path, capsys: object) -> None:
    out = tmp_path / "bench.json"
    assert main(["--iterations", "20", "--warmup", "2", "--sizes", "1024", "--out", str(out)]) == 0
    doc = json.loads(out.read_text())
    assert set(doc["results"]["1024"]) == set(STAGES)
