"""Hot-path benchmark: ``make bench`` / ``python -m mnemowall.bench`` (M1a-24, §3.8).

Measures p50/p99/max per stage over warm iterations for 1 KB, 10 KB and cap-sized (32 KB)
benign payloads, and records the hardware and versions. The §3.8 budgets apply to the 1 KB
case; they are targets to measure on an M2 Max, not claims. Timings are wall-clock
(``perf_counter_ns``) in one process, so a busy machine inflates them: record the load.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import platform
import subprocess
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Final

import mnemowall
from mnemowall.core.model import MemoryType
from mnemowall.core.provenance import Guard
from mnemowall.core.trust import TrustLevel
from mnemowall.keys import EphemeralKeyProvider
from mnemowall.ledger import Ledger
from mnemowall.policy import DecisionInputs, WriteRequest, decide, load_engine, load_policy
from mnemowall.policy.engine import _content_signals, _known_sinks
from mnemowall.signals.s2_type import classify
from mnemowall.signals.s4_obfuscation import normalize
from mnemowall.signals.write import (
    Op,
    Scope,
    ScopeKind,
    WriteFacts,
    s1_taint,
    s5_scope,
    s7_protected_mutation,
)

STAGES: Final = ("provenance_s1_s5_s7", "s3_s4_s10", "s2", "policy", "sign_append", "total")
BUDGETS_MS: Final = {
    "provenance_s1_s5_s7": 0.5,
    "s3_s4_s10": 3.0,
    "s2": 1.0,
    "policy": 1.0,
    "sign_append": 3.0,
    "total": 15.0,
}
DEFAULT_SIZES: Final = (1024, 10 * 1024, 32 * 1024)
_SENTENCES: Final = (
    "The quarterly review is scheduled for the second week of the month. ",
    "Our team prefers short written updates over long meetings. ",
    "The office in Lisbon opens at nine and closes at six. ",
    "Project Atlas moved its launch to the spring after user testing. ",
    "Customer feedback mentioned faster search and clearer billing pages. ",
)


def payload(size: int) -> str:
    """A benign, deterministic text of exactly ``size`` UTF-8 bytes."""
    text = ""
    i = 0
    while len(text) < size:
        text += _SENTENCES[i % len(_SENTENCES)]
        i += 1
    return text[:size]


def _percentile(sorted_ns: Sequence[int], q: float) -> float:
    k = max(0, math.ceil(q * len(sorted_ns)) - 1)
    return sorted_ns[k] / 1e6


def _measure(fn: Callable[[], Any], iterations: int, warmup: int) -> dict[str, float]:
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        fn()
        samples.append(time.perf_counter_ns() - t0)
    samples.sort()
    return {
        "n": iterations,
        "p50_ms": round(_percentile(samples, 0.50), 4),
        "p99_ms": round(_percentile(samples, 0.99), 4),
        "max_ms": round(samples[-1] / 1e6, 4),
    }


def _environment() -> dict[str, Any]:
    cpu = platform.processor() or platform.machine()
    if platform.system() == "Darwin":
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            cpu = subprocess.run(
                ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            ).stdout.strip()
    load = os.getloadavg() if hasattr(os, "getloadavg") else None
    return {
        "mnemowall": mnemowall.__version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu": cpu,
        "load_average": list(load) if load else None,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _stage_fns(
    text: str, policy: Any, engine: Any, session: Any, ledger: Ledger, counter: list[int]
) -> dict[str, Callable[[], Any]]:
    normalized = normalize(text)
    facts = WriteFacts(
        content=text,
        write_trust=TrustLevel.USER,
        op=Op.CREATE,
        target_scope=Scope(ScopeKind.USER),
        principal_scope=Scope(ScopeKind.USER),
    )
    inputs = DecisionInputs(
        trust=TrustLevel.USER,
        memory_type=MemoryType.FACT,
        op=Op.CREATE,
        scope=ScopeKind.USER,
        grants=frozenset(),
        protected=False,
        fired=frozenset(),
    )
    known = _known_sinks((), ())

    def provenance() -> None:
        session.write_trust()
        s1_taint(facts)
        s5_scope(facts)
        s7_protected_mutation(facts)

    def append() -> None:
        counter[0] += 1
        ledger.append_version(
            namespace=("bench",),
            key=f"k{counter[0] % 64}",
            content=text,
            scope="user",
            trust_level="user",
            effective_type="fact",
            memory_type="fact",
            bundle_id=policy.id,
            provenance={"n": counter[0]},
        )

    def total() -> None:
        engine.evaluate(WriteRequest(value=text))
        append()

    return {
        "provenance_s1_s5_s7": provenance,
        "s3_s4_s10": lambda: _content_signals(text, normalized, known),
        "s2": lambda: classify(normalized),
        "policy": lambda: decide(policy, inputs),
        "sign_append": append,
        "total": total,
    }


def run_bench(
    sizes: Sequence[int] = DEFAULT_SIZES, iterations: int = 10_000, warmup: int = 200
) -> dict[str, Any]:
    policy = load_policy()
    engine = load_engine(policy)
    provider = EphemeralKeyProvider()
    provider.init()
    results: dict[str, dict[str, dict[str, float]]] = {}
    verdict: dict[str, str] = {}
    g = Guard()
    with (
        tempfile.TemporaryDirectory() as d,
        g.session(tenant="bench", principal="p", agent="a", session_id="bench") as session,
    ):
        session.system_prompt()
        session.user_turn()
        ledger = Ledger.open(Path(d) / "ledger.db", provider, tenant_id="bench")
        counter = [0]
        for size in sizes:
            fns = _stage_fns(payload(size), policy, engine, session, ledger, counter)
            stage_results = {name: _measure(fn, iterations, warmup) for name, fn in fns.items()}
            results[str(size)] = stage_results
            over = any(stage_results[s]["p99_ms"] > BUDGETS_MS[s] for s in STAGES)
            verdict[str(size)] = "over_budget" if over else "within_budget"
        ledger.close()
    return {
        "iterations": iterations,
        "warmup": warmup,
        "budgets_ms": dict(BUDGETS_MS),
        "budgets_apply_to": "1024",
        "results": results,
        "verdict": verdict,
        "environment": _environment(),
    }


def render(report: dict[str, Any]) -> str:
    lines = [f"mnemowall bench: {report['iterations']} warm iterations per stage", ""]
    for size, stages in report["results"].items():
        lines.append(f"payload {int(size) // 1024} KB")
        for stage in STAGES:
            r = stages[stage]
            budget = BUDGETS_MS[stage] if size == report["budgets_apply_to"] else None
            mark = "" if budget is None else ("  ok" if r["p99_ms"] <= budget else "  OVER")
            limit = "" if budget is None else f"  (budget {budget} ms)"
            lines.append(
                f"  {stage:22} p50 {r['p50_ms']:8.3f}  p99 {r['p99_ms']:8.3f}"
                f"  max {r['max_ms']:8.3f} ms{limit}{mark}"
            )
    env = report["environment"]
    lines += [
        "",
        f"{env['cpu']} | {env['platform']} | Python {env['python']} | load {env['load_average']}",
    ]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m mnemowall.bench")
    parser.add_argument("--iterations", type=int, default=10_000)
    parser.add_argument("--warmup", type=int, default=200)
    parser.add_argument("--sizes", type=int, nargs="+", default=list(DEFAULT_SIZES))
    parser.add_argument("--out", type=Path, default=Path("bench-results.json"))
    args = parser.parse_args(argv)
    report = run_bench(args.sizes, args.iterations, args.warmup)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(render(report))
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
