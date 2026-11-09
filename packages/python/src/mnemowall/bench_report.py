"""Benchmark report v0 (M1b-10, §7.1, §3.8): ``make bench`` / ``python -m mnemowall.bench_report``.

One run records, side by side:

* red-team catch rates for the protected and unprotected setups, with Wilson 95% intervals;
* false positives on the benign set, per category;
* hot-path latency per stage (p50/p99/max) against the §3.8 budgets;
* the pins that make it reproducible: package versions, corpus seed and SHA-256, and the
  hardware, OS and load it ran on.

Catch rates and false positives are deterministic for a given corpus. Latency is wall-clock on
one machine and moves with load. The corpus is self-written (see :mod:`mnemowall.redteam.corpus`),
so the rates are a ceiling on our own test data; the Markdown says so in every report.
Needs the ``langgraph`` extra.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import subprocess
from collections.abc import Sequence
from importlib import metadata
from pathlib import Path
from typing import Any, Final

from mnemowall import bench
from mnemowall.redteam import THRESHOLDS, corpus, run_benign, run_pack, wilson_interval
from mnemowall.redteam.pack import REPORT_QUARANTINE

SCHEMA: Final = 1
PINNED: Final = (
    "mnemowall",
    "cryptography",
    "google-re2",
    "langgraph",
    "langgraph-checkpoint",
    "mem0ai",
    "PyYAML",
    "keyring",
)
GATED_BENIGN_LIMIT: Final = 0.005  # §7.1 goal: 5 per 1,000 (a regression gate, not a claim)


def _pins() -> dict[str, str]:
    pins = {"python": platform.python_version(), "implementation": platform.python_implementation()}
    for name in PINNED:
        try:
            pins[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            pins[name] = "not installed"
    return pins


def _memory_bytes() -> int | None:
    if platform.system() == "Darwin":
        with contextlib.suppress(OSError, subprocess.SubprocessError, ValueError):
            out = subprocess.run(
                ["/usr/sbin/sysctl", "-n", "hw.memsize"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            ).stdout
            return int(out.strip())
    with contextlib.suppress(OSError, ValueError):
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    return None


def _load() -> list[float] | None:
    return list(os.getloadavg()) if hasattr(os, "getloadavg") else None


def _rows(report: Any) -> dict[str, dict[str, Any]]:
    rows = {}
    for cls, r in report.classes.items():
        lo, hi = r.interval
        rows[cls] = {
            "total": r.total,
            "caught": r.caught,
            "rate": round(r.rate, 4),
            "wilson_95": [round(lo, 4), round(hi, 4)],
            "target": THRESHOLDS[cls],
            "passed": r.passed,
            "quarantined": r.quarantined,
            "assessable": r.assessable,
        }
    return rows


def build_report(
    *,
    iterations: int = 10_000,
    warmup: int = 200,
    sizes: Sequence[int] = bench.DEFAULT_SIZES,
    sample: int | None = None,
) -> dict[str, Any]:
    """Run everything once and return the report document (JSON-serialisable)."""
    load_before = _load()
    doc = corpus.corpus()
    protected = run_pack(protected=True, sample=sample)
    unprotected = run_pack(protected=False, sample=sample)
    benign = run_benign(sample=sample)
    latency = bench.run_bench(sizes, iterations, warmup)
    environment = {
        **latency.pop("environment"),
        "cpu_count": os.cpu_count(),
        "memory_bytes": _memory_bytes(),
        "load_average_before": load_before,
        "load_average_after": _load(),
    }
    categories = {}
    for name, r in benign.categories.items():
        lo, hi = r.interval
        categories[name] = {
            "source": r.source,
            "total": r.total,
            "held": r.held,
            "per_1000": round(1000 * r.rate, 2),
            "wilson_95": [round(lo, 4), round(hi, 4)],
            "gated": name != "tainted_link",
        }
    lo, hi = wilson_interval(benign.held, benign.total)
    return {
        "schema": SCHEMA,
        "corpus": {
            "version": doc["version"],
            "origin": doc["origin"],
            "seed": doc["seed"],
            "sha256": corpus.CORPUS_SHA256,
            "templates_version": doc["templates_version"],
            "attacks_per_class": corpus.ATTACKS_PER_CLASS,
            "benign_total": len(doc["benign"]),
            "sample": sample,
        },
        "pins": _pins(),
        "environment": environment,
        "redteam": {"protected": _rows(protected), "unprotected": _rows(unprotected)},
        "benign": {
            "total": benign.total,
            "held": benign.held,
            "wilson_95": [round(lo, 4), round(hi, 4)],
            "gated_limit": GATED_BENIGN_LIMIT,
            "categories": categories,
        },
        "latency": latency,
    }


def _pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def _quarantine(cls: str, row: dict[str, Any]) -> str:
    """Quarantine share where it is a measure (T5 is denied, T6 is blocked: not applicable)."""
    if cls not in REPORT_QUARANTINE | {"T1d", "T8"} or not row["total"]:
        return "n/a"
    return _pct(row["quarantined"] / row["total"])


def render_markdown(report: dict[str, Any]) -> str:
    c, env, pins = report["corpus"], report["environment"], report["pins"]
    sample = c["sample"]
    protected, unprotected = report["redteam"]["protected"], report["redteam"]["unprotected"]
    assessable = all(r["assessable"] for r in protected.values())
    mem = env.get("memory_bytes")
    lines = [
        "# Mnemowall benchmark report v0",
        "",
        f"Generated {env['timestamp']} by `make bench` (`python -m mnemowall.bench_report`).",
        "",
        "## Read this first",
        "",
        "- The attack and benign corpora are **self-written and templated** by the same team that"
        " wrote the detectors, and detector gaps this corpus revealed were fixed before this run."
        " The catch rates below are a **ceiling** on our own test data, not an estimate for"
        " real attacks.",
        "- Fact- and preference-shaped poisoning (T1b, T1c) is stored as wrapped data, not"
        " blocked: lexical detection cannot tell a false fact from a true one.",
        "- Latency is wall-clock on one machine and moves with load (load average recorded below).",
    ]
    if not assessable:
        lines.append(
            f"- This run used a sample ({sample} per class): rates are **not yet assessable** for"
            " publication (§7.1 needs at least 400 attacks per class)."
        )
    lines += [
        "",
        "## Reproduce",
        "",
        "```sh",
        "make bench   # writes bench-results.json and bench-report.md at the repository root",
        "```",
        "",
        "| Pin | Value |",
        "|---|---|",
        f"| Corpus | v{c['version']}, {c['origin']}, templates v{c['templates_version']} |",
        f"| Seed | {c['seed']} |",
        f"| Corpus SHA-256 | `{c['sha256']}` |",
        f"| Sample | {'full corpus' if sample is None else f'{sample} per class/category'} |",
    ]
    lines += [f"| {name} | {value} |" for name, value in pins.items()]
    lines += [
        "",
        "| Machine | Value |",
        "|---|---|",
        f"| CPU | {env['cpu']} ({env.get('cpu_count')} logical cores) |",
        f"| Memory | {round(mem / 2**30, 1) if mem else 'unknown'} GiB |",
        f"| OS | {env['platform']} |",
        f"| Load average (1/5/15 min), before / after | {env.get('load_average_before')} /"
        f" {env.get('load_average_after')} |",
        "",
        "## Red-team catch rates (Wilson 95%)",
        "",
        "| Class | Protected | Wilson 95% | Target | Result | Quarantined | Unprotected |",
        "|---|---|---|---|---|---|---|",
    ]
    for cls, r in protected.items():
        u = unprotected[cls]
        lo, hi = r["wilson_95"]
        lines.append(
            f"| {cls} | {r['caught']}/{r['total']} ({_pct(r['rate'])}) | [{lo:.3f}, {hi:.3f}]"
            f" | {_pct(r['target'])} | {'pass' if r['passed'] else 'FAIL'}"
            f" | {_quarantine(cls, r)}"
            f" | {u['caught']}/{u['total']} |"
        )
    lines += [
        "",
        "Caught means: T1a/T1b/T1c/T10 quarantined or stored only as wrapped data at tainted"
        " trust; T1d/T8 quarantined; T5 the attacker's text never reads back; T6 the original reads"
        " back unchanged.",
        "",
        "## False positives on the benign set",
        "",
        "| Category | Source | Held | Per 1,000 | Wilson 95% | Gate |",
        "|---|---|---|---|---|---|",
    ]
    b = report["benign"]
    for name, r in b["categories"].items():
        lo, hi = r["wilson_95"]
        gate = f"<= {1000 * b['gated_limit']:g} per 1,000" if r["gated"] else "reported only"
        lines.append(
            f"| {name} | {r['source']} | {r['held']}/{r['total']} | {r['per_1000']:.1f}"
            f" | [{lo:.3f}, {hi:.3f}] | {gate} |"
        )
    lo, hi = b["wilson_95"]
    lines += [
        f"| **all** | | {b['held']}/{b['total']} | {1000 * b['held'] / max(b['total'], 1):.1f}"
        f" | [{lo:.3f}, {hi:.3f}] | |",
        "",
        "`tainted_link` is third-party text carrying a link, phone number or address. The strict"
        " default holds it for review by design (I2); the row measures that cost. The gate is a"
        " regression check on our own corpus; §7.1's benign goal is measured per design partner in"
        " shadow mode.",
        "",
        "## Hot-path latency (ms)",
        "",
        f"{report['latency']['iterations']} warm iterations per stage after"
        f" {report['latency']['warmup']} warm-up calls. Budgets (§3.8) apply to the 1 KB payload.",
        "",
        "| Payload | Stage | p50 | p99 | max | Budget (p99) |",
        "|---|---|---|---|---|---|",
    ]
    lat = report["latency"]
    for size, stages in lat["results"].items():
        for stage in bench.STAGES:
            r = stages[stage]
            budget = lat["budgets_ms"][stage] if size == lat["budgets_apply_to"] else None
            mark = (
                ""
                if budget is None
                else (f"{budget} ok" if r["p99_ms"] <= budget else f"{budget} OVER")
            )
            lines.append(
                f"| {int(size) // 1024} KB | {stage} | {r['p50_ms']:.3f} | {r['p99_ms']:.3f}"
                f" | {r['max_ms']:.3f} | {mark} |"
            )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m mnemowall.bench_report")
    parser.add_argument("--iterations", type=int, default=10_000)
    parser.add_argument("--warmup", type=int, default=200)
    parser.add_argument("--sizes", type=int, nargs="+", default=list(bench.DEFAULT_SIZES))
    parser.add_argument("--sample", type=int, default=None, help="quick run: N per class")
    parser.add_argument("--json", type=Path, default=Path("bench-results.json"))
    parser.add_argument("--md", type=Path, default=Path("bench-report.md"))
    parser.add_argument("--render", type=Path, help="re-render Markdown from an earlier JSON")
    args = parser.parse_args(argv)
    if args.render is not None:
        report = json.loads(args.render.read_text(encoding="utf-8"))
        args.md.write_text(render_markdown(report), encoding="utf-8")
        print(f"wrote {args.md}")
        return 0
    if args.sample is not None and args.sample < 1:
        parser.error("--sample must be at least 1")
    report = build_report(
        iterations=args.iterations, warmup=args.warmup, sizes=args.sizes, sample=args.sample
    )
    args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.md.write_text(render_markdown(report), encoding="utf-8")
    print(f"wrote {args.json} and {args.md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
