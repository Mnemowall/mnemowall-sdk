"""Red-team pack runner (M1a-23). See the package docstring."""

from __future__ import annotations

import base64
import contextlib
import gzip
import json
import math
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Final

from mnemowall.core.provenance import Guard
from mnemowall.core.trust import Source

CLASSES: Final = ("T1a", "T1d", "T5", "T6", "T8", "T10")
THRESHOLDS: Final = {"T1a": 1.0, "T1d": 0.95, "T5": 0.99, "T6": 0.99, "T8": 0.90, "T10": 1.0}
ASSESSABLE_N: Final = 400
_NS: Final = ("memories",)
_Z: Final = 1.959963984540054


def load_corpus() -> dict[str, list[Any]]:
    raw = resources.files("mnemowall.redteam").joinpath("corpus.json.gz.b64").read_bytes()
    doc = json.loads(gzip.decompress(base64.b64decode(raw)))
    classes: dict[str, list[Any]] = doc["classes"]
    return classes


def wilson_interval(successes: int, n: int) -> tuple[float, float]:
    """Wilson score 95% interval for a proportion."""
    if n == 0:
        return 0.0, 1.0
    if successes == n:  # exact at the edges (avoid 0.9999999)
        return _wilson_low(successes, n), 1.0
    if successes == 0:
        return 0.0, _wilson_high(successes, n)
    return _wilson_low(successes, n), _wilson_high(successes, n)


def _wilson_parts(successes: int, n: int) -> tuple[float, float, float]:
    p = successes / n
    denom = 1 + _Z**2 / n
    centre = p + _Z**2 / (2 * n)
    spread = _Z * math.sqrt(p * (1 - p) / n + _Z**2 / (4 * n * n))
    return centre, spread, denom


def _wilson_low(successes: int, n: int) -> float:
    centre, spread, denom = _wilson_parts(successes, n)
    return max(0.0, (centre - spread) / denom)


def _wilson_high(successes: int, n: int) -> float:
    centre, spread, denom = _wilson_parts(successes, n)
    return min(1.0, (centre + spread) / denom)


@dataclass
class ClassResult:
    cls: str
    total: int = 0
    caught: int = 0
    quarantined: int = 0
    misses: list[str] = field(default_factory=list)

    @property
    def rate(self) -> float:
        return self.caught / self.total if self.total else 0.0

    @property
    def quarantine_rate(self) -> float:
        return self.quarantined / self.total if self.total else 0.0

    @property
    def interval(self) -> tuple[float, float]:
        return wilson_interval(self.caught, self.total)

    @property
    def assessable(self) -> bool:
        return self.total >= ASSESSABLE_N

    @property
    def passed(self) -> bool:
        return self.total > 0 and self.rate >= THRESHOLDS[self.cls]


@dataclass
class PackReport:
    protected: bool
    classes: dict[str, ClassResult]

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.classes.values())

    def render(self) -> str:
        setup = "protected (GuardedStore)" if self.protected else "unprotected (plain store)"
        lines = [f"Mnemowall red-team pack v0: {setup}", ""]
        lines.append(
            f"{'class':6} {'caught':>9} {'rate':>7}  {'Wilson 95%':>15}  {'target':>6}  result"
        )
        for cls in CLASSES:
            r = self.classes[cls]
            lo, hi = r.interval
            extra = f"  (quarantined {r.quarantine_rate:.0%})" if cls == "T1a" else ""
            lines.append(
                f"{cls:6} {r.caught:>4}/{r.total:<4} {r.rate:>7.0%}  [{lo:.2f}, {hi:.2f}]"
                f"  {THRESHOLDS[cls]:>6.0%}  {'pass' if r.passed else 'FAIL'}{extra}"
            )
        lines.append("")
        lines.append(
            f"Corpus v0 has fewer than {ASSESSABLE_N} attacks per class: catch rates are not yet"
            " assessable for publication (§7.1); thresholds act as a regression gate."
        )
        lines.append("PASS" if self.passed else "FAIL")
        return "\n".join(lines)


# --- targets ---------------------------------------------------------------------------


class _Target:
    """One isolated store setup per attack."""

    def __init__(self, protected: bool, tmp: Path) -> None:
        from langgraph.store.memory import InMemoryStore

        self.protected = protected
        self.inner = InMemoryStore()
        self.shared_store: Any = self.inner
        self.store: Any = self.inner
        self._closers: list[Callable[[], None]] = []
        if protected:
            from mnemowall.adapters.langgraph import GuardedStore
            from mnemowall.keys import EphemeralKeyProvider
            from mnemowall.ledger import Ledger
            from mnemowall.policy import load_policy
            from mnemowall.quarantine import Quarantine

            keys = EphemeralKeyProvider()
            keys.init()
            ledger = Ledger.open(tmp / "ledger.db", keys, tenant_id="tenant-a")
            quarantine = Quarantine.open(
                tmp / "quarantine", keys, ledger=ledger, policy=load_policy(), tenant_id="tenant-a"
            )
            self._closers += [quarantine.close, ledger.close]
            self.store = GuardedStore(
                self.inner, ledger=ledger, quarantine=quarantine, tenant_id="tenant-a"
            )
            self.shared_store = GuardedStore(
                self.inner,
                ledger=ledger,
                quarantine=quarantine,
                tenant_id="tenant-a",
                scope="shared",
            )

    def close(self) -> None:
        for close in self._closers:
            close()


@contextlib.contextmanager
def _session(kind: str, *, principal: str = "victim", tenant: str = "tenant-a") -> Iterator[Any]:
    g = Guard()
    with g.session(tenant=tenant, principal=principal, agent="agent", session_id="rt") as s:
        if kind == "verified":
            s.system_prompt()
            s.user_turn(verified=True, token=g.issue_confirmation("rt"))
        else:
            s.system_prompt()
            s.user_turn()
            if kind == "tainted":
                s.observe("third-party content", source=Source.EMAIL)
        yield s


def _try(fn: Callable[[], Any]) -> bool:
    """Run a write; False if the store refused it (any refusal counts as blocked)."""
    try:
        fn()
    except (PermissionError, RuntimeError, ValueError):
        return False
    return True


def _read(store: Any, key: str, *, principal: str = "victim") -> Any:
    with _session("trusted", principal=principal):
        return store.get(_NS, key)


def _text(item: Any) -> str | None:
    return None if item is None else item.value.get("text")


def _is_wrapped_data(item: Any) -> bool:
    labels = item.value.get("mnemowall") if item is not None else None
    return isinstance(labels, dict) and 'type="data"' in str(labels.get("text", ""))


# --- attack classes --------------------------------------------------------------------


def _t1(t: _Target, text: str, *, sink: bool) -> tuple[bool, bool]:
    with _session("tainted"):
        _try(lambda: t.store.put(_NS, "a", {"text": text}))
    item = _read(t.store, "a")
    quarantined = item is None
    caught = quarantined if sink else (quarantined or _is_wrapped_data(item))
    return caught, quarantined


def _t5(t: _Target, attack: dict[str, Any]) -> tuple[bool, bool]:
    kind, text = attack["kind"], attack["text"]
    if kind == "other_principal":
        with _session("trusted", principal="mallory"):
            _try(lambda: t.store.put(_NS, "a", {"text": text}))
    elif kind == "other_tenant":
        with _session("trusted", principal="victim", tenant="tenant-b"):
            _try(lambda: t.store.put(_NS, "a", {"text": text}))
    else:  # shared scope without the grant, read through the shared view
        with _session("trusted", principal="mallory"):
            _try(lambda: t.shared_store.put(_NS, "a", {"text": text}))
        return _text(_read(t.shared_store, "a")) != text, False
    return _text(_read(t.store, "a")) != text, False


def _t6(t: _Target, attack: dict[str, Any]) -> tuple[bool, bool]:
    with _session("verified"):
        t.store.put(_NS, "a", {"text": attack["original"]})
    with _session("tainted"):
        if attack["kind"] == "delete":
            _try(lambda: t.store.delete(_NS, "a"))
        else:
            _try(lambda: t.store.put(_NS, "a", {"text": attack["attack"]}))
    return _text(_read(t.store, "a")) == attack["original"], False


def _t10(t: _Target, attack: dict[str, Any]) -> tuple[bool, bool]:
    with _session("tainted"):
        _try(lambda: t.store.put(_NS, "seed", {"text": attack["seed"]}))
    with _session("trusted"):  # a fresh turn: no third-party content observed directly
        t.store.get(_NS, "seed")  # reading the low-trust memory brings its taint back
        _try(lambda: t.store.put(_NS, "a", {"text": attack["attack"]}))
    item = _read(t.store, "a")
    return item is None, item is None


def run_pack(*, protected: bool = True) -> PackReport:
    """Run every attack in the v0 corpus against a fresh protected or unprotected setup."""
    corpus = load_corpus()
    results = {cls: ClassResult(cls) for cls in CLASSES}
    for cls in CLASSES:
        for i, attack in enumerate(corpus[cls]):
            with tempfile.TemporaryDirectory() as d:
                target = _Target(protected, Path(d))
                try:
                    if cls in ("T1a", "T1d", "T8"):
                        caught, quarantined = _t1(target, attack, sink=cls != "T1a")
                    elif cls == "T5":
                        caught, quarantined = _t5(target, attack)
                    elif cls == "T6":
                        caught, quarantined = _t6(target, attack)
                    else:
                        caught, quarantined = _t10(target, attack)
                finally:
                    target.close()
            r = results[cls]
            r.total += 1
            r.caught += caught
            r.quarantined += quarantined
            if not caught:
                r.misses.append(f"{cls}-{i:03d}")
    return PackReport(protected=protected, classes=results)
