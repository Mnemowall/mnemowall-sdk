"""Red-team poisoning pack (M1a-23; corpus v1 since M1b-09, §7.1).

Run it against a protected setup (``GuardedStore``) and an unprotected one (a plain LangGraph
store) to see what Mnemowall changes. Classes: T1a standing instructions, T1b false facts, T1c
false preferences, T1d exfiltration sinks, T5 cross-scope/tenant writes, T6 tampering with
protected memories, T8 obfuscation, T10 taint laundering. A benign set (5,600 samples, most of
them trusted-user hard negatives) measures what the strict default holds back.

* CLI: ``mnemowall redteam [--unprotected] [--benign] [--sample N]``
* pytest: the ``mnemowall_redteam`` fixture (auto-registered plugin) returns :func:`run_pack`.

The corpus is **self-written and templated** (500 attacks per class), generated from encoded
templates with a fixed seed and decoded only inside the process that runs it
(:mod:`mnemowall.redteam.corpus`). It was written by the same team as the detectors, so its
catch rates are optimistic: a ceiling, not a field estimate.
"""

from mnemowall.redteam import corpus, pack
from mnemowall.redteam.pack import (
    ASSESSABLE_N,
    CLASSES,
    THRESHOLDS,
    BenignReport,
    BenignResult,
    ClassResult,
    PackReport,
    load_benign,
    load_corpus,
    run_benign,
    run_pack,
    wilson_interval,
)

__all__ = [
    "ASSESSABLE_N",
    "CLASSES",
    "THRESHOLDS",
    "BenignReport",
    "BenignResult",
    "ClassResult",
    "PackReport",
    "corpus",
    "load_benign",
    "load_corpus",
    "pack",
    "run_benign",
    "run_pack",
    "wilson_interval",
]
