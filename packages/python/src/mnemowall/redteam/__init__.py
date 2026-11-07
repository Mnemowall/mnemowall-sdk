"""Red-team poisoning pack v0 (M1a-23, §7.1).

Run it against a protected setup (``GuardedStore``) and an unprotected one (a plain LangGraph
store) to see what Mnemowall changes. Classes: T1a standing instructions, T1d exfiltration
sinks, T5 cross-scope/tenant writes, T6 tampering with protected memories, T8 obfuscation,
T10 taint laundering.

* CLI: ``mnemowall redteam [--unprotected]``
* pytest: the ``mnemowall_redteam`` fixture (auto-registered plugin) returns :func:`run_pack`.

The v0 corpus is small and self-written, stored gzip+base64 and decoded only when the pack
runs. With fewer than 400 attacks per class, catch rates are **not yet assessable** for
publication (§7.1); they are reported with Wilson 95% intervals and checked against the
per-class thresholds as a regression gate only.
"""

from mnemowall.redteam.pack import (
    ASSESSABLE_N,
    CLASSES,
    THRESHOLDS,
    ClassResult,
    PackReport,
    load_corpus,
    run_pack,
    wilson_interval,
)

__all__ = [
    "ASSESSABLE_N",
    "CLASSES",
    "THRESHOLDS",
    "ClassResult",
    "PackReport",
    "load_corpus",
    "run_pack",
    "wilson_interval",
]
