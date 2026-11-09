"""pytest plugin: provides the ``mnemowall_redteam`` fixture (registered via ``pytest11``).

Imports nothing heavy at load time, so installing mnemowall never breaks a test run that
doesn't use the fixture (LangGraph is imported only when the pack runs).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest


@pytest.fixture
def mnemowall_redteam() -> Callable[..., Any]:
    """Return ``mnemowall.redteam.run_pack``: ``report = mnemowall_redteam(protected=True)``.

    Pass ``sample=N`` for a quick run over the first N attacks per class.
    """
    from mnemowall.redteam import run_pack  # lazy by design

    return run_pack
