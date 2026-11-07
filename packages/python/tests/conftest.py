"""Hypothesis profiles: `ci` (default, 500 examples) and `nightly` (10,000 examples); Mem0 env."""

import os
import tempfile

from hypothesis import settings

# Mem0 reads these at import time (D43): no telemetry, and nothing written under ~/.mem0.
os.environ["MEM0_TELEMETRY"] = "False"
os.environ.setdefault("MEM0_DIR", tempfile.mkdtemp(prefix="mem0-test-"))

settings.register_profile("ci", max_examples=500, deadline=None)
settings.register_profile("nightly", max_examples=10_000, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))
