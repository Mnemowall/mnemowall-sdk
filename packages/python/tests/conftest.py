"""Hypothesis profiles: `ci` (default, 500 examples) and `nightly` (10,000 examples)."""

import os

from hypothesis import settings

settings.register_profile("ci", max_examples=500, deadline=None)
settings.register_profile("nightly", max_examples=10_000, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))
