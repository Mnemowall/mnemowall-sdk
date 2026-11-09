# Mnemowall

**A firewall plus version control for AI agent memory.** Alpha (0.1).

> Your guardrails decide what the agent sees; Mnemowall controls what it remembers, and lets you undo it.

- [`packages/python`](packages/python/README.md): the `mnemowall` Python SDK (Apache-2.0). Quickstart, CLI and limits are there.
- `make demo`: the 8-step demo ([docs/demo.md](docs/demo.md)), with no network and no keys.
- `make bench`: benchmark report (red-team rates with Wilson intervals, benign false positives, hot-path latency, pins and hardware). `make redteam`: the red-team pack on its own.
- Security reports: see [SECURITY.md](SECURITY.md).
