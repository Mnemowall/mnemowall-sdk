# Gates (§7.0). `make check` must stay under 5 minutes.
PY := packages/python
UV := uv --directory $(PY)

.PHONY: check lint type test secrets audit sbom workflows bench redteam demo

check: lint type test secrets workflows

lint:
	$(UV) run --locked ruff check .
	$(UV) run --locked ruff format --check .

type:
	$(UV) run --locked mypy

test:
	$(UV) run --locked pytest

secrets:
	gitleaks dir --no-banner --redact .
	gitleaks git --no-banner --redact --log-opts=HEAD .

workflows:
	uvx zizmor==1.31.1 --offline .github/workflows

audit:
	$(UV) export --locked --no-emit-project --format requirements-txt --output-file .audit-reqs.txt --quiet
	$(UV) run --locked pip-audit --strict --disable-pip --require-hashes -r .audit-reqs.txt

sbom:
	$(UV) run --locked cyclonedx-py environment --output-format JSON --output-file ../../sbom.cdx.json

# M1b-10: benchmark report v0: red-team rates (Wilson 95%), benign false positives and hot-path
# p99 per stage (§3.8, budgets apply to 1 KB), with pins, seed, corpus hash, hardware and load.
bench:
	$(UV) run --locked python -m mnemowall.bench_report --iterations 10000 \
		--json ../../bench-results.json --md ../../bench-report.md

# M1a-23 / M1b-09: red-team pack (corpus v1) against the protected and the unprotected setup.
redteam:
	$(UV) run --locked mnemowall redteam
	-$(UV) run --locked mnemowall redteam --unprotected

# M1a-25: the 8-step scripted demo (docs/demo.md). No network, no keys.
demo:
	$(UV) sync --locked --quiet
	$(UV) run --locked python -m mnemowall.demo
