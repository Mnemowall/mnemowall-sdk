# Gates (§7.0). `make check` must stay under 5 minutes.
PY := packages/python
UV := uv --directory $(PY)

.PHONY: check lint type test secrets audit sbom workflows bench redteam

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

# M1a-24: hot-path p99 per stage (§3.8). Budgets apply to 1 KB; record hardware and load.
bench:
	$(UV) run --locked python -m mnemowall.bench --iterations 10000 --out ../../bench-results.json

# M1a-23: red-team pack v0 against the protected and the unprotected setup.
redteam:
	$(UV) run --locked mnemowall redteam
	-$(UV) run --locked mnemowall redteam --unprotected
