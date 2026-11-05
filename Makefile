# Gates (§7.0). `make check` must stay under 5 minutes.
PY := packages/python
UV := uv --directory $(PY)

.PHONY: check lint type test secrets audit sbom workflows

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
	gitleaks git --no-banner --redact .

workflows:
	uvx zizmor==1.31.1 --offline .github/workflows

audit:
	$(UV) export --locked --no-emit-project --format requirements-txt --output-file .audit-reqs.txt --quiet
	$(UV) run --locked pip-audit --strict --disable-pip --require-hashes -r .audit-reqs.txt

sbom:
	$(UV) run --locked cyclonedx-py environment --output-format JSON --output-file ../../sbom.cdx.json
