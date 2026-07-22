UV ?= uv

.PHONY: audit build check docs format format-docs lint sync test typecheck

sync:
	$(UV) sync --all-extras --dev

format:
	$(UV) run ruff format .
	$(UV) run ruff check --fix .
	$(UV) run mdformat README.md docs

format-docs:
	$(UV) run mdformat README.md docs

lint:
	$(UV) run ruff format --check .
	$(UV) run ruff check .

typecheck:
	$(UV) run mypy

test:
	$(UV) run pytest

docs:
	$(UV) run mdformat --check README.md docs

build:
	$(UV) build --clear
	$(UV) run twine check --strict dist/*
	$(UV) run python scripts/validate_distribution.py

audit:
	mkdir -p .cache
	$(UV) export --quiet --locked --all-extras --all-groups \
		--no-emit-project --output-file .cache/audit-requirements.txt
	$(UV) run pip-audit --requirement .cache/audit-requirements.txt \
		--require-hashes --disable-pip --progress-spinner=off \
		--cache-dir .cache/pip-audit

check: lint typecheck test docs build
