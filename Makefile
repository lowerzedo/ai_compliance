UV ?= uv
NPM ?= npm
UI_DIR := ui
MARKDOWN_PATHS := README.md $(wildcard examples/*.md examples/*/*.md) $(if $(wildcard docs),docs)

.PHONY: audit build check docs format format-docs lint sync test typecheck \
	ui-build ui-format-check ui-test ui-typecheck

sync:
	$(UV) sync --all-extras --dev
	$(NPM) --prefix $(UI_DIR) ci

format:
	$(UV) run ruff format .
	$(UV) run ruff check --fix .
	$(UV) run mdformat $(MARKDOWN_PATHS)
	$(NPM) --prefix $(UI_DIR) run format

format-docs:
	$(UV) run mdformat $(MARKDOWN_PATHS)

lint:
	$(UV) run ruff format --check .
	$(UV) run ruff check .

typecheck:
	$(UV) run mypy

ui-format-check:
	$(NPM) --prefix $(UI_DIR) run format:check

ui-typecheck:
	$(NPM) --prefix $(UI_DIR) run typecheck

ui-test:
	$(NPM) --prefix $(UI_DIR) run test

test:
	$(UV) run pytest

docs:
	$(UV) run mdformat --check $(MARKDOWN_PATHS)

ui-build:
	$(NPM) --prefix $(UI_DIR) run build
	$(UV) run python scripts/validate_ui_assets.py

build: ui-build
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
	$(NPM) --prefix $(UI_DIR) run audit

check: lint typecheck test docs ui-format-check ui-typecheck ui-test build
