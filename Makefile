# Variables
PYTHON := /usr/bin/env python3
UV_RUN := uv run
UV_PIP := uv pip

.PHONY: run test ci clean build shiv publish-pypi publish pre-commit reset-uv lint

# If the first argument is "run"...
ifeq (run,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "run"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
endif

run:
	$(UV_RUN) -m src.mcp_scan.run ${RUN_ARGS}


lint:
	$(UV_RUN) ruff format && \
	$(UV_RUN) ruff check --fix

test:
	export MCP_SCAN_ENVIRONMENT=test && \
	$(UV_PIP) install -e .[test] && \
	$(UV_RUN) pytest

ci:
	export MCP_SCAN_ENVIRONMENT=ci && \
	$(UV_PIP) install -e .[test] && \
	$(UV_RUN) pytest

clean:
	rm -rf ./dist
	rm -rf ./mcp_scan/mcp_scan.egg-info
	rm -rf ./npm/dist

build: clean
	uv build --no-sources

shiv: build
	$(UV_PIP) install -e .[dev]
	mkdir -p dist
	$(UV_RUN) shiv -c mcp-scan -o dist/mcp-scan.pyz --python "$(PYTHON)" dist/*.whl

publish-pypi: build
	uv publish --token ${PYPI_TOKEN}

publish: publish-pypi

pre-commit:
	pre-commit run --all-files

reset-uv:
	rm -rf .venv 2>/dev/null || true
	rm uv.lock 2>/dev/null || true
	uv venv
