# If the first argument is "run"...
ifeq (run,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "run"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
endif

run:
	uv run -m src.mcp_scan.run ${RUN_ARGS}

test:
	uv pip install -e .[test]
	MCP_SCAN_ENVIRONMENT=test uv run pytest

ci:
	uv pip install -e .[test]
	MCP_SCAN_ENVIRONMENT=ci uv run pytest

clean:
	rm -rf ./dist
	rm -rf ./mcp_scan/mcp_scan.egg-info
	rm -rf ./npm/dist
	rm -rf ./ame.spec
	rm -rf ./mcp-scan.spec

binary:
	uv sync
	uv pip install -e .[dev]
	uv run pyinstaller --onefile --name mcp-scan src/mcp_scan/run.py

build: clean
	uv build --no-sources

shiv: build
	uv pip install -e .[dev]
	mkdir -p dist
	uv run shiv -c mcp-scan -o dist/mcp-scan.pyz --python "/usr/bin/env python3" dist/*.whl

publish-pypi: build
	uv publish --token ${PYPI_TOKEN}

publish: publish-pypi

pre-commit:
	pre-commit run --all-files

reset-uv:
	rm -rf .venv || true
	rm uv.lock || true
	uv venv

install-dev-server-cursor:
	uv run --directory $PWD -m src.mcp_scan.run install-mcp-server ~/.cursor/mcp.json --background --tool --client-name Cursor

install-dev-server-windsurf:
	uv run --directory $PWD -m src.mcp_scan.run install-mcp-server ~/.codeium/windsurf/mcp_config.json --background --tool --client-name Windsurf
