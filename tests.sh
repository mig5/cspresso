#!/bin/bash

set -eo pipefail

# Use exactly the same browser cache during installation and crawling.
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-${XDG_CACHE_HOME:-$HOME/.cache}/cspresso/pw-browsers}"

# Deterministic local integration tests. Public-site smoke tests are opt-in.
poetry run playwright install --with-deps chromium
poetry run pytest --run-browser -vvvv --cov=src/cspresso --cov-report=term-missing --disable-warnings
