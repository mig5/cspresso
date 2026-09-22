#!/bin/bash

set -eo pipefail

# Runner cache directories can be shared or writable by other users. Unless a
# caller supplies a cache explicitly, create an owned private directory for this
# test run and remove only that directory on exit (including test failures).
if [[ -z "${PLAYWRIGHT_BROWSERS_PATH:-}" ]]; then
  cspresso_test_cache="$(mktemp -d "${TMPDIR:-/tmp}/cspresso-tests.XXXXXXXX")"
  trap 'rm -rf -- "$cspresso_test_cache"' EXIT
  export PLAYWRIGHT_BROWSERS_PATH="$cspresso_test_cache"
fi

# Fail before downloading if an explicit cache violates the runtime checks.
poetry run python -c 'from cspresso.ensure_playwright import configure_browsers_path; configure_browsers_path()'

# Installation and tests inherit exactly the same browser path.
# Public-site smoke tests are opt-in.
poetry run playwright install --with-deps chromium
poetry run pytest --run-browser -vvvv --cov=src/cspresso --cov-report=term-missing --disable-warnings
