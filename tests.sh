#!/bin/bash

set -eo pipefail

# Pytests
poetry run playwright install --with-deps chromium
poetry run pytest -vvvv --cov=src/cspresso --cov-report=term-missing --disable-warnings 
