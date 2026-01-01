#!/bin/bash

set -eo pipefail

# Pytests
poetry run pytest -vvvv --cov=src/cspresso --cov-report=term-missing --disable-warnings
