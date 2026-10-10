#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-.venv/bin/python}"
PYTHONPATH="${PWD}${PYTHONPATH:+:${PYTHONPATH}}" exec "$PYTHON_BIN" -m scripts.demo "$@"
