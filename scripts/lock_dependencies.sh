#!/bin/sh
# Install uv==0.12.10 in the selected Python environment before running.
set -eu
cd "$(dirname "$0")/.."
lock_python=${PYTHON_BIN:-python3}
"$lock_python" -m uv pip compile requirements-dev.txt --universal \
  --python-version 3.11 --no-python-downloads --generate-hashes \
  --custom-compile-command './scripts/lock_dependencies.sh' \
  --output-file requirements-dev.lock "$@"
"$lock_python" -m uv pip compile requirements.txt --universal \
  --python-version 3.11 --no-python-downloads --generate-hashes \
  --constraints requirements-dev.lock \
  --custom-compile-command './scripts/lock_dependencies.sh' \
  --output-file requirements.lock "$@"
