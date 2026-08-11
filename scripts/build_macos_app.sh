#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

if [ -n "${PYTHON_BIN:-}" ]; then
    python_bin=$PYTHON_BIN
else
    bootstrap_python=${PYTHON_BOOTSTRAP:-python3}
    build_venv="$project_dir/.build-venv"
    "$bootstrap_python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else "Python 3.11 or newer is required")'
    "$bootstrap_python" -m venv "$build_venv"
    python_bin="$build_venv/bin/python"
fi

"$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else "Python 3.11 or newer is required")'
"$python_bin" -m pip install -r requirements-dev.txt
"$python_bin" -m PyInstaller --clean --noconfirm AegisScan.spec

printf '%s\n' "Built $project_dir/dist/AegisScan.app"
