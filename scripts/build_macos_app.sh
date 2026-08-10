#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

python_bin=${PYTHON_BIN:-python3}
"$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else "Python 3.11 or newer is required")'
"$python_bin" -m pip install -r requirements-dev.txt
"$python_bin" -m PyInstaller --clean --noconfirm AegisScan.spec

printf '%s\n' "Built $project_dir/dist/AegisScan.app"
