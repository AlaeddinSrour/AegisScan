# Contributing to AegisScan

Thanks for helping improve AegisScan. Keep changes focused, testable, and explicit
about their security and privacy effects.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.lock
```

The `.txt` requirements are dependency inputs; the `.lock` files pin transitive
versions and hashes for local builds and GitHub Actions. To intentionally update
them with Python 3.11 or newer:

```bash
python -m pip install uv==0.12.10
PYTHON_BIN=python ./scripts/lock_dependencies.sh --upgrade
```

Commit both locks together and rerun the quality gates. The universal resolver
includes platform-specific dependencies; actual platform compatibility is checked
by CI and release builds. The independent fixture benchmark exercises vulnerable
and safe SQL, file-path, and network-request cases using the bundled rules.

Run the quality gates before opening a pull request:

```bash
python -m compileall -q src aegisscan_app.py
python -m ruff check src tests aegisscan_app.py
QT_QPA_PLATFORM=offscreen python -m pytest \
  --cov=src --cov-report=term-missing --cov-fail-under=70
```

## Pull requests

- Add or update regression tests for behavior changes.
- Preserve repository-boundary, disposition-ledger, and patch-safety guarantees.
- Never commit credentials, private repositories, exported reports, build output,
  or user-specific paths.
- Treat intentionally vulnerable files in `tests/fixtures/` as test data; do not
  “fix” them unless the associated test is being changed deliberately.
- Update `README.md` when setup, configuration, privacy behavior, or user-visible
  workflows change.
- Keep generated `build/` and `dist/` artifacts out of pull requests.

For vulnerability reports, follow `SECURITY.md` instead of opening a public issue.
