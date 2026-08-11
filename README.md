# AegisScan

[![CI](https://github.com/AlaeddinSrour/AegisScan/actions/workflows/ci.yml/badge.svg)](https://github.com/AlaeddinSrour/AegisScan/actions/workflows/ci.yml)

Local-first macOS security auditing with repository-wide Semgrep discovery,
OSV dependency checks, redacted current/history secret detection, bounded Gemini
triage, an explicit evidence ledger, and guarded remediation.

> **Project status:** Version 0.2.1 beta. AegisScan is suitable for evaluation and
> development workflows, but findings and generated fixes still require human
> review before production use.

## Why AegisScan

Static analyzers are good at finding suspicious syntax, but a raw alert is not
the same thing as a reachable vulnerability. AegisScan adds repository context
and preserves the complete decision trail:

- Scans the selected repository with Semgrep instead of silently limiting the
  audit to changed lines.
- Matches resolved packages from supported manifests and lockfiles against the
  OSV vulnerability database.
- Scans both current files and Git history with Betterleaks while discarding
  matched secret values before results enter the report. Gitleaks remains a
  compatibility fallback during the transition.
- Assigns every candidate a stable ID and a final disposition: confirmed,
  needs review, false positive, or non-runtime.
- Separates runtime code from tests, fixtures, generated files, dependencies,
  documentation, and project-defined ignored paths.
- Sends findings to Gemini in bounded batches and requires structured,
  schema-validated responses.
- Requires source, sink, reachability, and confidence evidence before promoting
  an issue to Confirmed.
- Applies only deterministic safety-approved patches and validates modified
  syntax before committing an atomic file update.
- Can optionally publish AegisScan-created fixes on a dedicated GitHub branch
  and pull request.

## Privacy and trust boundary

Semgrep and secret scanning, scope classification, patch validation, and file
modification happen locally. Betterleaks network validation is deliberately not
enabled, so candidate credentials are not sent to provider APIs. OSV-Scanner may
query vulnerability/package metadata services using dependency names and
versions. For AI triage, AegisScan sends
Gemini the Semgrep finding, a bounded source excerpt around it, and locally
generated structural context. Dependency and secret findings bypass Gemini. Do
not scan a repository whose source is not permitted to be sent to the configured
Gemini service.

Gemini and GitHub credentials are held in memory by the desktop app and are not
saved in application preferences. Exported reports and local environment files
are ignored by Git. Repository text is treated as untrusted prompt input, and
the model cannot write files directly.

## Requirements

| Component | Requirement |
| --- | --- |
| Operating system | macOS 12 or newer for the desktop app |
| Python | 3.11 or newer when running from source |
| Semgrep | 1.172 or newer; must be available on `PATH` or via `SEMGREP_COMMAND` |
| OSV-Scanner | Version 2; must be available on `PATH` or via `OSV_SCANNER_COMMAND` |
| Betterleaks | Current release; must be available on `PATH` or via `BETTERLEAKS_COMMAND` |
| Gitleaks | Optional compatibility fallback when Betterleaks is unavailable |
| Gemini | API key with access to a configured model |

The prebuilt app is architecture-specific. Build on Apple Silicon for an arm64
bundle or on an Intel Mac for an x86_64 bundle.

## Quick start from source

```bash
git clone https://github.com/AlaeddinSrour/AegisScan.git
cd AegisScan
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
export GEMINI_API_KEY="your-key"
python -m src
```

Installing `requirements.txt` provides Semgrep for source-based runs. Install the
supplemental command-line scanners separately:

```bash
brew install osv-scanner betterleaks
```

The desktop app checks `PATH`, `/opt/homebrew/bin`, and `/usr/local/bin` for all
three scanners. If an enabled supplemental scanner is unavailable, AegisScan
preserves the other results and marks the audit incomplete instead of reporting
the repository as clean.

In the app:

1. Choose a repository.
2. Enter a Gemini API key under **New Audit** or **Settings**.
3. Keep automatic fixes disabled for the first review.
4. Run the audit and inspect **Confirmed**, **Needs review**, and
   **Non-runtime** separately.
5. Export the JSON report if an auditable artifact is required.

## How an audit works

1. Semgrep runs the bundled coverage-floor rules plus the `security-audit` and
   Python registries against the configured repository scope.
2. OSV-Scanner checks supported dependency manifests and lockfiles. Betterleaks
   scans current files and Git history with 100% match redaction; Gitleaks is
   used only when Betterleaks is unavailable.
3. Every raw result receives a stable detector-specific identifier and a
   deterministic code role.
4. Exact duplicate Semgrep records are removed. Secret matches in tests,
   fixtures, generated files, documentation, dependencies, and ignored paths
   are retained as Non-runtime instead of inflating the review queue.
5. Semgrep findings are grouped by directory and packed into batches of at most 15.
   Python files receive local import, definition, and call-edge context.
6. Deterministic and non-runtime findings bypass Gemini. Runtime Semgrep findings are sent
   through the stable `gemini-3.6-flash` → `gemini-3.5-flash` failover chain.
7. The returned JSON is validated as a strict `ReviewReport`. Missing or invalid
   candidate decisions become Needs review instead of disappearing.
8. Confirmed findings are reconciled against real repository paths, lines, code
   roles, and canonical sensitive sinks. Overlapping Semgrep and secret-scanner
   findings at the same sink are consolidated into one issue.
9. Optional fixes pass secret, control-flow, ambiguity, and syntax checks before
   an atomic write.

Semgrep parser errors in known non-runtime files remain visible as non-runtime
evidence. Runtime resource-limit failures become Needs review. Global or runtime
parser failures stop the audit because completeness is unknown.

If some or all Gemini batches fail, the desktop app finishes in visibly degraded
mode, suppresses the posture score, and preserves every untriaged runtime
candidate under Needs review. The CLI still writes the report and exits with
status `2`, preventing automation from treating incomplete triage as success.

## Desktop workspace

- **Dashboard** — posture, confirmed-risk metrics, review backlog, and scan state.
- **New audit** — repository, credential, batch, remediation, and publishing controls.
- **Activity** — audits completed during the current app session.
- **Confirmed** — runtime findings that passed the evidence gate.
- **Critical & high** — focused priority queue.
- **Needs review** — incomplete evidence, omitted candidates, and failed batches.
- **Non-runtime** — scoped-out evidence retained for auditability.
- **Reports** — JSON export and the retained analysis summary.
- **Integrations** — optional GitHub pull-request publishing.
- **Settings** — AI and audit defaults.

## Scope overrides

Add repository-relative glob patterns to `.aegisscanignore` in the repository
being scanned:

```gitignore
# Served as examples, not executed by the application
data/static/codefixes/**
custom/generated/**
```

Ignored candidates remain visible under Non-runtime. Prefix a pattern with `!`
to force a normally excluded path back into runtime scope:

```gitignore
generated/**
!generated/runtime/**
```

This scope file controls how findings are classified in the evidence ledger. To
skip files during Semgrep discovery, edit the comma-separated exclusions in **New
Audit** or **Settings**. The maximum Semgrep/secret-scanner target size is configurable
from 1–100 MB; increasing it can materially increase scan time and memory use.

## Configuration

| Environment variable | Purpose | Default |
| --- | --- | --- |
| `GEMINI_API_KEY` | Gemini credential used by the desktop app or CLI | none |
| `AEGISSCAN_GEMINI_MODELS` | Comma-separated model failover order | `gemini-3.6-flash,gemini-3.5-flash` |
| `AEGISSCAN_MAX_RETRIES` | Attempts per retryable model failure | `3` |
| `AEGISSCAN_API_TIMEOUT` | Timeout for one Gemini request, in seconds | `180` |
| `AEGISSCAN_INITIAL_BACKOFF` | Initial retry delay, in seconds | `15` |
| `AEGISSCAN_MAX_OUTPUT_TOKENS` | Maximum structured-response tokens | `16384` |
| `AEGISSCAN_SEMGREP_TIMEOUT` | Full Semgrep process timeout, in seconds | `300` |
| `SEMGREP_COMMAND` | Explicit Semgrep executable path | auto-detected |
| `AEGISSCAN_OSV_TIMEOUT` | OSV-Scanner process timeout, in seconds | `300` |
| `OSV_SCANNER_COMMAND` | Explicit OSV-Scanner executable path | auto-detected |
| `AEGISSCAN_BETTERLEAKS_TIMEOUT` | Secret-scanner timeout per mode, in seconds | `300` |
| `BETTERLEAKS_COMMAND` | Explicit Betterleaks executable path | auto-detected |
| `AEGISSCAN_GITLEAKS_TIMEOUT` | Legacy fallback timeout when the Betterleaks value is unset | `300` |
| `GITLEAKS_COMMAND` | Explicit Gitleaks fallback executable path | auto-detected |
| `GITHUB_TOKEN` | Optional credential for publishing fixes | none |
| `GITHUB_REPOSITORY` | Optional `owner/repository` publishing target | none |

The default model identifiers are explicit rather than moving `-latest` aliases,
so audit behavior does not silently change between releases.

## CLI

The CLI writes a report but does not modify or publish anything unless requested:

```bash
python -m src.full_scan \
  --repo /path/to/repository \
  --api-key "$GEMINI_API_KEY" \
  --batch-size 12 \
  --max-target-bytes 1000000 \
  --exclude .git --exclude .venv --exclude node_modules \
  --report aegisscan-report.json
```

Dependency and secret scanning are enabled by default. Use
`--no-dependency-scan` or `--no-secret-scan` only when intentionally running a
reduced-coverage audit; the chosen configuration is recorded by the live log.

Apply safety-validated fixes:

```bash
python -m src.full_scan \
  --repo /path/to/repository \
  --api-key "$GEMINI_API_KEY" \
  --apply-fixes \
  --report aegisscan-report.json
```

To publish changed files, also provide `--create-pull-request` and configure
`GITHUB_TOKEN` plus `GITHUB_REPOSITORY`. Use a fine-grained token limited to the
target repository with repository contents and pull-request write access. Keep
tokens in environment variables instead of shell-history arguments.

## Build the macOS app

```bash
PYTHON_BOOTSTRAP=python3.13 ./scripts/build_macos_app.sh
dist/AegisScan.app/Contents/MacOS/AegisScan --self-test
codesign --verify --deep --strict dist/AegisScan.app
open dist/AegisScan.app
```

The build script installs development dependencies and creates
`dist/AegisScan.app` from `AegisScan.spec`. Local bundles use ad-hoc signing;
public binary distribution requires the maintainer's Apple Developer ID signing
and notarization workflow.

### GitHub prereleases

Pushing a semantic version tag such as `v0.2.1` runs
`.github/workflows/release.yml`. GitHub builds separate native bundles on
`macos-15-intel` and `macos-15`, verifies their actual `x86_64` and `arm64`
architectures, and publishes both ZIP files plus SHA-256 checksums as a GitHub
prerelease. The automated bundles are ad-hoc signed and not Apple-notarized.

## Development

```bash
python -m pip install -r requirements-dev.txt
python -m compileall -q src aegisscan_app.py
python -m ruff check src tests aegisscan_app.py
QT_QPA_PLATFORM=offscreen python -m pytest \
  --cov=src --cov-report=term-missing --cov-fail-under=70
```

GitHub Actions runs the tests on Python 3.11 and 3.13 and performs a macOS app
build, self-test, and signature verification. Dependabot checks Python and
workflow dependencies weekly. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the
pull-request checklist and [`SECURITY.md`](SECURITY.md) for private vulnerability
reporting guidance.

## Security boundaries and limitations

- AegisScan is not a replacement for manual review, dynamic testing, penetration
  testing, or production monitoring.
- The bundled rules are a coverage floor, not a complete vulnerability taxonomy.
- Dependency matches are version-based; they do not prove that vulnerable code is
  reachable at runtime.
- Secret matches identify credential-shaped values but do not test whether a
  credential is valid. Generic patterns remain Needs review, while specific
  credential formats in current runtime source may be confirmed. Detected
  credentials should still be reviewed and rotated.
- Betterleaks live validation is intentionally disabled because it can make
  outbound requests containing candidate credentials. AegisScan does not enable
  it implicitly.
- Historical secret remediation is manual; AegisScan does not rewrite Git history.
- Large files or unusual languages can exceed Semgrep resource or parser limits;
  those gaps must not be interpreted as clean results.
- Suggested fixes can change behavior and must be reviewed and tested before use.
- Pull-request publishing requires a clean starting branch and stages only files
  changed by AegisScan during the current audit.

## Publishing this repository

Generated application bundles, build directories, caches, credentials, and
exported reports are excluded by `.gitignore`. Before making the repository
public:

1. Choose and add a `LICENSE` appropriate for the intended use.
2. Enable **Private vulnerability reporting** in the repository security settings.
3. Require the CI workflow on the default branch.
4. Create notarized release artifacts separately; do not commit `dist/`.

No license is currently included. Until one is added, copyright law reserves all
rights and others do not receive permission to copy, modify, or distribute the
project.
