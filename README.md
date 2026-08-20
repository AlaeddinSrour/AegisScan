# AegisScan

[![CI](https://github.com/AlaeddinSrour/AegisScan/actions/workflows/ci.yml/badge.svg)](https://github.com/AlaeddinSrour/AegisScan/actions/workflows/ci.yml)
[![AegisScan](https://github.com/AlaeddinSrour/AegisScan/actions/workflows/aegisscan.yml/badge.svg)](https://github.com/AlaeddinSrour/AegisScan/actions/workflows/aegisscan.yml)

Local-first macOS security auditing with repository-wide Semgrep discovery,
OSV dependency checks, redacted current/history secret detection, bounded Gemini
triage, an explicit evidence ledger, and guarded remediation.

> **Project status:** Version 0.3.1 beta. AegisScan is suitable for evaluation and
> development workflows, but findings and generated fixes still require human
> review before production use.

Version 0.3.1 improves audit accuracy with canonical duplicate findings,
current/history secret provenance, bounded JavaScript/TypeScript helper context,
separate scanner diagnostics, and dependency inventory telemetry. It retains the
reproducible multi-language SSRF and TOCTOU coverage introduced in version 0.3.0.

The desktop workspace also supports credential-free detector-only audits,
scanner readiness diagnostics, and persistent local audit comparisons that show
new, resolved, and unchanged actionable findings.

The current bundled JavaScript/TypeScript coverage floor also discovers Express
flows for command injection, path traversal, dynamic code evaluation, unsafe
deserialization, object-level authorization review, and reflected/DOM XSS.

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
- Applies centralized credential redaction to repository context before AI
  requests and again before JSON, SARIF, or UI retention.
- Assigns every candidate a stable ID and a final disposition: confirmed,
  needs review, duplicate, false positive, or non-runtime. Consolidated evidence
  points to its canonical finding instead of being mislabeled as a false alarm.
- Separates runtime code from tests, fixtures, generated files, dependencies,
  documentation, and project-defined ignored paths.
- Optionally sends findings to Gemini in bounded batches and requires structured,
  schema-validated responses; detector-only audits keep runtime candidates in
  Needs review without contacting an AI provider.
- Requires source, sink, reachability, and confidence evidence before promoting
  an issue to Confirmed.
- Includes bundled Python, JavaScript/TypeScript, Go, Java, and C# discovery for
  user-controlled URLs reaching common HTTP clients (SSRF) and filesystem
  check-then-use sequences (TOCTOU).
- Applies only deterministic safety-approved patches and validates modified
  syntax before committing an atomic file update.
- Can optionally publish AegisScan-created fixes on a dedicated GitHub branch
  and pull request.

## Privacy and trust boundary

Semgrep and secret scanning, scope classification, patch validation, finding
comparison, and file modification happen locally. Betterleaks network validation
is deliberately not enabled, so candidate credentials are not sent to provider
APIs. OSV-Scanner may query vulnerability/package metadata services using
dependency names and versions. The default bundled Semgrep mode is offline and
content-fingerprinted; the optional extended mode downloads mutable community
registry packs from Semgrep. When AI triage is enabled, AegisScan sends Gemini
the Semgrep finding, a bounded source excerpt around it, and locally generated
structural context, including bounded definitions of imported JavaScript and
TypeScript helpers used by a finding.
Dependency and secret findings bypass Gemini. Detector-only mode sends no
repository source or finding context to an AI provider. Do not enable AI triage
for a repository whose source is not permitted to be sent to the configured
Gemini service.

Gemini and GitHub credentials are held in memory by the desktop app and are not
saved in application preferences. Exported reports and local environment files
are ignored by Git. Repository text is treated as untrusted prompt input, and
the model cannot write files directly. Secret-shaped values found through any
detector are replaced with `[REDACTED SECRET]` before AI triage and report
serialization. Audit history stores at most 100 local
summary records and opaque finding fingerprints—not source excerpts or raw
finding IDs—and can be cleared from the Activity page.

## Requirements

| Component | Requirement |
| --- | --- |
| Operating system | macOS 12 or newer for the desktop app |
| Python | 3.11 or newer when running from source |
| Semgrep | 1.172 or newer; must be available on `PATH` or via `SEMGREP_COMMAND` |
| OSV-Scanner | Version 2; must be available on `PATH` or via `OSV_SCANNER_COMMAND` |
| Betterleaks | Current release; must be available on `PATH` or via `BETTERLEAKS_COMMAND` |
| Gitleaks | Optional compatibility fallback when Betterleaks is unavailable |
| Gemini | API key with model access; optional in detector-only desktop and CLI modes |

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
2. Open **Scanner Readiness** to verify the enabled local tools.
3. Enable Gemini triage and enter an API key under **New Audit** or
   **Settings**, or disable it for a local detector-only audit.
4. Keep automatic fixes disabled for the first review.
5. Choose **Reproducible** bundled rules, or explicitly select **Extended** if
   live Semgrep Registry augmentation is desired.
6. Run the audit and inspect **Confirmed**, **Needs review**, and
   **Non-runtime** separately.
7. Review the **Activity** comparison, then export JSON for archival or SARIF
   for GitHub/CI integration.

## How an audit works

1. Semgrep runs the versioned bundled coverage-floor rules against the configured
   repository scope and records their SHA-256 fingerprint. Extended mode also
   downloads the mutable `security-audit` and Python registry packs. The bundled
   floor includes SSRF taint flows and common TOCTOU sequences for Python,
   JavaScript/TypeScript, Go, Java, and C#.
2. OSV-Scanner checks supported dependency manifests and lockfiles and records
   discovered/scanned manifest and package inventory telemetry. Betterleaks
   scans current files and Git history with 100% match redaction; repeated
   secret evidence is consolidated while preserving current/history scope,
   occurrence count, and redacted commit provenance. Gitleaks is used only when
   Betterleaks is unavailable.
3. Every raw result receives a stable detector-specific identifier and a
   deterministic code role.
4. Exact duplicate Semgrep records are removed. Secret matches in tests,
   fixtures, generated files, documentation, dependencies, and ignored paths
   are retained as Non-runtime instead of inflating the review queue.
5. Semgrep findings are grouped by directory and packed into batches of at most 15.
   Python files receive local import, definition, and call-edge context;
   JavaScript and TypeScript findings receive bounded imported-helper context.
6. Deterministic and non-runtime findings bypass Gemini. With AI triage enabled,
   runtime Semgrep findings are sent through the stable `gemini-3.6-flash` →
   `gemini-3.5-flash` failover chain. With it disabled, those candidates remain
   explicitly visible under Needs review.
7. The returned JSON is validated as a strict `ReviewReport`. Missing or invalid
   candidate decisions become Needs review instead of disappearing.
8. Confirmed findings are reconciled against real repository paths, lines, code
   roles, and canonical sensitive sinks. Overlapping Semgrep and secret-scanner
   findings at the same sink are consolidated into one issue.
9. Bundled rule IDs are normalized independently of local installation paths,
   and report provenance records the AegisScan version, timestamps, target Git
   commit/branch/dirty state, AI model chain, ruleset hash, and scan settings.
10. Optional fixes pass secret, control-flow, ambiguity, and syntax checks before
   an atomic write.

Semgrep parser errors in known non-runtime files remain visible as scanner
diagnostics, separate from vulnerability totals. Runtime resource-limit failures
become Needs review and mark the audit
degraded. Global or runtime parser failures stop the audit because completeness
is unknown. Known vendored browser assets and generated bundles are scoped out
deterministically unless a repository override forces them into runtime scope.

If some or all Gemini batches fail, the desktop app finishes in visibly degraded
mode, suppresses the posture score, and preserves every untriaged runtime
candidate under Needs review. The CLI still writes the report and exits with
status `2`, preventing automation from treating incomplete triage as success.

## Desktop workspace

- **Dashboard** — posture, confirmed-risk metrics, review backlog, and scan state.
- **New audit** — repository, optional AI triage, scanner, remediation, and
  publishing controls.
- **Activity** — persistent local summaries with new/resolved/unchanged
  comparisons.
- **Confirmed** — runtime findings that passed the evidence gate.
- **Critical & high** — focused priority queue.
- **Needs review** — incomplete evidence, omitted candidates, and failed batches.
- **Non-runtime** — scoped-out evidence retained for auditability.
- **Reports** — JSON and SARIF 2.1.0 export plus the retained analysis summary.
- **Integrations** — optional GitHub pull-request publishing.
- **Scanner Readiness** — tool availability, versions, executable paths, and
  setup guidance.
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

The Semgrep rule mode is selected in **New audit** or **Settings**, or with
`--semgrep-rule-mode` in the CLI:

- `bundled` (default) uses only version-controlled AegisScan rules, works offline,
  and records the exact rules file SHA-256 in JSON and SARIF reports.
- `extended` adds the live `p/security-audit` and `p/python` registry packs. It
  provides broader community coverage, but requires network access and is not
  reproducible because registry contents can change independently of AegisScan.

## CLI

The CLI writes a report but does not modify or publish anything unless requested:

```bash
python -m src.full_scan \
  --repo /path/to/repository \
  --api-key "$GEMINI_API_KEY" \
  --batch-size 12 \
  --max-target-bytes 1000000 \
  --semgrep-rule-mode bundled \
  --exclude .git --exclude .venv --exclude node_modules \
  --report aegisscan-report.json \
  --sarif aegisscan-results.sarif
```

The JSON report includes detector telemetry, scanner diagnostics, duplicate
links, and secret current/history provenance. SARIF contains Confirmed and Needs
review results, while excluding deterministically Non-runtime, Duplicate, and
False positive evidence. It can be uploaded to
GitHub Code Scanning or consumed by SARIF-compatible CI and editor tooling.

For a local or CI audit that does not send code context to Gemini and needs no
API key, use detector-only mode. Runtime candidates remain visible as Needs
review instead of being promoted to Confirmed:

```bash
python -m src.full_scan \
  --repo /path/to/repository \
  --detector-only \
  --semgrep-rule-mode bundled \
  --report aegisscan-report.json \
  --sarif aegisscan-results.sarif
```

The included `aegisscan.yml` workflow runs this reproducible mode on pushes and
pull requests, retains both reports as artifacts, and uploads SARIF to GitHub
Code Scanning. Dependency and secret scanning are disabled in that workflow
because those external binaries are not installed on its runner; full local
audits keep both detectors enabled by default.

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

Pushing a semantic version tag such as `v0.3.0` runs
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
- The JavaScript/TypeScript regression floor covers representative SQL injection,
  SSRF, TOCTOU, command injection, path traversal, dynamic code evaluation,
  unsafe deserialization, object-level authorization candidates, hardcoded
  cryptographic material, and response/DOM XSS patterns. Business-logic findings
  still require contextual or dynamic testing.
- SSRF coverage follows recognized web-request sources into common Python,
  JavaScript/TypeScript, Go, Java, and C# HTTP clients. Custom frameworks,
  wrapper clients, dynamically constructed call paths, DNS rebinding, and
  redirect behavior can still require manual review or dynamic testing.
- TOCTOU coverage finds common filesystem existence/access checks followed by
  path operations, including Python `pathlib`, Node promise APIs, Go early
  guards, Java `File`/`Files`, and C# synchronous or asynchronous reads. It does
  not prove exploitability, model operating-system permissions, or detect every
  cross-function and asynchronous race.
- Confirmed SSRF and TOCTOU findings always require manual remediation because
  safe destination policies and atomic filesystem semantics are application-specific.
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
