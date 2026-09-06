# Changelog

## 0.4.4 beta — 2026-09-06

- Keep request-ID data-access findings anchored to the detector's lookup location
  when AI triage proposes the input assignment or another nearby lookup.

## 0.4.3 beta — 2026-09-06

- Use hashed transitive dependency locks for installation, macOS builds, and CI.
- Add CLI severity and Needs review failure policies with exit code 3, preserving
  exit code 2 for incomplete audits and writing reports before policy failures.
- Add independent vulnerable/safe regression fixtures for SQL injection, path
  traversal, and Python/Java network requests.

## 0.4.2 beta — 2026-09-05

### Benchmark reliability

- Exclude suppressed, duplicate, false-positive, and non-runtime evidence from
  active benchmark scoring without letting it satisfy expected findings.
- Preserve private-key declaration locations in SARIF and retain credential
  use sites as related locations.
- Keep runtime candidates visible when AI incorrectly classifies them as
  non-runtime, and confirm narrowly proven adjacent Sequelize interpolation.
- Recognize closed alphanumeric extension allowlists in path-traversal rules.

### Security

- Resolve expanded JavaScript/TypeScript imports before checking containment,
  preventing symlinks from adding files outside the repository to AI context.
- Redact quoted JSON keys, unquoted YAML/environment values, and escaped quoted
  credentials before prompts and report serialization.
- Pause automatic patching and audit PR publishing until rule-specific
  transformations are vetted. Findings retain manual remediation guidance.
- Reject unsupported patch syntax formats and require manual review for process
  execution, including imported aliases and explicit shell executables.

## 0.4.1 — 2026-08-26

### Changed

- Refined the complete desktop visual system with consistent surfaces, spacing,
  typography, controls, navigation states, and severity-aware dashboard cards.
- Added directional slide-and-fade transitions between workspace pages with
  safe cleanup during rapid navigation.
- Integrated the native macOS traffic-light controls into AegisScan's own
  surfaces, removing the detached title bar while preserving native behavior.
- Reorganized Settings into a compact responsive form and made dense pages
  scroll safely at the minimum supported window size.

### Quality

- Added GUI regression coverage for minimum-size layouts and bidirectional page
  transitions.
- Refreshed the README with a current native workspace screenshot.

## 0.4.0 — 2026-08-25

### Added

- OpenRouter triage with Gemini fallback, adaptive batch splitting, strict
  singleton recovery, aggregate usage telemetry, and an explicit option for
  providers that may retain prompts.
- Multi-language SSRF and TOCTOU coverage, Express open-redirect and IDOR rules,
  and stronger Java and JavaScript/TypeScript security discovery.
- Betterleaks current-tree and Git-history scanning with redacted evidence and a
  Gitleaks compatibility fallback.
- OSV dependency inventory improvements and temporary script-free npm lockfile
  resolution.
- OpenWrt firmware overlay, package, kernel, EOL, and bounded advisory analysis.
- Pinned OWASP Juice Shop, WebGoat, and IoTGoat security regression manifests
  and release gates.

### Changed

- AI verdicts now pass deterministic source, sink, reachability, location, scope,
  and confidence validation before confirmation.
- Large or malformed provider responses recover through bounded retries and
  preserve unresolved candidates for review.
- SARIF now preserves false positives and duplicates as suppressed informational
  evidence with stable fingerprints instead of silently omitting them.
- Vendored browser libraries, bundled static plugins, Maven wrappers, generated
  code, and versioned OpenWrt SDK sources no longer invalidate runtime coverage.
- The New Audit interface scales cleanly with the expanded scanner and provider
  controls.

### Security and privacy

- Secret values are redacted before AI triage and report serialization.
- Betterleaks live credential validation remains disabled.
- OpenRouter data-collecting routes remain disabled by default and require
  explicit opt-in.
