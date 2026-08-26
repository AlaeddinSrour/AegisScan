# Changelog

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
