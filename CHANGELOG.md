# Changelog

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
