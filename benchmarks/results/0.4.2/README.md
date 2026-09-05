# 0.4.2 beta validation

Validated on 2026-09-05 before the packaging-only version bump from 0.4.1.
All benchmark repositories were clean and at their pinned commits.

| Benchmark | Mode | Result |
| --- | --- | --- |
| Juice Shop v19 | Bundled rules with AI triage | 12/12 expected statuses and locations; pass |
| WebGoat | Bundled raw Semgrep, production Java sources | 1/1; pass |
| IoTGoat | Bundled detector-only firmware audit | 19/19 and all inventory/provenance gates; pass |

Metrics cover each manifest's scope, not every vulnerability in these projects.
The expected Juice Shop TOCTOU candidate remains Needs review.
Automatic patching and audit PR publishing are paused.

The original report snapshots are archived locally in release/0.4.2/evidence/.
Their checksums are recorded in evidence.json; raw reports are not committed.
Validation: 274 tests passed with 82.96% coverage, plus lint, compilation,
packaged self-test, and code-signature checks.
