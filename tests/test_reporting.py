import json

from src.full_scan import ScanOutcome
from src.models import FindingDisposition, ReviewIssue, ReviewReport
from src.reporting import build_report_payload, build_sarif_payload, write_sarif_report


def _outcome() -> ScanOutcome:
    issue = ReviewIssue(
        file="src/proxy.py",
        line=12,
        severity="HIGH",
        issue_name="Server-Side Request Forgery",
        description="User input reaches an outbound request without a destination policy.",
        original_code="requests.get(target)",
        suggested_fix="validate_destination(target)",
        finding_id="SG-confirmed",
        rule_id="aegisscan.python.user-input-to-network-request",
        confidence="HIGH",
        code_role="RUNTIME",
        source_evidence="request.args supplies target",
        sink_evidence="requests.get opens the destination",
        sink_file="src/proxy.py",
        sink_line=12,
        reachability_evidence="The route calls requests.get directly.",
        remediation_type="MANUAL_REQUIRED",
    )
    dispositions = [
        FindingDisposition(
            finding_id="SG-confirmed",
            status="CONFIRMED",
            reason="Complete source-to-sink evidence.",
            file="src/proxy.py",
            line=12,
            rule_id=issue.rule_id,
            code_role="RUNTIME",
            confidence="HIGH",
        ),
        FindingDisposition(
            finding_id="SG-review",
            status="NEEDS_REVIEW",
            reason="Cross-function reachability is incomplete.",
            file="src/files.py",
            line=7,
            rule_id="aegisscan.python.filesystem-check-then-use",
            message="Potential filesystem race.",
            code_role="RUNTIME",
            confidence="LOW",
        ),
        FindingDisposition(
            finding_id="SG-fixture",
            status="NON_RUNTIME",
            reason="Fixture code.",
            file="tests/example.py",
            line=2,
            rule_id="test.rule",
            code_role="FIXTURE",
            confidence="HIGH",
        ),
    ]
    return ScanOutcome(
        report=ReviewReport(
            analysis_scratchpad="Validated one SSRF flow.",
            issues=[issue],
            dispositions=dispositions,
        ),
        raw_finding_count=3,
        batch_count=1,
        semgrep_rule_mode="bundled",
        semgrep_rules_sha256="a" * 64,
        scan_started_at="2026-08-20T10:00:00+00:00",
        scan_completed_at="2026-08-20T10:01:00+00:00",
        repository_name="juice-shop",
        repository_commit="b" * 40,
        repository_branch="main",
        repository_dirty=False,
        ai_provider_order=["openrouter", "gemini"],
        ai_models=["gemini-test"],
        scan_exclusions=[".git"],
        max_target_bytes=2_000_000,
    )


def test_json_report_records_reproducible_rule_identity():
    payload = build_report_payload(_outcome())

    assert payload["summary"]["semgrep_rule_mode"] == "bundled"
    assert payload["summary"]["semgrep_rules_sha256"] == "a" * 64
    assert payload["summary"]["ai_triage_enabled"] is True
    assert payload["summary"]["confirmed_issues"] == 1
    assert payload["summary"]["firmware_findings"] == 0
    assert payload["summary"]["needs_review"] == 1
    assert payload["summary"]["provenance"] == {
        "aegisscan_version": "0.4.3",
        "scan_started_at": "2026-08-20T10:00:00+00:00",
        "scan_completed_at": "2026-08-20T10:01:00+00:00",
        "repository_name": "juice-shop",
        "repository_commit": "b" * 40,
        "repository_branch": "main",
        "repository_dirty": False,
        "ai_provider_order": ["openrouter", "gemini"],
        "ai_models": ["gemini-test"],
    }
    assert payload["summary"]["configuration"]["ai_provider_order"] == [
        "openrouter",
        "gemini",
    ]
    assert payload["summary"]["configuration"]["max_target_bytes"] == 2_000_000


def test_json_report_separates_scanner_diagnostics_and_detector_telemetry():
    outcome = _outcome()
    outcome.dependency_finding_count = 1
    outcome.detector_telemetry = {
        "osv": {
            "status": "completed",
            "manifests_discovered": 2,
            "manifests_scanned": 2,
            "packages_queried": 42,
            "unique_advisories": 7,
            "exported_dependency_findings": 1,
            "exported_unique_advisories": 1,
        }
    }
    outcome.detector_coverage_gaps = {"osv": ["package.json has no supported lockfile"]}
    outcome.scanner_diagnostics = {
        "semgrep": [
            {
                "kind": "Syntax error",
                "file": "tests/broken.ts",
                "line": 9,
                "code_role": "TEST",
                "message": "Non-runtime parsing was incomplete.",
            }
        ]
    }

    payload = build_report_payload(outcome)

    assert payload["summary"]["total_detector_findings"] == 4
    assert payload["summary"]["scanner_diagnostic_count"] == 1
    assert payload["summary"]["scanner_diagnostics"]["semgrep"][0]["file"] == ("tests/broken.ts")
    assert payload["summary"]["detector_telemetry"]["osv"]["packages_queried"] == 42
    assert payload["summary"]["dependency_finding_occurrences"] == 1
    assert payload["summary"]["raw_dependency_finding_occurrences"] == 1
    assert payload["summary"]["unique_dependency_advisories"] == 1
    assert payload["summary"]["detector_coverage_gaps"] == {
        "osv": ["package.json has no supported lockfile"]
    }
    assert payload["summary"]["audit_degraded"] is True


def test_sarif_summarizes_repeated_scanner_diagnostics_without_hiding_total():
    outcome = _outcome()
    outcome.scanner_diagnostics = {
        "semgrep": [
            {
                "kind": "Partial parsing",
                "file": f"vendor/source-{index}.c",
                "line": 1,
                "code_role": "DEPENDENCY",
                "message": "Dependency parser diagnostic.",
            }
            for index in range(40)
        ]
    }

    invocation = build_sarif_payload(outcome)["runs"][0]["invocations"][0]
    notifications = invocation["toolExecutionNotifications"]
    summary = notifications[-1]

    assert invocation["properties"]["scannerDiagnosticCount"] == 40
    assert len(notifications) == 26
    assert summary["descriptor"]["id"] == "semgrep.diagnostics-summarized"
    assert summary["properties"]["omittedDiagnosticDetails"] == 15
    assert summary["properties"]["countsByKindAndRole"] == {
        "Partial parsing [DEPENDENCY]": 40
    }


def test_sarif_contains_confirmed_and_needs_review_but_not_non_runtime():
    payload = build_sarif_payload(_outcome())
    run = payload["runs"][0]

    assert payload["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "AegisScan"
    assert len(run["results"]) == 2
    assert {item["properties"]["status"] for item in run["results"]} == {
        "CONFIRMED",
        "NEEDS_REVIEW",
    }
    assert run["results"][0]["level"] == "error"
    assert (
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "src/proxy.py"
    )
    confirmed_rule = run["tool"]["driver"]["rules"][0]
    assert "CWE-918" in confirmed_rule["properties"]["tags"]
    assert run["invocations"][0]["properties"]["semgrepRulesSha256"] == "a" * 64
    assert run["invocations"][0]["properties"]["aiTriageEnabled"] is True
    assert run["invocations"][0]["properties"]["repositoryCommit"] == "b" * 40


def test_sarif_exposes_secret_scanner_counts_and_dispositions():
    outcome = _outcome()
    outcome.secret_finding_count = 4
    outcome.secret_scanner = "betterleaks"
    outcome.report.dispositions.append(
        FindingDisposition(
            finding_id="SECRET-dependency",
            status="NON_RUNTIME",
            reason="The pattern is in vendored dependency source.",
            file="vendor/example.txt",
            line=1,
            rule_id="betterleaks.generic-password",
            code_role="DEPENDENCY",
            evidence_scope="CURRENT",
        )
    )

    properties = build_sarif_payload(outcome)["runs"][0]["invocations"][0]["properties"]

    assert properties["rawSecretFindingOccurrences"] == 4
    assert properties["secretScanner"] == "betterleaks"
    assert properties["secretDispositionCounts"] == {"NON_RUNTIME": 1}
    assert properties["exportedConfirmedSecretFindings"] == 0


def test_sarif_omits_history_only_secrets_by_default_but_can_include_them():
    outcome = _outcome()
    outcome.report.dispositions.append(
        FindingDisposition(
            finding_id="SECRET-history",
            status="NEEDS_REVIEW",
            reason="A redacted historical credential pattern needs review.",
            file="removed/credentials.json",
            line=40,
            rule_id="betterleaks.generic-password",
            message="Generic password",
            code_role="RUNTIME",
            confidence="MEDIUM",
            evidence_scope="GIT_HISTORY",
            commit="1234567890ab",
            commits=["1234567890ab"],
        )
    )

    default_payload = build_sarif_payload(outcome)
    complete_payload = build_sarif_payload(outcome, include_historical_secrets=True)

    default_run = default_payload["runs"][0]
    assert len(default_run["results"]) == 2
    assert default_run["invocations"][0]["properties"]["historicalSecretFindingsOmitted"] == 1
    assert (
        default_run["invocations"][0]["properties"]["historicalSecretExportPolicy"]
        == "CURRENT_TREE_ONLY"
    )
    omission = next(
        item
        for item in default_run["invocations"][0]["toolConfigurationNotifications"]
        if item["descriptor"]["id"] == "aegisscan.historical-secrets-omitted"
    )
    assert omission["properties"]["omittedFindings"] == 1
    historical = next(
        item
        for item in complete_payload["runs"][0]["results"]
        if item["partialFingerprints"]["aegisscanFindingId"] == "SECRET-history"
    )
    assert historical["properties"]["evidenceScope"] == "GIT_HISTORY"
    assert historical["properties"]["commits"] == ["1234567890ab"]


def test_sarif_exports_scanner_and_coverage_diagnostics_as_notifications():
    outcome = _outcome()
    outcome.scanner_diagnostics = {
        "semgrep": [
            {
                "kind": "Syntax error",
                "file": "tests/broken.ts",
                "line": 9,
                "code_role": "TEST",
                "message": "Parsing was incomplete.",
            }
        ]
    }
    outcome.detector_coverage_gaps = {"osv": ["package.json has no supported lockfile"]}

    invocation = build_sarif_payload(outcome)["runs"][0]["invocations"][0]

    diagnostic = invocation["toolExecutionNotifications"][0]
    assert diagnostic["descriptor"]["id"] == "semgrep.syntax-error"
    assert diagnostic["level"] == "note"
    assert (
        diagnostic["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "tests/broken.ts"
    )
    assert invocation["toolConfigurationNotifications"][0]["descriptor"]["id"] == "osv.coverage-gap"
    assert invocation["properties"]["scannerDiagnosticCountsByRole"] == {"TEST": 1}
    assert invocation["properties"]["runtimeScannerDiagnosticCount"] == 0
    assert invocation["properties"]["nonRuntimeScannerDiagnosticCount"] == 1


def test_sarif_explains_incomplete_ai_triage():
    outcome = _outcome()
    outcome.ai_attempted_batches = 2
    outcome.ai_successful_batches = 1
    outcome.failed_batches = [2]
    outcome.failed_batch_reasons = {2: "OpenRouter exceeded the wall-clock deadline."}

    invocation = build_sarif_payload(outcome)["runs"][0]["invocations"][0]

    assert invocation["properties"]["aiTriageDegraded"] is True
    assert invocation["properties"]["aiAttemptedBatches"] == 2
    assert invocation["properties"]["aiSuccessfulBatches"] == 1
    assert invocation["properties"]["failedBatches"] == [2]
    assert invocation["properties"]["failedBatchReasons"] == {
        2: "OpenRouter exceeded the wall-clock deadline."
    }
    failure = invocation["toolExecutionNotifications"][0]
    assert failure["descriptor"]["id"] == "aegisscan.ai-triage-failed"
    assert failure["properties"]["batch"] == 2


def test_sarif_preserves_rejected_candidates_as_suppressed_evidence():
    outcome = _outcome()
    outcome.report.dispositions.extend(
        [
            FindingDisposition(
                finding_id="SG-rejected",
                status="FALSE_POSITIVE",
                reason="A destination allowlist prevents attacker-controlled requests.",
                file="src/client.py",
                line=14,
                rule_id="aegisscan.python.user-input-to-network-request",
                message="Potential SSRF.",
                code_role="RUNTIME",
                confidence="HIGH",
            ),
            FindingDisposition(
                finding_id="SG-duplicate",
                status="DUPLICATE",
                reason="This candidate resolves to the confirmed canonical sink.",
                file="src/proxy.py",
                line=9,
                rule_id="python.requests.security.audit.requests-use",
                message="Potential outbound request.",
                code_role="RUNTIME",
                confidence="HIGH",
                canonical_finding_id="SG-confirmed",
            ),
        ]
    )

    run = build_sarif_payload(outcome)["runs"][0]
    suppressed = [result for result in run["results"] if result.get("suppressions")]

    assert {result["properties"]["status"] for result in suppressed} == {
        "FALSE_POSITIVE",
        "DUPLICATE",
    }
    assert all(result["level"] == "note" for result in suppressed)
    assert all(result["suppressions"][0]["status"] == "accepted" for result in suppressed)
    assert run["invocations"][0]["properties"]["dispositionCounts"] == {
        "CONFIRMED": 1,
        "DUPLICATE": 1,
        "FALSE_POSITIVE": 1,
        "NEEDS_REVIEW": 1,
        "NON_RUNTIME": 1,
    }
    assert (
        run["invocations"][0]["properties"]["exportedSuppressedDispositionCount"]
        == 2
    )


def test_json_and_sarif_include_ai_response_quality_telemetry():
    outcome = _outcome()
    outcome.ai_telemetry = {
        "semantic_defects_repaired": 3,
        "targeted_retriage_attempts": 2,
        "targeted_retriage_recovered": 1,
        "targeted_retriage_unresolved": 1,
    }

    assert build_report_payload(outcome)["summary"]["ai_telemetry"] == outcome.ai_telemetry
    invocation = build_sarif_payload(outcome)["runs"][0]["invocations"][0]
    assert invocation["properties"]["aiTelemetry"] == outcome.ai_telemetry


def test_sarif_separates_dependency_occurrences_from_unique_advisories():
    outcome = _outcome()
    outcome.dependency_finding_count = 9
    outcome.detector_telemetry = {
        "osv": {
            "raw_unique_advisories": 7,
            "exported_dependency_findings": 6,
            "exported_unique_advisories": 5,
        }
    }

    invocation = build_sarif_payload(outcome)["runs"][0]["invocations"][0]

    assert invocation["properties"]["rawDependencyFindingOccurrences"] == 9
    assert invocation["properties"]["dependencyFindingOccurrences"] == 6
    assert invocation["properties"]["uniqueDependencyAdvisories"] == 5


def test_sarif_marks_dependency_version_match_separately_from_runtime_reachability():
    outcome = _outcome()
    outcome.report.issues[0] = outcome.report.issues[0].model_copy(
        update={
            "rule_id": "osv.GHSA-test-advisory",
            "issue_name": "Vulnerable dependency: library",
            "description": "library 1.0.0 matches GHSA-test-advisory.",
            "reachability_evidence": (
                "The vulnerable version is present in dependency metadata; runtime call "
                "reachability was not established."
            ),
            "remediation_type": "MANUAL_REQUIRED",
        }
    )

    result = build_sarif_payload(outcome)["runs"][0]["results"][0]

    assert result["properties"]["findingType"] == "DEPENDENCY_ADVISORY"
    assert result["properties"]["affectedVersionStatus"] == "CONFIRMED"
    assert result["properties"]["runtimeReachability"] == "NOT_ESTABLISHED"
    assert "separate validation" in result["properties"]["riskInterpretation"]


def test_sarif_marks_openwrt_advisories_as_dependency_version_matches():
    outcome = _outcome()
    outcome.report.issues[0] = outcome.report.issues[0].model_copy(
        update={"rule_id": "aegisscan.openwrt.advisory.cve-2020-7248"}
    )

    result = build_sarif_payload(outcome)["runs"][0]["results"][0]

    assert result["properties"]["findingType"] == "DEPENDENCY_ADVISORY"
    assert result["properties"]["affectedVersionStatus"] == "CONFIRMED"


def test_write_sarif_report_outputs_valid_json(tmp_path):
    destination = tmp_path / "aegisscan.sarif"

    write_sarif_report(_outcome(), destination)

    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["$schema"].endswith("sarif-2.1.0.json")


def test_json_and_sarif_exports_redact_secret_material():
    outcome = _outcome()
    private_key = "-----BEGIN RSA PRIVATE KEY-----secret-material-----END RSA PRIVATE KEY-----"
    outcome.report.issues[0] = outcome.report.issues[0].model_copy(
        update={
            "original_code": f"const privateKey = '{private_key}'",
            "source_evidence": private_key,
        }
    )

    json_payload = json.dumps(build_report_payload(outcome))
    sarif_payload = json.dumps(build_sarif_payload(outcome))

    assert private_key not in json_payload
    assert private_key not in sarif_payload
    assert "[REDACTED SECRET]" in json_payload


def test_private_key_export_preserves_declaration_anchor():
    outcome = _outcome()
    issue = outcome.report.issues[0].model_copy(update={
        'file': 'lib/security.ts', 'line': 21, 'sink_file': 'lib/security.ts', 'sink_line': 54,
        'rule_id': 'aegisscan.javascript.hardcoded-private-key',
    })
    outcome.report = ReviewReport(analysis_scratchpad='', issues=[issue])
    result = build_sarif_payload(outcome)['runs'][0]['results'][0]
    assert result['locations'][0]['physicalLocation']['region']['startLine'] == 21
    assert result['relatedLocations'][0]['physicalLocation']['region']['startLine'] == 54
