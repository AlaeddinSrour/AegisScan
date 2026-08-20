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
    assert payload["summary"]["needs_review"] == 1
    assert payload["summary"]["provenance"] == {
        "aegisscan_version": "0.3.1",
        "scan_started_at": "2026-08-20T10:00:00+00:00",
        "scan_completed_at": "2026-08-20T10:01:00+00:00",
        "repository_name": "juice-shop",
        "repository_commit": "b" * 40,
        "repository_branch": "main",
        "repository_dirty": False,
        "ai_models": ["gemini-test"],
    }
    assert payload["summary"]["configuration"]["max_target_bytes"] == 2_000_000


def test_json_report_separates_scanner_diagnostics_and_detector_telemetry():
    outcome = _outcome()
    outcome.detector_telemetry = {
        "osv": {
            "status": "completed",
            "manifests_discovered": 2,
            "manifests_scanned": 2,
            "packages_queried": 42,
        }
    }
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

    assert payload["summary"]["total_detector_findings"] == 3
    assert payload["summary"]["scanner_diagnostic_count"] == 1
    assert payload["summary"]["scanner_diagnostics"]["semgrep"][0]["file"] == (
        "tests/broken.ts"
    )
    assert payload["summary"]["detector_telemetry"]["osv"]["packages_queried"] == 42


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
    assert run["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"] == "src/proxy.py"
    confirmed_rule = run["tool"]["driver"]["rules"][0]
    assert "CWE-918" in confirmed_rule["properties"]["tags"]
    assert run["invocations"][0]["properties"]["semgrepRulesSha256"] == "a" * 64
    assert run["invocations"][0]["properties"]["aiTriageEnabled"] is True
    assert run["invocations"][0]["properties"]["repositoryCommit"] == "b" * 40


def test_write_sarif_report_outputs_valid_json(tmp_path):
    destination = tmp_path / "aegisscan.sarif"

    write_sarif_report(_outcome(), destination)

    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["$schema"].endswith("sarif-2.1.0.json")


def test_json_and_sarif_exports_redact_secret_material():
    outcome = _outcome()
    private_key = (
        "-----BEGIN RSA PRIVATE KEY-----secret-material"
        "-----END RSA PRIVATE KEY-----"
    )
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
