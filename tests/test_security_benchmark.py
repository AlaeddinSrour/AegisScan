import json
from pathlib import Path

from src.security_benchmark import Finding, evaluate, findings_from_sarif


def test_benchmark_measures_recall_precision_duplicates_and_unresolved():
    manifest = {
        "name": "unit baseline",
        "scope": {"include_rule_prefixes": ["aegisscan."]},
        "expected": [
            {"rule_id": "aegisscan.java.ssrf", "path": "src/App.java", "line": 12},
            {"rule_id": "aegisscan.java.toctou", "path": "src/File.java", "line": 8},
        ],
        "gates": {
            "min_recall": 1.0,
            "min_precision": 1.0,
            "max_unexpected": 0,
            "max_unresolved": 0,
            "max_duplicate_rate": 0.0,
            "require_complete": True,
        },
    }
    findings = [
        Finding("aegisscan.java.ssrf", "/tmp/repo/src/App.java", 12, "CONFIRMED"),
        Finding("aegisscan.java.ssrf", "/tmp/repo/src/App.java", 12, "CONFIRMED"),
        Finding("aegisscan.java.extra", "/tmp/repo/src/Other.java", 3, "NEEDS_REVIEW"),
    ]

    report = evaluate(findings, manifest, {"execution_successful": True})

    assert report["passed"] is False
    assert report["metrics"] == {
        "expected": 2,
        "matched": 1,
        "actual_scoped": 3,
        "unique_scoped": 2,
        "recall": 0.5,
        "precision": 0.5,
        "duplicate_count": 1,
        "duplicate_rate": 0.3333,
        "unresolved": 1,
        "unexpected": 1,
        "forbidden": 0,
        "execution_successful": True,
    }
    assert report["missing"][0]["rule_id"] == "aegisscan.java.toctou"
    assert report["unexpected"][0]["rule_id"] == "aegisscan.java.extra"


def test_sarif_completeness_requires_success_without_runtime_gaps():
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "auditDegraded": False,
                            "failedBatches": [],
                            "runtimeScanGaps": 1,
                            "aiTelemetry": {"request_attempts": 4},
                        },
                    }
                ],
                "results": [],
            }
        ],
    }

    findings, telemetry = findings_from_sarif(payload)

    assert findings == []
    assert telemetry["execution_successful"] is False
    assert telemetry["errors"] == 1
    assert telemetry["provider_request_attempts"] == 4


def test_firmware_benchmark_gates_reject_dirty_incomplete_inventory():
    manifest = {
        "expected": [],
        "gates": {
            "require_clean_repository": True,
            "required_semgrep_rule_mode": "bundled",
            "max_scanner_diagnostics": 0,
            "min_inventory_coverage_ratio": 1.0,
            "expected_kernel_versions": ["4.9.152", "4.14.95"],
            "min_kernel_advisory_matches": 6,
        },
    }
    telemetry = {
        "repository_dirty": True,
        "semgrep_rule_mode": "extended",
        "scanner_diagnostics": 3,
        "inventory_coverage_ratio": 0.8,
        "kernel_versions": ["4.14.95"],
        "kernel_advisory_matches": 3,
    }

    report = evaluate([], manifest, telemetry)

    assert report["passed"] is False
    assert len(report["failures"]) == 6
    assert any("clean Git checkout" in item for item in report["failures"])
    assert any("inventory coverage" in item for item in report["failures"])


def test_iotgoat_manifest_pins_all_firmware_and_openwrt_expectations():
    manifest = json.loads(
        (Path(__file__).parents[1] / "benchmarks/iotgoat.json").read_text(
            encoding="utf-8"
        )
    )

    assert manifest["repository"]["commit"] == (
        "f67b7f961301d7a56b435fd7cffac73600f0c97b"
    )
    assert len(manifest["expected"]) == 19
    assert manifest["gates"]["min_recall"] == 1.0
    assert manifest["gates"]["min_precision"] == 1.0
    assert manifest["gates"]["require_complete"] is True
    assert manifest["gates"]["min_inventory_coverage_ratio"] == 1.0
    assert manifest["gates"]["expected_kernel_versions"] == ["4.9.152", "4.14.95"]
    assert manifest["gates"]["min_kernel_advisory_matches"] == 6


def test_webgoat_manifest_pins_raw_detector_findings_without_triage_statuses():
    manifest = json.loads(
        (Path(__file__).parents[1] / "benchmarks/webgoat.json").read_text(
            encoding="utf-8"
        )
    )

    assert manifest["repository"]["commit"] == (
        "7517acca95d9851da706452454c223dd13545ef4"
    )
    assert len(manifest["expected"]) == 1
    assert all("status" not in item for item in manifest["expected"])
    assert manifest["gates"]["max_unresolved"] == 0


def test_suppressed_evidence_is_not_scored_as_active_or_used_to_satisfy_expected():
    manifest = {
        "expected": [{"rule_id": "rule", "path": "app.py", "line": 1}],
        "forbidden": [{"rule_id": "fp", "path": "app.py"}],
        "gates": {"min_recall": 1, "max_forbidden": 0},
    }
    findings = [Finding("rule", "app.py", 1, "FALSE_POSITIVE"),
                Finding("fp", "app.py", 2, "FALSE_POSITIVE"),
                Finding("fp", "app.py", 3, "DUPLICATE"),
                Finding("fp", "app.py", 4, "NON_RUNTIME"),
                Finding("fp", "app.py", 5, "CONFIRMED", suppressed=True)]
    report = evaluate(findings, manifest, {})
    assert report['metrics']['actual_scoped'] == 0
    assert report['metrics']['forbidden'] == 0
    assert report['metrics']['matched'] == 0
    assert not report['passed']
    active = evaluate([Finding("fp", "app.py", 2, "CONFIRMED")], manifest, {})
    assert active['metrics']['forbidden'] == 1


def test_sarif_only_accepted_suppressions_hide_active_results():
    payload = {'runs': [{'results': [
        {'ruleId': 'r', 'properties': {'status': 'CONFIRMED'},
         'suppressions': [{'status': status}]} for status in ['accepted', 'underReview', 'rejected']
    ]}]}
    findings, _ = findings_from_sarif(payload)
    assert [item.suppressed for item in findings] == [True, False, False]
