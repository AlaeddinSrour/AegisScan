import json
from unittest.mock import patch

import pytest

from src.full_scan import ScanOutcome, audit_exit_code, main
from src.models import FindingDisposition, ReviewIssue, ReviewReport


def outcome(severity=None, role="RUNTIME", review=False, degraded=False):
    issues = [] if severity is None else [ReviewIssue(
        file="app.py", line=1, severity=severity, issue_name="Finding", description="Evidence",
        original_code="", suggested_fix="", code_role=role, remediation_type="MANUAL_REQUIRED",
    )]
    dispositions = [] if not review else [FindingDisposition(
        finding_id="candidate", status="NEEDS_REVIEW", reason="Unresolved", code_role=role,
    )]
    return ScanOutcome(
        report=ReviewReport(analysis_scratchpad="", issues=issues, dispositions=dispositions),
        raw_finding_count=0, batch_count=0,
        detector_errors={"semgrep": ["failed"]} if degraded else {},
    )


@pytest.mark.parametrize("severity,threshold,expected", [
    ("CRITICAL", "none", 0), ("HIGH", "high", 3), ("CRITICAL", "high", 3),
    ("WARNING", "high", 0), ("HIGH", "critical", 0), ("INFO", "info", 3),
    ("WARNING", "warning", 3), (None, "high", 0),
])
def test_severity_threshold(severity, threshold, expected):
    assert audit_exit_code(outcome(severity), fail_on=threshold) == expected


def test_non_runtime_and_unresolved_candidates_have_separate_policies():
    assert audit_exit_code(outcome("CRITICAL", role="FIXTURE"), fail_on="high") == 0
    assert audit_exit_code(outcome(review=True), fail_on="high") == 0
    assert audit_exit_code(outcome(review=True), fail_on_needs_review=True) == 3
    assert audit_exit_code(outcome(review=True, role="TEST"), fail_on_needs_review=True) == 0


def test_incomplete_scan_takes_precedence_over_thresholds():
    assert audit_exit_code(outcome("CRITICAL", degraded=True), fail_on="high") == 2


@pytest.mark.parametrize("scan,expected", [
    (outcome("HIGH"), 3), (outcome("HIGH", degraded=True), 2),
])
def test_cli_writes_both_reports_before_failing(tmp_path, monkeypatch, scan, expected):
    report, sarif = tmp_path / "audit.json", tmp_path / "audit.sarif"
    monkeypatch.setattr("sys.argv", ["aegisscan", "--fail-on", "high", "--report", str(report),
                                    "--sarif", str(sarif)])
    with patch("src.full_scan.run_full_scan", return_value=scan):
        with pytest.raises(SystemExit) as exc:
            main()
    assert exc.value.code == expected
    assert json.loads(report.read_text())["report"]["issues"]
    assert json.loads(sarif.read_text())["runs"][0]["results"]
