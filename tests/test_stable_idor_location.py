import pytest

from src.full_scan import ScanOutcome, SemgrepCandidate, _anchor_issue_sink
from src.models import ReviewIssue, ReviewReport
from src.reporting import build_sarif_payload


@pytest.mark.parametrize("proposed_line", [1, 2, 3])
def test_idor_export_uses_detector_lookup_despite_model_location(tmp_path, proposed_line):
    (tmp_path / "order.ts").write_text(
        "const id = req.params.id\n"
        "BasketModel.findOne({ where: { id } })\n"
        "OtherModel.findByPk(id)\n"
    )
    candidate = SemgrepCandidate(
        finding_id="SG-order", rule_id="aegisscan.javascript.express-id-to-data-access",
        message="Request ID reaches data lookup", file="order.ts", line=2,
        code_role="RUNTIME", raw_text="",
    )
    issue = ReviewIssue(
        file="order.ts", line=proposed_line, sink_line=proposed_line,
        severity="HIGH", issue_name="IDOR", description="Missing ownership check",
        original_code="const id = req.params.id", suggested_fix="",
        rule_id=candidate.rule_id, finding_id=candidate.finding_id,
        sink_evidence=f"BasketModel.findOne consumes id at order.ts:{proposed_line}",
    )
    file, line, evidence = _anchor_issue_sink(tmp_path, issue, candidate)
    anchored = issue.model_copy(update={"sink_file": file, "sink_line": line,
                                       "sink_evidence": evidence})
    outcome = ScanOutcome(report=ReviewReport(analysis_scratchpad="", issues=[anchored]),
                          raw_finding_count=1, batch_count=1)
    result = build_sarif_payload(outcome)["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"] == {
        "artifactLocation": {"uri": "order.ts"}, "region": {"startLine": 2},
    }
    assert result["partialFingerprints"]["aegisscanFindingId"] == "SG-order"
    assert result["properties"]["sinkEvidence"].endswith("order.ts:2")
