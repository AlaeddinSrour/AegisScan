from datetime import UTC, datetime

from src.audit_history import (
    MAX_HISTORY_ENTRIES,
    build_failure_entry,
    build_history_entry,
    dump_history,
    latest_completed_entry,
    load_history,
)
from src.full_scan import ScanOutcome
from src.models import FindingDisposition, ReviewIssue, ReviewReport


def _outcome(*finding_ids: str, ai_triage: bool = True) -> ScanOutcome:
    issues = [
        ReviewIssue(
            file=f"src/{finding_id}.py",
            line=index,
            severity="HIGH",
            issue_name="Test issue",
            description="A test source reaches a test sink.",
            original_code="unsafe(value)",
            suggested_fix="safe(value)",
            finding_id=finding_id,
            rule_id="test.rule",
        )
        for index, finding_id in enumerate(finding_ids, start=1)
    ]
    dispositions = [
        FindingDisposition(
            finding_id=issue.finding_id,
            status="CONFIRMED",
            reason="Confirmed for history comparison.",
            file=issue.file,
            line=issue.line,
            rule_id=issue.rule_id,
        )
        for issue in issues
    ]
    return ScanOutcome(
        report=ReviewReport(
            analysis_scratchpad="test",
            issues=issues,
            dispositions=dispositions,
        ),
        raw_finding_count=len(issues),
        batch_count=1,
        ai_triage_enabled=ai_triage,
    )


def test_history_compares_new_resolved_and_unchanged_findings(tmp_path):
    first = build_history_entry(
        _outcome("SG-one", "SG-two"),
        str(tmp_path),
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
    )
    second = build_history_entry(
        _outcome("SG-two", "SG-three", ai_triage=False),
        str(tmp_path),
        first,
        timestamp=datetime(2026, 1, 2, tzinfo=UTC),
    )

    assert first["comparison"] == {"new": 2, "resolved": 0, "unchanged": 0}
    assert second["comparison"] == {"new": 1, "resolved": 1, "unchanged": 1}
    assert second["audit_mode"] == "Detector only"
    assert second["repository"] == str(tmp_path.resolve())


def test_history_persists_only_opaque_finding_fingerprints(tmp_path):
    entry = build_history_entry(_outcome("SG-sensitive-id"), str(tmp_path))
    serialized = dump_history([entry])

    assert "SG-sensitive-id" not in serialized
    assert "src/SG-sensitive-id.py" not in serialized
    assert all(len(value) == 24 for value in entry["fingerprints"])
    assert load_history(serialized) == [entry]


def test_history_loading_is_defensive_and_bounded():
    entries = [{"timestamp": str(index)} for index in range(MAX_HISTORY_ENTRIES + 5)]

    assert load_history("not json") == []
    assert load_history("{}") == []
    assert len(load_history(dump_history(entries))) == MAX_HISTORY_ENTRIES
    assert load_history(dump_history(entries))[0]["timestamp"] == "5"


def test_latest_completed_entry_skips_failures_and_other_repositories(tmp_path):
    repository = tmp_path / "current"
    other = tmp_path / "other"
    current = build_history_entry(_outcome("SG-current"), str(repository))
    entries = [
        current,
        build_history_entry(_outcome("SG-other"), str(other)),
        build_failure_entry(str(repository)),
    ]

    assert latest_completed_entry(entries, str(repository)) is current
