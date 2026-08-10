from unittest.mock import MagicMock, patch

from src.full_scan import batch_findings, run_full_scan, split_semgrep_findings
from src.models import ReviewIssue, ReviewReport


def _finding(number: int, path: str, line: int = 1) -> str:
    return (
        f"Finding #{number}:\n"
        f"Rule ID: test.rule\n"
        f"File: {path}:{line}\n"
        "Message: unsafe\n"
        "Code Snippet: dangerous()\n"
    )


def test_split_semgrep_findings_ignores_finding_like_context_lines():
    text = _finding(1, "src/a.py") + "Finding #99:\nnot a header\n" + _finding(2, "lib/b.py")
    findings = split_semgrep_findings(text)
    assert len(findings) == 2
    assert "Finding #99" in findings[0]


def test_batch_findings_clamps_to_fifteen_and_tracks_files():
    findings = [_finding(index, f"src/file_{index}.py") for index in range(1, 18)]
    batches = batch_findings(findings, batch_size=99)
    assert [len(batch.findings) for batch in batches] == [15, 2]
    assert "src/file_1.py" in batches[0].files


def test_run_full_scan_disables_diff_filter_and_merges_report(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("dangerous()\n", encoding="utf-8")
    issue = ReviewIssue(
        file="app.py",
        line=1,
        severity="HIGH",
        issue_name="Command Injection",
        description="Untrusted data reaches a command sink.",
        original_code="dangerous()",
        suggested_fix="safe_call()",
        confidence="HIGH",
        source_evidence="HTTP request value reaches dangerous().",
        sink_evidence="dangerous() executes an operating-system command.",
        reachability_evidence="The runtime handler calls dangerous() directly.",
    )
    llm_report = ReviewReport(analysis_scratchpad="source reaches sink", issues=[issue])
    progress_events: list[str] = []

    with patch("src.full_scan.run_semgrep_scan", return_value=_finding(1, "app.py")) as scan:
        with patch("src.full_scan.call_gemini_with_failover", return_value=llm_report):
            outcome = run_full_scan(
                str(tmp_path),
                "",
                client=MagicMock(),
                apply_fixes=False,
                progress=progress_events.append,
            )

    scan.assert_called_once_with(str(tmp_path.resolve()), changed_files_lines=None)
    assert outcome.raw_finding_count == 1
    assert outcome.batch_count == 1
    assert len(outcome.report.issues) == 1
    assert outcome.report.issues[0].file == issue.file
    assert outcome.report.issues[0].finding_id.startswith("SG-")
    assert outcome.report.issues[0].code_role == "RUNTIME"
    assert outcome.report.dispositions[0].status == "CONFIRMED"
    for phase in (
        "[SETUP]",
        "[DISCOVER]",
        "[PLAN]",
        "[CONTEXT]",
        "[AI]",
        "[VALIDATE]",
        "[MERGE]",
        "[REMEDIATE]",
        "[PUBLISH]",
        "[COMPLETE]",
    ):
        assert any(event.startswith(phase) for event in progress_events)


def test_run_full_scan_rejects_issue_path_outside_repository(tmp_path):
    report = ReviewReport(
        analysis_scratchpad="bad path",
        issues=[
            ReviewIssue(
                file="../outside.py",
                line=1,
                severity="HIGH",
                issue_name="Path escape",
                description="Invalid path.",
                original_code="x",
                suggested_fix="y",
            )
        ],
    )
    with patch("src.full_scan.run_semgrep_scan", return_value=_finding(1, "inside.py")):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())
    assert outcome.report.issues == []


def test_fixture_candidate_cannot_be_promoted_to_runtime_issue(tmp_path):
    fixture = tmp_path / "data" / "static" / "codefixes" / "search_1.ts"
    fixture.parent.mkdir(parents=True)
    fixture.write_text("unsafeQuery(input)\n", encoding="utf-8")
    issue = ReviewIssue(
        file="data/static/codefixes/search_1.ts",
        line=1,
        severity="HIGH",
        issue_name="SQL Injection",
        description="Input reaches an interpolated query.",
        original_code="unsafeQuery(input)",
        suggested_fix="safeQuery(input)",
        confidence="HIGH",
        source_evidence="input is attacker controlled",
        sink_evidence="unsafeQuery executes SQL",
        reachability_evidence="fixture function calls the sink",
    )
    report = ReviewReport(analysis_scratchpad="fixture", issues=[issue])
    with patch(
        "src.full_scan.run_semgrep_scan",
        return_value=_finding(1, "data/static/codefixes/search_1.ts"),
    ):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report) as ai_call:
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert outcome.report.issues == []
    assert outcome.disposition_count("NON_RUNTIME") == 1
    assert outcome.report.dispositions[0].code_role == "FIXTURE"
    ai_call.assert_not_called()


def test_runtime_candidate_cannot_redirect_canonical_sink_into_tests(tmp_path):
    (tmp_path / "app.py").write_text("source = input()\n", encoding="utf-8")
    test_sink = tmp_path / "tests" / "test_app.py"
    test_sink.parent.mkdir()
    test_sink.write_text("eval(source)\n", encoding="utf-8")
    issue = ReviewIssue(
        file="app.py",
        line=1,
        sink_file="tests/test_app.py",
        sink_line=1,
        severity="HIGH",
        issue_name="Code execution",
        description="Input reaches eval.",
        original_code="eval(source)",
        suggested_fix="safe(source)",
        confidence="HIGH",
        source_evidence="input",
        sink_evidence="eval",
        reachability_evidence="test-only path",
    )
    report = ReviewReport(analysis_scratchpad="redirect", issues=[issue])
    with patch("src.full_scan.run_semgrep_scan", return_value=_finding(1, "app.py")):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert outcome.report.issues == []
    assert outcome.disposition_count("NON_RUNTIME") == 1
    assert outcome.report.dispositions[0].code_role == "TEST"


def test_omitted_candidate_is_preserved_for_review(tmp_path):
    (tmp_path / "app.py").write_text("dangerous()\n", encoding="utf-8")
    report = ReviewReport(analysis_scratchpad="uncertain", issues=[])
    with patch("src.full_scan.run_semgrep_scan", return_value=_finding(1, "app.py")):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert outcome.report.issues == []
    assert outcome.disposition_count("NEEDS_REVIEW") == 1
    assert "did not return" in outcome.report.dispositions[0].reason


def test_runtime_scan_incomplete_candidate_bypasses_ai_and_needs_review(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "large.js").write_text("const value = 1\n", encoding="utf-8")
    finding = (
        "Finding #1:\n"
        "Rule ID: aegisscan.semgrep.runtime-scan-incomplete\n"
        "File: src/large.js:1\n"
        "Message: Semgrep timed out; manual review is required.\n"
        "Code Snippet: [Resource-limit error.]\n"
    )
    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover") as ai_call:
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    ai_call.assert_not_called()
    assert outcome.report.issues == []
    assert outcome.disposition_count("NEEDS_REVIEW") == 1
    assert "resource limit" in outcome.report.dispositions[0].reason


def test_hardcoded_private_key_requires_manual_remediation(tmp_path):
    source = tmp_path / "security.ts"
    source.write_text("const privateKey = 'embedded'\n", encoding="utf-8")
    issue = ReviewIssue(
        file="security.ts",
        line=1,
        severity="CRITICAL",
        issue_name="Hardcoded JWT Private Key",
        description="A signing key is embedded in runtime source.",
        original_code="const privateKey = 'embedded'",
        suggested_fix="const privateKey = process.env.JWT_PRIVATE_KEY",
        confidence="HIGH",
        source_evidence="privateKey contains a repository-exposed credential",
        sink_evidence="the key signs authentication tokens",
        reachability_evidence="the token authorization path uses privateKey",
    )
    report = ReviewReport(analysis_scratchpad="key exposure", issues=[issue])
    with patch("src.full_scan.run_semgrep_scan", return_value=_finding(1, "security.ts")):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert len(outcome.report.issues) == 1
    assert outcome.report.issues[0].remediation_type == "MANUAL_REQUIRED"


def test_partial_batch_failure_preserves_candidates_for_review(tmp_path):
    (tmp_path / "a.py").write_text("dangerous()\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("dangerous()\n", encoding="utf-8")
    report = ReviewReport(analysis_scratchpad="first batch", issues=[])
    findings = _finding(1, "a.py") + _finding(2, "b.py")
    with patch("src.full_scan.run_semgrep_scan", return_value=findings):
        with patch(
            "src.full_scan.call_gemini_with_failover",
            side_effect=[report, RuntimeError("model outage")],
        ):
            outcome = run_full_scan(
                str(tmp_path), "", client=MagicMock(), batch_size=1
            )

    assert outcome.failed_batches == [2]
    assert outcome.failed_batch_reasons == {2: "model outage"}
    assert outcome.ai_attempted_batches == 2
    assert outcome.ai_successful_batches == 1
    assert outcome.ai_triage_degraded
    assert not outcome.all_ai_batches_failed
    assert outcome.disposition_count("NEEDS_REVIEW") == 2
    assert len(outcome.report.dispositions) == outcome.raw_finding_count


def test_all_batch_failures_return_degraded_manual_review(tmp_path):
    (tmp_path / "app.py").write_text("dangerous()\n", encoding="utf-8")
    with patch("src.full_scan.run_semgrep_scan", return_value=_finding(1, "app.py")):
        with patch(
            "src.full_scan.call_gemini_with_failover",
            side_effect=RuntimeError("model outage"),
        ):
            progress: list[str] = []
            outcome = run_full_scan(
                str(tmp_path), "", client=MagicMock(), progress=progress.append
            )

    assert outcome.report.issues == []
    assert outcome.failed_batches == [1]
    assert outcome.failed_batch_reasons == {1: "model outage"}
    assert outcome.disposition_count("NEEDS_REVIEW") == 1
    assert outcome.ai_triage_degraded
    assert outcome.all_ai_batches_failed
    assert any("degraded mode" in event for event in progress)


def test_helper_candidate_is_consolidated_into_canonical_sink(tmp_path):
    source = tmp_path / "routes" / "videoHandler.ts"
    source.parent.mkdir(parents=True)
    source.write_text(
        "\n".join(
            ["const x = 1"] * 56
            + ["challengeUtils.solveIf(challenge, () => utils.contains(subs, '<script>'))"]
            + ["const x = 1"] * 13
            + ["compiledTemplate = compiledTemplate.replace(marker, subs)"]
        )
        + "\n",
        encoding="utf-8",
    )
    findings = _finding(1, "routes/videoHandler.ts", 57) + _finding(
        2, "routes/videoHandler.ts", 71
    )
    helper = ReviewIssue(
        file="routes/videoHandler.ts",
        line=57,
        sink_file="routes/videoHandler.ts",
        sink_line=57,
        severity="HIGH",
        issue_name="Cross-Site Scripting (XSS)",
        description="A payload is checked near an unsafe output path.",
        original_code="challengeUtils.solveIf(challenge, () => utils.contains(subs, '<script>'))",
        suggested_fix="validateSubs(subs)",
        confidence="HIGH",
        source_evidence="Uploaded subtitles can control subs.",
        sink_evidence="The payload is detected here.",
        reachability_evidence="The promotion handler reads subtitles.",
    )
    sink = ReviewIssue(
        file="routes/videoHandler.ts",
        line=71,
        sink_file="routes/videoHandler.ts",
        sink_line=71,
        severity="HIGH",
        issue_name="Cross-Site Scripting (XSS)",
        description="Untrusted subtitles are inserted into executable markup.",
        original_code="compiledTemplate = compiledTemplate.replace(marker, subs)",
        suggested_fix="compiledTemplate = compiledTemplate.replace(marker, escapeHtml(subs))",
        confidence="HIGH",
        source_evidence="Uploaded subtitle contents control subs.",
        sink_evidence="replace inserts subs into a script element.",
        reachability_evidence="The promotion response sends the resulting template.",
    )
    report = ReviewReport(analysis_scratchpad="duplicate flow", issues=[helper, sink])
    with patch("src.full_scan.run_semgrep_scan", return_value=findings):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert [(issue.file, issue.line) for issue in outcome.report.issues] == [
        ("routes/videoHandler.ts", 71)
    ]
    assert outcome.disposition_count("CONFIRMED") == 1
    assert outcome.disposition_count("FALSE_POSITIVE") == 1
