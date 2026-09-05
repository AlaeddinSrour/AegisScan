import re
from unittest.mock import MagicMock, patch

import pytest

from src.full_scan import (
    _merge_reports,
    _normalize_manual_remediations,
    _requires_manual_remediation,
    batch_findings,
    run_full_scan,
    split_semgrep_findings,
)
from src.models import FindingDisposition, ReviewIssue, ReviewReport
from src.semgrep_runner import (
    DEFAULT_EXCLUDES,
    DEFAULT_MAX_TARGET_BYTES,
    SemgrepScanOutput,
)
from src.supplemental_scanners import DetectorResult


@pytest.fixture(autouse=True)
def completed_supplemental_scanners(monkeypatch):
    monkeypatch.setattr(
        "src.full_scan.scan_firmware", lambda _path, **_kwargs: DetectorResult(detector="firmware")
    )
    monkeypatch.setattr(
        "src.full_scan.scan_dependencies", lambda _path: DetectorResult(detector="osv")
    )
    monkeypatch.setattr(
        "src.full_scan.scan_secrets",
        lambda _path, **_kwargs: DetectorResult(detector="gitleaks"),
    )


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


def test_full_scan_removes_exact_duplicate_semgrep_findings(tmp_path):
    (tmp_path / "app.py").write_text("dangerous()\n", encoding="utf-8")
    duplicated = _finding(1, "app.py") + _finding(2, "app.py")
    progress: list[str] = []
    report = ReviewReport(analysis_scratchpad="reviewed", issues=[])

    with patch("src.full_scan.run_semgrep_scan", return_value=duplicated):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock(), progress=progress.append)

    assert outcome.raw_finding_count == 1
    assert len(outcome.report.dispositions) == 1
    assert any("Removed 1 exact duplicate" in event for event in progress)


def test_non_runtime_semgrep_diagnostics_do_not_inflate_finding_totals(tmp_path):
    diagnostic = {
        "kind": "Syntax error",
        "file": "tests/broken.ts",
        "line": 9,
        "code_role": "TEST",
        "message": "Semgrep could not fully parse this test file.",
    }
    semgrep_output = SemgrepScanOutput("", [diagnostic])

    with patch("src.full_scan.run_semgrep_scan", return_value=semgrep_output):
        with patch("src.full_scan.call_gemini_with_failover") as ai_call:
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    ai_call.assert_not_called()
    assert outcome.raw_finding_count == 0
    assert outcome.total_finding_count == 0
    assert outcome.scanner_diagnostic_count == 1
    assert outcome.scanner_diagnostics == {"semgrep": [diagnostic]}


def test_typescript_imported_helper_context_is_sent_for_triage(tmp_path):
    routes = tmp_path / "routes"
    lib = tmp_path / "lib"
    routes.mkdir()
    lib.mkdir()
    (routes / "redirect.ts").write_text(
        "import * as security from '../lib/insecurity'\n"
        "export const redirect = (url: string) => {\n"
        "  if (security.isRedirectAllowed(url)) return url\n"
        "}\n",
        encoding="utf-8",
    )
    (lib / "insecurity.ts").write_text(
        "export const isRedirectAllowed = (url: string) => {\n"
        "  return new URL(url).hostname === 'example.test'\n"
        "}\n",
        encoding="utf-8",
    )
    report = ReviewReport(analysis_scratchpad="reviewed", issues=[])

    with patch(
        "src.full_scan.run_semgrep_scan",
        return_value=_finding(1, "routes/redirect.ts", 3),
    ):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report) as ai_call:
            run_full_scan(str(tmp_path), "", client=MagicMock())

    prompt = ai_call.call_args.args[1]
    assert "Imported helper: isRedirectAllowed" in prompt
    assert "new URL(url).hostname" in prompt


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

    scan.assert_called_once_with(
        str(tmp_path.resolve()),
        changed_files_lines=None,
        exclude_patterns=DEFAULT_EXCLUDES,
        max_target_bytes=DEFAULT_MAX_TARGET_BYTES,
        rule_mode="bundled",
    )
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


def test_openwrt_tree_forces_bundled_rules_and_warns_for_dirty_worktree(
    tmp_path, monkeypatch
):
    (tmp_path / "OpenWrt/openwrt-18.06.2/files/etc").mkdir(parents=True)
    progress_events: list[str] = []
    monkeypatch.setattr(
        "src.full_scan._git_provenance", lambda _root: ("a" * 40, "main", True)
    )

    with patch("src.full_scan.run_semgrep_scan", return_value="") as scan:
        outcome = run_full_scan(
            str(tmp_path),
            "",
            client=MagicMock(),
            semgrep_rule_mode="extended",
            progress=progress_events.append,
        )

    assert scan.call_args.kwargs["rule_mode"] == "bundled"
    assert outcome.semgrep_rule_mode == "bundled"
    assert outcome.repository_dirty is True
    assert any("uncommitted or untracked" in event for event in progress_events)
    assert any("using bundled Semgrep rules" in event for event in progress_events)


def test_reconciliation_removes_unsupported_secondary_description_claim(tmp_path):
    source = tmp_path / "login.ts"
    source.write_text("database.query(userInput)\n", encoding="utf-8")
    finding = _finding(1, "login.ts").replace(
        "test.rule",
        "aegisscan.javascript.express-sequelize-taint-sqli",
    )
    issue = ReviewIssue(
        file="login.ts",
        line=1,
        sink_file="login.ts",
        sink_line=1,
        severity="HIGH",
        issue_name="SQL Injection",
        description=(
            "User input from req.body.email in lib/insecurity.ts reaches a raw SQL query, "
            "enabling SQL injection. "
            "The hardcoded password string should be replaced with a securely hashed credential."
        ),
        original_code="database.query(userInput)",
        suggested_fix="",
        confidence="HIGH",
        source_evidence="HTTP request input controls userInput.",
        sink_evidence="database.query executes the raw SQL string.",
        reachability_evidence="The route directly invokes database.query.",
        remediation_type="MANUAL_REQUIRED",
    )
    report = ReviewReport(analysis_scratchpad="SQL flow validated", issues=[issue])

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert outcome.report.issues[0].description == (
        "User input from req.body.email in lib/insecurity.ts reaches a raw SQL query, "
        "enabling SQL injection."
    )


def test_clean_semgrep_still_runs_supplemental_detectors(tmp_path, monkeypatch):
    dependency_issue = ReviewIssue(
        file="requirements.txt",
        line=1,
        severity="HIGH",
        issue_name="Vulnerable dependency",
        description="A resolved package version has a known advisory.",
        original_code="library==1.0.0",
        suggested_fix="Upgrade after compatibility testing.",
        finding_id="OSV-test",
        rule_id="osv.GHSA-test",
        confidence="MEDIUM",
        code_role="RUNTIME",
        source_evidence="Resolved from requirements.txt.",
        sink_evidence="The version is affected.",
        sink_file="requirements.txt",
        sink_line=1,
        reachability_evidence="Runtime reachability was not established.",
        remediation_type="MANUAL_REQUIRED",
    )
    disposition = {
        "finding_id": "OSV-test",
        "status": "CONFIRMED",
        "reason": "Known advisory match.",
        "file": "requirements.txt",
        "line": 1,
        "rule_id": "osv.GHSA-test",
        "code_role": "RUNTIME",
        "confidence": "MEDIUM",
    }
    (tmp_path / "requirements.txt").write_text("library==1.0.0\n")
    monkeypatch.setattr(
        "src.full_scan.scan_dependencies",
        lambda _path: DetectorResult(
            detector="osv",
            finding_count=1,
            issues=[dependency_issue],
            dispositions=[FindingDisposition(**disposition)],
        ),
    )

    with patch("src.full_scan.run_semgrep_scan", return_value=""):
        with patch("src.full_scan.call_gemini_with_failover") as ai_call:
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    ai_call.assert_not_called()
    assert outcome.raw_finding_count == 0
    assert outcome.dependency_finding_count == 1
    assert outcome.total_finding_count == 1
    assert len(outcome.report.issues) == 1
    assert outcome.report.issues[0].finding_id == dependency_issue.finding_id
    assert outcome.report.issues[0].suggested_fix == ""
    assert outcome.report.issues[0].remediation_guidance
    assert not outcome.audit_degraded


def test_firmware_findings_are_counted_in_detector_total(tmp_path, monkeypatch):
    issue = ReviewIssue(
        file="OpenWrt/openwrt-1.2.3/files/etc/rc.local",
        line=1,
        severity="CRITICAL",
        issue_name="Startup backdoor",
        description="A backdoor service is launched at startup.",
        original_code="/usr/bin/shellback &",
        suggested_fix="",
        finding_id="FIRMWARE-test",
        rule_id="aegisscan.firmware.startup-backdoor",
        confidence="HIGH",
        code_role="RUNTIME",
        source_evidence="The entry is persisted in rc.local.",
        sink_evidence="The service is launched at boot.",
        sink_file="OpenWrt/openwrt-1.2.3/files/etc/rc.local",
        sink_line=1,
        reachability_evidence="Normal boot executes rc.local.",
        remediation_type="MANUAL_REQUIRED",
    )
    disposition = FindingDisposition(
        finding_id=issue.finding_id,
        status="CONFIRMED",
        reason="Deterministic firmware match.",
        file=issue.file,
        line=issue.line,
        rule_id=issue.rule_id,
        code_role="RUNTIME",
        confidence="HIGH",
    )
    monkeypatch.setattr(
        "src.full_scan.scan_firmware",
        lambda _path, **_kwargs: DetectorResult(
            detector="firmware",
            finding_count=1,
            issues=[issue],
            dispositions=[disposition],
        ),
    )

    with patch("src.full_scan.run_semgrep_scan", return_value=""):
        outcome = run_full_scan(str(tmp_path), "", ai_triage=False)

    assert outcome.firmware_finding_count == 1
    assert outcome.total_finding_count == 1
    assert outcome.report.issues[0].finding_id == "FIRMWARE-test"


def test_firmware_specific_manual_guidance_is_preserved():
    issue = ReviewIssue(
        file="firmware/files/etc/rc.local",
        line=4,
        severity="HIGH",
        issue_name="Cleartext Telnet service",
        description="The firmware launches telnetd at boot.",
        original_code="telnetd &",
        suggested_fix="",
        remediation_guidance="Remove Telnet and restrict SSH to trusted management networks.",
        finding_id="FIRMWARE-guidance",
        rule_id="aegisscan.firmware.insecure-telnet-service",
        confidence="HIGH",
        code_role="RUNTIME",
        source_evidence="rc.local enables the daemon.",
        sink_evidence="telnetd opens a cleartext service.",
        sink_file="firmware/files/etc/rc.local",
        sink_line=4,
        reachability_evidence="Normal boot executes rc.local.",
        remediation_type="MANUAL_REQUIRED",
    )
    report = ReviewReport(analysis_scratchpad="", issues=[issue], dispositions=[])

    normalized = _normalize_manual_remediations(report)

    assert normalized.issues[0].remediation_guidance == issue.remediation_guidance


def test_dependency_metrics_are_reconciled_after_final_report_merge(tmp_path, monkeypatch):
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies":{"library":"1.0.0"}}\n', encoding="utf-8")
    issues = []
    dispositions = []
    for index, advisory in enumerate(("GHSA-one", "GHSA-two"), start=1):
        finding_id = f"OSV-{index}"
        issues.append(
            ReviewIssue(
                file="package.json",
                line=1,
                severity="HIGH",
                issue_name=f"Vulnerable dependency: library ({advisory})",
                description=f"library 1.0.0 matches {advisory}.",
                original_code="library 1.0.0",
                suggested_fix="",
                finding_id=finding_id,
                rule_id=f"osv.{advisory}",
                confidence="MEDIUM",
                code_role="RUNTIME",
                source_evidence="Resolved from package.json.",
                sink_evidence=f"The version is affected by {advisory}.",
                sink_file="package.json",
                sink_line=1,
                reachability_evidence="Dependency metadata establishes presence.",
                remediation_type="MANUAL_REQUIRED",
            )
        )
        dispositions.append(
            FindingDisposition(
                finding_id=finding_id,
                status="CONFIRMED",
                reason="Known advisory match.",
                file="package.json",
                line=1,
                rule_id=f"osv.{advisory}",
                code_role="RUNTIME",
                confidence="MEDIUM",
            )
        )
    monkeypatch.setattr(
        "src.full_scan.scan_dependencies",
        lambda _path: DetectorResult(
            detector="osv",
            finding_count=2,
            issues=issues,
            dispositions=dispositions,
            telemetry={
                "raw_dependency_finding_occurrences": 2,
                "raw_unique_advisories": 2,
            },
        ),
    )

    with patch("src.full_scan.run_semgrep_scan", return_value=""):
        outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert len([issue for issue in outcome.report.issues if issue.rule_id.startswith("osv.")]) == 2
    assert outcome.exported_dependency_finding_count == 2
    assert outcome.unique_dependency_advisory_count == 2
    telemetry = outcome.detector_telemetry["osv"]
    assert telemetry["exported_dependency_findings"] == 2
    assert telemetry["exported_unique_advisories"] == 2
    assert telemetry["exported_affected_packages"] == [
        {"package": "library", "unique_advisories": 2, "findings": 2}
    ]


def test_detector_only_scan_needs_no_api_key_and_retains_runtime_candidates(tmp_path):
    (tmp_path / "app.py").write_text("dangerous()\n", encoding="utf-8")
    progress_events: list[str] = []

    with patch("src.full_scan.run_semgrep_scan", return_value=_finding(1, "app.py")):
        with patch("src.full_scan.call_gemini_with_failover") as ai_call:
            outcome = run_full_scan(
                str(tmp_path),
                "",
                ai_triage=False,
                progress=progress_events.append,
            )

    ai_call.assert_not_called()
    assert outcome.ai_triage_enabled is False
    assert outcome.ai_attempted_batches == 0
    assert outcome.ai_successful_batches == 0
    assert outcome.report.issues == []
    assert outcome.disposition_count("NEEDS_REVIEW") == 1
    assert outcome.report.dispositions[0].confidence == "LOW"
    assert not outcome.audit_degraded
    assert any("intentionally disabled" in event for event in progress_events)


def test_ai_triage_still_requires_an_api_key_or_client(tmp_path):
    with pytest.raises(ValueError, match="OpenRouter or Gemini API key"):
        run_full_scan(str(tmp_path), "")


def test_openrouter_can_be_the_only_ai_provider(tmp_path):
    (tmp_path / "app.py").write_text("dangerous()\n", encoding="utf-8")
    report = ReviewReport(analysis_scratchpad="OpenRouter review", issues=[])
    with patch("src.full_scan.run_semgrep_scan", return_value=_finding(1, "app.py")):
        with patch(
            "src.full_scan.call_openrouter_with_failover", return_value=report
        ) as openrouter_call:
            outcome = run_full_scan(
                str(tmp_path),
                "",
                openrouter_api_key="sk-or-test",
                ai_provider="openrouter",
            )

    openrouter_call.assert_called_once()
    assert outcome.ai_provider_order == ["openrouter"]
    assert outcome.ai_models == ["deepseek/deepseek-v4-flash"]
    assert outcome.ai_successful_batches == 1


def test_openrouter_uses_smaller_context_batches(tmp_path):
    for index in range(7):
        (tmp_path / f"app_{index}.py").write_text("dangerous()\n", encoding="utf-8")
    findings = "".join(_finding(index + 1, f"app_{index}.py") for index in range(7))
    report = ReviewReport(analysis_scratchpad="reviewed", issues=[])

    with patch("src.full_scan.run_semgrep_scan", return_value=findings):
        with patch(
            "src.full_scan.call_openrouter_with_failover", return_value=report
        ) as openrouter_call:
            outcome = run_full_scan(
                str(tmp_path),
                "",
                openrouter_api_key="sk-or-test",
                ai_provider="openrouter",
                batch_size=12,
            )

    assert outcome.batch_count == 3
    assert openrouter_call.call_count == 3


def test_failed_ai_batch_is_recursively_split_and_recovered(tmp_path):
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text("dangerous()\n", encoding="utf-8")
    findings = _finding(1, "a.py") + _finding(2, "b.py")

    def recover_small_batches(_key, prompt, progress=None, **_kwargs):
        del progress
        candidate_ids = re.findall(r"(?m)^Candidate ID:\s*(\S+)\s*$", prompt)
        if len(candidate_ids) > 1:
            raise RuntimeError("combined response malformed")
        return ReviewReport(
            analysis_scratchpad="single finding recovered",
            issues=[],
            dispositions=[
                FindingDisposition(
                    finding_id=candidate_ids[0],
                    status="FALSE_POSITIVE",
                    reason="No sensitive sink is reachable.",
                )
            ],
        )

    with patch("src.full_scan.run_semgrep_scan", return_value=findings):
        with patch(
            "src.full_scan.call_openrouter_with_failover",
            side_effect=recover_small_batches,
        ) as openrouter_call:
            outcome = run_full_scan(
                str(tmp_path),
                "",
                openrouter_api_key="sk-or-test",
                ai_provider="openrouter",
            )

    assert openrouter_call.call_count == 3
    assert outcome.ai_attempted_batches == 1
    assert outcome.ai_successful_batches == 1
    assert outcome.failed_batches == []
    assert not outcome.audit_degraded
    assert [item.status for item in outcome.report.dispositions] == [
        "FALSE_POSITIVE",
        "FALSE_POSITIVE",
    ]


def test_repaired_candidate_receives_strict_singleton_retriage(tmp_path):
    (tmp_path / "app.py").write_text("dangerous()\n", encoding="utf-8")
    calls: list[bool] = []

    def triage(_key, prompt, progress=None, allow_semantic_repair=True, **_kwargs):
        del progress
        calls.append(allow_semantic_repair)
        candidate_id = re.search(r"(?m)^Candidate ID:\s*(\S+)\s*$", prompt).group(1)
        if allow_semantic_repair:
            return ReviewReport(
                analysis_scratchpad="provider omitted the verdict",
                issues=[],
                dispositions=[
                    FindingDisposition(
                        finding_id=candidate_id,
                        status="NEEDS_REVIEW",
                        reason=(
                            "The model omitted this candidate; deterministic repair retained "
                            "it for manual review."
                        ),
                        confidence="LOW",
                    )
                ],
            )
        return ReviewReport(
            analysis_scratchpad="strict singleton verdict",
            issues=[],
            dispositions=[
                FindingDisposition(
                    finding_id=candidate_id,
                    status="FALSE_POSITIVE",
                    reason="No sensitive sink is reachable.",
                    confidence="HIGH",
                )
            ],
        )

    with patch("src.full_scan.run_semgrep_scan", return_value=_finding(1, "app.py")):
        with patch("src.full_scan.call_openrouter_with_failover", side_effect=triage):
            outcome = run_full_scan(
                str(tmp_path),
                "",
                openrouter_api_key="sk-or-test",
                ai_provider="openrouter",
            )

    assert calls == [True, False]
    assert outcome.report.dispositions[0].status == "FALSE_POSITIVE"
    assert outcome.ai_telemetry["targeted_retriage_attempts"] == 1
    assert outcome.ai_telemetry["targeted_retriage_recovered"] == 1
    assert not outcome.ai_triage_degraded


def test_bundled_hmac_rule_is_confirmed_without_strict_provider_retriage(tmp_path):
    (tmp_path / "security.ts").write_text(
        "crypto.createHmac('sha256', '0123456789abcdef')\n",
        encoding="utf-8",
    )
    finding = _finding(1, "security.ts").replace(
        "test.rule",
        "aegisscan.javascript.hardcoded-hmac-key",
    )
    calls: list[bool] = []

    def triage(_key, prompt, progress=None, allow_semantic_repair=True, **_kwargs):
        del progress
        calls.append(allow_semantic_repair)
        candidate_id = re.search(r"(?m)^Candidate ID:\s*(\S+)\s*$", prompt).group(1)
        return ReviewReport(
            analysis_scratchpad="provider omitted credential evidence",
            issues=[],
            dispositions=[
                FindingDisposition(
                    finding_id=candidate_id,
                    status="NEEDS_REVIEW",
                    reason=(
                        "The model omitted this candidate; deterministic repair retained "
                        "it for manual review."
                    ),
                    confidence="LOW",
                )
            ],
        )

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_openrouter_with_failover", side_effect=triage):
            outcome = run_full_scan(
                str(tmp_path),
                "",
                openrouter_api_key="sk-or-test",
                ai_provider="openrouter",
            )

    assert calls == [True]
    assert len(outcome.report.issues) == 1
    assert outcome.report.issues[0].issue_name == "Hardcoded HMAC key"
    assert outcome.report.issues[0].original_code == ""
    assert outcome.report.dispositions[0].status == "CONFIRMED"
    assert outcome.ai_telemetry["deterministic_retriage_skipped"] == 1


def test_bundled_private_key_rule_survives_missing_provider_verdict(tmp_path):
    (tmp_path / "security.ts").write_text(
        "const privateKey = '-----BEGIN PRIVATE KEY-----redacted'\n",
        encoding="utf-8",
    )
    finding = _finding(1, "security.ts").replace(
        "test.rule",
        "aegisscan.javascript.hardcoded-private-key",
    )
    incomplete = ReviewReport(
        analysis_scratchpad="provider omitted the candidate",
        issues=[],
        dispositions=[],
    )

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=incomplete):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert len(outcome.report.issues) == 1
    assert outcome.report.issues[0].issue_name == "Hardcoded private key"
    assert outcome.report.issues[0].original_code == ""
    assert outcome.report.dispositions[0].status == "CONFIRMED"


def test_auto_provider_falls_back_from_openrouter_to_gemini(tmp_path):
    (tmp_path / "app.py").write_text("dangerous()\n", encoding="utf-8")
    report = ReviewReport(analysis_scratchpad="Gemini fallback", issues=[])
    progress: list[str] = []
    with patch("src.full_scan.run_semgrep_scan", return_value=_finding(1, "app.py")):
        with patch(
            "src.full_scan.call_openrouter_with_failover",
            side_effect=RuntimeError("OpenRouter credits exhausted"),
        ):
            with patch(
                "src.full_scan.call_gemini_with_failover", return_value=report
            ) as gemini_call:
                outcome = run_full_scan(
                    str(tmp_path),
                    "gemini-key",
                    openrouter_api_key="sk-or-test",
                    ai_provider="auto",
                    client=MagicMock(),
                    progress=progress.append,
                )

    gemini_call.assert_called_once()
    assert outcome.ai_provider_order == ["openrouter", "gemini"]
    assert outcome.ai_successful_batches == 1
    assert any("trying the next configured provider" in item for item in progress)


@pytest.mark.parametrize(
    ("provider", "expected"),
    [
        ("openrouter", "OpenRouter API key"),
        ("gemini", "Gemini API key"),
    ],
)
def test_explicit_ai_provider_requires_its_own_key(tmp_path, provider, expected):
    with pytest.raises(ValueError, match=expected):
        run_full_scan(str(tmp_path), "", ai_provider=provider)


def test_detector_failure_marks_audit_degraded(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "src.full_scan.scan_dependencies",
        lambda _path: DetectorResult(detector="osv", errors=["tool unavailable"]),
    )
    with patch("src.full_scan.run_semgrep_scan", return_value=""):
        outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert outcome.audit_degraded
    assert not outcome.ai_triage_degraded
    assert outcome.detector_errors == {"osv": ["tool unavailable"]}


def test_dependency_coverage_gap_marks_audit_degraded(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "src.full_scan.scan_dependencies",
        lambda _path: DetectorResult(
            detector="osv",
            coverage_gaps=["package.json has no supported lockfile"],
            telemetry={"status": "coverage_unavailable"},
        ),
    )
    with patch("src.full_scan.run_semgrep_scan", return_value=""):
        outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert outcome.audit_degraded
    assert outcome.detector_errors == {}
    assert outcome.detector_coverage_gaps == {"osv": ["package.json has no supported lockfile"]}


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
    assert outcome.runtime_scan_gap_count == 1
    assert outcome.audit_degraded


@pytest.mark.parametrize(
    "rule_id",
    [
        "java.lang.security.audit.crypto.use-of-md5.use-of-md5",
        "java.lang.security.audit.crypto.weak-random.weak-random",
        "java.spring.security.unrestricted-request-mapping.unrestricted-request-mapping",
    ],
)
def test_deterministic_java_review_rules_bypass_ai_without_degrading_audit(tmp_path, rule_id):
    (tmp_path / "HashingAssignment.java").write_text("unsafe();\n", encoding="utf-8")
    finding = (
        "Finding #1:\n"
        f"Rule ID: {rule_id}\n"
        "File: HashingAssignment.java:1\n"
        "Message: security-sensitive Java construct\n"
        "Code Snippet: unsafe();\n"
    )

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover") as ai_call:
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    ai_call.assert_not_called()
    assert outcome.disposition_count("NEEDS_REVIEW") == 1
    assert outcome.ai_attempted_batches == 0
    assert outcome.audit_degraded is False


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


@pytest.mark.parametrize(
    ("issue_name", "rule_id"),
    [
        ("Server-Side Request Forgery", "aegisscan.python.user-input-to-network-request"),
        ("Filesystem Race", "aegisscan.python.filesystem-check-then-use"),
        ("Path Traversal", "aegisscan.javascript.express-path-traversal"),
        ("Insecure Direct Object Reference", "aegisscan.javascript.express-id-to-data-access"),
    ],
)
def test_context_dependent_security_fixes_require_manual_remediation(issue_name, rule_id):
    issue = ReviewIssue(
        file="app.py",
        line=1,
        severity="HIGH",
        issue_name=issue_name,
        description="Attacker input reaches a sensitive operation.",
        original_code="unsafe(value)",
        suggested_fix="safer(value)",
    )

    assert _requires_manual_remediation(issue, rule_id)


def test_manual_remediation_replaces_patch_fragments_with_actionable_guidance():
    issue = ReviewIssue(
        file="proxy.ts",
        line=4,
        severity="HIGH",
        issue_name="Server-Side Request Forgery",
        description="Request data reaches fetch.",
        original_code="await fetch(url)",
        suggested_fix="await fetch(url) // validate this first",
        remediation_type="MANUAL_REQUIRED",
    )

    normalized = _normalize_manual_remediations(
        ReviewReport(analysis_scratchpad="ssrf", issues=[issue])
    ).issues[0]

    assert normalized.suggested_fix == ""
    assert "allow" in normalized.remediation_guidance.casefold()
    assert "redirect" in normalized.remediation_guidance.casefold()


def test_unvetted_automatic_remediation_is_downgraded_to_manual():
    issue = ReviewIssue(
        file="routes/search.ts",
        line=23,
        severity="HIGH",
        issue_name="SQL Injection",
        description="Request input reaches a string-built SQL query.",
        original_code="query(`SELECT ${value}`)",
        suggested_fix="query('SELECT ?', { replacements: [value] })",
        remediation_guidance="Use Python os.path.commonpath() even though this is TypeScript.",
        remediation_type="AUTOMATIC",
    )

    normalized = _normalize_manual_remediations(
        ReviewReport(analysis_scratchpad="sqli", issues=[issue])
    ).issues[0]

    assert normalized.remediation_type == "MANUAL_REQUIRED"
    assert not normalized.suggested_fix
    assert "parameterized" in normalized.remediation_guidance.casefold()
    assert "tests" in normalized.remediation_guidance.casefold()
    assert "os.path" not in normalized.remediation_guidance


def test_empty_automatic_replacement_is_downgraded_to_manual_remediation():
    issue = ReviewIssue(
        file="app.py",
        line=1,
        severity="HIGH",
        issue_name="Security Finding",
        description="A security boundary requires an application-aware change.",
        original_code="unsafe(value)",
        suggested_fix="",
        remediation_type="AUTOMATIC",
    )

    normalized = _normalize_manual_remediations(
        ReviewReport(analysis_scratchpad="missing fix", issues=[issue])
    ).issues[0]

    assert normalized.remediation_type == "MANUAL_REQUIRED"
    assert normalized.remediation_guidance


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
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock(), batch_size=1)

    assert outcome.failed_batches == [2]
    assert outcome.failed_batch_reasons[2].endswith(": model outage")
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
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock(), progress=progress.append)

    assert outcome.report.issues == []
    assert outcome.failed_batches == [1]
    assert outcome.failed_batch_reasons[1].endswith(": model outage")
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
    findings = _finding(1, "routes/videoHandler.ts", 57) + _finding(2, "routes/videoHandler.ts", 71)
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
    assert outcome.disposition_count("DUPLICATE") == 1
    duplicate = next(item for item in outcome.report.dispositions if item.status == "DUPLICATE")
    assert duplicate.canonical_finding_id


def test_semgrep_and_secret_scanner_findings_share_one_canonical_issue(tmp_path, monkeypatch):
    semgrep_finding = _finding(1, "security.ts")
    semgrep_finding_id = batch_findings([semgrep_finding])[0].findings[0].finding_id
    (tmp_path / "security.ts").write_text(
        "const privateKey = loadEmbeddedKey()\n" + "\n" * 18 + "authenticate(privateKey)\n",
        encoding="utf-8",
    )
    semgrep_issue = ReviewIssue(
        file="security.ts",
        line=20,
        sink_file="security.ts",
        sink_line=20,
        severity="HIGH",
        issue_name="Hardcoded private key",
        description="An embedded private key is used for authentication.",
        original_code="authenticate(privateKey)",
        suggested_fix="authenticate(loadKeyFromSecretStore())",
        confidence="HIGH",
        source_evidence="The repository embeds the signing credential at security.ts:1.",
        sink_evidence="The runtime authentication path consumes the key.",
        reachability_evidence="The application loads this value during startup.",
        remediation_type="MANUAL_REQUIRED",
        finding_id=semgrep_finding_id,
    )
    secret_issue = semgrep_issue.model_copy(
        update={
            "finding_id": "SECRET-one",
            "rule_id": "betterleaks.private-key",
            "file": "security.ts",
            "line": 1,
            "sink_file": "security.ts",
            "sink_line": 1,
            "issue_name": "Potential hardcoded secret: Private key",
            "source_evidence": "Betterleaks matched a redacted private key.",
            "sink_evidence": "A credential-shaped value is stored in source.",
            "reachability_evidence": "The value is present in runtime source.",
        }
    )
    secret_disposition = FindingDisposition(
        finding_id="SECRET-one",
        status="CONFIRMED",
        reason="A specific credential format was detected.",
        file="security.ts",
        line=1,
        rule_id="betterleaks.private-key",
        message="Private key",
        code_role="RUNTIME",
        confidence="HIGH",
    )
    monkeypatch.setattr(
        "src.full_scan.scan_secrets",
        lambda _path, **_kwargs: DetectorResult(
            detector="betterleaks",
            finding_count=1,
            issues=[secret_issue],
            dispositions=[secret_disposition],
        ),
    )
    report = ReviewReport(analysis_scratchpad="runtime key use", issues=[semgrep_issue])

    with patch(
        "src.full_scan.run_semgrep_scan",
        return_value=semgrep_finding,
    ):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert len(outcome.report.issues) == 1
    assert outcome.report.issues[0].rule_id == "test.rule"
    assert outcome.secret_finding_count == 1
    assert outcome.secret_scanner == "betterleaks"
    assert outcome.disposition_count("CONFIRMED") == 1
    assert outcome.disposition_count("DUPLICATE") == 1


def test_nearby_cross_rule_findings_have_stable_canonical_result(tmp_path):
    source = tmp_path / "routes" / "redirect.ts"
    source.parent.mkdir(parents=True)
    source.write_text("\n".join(["const value = 1"] * 30) + "\n", encoding="utf-8")

    registry = ReviewIssue(
        file="routes/redirect.ts",
        line=20,
        sink_file="routes/redirect.ts",
        sink_line=20,
        severity="HIGH",
        issue_name="Open Redirect",
        description="An attacker-controlled URL reaches a redirect sink.",
        original_code="res.redirect(target)",
        suggested_fix="",
        finding_id="SG-registry",
        rule_id="javascript.express.security.audit.express-open-redirect",
        confidence="HIGH",
        source_evidence="The request supplies target.",
        sink_evidence="res.redirect sends the response to target.",
        reachability_evidence="The route invokes the redirect directly.",
        remediation_type="MANUAL_REQUIRED",
    )
    bundled = registry.model_copy(
        update={
            "line": 23,
            "sink_line": 23,
            "finding_id": "SG-bundled",
            "rule_id": "aegisscan.javascript.express-open-redirect",
            "description": "Untrusted redirect input reaches the response sink.",
        }
    )

    def report_for(issue: ReviewIssue) -> ReviewReport:
        return ReviewReport(
            analysis_scratchpad=f"reviewed {issue.finding_id}",
            issues=[issue],
            dispositions=[
                FindingDisposition(
                    finding_id=issue.finding_id,
                    status="CONFIRMED",
                    reason="Runtime redirect flow was confirmed.",
                    file=issue.file,
                    line=issue.line,
                    rule_id=issue.rule_id,
                    message="Potential open redirect",
                    code_role="RUNTIME",
                    confidence="HIGH",
                )
            ],
        )

    forward = _merge_reports(
        [(1, report_for(registry)), (2, report_for(bundled))],
        tmp_path,
    )
    reversed_order = _merge_reports(
        [(1, report_for(bundled)), (2, report_for(registry))],
        tmp_path,
    )

    for report in (forward, reversed_order):
        assert [issue.finding_id for issue in report.issues] == ["SG-bundled"]
        verdicts = {
            disposition.finding_id: (
                disposition.status,
                disposition.canonical_finding_id,
            )
            for disposition in report.dispositions
        }
        assert verdicts == {
            "SG-bundled": ("CONFIRMED", ""),
            "SG-registry": ("DUPLICATE", "SG-bundled"),
        }


def test_nearby_different_secret_types_remain_separate(tmp_path):
    source = tmp_path / "security.ts"
    source.write_text("\n".join(["const value = 1"] * 40) + "\n", encoding="utf-8")
    private_key = ReviewIssue(
        file="security.ts",
        line=21,
        sink_file="security.ts",
        sink_line=21,
        severity="CRITICAL",
        issue_name="Hardcoded private key",
        description="A private key is embedded in runtime source.",
        original_code="const privateKey = embeddedKey",
        suggested_fix="",
        finding_id="SG-private-key",
        rule_id="aegisscan.javascript.hardcoded-private-key",
        confidence="HIGH",
        source_evidence="The private key is stored in source.",
        sink_evidence="The private key is loaded for signing.",
        reachability_evidence="Startup code loads the credential.",
        remediation_type="MANUAL_REQUIRED",
    )
    hmac_key = private_key.model_copy(
        update={
            "line": 32,
            "sink_line": 32,
            "issue_name": "Hardcoded HMAC key",
            "description": "A hardcoded HMAC key is passed to createHmac.",
            "original_code": "createHmac('sha256', hmacKey)",
            "finding_id": "SG-hmac-key",
            "rule_id": "javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret",
            "source_evidence": "The HMAC key is a source literal.",
            "sink_evidence": "createHmac consumes the HMAC key.",
        }
    )
    dispositions = [
        FindingDisposition(
            finding_id=issue.finding_id,
            status="CONFIRMED",
            reason="A runtime credential use was confirmed.",
            file=issue.file,
            line=issue.line,
            rule_id=issue.rule_id,
            message=issue.issue_name,
            code_role="RUNTIME",
            confidence="HIGH",
        )
        for issue in (private_key, hmac_key)
    ]
    merged = _merge_reports(
        [
            (
                1,
                ReviewReport(
                    analysis_scratchpad="reviewed distinct credentials",
                    issues=[private_key, hmac_key],
                    dispositions=dispositions,
                ),
            )
        ],
        tmp_path,
    )

    assert {issue.finding_id for issue in merged.issues} == {
        "SG-private-key",
        "SG-hmac-key",
    }
    assert all(item.status == "CONFIRMED" for item in merged.dispositions)


def test_overlapping_hmac_and_jwt_secret_rules_share_one_canonical_issue(tmp_path):
    source = tmp_path / "lib" / "insecurity.ts"
    source.parent.mkdir(parents=True)
    source.write_text(
        "\n".join(["const value = 1"] * 41 + ["crypto.createHmac('sha256', secret)"])
        + "\n",
        encoding="utf-8",
    )
    bundled = ReviewIssue(
        file="lib/insecurity.ts",
        line=42,
        sink_file="lib/insecurity.ts",
        sink_line=42,
        severity="HIGH",
        issue_name="Hardcoded HMAC Key",
        description="A hardcoded HMAC key reaches createHmac.",
        original_code="crypto.createHmac('sha256', secret)",
        suggested_fix="",
        finding_id="SG-bundled-hmac",
        rule_id="aegisscan.javascript.hardcoded-hmac-key",
        confidence="HIGH",
        source_evidence="A cryptographic key literal is embedded in source.",
        sink_evidence="createHmac consumes the embedded key.",
        reachability_evidence="The exported helper invokes createHmac.",
        remediation_type="MANUAL_REQUIRED",
    )
    registry = bundled.model_copy(
        update={
            "issue_name": "Hardcoded Cryptographic Secret",
            "description": "A hardcoded HMAC secret reaches createHmac.",
            "finding_id": "SG-registry-jwt",
            "rule_id": "javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret",
        }
    )
    dispositions = [
        FindingDisposition(
            finding_id=issue.finding_id,
            status="CONFIRMED",
            reason="The embedded runtime signing secret was confirmed.",
            file=issue.file,
            line=issue.line,
            rule_id=issue.rule_id,
            message=issue.issue_name,
            code_role="RUNTIME",
            confidence="HIGH",
        )
        for issue in (bundled, registry)
    ]

    merged = _merge_reports(
        [
            (
                1,
                ReviewReport(
                    analysis_scratchpad="overlapping secret rules",
                    issues=[registry, bundled],
                    dispositions=dispositions,
                ),
            )
        ],
        tmp_path,
    )

    assert [issue.finding_id for issue in merged.issues] == ["SG-bundled-hmac"]
    verdicts = {item.finding_id: item.status for item in merged.dispositions}
    assert verdicts == {
        "SG-bundled-hmac": "CONFIRMED",
        "SG-registry-jwt": "DUPLICATE",
    }


def test_private_key_declaration_and_signing_use_share_one_canonical_issue(tmp_path):
    source = tmp_path / "lib" / "insecurity.ts"
    source.parent.mkdir(parents=True)
    source.write_text(
        "\n".join(
            ["const value = 1"] * 20
            + ["const privateKey = 'redacted-private-key'"]
            + ["const value = 1"] * 32
            + ["jwt.sign(user, privateKey)"]
        )
        + "\n",
        encoding="utf-8",
    )
    detector = ReviewIssue(
        file="lib/insecurity.ts",
        line=21,
        sink_file="lib/insecurity.ts",
        sink_line=21,
        severity="CRITICAL",
        issue_name="Hardcoded private key",
        description="A private key is embedded in runtime source.",
        original_code="const privateKey = 'redacted-private-key'",
        suggested_fix="",
        finding_id="SECRET-private-key",
        rule_id="betterleaks.private-key",
        confidence="HIGH",
        source_evidence="Betterleaks matched a redacted value at lib/insecurity.ts:21.",
        sink_evidence="A credential-shaped value is stored in repository source.",
        reachability_evidence="The value is present in current runtime source.",
        remediation_type="MANUAL_REQUIRED",
    )
    contextual = detector.model_copy(
        update={
            "line": 21,
            "sink_line": 54,
            "description": "The embedded private key reaches JWT signing.",
            "original_code": "jwt.sign(user, privateKey)",
            "finding_id": "SG-private-key-use",
            "rule_id": "aegisscan.javascript.hardcoded-private-key",
            "source_evidence": "The literal assigned to privateKey at line 21 is embedded.",
            "sink_evidence": "privateKey is passed to jwt.sign at line 54.",
            "reachability_evidence": "The exported authorization helper signs JWTs.",
        }
    )
    dispositions = [
        FindingDisposition(
            finding_id=issue.finding_id,
            status="CONFIRMED",
            reason="The embedded runtime signing key was confirmed.",
            file=issue.file,
            line=issue.line,
            rule_id=issue.rule_id,
            message=issue.issue_name,
            code_role="RUNTIME",
            confidence="HIGH",
        )
        for issue in (detector, contextual)
    ]

    merged = _merge_reports(
        [
            (
                1,
                ReviewReport(
                    analysis_scratchpad="private-key declaration and use",
                    issues=[detector, contextual],
                    dispositions=dispositions,
                ),
            )
        ],
        tmp_path,
    )

    assert [issue.finding_id for issue in merged.issues] == ["SG-private-key-use"]
    verdicts = {
        item.finding_id: (item.status, item.canonical_finding_id)
        for item in merged.dispositions
    }
    assert verdicts == {
        "SECRET-private-key": ("DUPLICATE", "SG-private-key-use"),
        "SG-private-key-use": ("CONFIRMED", ""),
    }


def test_unresolved_signing_use_consolidates_into_confirmed_key_declaration(tmp_path):
    source = tmp_path / "lib" / "insecurity.ts"
    source.parent.mkdir(parents=True)
    source.write_text(
        "\n".join(
            ["const value = 1"] * 20
            + ["const privateKey = 'redacted-private-key'"]
            + ["const value = 1"] * 32
            + ["jwt.sign(user, privateKey)"]
        )
        + "\n",
        encoding="utf-8",
    )
    detector = ReviewIssue(
        file="lib/insecurity.ts",
        line=21,
        sink_file="lib/insecurity.ts",
        sink_line=21,
        severity="CRITICAL",
        issue_name="Hardcoded private key",
        description="A private key is embedded in runtime source.",
        original_code="",
        suggested_fix="",
        finding_id="SECRET-private-key",
        rule_id="betterleaks.private-key",
        confidence="HIGH",
        source_evidence="A redacted private key was detected at lib/insecurity.ts:21.",
        sink_evidence="A credential-shaped value is stored in repository source.",
        reachability_evidence="The value is present in current runtime source.",
        remediation_type="MANUAL_REQUIRED",
    )
    report = ReviewReport(
        analysis_scratchpad="provider did not complete the signing-use verdict",
        issues=[detector],
        dispositions=[
            FindingDisposition(
                finding_id="SECRET-private-key",
                status="CONFIRMED",
                reason="A specific private-key format was detected.",
                file="lib/insecurity.ts",
                line=21,
                rule_id="betterleaks.private-key",
                message="Private key",
                code_role="RUNTIME",
                confidence="HIGH",
            ),
            FindingDisposition(
                finding_id="SG-jwt-use",
                status="NEEDS_REVIEW",
                reason="The provider omitted complete credential evidence.",
                file="lib/insecurity.ts",
                line=54,
                rule_id=(
                    "javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret"
                ),
                message="A hardcoded JWT signing credential may be in use.",
                code_role="RUNTIME",
                confidence="LOW",
            ),
        ],
    )

    merged = _merge_reports([(1, report)], tmp_path)

    assert [issue.finding_id for issue in merged.issues] == ["SECRET-private-key"]
    verdicts = {
        item.finding_id: (item.status, item.canonical_finding_id)
        for item in merged.dispositions
    }
    assert verdicts["SG-jwt-use"] == ("DUPLICATE", "SECRET-private-key")


def test_typescript_path_traversal_is_evidence_bounded_and_manual(tmp_path):
    source = tmp_path / "routes" / "vulnCodeFixes.ts"
    source.parent.mkdir(parents=True)
    vulnerable_line = (
        "fs.readFileSync('./data/static/codefixes/' + key + '.info.yml', 'utf8')"
    )
    source.write_text(vulnerable_line + "\n", encoding="utf-8")
    finding = (
        "Finding #1:\n"
        "Rule ID: aegisscan.javascript.express-path-traversal\n"
        "File: routes/vulnCodeFixes.ts:1\n"
        "Message: Request data reaches a path traversal sink\n"
        f"Code Snippet: {vulnerable_line}\n"
    )
    candidate = batch_findings([finding])[0].findings[0]
    issue = ReviewIssue(
        file=candidate.file,
        line=1,
        sink_file=candidate.file,
        sink_line=1,
        severity="HIGH",
        issue_name="Path Traversal in code fix retrieval",
        description=(
            "User-controlled key enables path traversal to read arbitrary files such as "
            "/etc/passwd."
        ),
        original_code=vulnerable_line,
        suggested_fix="fs.readFileSync(safePath, 'utf8')",
        remediation_guidance="Use Python os.path.commonpath().",
        finding_id=candidate.finding_id,
        rule_id=candidate.rule_id,
        confidence="HIGH",
        source_evidence="req.body.key supplies the path component.",
        sink_evidence="fs.readFileSync consumes the constructed path.",
        reachability_evidence="req.body.key reaches fs.readFileSync directly.",
        remediation_type="AUTOMATIC",
    )
    report = ReviewReport(
        analysis_scratchpad="path traversal confirmed",
        issues=[issue],
        dispositions=[
            FindingDisposition(
                finding_id=candidate.finding_id,
                status="CONFIRMED",
                reason="The source reaches the file read.",
                file=candidate.file,
                line=1,
                rule_id=candidate.rule_id,
                message=candidate.message,
                code_role="RUNTIME",
                confidence="HIGH",
            )
        ],
    )

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    confirmed = outcome.report.issues[0]
    assert confirmed.remediation_type == "MANUAL_REQUIRED"
    assert confirmed.suggested_fix == ""
    assert "Node.js path.resolve()" in confirmed.remediation_guidance
    assert "path.relative()" in confirmed.remediation_guidance
    assert "os.path" not in confirmed.remediation_guidance
    assert "`.info.yml`" in confirmed.description
    assert "/etc/passwd" not in confirmed.description
    assert "broader arbitrary-file access is not established" in confirmed.description


def test_express_object_send_is_not_reported_as_xss(tmp_path):
    source = tmp_path / "routes" / "dataExport.ts"
    source.parent.mkdir(parents=True)
    source_line = "res.status(200).send({ userData: JSON.stringify(userData) })"
    source.write_text(source_line + "\n", encoding="utf-8")
    finding = (
        "Finding #1:\n"
        "Rule ID: aegisscan.javascript.express-response-xss\n"
        "File: routes/dataExport.ts:1\n"
        "Message: response data might execute as HTML\n"
        f"Code Snippet: {source_line}\n"
    )
    candidate = batch_findings([finding])[0].findings[0]
    issue = ReviewIssue(
        file=candidate.file,
        line=1,
        severity="HIGH",
        issue_name="Cross-Site Scripting (XSS)",
        description="Object data might be rendered as HTML.",
        original_code=source_line,
        suggested_fix="res.status(200).json({ userData })",
        finding_id=candidate.finding_id,
        rule_id=candidate.rule_id,
        confidence="HIGH",
        source_evidence="Database values populate userData.",
        sink_evidence="res.send receives an object.",
        reachability_evidence="The route returns the object.",
    )
    report = ReviewReport(analysis_scratchpad="response reviewed", issues=[issue])

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert outcome.report.issues == []
    verdict = outcome.report.dispositions[0]
    assert verdict.status == "FALSE_POSITIVE"
    assert "serializes" in verdict.reason
    assert "JSON" in verdict.reason


def test_public_delivery_catalog_lookup_is_not_idor(tmp_path):
    source = tmp_path / "routes" / "delivery.ts"
    source.parent.mkdir(parents=True)
    source.write_text(
        "export function getDeliveryMethods () {\n"
        "  return DeliveryModel.findAll()\n"
        "}\n"
        "export function getDeliveryMethod () {\n"
        "  return DeliveryModel.findOne({ where: { id: req.params.id } })\n"
        "}\n",
        encoding="utf-8",
    )
    finding = (
        "Finding #1:\n"
        "Rule ID: aegisscan.javascript.express-id-to-data-access\n"
        "File: routes/delivery.ts:5\n"
        "Message: request id reaches a model lookup\n"
        "Code Snippet: DeliveryModel.findOne({ where: { id: req.params.id } })\n"
    )
    report = ReviewReport(analysis_scratchpad="catalog reviewed", issues=[])

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert outcome.report.dispositions[0].status == "FALSE_POSITIVE"
    assert "shared catalog" in outcome.report.dispositions[0].reason


def test_authenticated_owner_scoped_payment_lookup_is_not_idor(tmp_path):
    routes = tmp_path / "routes"
    library = tmp_path / "lib"
    routes.mkdir()
    library.mkdir()
    routes.joinpath("payment.ts").write_text(
        "export function getPaymentMethodById () {\n"
        "  return CardModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })\n"
        "}\n",
        encoding="utf-8",
    )
    library.joinpath("insecurity.ts").write_text(
        "export const appendUserId = () => (req, res, next) => {\n"
        "  req.body.UserId = authenticatedUsers.tokenMap[jwtFrom(req)].data.id\n"
        "  next()\n"
        "}\n",
        encoding="utf-8",
    )
    tmp_path.joinpath("server.ts").write_text(
        "app.get('/api/Cards/:id', security.appendUserId(), "
        "payment.getPaymentMethodById())\n",
        encoding="utf-8",
    )
    finding = (
        "Finding #1:\n"
        "Rule ID: aegisscan.javascript.express-id-to-data-access\n"
        "File: routes/payment.ts:2\n"
        "Message: request id reaches a model lookup\n"
        "Code Snippet: CardModel.findOne({ where: { id: req.params.id, "
        "UserId: req.body.UserId } })\n"
    )
    report = ReviewReport(analysis_scratchpad="payment reviewed", issues=[])

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    verdict = outcome.report.dispositions[0]
    assert verdict.status == "FALSE_POSITIVE"
    assert "authenticated server-side middleware" in verdict.reason


def test_unscoped_basket_lookup_is_confirmed_without_provider_evidence(tmp_path):
    source = tmp_path / "routes" / "order.ts"
    source.parent.mkdir(parents=True)
    source.write_text(
        "export function placeOrder () {\n"
        "  return (req, res) => {\n"
        "    const id = req.params.id\n"
        "    return BasketModel.findOne({ where: { id }, include: [ProductModel] })\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    finding = (
        "Finding #1:\n"
        "Rule ID: aegisscan.javascript.express-id-to-data-access\n"
        "File: routes/order.ts:4\n"
        "Message: request id reaches a model lookup\n"
        "Code Snippet: BasketModel.findOne({ where: { id } })\n"
    )
    incomplete = ReviewReport(
        analysis_scratchpad="provider omitted authorization evidence",
        issues=[],
        dispositions=[],
    )

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=incomplete):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert len(outcome.report.issues) == 1
    issue = outcome.report.issues[0]
    assert issue.issue_name == "Insecure Direct Object Reference (IDOR)"
    assert issue.confidence == "HIGH"
    assert issue.remediation_type == "MANUAL_REQUIRED"
    assert outcome.report.dispositions[0].status == "CONFIRMED"


def test_explicit_post_lookup_ownership_denial_prevents_deterministic_idor(tmp_path):
    source = tmp_path / "routes" / "basket.ts"
    source.parent.mkdir(parents=True)
    source.write_text(
        "const id = req.params.id\n"
        "const basket = await BasketModel.findOne({ where: { id } })\n"
        "if (basket.UserId !== authenticatedUser.id) {\n"
        "  return res.status(403).end()\n"
        "}\n"
        "res.json(basket)\n",
        encoding="utf-8",
    )
    finding = (
        "Finding #1:\n"
        "Rule ID: aegisscan.javascript.express-id-to-data-access\n"
        "File: routes/basket.ts:2\n"
        "Message: request id reaches a model lookup\n"
        "Code Snippet: BasketModel.findOne({ where: { id } })\n"
    )
    incomplete = ReviewReport(
        analysis_scratchpad="ownership guard requires contextual review",
        issues=[],
        dispositions=[],
    )

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=incomplete):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert outcome.report.issues == []
    assert outcome.report.dispositions[0].status == "NEEDS_REVIEW"


def test_direct_express_url_fetch_is_confirmed_without_provider_evidence(tmp_path):
    source = tmp_path / "routes" / "profileImageUrlUpload.ts"
    source.parent.mkdir(parents=True)
    source.write_text(
        "export function upload () {\n"
        "  return async (req, res) => {\n"
        "    const url = req.body.imageUrl\n"
        "    const response = await fetch(url)\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    finding = (
        "Finding #1:\n"
        "Rule ID: aegisscan.javascript.user-input-to-network-request\n"
        "File: routes/profileImageUrlUpload.ts:4\n"
        "Message: user-controlled URL reaches fetch\n"
        "Code Snippet: const response = await fetch(url)\n"
    )
    incomplete = ReviewReport(
        analysis_scratchpad="provider omitted SSRF evidence",
        issues=[],
        dispositions=[],
    )

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=incomplete):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert len(outcome.report.issues) == 1
    issue = outcome.report.issues[0]
    assert issue.issue_name == "Server-Side Request Forgery (SSRF)"
    assert issue.confidence == "HIGH"
    assert issue.remediation_type == "MANUAL_REQUIRED"
    assert outcome.report.dispositions[0].status == "CONFIRMED"


def test_destination_policy_prevents_deterministic_ssrf_confirmation(tmp_path):
    source = tmp_path / "routes" / "proxy.ts"
    source.parent.mkdir(parents=True)
    source.write_text(
        "const target = req.query.url\n"
        "const parsed = new URL(target)\n"
        "if (!allowedHosts.includes(parsed.hostname)) return res.status(403).end()\n"
        "const response = await fetch(target)\n",
        encoding="utf-8",
    )
    finding = (
        "Finding #1:\n"
        "Rule ID: aegisscan.javascript.user-input-to-network-request\n"
        "File: routes/proxy.ts:4\n"
        "Message: user-controlled URL reaches fetch\n"
        "Code Snippet: const response = await fetch(target)\n"
    )
    incomplete = ReviewReport(
        analysis_scratchpad="destination policy requires contextual review",
        issues=[],
        dispositions=[],
    )

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=incomplete):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert outcome.report.issues == []
    assert outcome.report.dispositions[0].status == "NEEDS_REVIEW"


def test_bypassable_redirect_guard_overrides_invalid_model_duplicate(tmp_path):
    route = tmp_path / "routes" / "redirect.ts"
    policy = tmp_path / "lib" / "insecurity.ts"
    route.parent.mkdir(parents=True)
    policy.parent.mkdir(parents=True)
    route.write_text(
        "import * as security from '../lib/insecurity'\n"
        "export function performRedirect () {\n"
        "  return ({ query }: Request, res: Response) => {\n"
        "    const toUrl: string = query.to as string\n"
        "    if (security.isRedirectAllowed(toUrl)) {\n"
        "      res.redirect(toUrl)\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    policy.write_text(
        "export const redirectAllowlist = new Set(['https://example.test'])\n"
        "export const isRedirectAllowed = (url: string) => {\n"
        "  let allowed = false\n"
        "  for (const allowedUrl of redirectAllowlist) {\n"
        "    allowed = allowed || url.includes(allowedUrl)\n"
        "  }\n"
        "  return allowed\n"
        "}\n",
        encoding="utf-8",
    )
    finding = (
        "Finding #1:\n"
        "Rule ID: aegisscan.javascript.express-open-redirect\n"
        "File: routes/redirect.ts:6\n"
        "Message: user-controlled URL reaches res.redirect\n"
        "Code Snippet: res.redirect(toUrl)\n"
    )
    finding_id = batch_findings([finding])[0].findings[0].finding_id
    invalid_duplicate = ReviewReport(
        analysis_scratchpad="invalid duplicate reference",
        issues=[],
        dispositions=[
            FindingDisposition(
                finding_id=finding_id,
                status="DUPLICATE",
                reason="Same redirect as an omitted candidate.",
                canonical_finding_id="SG-missing",
            )
        ],
    )

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch(
            "src.full_scan.call_gemini_with_failover",
            return_value=invalid_duplicate,
        ):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert len(outcome.report.issues) == 1
    issue = outcome.report.issues[0]
    assert issue.issue_name == "Open Redirect"
    assert "includes()" in issue.reachability_evidence
    assert outcome.report.dispositions[0].status == "CONFIRMED"
    assert outcome.report.dispositions[0].confidence == "HIGH"


def test_exact_redirect_allowlist_is_not_deterministically_downgraded(tmp_path):
    route = tmp_path / "routes" / "redirect.ts"
    route.parent.mkdir(parents=True)
    route.write_text(
        "const allowedUrls = new Set(['https://example.test/path'])\n"
        "function isRedirectAllowed (url: string) {\n"
        "  return allowedUrls.has(url)\n"
        "}\n"
        "export function performRedirect () {\n"
        "  return ({ query }: Request, res: Response) => {\n"
        "    const toUrl: string = query.to as string\n"
        "    if (isRedirectAllowed(toUrl)) {\n"
        "      res.redirect(toUrl)\n"
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    finding = (
        "Finding #1:\n"
        "Rule ID: aegisscan.javascript.express-open-redirect\n"
        "File: routes/redirect.ts:9\n"
        "Message: user-controlled URL reaches res.redirect\n"
        "Code Snippet: res.redirect(toUrl)\n"
    )
    incomplete = ReviewReport(
        analysis_scratchpad="exact allowlist requires no deterministic finding",
        issues=[],
        dispositions=[],
    )

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=incomplete):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert outcome.report.issues == []
    assert outcome.report.dispositions[0].status == "NEEDS_REVIEW"


def test_configured_local_file_xss_requires_attacker_write_evidence(tmp_path):
    source = tmp_path / "routes" / "videoHandler.ts"
    source.parent.mkdir(parents=True)
    source.write_text(
        "const subs = fs.readFileSync(config.get('promotion.subtitles'))\n"
        "compiledTemplate = compiledTemplate.replace(marker, subs)\n",
        encoding="utf-8",
    )
    finding = (
        "Finding #1:\n"
        "Rule ID: javascript.lang.security.audit.unknown-value-with-script-tag."
        "unknown-value-with-script-tag\n"
        "File: routes/videoHandler.ts:2\n"
        "Message: unknown value is inserted into a script tag\n"
        "Code Snippet: compiledTemplate = compiledTemplate.replace(marker, subs)\n"
    )
    candidate = batch_findings([finding])[0].findings[0]
    issue = ReviewIssue(
        file=candidate.file,
        line=2,
        severity="HIGH",
        issue_name="Cross-Site Scripting (XSS)",
        description="Subtitle content is inserted into script-capable markup.",
        original_code="compiledTemplate = compiledTemplate.replace(marker, subs)",
        suggested_fix="compiledTemplate = compiledTemplate.replace(marker, escapeHtml(subs))",
        finding_id=candidate.finding_id,
        rule_id=candidate.rule_id,
        confidence="HIGH",
        source_evidence="Config-controlled file path read by getSubsFromFile().",
        sink_evidence="replace inserts subs into the template.",
        reachability_evidence="The route reads the configured file and returns the template.",
    )
    report = ReviewReport(analysis_scratchpad="local file reviewed", issues=[issue])

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert outcome.report.issues == []
    verdict = outcome.report.dispositions[0]
    assert verdict.status == "NEEDS_REVIEW"
    assert "attacker can modify" in verdict.reason


def test_confirmed_sink_absorbs_same_location_needs_review_duplicate(tmp_path):
    source = tmp_path / "routes" / "redirect.ts"
    source.parent.mkdir(parents=True)
    source.write_text("res.redirect(toUrl)\n", encoding="utf-8")
    canonical = ReviewIssue(
        file="routes/redirect.ts",
        line=1,
        sink_file="routes/redirect.ts",
        sink_line=1,
        severity="HIGH",
        issue_name="Open Redirect",
        description="Request data reaches a redirect sink after a bypassable check.",
        original_code="res.redirect(toUrl)",
        suggested_fix="",
        finding_id="SG-registry",
        rule_id="javascript.express.security.audit.possible-user-input-redirect",
        confidence="HIGH",
        source_evidence="req.query.to supplies toUrl.",
        sink_evidence="res.redirect consumes toUrl.",
        reachability_evidence="The route invokes the redirect.",
        remediation_type="MANUAL_REQUIRED",
    )
    report = ReviewReport(
        analysis_scratchpad="redirect overlap",
        issues=[canonical],
        dispositions=[
            FindingDisposition(
                finding_id="SG-registry",
                status="CONFIRMED",
                reason="The redirect flow is confirmed.",
                file="routes/redirect.ts",
                line=1,
                rule_id=canonical.rule_id,
                message="Possible open redirect",
                code_role="RUNTIME",
                confidence="HIGH",
            ),
            FindingDisposition(
                finding_id="SG-bundled",
                status="NEEDS_REVIEW",
                reason="Invalid duplicate reference required repair.",
                file="routes/redirect.ts",
                line=1,
                rule_id="aegisscan.javascript.express-open-redirect",
                message="Potential open redirect",
                code_role="RUNTIME",
                confidence="LOW",
            ),
        ],
    )

    merged = _merge_reports([(1, report)], tmp_path)

    verdicts = {
        item.finding_id: (item.status, item.canonical_finding_id)
        for item in merged.dispositions
    }
    assert verdicts == {
        "SG-bundled": ("DUPLICATE", "SG-registry"),
        "SG-registry": ("CONFIRMED", ""),
    }


def test_placeholder_disposition_reason_is_replaced(tmp_path):
    (tmp_path / "app.py").write_text("dangerous(value)\n", encoding="utf-8")
    finding = _finding(1, "app.py")
    candidate = batch_findings([finding])[0].findings[0]
    report = ReviewReport(
        analysis_scratchpad="incomplete evidence",
        issues=[],
        dispositions=[
            FindingDisposition(
                finding_id=candidate.finding_id,
                status="NEEDS_REVIEW",
                reason="NEEDS_REVIEW",
            )
        ],
    )

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    verdict = outcome.report.dispositions[0]
    assert verdict.status == "NEEDS_REVIEW"
    assert verdict.reason != "NEEDS_REVIEW"
    assert "insufficient" in verdict.reason


@pytest.mark.parametrize(
    ("path", "expected_status"),
    [
        ("frontend/src/app/navbar/navbar.component.html", "FALSE_POSITIVE"),
        ("views/form.hbs", "NEEDS_REVIEW"),
    ],
)
def test_generic_unquoted_template_rule_uses_framework_semantics(
    tmp_path,
    path,
    expected_status,
):
    source = tmp_path / path
    source.parent.mkdir(parents=True)
    source.write_text('<img alt={{value}}>\n', encoding="utf-8")
    finding = _finding(1, path).replace(
        "test.rule",
        "generic.html-templates.security.unquoted-attribute-var.unquoted-attribute-var",
    )
    finding_id = batch_findings([finding])[0].findings[0].finding_id
    issue = ReviewIssue(
        file=path,
        line=1,
        sink_file=path,
        sink_line=1,
        severity="HIGH",
        issue_name="Cross-Site Scripting (XSS)",
        description="An unquoted template value permits attribute injection.",
        original_code="<img alt={{value}}>",
        suggested_fix='<img alt="{{value}}">',
        finding_id=finding_id,
        confidence="HIGH",
        source_evidence="The template value may be user-controlled.",
        sink_evidence="The value appears in an unquoted attribute.",
        reachability_evidence="The runtime renders this template.",
    )
    report = ReviewReport(
        analysis_scratchpad="template issue confirmed",
        issues=[issue],
        dispositions=[
            FindingDisposition(
                finding_id=finding_id,
                status="CONFIRMED",
                reason="The model treated generic template syntax as raw HTML substitution.",
            )
        ],
    )

    progress: list[str] = []
    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(
                str(tmp_path),
                "",
                client=MagicMock(),
                progress=progress.append,
            )

    assert outcome.report.issues == []
    assert outcome.disposition_count(expected_status) == 1
    if expected_status == "FALSE_POSITIVE":
        assert any("1 false positives" in event for event in progress)


def test_non_english_open_redirect_is_normalized_and_anchored_to_real_sink(tmp_path):
    path = "routes/redirect.ts"
    source = tmp_path / path
    source.parent.mkdir(parents=True)
    source.write_text(
        "\n".join(
            ["const value = 1"] * 16
            + [
                "challengeUtils.solveIf(challenge, () => isUnintendedRedirect(toUrl))",
                "res.redirect(toUrl)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    finding = _finding(1, path, 17).replace(
        "test.rule",
        "javascript.express.security.audit.possible-user-input-redirect",
    )
    finding_id = batch_findings([finding])[0].findings[0].finding_id
    issue = ReviewIssue(
        file=path,
        line=17,
        sink_file=path,
        sink_line=17,
        severity="HIGH",
        issue_name="开放重定向",
        description="用户控制的参数直接用于重定向。",
        original_code=(
            "challengeUtils.solveIf(challenge, () => isUnintendedRedirect(toUrl))"
        ),
        suggested_fix="",
        remediation_guidance="使用规范化网址白名单。",
        finding_id=finding_id,
        confidence="HIGH",
        source_evidence="请求参数控制目标。",
        sink_evidence="重定向位于 routes/redirect.ts:17。",
        reachability_evidence="请求处理程序调用重定向。",
        remediation_type="MANUAL_REQUIRED",
    )
    report = ReviewReport(
        analysis_scratchpad="确认开放重定向。",
        issues=[issue],
        dispositions=[
            FindingDisposition(
                finding_id=finding_id,
                status="CONFIRMED",
                reason="确认漏洞。",
            )
        ],
    )

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    normalized = outcome.report.issues[0]
    assert normalized.issue_name == "Open Redirect"
    assert normalized.line == 18
    assert normalized.sink_line == 18
    assert "routes/redirect.ts:18" in normalized.sink_evidence
    assert not re.search(r"[\u3400-\u9fff]", normalized.description)
    assert not re.search(r"[\u3400-\u9fff]", normalized.remediation_guidance)
    assert not re.search(r"[\u3400-\u9fff]", outcome.report.analysis_scratchpad)
    assert not re.search(r"[\u3400-\u9fff]", outcome.report.dispositions[0].reason)


def test_private_key_declaration_remains_primary_and_signing_use_is_related_sink(tmp_path):
    source = tmp_path / "security.ts"
    source.write_text(
        "const privateKey = embeddedKey\n"
        + "\n" * 8
        + "export const authorize = (user) => jwt.sign(user, privateKey)\n",
        encoding="utf-8",
    )
    finding = _finding(1, "security.ts", 1).replace(
        "test.rule",
        "aegisscan.javascript.hardcoded-private-key",
    )
    finding_id = batch_findings([finding])[0].findings[0].finding_id
    issue = ReviewIssue(
        file="security.ts",
        line=9,
        sink_file="security.ts",
        sink_line=9,
        severity="CRITICAL",
        issue_name="Hardcoded private key",
        description="An embedded private key is used to sign JWTs.",
        original_code="authorize(user, privateKey)",
        suggested_fix="",
        finding_id=finding_id,
        confidence="HIGH",
        source_evidence="The private key is embedded at security.ts:1.",
        sink_evidence="JWT signing uses the key at security.ts:9.",
        reachability_evidence="The exported authorization function signs tokens.",
        remediation_type="MANUAL_REQUIRED",
    )
    report = ReviewReport(analysis_scratchpad="credential use confirmed", issues=[issue])

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    anchored = outcome.report.issues[0]
    assert anchored.line == 1
    assert anchored.sink_line == 10
    assert "security.ts:10" in anchored.sink_evidence
    assert anchored.original_code == ""


def test_path_traversal_is_anchored_to_file_operation_not_preceding_check(tmp_path):
    source = tmp_path / "route.ts"
    source.write_text(
        "if (fs.existsSync(path)) {\n"
        "  const value = fs.readFileSync(path, 'utf8')\n"
        "}\n",
        encoding="utf-8",
    )
    finding = _finding(1, "route.ts", 1).replace(
        "test.rule",
        "aegisscan.javascript.express-path-traversal",
    )
    finding_id = batch_findings([finding])[0].findings[0].finding_id
    issue = ReviewIssue(
        file="route.ts",
        line=1,
        sink_file="route.ts",
        sink_line=1,
        severity="HIGH",
        issue_name="Path Traversal",
        description="A request-controlled path reaches a file read.",
        original_code="if (fs.existsSync(path)) {",
        suggested_fix="",
        finding_id=finding_id,
        confidence="HIGH",
        source_evidence="req.body.path controls path.",
        sink_evidence="The file operation is reported at route.ts:1.",
        reachability_evidence="The request handler reads the selected path.",
        remediation_type="MANUAL_REQUIRED",
    )
    report = ReviewReport(analysis_scratchpad="path flow confirmed", issues=[issue])

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    anchored = outcome.report.issues[0]
    assert anchored.line == 2
    assert anchored.sink_line == 2
    assert "route.ts:2" in anchored.sink_evidence


def test_confirmed_toctou_without_mutation_surface_is_downgraded(tmp_path):
    source = tmp_path / "app.ts"
    source.write_text(
        "const path = req.body.path\n"
        "if (fs.existsSync(path)) {\n"
        "  fs.readFileSync(path)\n"
        "}\n",
        encoding="utf-8",
    )
    finding = _finding(1, "app.ts", 2).replace(
        "test.rule",
        "aegisscan.javascript.filesystem-check-then-use",
    )
    finding_id = batch_findings([finding])[0].findings[0].finding_id
    issue = ReviewIssue(
        file="app.ts",
        line=2,
        sink_file="app.ts",
        sink_line=2,
        severity="HIGH",
        issue_name="TOCTOU",
        description="The file could be replaced between the check and read.",
        original_code="if (fs.existsSync(path)) {",
        suggested_fix="",
        finding_id=finding_id,
        confidence="HIGH",
        source_evidence="req.body.path controls the selected path.",
        sink_evidence="fs.readFileSync uses the checked path.",
        reachability_evidence="The model asserts that an attacker can replace the file.",
        remediation_type="MANUAL_REQUIRED",
    )
    report = ReviewReport(analysis_scratchpad="race confirmed", issues=[issue])

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert outcome.report.issues == []
    assert outcome.disposition_count("NEEDS_REVIEW") == 1
    assert "does not prove" in outcome.report.dispositions[0].reason


def test_toctou_confirmation_is_retained_with_concrete_mutation_surface(tmp_path):
    source = tmp_path / "app.ts"
    source.write_text(
        "const path = req.body.path\n"
        "fs.renameSync(req.body.replacement, path)\n"
        "if (fs.existsSync(path)) {\n"
        "  fs.readFileSync(path)\n"
        "}\n",
        encoding="utf-8",
    )
    finding = _finding(1, "app.ts", 3).replace(
        "test.rule",
        "aegisscan.javascript.filesystem-check-then-use",
    )
    finding_id = batch_findings([finding])[0].findings[0].finding_id
    issue = ReviewIssue(
        file="app.ts",
        line=3,
        sink_file="app.ts",
        sink_line=3,
        severity="HIGH",
        issue_name="TOCTOU",
        description="A user-controlled rename surface can race the check and read.",
        original_code="if (fs.existsSync(path)) {",
        suggested_fix="",
        finding_id=finding_id,
        confidence="HIGH",
        source_evidence="req.body.replacement controls the source of fs.renameSync.",
        sink_evidence="fs.readFileSync uses the checked path.",
        reachability_evidence="The route exposes rename and read operations on the same path.",
        remediation_type="MANUAL_REQUIRED",
    )
    report = ReviewReport(analysis_scratchpad="mutation surface confirmed", issues=[issue])

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert len(outcome.report.issues) == 1
    assert outcome.disposition_count("CONFIRMED") == 1


def test_unconfirmed_toctou_candidate_is_retained_for_review(tmp_path):
    source = tmp_path / "app.ts"
    source.write_text(
        "if (fs.existsSync(path)) {\n  fs.readFileSync(path)\n}\n",
        encoding="utf-8",
    )
    finding = _finding(1, "app.ts", 1).replace(
        "test.rule",
        "aegisscan.javascript.filesystem-check-then-use",
    )
    finding_id = batch_findings([finding])[0].findings[0].finding_id
    report = ReviewReport(
        analysis_scratchpad="race prerequisites not established",
        issues=[],
        dispositions=[
            FindingDisposition(
                finding_id=finding_id,
                status="FALSE_POSITIVE",
                reason="Filesystem mutation was not proven.",
            )
        ],
    )

    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        with patch("src.full_scan.call_gemini_with_failover", return_value=report):
            outcome = run_full_scan(str(tmp_path), "", client=MagicMock())

    assert outcome.report.issues == []
    assert outcome.disposition_count("NEEDS_REVIEW") == 1
    assert "check-then-use" in outcome.report.dispositions[0].reason


def test_distinct_openwrt_advisories_at_same_recipe_line_remain_separate(tmp_path):
    recipe = tmp_path / "package/libs/ustream-ssl/Makefile"
    recipe.parent.mkdir(parents=True)
    recipe.write_text("define Package/libustream-mbedtls\n", encoding="utf-8")
    first = ReviewIssue(
        file="package/libs/ustream-ssl/Makefile",
        line=1,
        sink_file="package/libs/ustream-ssl/Makefile",
        sink_line=1,
        severity="HIGH",
        issue_name="Selected OpenWrt component affected by CVE-2019-5101",
        description="The selected release is affected by CVE-2019-5101.",
        original_code="CONFIG_PACKAGE_libustream-mbedtls=y",
        suggested_fix="",
        finding_id="FW-cve-2019-5101",
        rule_id="aegisscan.openwrt.advisory.cve-2019-5101",
        confidence="HIGH",
        source_evidence="The build profile selects libustream-mbedtls.",
        sink_evidence="The official affected release range matches.",
        reachability_evidence="The component is included in the firmware image.",
        remediation_type="MANUAL_REQUIRED",
    )
    second = first.model_copy(
        update={
            "issue_name": "Selected OpenWrt component affected by CVE-2019-5102",
            "description": "The selected release is affected by CVE-2019-5102.",
            "finding_id": "FW-cve-2019-5102",
            "rule_id": "aegisscan.openwrt.advisory.cve-2019-5102",
        }
    )
    dispositions = [
        FindingDisposition(
            finding_id=issue.finding_id,
            status="CONFIRMED",
            reason="The selected package and release range match the advisory.",
            file=issue.file,
            line=issue.line,
            rule_id=issue.rule_id,
            message=issue.issue_name,
            code_role="RUNTIME",
            confidence="HIGH",
        )
        for issue in (first, second)
    ]

    merged = _merge_reports(
        [
            (
                1,
                ReviewReport(
                    analysis_scratchpad="matched official advisories",
                    issues=[first, second],
                    dispositions=dispositions,
                ),
            )
        ],
        tmp_path,
    )

    assert {issue.finding_id for issue in merged.issues} == {
        "FW-cve-2019-5101",
        "FW-cve-2019-5102",
    }
    assert all(item.status == "CONFIRMED" for item in merged.dispositions)


@pytest.mark.parametrize("options", [{"apply_fixes": True}, {"create_pull_request": True}])
def test_paused_mutation_modes_fail_before_scanning(tmp_path, options):
    with patch("src.full_scan.run_semgrep_scan") as scanner:
        with pytest.raises(ValueError, match="paused until vetted"):
            run_full_scan(str(tmp_path), "", ai_triage=False, **options)
        scanner.assert_not_called()


@pytest.mark.parametrize("flag", ["--apply-fixes", "--create-pull-request"])
def test_cli_explains_paused_mutation_modes(tmp_path, monkeypatch, caplog, flag):
    from src.full_scan import main

    report = tmp_path / "report.json"
    monkeypatch.setattr("sys.argv", [
        "aegisscan", "--repo", str(tmp_path), "--detector-only",
        "--report", str(report), flag,
    ])
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 1
    assert "paused until vetted" in caplog.text
    assert not report.exists()


def test_ai_cannot_hide_runtime_finding_as_non_runtime(tmp_path):
    from src.full_scan import SemgrepCandidate, FindingBatch, _reconcile_batch_report
    source = tmp_path / 'app.java'
    source.write_text('networkCall(input);\n')
    candidate = SemgrepCandidate(finding_id='SG-1', rule_id='aegisscan.java.user-input-to-network-request',
        file='app.java', line=1, message='SSRF', code_role='RUNTIME', raw_text='')
    report = ReviewReport(analysis_scratchpad='', issues=[], dispositions=[
        FindingDisposition(finding_id='SG-1', status='NON_RUNTIME', reason='Training application')])
    reconciled = _reconcile_batch_report(report, FindingBatch(findings=[candidate], files={'app.java'}), tmp_path)
    assert reconciled.dispositions[0].status == 'NEEDS_REVIEW'


@pytest.mark.parametrize('middle,query,confirmed', [
    ("criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)\n", 'models.sequelize.query(`SELECT * FROM Products WHERE name = \'${criteria}\'`)', True),
    ('', 'models.sequelize.query(`SELECT * FROM Products WHERE name = \'${criteria}\'`)', True),
    ('criteria = escapeSql(criteria)\n', 'models.sequelize.query(`SELECT * FROM Products WHERE name = \'${criteria}\'`)', False),
    ('', 'models.sequelize.query("SELECT * FROM Products WHERE name = ?", {replacements: [criteria]})', False),
])
def test_deterministic_sql_requires_proven_adjacent_unescaped_flow(tmp_path, middle, query, confirmed):
    from src.full_scan import SemgrepCandidate, _deterministic_sequelize_template_issue
    text = "let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''\n" + middle + query + '\n'
    (tmp_path / 'app.ts').write_text(text)
    candidate = SemgrepCandidate(finding_id='SG-1', rule_id='aegisscan.javascript.express-sequelize-taint-sqli',
        file='app.ts', line=len(text.splitlines()), message='SQL injection', code_role='RUNTIME', raw_text='')
    issue = _deterministic_sequelize_template_issue(tmp_path, candidate)
    assert (issue is not None) == confirmed
    if issue:
        assert issue.remediation_type == 'MANUAL_REQUIRED'
