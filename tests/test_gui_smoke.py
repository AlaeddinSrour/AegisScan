import os
import json

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QPoint, QSettings
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from src.gui import AegisScanWindow, ScanWorker
from src.full_scan import ScanOutcome
from src.models import FindingDisposition, ReviewReport


def _test_settings(tmp_path):
    return QSettings(str(tmp_path / "aegisscan-test.ini"), QSettings.Format.IniFormat)


def test_main_window_builds_with_isolated_settings(tmp_path):
    application = QApplication.instance() or QApplication([])
    window = AegisScanWindow(_test_settings(tmp_path))

    assert window.windowTitle() == "AegisScan"
    assert "dashboard" in window.page_indexes
    assert "readiness" in window.page_indexes
    assert window.new_scan.api_key_input.echoMode().name == "Password"
    assert window.new_scan.openrouter_api_key_input.echoMode().name == "Password"
    assert window.new_scan.ai_provider.currentData() == "auto"
    assert window.new_scan.audit_mode.currentData() == "bundled"
    window.set_semgrep_rule_mode("extended")
    assert window.new_scan.audit_mode.currentData() == "extended"
    assert window.app_settings.rule_mode.currentData() == "extended"
    window.set_ai_triage(False)
    assert not window.new_scan.api_key_input.isEnabled()
    assert not window.new_scan.openrouter_api_key_input.isEnabled()
    assert not window.new_scan.batch_size.isEnabled()
    assert not window.app_settings.api_key.isEnabled()
    assert not window.app_settings.openrouter_api_key.isEnabled()
    assert "detector-only" in window.new_scan.launch_button.text().lower()

    window.close()
    application.processEvents()


def test_desktop_can_export_sarif(tmp_path, monkeypatch):
    application = QApplication.instance() or QApplication([])
    window = AegisScanWindow(_test_settings(tmp_path))
    window.outcome = ScanOutcome(
        report=ReviewReport(analysis_scratchpad="clean", issues=[]),
        raw_finding_count=0,
        batch_count=0,
        semgrep_rule_mode="bundled",
        semgrep_rules_sha256="b" * 64,
    )
    destination = tmp_path / "desktop-export.sarif"
    monkeypatch.setattr(
        "src.gui.QFileDialog.getSaveFileName",
        lambda *_args, **_kwargs: (str(destination), "SARIF report (*.sarif)"),
    )

    window.export_report()

    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["invocations"][0]["properties"]["semgrepRuleMode"] == "bundled"
    window.close()
    application.processEvents()


def test_new_audit_controls_do_not_overlap_at_minimum_window_size(tmp_path):
    application = QApplication.instance() or QApplication([])
    window = AegisScanWindow(_test_settings(tmp_path))
    window.resize(window.minimumSize())
    window.navigate("new_scan")
    window.show()
    QTest.qWait(250)

    page = window.new_scan
    assert page.isVisible()
    assert page.scroll_content.isVisible()
    assert page.config_card.isVisible()

    def vertical_bounds(widget):
        top = widget.mapTo(page.scroll_content, QPoint(0, 0)).y()
        return top, top + widget.height()

    ordered_rows = [
        page.ai_triage,
        page.ai_provider_label,
        page.ai_provider,
        page.api_key_label,
        page.api_key_input,
        page.openrouter_api_key_label,
        page.openrouter_api_key_input,
        page.ai_privacy_note,
        page.options_panel,
        page.limits_panel,
        page.dependency_scan,
        page.secret_scan,
        page.readiness_button,
        page.apply_fixes,
        page.publish_pr,
        page.launch_button,
    ]
    for first, second in zip(ordered_rows, ordered_rows[1:]):
        assert vertical_bounds(first)[1] <= vertical_bounds(second)[0]

    for field_label, control in (
        (page.batch_size_label, page.batch_size),
        (page.audit_mode_label, page.audit_mode),
        (page.max_target_label, page.max_target_mb),
        (page.exclusions_label, page.exclusions),
    ):
        assert vertical_bounds(field_label)[1] <= vertical_bounds(control)[0]

    assert page.scroll_area.verticalScrollBar().maximum() > 0

    window.close()
    application.processEvents()


def test_scan_worker_passes_detector_only_setting(monkeypatch):
    application = QApplication.instance() or QApplication([])
    outcome = ScanOutcome(
        report=ReviewReport(analysis_scratchpad="detectors only", issues=[]),
        raw_finding_count=0,
        batch_count=0,
        ai_triage_enabled=False,
    )
    calls = []
    monkeypatch.setattr(
        "src.gui.run_full_scan",
        lambda *args, **kwargs: calls.append((args, kwargs)) or outcome,
    )
    worker = ScanWorker(
        {
            "repo_path": "/repo",
            "gemini_api_key": "",
            "openrouter_api_key": "",
            "ai_provider": "auto",
            "batch_size": 10,
            "apply_fixes": False,
            "create_pull_request": False,
            "github_token": "",
            "repository": "",
            "dependency_scan": True,
            "secret_scan": True,
            "exclude_patterns": [".git"],
            "max_target_bytes": 1_000_000,
            "semgrep_rule_mode": "bundled",
            "ai_triage": False,
        }
    )
    completed = []
    worker.completed.connect(completed.append)

    worker.run()

    assert calls[0][1]["ai_triage"] is False
    assert completed == [outcome]
    application.processEvents()


def test_detector_only_result_is_saved_and_opens_review_queue(tmp_path):
    application = QApplication.instance() or QApplication([])
    window = AegisScanWindow(_test_settings(tmp_path))
    window.set_repository(str(tmp_path))
    outcome = ScanOutcome(
        report=ReviewReport(
            analysis_scratchpad="Local detector candidate",
            issues=[],
            dispositions=[
                FindingDisposition(
                    finding_id="SG-review",
                    status="NEEDS_REVIEW",
                    reason="AI triage intentionally disabled.",
                    file="src/app.py",
                    line=4,
                    rule_id="test.rule",
                )
            ],
        ),
        raw_finding_count=1,
        batch_count=1,
        ai_triage_enabled=False,
    )

    window._scan_completed(outcome)

    assert window.stack.currentIndex() == window.page_indexes["review_queue"]
    assert window.dashboard.security_ring.caption == "REVIEW QUEUE"
    assert window.history[-1]["audit_mode"] == "Detector only"
    assert window.history[-1]["comparison"]["new"] == 1
    assert window.settings.value("audit_history")

    window.close()
    application.processEvents()
    restored = AegisScanWindow(_test_settings(tmp_path))
    assert restored.history[-1]["audit_mode"] == "Detector only"
    assert restored.history[-1]["comparison"]["new"] == 1
    restored.close()
    application.processEvents()


def test_completed_dirty_repository_is_prominently_marked(tmp_path):
    application = QApplication.instance() or QApplication([])
    window = AegisScanWindow(_test_settings(tmp_path))
    outcome = ScanOutcome(
        report=ReviewReport(analysis_scratchpad="complete", issues=[]),
        raw_finding_count=0,
        batch_count=0,
        repository_dirty=True,
    )

    window._scan_completed(outcome)

    assert "dirty tree" in window.global_status.text.text().casefold()
    assert "cannot be reproduced" in window.new_scan.console.toPlainText()
    window.close()
    application.processEvents()


def test_degraded_scan_opens_manual_review_without_failure_dialog(tmp_path):
    application = QApplication.instance() or QApplication([])
    window = AegisScanWindow(_test_settings(tmp_path))
    outcome = ScanOutcome(
        report=ReviewReport(
            analysis_scratchpad="AI unavailable",
            issues=[],
            dispositions=[
                FindingDisposition(
                    finding_id="SG-test",
                    status="NEEDS_REVIEW",
                    reason="AI triage failed; manual review required.",
                    file="app.py",
                    line=1,
                    rule_id="test.rule",
                    code_role="RUNTIME",
                )
            ],
        ),
        raw_finding_count=1,
        batch_count=1,
        failed_batches=[1],
        failed_batch_reasons={1: "invalid API key"},
        ai_attempted_batches=1,
        ai_successful_batches=0,
    )

    window._scan_completed(outcome)

    assert window.global_status.text.text() == "Audit incomplete"
    assert window.stack.currentIndex() == window.page_indexes["review_queue"]
    assert window.dashboard.security_ring.caption == "INCOMPLETE"
    assert not window.dashboard.security_ring.has_score

    window.close()
    application.processEvents()


def test_dependency_coverage_gap_is_visible_on_dashboard(tmp_path):
    application = QApplication.instance() or QApplication([])
    window = AegisScanWindow(_test_settings(tmp_path))
    outcome = ScanOutcome(
        report=ReviewReport(analysis_scratchpad="Dependency inventory incomplete", issues=[]),
        raw_finding_count=0,
        batch_count=0,
        detector_coverage_gaps={
            "osv": ["package.json has no supported lockfile or resolved inventory."]
        },
        detector_telemetry={
            "osv": {
                "manifests_discovered": 1,
                "packages_in_local_inventory": 0,
                "packages_queried": 42,
                "raw_unique_advisories": 7,
                "exported_unique_advisories": 5,
                "exported_dependency_findings": 6,
                "exported_affected_packages": [
                    {"package": "library", "unique_advisories": 5, "findings": 6}
                ],
            }
        },
    )

    window.outcome = outcome
    window.dashboard.refresh()

    assert outcome.audit_degraded
    assert window.dashboard.security_ring.caption == "INCOMPLETE"
    assert "incomplete" in window.dashboard.dependency_status.text().lower()
    assert "library: 5 advisories, 6 findings" in (window.dashboard.dependency_status.toolTip())

    window.close()
    application.processEvents()


def test_dashboard_groups_dependencies_and_shows_ai_retriage_quality(tmp_path):
    application = QApplication.instance() or QApplication([])
    window = AegisScanWindow(_test_settings(tmp_path))
    outcome = ScanOutcome(
        report=ReviewReport(analysis_scratchpad="Complete audit", issues=[]),
        raw_finding_count=0,
        batch_count=1,
        ai_attempted_batches=1,
        ai_successful_batches=1,
        ai_provider_order=["openrouter"],
        ai_telemetry={
            "request_attempts": 4,
            "semantic_defects_repaired": 2,
            "targeted_retriage_attempts": 2,
            "targeted_retriage_recovered": 1,
            "targeted_retriage_unresolved": 1,
        },
        detector_telemetry={
            "osv": {
                "exported_unique_advisories": 7,
                "exported_dependency_findings": 9,
                "exported_affected_packages": [
                    {"package": "library-a", "unique_advisories": 5, "findings": 6},
                    {"package": "library-b", "unique_advisories": 2, "findings": 3},
                ],
            }
        },
    )

    window.outcome = outcome
    window.dashboard.refresh()

    assert "2 affected packages" in window.dashboard.dependency_status.text()
    assert "7 advisories" in window.dashboard.dependency_status.text()
    assert "strict re-triage 1/2 recovered" in window.dashboard.ai_status.text()
    assert "Still needs review: 1" in window.dashboard.ai_status.toolTip()

    window.close()
    application.processEvents()


def test_large_evidence_ledgers_are_lazy_and_paginated(tmp_path):
    application = QApplication.instance() or QApplication([])
    window = AegisScanWindow(_test_settings(tmp_path))
    review_items = [
        FindingDisposition(
            finding_id=f"SG-review-{index}",
            status="NEEDS_REVIEW",
            reason="Manual review required.",
            file=f"src/review_{index}.py",
            line=index + 1,
            rule_id="test.review",
        )
        for index in range(601)
    ]
    non_runtime_items = [
        FindingDisposition(
            finding_id=f"SG-non-runtime-{index}",
            status="NON_RUNTIME",
            reason="Fixture source.",
            file=f"tests/fixture_{index}.py",
            line=index + 1,
            rule_id="test.fixture",
        )
        for index in range(601)
    ]
    outcome = ScanOutcome(
        report=ReviewReport(
            analysis_scratchpad="Large report",
            issues=[],
            dispositions=review_items + non_runtime_items,
        ),
        raw_finding_count=1_202,
        batch_count=1,
        ai_triage_enabled=False,
    )

    window._scan_completed(outcome)

    assert window.stack.currentIndex() == window.page_indexes["review_queue"]
    assert len(window.review_queue.filtered_dispositions) == 601
    assert window.review_queue.table.rowCount() == 250
    assert window.review_queue.page_status.text() == "Showing 1–250 of 601 candidates"
    assert window.non_runtime.table.rowCount() == 0

    window.review_queue.next_page.click()
    assert window.review_queue.table.rowCount() == 250
    assert window.review_queue.visible_dispositions[0].finding_id == "SG-review-250"
    assert window.review_queue.page_status.text() == "Showing 251–500 of 601 candidates"

    window.review_queue.search.setText("SG-review-600")
    assert window.review_queue.page_index == 0
    assert window.review_queue.table.rowCount() == 1
    assert window.review_queue.visible_dispositions[0].finding_id == "SG-review-600"

    window.navigate("non_runtime")
    assert len(window.non_runtime.filtered_dispositions) == 601
    assert window.non_runtime.table.rowCount() == 250

    window.close()
    application.processEvents()
