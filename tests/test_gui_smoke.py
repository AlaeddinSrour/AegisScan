import os
import json

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QPoint, QSettings
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from src.gui import AegisScanWindow
from src.full_scan import ScanOutcome
from src.models import FindingDisposition, ReviewReport


def test_main_window_builds_with_isolated_settings(tmp_path):
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, str(tmp_path))
    application = QApplication.instance() or QApplication([])
    window = AegisScanWindow()

    assert window.windowTitle() == "AegisScan"
    assert "dashboard" in window.page_indexes
    assert window.new_scan.api_key_input.echoMode().name == "Password"
    assert window.new_scan.audit_mode.currentData() == "bundled"
    window.set_semgrep_rule_mode("extended")
    assert window.new_scan.audit_mode.currentData() == "extended"
    assert window.app_settings.rule_mode.currentData() == "extended"

    window.close()
    application.processEvents()


def test_desktop_can_export_sarif(tmp_path, monkeypatch):
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, str(tmp_path))
    application = QApplication.instance() or QApplication([])
    window = AegisScanWindow()
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
    assert payload["runs"][0]["invocations"][0]["properties"][
        "semgrepRuleMode"
    ] == "bundled"
    window.close()
    application.processEvents()


def test_new_audit_controls_do_not_overlap_at_minimum_window_size(tmp_path):
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, str(tmp_path))
    application = QApplication.instance() or QApplication([])
    window = AegisScanWindow()
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
        page.options_panel,
        page.limits_panel,
        page.dependency_scan,
        page.secret_scan,
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


def test_degraded_scan_opens_manual_review_without_failure_dialog(tmp_path):
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, str(tmp_path))
    application = QApplication.instance() or QApplication([])
    window = AegisScanWindow()
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
