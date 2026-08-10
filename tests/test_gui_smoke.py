import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QSettings
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

    assert window.global_status.text.text() == "AI triage incomplete"
    assert window.stack.currentIndex() == window.page_indexes["review_queue"]
    assert window.dashboard.security_ring.caption == "INCOMPLETE"
    assert not window.dashboard.security_ring.has_score

    window.close()
    application.processEvents()
