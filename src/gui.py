"""Modern PySide6 desktop interface for AegisScan."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Callable

from PySide6.QtCore import (
    QObject,
    Property,
    QEasingCurve,
    QPropertyAnimation,
    QRect,
    QSettings,
    QSize,
    Qt,
    QThread,
    QTimer,
    Signal,
    Slot,
)
from PySide6.QtGui import (
    QAction,
    QColor,
    QFontMetrics,
    QKeySequence,
    QPainter,
    QPen,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGraphicsOpacityEffect,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from . import __version__
from .full_scan import ScanOutcome, run_full_scan
from .github_ops import apply_auto_fixes_with_paths, auto_fix_eligibility
from .models import FindingDisposition, ReviewIssue


APP_STYLE = """
* {
    font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    color: #3d3d3a;
}
QMainWindow, QWidget#AppRoot, QWidget#Canvas { background: #faf9f5; }
QFrame#Sidebar {
    background: #f5f0e8;
    border: 0;
    border-right: 1px solid #e6dfd8;
}
QFrame#Topbar {
    background: #faf9f5;
    border: 0;
    border-bottom: 1px solid #e6dfd8;
}
QFrame[card="true"] {
    background: #faf9f5;
    border: 1px solid #e6dfd8;
    border-radius: 12px;
}
QFrame[softCard="true"] {
    background: #efe9de;
    border: 0;
    border-radius: 12px;
}
QLabel#Brand {
    color: #141413;
    font-family: Inter, -apple-system, sans-serif;
    font-size: 20px;
    font-weight: 600;
}
QLabel#BrandMark {
    background: transparent;
    border: 0;
    color: #141413;
    font-family: Georgia, "Times New Roman", serif;
    font-size: 26px;
    font-weight: 400;
}
QLabel#Eyebrow {
    color: #6c6a64;
    font-family: Inter, -apple-system, sans-serif;
    font-size: 11px;
    font-weight: 500;
}
QLabel#PageTitle {
    color: #141413;
    font-family: "Iowan Old Style", Georgia, "Times New Roman", serif;
    font-size: 34px;
    font-weight: 400;
}
QLabel#PageSubtitle {
    color: #6c6a64;
    font-size: 14px;
}
QLabel#SectionTitle {
    color: #252523;
    font-size: 16px;
    font-weight: 500;
}
QLabel#HeroTitle {
    color: #141413;
    font-family: "Iowan Old Style", Georgia, "Times New Roman", serif;
    font-size: 39px;
    font-weight: 400;
}
QLabel#HeroKicker {
    color: #8b4651;
    font-size: 11px;
    font-weight: 500;
}
QLabel#Muted, QLabel#MetricLabel { color: #6c6a64; font-size: 12px; }
QLabel#MetricValue {
    color: #141413;
    font-family: "Iowan Old Style", Georgia, "Times New Roman", serif;
    font-size: 32px;
    font-weight: 400;
}
QLabel#Good { color: #5db872; font-weight: 500; }
QLabel#Warning { color: #d4a017; font-weight: 500; }
QLabel#Danger { color: #c64545; font-weight: 500; }
QLabel#Accent { color: #8b4651; font-weight: 500; }
QLabel[pill="true"] {
    background: #faf9f5;
    border: 1px solid #e6dfd8;
    border-radius: 8px;
    color: #3d3d3a;
    padding: 8px 12px;
}
QPushButton {
    background: #faf9f5;
    border: 1px solid #e6dfd8;
    border-radius: 8px;
    padding: 10px 16px;
    color: #141413;
    font-size: 13px;
    font-weight: 500;
}
QPushButton:pressed { background: #efe9de; }
QPushButton:disabled { color: #8e8b82; background: #e6dfd8; border-color: #e6dfd8; }
QPushButton[primary="true"] {
    background: #8b4651;
    border: 1px solid #8b4651;
    color: #ffffff;
    padding: 11px 18px;
}
QPushButton[primary="true"]:pressed { background: #6f3540; border-color: #6f3540; }
QPushButton[nav="true"] {
    background: transparent;
    border: 0;
    border-radius: 8px;
    color: #6c6a64;
    text-align: left;
    padding: 9px 11px;
    font-size: 13px;
    font-weight: 500;
}
QPushButton[nav="true"][active="true"] { background: #e8e0d2; color: #141413; }
QToolButton[section="true"] {
    background: transparent;
    border: 0;
    color: #8e8b82;
    text-align: left;
    padding: 11px 7px 6px 7px;
    font-size: 10px;
    font-weight: 500;
}
QLineEdit, QSpinBox, QComboBox {
    background: #faf9f5;
    border: 1px solid #e6dfd8;
    border-radius: 8px;
    padding: 9px 12px;
    color: #141413;
    selection-background-color: #8b4651;
    min-height: 20px;
}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border: 2px solid #8b4651; }
QComboBox::drop-down { border: 0; width: 28px; }
QComboBox QAbstractItemView {
    background: #faf9f5;
    border: 1px solid #e6dfd8;
    selection-background-color: #efe9de;
    selection-color: #141413;
}
QCheckBox { color: #3d3d3a; spacing: 8px; }
QCheckBox::indicator {
    width: 17px; height: 17px; border-radius: 4px;
    border: 1px solid #e6dfd8; background: #faf9f5;
}
QCheckBox::indicator:checked { background: #8b4651; border-color: #8b4651; }
QProgressBar {
    background: #e6dfd8; border: 0; border-radius: 3px; height: 6px; text-align: center;
}
QProgressBar::chunk { background: #8b4651; border-radius: 3px; }
QTableWidget {
    background: #faf9f5;
    alternate-background-color: #f5f0e8;
    border: 1px solid #e6dfd8;
    border-radius: 12px;
    gridline-color: transparent;
    selection-background-color: #efe9de;
    selection-color: #141413;
    outline: 0;
}
QHeaderView::section {
    background: #f5f0e8;
    color: #6c6a64;
    border: 0;
    border-bottom: 1px solid #e6dfd8;
    padding: 10px;
    font-size: 11px;
    font-weight: 500;
}
QTableWidget::item { padding: 9px; border-bottom: 1px solid #ebe6df; }
QPlainTextEdit, QTextEdit {
    background: #181715;
    border: 0;
    border-radius: 12px;
    padding: 14px;
    color: #faf9f5;
    selection-background-color: #6f3540;
    font-family: "JetBrains Mono", "SF Mono", Menlo, monospace;
    font-size: 11px;
}
QScrollArea { border: 0; background: transparent; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #d8d0c4; min-height: 30px; border-radius: 5px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QSplitter::handle { background: #e6dfd8; width: 1px; }
QMenuBar { background: #faf9f5; color: #3d3d3a; border-bottom: 1px solid #e6dfd8; }
QMenuBar::item:selected { background: #efe9de; border-radius: 6px; }
QMenu { background: #faf9f5; border: 1px solid #e6dfd8; padding: 6px; }
QMenu::item { padding: 7px 28px 7px 12px; border-radius: 6px; }
QMenu::item:selected { background: #efe9de; color: #141413; }
QMessageBox {
    background-color: #faf9f5;
}
QMessageBox QLabel {
    background: transparent;
    color: #252523;
    font-size: 13px;
}
QMessageBox QPushButton {
    background: #faf9f5;
    border: 1px solid #d8d0c4;
    color: #141413;
    min-width: 100px;
    padding: 6px 12px;
}
QMessageBox QPushButton:hover { background: #efe9de; }
QMessageBox QPushButton:pressed { background: #e8e0d2; }
QMessageBox QTextEdit {
    background: #181715;
    color: #faf9f5;
    border: 0;
}
"""


SEVERITY_COLORS = {
    "CRITICAL": "#c64545",
    "HIGH": "#8b4651",
    "WARNING": "#d4a017",
    "INFO": "#5db8a6",
}


def card(soft: bool = False) -> QFrame:
    frame = QFrame()
    frame.setProperty("softCard" if soft else "card", True)
    return frame


def label(text: str, object_name: str = "") -> QLabel:
    widget = QLabel(text)
    if object_name:
        widget.setObjectName(object_name)
    widget.setWordWrap(True)
    return widget


def primary_button(text: str, callback: Callable[[], None]) -> QPushButton:
    button = QPushButton(text)
    button.setProperty("primary", True)
    button.clicked.connect(callback)
    return button


def pipeline_step(number: str, title: str, description: str) -> QFrame:
    item = card(soft=True)
    item_layout = QVBoxLayout(item)
    item_layout.setContentsMargins(13, 12, 13, 12)
    item_layout.setSpacing(4)
    item_layout.addWidget(label(number, "Accent"))
    item_layout.addWidget(label(title, "SectionTitle"))
    item_layout.addWidget(label(description, "Muted"))
    return item


class ScanStage(QFrame):
    def __init__(self, number: str, title: str, description: str) -> None:
        super().__init__()
        self.setProperty("softCard", True)
        self.step_number = number
        self.number = QLabel(number)
        self.number.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.number.setFixedSize(28, 28)
        content = QVBoxLayout()
        content.setSpacing(1)
        content.addWidget(label(title, "SectionTitle"))
        content.addWidget(label(description, "Muted"))
        row = QHBoxLayout(self)
        row.setContentsMargins(12, 9, 12, 9)
        row.setSpacing(10)
        row.addWidget(self.number)
        row.addLayout(content, 1)
        self.set_state("pending")

    def set_state(self, state: str) -> None:
        styles = {
            "pending": ("#faf9f5", "#6c6a64", "#e6dfd8"),
            "active": ("#8b4651", "#ffffff", "#8b4651"),
            "done": ("#5db872", "#ffffff", "#5db872"),
        }
        background, foreground, border = styles[state]
        self.number.setText("✓" if state == "done" else self.step_number)
        self.number.setStyleSheet(
            f"background: {background}; color: {foreground}; border: 1px solid {border}; "
            "border-radius: 14px; font-family: Inter; font-weight: 500;"
        )


def elevate(widget: QWidget, blur: int = 28, opacity: int = 85) -> None:
    # The interface uses color-block elevation and reserves shadows for rare hover states.
    return


class HeroPanel(QFrame):
    """Warm editorial hero surface for the dashboard."""

    def __init__(self) -> None:
        super().__init__()
        self.setMinimumHeight(232)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

    def paintEvent(self, event: object) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(0, 0, -1, -1)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#efe9de"))
        painter.drawRoundedRect(rect, 16, 16)
        painter.end()
        super().paintEvent(event)  # type: ignore[arg-type]


class SecurityRing(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.score = 0
        self._display_score = 0.0
        self.has_score = False
        self.caption = "NOT SCANNED"
        self.setFixedSize(158, 158)
        self.score_animation = QPropertyAnimation(self, b"displayScore", self)
        self.score_animation.setDuration(720)
        self.score_animation.setEasingCurve(QEasingCurve.Type.OutCubic)

    def get_display_score(self) -> float:
        return self._display_score

    def set_display_score(self, value: float) -> None:
        self._display_score = max(0.0, min(100.0, value))
        self.update()

    displayScore = Property(float, get_display_score, set_display_score)

    def set_score(self, score: int, caption: str = "POSTURE") -> None:
        self.score = max(0, min(100, score))
        self.has_score = True
        self.caption = caption
        self.score_animation.stop()
        self.score_animation.setStartValue(self._display_score)
        self.score_animation.setEndValue(float(self.score))
        self.score_animation.start()

    def set_unknown(self, caption: str = "INCOMPLETE") -> None:
        self.score_animation.stop()
        self.has_score = False
        self.caption = caption
        self.update()

    def paintEvent(self, _event: object) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        ring = self.rect().adjusted(18, 18, -18, -18)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#181715"))
        painter.drawEllipse(ring.adjusted(-8, -8, 8, 8))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(QColor("#3b3935"), 10, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(ring, 0, 360 * 16)
        painter.setPen(QPen(QColor("#8b4651"), 10, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(
            ring,
            90 * 16,
            -int(360 * 16 * (self._display_score / 100 if self.has_score else 0.08)),
        )

        font = painter.font()
        font.setPointSize(28)
        font.setFamily("Iowan Old Style")
        font.setBold(False)
        painter.setFont(font)
        painter.setPen(QColor("#faf9f5"))
        value_metrics = QFontMetrics(font)
        font.setPointSize(9)
        font.setFamily("Inter")
        font.setBold(False)
        caption_metrics = QFontMetrics(font)
        gap = 5
        group_height = value_metrics.height() + gap + caption_metrics.height()
        # Font ascent/descent boxes are visually bottom-heavy on macOS. Lift the
        # complete value-and-caption group slightly for optical centering.
        group_top = (self.height() - group_height) // 2 - 5
        value_rect = QRect(
            0,
            group_top,
            self.width(),
            value_metrics.height(),
        )
        caption_rect = QRect(
            0,
            value_rect.bottom() + 1 + gap,
            self.width(),
            caption_metrics.height(),
        )
        painter.drawText(
            value_rect,
            Qt.AlignmentFlag.AlignCenter,
            str(round(self._display_score)) if self.has_score else "—",
        )
        painter.setFont(font)
        painter.setPen(QColor("#a09d96"))
        painter.drawText(caption_rect, Qt.AlignmentFlag.AlignCenter, self.caption)


class PulseDot(QWidget):
    def __init__(self, color: str = "#5db872") -> None:
        super().__init__()
        self.color = QColor(color)
        self._pulse = 0.0
        self.setFixedSize(22, 22)
        self.pulse_animation = QPropertyAnimation(self, b"pulse", self)
        self.pulse_animation.setDuration(1600)
        self.pulse_animation.setStartValue(0.0)
        self.pulse_animation.setKeyValueAt(0.5, 1.0)
        self.pulse_animation.setEndValue(0.0)
        self.pulse_animation.setLoopCount(-1)
        self.pulse_animation.setEasingCurve(QEasingCurve.Type.InOutSine)
        self.pulse_animation.start()

    def get_pulse(self) -> float:
        return self._pulse

    def set_pulse(self, value: float) -> None:
        self._pulse = max(0.0, min(1.0, value))
        self.update()

    pulse = Property(float, get_pulse, set_pulse)

    def set_color(self, color: str) -> None:
        self.color = QColor(color)

    def paintEvent(self, _event: object) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        halo = QColor(self.color)
        halo.setAlpha(int(72 * (1.0 - self._pulse)))
        painter.setBrush(halo)
        radius = 6 + int(4 * self._pulse)
        painter.drawEllipse(11 - radius, 11 - radius, radius * 2, radius * 2)
        painter.setBrush(self.color)
        painter.drawEllipse(7, 7, 8, 8)


class StatusIndicator(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        self.dot = PulseDot()
        self.text = label("Ready", "Good")
        layout.addWidget(self.dot)
        layout.addWidget(self.text)

    def set_status(self, text: str, state: str = "good") -> None:
        colors = {"good": "#5db872", "busy": "#e8a55a", "error": "#c64545"}
        self.dot.set_color(colors.get(state, colors["good"]))
        self.text.setText(text)
        self.text.setStyleSheet(f"color: {colors.get(state, colors['good'])}; font-weight: 500;")


class FadeStackedWidget(QStackedWidget):
    def __init__(self) -> None:
        super().__init__()
        self._fade_animation: QPropertyAnimation | None = None
        self._fade_page: QWidget | None = None

    def fade_to(self, index: int) -> None:
        if index == self.currentIndex():
            return
        if self._fade_animation is not None:
            self._fade_animation.stop()
        if self._fade_page is not None:
            self._fade_page.setGraphicsEffect(None)
        self.setCurrentIndex(index)
        page = self.currentWidget()
        effect = QGraphicsOpacityEffect(page)
        effect.setOpacity(0.0)
        page.setGraphicsEffect(effect)
        animation = QPropertyAnimation(effect, b"opacity", self)
        animation.setDuration(210)
        animation.setStartValue(0.0)
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        animation.finished.connect(lambda: self._finish_fade(page, effect))
        self._fade_page = page
        self._fade_animation = animation
        animation.start()

    def _finish_fade(self, page: QWidget, effect: QGraphicsOpacityEffect) -> None:
        effect.setOpacity(1.0)
        if page.graphicsEffect() is effect:
            page.setGraphicsEffect(None)
        if self._fade_page is page:
            self._fade_page = None
            self._fade_animation = None


class SeverityDistribution(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.counts = {key: 0 for key in SEVERITY_COLORS}
        self._reveal = 1.0
        self.setMinimumHeight(158)
        self.reveal_animation = QPropertyAnimation(self, b"reveal", self)
        self.reveal_animation.setDuration(560)
        self.reveal_animation.setEasingCurve(QEasingCurve.Type.OutCubic)

    def get_reveal(self) -> float:
        return self._reveal

    def set_reveal(self, value: float) -> None:
        self._reveal = max(0.0, min(1.0, value))
        self.update()

    reveal = Property(float, get_reveal, set_reveal)

    def set_counts(self, issues: list[ReviewIssue]) -> None:
        self.counts = {key: 0 for key in SEVERITY_COLORS}
        for issue in issues:
            self.counts[issue.severity] = self.counts.get(issue.severity, 0) + 1
        self.reveal_animation.stop()
        self.reveal_animation.setStartValue(0.0)
        self.reveal_animation.setEndValue(1.0)
        self.reveal_animation.start()

    def paintEvent(self, _event: object) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        maximum = max(1, max(self.counts.values(), default=0))
        row_height = max(28, self.height() // 4)
        for index, severity in enumerate(("CRITICAL", "HIGH", "WARNING", "INFO")):
            top = index * row_height + 5
            count = self.counts.get(severity, 0)
            painter.setPen(QColor("#faf9f5"))
            painter.drawText(0, top, 74, 20, Qt.AlignmentFlag.AlignVCenter, severity.title())
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#3b3935"))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRoundedRect(80, top + 5, max(40, self.width() - 120), 9, 4, 4)
            width = int(
                max(5 if count else 0, (self.width() - 120) * count / maximum)
                * self._reveal
            )
            painter.setBrush(QColor(SEVERITY_COLORS[severity]))
            painter.drawRoundedRect(80, top + 5, width, 9, 4, 4)
            painter.setPen(QColor("#faf9f5"))
            painter.drawText(self.width() - 32, top, 28, 20, Qt.AlignmentFlag.AlignCenter, str(count))


class SeverityBadge(QFrame):
    def __init__(self, severity: str) -> None:
        super().__init__()
        self.setProperty("softCard", True)
        accent = SEVERITY_COLORS[severity]
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        dot = QLabel("●")
        dot.setStyleSheet(f"color: {accent};")
        layout.addWidget(dot)
        layout.addWidget(label(severity.title(), "Muted"))
        layout.addStretch()
        self.value = QLabel("0")
        self.value.setStyleSheet(f"color: {accent}; font-size: 16px; font-weight: 750;")
        layout.addWidget(self.value)

    def set_count(self, count: int) -> None:
        self.value.setText(str(count))


class ScanWorker(QObject):
    progress = Signal(str)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, options: dict[str, object]) -> None:
        super().__init__()
        self.options = options

    @Slot()
    def run(self) -> None:
        try:
            outcome = run_full_scan(
                str(self.options["repo_path"]),
                str(self.options["gemini_api_key"]),
                batch_size=int(self.options["batch_size"]),
                apply_fixes=bool(self.options["apply_fixes"]),
                create_pull_request=bool(self.options["create_pull_request"]),
                github_token=str(self.options["github_token"]),
                repository=str(self.options["repository"]),
                progress=self.progress.emit,
            )
            self.completed.emit(outcome)
        except Exception as exc:
            self.failed.emit(str(exc))


class NavButton(QPushButton):
    def __init__(self, text: str, page_key: str, callback: Callable[[str], None]) -> None:
        icons = {
            "dashboard": "◇",
            "new_scan": "⌁",
            "activity": "◷",
            "findings": "◉",
            "high_risk": "△",
            "review_queue": "?",
            "non_runtime": "⊘",
            "reports": "▤",
            "integrations": "⌘",
            "settings": "⚙",
        }
        visible_text = text.replace("&&", "&").replace("&", "&&")
        super().__init__(f"{icons.get(page_key, '·')}   {visible_text}")
        self.page_key = page_key
        self.setProperty("nav", True)
        self.setProperty("active", False)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clicked.connect(lambda: callback(self.page_key))

    def set_active(self, active: bool) -> None:
        self.setProperty("active", active)
        self.style().unpolish(self)
        self.style().polish(self)


class NavSection(QWidget):
    def __init__(
        self,
        title: str,
        items: list[tuple[str, str]],
        callback: Callable[[str], None],
        expanded: bool = True,
    ) -> None:
        super().__init__()
        self.buttons: list[NavButton] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        self.header = QToolButton()
        self.header.setProperty("section", True)
        self.header.setText(title.upper())
        self.header.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.header.setArrowType(
            Qt.ArrowType.DownArrow if expanded else Qt.ArrowType.RightArrow
        )
        self.header.clicked.connect(self.toggle)
        layout.addWidget(self.header)
        self.children = QWidget()
        children_layout = QVBoxLayout(self.children)
        children_layout.setContentsMargins(0, 0, 0, 0)
        children_layout.setSpacing(2)
        for text, key in items:
            button = NavButton(text, key, callback)
            children_layout.addWidget(button)
            self.buttons.append(button)
        self.children.setVisible(expanded)
        layout.addWidget(self.children)

    def toggle(self) -> None:
        visible = not self.children.isVisible()
        self.children.setVisible(visible)
        self.header.setArrowType(
            Qt.ArrowType.DownArrow if visible else Qt.ArrowType.RightArrow
        )


class MetricCard(QFrame):
    def __init__(
        self, title: str, value: str, accent: str, icon: str, context: str
    ) -> None:
        super().__init__()
        self.setProperty("card", True)
        object_name = "Metric" + title.replace(" ", "").replace("&", "")
        self.setObjectName(object_name)
        self.setStyleSheet(
            f"QFrame#{object_name} {{ background: #efe9de; border: 0; border-radius: 12px; }}"
            f"QFrame#{object_name} QLabel {{ color: #3d3d3a; }}"
        )
        self.accent = accent
        self.current_number = int(value)
        self.target_number = int(value)
        self.value_timer = QTimer(self)
        self.value_timer.timeout.connect(self._animate_value)
        self.setMinimumHeight(132)
        elevate(self, 22, 62)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(5)
        top = QHBoxLayout()
        top.addStretch()
        icon_label = QLabel(icon)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setFixedSize(30, 30)
        icon_label.setStyleSheet(
            "background: #181715; color: #faf9f5; border: 0; "
            "border-radius: 15px; font-family: Inter; font-size: 13px; font-weight: 500;"
        )
        top.addWidget(icon_label)
        top.addStretch()
        layout.addLayout(top)
        context_label = label(context, "Muted")
        context_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(context_label)
        self.value = label(value, "MetricValue")
        self.value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.value)
        title_label = label(title, "MetricLabel")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)

    def set_number(self, number: int) -> None:
        self.target_number = int(number)
        if self.current_number == self.target_number:
            self.value.setText(str(number))
            return
        self.value_timer.start(28)

    def _animate_value(self) -> None:
        distance = self.target_number - self.current_number
        if distance == 0:
            self.value_timer.stop()
            return
        step = max(1, abs(distance) // 5)
        self.current_number += step if distance > 0 else -step
        if (distance > 0 and self.current_number > self.target_number) or (
            distance < 0 and self.current_number < self.target_number
        ):
            self.current_number = self.target_number
        self.value.setText(str(self.current_number))

    def enterEvent(self, event: object) -> None:
        super().enterEvent(event)  # type: ignore[arg-type]

    def leaveEvent(self, event: object) -> None:
        super().leaveEvent(event)  # type: ignore[arg-type]


class DashboardPage(QWidget):
    def __init__(self, app: "AegisScanWindow") -> None:
        super().__init__()
        self.app = app
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 22, 30, 26)
        layout.setSpacing(14)
        context_row = QHBoxLayout()
        command_center = label("SECURITY WORKSPACE", "Eyebrow")
        command_center.setWordWrap(False)
        context_row.addWidget(command_center)
        context_row.addStretch()
        local_first = label("Local-first  ·  Full repository", "Muted")
        local_first.setWordWrap(False)
        context_row.addWidget(local_first)
        layout.addLayout(context_row)

        hero = HeroPanel()
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(30, 24, 30, 24)
        hero_layout.setSpacing(24)
        hero_copy = QVBoxLayout()
        hero_copy.setSpacing(7)
        hero_copy.addWidget(label("THOUGHTFUL SECURITY, COMPLETE CONTEXT", "HeroKicker"))
        hero_copy.addWidget(label("Understand your repository’s real risk.", "HeroTitle"))
        hero_copy.addWidget(
            label(
                "Turn repository-wide static analysis into evidence-backed, context-aware mitigations while your source stays under your control.",
                "PageSubtitle",
            )
        )
        hero_copy.addSpacing(5)
        self.repo_label = label(app.repo_path or "Choose a repository")
        self.repo_label.setProperty("pill", True)
        self.repo_label.setMaximumWidth(520)
        hero_copy.addWidget(self.repo_label)
        hero_copy.addStretch()
        hero_actions = QHBoxLayout()
        hero_actions.addWidget(primary_button("Start new audit  →", lambda: app.navigate("new_scan")))
        choose = QPushButton("Change repository")
        choose.clicked.connect(app.choose_repository)
        hero_actions.addWidget(choose)
        hero_actions.addStretch()
        hero_copy.addLayout(hero_actions)
        hero_layout.addLayout(hero_copy, 1)
        ring_area = QVBoxLayout()
        ring_area.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.security_ring = SecurityRing()
        ring_area.addWidget(self.security_ring, alignment=Qt.AlignmentFlag.AlignCenter)
        hero_layout.addLayout(ring_area)
        layout.addWidget(hero)

        metrics = QHBoxLayout()
        metrics.setSpacing(12)
        self.issue_metric = MetricCard("Confirmed issues", "0", "#8b4651", "◎", "Total")
        self.critical_metric = MetricCard("Critical & high", "0", "#c64545", "△", "Priority")
        self.review_metric = MetricCard("Needs review", "0", "#d4a017", "?", "Unresolved")
        self.non_runtime_metric = MetricCard("Excluded evidence", "0", "#5db8a6", "⊘", "Scoped out")
        for item in (
            self.issue_metric,
            self.critical_metric,
            self.review_metric,
            self.non_runtime_metric,
        ):
            metrics.addWidget(item)
        layout.addLayout(metrics)

        lower = QHBoxLayout()
        lower.setSpacing(12)
        severity = card()
        severity.setObjectName("DarkCard")
        severity.setStyleSheet(
            "QFrame#DarkCard { background: #181715; border: 0; border-radius: 12px; }"
            "QFrame#DarkCard QLabel { color: #faf9f5; }"
            "QFrame#DarkCard QLabel#Muted, QFrame#DarkCard QLabel#Eyebrow { color: #a09d96; }"
        )
        severity_layout = QVBoxLayout(severity)
        severity_layout.setContentsMargins(20, 17, 20, 15)
        severity_header = QHBoxLayout()
        severity_header.addWidget(label("Risk distribution", "SectionTitle"))
        severity_header.addStretch()
        severity_header.addWidget(label("Confirmed only", "Eyebrow"))
        severity_layout.addLayout(severity_header)
        severity_layout.addWidget(label("Current issue composition by severity.", "Muted"))
        self.distribution = SeverityDistribution()
        severity_layout.addWidget(self.distribution, 1)
        lower.addWidget(severity, 3)

        posture = card()
        posture.setObjectName("CreamCard")
        posture.setStyleSheet(
            "QFrame#CreamCard { background: #efe9de; border: 0; border-radius: 12px; }"
        )
        posture_layout = QVBoxLayout(posture)
        posture_layout.setContentsMargins(20, 17, 20, 17)
        posture_header = QHBoxLayout()
        posture_header.addWidget(label("Protection stack", "SectionTitle"))
        posture_header.addStretch()
        self.stack_count = label("4 / 4", "Good")
        posture_header.addWidget(self.stack_count)
        posture_layout.addLayout(posture_header)
        self.stack_description = label("All deterministic controls operational.", "Muted")
        posture_layout.addWidget(self.stack_description)
        posture_layout.addSpacing(6)
        self.engine_status = label("✓  Semgrep completeness enforced", "Good")
        posture_layout.addWidget(self.engine_status)
        posture_layout.addWidget(label("✓  Every candidate receives a disposition", "Good"))
        posture_layout.addWidget(label("✓  Runtime scope classification active", "Good"))
        posture_layout.addWidget(label("✓  Manual-remediation safety gate", "Good"))
        posture_layout.addSpacing(5)
        self.coverage = QProgressBar()
        self.coverage.setRange(0, 100)
        self.coverage.setValue(100)
        self.coverage.setTextVisible(False)
        posture_layout.addWidget(self.coverage)
        posture_layout.addStretch()
        lower.addWidget(posture, 2)
        layout.addLayout(lower)

    def refresh(self) -> None:
        self.repo_label.setText(self.app.repo_path or "Choose a repository")
        outcome = self.app.outcome
        if not outcome:
            return
        critical = sum(
            issue.severity in {"CRITICAL", "HIGH"} for issue in outcome.report.issues
        )
        self.issue_metric.set_number(len(outcome.report.issues))
        self.critical_metric.set_number(critical)
        self.review_metric.set_number(outcome.disposition_count("NEEDS_REVIEW"))
        self.non_runtime_metric.set_number(
            outcome.disposition_count("NON_RUNTIME")
            + outcome.disposition_count("FALSE_POSITIVE")
        )
        self.distribution.set_counts(outcome.report.issues)
        score = 100
        for issue in outcome.report.issues:
            score -= {"CRITICAL": 24, "HIGH": 12, "WARNING": 4, "INFO": 1}[issue.severity]
        if outcome.ai_triage_degraded:
            self.security_ring.set_unknown("INCOMPLETE")
            self.engine_status.setText("!  Gemini triage incomplete; manual review required")
            self.engine_status.setStyleSheet("color: #c64545; font-weight: 500;")
            self.stack_count.setText("3 / 4")
            self.stack_count.setStyleSheet("color: #c64545; font-weight: 500;")
            self.stack_description.setText(
                "Deterministic scanning completed, but AI triage did not cover every batch."
            )
            completed = outcome.ai_successful_batches
            attempted = outcome.ai_attempted_batches
            self.coverage.setValue(round(100 * completed / attempted) if attempted else 100)
        else:
            self.security_ring.set_score(max(0, score), "POSTURE")
            self.engine_status.setText("✓  Semgrep completeness enforced")
            self.engine_status.setStyleSheet("")
            self.stack_count.setText("4 / 4")
            self.stack_count.setStyleSheet("")
            self.stack_description.setText("All deterministic controls operational.")
            self.coverage.setValue(100)


class NewScanPage(QWidget):
    def __init__(self, app: "AegisScanWindow") -> None:
        super().__init__()
        self.app = app
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 24, 28, 28)
        outer.setSpacing(16)
        outer.addWidget(label("SCANS / NEW AUDIT", "Eyebrow"))
        outer.addWidget(label("Configure a full-repository audit", "PageTitle"))
        outer.addWidget(
            label(
                "Scanning runs locally; bounded finding context and source excerpts are sent to Gemini for triage.",
                "PageSubtitle",
            )
        )

        stages = QHBoxLayout()
        stages.setSpacing(10)
        self.discover_stage = ScanStage("1", "Discover", "Map repository risk")
        self.reason_stage = ScanStage("2", "Reason", "Validate with context")
        self.remediate_stage = ScanStage("3", "Remediate", "Apply approved fixes")
        self.discover_stage.set_state("active")
        for stage in (self.discover_stage, self.reason_stage, self.remediate_stage):
            stages.addWidget(stage)
        outer.addLayout(stages)

        body = QHBoxLayout()
        body.setSpacing(16)
        config = card()
        config_layout = QVBoxLayout(config)
        config_layout.setContentsMargins(22, 20, 22, 20)
        config_layout.setSpacing(12)
        config_layout.addWidget(label("Audit configuration", "SectionTitle"))
        config_layout.addWidget(label("Repository", "Muted"))
        repo_row = QHBoxLayout()
        self.repo_input = QLineEdit(app.repo_path)
        self.repo_input.setPlaceholderText("/path/to/repository")
        self.repo_input.textChanged.connect(app.set_repository)
        repo_row.addWidget(self.repo_input, 1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(app.choose_repository)
        repo_row.addWidget(browse)
        config_layout.addLayout(repo_row)

        config_layout.addWidget(label("Gemini API key", "Muted"))
        self.api_key_input = QLineEdit(app.api_key)
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_input.setPlaceholderText("Stored only for this app session")
        self.api_key_input.textChanged.connect(app.set_api_key)
        config_layout.addWidget(self.api_key_input)

        options_row = QHBoxLayout()
        option_left = QVBoxLayout()
        option_left.addWidget(label("Findings per AI batch", "Muted"))
        self.batch_size = QSpinBox()
        self.batch_size.setRange(1, 15)
        self.batch_size.setValue(app.batch_size)
        self.batch_size.valueChanged.connect(app.set_batch_size)
        option_left.addWidget(self.batch_size)
        options_row.addLayout(option_left)
        option_right = QVBoxLayout()
        option_right.addWidget(label("Audit mode", "Muted"))
        mode = QComboBox()
        mode.addItems(["Full repository · Semgrep + AI", "Semgrep triage only"])
        mode.model().item(1).setEnabled(False)
        option_right.addWidget(mode)
        options_row.addLayout(option_right, 1)
        config_layout.addLayout(options_row)

        self.apply_fixes = QCheckBox("Apply fixes that pass deterministic safety checks")
        self.apply_fixes.setChecked(app.apply_fixes)
        self.apply_fixes.toggled.connect(app.set_apply_fixes)
        config_layout.addWidget(self.apply_fixes)
        self.publish_pr = QCheckBox("Publish changed files as a new GitHub pull request")
        self.publish_pr.setChecked(app.create_pr)
        self.publish_pr.toggled.connect(self._publish_toggled)
        config_layout.addWidget(self.publish_pr)
        config_layout.addStretch()
        self.launch_button = primary_button("Run full audit  →", app.start_scan)
        self.launch_button.setMinimumHeight(44)
        config_layout.addWidget(self.launch_button)
        body.addWidget(config, 5)

        live = card()
        live_layout = QVBoxLayout(live)
        live_layout.setContentsMargins(22, 20, 22, 20)
        live_layout.addWidget(label("Live audit", "SectionTitle"))
        self.live_status = label("Waiting for configuration", "Muted")
        live_layout.addWidget(self.live_status)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        live_layout.addWidget(self.progress)
        self.idle_panel = card(soft=True)
        self.idle_panel.setMinimumHeight(158)
        idle_layout = QVBoxLayout(self.idle_panel)
        idle_layout.setContentsMargins(12, 12, 12, 12)
        idle_layout.setSpacing(5)
        idle_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        idle_icon = QLabel("⌁")
        idle_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        idle_icon.setFixedSize(44, 44)
        idle_icon.setStyleSheet(
            "background: #181715; color: #faf9f5; "
            "border: 0; border-radius: 22px; font-size: 22px;"
        )
        idle_layout.addWidget(idle_icon, alignment=Qt.AlignmentFlag.AlignCenter)
        idle_title = label("Ready for full coverage", "SectionTitle")
        idle_title.setWordWrap(False)
        idle_layout.addWidget(idle_title, alignment=Qt.AlignmentFlag.AlignCenter)
        idle_description = label(
            "The live console will trace discovery, AI triage, and remediation.", "Muted"
        )
        idle_description.setMaximumWidth(310)
        idle_description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        idle_layout.addWidget(idle_description, alignment=Qt.AlignmentFlag.AlignCenter)
        live_layout.addWidget(self.idle_panel)
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(2000)
        self.console.setPlaceholderText(
            "Scan progress will appear here. Repository source is treated as untrusted data."
        )
        live_layout.addWidget(self.console, 1)
        body.addWidget(live, 4)
        outer.addLayout(body, 1)

    def _publish_toggled(self, checked: bool) -> None:
        if checked:
            self.apply_fixes.setChecked(True)
        self.app.set_create_pr(checked)

    def set_running(self, running: bool) -> None:
        self.launch_button.setEnabled(not running)
        if running:
            self.progress.setRange(0, 0)
            self.live_status.setText("Audit in progress")
            self.live_status.setObjectName("Accent")
            self.console.clear()
            self.append_progress(
                "[SESSION] Audit started · credentials and repository source are excluded from this log"
            )
            self.idle_panel.hide()
            self.discover_stage.set_state("active")
            self.reason_stage.set_state("pending")
            self.remediate_stage.set_state("pending")
        else:
            self.progress.setRange(0, 1)
            self.progress.setValue(1)

    def append_progress(self, message: str) -> None:
        clean_message = " ".join(message.strip().splitlines())
        status_text = clean_message.split("] ", 1)[-1]
        self.live_status.setText(
            status_text if len(status_text) <= 110 else status_text[:107] + "…"
        )
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.appendPlainText(f"[{timestamp}]  {clean_message}")
        lowered = clean_message.casefold()
        if any(tag in lowered for tag in ("[plan]", "[context]", "[ai]", "[validate]")):
            self.discover_stage.set_state("done")
            self.reason_stage.set_state("active")
        if "[remediate]" in lowered or "[publish]" in lowered:
            self.reason_stage.set_state("done")
            self.remediate_stage.set_state("active")
        if "[complete]" in lowered:
            self.discover_stage.set_state("done")
            self.reason_stage.set_state("done")
            self.remediate_stage.set_state("done")

    def sync_repository(self, path: str) -> None:
        self.repo_input.blockSignals(True)
        self.repo_input.setText(path)
        self.repo_input.blockSignals(False)

    def sync_api_key(self, value: str) -> None:
        self.api_key_input.blockSignals(True)
        self.api_key_input.setText(value)
        self.api_key_input.blockSignals(False)


class ActivityPage(QWidget):
    def __init__(self, app: "AegisScanWindow") -> None:
        super().__init__()
        self.app = app
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 28)
        layout.setSpacing(16)
        layout.addWidget(label("SCANS / ACTIVITY", "Eyebrow"))
        layout.addWidget(label("Session activity", "PageTitle"))
        layout.addWidget(label("A local record of audits run during this app session.", "PageSubtitle"))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Repository", "Semgrep", "Batches", "Confirmed", "Status"]
        )
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in range(1, 5):
            self.table.horizontalHeader().setSectionResizeMode(
                column, QHeaderView.ResizeMode.ResizeToContents
            )
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table, 1)

    def refresh(self) -> None:
        self.table.setRowCount(len(self.app.history))
        for row, entry in enumerate(reversed(self.app.history)):
            for column, key in enumerate(
                ("repository", "findings", "batches", "issues", "status")
            ):
                self.table.setItem(row, column, QTableWidgetItem(str(entry[key])))


class FindingsPage(QWidget):
    def __init__(self, app: "AegisScanWindow", high_only: bool = False) -> None:
        super().__init__()
        self.app = app
        self.high_only = high_only
        self.filtered_issues: list[ReviewIssue] = []
        self.selected_issue: ReviewIssue | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 28)
        layout.setSpacing(15)
        layout.addWidget(label("FINDINGS / PRIORITIZED", "Eyebrow"))
        layout.addWidget(
            label("Critical & high risk" if high_only else "Confirmed findings", "PageTitle")
        )
        layout.addWidget(
            label(
                "Only runtime issues with complete source-to-sink evidence appear here.",
                "PageSubtitle",
            )
        )

        summary = QHBoxLayout()
        summary.setSpacing(10)
        self.severity_badges = {
            severity: SeverityBadge(severity)
            for severity in ("CRITICAL", "HIGH", "WARNING", "INFO")
        }
        for badge in self.severity_badges.values():
            summary.addWidget(badge)
        layout.addLayout(summary)

        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search issue, file, or description…")
        self.search.textChanged.connect(self.refresh)
        filters.addWidget(self.search, 1)
        self.severity = QComboBox()
        self.severity.addItems(["All severities", "Critical", "High", "Warning", "Info"])
        self.severity.currentTextChanged.connect(self.refresh)
        if high_only:
            self.severity.setCurrentText("All severities")
            self.severity.setEnabled(False)
        filters.addWidget(self.severity)
        export = QPushButton("Export report")
        export.clicked.connect(app.export_report)
        filters.addWidget(export)
        layout.addLayout(filters)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Severity", "Issue", "File", "Line"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self.show_selected)
        splitter.addWidget(self.table)

        detail = card()
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(20, 18, 20, 18)
        self.detail_title = label("Select a finding", "SectionTitle")
        self.detail_meta = label("Issue context and remediation will appear here.", "Muted")
        self.detail_body = QTextEdit()
        self.detail_body.setReadOnly(True)
        detail_layout.addWidget(self.detail_title)
        detail_layout.addWidget(self.detail_meta)
        detail_layout.addWidget(self.detail_body, 1)
        patch_actions = QHBoxLayout()
        patch_actions.setSpacing(10)
        self.patch_status = label("Select a finding to review its patch.", "Muted")
        self.patch_status.setWordWrap(True)
        patch_actions.addWidget(self.patch_status, 1)
        self.apply_patch_button = primary_button(
            "Review and apply patch", self.apply_selected_patch
        )
        self.apply_patch_button.setEnabled(False)
        patch_actions.addWidget(self.apply_patch_button)
        detail_layout.addLayout(patch_actions)
        splitter.addWidget(detail)
        splitter.setSizes([720, 380])
        layout.addWidget(splitter, 1)

    def refresh(self) -> None:
        all_issues = list(self.app.outcome.report.issues) if self.app.outcome else []
        for severity, badge in self.severity_badges.items():
            badge.set_count(sum(issue.severity == severity for issue in all_issues))
        issues = list(all_issues)
        if self.high_only:
            issues = [issue for issue in issues if issue.severity in {"CRITICAL", "HIGH"}]
        selected_severity = self.severity.currentText().upper()
        if not self.high_only and selected_severity != "ALL SEVERITIES":
            issues = [issue for issue in issues if issue.severity == selected_severity]
        term = self.search.text().strip().casefold()
        if term:
            issues = [
                issue
                for issue in issues
                if term
                in " ".join(
                    (issue.issue_name, issue.file, issue.description, issue.severity)
                ).casefold()
            ]
        self.filtered_issues = issues
        self.table.setRowCount(len(issues))
        for row, issue in enumerate(issues):
            severity_item = QTableWidgetItem(issue.severity)
            severity_item.setForeground(QColor(SEVERITY_COLORS.get(issue.severity, "#6c6a64")))
            self.table.setItem(row, 0, severity_item)
            self.table.setItem(row, 1, QTableWidgetItem(issue.issue_name))
            self.table.setItem(row, 2, QTableWidgetItem(issue.file))
            self.table.setItem(row, 3, QTableWidgetItem(str(issue.line)))
        if issues:
            self.table.selectRow(0)
        else:
            self.selected_issue = None
            self.detail_title.setText("No findings in this view")
            self.detail_meta.setText("Run an audit or adjust the filters.")
            self.detail_body.setPlainText(
                "No issue details are available yet.\n\n"
                "Start a full-repository audit to populate this workspace with "
                "evidence-backed findings and safety-reviewed remediations."
            )
            self.patch_status.setText("No patch is available in this view.")
            self.apply_patch_button.setText("Review and apply patch")
            self.apply_patch_button.setEnabled(False)

    def show_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self.filtered_issues):
            return
        issue = self.filtered_issues[row]
        self.selected_issue = issue
        self.detail_title.setText(issue.issue_name)
        self.detail_meta.setText(
            f"{issue.severity}  ·  {issue.confidence} confidence  ·  "
            f"{issue.file}:{issue.line}  ·  {issue.rule_id or 'unknown rule'}"
        )
        self.detail_body.setPlainText(
            f"WHY IT MATTERS\n{issue.description}\n\n"
            f"UNTRUSTED SOURCE\n{issue.source_evidence}\n\n"
            f"SECURITY SINK\n{issue.sink_evidence}\n\n"
            f"REACHABILITY\n{issue.reachability_evidence}\n\n"
            f"REMEDIATION MODE\n{issue.remediation_type}\n\n"
            f"ORIGINAL CODE\n{issue.original_code}\n\n"
            f"SUGGESTED FIX\n{issue.suggested_fix}"
        )
        patch_key = self.app.issue_patch_key(issue)
        if patch_key in self.app.applied_issue_patches:
            self.patch_status.setText("This patch was applied during the current session.")
            self.patch_status.setObjectName("Good")
            self.apply_patch_button.setText("Patch applied")
            self.apply_patch_button.setEnabled(False)
            self.patch_status.style().unpolish(self.patch_status)
            self.patch_status.style().polish(self.patch_status)
            return
        eligible, reason = auto_fix_eligibility(issue)
        self.patch_status.setText(reason)
        self.patch_status.setObjectName("Good" if eligible else "Muted")
        self.apply_patch_button.setText("Review and apply patch")
        self.apply_patch_button.setEnabled(eligible)
        self.patch_status.style().unpolish(self.patch_status)
        self.patch_status.style().polish(self.patch_status)

    def apply_selected_patch(self) -> None:
        issue = self.selected_issue
        if issue is None:
            return
        eligible, reason = auto_fix_eligibility(issue)
        if not eligible:
            self.app._error(reason)
            self.show_selected()
            return

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Apply individual patch")
        box.setText(f"Apply the suggested patch to {issue.file}:{issue.line}?")
        box.setInformativeText(
            "AegisScan will run the deterministic safety check again and modify only this finding."
        )
        box.setDetailedText(
            f"ORIGINAL CODE\n{issue.original_code}\n\n"
            f"SUGGESTED FIX\n{issue.suggested_fix}"
        )
        box.setStandardButtons(
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Apply
        )
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        if box.exec() != QMessageBox.StandardButton.Apply:
            return

        changed_files = apply_auto_fixes_with_paths([issue], self.app.repo_path)
        if issue.file not in changed_files:
            self.patch_status.setText(
                "Patch could not be applied; the original code may have changed."
            )
            self.patch_status.setObjectName("Danger")
            self.patch_status.style().unpolish(self.patch_status)
            self.patch_status.style().polish(self.patch_status)
            self.app._error(
                "The patch was not applied. The source may have changed since the audit, "
                "or the original code could not be matched safely."
            )
            return

        self.app.record_individual_patch(issue, changed_files)
        self.show_selected()


class DispositionPage(QWidget):
    """Evidence ledger view for candidates that are not confirmed issues."""

    def __init__(
        self,
        app: "AegisScanWindow",
        *,
        statuses: set[str],
        title: str,
        subtitle: str,
    ) -> None:
        super().__init__()
        self.app = app
        self.statuses = statuses
        self.filtered_dispositions: list[FindingDisposition] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 28)
        layout.setSpacing(15)
        layout.addWidget(label("FINDINGS / EVIDENCE LEDGER", "Eyebrow"))
        layout.addWidget(label(title, "PageTitle"))
        layout.addWidget(label(subtitle, "PageSubtitle"))

        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search candidate ID, rule, file, or reason…")
        self.search.textChanged.connect(self.refresh)
        filters.addWidget(self.search, 1)
        export = QPushButton("Export report")
        export.clicked.connect(app.export_report)
        filters.addWidget(export)
        layout.addLayout(filters)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Status", "Rule", "File", "Line"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self.show_selected)
        splitter.addWidget(self.table)

        detail = card()
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(20, 18, 20, 18)
        self.detail_title = label("Select a candidate", "SectionTitle")
        self.detail_meta = label("Disposition evidence will appear here.", "Muted")
        self.detail_body = QTextEdit()
        self.detail_body.setReadOnly(True)
        detail_layout.addWidget(self.detail_title)
        detail_layout.addWidget(self.detail_meta)
        detail_layout.addWidget(self.detail_body, 1)
        splitter.addWidget(detail)
        splitter.setSizes([720, 380])
        layout.addWidget(splitter, 1)

    def refresh(self) -> None:
        dispositions = (
            list(self.app.outcome.report.dispositions) if self.app.outcome else []
        )
        dispositions = [item for item in dispositions if item.status in self.statuses]
        term = self.search.text().strip().casefold()
        if term:
            dispositions = [
                item
                for item in dispositions
                if term
                in " ".join(
                    (
                        item.finding_id,
                        item.status,
                        item.rule_id,
                        item.file,
                        item.reason,
                        item.code_role,
                    )
                ).casefold()
            ]
        self.filtered_dispositions = dispositions
        self.table.setRowCount(len(dispositions))
        for row, disposition in enumerate(dispositions):
            self.table.setItem(row, 0, QTableWidgetItem(disposition.status.replace("_", " ").title()))
            self.table.setItem(row, 1, QTableWidgetItem(disposition.rule_id))
            self.table.setItem(row, 2, QTableWidgetItem(disposition.file))
            self.table.setItem(row, 3, QTableWidgetItem(str(disposition.line or "—")))
        if dispositions:
            self.table.selectRow(0)
        else:
            self.detail_title.setText("No candidates in this view")
            self.detail_meta.setText("Run an audit or inspect another evidence state.")
            self.detail_body.setPlainText(
                "Every raw Semgrep candidate receives a durable disposition. "
                "Nothing omitted by AI triage is silently discarded."
            )

    def show_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self.filtered_dispositions):
            return
        disposition = self.filtered_dispositions[row]
        self.detail_title.setText(disposition.status.replace("_", " ").title())
        self.detail_meta.setText(
            f"{disposition.finding_id}  ·  {disposition.file}:{disposition.line or '—'}"
        )
        self.detail_body.setPlainText(
            f"DISPOSITION REASON\n{disposition.reason}\n\n"
            f"SEMGREP MESSAGE\n{disposition.message or 'No rule message was provided.'}\n\n"
            f"CODE ROLE\n{disposition.code_role}\n\n"
            f"CONFIDENCE\n{disposition.confidence}\n\n"
            f"SEMGREP RULE\n{disposition.rule_id}"
        )


class ReportsPage(QWidget):
    def __init__(self, app: "AegisScanWindow") -> None:
        super().__init__()
        self.app = app
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 28)
        layout.setSpacing(16)
        layout.addWidget(label("WORKSPACE / REPORTS", "Eyebrow"))
        layout.addWidget(label("Audit reports", "PageTitle"))
        layout.addWidget(
            label("Export the current structured ReviewReport for archival or downstream review.", "PageSubtitle")
        )
        summary = card()
        summary_layout = QHBoxLayout(summary)
        summary_layout.setContentsMargins(22, 20, 22, 20)
        summary_text = QVBoxLayout()
        summary_text.addWidget(label("Current session report", "SectionTitle"))
        self.summary = label("No audit has been completed in this session.", "Muted")
        summary_text.addWidget(self.summary)
        summary_layout.addLayout(summary_text, 1)
        self.export_button = primary_button("Export JSON…", app.export_report)
        self.export_button.setEnabled(False)
        summary_layout.addWidget(self.export_button)
        layout.addWidget(summary)

        reasoning = card()
        reasoning_layout = QVBoxLayout(reasoning)
        reasoning_layout.setContentsMargins(22, 20, 22, 20)
        reasoning_layout.addWidget(label("Audit reasoning trace", "SectionTitle"))
        reasoning_layout.addWidget(
            label(
                "Concise per-batch data-flow notes retained by the ReviewReport schema.",
                "Muted",
            )
        )
        self.scratchpad = QTextEdit()
        self.scratchpad.setReadOnly(True)
        reasoning_layout.addWidget(self.scratchpad, 1)
        layout.addWidget(reasoning, 1)

    def refresh(self) -> None:
        outcome = self.app.outcome
        self.export_button.setEnabled(outcome is not None)
        if not outcome:
            return
        self.summary.setText(
            f"{outcome.raw_finding_count} raw findings · {outcome.batch_count} batches · "
            f"{len(outcome.report.issues)} confirmed · "
            f"{outcome.disposition_count('NEEDS_REVIEW')} needs review · "
            f"{outcome.disposition_count('NON_RUNTIME')} non-runtime · "
            f"{outcome.disposition_count('FALSE_POSITIVE')} false positives · "
            f"{len(outcome.fixed_files)} changed files"
        )
        self.scratchpad.setPlainText(outcome.report.analysis_scratchpad)


class IntegrationsPage(QWidget):
    def __init__(self, app: "AegisScanWindow") -> None:
        super().__init__()
        self.app = app
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 28)
        layout.setSpacing(16)
        layout.addWidget(label("WORKSPACE / INTEGRATIONS", "Eyebrow"))
        layout.addWidget(label("Optional integrations", "PageTitle"))
        layout.addWidget(
            label(
                "AegisScan runs locally. GitHub is used only when you explicitly publish safety-validated fixes.",
                "PageSubtitle",
            )
        )
        github_card = card()
        card_layout = QVBoxLayout(github_card)
        card_layout.setContentsMargins(22, 20, 22, 20)
        top = QHBoxLayout()
        top.addWidget(label("GitHub pull requests", "SectionTitle"))
        top.addStretch()
        self.connection_state = label("Not configured", "Muted")
        top.addWidget(self.connection_state)
        card_layout.addLayout(top)
        card_layout.addWidget(
            label(
                "Creates a dedicated aegis-audit timestamp branch. It never pushes directly to your default branch.",
                "Muted",
            )
        )
        card_layout.addSpacing(8)
        card_layout.addWidget(label("Repository (owner/name)", "Muted"))
        self.repository = QLineEdit(app.github_repository)
        self.repository.setPlaceholderText("organization/repository")
        self.repository.textChanged.connect(app.set_github_repository)
        card_layout.addWidget(self.repository)
        card_layout.addWidget(label("Personal access token", "Muted"))
        self.token = QLineEdit(app.github_token)
        self.token.setEchoMode(QLineEdit.EchoMode.Password)
        self.token.setPlaceholderText("Stored only for this app session")
        self.token.textChanged.connect(app.set_github_token)
        card_layout.addWidget(self.token)
        enable = QCheckBox("Enable pull-request publishing for the next audit")
        enable.setChecked(app.create_pr)
        enable.toggled.connect(self._toggle)
        card_layout.addWidget(enable)
        layout.addWidget(github_card)
        layout.addStretch()

    def _toggle(self, checked: bool) -> None:
        self.app.set_create_pr(checked)
        if checked:
            self.app.set_apply_fixes(True)
        self.connection_state.setText("Ready" if checked else "Not configured")
        self.connection_state.setObjectName("Good" if checked else "Muted")


class SettingsPage(QWidget):
    def __init__(self, app: "AegisScanWindow") -> None:
        super().__init__()
        self.app = app
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 28)
        layout.setSpacing(16)
        layout.addWidget(label("WORKSPACE / SETTINGS", "Eyebrow"))
        layout.addWidget(label("Application settings", "PageTitle"))
        layout.addWidget(
            label(
                "Credentials stay in memory. Finding context and source excerpts are sent to Gemini during audits.",
                "PageSubtitle",
            )
        )

        grid = QGridLayout()
        grid.setSpacing(14)
        ai = card()
        ai_layout = QVBoxLayout(ai)
        ai_layout.setContentsMargins(22, 20, 22, 20)
        ai_layout.addWidget(label("AI provider", "SectionTitle"))
        ai_layout.addWidget(label("Gemini API key", "Muted"))
        self.api_key = QLineEdit(app.api_key)
        self.api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key.setPlaceholderText("Session-only credential")
        self.api_key.textChanged.connect(app.set_api_key)
        ai_layout.addWidget(self.api_key)
        ai_layout.addWidget(
            label("Structured JSON output is enforced through ReviewReport.", "Good")
        )
        ai_layout.addStretch()
        grid.addWidget(ai, 0, 0)

        audit = card()
        audit_layout = QVBoxLayout(audit)
        audit_layout.setContentsMargins(22, 20, 22, 20)
        audit_layout.addWidget(label("Audit defaults", "SectionTitle"))
        audit_layout.addWidget(label("Findings per batch", "Muted"))
        self.batch = QSpinBox()
        self.batch.setRange(1, 15)
        self.batch.setValue(app.batch_size)
        self.batch.valueChanged.connect(app.set_batch_size)
        audit_layout.addWidget(self.batch)
        self.auto_fix = QCheckBox("Apply safe fixes by default")
        self.auto_fix.setChecked(app.apply_fixes)
        self.auto_fix.toggled.connect(app.set_apply_fixes)
        audit_layout.addWidget(self.auto_fix)
        audit_layout.addStretch()
        grid.addWidget(audit, 0, 1)

        about = card()
        about_layout = QVBoxLayout(about)
        about_layout.setContentsMargins(22, 20, 22, 20)
        about_layout.addWidget(label("Protection layers", "SectionTitle"))
        about_layout.addWidget(label("✓  Explicit Semgrep completeness status", "Good"))
        about_layout.addWidget(label("✓  Per-candidate disposition ledger", "Good"))
        about_layout.addWidget(label("✓  Runtime / fixture scope classification", "Good"))
        about_layout.addWidget(label("✓  Evidence-backed confirmation gate", "Good"))
        about_layout.addWidget(label("✓  Manual secret-remediation gate", "Good"))
        grid.addWidget(about, 1, 0, 1, 2)
        layout.addLayout(grid)
        layout.addStretch()

    def sync_api_key(self, value: str) -> None:
        self.api_key.blockSignals(True)
        self.api_key.setText(value)
        self.api_key.blockSignals(False)


class AegisScanWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.settings = QSettings("AegisScan", "AegisScan")
        self.repo_path = str(self.settings.value("repository", os.getcwd()))
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.github_token = os.getenv("GITHUB_TOKEN", "")
        self.github_repository = str(
            self.settings.value("github_repository", os.getenv("GITHUB_REPOSITORY", ""))
        )
        self.batch_size = int(self.settings.value("batch_size", 12))
        self.apply_fixes = str(self.settings.value("apply_fixes", "false")).lower() == "true"
        self.create_pr = False
        self.outcome: ScanOutcome | None = None
        self.history: list[dict[str, object]] = []
        self.applied_issue_patches: set[str] = set()
        self.thread: QThread | None = None
        self.worker: ScanWorker | None = None
        self.nav_buttons: list[NavButton] = []
        self.page_indexes: dict[str, int] = {}

        self.setWindowTitle("AegisScan")
        self.resize(1360, 840)
        self.setMinimumSize(QSize(1100, 700))
        self.setStyleSheet(APP_STYLE)
        self._build_menu()
        self._build_shell()
        restored_section = str(self.settings.value("last_section", "dashboard"))
        self.navigate(
            restored_section if restored_section in self.page_indexes else "dashboard"
        )

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("File")
        choose = QAction("Choose Repository…", self)
        choose.setShortcut(QKeySequence.StandardKey.Open)
        choose.triggered.connect(self.choose_repository)
        file_menu.addAction(choose)
        start = QAction("Run Full Audit", self)
        start.setShortcut(QKeySequence("Ctrl+R"))
        start.triggered.connect(self.start_scan)
        file_menu.addAction(start)
        export = QAction("Export Report…", self)
        export.setShortcut(QKeySequence.StandardKey.SaveAs)
        export.triggered.connect(self.export_report)
        file_menu.addAction(export)
        file_menu.addSeparator()
        file_menu.addAction("Close", self.close, QKeySequence.StandardKey.Close)

        view_menu = self.menuBar().addMenu("View")
        for title, key in (
            ("Dashboard", "dashboard"),
            ("New Audit", "new_scan"),
            ("Confirmed Findings", "findings"),
            ("Needs Review", "review_queue"),
            ("Non-runtime Evidence", "non_runtime"),
            ("Reports", "reports"),
            ("Settings", "settings"),
        ):
            action = QAction(title, self)
            action.triggered.connect(lambda checked=False, page=key: self.navigate(page))
            view_menu.addAction(action)

        help_menu = self.menuBar().addMenu("Help")
        help_menu.addAction("About AegisScan", self.show_about)

    def _build_shell(self) -> None:
        root = QWidget()
        root.setObjectName("AppRoot")
        self.setCentralWidget(root)
        shell = QHBoxLayout(root)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(246)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(16, 20, 16, 18)
        sidebar_layout.setSpacing(4)
        brand_row = QHBoxLayout()
        mark = QLabel("✣")
        mark.setObjectName("BrandMark")
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark.setFixedSize(34, 38)
        brand_row.addWidget(mark)
        brand_row.addWidget(label("AegisScan", "Brand"))
        brand_row.addStretch()
        sidebar_layout.addLayout(brand_row)
        sidebar_layout.addSpacing(18)

        dashboard_button = NavButton("Dashboard", "dashboard", self.navigate)
        self.nav_buttons.append(dashboard_button)
        sidebar_layout.addWidget(dashboard_button)

        sections = [
            NavSection(
                "Scans",
                [("New audit", "new_scan"), ("Activity", "activity")],
                self.navigate,
            ),
            NavSection(
                "Findings",
                [
                    ("Confirmed", "findings"),
                    ("Critical & high", "high_risk"),
                    ("Needs review", "review_queue"),
                    ("Non-runtime", "non_runtime"),
                ],
                self.navigate,
            ),
            NavSection(
                "Workspace",
                [
                    ("Reports", "reports"),
                    ("Integrations", "integrations"),
                    ("Settings", "settings"),
                ],
                self.navigate,
            ),
        ]
        for section in sections:
            self.nav_buttons.extend(section.buttons)
            sidebar_layout.addWidget(section)
        sidebar_layout.addStretch()
        protection = card(soft=True)
        protection_layout = QVBoxLayout(protection)
        protection_layout.setContentsMargins(12, 11, 12, 11)
        protection_layout.addWidget(label("PROTECTION ACTIVE", "Eyebrow"))
        sidebar_health = QProgressBar()
        sidebar_health.setRange(0, 100)
        sidebar_health.setValue(100)
        sidebar_health.setTextVisible(False)
        protection_layout.addWidget(sidebar_health)
        protection_layout.addWidget(label("Local-first audit engine", "Muted"))
        sidebar_layout.addWidget(protection)
        shell.addWidget(sidebar)

        main = QWidget()
        main.setObjectName("Canvas")
        main_layout = QVBoxLayout(main)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        topbar = QFrame()
        topbar.setObjectName("Topbar")
        topbar.setFixedHeight(66)
        topbar_layout = QHBoxLayout(topbar)
        topbar_layout.setContentsMargins(26, 0, 26, 0)
        banner_title = QLabel("AegisScan security workspace")
        banner_title.setStyleSheet(
            "color: #141413; font-family: 'Iowan Old Style', Georgia, serif; "
            "font-size: 18px; font-weight: 400;"
        )
        topbar_layout.addWidget(banner_title)
        topbar_layout.addSpacing(18)
        self.breadcrumb = label("Dashboard", "Muted")
        self.breadcrumb.setWordWrap(False)
        topbar_layout.addWidget(self.breadcrumb)
        topbar_layout.addStretch()
        self.global_status = StatusIndicator()
        topbar_layout.addWidget(self.global_status)
        quick_scan = primary_button("New audit", lambda: self.navigate("new_scan"))
        topbar_layout.addWidget(quick_scan)
        main_layout.addWidget(topbar)

        self.stack = FadeStackedWidget()
        self.dashboard = DashboardPage(self)
        self.new_scan = NewScanPage(self)
        self.activity = ActivityPage(self)
        self.findings = FindingsPage(self)
        self.high_risk = FindingsPage(self, high_only=True)
        self.review_queue = DispositionPage(
            self,
            statuses={"NEEDS_REVIEW"},
            title="Needs review",
            subtitle=(
                "Candidates with incomplete evidence, failed AI triage, or ambiguous reachability stay visible here."
            ),
        )
        self.non_runtime = DispositionPage(
            self,
            statuses={"NON_RUNTIME", "FALSE_POSITIVE"},
            title="Non-runtime and rejected evidence",
            subtitle=(
                "Fixtures, tests, generated material, ignored paths, and false positives remain auditable without inflating runtime risk."
            ),
        )
        self.reports = ReportsPage(self)
        self.integrations = IntegrationsPage(self)
        self.app_settings = SettingsPage(self)
        pages = [
            ("dashboard", self.dashboard),
            ("new_scan", self.new_scan),
            ("activity", self.activity),
            ("findings", self.findings),
            ("high_risk", self.high_risk),
            ("review_queue", self.review_queue),
            ("non_runtime", self.non_runtime),
            ("reports", self.reports),
            ("integrations", self.integrations),
            ("settings", self.app_settings),
        ]
        for key, page in pages:
            self.page_indexes[key] = self.stack.addWidget(page)
        main_layout.addWidget(self.stack, 1)
        shell.addWidget(main, 1)

    def navigate(self, key: str) -> None:
        if key not in self.page_indexes:
            return
        self.stack.fade_to(self.page_indexes[key])
        self.settings.setValue("last_section", key)
        for button in self.nav_buttons:
            button.set_active(button.page_key == key)
        names = {
            "dashboard": "Dashboard",
            "new_scan": "Scans  /  New audit",
            "activity": "Scans  /  Activity",
            "findings": "Findings  /  Confirmed",
            "high_risk": "Findings  /  Critical & high",
            "review_queue": "Findings  /  Needs review",
            "non_runtime": "Findings  /  Non-runtime",
            "reports": "Workspace  /  Reports",
            "integrations": "Workspace  /  Integrations",
            "settings": "Workspace  /  Settings",
        }
        self.breadcrumb.setText(names[key])
        page = self.stack.currentWidget()
        refresh = getattr(page, "refresh", None)
        if refresh:
            refresh()

    def choose_repository(self) -> None:
        selected = QFileDialog.getExistingDirectory(
            self,
            "Choose repository",
            self.repo_path or str(Path.home()),
        )
        if selected:
            self.set_repository(selected)
            self.new_scan.sync_repository(selected)
            self.dashboard.refresh()

    def set_repository(self, value: str) -> None:
        self.repo_path = value
        self.settings.setValue("repository", value)

    def set_api_key(self, value: str) -> None:
        self.api_key = value
        if hasattr(self, "new_scan") and self.sender() is not self.new_scan.api_key_input:
            self.new_scan.sync_api_key(value)
        if hasattr(self, "app_settings") and self.sender() is not self.app_settings.api_key:
            self.app_settings.sync_api_key(value)

    def set_batch_size(self, value: int) -> None:
        self.batch_size = value
        self.settings.setValue("batch_size", value)
        if hasattr(self, "new_scan") and self.new_scan.batch_size.value() != value:
            self.new_scan.batch_size.setValue(value)
        if hasattr(self, "app_settings") and self.app_settings.batch.value() != value:
            self.app_settings.batch.setValue(value)

    def set_apply_fixes(self, checked: bool) -> None:
        self.apply_fixes = checked
        self.settings.setValue("apply_fixes", checked)
        if hasattr(self, "new_scan") and self.new_scan.apply_fixes.isChecked() != checked:
            self.new_scan.apply_fixes.setChecked(checked)
        if hasattr(self, "app_settings") and self.app_settings.auto_fix.isChecked() != checked:
            self.app_settings.auto_fix.setChecked(checked)

    def set_create_pr(self, checked: bool) -> None:
        self.create_pr = checked
        if checked:
            self.set_apply_fixes(True)
        if hasattr(self, "new_scan") and self.new_scan.publish_pr.isChecked() != checked:
            self.new_scan.publish_pr.setChecked(checked)

    def set_github_repository(self, value: str) -> None:
        self.github_repository = value
        self.settings.setValue("github_repository", value)

    def set_github_token(self, value: str) -> None:
        self.github_token = value

    @staticmethod
    def issue_patch_key(issue: ReviewIssue) -> str:
        return issue.finding_id or f"{issue.file}:{issue.line}:{issue.issue_name}"

    def record_individual_patch(
        self, issue: ReviewIssue, changed_files: list[str]
    ) -> None:
        """Synchronize a successful one-finding patch across the session UI."""
        self.applied_issue_patches.add(self.issue_patch_key(issue))
        if self.outcome:
            for changed_file in changed_files:
                if changed_file not in self.outcome.fixed_files:
                    self.outcome.fixed_files.append(changed_file)
        if hasattr(self, "new_scan"):
            self.new_scan.append_progress(
                f"[REMEDIATE] Individual patch applied · {issue.file}:{issue.line} · "
                f"{issue.issue_name}"
            )
        self.global_status.set_status("Patch applied", "good")

    def start_scan(self) -> None:
        repo = Path(self.repo_path).expanduser()
        if not repo.is_dir():
            self._error("Choose an existing repository directory before starting.")
            self.navigate("new_scan")
            return
        if not self.api_key.strip():
            self._error("Enter a Gemini API key in New Audit or Settings.")
            self.navigate("new_scan")
            return
        if self.create_pr and (
            not self.github_token.strip() or not self.github_repository.strip()
        ):
            self._error("Configure both the GitHub token and owner/repository integration.")
            self.navigate("integrations")
            return
        if self.thread and self.thread.isRunning():
            return

        options: dict[str, object] = {
            "repo_path": str(repo),
            "gemini_api_key": self.api_key.strip(),
            "batch_size": self.batch_size,
            "apply_fixes": self.apply_fixes,
            "create_pull_request": self.create_pr,
            "github_token": self.github_token.strip(),
            "repository": self.github_repository.strip(),
        }
        self.navigate("new_scan")
        self.new_scan.set_running(True)
        self.global_status.set_status("Scanning", "busy")
        self.thread = QThread(self)
        self.worker = ScanWorker(options)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.new_scan.append_progress)
        self.worker.completed.connect(self._scan_completed)
        self.worker.failed.connect(self._scan_failed)
        self.worker.completed.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self._thread_finished)
        self.thread.start()

    @Slot()
    def _thread_finished(self) -> None:
        thread = self.thread
        self.thread = None
        self.worker = None
        if thread is not None:
            thread.deleteLater()

    @Slot(object)
    def _scan_completed(self, outcome: ScanOutcome) -> None:
        self.outcome = outcome
        self.new_scan.set_running(False)
        self.new_scan.append_progress(
            f"[SESSION] Results synchronized · {len(outcome.report.issues)} confirmed · "
            f"{outcome.disposition_count('NEEDS_REVIEW')} needs review · "
            f"{outcome.disposition_count('NON_RUNTIME')} non-runtime · "
            f"{outcome.batch_count} batches"
        )
        if outcome.ai_triage_degraded:
            self.new_scan.append_progress(
                "[WARNING] Gemini triage was incomplete. Untriaged runtime candidates "
                "are preserved in Needs review; no clean result was inferred."
            )
            self.global_status.set_status("AI triage incomplete", "error")
            history_status = "Needs review"
        else:
            self.global_status.set_status("Audit complete", "good")
            history_status = "Completed"
        self.history.append(
            {
                "repository": self.repo_path,
                "findings": outcome.raw_finding_count,
                "batches": outcome.batch_count,
                "issues": len(outcome.report.issues),
                "status": history_status,
            }
        )
        self.dashboard.refresh()
        self.findings.refresh()
        self.high_risk.refresh()
        self.review_queue.refresh()
        self.non_runtime.refresh()
        self.reports.refresh()
        self.navigate("review_queue" if outcome.ai_triage_degraded else "findings")

    @Slot(str)
    def _scan_failed(self, message: str) -> None:
        self.new_scan.set_running(False)
        self.new_scan.append_progress(f"[ERROR] Audit failed: {message}")
        self.global_status.set_status("Audit failed", "error")
        self.history.append(
            {
                "repository": self.repo_path,
                "findings": "—",
                "batches": "—",
                "issues": "—",
                "status": "Failed",
            }
        )
        self._error(message)

    def export_report(self) -> None:
        if not self.outcome:
            self._error("Run an audit before exporting a report.")
            return
        destination, _ = QFileDialog.getSaveFileName(
            self,
            "Export AegisScan report",
            str(Path.home() / "aegisscan-report.json"),
            "JSON report (*.json)",
        )
        if not destination:
            return
        if not destination.endswith(".json"):
            destination += ".json"
        payload = {
            "summary": {
                "raw_semgrep_findings": self.outcome.raw_finding_count,
                "batches": self.outcome.batch_count,
                "failed_batches": self.outcome.failed_batches,
                "failed_batch_reasons": self.outcome.failed_batch_reasons,
                "ai_attempted_batches": self.outcome.ai_attempted_batches,
                "ai_successful_batches": self.outcome.ai_successful_batches,
                "ai_triage_degraded": self.outcome.ai_triage_degraded,
                "fixed_files": self.outcome.fixed_files,
                "pull_request_url": self.outcome.pull_request_url,
            },
            "report": self.outcome.report.model_dump(),
        }
        Path(destination).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.global_status.set_status("Report exported", "good")

    def show_about(self) -> None:
        QMessageBox.about(
            self,
            "About AegisScan",
            "<h2>AegisScan</h2>"
            f"<p>Version {__version__} (beta)</p>"
            "<p>Local-first controls with bounded Gemini triage of repository findings.</p>"
            "<p>Semgrep · Gemini · Pydantic · Deterministic patch safety</p>",
        )

    def _error(self, message: str) -> None:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("AegisScan")
        compact = " ".join(message.split())
        if len(compact) > 260:
            box.setText(compact[:257] + "…")
            box.setInformativeText("Open Details to inspect the complete diagnostic.")
            box.setDetailedText(message)
        else:
            box.setText(compact)
        box.exec()


def main() -> None:
    QApplication.setApplicationName("AegisScan")
    QApplication.setOrganizationName("AegisScan")
    application = QApplication.instance() or QApplication(sys.argv)
    application.setStyle("Fusion")
    window = AegisScanWindow()
    window.show()
    raise SystemExit(application.exec())


if __name__ == "__main__":
    main()
