"""Main window and scan lifecycle state management for the AEGIS GUI."""

from __future__ import annotations

import enum
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QTimer, Qt, Slot
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QProgressBar,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from aegis.gui.styles import (
    CARD_PADDING,
    SECTION_GAP,
    WINDOW_PADDING,
    build_stylesheet,
)
from aegis.gui.widgets.banner import Banner, BannerStyle
from aegis.gui.widgets.finding_detail import FindingDetail
from aegis.gui.widgets.findings_table import FindingsTable
from aegis.gui.widgets.path_row import PathRow, ReportPathRow
from aegis.gui.widgets.severity_chips import SeverityChips
from aegis.report import ReportError, UnsafeOutputPathError, write_report
from aegis.scanner import ScanResult, ScanStatus

if TYPE_CHECKING:
    from aegis.gui.worker import ScanWorker


class GuiState(enum.Enum):
    """Visible lifecycle states for the desktop application."""

    READY = "READY"
    SCANNING = "SCANNING"
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    EMPTY = "EMPTY"
    INVALID_PATH = "INVALID_PATH"


class MainWindow(QMainWindow):
    """Dark desktop workspace that runs scans asynchronously and presents results."""

    def __init__(self) -> None:
        super().__init__()
        from aegis.gui.main import APPLICATION_TITLE, create_application_icon

        self.setWindowTitle(APPLICATION_TITLE)
        self.setWindowIcon(create_application_icon())
        self.setMinimumSize(900, 640)
        self.setStyleSheet(build_stylesheet())

        self._state = GuiState.READY
        self._worker: ScanWorker | None = None
        self._worker_outcome_received = False
        self._worker_finished = False
        self._close_when_finished = False
        self._result: ScanResult | None = None
        self._automatic_report_path: Path | None = None

        central_widget = QWidget(self)
        central_widget.setObjectName("appSurface")
        central_layout = QVBoxLayout(central_widget)
        central_layout.setContentsMargins(
            WINDOW_PADDING, WINDOW_PADDING, WINDOW_PADDING, WINDOW_PADDING
        )
        central_layout.setSpacing(SECTION_GAP)

        header = QFrame(central_widget)
        header.setObjectName("headerBar")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 8, 12, 8)
        header_layout.setSpacing(10)

        wordmark = QLabel("A E G I S", header)
        wordmark.setObjectName("wordmark")
        header_layout.addWidget(wordmark)

        subtitle = QLabel("Application Security & Inspection System", header)
        subtitle.setObjectName("brandSubtitle")
        header_layout.addWidget(subtitle)
        header_layout.addStretch()

        privacy_label = QLabel(
            "Local scan · source code never leaves this machine", header
        )
        privacy_label.setObjectName("privacyLabel")
        header_layout.addWidget(privacy_label)
        central_layout.addWidget(header)

        input_card = self._create_card()
        input_card.setObjectName("pathCard")
        input_layout = QHBoxLayout(input_card)
        input_layout.setContentsMargins(CARD_PADDING, 8, CARD_PADDING, 8)
        input_layout.setSpacing(10)

        project_group = QWidget(input_card)
        project_layout = QVBoxLayout(project_group)
        project_layout.setContentsMargins(0, 0, 0, 0)
        project_layout.setSpacing(4)
        project_label = QLabel("PROJECT FOLDER", project_group)
        project_label.setObjectName("sectionLabel")
        project_layout.addWidget(project_label)

        self.path_row = PathRow(project_group)
        self.path_row.path_changed.connect(self._on_path_changed)
        project_layout.addWidget(self.path_row)
        input_layout.addWidget(project_group, 1)

        report_group = QWidget(input_card)
        report_layout = QVBoxLayout(report_group)
        report_layout.setContentsMargins(0, 0, 0, 0)
        report_layout.setSpacing(4)
        report_label = QLabel("REPORT OUTPUT", report_group)
        report_label.setObjectName("sectionLabel")
        report_layout.addWidget(report_label)

        self.report_path_row = ReportPathRow(report_group)
        self.report_path_row.path_changed.connect(self._on_report_path_changed)
        report_layout.addWidget(self.report_path_row)
        input_layout.addWidget(report_group, 1)

        self.scan_button = QPushButton("Scan Project", input_card)
        self.scan_button.setObjectName("scanButton")
        self.scan_button.clicked.connect(self._start_scan)
        input_layout.addWidget(self.scan_button, 0, Qt.AlignmentFlag.AlignBottom)
        central_layout.addWidget(input_card)

        self.progress_bar = QProgressBar(central_widget)
        self.progress_bar.setObjectName("scanProgress")
        self.progress_bar.setRange(0, 0)
        self.progress_bar.hide()
        central_layout.addWidget(self.progress_bar)

        self.status_label = QLabel(central_widget)
        self.status_label.setObjectName("statusMessage")
        self.status_label.setWordWrap(True)
        central_layout.addWidget(self.status_label)

        self.results_card = self._create_card()
        self.results_card.setObjectName("placeholderCard")
        results_layout = QVBoxLayout(self.results_card)
        results_layout.setContentsMargins(
            CARD_PADDING, CARD_PADDING, CARD_PADDING, CARD_PADDING
        )
        results_layout.setSpacing(8)

        self.result_banner = Banner(BannerStyle.INFO, "", self.results_card)
        self.result_banner.hide()
        results_layout.addWidget(self.result_banner)

        summary_row = QHBoxLayout()
        summary_row.setContentsMargins(0, 0, 0, 0)
        self.finding_count_label = QLabel("", self.results_card)
        self.finding_count_label.setObjectName("findingCount")
        summary_row.addWidget(self.finding_count_label)

        self.severity_chips = SeverityChips(self.results_card)
        self.severity_chips.hide()
        summary_row.addWidget(self.severity_chips)
        summary_row.addStretch()
        results_layout.addLayout(summary_row)

        self.findings_splitter = QSplitter(self.results_card)
        self.findings_splitter.setObjectName("findingsSplitter")
        self.findings_splitter.setOrientation(Qt.Orientation.Horizontal)
        self.findings_table = FindingsTable(self.findings_splitter)
        self.finding_detail = FindingDetail(self.findings_splitter)
        self.findings_table.setMinimumWidth(230)
        self.finding_detail.setMinimumWidth(230)
        self.findings_splitter.addWidget(self.findings_table)
        self.findings_splitter.addWidget(self.finding_detail)
        self.findings_splitter.setStretchFactor(0, 65)
        self.findings_splitter.setStretchFactor(1, 35)
        self.findings_splitter.setChildrenCollapsible(False)
        self.findings_splitter.setSizes([550, 297])
        self.findings_table.finding_selected.connect(
            self.finding_detail.load_finding
        )
        self.findings_table.selection_cleared.connect(self.finding_detail.clear)
        results_layout.addWidget(self.findings_splitter, 1)

        self.empty_results_label = QLabel(
            "Choose a project folder to inspect its findings.",
            self.results_card,
        )
        self.empty_results_label.setObjectName("secondaryText")
        self.empty_results_label.setWordWrap(True)
        results_layout.addWidget(self.empty_results_label)

        report_footer = QHBoxLayout()
        report_footer.setContentsMargins(0, 0, 0, 0)
        self.report_status_label = QLabel("", self.results_card)
        self.report_status_label.setObjectName("reportStatus")
        report_footer.addWidget(self.report_status_label)
        report_footer.addStretch()
        self.save_report_button = QPushButton("Save JSON report", self.results_card)
        self.save_report_button.setObjectName("saveReportButton")
        self.save_report_button.setEnabled(False)
        self.save_report_button.clicked.connect(self._save_report)
        report_footer.addWidget(self.save_report_button)
        results_layout.addLayout(report_footer)

        central_layout.addWidget(self.results_card, 1)

        self.setCentralWidget(central_widget)
        self._clear_result_presentation()
        self._set_state(GuiState.READY)

    @property
    def state(self) -> GuiState:
        """Current GUI lifecycle state."""
        return self._state

    def _create_card(self) -> QFrame:
        card = QFrame(self)
        card.setObjectName("placeholderCard")
        return card

    def _set_state(self, state: GuiState) -> None:
        self._state = state
        self.progress_bar.setVisible(state is GuiState.SCANNING)
        self.scan_button.setText(
            "Scanning…" if state is GuiState.SCANNING else "Scan Project"
        )
        if state is GuiState.SCANNING:
            project_path = self.path_row.path()
            project_name = project_path.name if project_path is not None else "project"
            self.status_label.setText(
                f"Scanning {project_name}… Both scanner engines are running locally. "
                "Detailed progress is not available."
            )
        elif state is GuiState.READY:
            project_path = self.path_row.path()
            report_path = self.report_path_row.path()
            ready_to_scan = (
                project_path is not None
                and project_path.exists()
                and project_path.is_dir()
                and report_path is not None
                and not self._report_path_is_inside_project(report_path, project_path)
            )
            self.status_label.setText(
                "Ready to scan this project."
                if ready_to_scan
                else "Choose a project folder and report location to begin."
            )
        elif state is GuiState.SUCCESS:
            self.status_label.setText("Scan completed successfully.")
        elif state is GuiState.EMPTY:
            self.status_label.setText(
                "Scan completed with no findings. This is not proof the project is secure."
            )
        elif state is GuiState.PARTIAL:
            self.status_label.setText(
                "Scan completed with partial results. Review the warning below."
            )
        elif state is GuiState.FAILED:
            self.status_label.setText(
                "The scan could not be completed. Check the project and try again."
            )
        elif state is GuiState.INVALID_PATH:
            self.status_label.setText(
                "Please select a valid project directory and report destination."
            )

    def _start_scan(self) -> None:
        if self._worker is not None:
            return

        project_path = self.path_row.path()
        if project_path is None:
            self.path_row.show_error("Select a project directory.")
            self._set_state(GuiState.INVALID_PATH)
            return
        if not project_path.exists():
            self.path_row.show_error("The selected directory does not exist.")
            self._set_state(GuiState.INVALID_PATH)
            return
        if not project_path.is_dir():
            self.path_row.show_error("The selected path is not a directory.")
            self._set_state(GuiState.INVALID_PATH)
            return
        report_path = self.report_path_row.path()
        if report_path is None:
            self.report_path_row.show_error("Choose a report output location.")
            self._set_state(GuiState.INVALID_PATH)
            return
        if self._report_path_is_inside_project(report_path, project_path):
            self.report_path_row.show_error(
                "The report must be saved outside the scanned project."
            )
            self._set_state(GuiState.INVALID_PATH)
            return
        self.path_row.clear_error()
        self.report_path_row.clear_error()

        from aegis.gui.worker import ScanWorker

        worker = ScanWorker(project_path, parent=self)
        self._worker = worker
        self._worker_outcome_received = False
        self._worker_finished = False
        self.path_row.setEnabled(False)
        self.report_path_row.setEnabled(False)
        self.scan_button.setEnabled(False)
        self._set_state(GuiState.SCANNING)

        worker.scan_complete.connect(self._on_scan_complete)
        worker.scan_error.connect(self._on_scan_error)
        worker.finished.connect(self._on_worker_finished)
        self._clear_result_presentation()
        worker.start()

    @Slot(object)
    def _on_scan_complete(self, result: ScanResult) -> None:
        self._worker_outcome_received = True
        self._result = result
        if result.status is ScanStatus.SUCCESS:
            state = GuiState.SUCCESS if result.findings else GuiState.EMPTY
        elif result.status is ScanStatus.PARTIAL:
            state = GuiState.PARTIAL
        else:
            state = GuiState.FAILED
        self._set_state(state)
        self._present_scan_result(result, state)
        self._complete_worker_lifecycle()

    @Slot(str)
    def _on_scan_error(self, _message: str) -> None:
        self._worker_outcome_received = True
        self._set_state(GuiState.FAILED)
        self._clear_result_presentation()
        self._show_banner(
            BannerStyle.FAILED,
            "The scan could not be completed. Check the project and try again.",
        )
        self.empty_results_label.setText(
            "No scan results are available because the scan did not complete."
        )
        self.empty_results_label.show()
        self._complete_worker_lifecycle()

    def _clear_result_presentation(self) -> None:
        self._result = None
        self.result_banner.hide()
        self.severity_chips.hide()
        self.severity_chips.update_counts([])
        self.findings_splitter.hide()
        self.findings_table.clear()
        self.finding_detail.clear()
        self.finding_count_label.clear()
        self.empty_results_label.hide()
        self.empty_results_label.setText(
            "Choose a project folder to inspect its findings."
        )
        self.report_status_label.clear()
        self.save_report_button.setEnabled(False)

    def _present_scan_result(
        self,
        result: ScanResult,
        state: GuiState,
    ) -> None:
        findings = result.findings
        self.findings_table.load_findings(findings)
        self.finding_detail.clear()
        self.severity_chips.update_counts(findings)
        count = len(findings)
        self.finding_count_label.setText(
            f"{count} finding{'s' if count != 1 else ''}"
        )
        self.save_report_button.setEnabled(state is not GuiState.FAILED)

        if findings:
            self.severity_chips.show()
            self.findings_splitter.show()
            if self.findings_table.model.rowCount():
                self.findings_table.table.setCurrentIndex(
                    self.findings_table.model.index(0, 0)
                )

        if state is GuiState.EMPTY:
            self._show_banner(
                BannerStyle.INFO,
                "NO FINDINGS · Both scanners completed and reported nothing. "
                "This is not proof the code is secure.",
            )
            self.empty_results_label.setText(
                "The scan completed successfully and returned no findings."
            )
            self.empty_results_label.show()
        elif state is GuiState.PARTIAL:
            self._show_banner(
                BannerStyle.PARTIAL,
                self._scanner_error_message(
                    result,
                    "The scan is incomplete. Results may not include all issues.",
                ),
            )
            if not findings:
                self.empty_results_label.setText(
                    "No findings were returned by the scanner that completed."
                )
                self.empty_results_label.show()
        elif state is GuiState.FAILED:
            self._show_banner(
                BannerStyle.FAILED,
                self._scanner_error_message(
                    result,
                    "All scan engines failed. Returned findings may be incomplete.",
                ),
            )
            if not findings:
                self.empty_results_label.setText(
                    "No findings are available from the failed scan."
                )
                self.empty_results_label.show()
        elif state is GuiState.SUCCESS:
            self._show_banner(
                BannerStyle.INFO,
                "SCAN COMPLETED · Bandit and secret rules both ran.",
            )
            self.empty_results_label.hide()

    def _scanner_error_message(self, result: ScanResult, fallback: str) -> str:
        if not result.errors:
            return fallback
        details = [
            f"{error.scanner}: {error.message}"
            for error in result.errors
        ]
        return f"{fallback} {' '.join(details)}"

    def _show_banner(self, style: BannerStyle, message: str) -> None:
        self.result_banner.set_content(style, message)
        self.result_banner.show()

    @staticmethod
    def _report_path_is_inside_project(
        report_path: Path,
        project_path: Path,
    ) -> bool:
        """Check the destination boundary without traversing project contents."""
        try:
            report_path.resolve(strict=False).relative_to(
                project_path.resolve(strict=False)
            )
        except ValueError:
            return False
        except (OSError, RuntimeError):
            return True
        return True

    def _save_report(self) -> None:
        result = self._result
        report_path = self.report_path_row.path()
        if result is None or result.status is ScanStatus.FAILED:
            return
        if report_path is None:
            self.report_path_row.show_error("Choose a report output location.")
            return
        if self._report_path_is_inside_project(report_path, result.project_path):
            self.report_path_row.show_error(
                "The report must be saved outside the scanned project."
            )
            return

        self.report_path_row.clear_error()
        try:
            write_report(result, report_path)
        except UnsafeOutputPathError:
            self.report_path_row.show_error(
                "The report must be saved outside the scanned project."
            )
        except ReportError:
            self.report_status_label.setText(
                "The report could not be saved. Check the selected destination."
            )
        else:
            self.report_status_label.setText(f"Report saved · {report_path.name}")

    def _on_report_path_changed(self, _path: object) -> None:
        self.report_path_row.clear_error()
        self.report_status_label.clear()
        project_path = self.path_row.path()
        report_path = self.report_path_row.path()
        if (
            project_path is not None
            and project_path.exists()
            and project_path.is_dir()
            and report_path is not None
        ):
            if self._report_path_is_inside_project(report_path, project_path):
                self.report_path_row.show_error(
                    "The report must be saved outside the scanned project."
                )
                self._set_state(GuiState.INVALID_PATH)
            elif self._state is GuiState.INVALID_PATH:
                self._set_state(GuiState.READY)

    @staticmethod
    def _default_report_path(project_path: Path) -> Path:
        report_path = (
            Path.home()
            / "aegis-reports"
            / f"{project_path.name or 'project'}.json"
        )
        if MainWindow._report_path_is_inside_project(report_path, project_path):
            report_path = (
                project_path.parent
                / "aegis-reports"
                / f"{project_path.name or 'project'}.json"
            )
        return report_path

    @Slot()
    def _on_worker_finished(self) -> None:
        self._worker_finished = True
        if not self._worker_outcome_received:
            QTimer.singleShot(0, self._handle_finished_without_outcome)
        self._complete_worker_lifecycle()

    @Slot()
    def _handle_finished_without_outcome(self) -> None:
        if self._worker is None or self._worker_outcome_received:
            return
        self._worker_outcome_received = True
        self._set_state(GuiState.FAILED)
        self._complete_worker_lifecycle()

    def _complete_worker_lifecycle(self) -> None:
        if not (self._worker_finished and self._worker_outcome_received):
            return

        worker = self._worker
        self._worker = None
        if worker is not None:
            worker.deleteLater()
        self.path_row.setEnabled(True)
        self.report_path_row.setEnabled(True)
        self.scan_button.setEnabled(True)

        if self._close_when_finished:
            self.close()

    def _on_path_changed(self, _path: object) -> None:
        self.path_row.clear_error()
        if self._result is not None:
            self._clear_result_presentation()
        project_path = self.path_row.path()
        if (
            self.report_path_row.path() is None
            or self.report_path_row.path() == self._automatic_report_path
        ):
            if project_path is None:
                self._automatic_report_path = None
                self.report_path_row.set_path(None)
            else:
                self._automatic_report_path = self._default_report_path(project_path)
                self.report_path_row.set_path(self._automatic_report_path)
        self._set_state(GuiState.READY)

    def closeEvent(self, event: QCloseEvent) -> None:
        """Defer closing while a scan is active; never destroy a running thread."""
        if self._worker is not None:
            self._close_when_finished = True
            self.status_label.setText(
                "The scan is still running. This window will close when it finishes."
            )
            event.ignore()
            return
        event.accept()
