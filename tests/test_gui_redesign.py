"""Tests for the reference-inspired AEGIS desktop workspace."""

import importlib.util
import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

if importlib.util.find_spec("PySide6") is None:
    pytest.skip(
        "PySide6 is not installed; install the [gui] extra to run GUI tests",
        allow_module_level=True,
    )

from PySide6.QtCore import QCoreApplication, QEvent, QEventLoop, QTimer, Qt
from PySide6.QtWidgets import QApplication

from aegis.gui.main_window import GuiState, MainWindow
from aegis.gui.widgets.findings_table import FindingsTable
from aegis.models import Finding, Severity
from aegis.scanner import ScanResult, ScanStatus


@pytest.fixture(scope="module")
def qapplication():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def window(qapplication):
    main_window = MainWindow()
    yield main_window
    try:
        if main_window._worker is None:
            main_window.close()
    finally:
        main_window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        qapplication.processEvents()


def _finding(
    title: str,
    file: str,
    severity: Severity,
    line: int | None = 1,
) -> Finding:
    return Finding(
        id=f"{title}:{file}:{line}",
        severity=severity,
        file=file,
        line=line,
        rule_id=f"RULE-{title.upper().replace(' ', '-')}",
        title=title,
        description="Safe test description.",
        evidence="RAW_TEST_SECRET",
        redacted="value = '[REDACTED]'",
    )


def _wait_for_worker(qapplication, window):
    loop = QEventLoop()
    timeout = QTimer()
    timeout.setSingleShot(True)
    timeout.timeout.connect(loop.quit)

    def check():
        if window._worker is None:
            loop.quit()
        else:
            QTimer.singleShot(1, check)

    check()
    if window._worker is not None:
        timeout.start(5000)
        loop.exec()
    timeout.stop()
    assert window._worker is None


def test_workspace_matches_dark_compact_reference(window, qapplication):
    finding = _finding("issue", "app.py", Severity.HIGH)
    window._present_scan_result(
        ScanResult(project_path=Path.cwd(), findings=[finding]),
        GuiState.SUCCESS,
    )
    window.resize(900, 640)
    window.show()
    qapplication.processEvents()

    assert window.minimumSize().width() == 900
    assert window.minimumSize().height() == 640
    assert window.findChild(type(window.status_label), "privacyLabel").text() == (
        "Local scan · source code never leaves this machine"
    )
    assert window.path_row.path_edit.objectName() == "projectPath"
    assert window.report_path_row.path_edit.objectName() == "reportPath"
    assert min(window.findings_splitter.sizes()) >= 230


def test_default_report_destination_is_outside_selected_project(
    window, tmp_path
):
    project = tmp_path / "source-project"
    project.mkdir()

    window.path_row.set_path(project)

    report_path = window.report_path_row.path()
    assert report_path is not None
    assert not report_path.resolve().is_relative_to(project.resolve())
    assert report_path.suffix == ".json"


def test_report_inside_project_is_rejected_before_scanning(window, tmp_path):
    project = tmp_path / "source-project"
    project.mkdir()
    window.path_row.set_path(project)
    window.report_path_row.set_path(project / "aegis-report.json")

    window._start_scan()

    assert window.state is GuiState.INVALID_PATH
    assert window._worker is None
    assert "outside the scanned project" in window.report_path_row.error_label.text()

    window.report_path_row.set_path(tmp_path / "outside-report.json")
    assert window.state is GuiState.READY
    assert window.report_path_row.error_label.isHidden()


def test_search_filter_and_sort_keep_findings_bound_to_rows(qapplication):
    findings = [
        _finding("zeta issue", "z.py", Severity.LOW, 4),
        _finding("alpha issue", "a.py", Severity.CRITICAL, 8),
        _finding("beta issue", "b.py", Severity.HIGH, 2),
    ]
    table = FindingsTable()
    selected = []
    table.finding_selected.connect(selected.append)

    table.load_findings(findings)
    table.sort_combo.setCurrentText("File")

    assert table.model.item(0, 3).text() == "a.py"
    assert table.model.item(0, 0).data(Qt.ItemDataRole.UserRole) is findings[1]
    table.filter_buttons[Severity.HIGH].click()
    assert table.model.rowCount() == 1
    assert table.model.item(0, 0).data(Qt.ItemDataRole.UserRole) is findings[2]

    table.filter_buttons[None].click()
    table.search_edit.setText("z.py")
    assert table.model.rowCount() == 1
    assert table.model.item(0, 0).data(Qt.ItemDataRole.UserRole) is findings[0]
    table.table.setCurrentIndex(table.model.index(0, 0))
    assert selected == [findings[0]]
    table.close()
    table.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    qapplication.processEvents()


def test_success_result_can_be_saved_through_existing_report_writer(
    window, monkeypatch, tmp_path, qapplication
):
    project = tmp_path / "project"
    project.mkdir()
    output = tmp_path / "reports" / "result.json"
    finding = _finding("issue", "app.py", Severity.HIGH)
    result = ScanResult(
        project_path=project.resolve(),
        findings=[finding],
        status=ScanStatus.SUCCESS,
    )
    monkeypatch.setattr("aegis.gui.worker.run_scan", lambda _path: result)
    calls = []
    monkeypatch.setattr(
        "aegis.gui.main_window.write_report",
        lambda scan_result, destination: calls.append((scan_result, destination)),
    )
    window.path_row.set_path(project)
    window.report_path_row.set_path(output)

    window._start_scan()
    _wait_for_worker(qapplication, window)
    assert window.state is GuiState.SUCCESS
    assert window.finding_count_label.text() == "1 finding"
    assert window.save_report_button.isEnabled()

    window.save_report_button.click()

    assert calls == [(result, output)]
    assert window.report_status_label.text() == "Report saved · result.json"


def test_failed_result_keeps_findings_but_does_not_offer_report_save(
    window, monkeypatch, tmp_path, qapplication
):
    project = tmp_path / "project"
    project.mkdir()
    result = ScanResult(
        project_path=project.resolve(),
        findings=[_finding("returned issue", "app.py", Severity.MEDIUM)],
        status=ScanStatus.FAILED,
    )
    monkeypatch.setattr("aegis.gui.worker.run_scan", lambda _path: result)
    window.path_row.set_path(project)

    window._start_scan()
    _wait_for_worker(qapplication, window)

    assert window.state is GuiState.FAILED
    assert window.findings_table.model.rowCount() == 1
    assert not window.save_report_button.isEnabled()
