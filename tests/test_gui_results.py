"""Tests for findings widgets and scan-result presentation."""

import importlib.util
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

if importlib.util.find_spec("PySide6") is None:
    pytest.skip("PySide6 is not installed; install the [gui] extra to run GUI tests",
                allow_module_level=True)

from PySide6.QtCore import QCoreApplication, QEvent, QEventLoop, QTimer, Qt
from PySide6.QtWidgets import QApplication, QLabel

from aegis.gui.styles import SEVERITY_COLORS
from aegis.gui.main_window import GuiState, MainWindow
from aegis.gui.widgets.finding_detail import FindingDetail
from aegis.gui.widgets.findings_table import FindingsTable
from aegis.gui.widgets.severity_chips import SeverityChips
from aegis.models import Finding, Severity
from aegis.scanner import ScanResult, ScanStatus, ScannerError


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
    *,
    rule_id: str = "AEGIS-TEST",
    file: str = "src/app.py",
    line: int | None = 8,
    severity: Severity = Severity.HIGH,
    title: str = "Example finding",
    description: str = "Description text",
    evidence: str = "RAW_SECRET_VALUE",
    redacted: str = "password = '[REDACTED]'",
    remediation: str = "Use a secure configuration source.",
) -> Finding:
    return Finding(
        id=f"{rule_id}:{file}:{line}",
        severity=severity,
        file=file,
        line=line,
        rule_id=rule_id,
        title=title,
        description=description,
        evidence=evidence,
        redacted=redacted,
        remediation=remediation,
    )


def _wait_until(qapplication, predicate, timeout_ms=5000):
    loop = QEventLoop()
    timeout = QTimer()
    timeout.setSingleShot(True)
    timeout.timeout.connect(loop.quit)

    def check():
        if predicate():
            loop.quit()
        else:
            QTimer.singleShot(1, check)

    check()
    if not predicate():
        timeout.start(timeout_ms)
        loop.exec()
    timeout.stop()
    assert predicate(), "Condition was not met before timeout"


def _present_result(monkeypatch, window, tmp_path, result, qapplication):
    monkeypatch.setattr(
        "aegis.gui.worker.run_scan",
        lambda _path: result,
    )
    window.path_row.set_path(tmp_path)
    window._start_scan()
    _wait_until(qapplication, lambda: window._worker is None)


def _widget_text(widget) -> str:
    return "\n".join(
        label.text()
        for label in widget.findChildren(QLabel)
    )


def test_findings_table_populates_model_and_preserves_finding_objects(qapplication):
    findings = [
        _finding(file="pkg/first.py", line=None, title="First"),
        _finding(file="pkg/second.py", line=22, title="Second"),
    ]
    table = FindingsTable()
    detail = FindingDetail()
    selected = []
    table.finding_selected.connect(selected.append)
    table.finding_selected.connect(detail.load_finding)
    table.selection_cleared.connect(detail.clear)

    table.load_findings(findings)

    assert table.model.rowCount() == 2
    assert table.model.columnCount() == 5
    assert [
        table.model.headerData(column, Qt.Orientation.Horizontal)
        for column in range(table.model.columnCount())
    ] == ["Severity", "Finding", "Rule", "File", "Line"]
    assert table.model.item(0, 3).text() == "pkg/first.py"
    assert table.model.item(0, 4).text() == "—"
    assert table.model.item(1, 4).text() == "22"
    assert table.model.item(0, 0).text() == "HIGH"
    assert (
        table.model.item(0, 0).background().color().name()
        == SEVERITY_COLORS["HIGH"][0]
    )

    table.table.setCurrentIndex(table.model.index(1, 0))
    assert selected == [findings[1]]
    assert detail.title_label.text() == "Second"
    table.table.clearSelection()
    assert detail.title_label.text() == "Select a finding to view its details."


def test_finding_detail_handles_missing_optional_fields():
    finding = _finding(
        line=None,
        description="",
        evidence="RAW_SECRET_VALUE",
        redacted="",
        remediation="",
    )
    detail = FindingDetail()

    detail.load_finding(finding)
    text = _widget_text(detail)

    assert detail.title_label.text() == "Example finding"
    assert detail.fields["line"].text() == "Not available"
    assert "Not provided." in detail.description_label.text()
    assert "No redacted evidence available." in detail.evidence_label.text()
    assert "No remediation guidance available." in detail.remediation_label.text()
    assert "RAW_SECRET_VALUE" not in text


def test_severity_counters_include_every_severity():
    findings = [
        _finding(severity=Severity.CRITICAL),
        _finding(rule_id="high-1", severity=Severity.HIGH),
        _finding(rule_id="high-2", severity=Severity.HIGH),
        _finding(severity=Severity.MEDIUM),
        _finding(severity=Severity.LOW),
        _finding(severity=Severity.INFO),
    ]
    chips = SeverityChips()

    chips.update_counts(findings)

    assert chips.counts() == {
        Severity.CRITICAL: 1,
        Severity.HIGH: 2,
        Severity.MEDIUM: 1,
        Severity.LOW: 1,
        Severity.INFO: 1,
    }


@pytest.mark.parametrize(
    "status,findings,expected_state,expected_banner",
    [
        (ScanStatus.SUCCESS, [_finding()], GuiState.SUCCESS, True),
        (ScanStatus.SUCCESS, [], GuiState.EMPTY, True),
        (ScanStatus.PARTIAL, [_finding()], GuiState.PARTIAL, True),
        (ScanStatus.PARTIAL, [], GuiState.PARTIAL, True),
        (ScanStatus.FAILED, [_finding()], GuiState.FAILED, True),
        (ScanStatus.FAILED, [], GuiState.FAILED, True),
    ],
)
def test_result_state_presentation(
    monkeypatch,
    window,
    tmp_path,
    qapplication,
    status,
    findings,
    expected_state,
    expected_banner,
):
    errors = (
        [
            ScannerError(
                scanner="bandit_runner",
                error_type="BanditError",
                message="Scanner failed with BanditError.",
            )
        ]
        if status in (ScanStatus.PARTIAL, ScanStatus.FAILED)
        else []
    )
    result = ScanResult(
        project_path=tmp_path.resolve(),
        findings=findings,
        status=status,
        errors=errors,
    )

    _present_result(monkeypatch, window, tmp_path, result, qapplication)

    assert window.state is expected_state
    assert window.result_banner.isHidden() == (not expected_banner)
    assert window.findings_splitter.isHidden() == (not bool(findings))
    assert window.severity_chips.isHidden() == (not bool(findings))
    if status is ScanStatus.PARTIAL:
        assert "incomplete" in window.result_banner.label.text().lower()
        assert "bandit_runner" in window.result_banner.label.text()
    if status is ScanStatus.FAILED:
        assert "failed" in window.result_banner.label.text().lower()
        assert window.findings_table.model.rowCount() == len(findings)
    if status is ScanStatus.SUCCESS and not findings:
        assert "no findings" in window.result_banner.label.text().lower()
    if status is ScanStatus.PARTIAL and not findings:
        assert not window.empty_results_label.isHidden()
        assert "No findings" in window.empty_results_label.text()


def test_worker_error_uses_generic_failure_presentation(
    monkeypatch, window, tmp_path, qapplication
):
    monkeypatch.setattr(
        "aegis.gui.worker.run_scan",
        lambda _path: (_ for _ in ()).throw(
            RuntimeError("RAW_SECRET_VALUE in source")
        ),
    )
    window.path_row.set_path(tmp_path)
    window._start_scan()
    _wait_until(qapplication, lambda: window._worker is None)

    assert window.state is GuiState.FAILED
    assert not window.result_banner.isHidden()
    assert "could not be completed" in window.result_banner.label.text()
    assert "RAW_SECRET_VALUE" not in _widget_text(window)


def test_severity_counts_update_between_scans_and_details_clear(
    monkeypatch, window, tmp_path, qapplication
):
    first = _finding(severity=Severity.CRITICAL, title="First selected")
    second = _finding(rule_id="second", severity=Severity.INFO, title="Second scan")
    results = iter(
        [
            ScanResult(
                project_path=tmp_path.resolve(),
                findings=[first, _finding(rule_id="high", severity=Severity.HIGH)],
                status=ScanStatus.SUCCESS,
            ),
            ScanResult(
                project_path=tmp_path.resolve(),
                findings=[second],
                status=ScanStatus.SUCCESS,
            ),
            ScanResult(
                project_path=tmp_path.resolve(),
                findings=[],
                status=ScanStatus.SUCCESS,
            ),
        ]
    )
    monkeypatch.setattr(
        "aegis.gui.worker.run_scan",
        lambda _path: next(results),
    )

    window.path_row.set_path(tmp_path)
    window._start_scan()
    _wait_until(qapplication, lambda: window._worker is None)
    assert window.severity_chips.counts()[Severity.CRITICAL] == 1
    assert window.severity_chips.counts()[Severity.HIGH] == 1
    assert window.finding_detail.title_label.text() == "First selected"
    window.findings_table.table.setCurrentIndex(
        window.findings_table.model.index(0, 0)
    )
    assert window.finding_detail.title_label.text() == "First selected"

    window._start_scan()
    assert window.finding_detail.title_label.text() != "First selected"
    _wait_until(qapplication, lambda: window._worker is None)
    assert window.severity_chips.counts()[Severity.CRITICAL] == 0
    assert window.severity_chips.counts()[Severity.INFO] == 1
    assert window.findings_table.model.rowCount() == 1

    window._start_scan()
    _wait_until(qapplication, lambda: window._worker is None)
    assert window.state is GuiState.EMPTY
    assert window.findings_table.model.rowCount() == 0
    assert window.severity_chips.counts() == {
        Severity.CRITICAL: 0,
        Severity.HIGH: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.INFO: 0,
    }
    assert window.finding_detail.title_label.text() != "First selected"


def test_detail_panel_only_displays_redacted_evidence(qapplication):
    finding = _finding()
    detail = FindingDetail()

    detail.load_finding(finding)

    assert finding.redacted in detail.evidence_label.text()
    assert finding.evidence not in _widget_text(detail)
