"""Focused tests for the optional AEGIS background scan worker."""

import importlib.util
import os
import threading
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

if importlib.util.find_spec("PySide6") is None:
    pytest.skip("PySide6 is not installed; install the [gui] extra to run GUI tests",
                allow_module_level=True)

from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from aegis.models import Finding, Severity
from aegis.scanner import ScanResult, ScanStatus
from aegis.gui.worker import ScanWorker


@pytest.fixture(scope="module")
def qapplication():
    """Return the process-wide Qt application instance."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _wait_for_signal(worker, signal):
    """Run the GUI event loop until the expected result and thread finish."""
    loop = QEventLoop()
    received = []
    finished = []
    timed_out = []

    def on_signal(value):
        received.append(value)
        if finished:
            loop.quit()

    def on_finished():
        finished.append(True)
        if received:
            loop.quit()

    def on_timeout():
        timed_out.append(True)
        loop.quit()

    signal.connect(on_signal)
    worker.finished.connect(on_finished)
    timeout = QTimer()
    timeout.setSingleShot(True)
    timeout.timeout.connect(on_timeout)
    timeout.start(5000)
    worker.start()
    while not (received and finished) and not timed_out:
        loop.exec()
    timeout.stop()
    signal.disconnect(on_signal)
    worker.finished.disconnect(on_finished)
    assert not timed_out, "Worker did not finish before timeout"
    assert received, "Worker did not emit its expected signal"
    return received[0]


@pytest.mark.parametrize(
    "status,has_findings",
    [
        (ScanStatus.SUCCESS, True),
        (ScanStatus.PARTIAL, False),
        (ScanStatus.FAILED, False),
    ],
)
def test_worker_emits_each_scan_result_status(
    qapplication, monkeypatch, tmp_path, status, has_findings
):
    findings = (
        [
            Finding(
                id="test-rule:app.py:1",
                severity=Severity.HIGH,
                file="app.py",
                line=1,
                rule_id="test-rule",
                title="Test finding",
                description="A test finding.",
                redacted="token = '[REDACTED]'",
            )
        ]
        if has_findings
        else []
    )
    expected = ScanResult(
        project_path=tmp_path.resolve(),
        findings=findings,
        status=status,
    )
    calls = []

    def scan(project_path: Path) -> ScanResult:
        calls.append(project_path)
        return expected

    monkeypatch.setattr("aegis.gui.worker.run_scan", scan)
    worker = ScanWorker(tmp_path)

    result = _wait_for_signal(worker, worker.scan_complete)

    assert result is expected
    assert result.status is status
    assert result.findings == findings
    assert calls == [tmp_path]


def test_worker_reports_invalid_path_without_exposing_exception_message(
    qapplication, tmp_path
):
    missing_path = tmp_path / "missing-project"
    worker = ScanWorker(missing_path)

    message = _wait_for_signal(worker, worker.scan_error)

    assert message == "Invalid project path. Select an existing directory."
    assert str(missing_path) not in message


def test_worker_reports_unexpected_exception_without_raw_message(
    qapplication, monkeypatch, tmp_path
):
    def scan(_project_path: Path) -> ScanResult:
        raise RuntimeError("private source content and secret-value")

    monkeypatch.setattr("aegis.gui.worker.run_scan", scan)
    worker = ScanWorker(tmp_path)

    message = _wait_for_signal(worker, worker.scan_error)

    assert message == "The scan could not be completed (RuntimeError)."
    assert "private source content" not in message
    assert "secret-value" not in message


def test_worker_scans_off_gui_thread_without_blocking_event_loop(
    qapplication, monkeypatch, tmp_path
):
    gui_thread_id = threading.get_ident()
    scan_thread_ids = []
    gui_timer_fired = []
    expected = ScanResult(project_path=tmp_path.resolve())

    def scan(_project_path: Path) -> ScanResult:
        scan_thread_ids.append(threading.get_ident())
        time.sleep(0.05)
        return expected

    monkeypatch.setattr("aegis.gui.worker.run_scan", scan)
    worker = ScanWorker(tmp_path)
    QTimer.singleShot(0, lambda: gui_timer_fired.append(True))

    result = _wait_for_signal(worker, worker.scan_complete)

    assert result is expected
    assert scan_thread_ids
    assert scan_thread_ids[0] != gui_thread_id
    assert gui_timer_fired == [True]
