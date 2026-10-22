"""State, path validation, and worker integration tests for the AEGIS GUI."""

import importlib.util
import os
import threading

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

if importlib.util.find_spec("PySide6") is None:
    pytest.skip("PySide6 is not installed; install the [gui] extra to run GUI tests",
                allow_module_level=True)

from PySide6.QtCore import QCoreApplication, QEvent, QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from aegis.gui.main_window import GuiState, MainWindow
from aegis.models import Finding, Severity
from aegis.scanner import ScanResult, ScanStatus


@pytest.fixture(scope="module")
def qapplication():
    """Return the process-wide Qt application instance."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def window(qapplication):
    main_window = MainWindow()
    yield main_window
    if main_window._worker is None:
        main_window.close()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    qapplication.processEvents()


def _wait_until(qapplication, predicate, timeout_ms=5000):
    """Process Qt events until a condition is true or the test times out."""
    loop = QEventLoop()
    timeout = QTimer()
    timeout.setSingleShot(True)
    timeout.timeout.connect(loop.quit)

    def check_condition():
        if predicate():
            loop.quit()
        else:
            QTimer.singleShot(1, check_condition)

    check_condition()
    if not predicate():
        timeout.start(timeout_ms)
        loop.exec()
    timeout.stop()
    assert predicate(), "Condition was not met before timeout"


def _finding() -> Finding:
    return Finding(
        id="test-rule:app.py:1",
        severity=Severity.HIGH,
        file="app.py",
        line=1,
        rule_id="test-rule",
        title="Test finding",
        description="A finding for GUI state tests.",
        evidence="raw secret that must not be displayed",
        redacted="token = '[REDACTED]'",
    )


def _start_result_scan(monkeypatch, window, project_path, result):
    monkeypatch.setattr(
        "aegis.gui.worker.run_scan",
        lambda _project_path: result,
    )
    window.path_row.set_path(project_path)
    window._start_scan()


def test_initial_state_is_ready(window):
    assert window.state is GuiState.READY
    assert window.progress_bar.isHidden()
    assert window.scan_button.isEnabled()
    assert window.path_row.isEnabled()


@pytest.mark.parametrize(
    "selected_path,expected_message",
    [
        (None, "Select a project directory."),
        (pytest.param("missing", "The selected directory does not exist.")),
        (pytest.param("file", "The selected path is not a directory.")),
    ],
)
def test_invalid_paths_are_rejected_inline(
    window, tmp_path, selected_path, expected_message
):
    if selected_path == "missing":
        path = tmp_path / "missing"
        window.path_row.set_path(path)
    elif selected_path == "file":
        path = tmp_path / "project.py"
        path.write_text("pass\n", encoding="utf-8")
        window.path_row.set_path(path)

    window._start_scan()

    assert window.state is GuiState.INVALID_PATH
    assert window.path_row.error_label.text() == expected_message
    assert window._worker is None


def test_valid_path_starts_worker_and_enters_scanning(
    window, monkeypatch, tmp_path, qapplication
):
    scan_started = threading.Event()
    allow_scan_to_finish = threading.Event()
    expected = ScanResult(project_path=tmp_path.resolve())
    calls = []

    def blocked_scan(path):
        calls.append(path)
        scan_started.set()
        assert allow_scan_to_finish.wait(timeout=5)
        return expected

    monkeypatch.setattr("aegis.gui.worker.run_scan", blocked_scan)
    window.path_row.set_path(tmp_path)

    window._start_scan()

    worker = window._worker
    assert worker is not None
    assert scan_started.wait(timeout=2)
    assert worker.isRunning()
    assert window.state is GuiState.SCANNING
    assert not window.progress_bar.isHidden()
    assert window.progress_bar.minimum() == 0
    assert window.progress_bar.maximum() == 0
    assert not window.scan_button.isEnabled()
    assert not window.path_row.isEnabled()

    allow_scan_to_finish.set()
    _wait_until(qapplication, lambda: window._worker is None)
    assert calls == [tmp_path]
    assert window.state is GuiState.EMPTY


def test_duplicate_scan_is_prevented(window, monkeypatch, tmp_path, qapplication):
    scan_started = threading.Event()
    allow_scan_to_finish = threading.Event()
    calls = []
    expected = ScanResult(project_path=tmp_path.resolve())

    def blocked_scan(path):
        calls.append(path)
        scan_started.set()
        assert allow_scan_to_finish.wait(timeout=5)
        return expected

    monkeypatch.setattr("aegis.gui.worker.run_scan", blocked_scan)
    window.path_row.set_path(tmp_path)
    window._start_scan()
    worker = window._worker
    assert worker is not None
    assert scan_started.wait(timeout=2)

    window._start_scan()

    assert window._worker is worker
    assert calls == [tmp_path]
    allow_scan_to_finish.set()
    _wait_until(qapplication, lambda: window._worker is None)
    assert calls == [tmp_path]


@pytest.mark.parametrize(
    "status,findings,expected_state",
    [
        (ScanStatus.SUCCESS, [_finding()], GuiState.SUCCESS),
        (ScanStatus.SUCCESS, [], GuiState.EMPTY),
        (ScanStatus.PARTIAL, [], GuiState.PARTIAL),
        (ScanStatus.FAILED, [], GuiState.FAILED),
    ],
)
def test_result_status_maps_to_gui_state(
    window, monkeypatch, tmp_path, qapplication, status, findings, expected_state
):
    result = ScanResult(
        project_path=tmp_path.resolve(),
        findings=findings,
        status=status,
    )

    _start_result_scan(monkeypatch, window, tmp_path, result)
    _wait_until(qapplication, lambda: window._worker is None)

    assert window.state is expected_state
    assert window.path_row.isEnabled()
    assert window.scan_button.isEnabled()
    assert window.progress_bar.isHidden()
    assert "raw secret" not in window.status_label.text()


def test_worker_error_sets_failed_state_without_displaying_raw_message(
    window, monkeypatch, tmp_path, qapplication
):
    def raise_error(_path):
        raise RuntimeError("secret-value in private source")

    monkeypatch.setattr("aegis.gui.worker.run_scan", raise_error)
    window.path_row.set_path(tmp_path)
    window._start_scan()
    _wait_until(qapplication, lambda: window._worker is None)

    assert window.state is GuiState.FAILED
    assert "secret-value" not in window.status_label.text()
    assert "private source" not in window.status_label.text()
    assert window.path_row.isEnabled()
    assert window.scan_button.isEnabled()
    assert window.progress_bar.isHidden()


def test_close_is_deferred_until_active_worker_finishes(
    window, monkeypatch, tmp_path, qapplication
):
    scan_started = threading.Event()
    allow_scan_to_finish = threading.Event()

    def blocked_scan(path):
        scan_started.set()
        assert allow_scan_to_finish.wait(timeout=5)
        return ScanResult(project_path=path.resolve())

    monkeypatch.setattr("aegis.gui.worker.run_scan", blocked_scan)
    window.path_row.set_path(tmp_path)
    window.show()
    window._start_scan()
    worker = window._worker
    assert worker is not None
    assert scan_started.wait(timeout=2)

    window.close()

    assert window.isVisible()
    assert worker.isRunning()
    assert window._worker is worker

    allow_scan_to_finish.set()
    _wait_until(
        qapplication,
        lambda: window._worker is None and not window.isVisible(),
    )
    assert window.state is GuiState.EMPTY
