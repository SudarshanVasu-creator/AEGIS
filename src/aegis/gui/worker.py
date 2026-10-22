"""Background scan worker for the AEGIS desktop GUI."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal

from aegis.scanner import ScanResult, run_scan


class ScanWorker(QThread):
    """Run one scan in a background thread and report its outcome via signals.

    ``scan_complete`` carries every returned :class:`ScanResult`, including
    PARTIAL and FAILED statuses. ``scan_error`` is reserved for exceptions
    raised by ``run_scan``. Its message is sanitized: invalid paths receive a
    fixed prompt, and unexpected failures include only the exception type.
    """

    scan_complete = Signal(object)
    scan_error = Signal(str)

    def __init__(self, project_path: Path, parent=None) -> None:
        super().__init__(parent)
        self._project_path: Path | None = project_path

    def run(self) -> None:
        """Execute the scan on this worker thread."""
        project_path = self._project_path
        self._project_path = None

        if project_path is None:
            self.scan_error.emit("The scan worker has no project path.")
            return

        try:
            result = run_scan(project_path)
        except ValueError:
            self.scan_error.emit(
                "Invalid project path. Select an existing directory."
            )
        except Exception as exc:
            self.scan_error.emit(
                f"The scan could not be completed ({type(exc).__name__})."
            )
        else:
            self.scan_complete.emit(result)
