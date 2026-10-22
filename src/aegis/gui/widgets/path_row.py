"""Project directory selection row for the AEGIS desktop GUI."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class PathRow(QWidget):
    """Read-only project path field with a directory picker and inline error."""

    path_changed = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self.path_edit = QLineEdit(self)
        self.path_edit.setObjectName("projectPath")
        self.path_edit.setReadOnly(True)
        self.path_edit.setPlaceholderText("Select a project directory")

        self.browse_button = QPushButton("Browse…", self)
        self.browse_button.setObjectName("browseButton")
        self.browse_button.clicked.connect(self._browse)

        path_layout = QHBoxLayout()
        path_layout.setContentsMargins(0, 0, 0, 0)
        path_layout.addWidget(self.path_edit, 1)
        path_layout.addWidget(self.browse_button)

        self.error_label = QLabel(self)
        self.error_label.setObjectName("inlineError")
        self.error_label.setWordWrap(True)
        self.error_label.hide()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addLayout(path_layout)
        layout.addWidget(self.error_label)

    def path(self) -> Path | None:
        """Return the selected path, or ``None`` when no path is selected."""
        value = self.path_edit.text().strip()
        return Path(value) if value else None

    def set_path(self, path: Path | None) -> None:
        """Set the selected path and notify listeners."""
        self.path_edit.setText(str(path) if path is not None else "")
        self.clear_error()
        self.path_changed.emit(path)

    def show_error(self, message: str) -> None:
        """Display an inline path validation message."""
        self.error_label.setText(message)
        self.error_label.show()

    def clear_error(self) -> None:
        """Hide and clear the inline path validation message."""
        self.error_label.clear()
        self.error_label.hide()

    def _browse(self) -> None:
        selected = QFileDialog.getExistingDirectory(
            self,
            "Select project directory",
            str(Path.home()),
        )
        if selected:
            self.set_path(Path(selected))


class ReportPathRow(QWidget):
    """Report destination row with a save-file picker and inline validation."""

    path_changed = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self.path_edit = QLineEdit(self)
        self.path_edit.setObjectName("reportPath")
        self.path_edit.setReadOnly(True)
        self.path_edit.setPlaceholderText("Choose an output location")

        self.browse_button = QPushButton("Browse…", self)
        self.browse_button.setObjectName("reportBrowseButton")
        self.browse_button.clicked.connect(self._browse)

        path_layout = QHBoxLayout()
        path_layout.setContentsMargins(0, 0, 0, 0)
        path_layout.setSpacing(6)
        path_layout.addWidget(self.path_edit, 1)
        path_layout.addWidget(self.browse_button)

        self.error_label = QLabel(self)
        self.error_label.setObjectName("inlineError")
        self.error_label.setWordWrap(True)
        self.error_label.hide()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addLayout(path_layout)
        layout.addWidget(self.error_label)

    def path(self) -> Path | None:
        """Return the selected report path, or ``None`` if it is empty."""
        value = self.path_edit.text().strip()
        return Path(value) if value else None

    def set_path(self, path: Path | None) -> None:
        """Set the report destination and notify listeners."""
        self.path_edit.setText(str(path) if path is not None else "")
        self.clear_error()
        self.path_changed.emit(path)

    def show_error(self, message: str) -> None:
        """Display an inline report destination validation message."""
        self.error_label.setText(message)
        self.error_label.show()

    def clear_error(self) -> None:
        """Hide and clear the inline report destination error."""
        self.error_label.clear()
        self.error_label.hide()

    def _browse(self) -> None:
        current = str(self.path()) if self.path() is not None else ""
        selected, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "Choose JSON report destination",
            current,
            "JSON files (*.json)",
        )
        if selected:
            self.set_path(Path(selected))
