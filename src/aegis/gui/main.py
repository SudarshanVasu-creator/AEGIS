"""Application entry point for the AEGIS desktop GUI."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from aegis.gui.styles import (
    BASE_FONT_SIZE,
    FONT_FAMILY,
    build_stylesheet,
)

if TYPE_CHECKING:
    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QMainWindow

APPLICATION_TITLE = "AEGIS — Application Security & Inspection System"


def icon_path(filename: str = "aegis.ico") -> Path:
    """Resolve a GUI icon from the source tree, install prefix, or PyInstaller bundle."""
    bundle_root = getattr(sys, "_MEIPASS", None)
    if bundle_root is not None:
        return Path(bundle_root) / "assets" / "icons" / filename

    source_tree_path = (
        Path(__file__).resolve().parents[3] / "assets" / "icons" / filename
    )
    if source_tree_path.is_file():
        return source_tree_path

    return Path(sys.prefix) / "assets" / "icons" / filename


def create_application_icon() -> QIcon:
    """Load the supplied Windows icon for application and window chrome."""
    from PySide6.QtGui import QIcon

    path = icon_path()
    icon = QIcon(str(path))
    if icon.isNull():
        raise FileNotFoundError(f"AEGIS application icon not found: {path}")
    return icon


def create_main_window() -> QMainWindow:
    """Create and return the main window without starting the Qt event loop."""
    from aegis.gui.main_window import MainWindow

    return MainWindow()


def main() -> int:
    """Launch the GUI and return Qt's event-loop exit code."""
    try:
        from PySide6.QtGui import QFont
        from PySide6.QtWidgets import QApplication
    except ModuleNotFoundError as exc:
        if exc.name == "PySide6" or (exc.name or "").startswith("PySide6."):
            print(
                "The AEGIS desktop GUI requires PySide6. "
                'Install it with: pip install -e ".[gui]"',
                file=sys.stderr,
            )
            return 1
        raise

    app = QApplication(sys.argv)
    app.setFont(QFont(FONT_FAMILY, BASE_FONT_SIZE))
    app.setStyleSheet(build_stylesheet())
    app.setWindowIcon(create_application_icon())
    window = create_main_window()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
