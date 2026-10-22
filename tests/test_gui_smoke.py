"""Smoke tests for the optional AEGIS desktop GUI."""

import importlib.util
import os
import sys

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

if importlib.util.find_spec("PySide6") is None:
    pytest.skip("PySide6 is not installed; install the [gui] extra to run GUI tests",
                allow_module_level=True)

from PySide6.QtWidgets import QApplication

from aegis.gui.main import (
    APPLICATION_TITLE,
    create_application_icon,
    create_main_window,
    icon_path,
)


@pytest.fixture(scope="module")
def qapplication():
    """Return the process-wide Qt application instance."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_main_window_smoke(qapplication):
    window = create_main_window()
    try:
        assert window.windowTitle() == APPLICATION_TITLE
        assert window.minimumWidth() == 900
        assert window.minimumHeight() == 640
        assert not window.windowIcon().isNull()
    finally:
        window.close()


def test_icon_assets_resolve_and_load(qapplication):
    path = icon_path()

    assert path.name == "aegis.ico"
    assert path.is_file()
    assert not create_application_icon().isNull()
    assert not create_application_icon().pixmap(32, 32).isNull()


def test_icon_path_uses_pyinstaller_bundle_root(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    assert icon_path() == tmp_path / "assets" / "icons" / "aegis.ico"


def test_application_icon_is_set(qapplication):
    qapplication.setWindowIcon(create_application_icon())

    assert not qapplication.windowIcon().isNull()
