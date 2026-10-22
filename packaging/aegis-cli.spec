# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.building.datastruct import Tree

ROOT = Path(SPECPATH).parent
SOURCE = ROOT / "src"
RUNTIME = ROOT / "build" / "packaging" / "python-runtime"

a = Analysis(
    [str(SOURCE / "aegis" / "__main__.py")],
    pathex=[str(SOURCE)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[str(ROOT / "packaging" / "pyinstaller_runtime.py")],
    excludes=[],
    noarchive=False,
    optimize=0,
)
a.datas += Tree(str(RUNTIME), prefix="runtime")
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="aegis",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)
collection = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="aegis",
)
