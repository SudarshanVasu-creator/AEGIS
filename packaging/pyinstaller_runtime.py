"""Point Bandit's subprocess invocation at the bundled Python runtime."""

from __future__ import annotations

import os
import sys
from pathlib import Path

if getattr(sys, "frozen", False):
    runtime_dir = Path(sys._MEIPASS) / "runtime"
    python_executable = runtime_dir / "python.exe"
    if not python_executable.is_file():
        raise RuntimeError("The bundled AEGIS Python runtime is missing.")

    bundled_packages = runtime_dir / "site-packages"
    existing_pythonpath = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = os.pathsep.join(
        part
        for part in (str(bundled_packages), existing_pythonpath)
        if part
    )
    sys.executable = str(python_executable)
