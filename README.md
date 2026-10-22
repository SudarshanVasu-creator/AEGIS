# AEGIS — Application Security & Inspection System

[![Python](https://img.shields.io/badge/Python-3.13%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Bandit](https://img.shields.io/badge/Security%20Analysis-Bandit-orange)](https://bandit.readthedocs.io/)

AEGIS is a local source-code security scanner for Python projects. It combines
Bandit's Python static analysis with AEGIS's heuristic patterns for common
hardcoded secrets, then presents findings through a command-line interface (CLI)
or an optional PySide6 desktop GUI. Findings include severity, relative file and
line information where available, descriptions, redacted evidence, and
remediation guidance. Results can be saved as JSON.

AEGIS is intended for students, workshop participants, and Python developers who
want a local first-pass security review or an educational demonstration of static
analysis and secret scanning. Scans are performed locally by the application; it
does not send project source or reports to an AEGIS remote service. Windows
packaging downloads a Python runtime and dependencies during the build.

**AEGIS is a source-code scanner, not a guarantee that a project is secure.**
Detection is limited to the implemented scanners and their rules.

## Features

- Bandit-based static security analysis of Python source files.
- Regex-based detection for selected hardcoded secret patterns, including
  credential and token assignments.
- Findings with severity, relative file path, optional line number, rule ID,
  description, and remediation guidance.
- Redacted evidence in the GUI and JSON output; raw evidence is not serialized
  into reports.
- CLI scanning and an optional PySide6 desktop GUI.
- JSON report generation using the existing report writer.
- GUI severity counters, severity filters, text search, sorting, and a
  selectable findings table with a detail panel.
- Local project scanning that does not intentionally modify scanned files.

## Architecture and technology

- **Python:** Python 3.13 or later for the application. The Windows packaging
  script currently requires 64-bit Python 3.13.
- **Runtime dependency:** Bandit (`bandit>=1.8.0`).
- **Optional GUI dependency:** PySide6 (`PySide6>=6.6`), installed through the
  `gui` extra. It is not required for a CLI-only installation.
- **Development dependencies:** `pytest>=8.0`, `pytest-cov>=5.0`, and
  `PyInstaller>=6.13,<7` (see `requirements-dev.txt`).

The `src/aegis/` backend is shared by both entry points:

- `cli.py` parses CLI arguments and returns documented process exit codes.
- `scanner.py` validates the project path, runs both scanner engines, combines
  findings, clears raw evidence, and returns `SUCCESS`, `PARTIAL`, or `FAILED`.
- `bandit_runner.py` invokes Bandit for Python AST-based analysis.
- `secret_scanner.py` applies the implemented secret-detection patterns to
  eligible text files.
- `redactor.py` replaces recognized secret values with `[REDACTED]`.
- `models.py` defines findings and severity levels.
- `report.py` writes the JSON report and rejects destinations inside the
  scanned project.
- `gui/` provides a PySide6 interface that invokes the existing scanner in a
  background `QThread` and uses the existing report writer for JSON export.

The GUI can be launched with `python -m aegis.gui` or the installed
`aegis-gui` command. The CLI remains available as `aegis` or `python -m aegis`.
For module details and the architecture diagram, see
[docs/architecture.md](docs/architecture.md) and
[docs/image/aegis-architecture.png](docs/image/aegis-architecture.png).
The original GUI design and implementation plan is retained in
[aegis-gui-plan.md](aegis-gui-plan.md); its implementation-status note identifies
which original proposals were superseded.

## Requirements and installation

The following examples use Windows PowerShell from the repository root. The
CLI-only installation does not install PySide6:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

To install the desktop GUI as well:

```powershell
python -m pip install -e ".[gui]"
```

Install test and build tools when developing or preparing a Windows build:

```powershell
python -m pip install -r requirements-dev.txt
```

GUI tests require the `gui` extra. The GUI test modules select Qt's offscreen
platform when it is not already configured.

## CLI usage

Scan a project and write a JSON report:

```powershell
aegis scan --project "C:\work\my-project" --output "C:\reports\my-project.json"
```

`--output` is optional. If omitted, the CLI writes `aegis-report.json` in the
current working directory. The report destination must be outside the scanned
project directory. The report writer creates the destination's parent directory
if needed.

From an editable development installation, the equivalent module invocation is:

```powershell
python -m aegis scan --project "C:\work\my-project" --output "C:\reports\my-project.json"
```

Useful help commands:

```powershell
aegis --help
aegis scan --help
```

The report's `scan_status` is `SUCCESS` when both scanners complete, `PARTIAL`
when at least one scanner fails and the remaining scanner's results are
returned, and `FAILED` when all scanner engines fail. A successful scan with no
findings is not a security certification or proof that the project is secure.

CLI exit behavior:

| Exit code | Meaning |
|---|---|
| `0` | Scan completed and report written; status may be `SUCCESS` or `PARTIAL`. |
| `1` | Invalid project path or unsafe report destination. |
| `2` | All scanners failed; a returned `FAILED` result is written to the report when possible. Argparse syntax errors also use argparse's standard exit code `2`. |
| `3` | Report could not be written. |

## Desktop GUI usage

After installing the optional GUI dependency, launch the application from the
repository's active Python environment:

```powershell
python -m aegis.gui
```

Alternatively, use the installed entry point:

```powershell
aegis-gui
```

In the window:

1. Choose a project directory with **Browse**.
2. Review the suggested JSON report destination or choose another location with
   the report **Browse** button. The default is
   `%USERPROFILE%\aegis-reports\<project-name>.json`.
3. Select **Scan Project**. The scan runs in a background thread; the GUI
   remains responsive and shows indeterminate progress rather than a guessed
   percentage.
4. Review the result status, finding count, severity counts, and findings. Use
   the severity filters, search field, and sort control to navigate results.
   Selecting a row updates the details panel.
5. Select **Save JSON report** to write the displayed `SUCCESS` or `PARTIAL`
   result through the existing report writer.

The GUI reports invalid project or report paths before scanning, rejects a
report destination inside the scanned project, distinguishes partial and failed
scans, and clearly labels a successful scan with zero findings. It performs
scans locally using the same backend as the CLI. A completely failed scan does
not offer report export from the GUI.

## Windows release builds

The repository provides `packaging/build.ps1` and separate PyInstaller
specifications. Build from the repository root using 64-bit Python 3.13. The
script requires the GUI extra and PyInstaller; install them with:

```powershell
python -m pip install -e ".[gui]"
python -m pip install -r requirements-dev.txt
```

Build both distributions:

```powershell
.\packaging\build.ps1
```

If the current PowerShell execution policy blocks this script, the following
process-scoped bypass was used to run it without changing persistent policy:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\packaging\build.ps1
```

The build script downloads the matching official Python 3.13 embeddable runtime
and installs the runtime dependencies into it. A network connection to
python.org and package indexes may therefore be needed during build. It creates
two **onedir** distributions:

- `dist\windows\aegis\aegis.exe` — console-enabled CLI.
- `dist\windows\aegis-gui\aegis-gui.exe` — windowed GUI, with the supplied
  application icon.

Each executable depends on the other generated files in its distribution,
including its `_internal` directory and bundled runtime. Keep and distribute
each complete directory; do not copy the `.exe` alone or treat it as a
standalone single-file program.

Example packaged CLI commands:

```powershell
.\dist\windows\aegis\aegis.exe --help
.\dist\windows\aegis\aegis.exe scan --project "C:\work\my-project" --output "C:\reports\my-project.json"
```

Launch the packaged GUI with:

```powershell
.\dist\windows\aegis-gui\aegis-gui.exe
```

The CLI bundle uses its bundled Python runtime to start Bandit. Test a copied
distribution on the intended Windows environment, independently of the build
machine's Python installation and active virtual environment.

## Security, privacy, and limitations

- The scanners analyze local files and the application does not intentionally
  upload source code or reports to an AEGIS service. This does not cover
  operating-system telemetry, third-party software, or the security of reports
  after they are saved.
- Bandit analyzes Python source. AEGIS's custom secret scanner uses selected
  patterns on eligible text files; it is not an exhaustive secret detector.
- Raw finding evidence is cleared by the scan orchestrator. GUI details display
  `finding.redacted`, and JSON reports export that redacted value as
  `findings[].evidence`. Redaction is pattern-based and cannot guarantee that
  every sensitive value will be recognized.
- Scanner rules can produce false positives and false negatives. Review
  findings in context and use additional security review methods.
- A `PARTIAL` result means at least one scanner failed; its findings may be
  incomplete. A `FAILED` result means all scanner engines failed. Neither is a
  clean scan.
- The JSON report writer and GUI reject a report destination inside the scanned
  project. The scanners are designed to read project files without modifying
  them.
- A `SUCCESS` result with zero findings means only that the implemented
  scanners completed without reporting a match. It does not certify project
  security.
- AEGIS does not claim exhaustive coverage of languages, frameworks, or
  vulnerability classes, and is not a substitute for a professional security
  assessment.

## Testing and verification

Run the project test suite from the repository root:

```powershell
python -m pytest
```

The tests cover models, scanning and redaction, report generation, CLI behavior,
and GUI widgets/state/worker behavior using synthetic fixtures. GUI tests can
run headlessly with Qt's offscreen platform. Tests that require PySide6 are
skipped if the optional GUI dependency is not installed. The fixtures use fake
credentials; do not replace them with real secrets.

The full test suite completed during this documentation update with **381
passed and 3 skipped**. Automated tests do not replace launching and exercising
the packaged CLI and GUI. The onedir distributions should be smoke-tested on the
target Windows environment.

In a previously recorded Windows 11 x64 package smoke test, the packaged CLI
help and a real fixture scan succeeded, producing a `SUCCESS` report with 12
findings. The packaged GUI launched without a console, scanned the same fixture,
displayed a selected finding with redacted evidence, exported JSON, and exited
cleanly. This manual check does not establish compatibility on every Windows
machine or test an installer; AEGIS currently builds onedir folders, not an
installer.

## Project structure

```text
AEGIS/
├── assets/icons/                 # Supplied PNG and ICO application icons
├── docs/
│   ├── architecture.md           # Backend, GUI, and report architecture
│   └── image/
│       └── aegis-architecture.png
├── packaging/
│   ├── aegis-cli.spec            # Console CLI distribution
│   ├── aegis-gui.spec            # Windowed GUI distribution
│   ├── build.ps1                 # Windows build orchestration
│   └── pyinstaller_runtime.py    # Bundled Bandit runtime hook
├── src/aegis/
│   ├── bandit_runner.py
│   ├── cli.py
│   ├── models.py
│   ├── redactor.py
│   ├── report.py
│   ├── scanner.py
│   ├── secret_scanner.py
│   └── gui/                      # PySide6 entry point, worker, widgets, styles
├── tests/
│   ├── fixtures/vulnerable_project/  # Synthetic test project; fake values only
│   └── test_*.py
├── aegis-gui-plan.md             # Original design and implementation plan/status
├── pyproject.toml
├── requirements.txt
└── requirements-dev.txt
```

## Workshop and release use

For a workshop distribution, provide the full `aegis` folder for the CLI and/or
the full `aegis-gui` folder for the desktop application from
`dist\windows\`. Keep each `.exe`, its `_internal` directory, and all other
generated files together. Participants can launch the GUI directly or run the
CLI from PowerShell as shown above; a separate Python installation is not
required by the bundles.

Do not distribute the test fixture as a real target project or use reports
containing real credentials in workshop materials. Use synthetic examples and
keep generated reports outside scanned project directories.

## License

No license has been selected for this project.
