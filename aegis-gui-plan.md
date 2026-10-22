# AEGIS Desktop GUI — Implementation Plan

> **Implementation status (2026-10-22): Complete.** This file preserves the
> original approved design and work plan as project history. All nine subtasks
> below are implemented. Where the original proposal differs from the shipped
> application, use the current code, [README.md](README.md), and
> [docs/architecture.md](docs/architecture.md) as the source of truth.
>
> Key implementation updates since this proposal:
>
> - The current workspace follows the supplied dark visual reference rather
>   than the light palette documented below. It is a single workspace with
>   inline state banners, not the original stacked-panel proposal.
> - The current findings table columns are **Severity, Finding, Rule, File,
>   Line**; it includes search, severity filters, and sorting.
> - Windows packaging produces separate console CLI and windowed GUI **onedir**
>   distributions. It does not produce the single dual-mode executable proposed
>   here. Keep each executable with its generated `_internal` directory/runtime.
> - The GUI selects a project folder and a report destination, runs the shared
>   scanner in a background `QThread`, presents `SUCCESS`, `EMPTY`, `PARTIAL`,
>   `FAILED`, and invalid-path states, and saves successful or partial results
>   through the existing report writer.
> - A successful zero-finding result is presented as `EMPTY`, but is not
>   described as proof of security. `PARTIAL` remains partial even when it has
>   no findings; findings returned with a failed result remain visible.
> - The worker sanitizes unexpected scan errors; finding details display only
>   the backend-provided redacted evidence.

## Approved Design Decisions

1. **Framework:** PySide6 (Qt for Python) — see Technology Decision section for rationale.
2. **Architecture:** GUI is a new entry point (`src/aegis/gui/`) that calls the existing
   `scanner.run_scan()` and `report.write_report()` APIs. No scanning logic is duplicated.
3. **Threading:** `QThread` worker runs `run_scan()` off the main thread; progress signals
   are emitted via Qt signal–slot pattern.
4. **Progress bar:** Indeterminate (pulsing) — no percentage, no backend callbacks required.
5. **Findings layout:** Split pane — findings list on the left, detail panel on the right,
   updating on row selection. Window is resizable; both panes expand naturally.
6. **CLI preservation:** `src/aegis/cli.py`, `__main__.py`, and all exit-code behaviour
   remain completely unchanged.
7. **PySide6 is optional:** Added as `[gui]` extra in `pyproject.toml`; `pip install -e .`
   gives CLI only; `pip install -e ".[gui]"` adds the GUI.
8. **GUI entry points:** `python -m aegis.gui` for developer use; `aegis-gui` console_scripts
   entry point installs as `aegis-gui.exe` when installed with the `[gui]` extra.
9. **Packaging proposal (superseded):** The original proposal was a single
   `aegis.exe` for Windows; the implementation instead builds distinct CLI and
   GUI distributions as noted above.
10. **Design reference:** Claude Design HTML file is a visual spec only — no JS, no
    browser runtime, no iframe protocol is reused in the desktop application.

---

## Top-Level Overview

**Goal:** Add a polished desktop GUI to AEGIS that reproduces the Claude Design reference
faithfully and integrates with the existing Python scanning backend.

**Scope:**
- New `src/aegis/gui/` package with PySide6 UI code.
- New `aegis-gui` entry point (installed alongside `aegis` CLI entry point).
- Progress bar and all scan lifecycle states from the design reference.
- JSON report export through the existing `report.write_report()`.
- PyInstaller packaging configuration for a Windows executable.
- No changes to scanning logic, security protections, redaction, or CLI.

**Non-goals:**
- Rewriting any scanner, model, redactor, or report module.
- Building a web server or serving the HTML prototype.
- Adding new scanning rules or severity categories.
- Cross-platform packaging (Windows only for MVP).

---

## Technology Decision: PySide6 vs Tauri

### PySide6 (Recommended)

| Criterion | Assessment |
|---|---|
| Visual fidelity | High — QSS (Qt Style Sheets) can faithfully reproduce the design tokens; custom-painted widgets for severity bars |
| Dev time | Low — single language (Python), no build pipeline, no toolchain setup |
| Python integration | Seamless — import existing modules directly; no IPC, no bridge |
| Backend complexity | None — `run_scan()` called directly in a QThread worker |
| Dependencies | One pip install (`PySide6`) |
| Resource usage | ~60–80 MB RAM at runtime; ~25 MB wheel; reasonable for a security tool |
| Packaging | PyInstaller + `--onefile` works reliably with PySide6 on Windows |
| Local-only | Yes — no network required at runtime |
| MVP risk | Low — well-documented, stable Qt 6.x API, large Python community |

### Tauri (Not recommended)

| Criterion | Assessment |
|---|---|
| Visual fidelity | High — renders the HTML design exactly |
| Dev time | High — requires Rust toolchain, Node.js frontend build, Tauri CLI, IPC bridge to Python |
| Python integration | Complex — must run Python as sidecar subprocess; all data crosses JSON IPC boundary |
| Backend complexity | High — full IPC layer to expose `run_scan()`, stream progress, serialise results |
| Dependencies | Rust, Node.js, npm/pnpm, Tauri CLI — significant setup and CI complexity |
| Resource usage | Low binary size but requires either bundled Python or separate Python install |
| Packaging | More complex — Python sidecar must be bundled separately |
| MVP risk | High — adds multiple new runtimes and a non-trivial IPC design |

**Decision: PySide6.**

The HTML prototype is a visual specification, not production code. No browser APIs, iframe
protocols, or JS runtime from that file are suitable for reuse. PySide6 lets us reproduce
every visible element (colour palette, typography, cards, severity chips, progress bar,
state transitions) using QSS and standard Qt widgets, while calling the existing Python
backend with zero IPC overhead. Tauri would require building and maintaining an entirely
separate frontend-to-backend communication layer for no additional user-facing benefit.

---

## Design Reference: Key Extracted Tokens

These values are taken from the Claude Design prototype and apply to all GUI widgets.

### Colours
| Token | Hex | Use |
|---|---|---|
| `bg-canvas` | `#faf9f5` | Window / main background |
| `bg-card` | `#ffffff` | Cards, panels |
| `text-primary` | `#1f1e1d` | Body text, labels |
| `text-secondary` | `#6b6a68` | Subtext, meta |
| `shadow` | `rgba(0,0,0,0.12)` | Card drop shadow |
| `error-bg` | `#2a1215` | Error state background |
| `error-text` | `#ff8a80` | Error state text |
| `error-border` | `#5c2b2e` | Error state border |

### Typography
- Font stack: `system-ui, -apple-system, "Segoe UI", sans-serif`
- Base: 14px / 1.4 line-height
- Labels: 13px, weight 500
- Monospace (error messages): `ui-monospace, monospace` (maps to Consolas on Windows)

### Spacing
- Window padding: 32px (adapted from 48px design canvas padding for a native window)
- Section gap: 24px
- Card internal padding: 20px

---

## GUI Layout and States

The design specifies two boards: **Workspace** (completed scan) and **States** (all
lifecycle states). Both are reproduced as in-app transitions within a single window.

### Window structure
```
MainWindow (fixed minimum: 900×640)
├── Header bar
│   ├── AEGIS wordmark + shield icon
│   └── (no menu bar — single-purpose tool)
└── Central widget (stacked layout)
    ├── ProjectPanel   — path input + scan button
    └── ResultsPanel   — findings table + export button
```

### State machine
```
READY ──[Start Scan]──► SCANNING ──[success]──► SUCCESS
                    │                    └──[no findings]──► EMPTY
                    │           ──[partial failure]──► PARTIAL
                    │           ──[all scanners fail]──► FAILED
                    └──[invalid path]──► INVALID_PATH
```

### States and their UI representation

| State | Description | Visual |
|---|---|---|
| `READY` | Initial; path not yet selected or validated | Empty path field, disabled scan button |
| `SCANNING` | Scan running in worker thread | Progress bar (indeterminate → pulsing), scan button disabled |
| `SUCCESS` | Both scanners completed, ≥1 finding | Findings table populated; severity summary chips |
| `EMPTY` | Both scanners completed, 0 findings | "No issues found" message card |
| `PARTIAL` | One scanner failed | Findings table + yellow warning banner naming failed scanner |
| `FAILED` | All scanners failed | Error card (dark red bg `#2a1215`, red text `#ff8a80`) |
| `INVALID_PATH` | Path does not exist or is not a directory | Inline error under path field |

---

## GUI Components

### 1. Path input row
- `QLineEdit` for directory path (read-only, populated by picker)
- "Browse…" `QPushButton` → opens `QFileDialog.getExistingDirectory()`
- Inline error label (hidden until INVALID_PATH state)

### 2. Scan button
- Primary action button; disabled during SCANNING
- Text: "Scan Project" → "Scanning…" during scan

### 3. Progress bar
- `QProgressBar` in indeterminate mode (value = -1 / pulse) during SCANNING
- Hidden when not scanning
- Rationale: bandit subprocess duration is not predictable, so indeterminate is correct;
  the bar shows the application is alive rather than claiming false percentage accuracy

### 4. Status / summary row (post-scan)
- Severity count chips: CRITICAL · HIGH · MEDIUM · LOW · INFO
- Each chip is a small coloured `QLabel` with a rounded QSS background

### 5. Findings table
- `QTableWidget` or `QTableView` with custom delegate
- Columns: Severity | File | Line | Rule ID | Title
- Rows sorted by severity first (matching `run_scan()` output order)
- Click a row → detail panel expands below (or in a side panel) showing description +
  redacted evidence + remediation

### 6. Detail panel (finding detail)
- Shown when a row is selected in the findings table
- Fields: Title, Severity, File, Line, Rule ID, Description, Evidence (redacted), Remediation
- Evidence displayed in monospace font, dark background (matches error card style)

### 7. Export button
- "Export Report" `QPushButton`; visible after SCANNING completes (any result)
- Opens `QFileDialog.getSaveFileName()` with JSON filter
- Calls `report.write_report(result, output_path)` — no new logic
- Shows `QMessageBox` on success; inline error label on `ReportError`

### 8. Partial / error banners
- `QFrame` banner with icon + message text
- PARTIAL: amber/yellow variant
- FAILED: dark red variant matching `error-bg` / `error-text` / `error-border` tokens

---

## Backend Integration Points

The GUI communicates with the existing backend through exactly these interfaces:

| GUI action | Backend call | Module |
|---|---|---|
| Start scan | `scanner.run_scan(project_path)` | `aegis.scanner` |
| Export report | `report.write_report(result, output_path)` | `aegis.report` |
| Derive severity counts | `Counter(f.severity for f in result.findings)` | `aegis.models.Severity` |
| Display redacted evidence | `finding.redacted` field | `aegis.models.Finding` |
| Show scanner errors | `result.errors[i].message` | `aegis.scanner.ScannerError` |
| Determine scan outcome | `result.status` (SUCCESS / PARTIAL / FAILED) | `aegis.scanner.ScanStatus` |

### Threading contract
- `run_scan()` blocks for the duration of the Bandit subprocess (up to 120 s default).
- The GUI must run it in a `QThread` worker and communicate back via Qt signals:
  - `scan_complete(ScanResult)` — emitted when `run_scan()` returns
  - `scan_error(str)` — emitted if `run_scan()` raises `ValueError`
- The main thread never calls `run_scan()` directly.

### No backend changes required
The existing API surface is sufficient. The only addition is a thin
`src/aegis/gui/worker.py` that wraps `run_scan()` in a `QThread`.

---

## Repository Changes

```
src/aegis/
├── gui/                          ← NEW package
│   ├── __init__.py
│   ├── main.py                   ← QApplication entry point
│   ├── main_window.py            ← MainWindow: stacked panels + state machine
│   ├── worker.py                 ← QThread wrapper for run_scan()
│   ├── widgets/
│   │   ├── __init__.py
│   │   ├── path_row.py           ← Path input + Browse button
│   │   ├── scan_button.py        ← Scan/Scanning button
│   │   ├── progress_bar.py       ← Indeterminate progress bar
│   │   ├── severity_chips.py     ← Coloured severity count labels
│   │   ├── findings_table.py     ← QTableView + custom model
│   │   ├── finding_detail.py     ← Expanded finding detail panel
│   │   └── banner.py             ← Partial/failed/error banner
│   └── styles.py                 ← QSS stylesheet constants + colour tokens
├── __main__.py                   ← unchanged (CLI entry)
├── cli.py                        ← unchanged
└── ...                           ← all other modules unchanged

packaging/
├── aegis.spec                    ← PyInstaller spec file
└── build_exe.ps1                 ← PowerShell build script

pyproject.toml                    ← add PySide6 to [project.optional-dependencies]
                                     add aegis-gui console_scripts entry point
```

---

## Sub-Tasks

---

### Sub-Task 1 — Styles and Design Tokens

**Status:** [x] complete

**Intent:**
Establish the PySide6 QSS stylesheet and Python colour/spacing constants that all widgets
will use. Getting the design tokens right first ensures every subsequent widget is
consistent without iterating on colours later.

**Expected Outcomes:**
- `src/aegis/gui/styles.py` defines Python constants for every colour token and a
  `build_stylesheet() -> str` function that returns a complete QSS string.
- Opening a minimal QApplication with the stylesheet applied produces the `#faf9f5`
  background and correct system font rendering on Windows.

**Todo List:**
1. Create `src/aegis/gui/__init__.py` (empty).
2. Create `src/aegis/gui/styles.py` with colour constants matching design tokens.
3. Write `build_stylesheet()` that emits QSS targeting `QMainWindow`, `QWidget`,
   `QPushButton`, `QLineEdit`, `QTableView`, `QLabel`, `QProgressBar`, `QFrame`.
4. Create `src/aegis/gui/main.py` with a minimal `QApplication` that applies the
   stylesheet and opens a blank `QMainWindow` — confirm it renders on Windows.
5. Add `aegis-gui` entry point to `pyproject.toml` pointing to `aegis.gui.main:main`.

**Relevant Context:**
- Design tokens: `bg-canvas #faf9f5`, `bg-card #ffffff`, `text-primary #1f1e1d`,
  `text-secondary #6b6a68`, card shadow `rgba(0,0,0,0.12)`.
- QSS does not support `box-shadow`; use a `QGraphicsDropShadowEffect` on card widgets.
- System font on Windows: "Segoe UI" (already in font stack); Qt picks it automatically.
- Do not use `QDarkStyle` or any third-party theme library.

---

### Sub-Task 2 — Scan Worker Thread

**Status:** [x] complete

**Intent:**
Wrap `scanner.run_scan()` in a `QThread` so the GUI never blocks the event loop during
a scan. This is the most critical architectural piece because without it the window will
freeze for the full duration of the Bandit subprocess.

**Expected Outcomes:**
- `src/aegis/gui/worker.py` defines `ScanWorker(QThread)` with signals
  `scan_complete(object)` and `scan_error(str)`.
- `ScanWorker` accepts `project_path: Path` at construction; `run()` calls
  `scanner.run_scan(project_path)` and emits the appropriate signal.
- A manual smoke test (or pytest) confirms the worker emits `scan_complete` on a valid
  project and `scan_error` when passed a non-existent path.

**Todo List:**
1. Create `src/aegis/gui/worker.py` with `ScanWorker(QThread)`.
2. Define signals: `scan_complete = Signal(object)`, `scan_error = Signal(str)`.
3. In `run()`: call `scanner.run_scan(project_path)`, emit `scan_complete(result)` on
   success, emit `scan_error(str(e))` on `ValueError`.
4. Write a minimal pytest test in `tests/test_gui_worker.py` using `QApplication` fixture
   that fires the worker against `tests/fixtures/vulnerable_project/` and asserts
   `scan_complete` is emitted with a `ScanResult` containing findings.

**Relevant Context:**
- Import `from aegis import scanner` — no changes to `scanner.py` needed.
- `run_scan()` raises `ValueError` for invalid paths; all other exceptions should be
  caught and re-emitted as `scan_error`.
- The worker must be started with `.start()`, not `.run()`, to get actual thread separation.
- Use `QThread` rather than `QRunnable` because we need `moveToThread` signal routing.

---

### Sub-Task 3 — Main Window and State Machine

**Status:** [x] complete

**Intent:**
Build the `MainWindow` shell with a `QStackedWidget` that transitions between the scan
lifecycle states. All panels are placeholders at this stage; the goal is a working state
machine wired to the worker's signals.

**Expected Outcomes:**
- `MainWindow` displays the AEGIS header, transitions between READY / SCANNING /
  result states in response to worker signals.
- Progress bar appears during SCANNING and disappears on completion.
- Window title reads "AEGIS — Application Security & Inspection System".
- Minimum window size: 900×640.

**Todo List:**
1. Create `src/aegis/gui/main_window.py` with `MainWindow(QMainWindow)`.
2. Add `QStackedWidget` with placeholder panels for each state.
3. Define `_set_state(state: GuiState)` slot that switches the stacked panel and
   shows/hides the progress bar.
4. Instantiate `ScanWorker`; connect `scan_complete` → `_on_scan_complete`,
   `scan_error` → `_on_scan_error`.
5. Wire the scan button to `_start_scan()`: validate path, construct worker, call `.start()`.
6. Confirm state transitions cycle correctly in a manual test.

**Relevant Context:**
- `GuiState` is a simple `enum.Enum` with values: READY, SCANNING, SUCCESS, PARTIAL,
  FAILED, EMPTY, INVALID_PATH.
- The progress bar widget is a `QProgressBar` set to `setRange(0, 0)` (indeterminate)
  while scanning, then hidden after.
- Do not block the event loop anywhere in this file.

---

### Sub-Task 4 — Path Input and Project Selection

**Status:** [x] complete

**Intent:**
Implement the project path row: a read-only line edit populated by a directory picker,
with inline validation and a clear error display for invalid paths.

**Expected Outcomes:**
- User clicks "Browse…" → `QFileDialog.getExistingDirectory()` opens; selected path
  populates the line edit.
- If the path does not exist or is not a directory (checked before scan starts), an
  inline red label appears beneath the field.
- The scan button is disabled until a valid directory path is populated.

**Todo List:**
1. Create `src/aegis/gui/widgets/path_row.py` with `PathRow(QWidget)`.
2. Add `QLineEdit` (read-only), "Browse…" `QPushButton`, and error `QLabel` (hidden).
3. Connect Browse button → `QFileDialog.getExistingDirectory()` → populate line edit.
4. Expose `path() -> Path | None` property; emit `path_changed(Path)` signal.
5. Add `show_error(message: str)` and `clear_error()` methods.
6. In `MainWindow._start_scan()`, validate `path.exists() and path.is_dir()` before
   creating the worker; call `path_row.show_error(...)` on failure.

**Relevant Context:**
- The line edit is read-only (populated by picker only) to prevent users typing raw paths
  that bypass OS path normalisation.
- Path validation here is a UX check only; `run_scan()` performs its own validation
  internally (including symlink and containment checks).

---

### Sub-Task 5 — Findings Table and Severity Summary

**Status:** [x] complete

**Intent:**
Build the results view: severity count chips above a horizontal split pane containing
the findings list on the left and a live detail panel on the right.

**Expected Outcomes:**
- Five severity chips (CRITICAL, HIGH, MEDIUM, LOW, INFO) display counts from
  `result.findings`, using appropriate background colours.
- A `QSplitter` divides the results area horizontally: findings table on the left,
  finding detail panel on the right. Both panes resize with the window.
- Findings table shows all findings sorted as returned by `run_scan()` (no re-sorting
  needed — already severity-first).
- Clicking a row updates the detail panel on the right immediately.
- Zero-findings state shows a "No issues found" card instead of the split pane.

**Todo List:**
1. Create `src/aegis/gui/widgets/severity_chips.py` — `SeverityChips(QWidget)` with
   five `QLabel` chips; `update_counts(findings: list[Finding])` method.
2. Define severity colour map (CRITICAL = red-adjacent, HIGH = orange, MEDIUM = yellow,
   LOW = blue, INFO = grey — colours to be confirmed against design reference).
3. Create `src/aegis/gui/widgets/findings_table.py` — `FindingsTable(QWidget)` wrapping
   a `QTableWidget`; `load_findings(findings: list[Finding])` method.
4. Table columns: Severity | File | Line | Rule ID | Title (read-only, no editing).
5. Emit `finding_selected(Finding)` signal on row click.
6. Create `src/aegis/gui/widgets/finding_detail.py` — `FindingDetail(QWidget)` with
   labelled fields; `load_finding(finding: Finding)` method.
7. In `MainWindow` results panel: use `QSplitter(Qt.Horizontal)` with `FindingsTable`
   on the left and `FindingDetail` on the right; set initial sizes to roughly 55% / 45%.
8. Wire `findings_table.finding_selected` → `finding_detail.load_finding` in `MainWindow`.

**Relevant Context:**
- Severity counts: `from collections import Counter; counts = Counter(f.severity for f in
  result.findings)` — use `Severity` enum values as keys.
- The `finding.redacted` field (not `finding.evidence`) is displayed in the detail panel.
- `Finding.to_dict()` returns `"evidence"` mapped to `finding.redacted` — the GUI can
  use `finding.redacted` directly rather than going through `to_dict()`.

---

### Sub-Task 6 — Partial and Failed Banners

**Status:** [x] complete

**Intent:**
Display clear, actionable status banners for PARTIAL and FAILED scan outcomes so users
understand when scanner errors occurred and can take action.

**Expected Outcomes:**
- PARTIAL state: amber banner names the failed scanner and its error message; findings
  from the successful scanner are still shown.
- FAILED state: dark red card (design token `error-bg` / `error-text` / `error-border`)
  shows all error messages; no findings table is shown.
- EMPTY state: neutral info card "No security issues were found in this project."

**Todo List:**
1. Create `src/aegis/gui/widgets/banner.py` with `Banner(QFrame)` that accepts a
   `BannerStyle` enum (PARTIAL, FAILED, INFO) and message text.
2. Apply QSS colours per `BannerStyle`: PARTIAL uses amber (`#7c5c00` bg, `#fff8e6` text),
   FAILED uses error tokens (`#2a1215` bg, `#ff8a80` text, `#5c2b2e` border).
3. In `MainWindow._on_scan_complete()`: inspect `result.status`; insert appropriate
   `Banner` above the findings table for PARTIAL; replace the results area for FAILED.
4. Error message text comes from `result.errors[i].message` (already safe/sanitised).

**Relevant Context:**
- `ScannerError.message` is guaranteed safe — no raw code, no secret values.
- `ScanStatus.PARTIAL` means one scanner failed; the other succeeded, so `result.findings`
  is non-empty (or may be empty if the successful scanner found nothing).
- `ScanStatus.FAILED` means `result.findings` is empty.

---

### Sub-Task 7 — Report Export

**Status:** [x] complete

**Intent:**
Wire the Export Report button to `report.write_report()` so users can save a JSON report
to any location outside the scanned project directory.

**Expected Outcomes:**
- "Export Report" button opens `QFileDialog.getSaveFileName()` with a `.json` filter and
  a sensible default filename (`aegis-report-{project_name}.json`).
- `report.write_report(result, output_path)` is called; on success a `QMessageBox`
  confirms the path written.
- `ReportError` and `UnsafeOutputPathError` are caught and displayed as inline error text
  (not a crash).
- Button is disabled until a scan has completed.

**Todo List:**
1. Add "Export Report" `QPushButton` to the results area; disabled initially.
2. Connect to `_export_report()` slot in `MainWindow`.
3. In `_export_report()`: open save dialog; if accepted, call `report.write_report()`
   inside a try/except catching `ReportError` and `UnsafeOutputPathError`.
4. On success: show `QMessageBox.information(...)`.
5. On error: show inline error label or `QMessageBox.warning(...)`.

**Relevant Context:**
- `from aegis.report import write_report, ReportError, UnsafeOutputPathError`
- Default filename: `f"aegis-report-{self._result.project_path.name}.json"`
- The save dialog naturally enforces that the user explicitly picks a destination —
  no additional path validation is needed beyond what `write_report()` already does.
- Do NOT run `write_report()` in a worker thread — JSON serialisation is fast and does
  not involve the Bandit subprocess.

---

### Sub-Task 8 — PyInstaller Packaging (original single-executable proposal)

**Status:** [x] complete

**Intent:**
**Original proposal, superseded:** produce a single `aegis.exe` Windows
executable that users can run without installing Python, PySide6, or Bandit
manually. The implemented release uses two separate onedir distributions as
described in the implementation-status note above.

**Expected Outcomes:**
- `packaging/aegis.spec` defines a PyInstaller spec that includes all `aegis` modules,
  PySide6 Qt platform plugins, and Bandit.
- `packaging/build_exe.ps1` runs `pyinstaller packaging/aegis.spec` from the project root.
- The resulting `dist/aegis.exe` opens the AEGIS GUI window when double-clicked (no
  terminal window).
- `aegis.exe scan --project <path> --output <file>` still works from a terminal (CLI mode).

**Todo List:**
1. Add `PySide6` to `[project.optional-dependencies]` in `pyproject.toml` under a
   `[gui]` extra.
2. Create `packaging/aegis.spec` using PyInstaller's `Analysis` + `EXE` with:
   - `console=False` for GUI mode (no black terminal window on double-click)
   - `--add-data` for any Qt platform plugin paths
   - `hiddenimports=['bandit', 'aegis.scanner', 'aegis.report', 'aegis.gui.main']`
3. Create `packaging/build_exe.ps1` that activates the venv and runs PyInstaller.
4. Test that `dist/aegis.exe` launches the GUI and runs a scan against the fixture project.
5. Document the build steps in `README.md` under a new "Building the Windows Executable"
   section.

**Relevant Context:**
- PyInstaller must be installed in the venv (`pip install pyinstaller`) — it is a dev
  dependency, not a runtime one; add it to `requirements-dev.txt`.
- PySide6 includes `pyside6-deploy` but PyInstaller is more reliable for complex packages.
- Bandit uses `pkg_resources` for entry points; PyInstaller's `--collect-all bandit` flag
  ensures all Bandit plugins are included.
- `console=False` hides the terminal on double-click but CLI usage still works because
  Windows attaches a console when invoked from a terminal.

---

### Sub-Task 9 — GUI Tests

**Status:** [x] complete

**Intent:**
Add automated tests for the GUI layer that can run headlessly in CI (using Qt's offscreen
platform) and cover the key integration paths without testing Qt internals.

**Expected Outcomes:**
- `tests/test_gui_worker.py` passes: worker emits `scan_complete` with valid `ScanResult`.
- `tests/test_gui_state.py` passes: `MainWindow` state transitions are exercised; correct
  panels shown for each `ScanStatus` value.
- All existing tests continue to pass unchanged.
- Tests use `QT_QPA_PLATFORM=offscreen` environment variable (set in `conftest.py`).

**Todo List:**
1. Add `conftest.py` (or update existing) to set `QT_QPA_PLATFORM=offscreen` before any
   Qt import.
2. Add `QApplication` pytest fixture (session-scoped) in `conftest.py`.
3. Write `tests/test_gui_worker.py` (see Sub-Task 2 notes).
4. Write `tests/test_gui_state.py` testing `_set_state()` transitions and verifying
   correct widget visibility per state.
5. Ensure `pytest tests/` still passes with `PySide6` installed; document that
   `pip install -e ".[gui]"` is required before running GUI tests.

**Relevant Context:**
- PySide6 requires a `QApplication` singleton before any widget is instantiated.
- Offscreen platform: `os.environ["QT_QPA_PLATFORM"] = "offscreen"` set before
  `from PySide6.QtWidgets import QApplication`.
- Do not test visual rendering (pixel comparison) — test state, data loading, and signal
  wiring only.

---

## Dependency Summary

| Package | Version Constraint | Purpose | Dev only |
|---|---|---|---|
| `PySide6` | `>=6.6` | Qt for Python GUI framework | No (runtime) |
| `pyinstaller` | `>=6.0` | Windows executable packaging | Yes |

Existing dependencies (`bandit`, `pytest`, `pytest-cov`) unchanged.

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| PySide6 wheel size inflates exe above acceptable limit | Low | Low | Use `--exclude-module` in spec to strip unused Qt modules |
| Bandit subprocess not found inside PyInstaller bundle | Medium | High | Use `sys.executable` path (already done in `bandit_runner.py`); bundle Python interpreter |
| QT_QPA_PLATFORM offscreen not available in CI | Low | Medium | Install `libxcb` on Linux CI; on Windows offscreen is always available |
| `QFileDialog` returns empty string if dialog cancelled | Low | Low | Guard with `if not path: return` in export handler |
| `run_scan()` raises unexpected exception (not ValueError) | Low | Medium | Catch `Exception` in worker as fallback; emit `scan_error` |
| PyInstaller + Python 3.13 compatibility | Low | Medium | Verify with PyInstaller >=6.0 which supports 3.12/3.13 |
