# AEGIS Architecture

## Overview

AEGIS is a Python application with a CLI and an optional PySide6 desktop GUI. Both
entry points use the same backend to scan local project files for security issues.
The scanning implementation does not send project source or reports to an AEGIS
remote service. This is not a statement about operating-system telemetry, third-party
software, or activity during the separate Windows build process.

The pipeline has five stages:

```
CLI or GUI  →  Path Validation  →  Scanner Engines  →  Redactor  →  Report Writer
                                      ├── Bandit runner (Python AST, .py files)
                                      └── Regex secret scanner (eligible text files)
```

The GUI calls `run_scan()` on a `QThread`, receives its `ScanResult` through Qt
signals, and uses `write_report()` when the user saves a JSON report. The CLI calls
the same backend directly.

---

## Modules

### `aegis.cli`

Entry point. Parses command-line arguments using `argparse`.

- `scan --project <path> [--output <file>]` — runs the full pipeline. If omitted,
  the report is written to `aegis-report.json` in the current working directory.
- `--version` — prints the package version and exits.
- Validates that `--project` exists and is a directory before invoking the scanner.
- Prints a human-readable summary without raw finding evidence or secret values.
- Returns `0` when scanning completed and the report was written, including a
  `PARTIAL` result; returns `1` for invalid project/output paths, `2` when all
  scanner engines fail, and `3` when report writing fails. Argparse syntax errors
  use argparse's standard exit status `2`.

### `aegis.models`

Defines the `Severity` enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) and the
`Finding` dataclass. Each `Finding` carries:

| Field | Type | Notes |
|---|---|---|
| `id` | `str` | `rule_id:relative_file:line` — unique per finding |
| `severity` | `Severity` | Enum value |
| `file` | `str` | Relative path from the project root |
| `line` | `int \| None` | 1-based line number |
| `rule_id` | `str` | Scanner rule identifier (e.g. `B602`, `AEGIS-SECRET-AWS-KEY-ID`) |
| `title` | `str` | Short human-readable description |
| `description` | `str` | Detailed description |
| `evidence` | `str` | **Internal only — never written to output** |
| `redacted` | `str` | Evidence with secret values replaced by `[REDACTED]` |
| `remediation` | `str` | Actionable fix guidance |

`Finding.to_dict()` serialises for JSON export. The `evidence` field is **excluded
entirely**; `redacted` is exported under the key `"evidence"` so reports remain
actionable without exposing raw secret values.

### `aegis.redactor`

Exposes a single `redact(text: str) -> str` function. Applies a list of compiled
regex patterns to replace secret *values* with `[REDACTED]`. Variable names and
assignment operators are preserved so findings remain actionable.

Patterns covered:

| Category | Example match |
|---|---|
| AWS Access Key ID | `AKIA[A-Z0-9]{16}` — bare 20-char token |
| AWS Secret Access Key | `aws_secret_access_key = '…'` |
| GitHub personal access token | `ghp_…`, `github_pat_…` |
| Generic API key / token | `api_key = '…'`, `access_token: '…'` |
| Hardcoded password | `password = '…'`, `db_password: '…'` |

The function is deterministic and idempotent. It makes no network calls, no file I/O,
and never logs the pre-redaction value.

### `aegis.secret_scanner`

File-based scanner. Walks the project directory with `Path.rglob("*")`. For each
eligible text file, applies the implemented secret patterns line-by-line.

- Skips binary files (catches `UnicodeDecodeError`, logs a warning, continues).
- Excludes generated and dependency directories such as `.git/`, `__pycache__/`,
  `venv/`, `.venv/`, `env/`, `ENV/`, `node_modules/`, `dist/`, and `build/`, plus
  configured binary/compiled file suffixes.
- All file paths in findings are relative to the project root.

This is a heuristic scanner for selected patterns, not comprehensive secret
detection. Binary files are skipped; multi-line, encoded, or otherwise
unrecognized values may not be detected.

Returns a list of `Finding` objects with `evidence` populated and `redacted` already
set by calling `redact()` internally.

### `aegis.bandit_runner`

Invokes Bandit via a safe subprocess argument list (`shell=False`) with JSON output
(`bandit -f json`). Parses stdout and converts Bandit results into `Finding` objects.

- Maps Bandit severity + confidence levels to `aegis.Severity`.
- Applies the same directory exclusions as `secret_scanner`.
- Bandit emits paths that the runner relativises against the project root.
- Redacts Bandit code and issue text before storing displayable evidence.

Custom exceptions:
- `BanditError` — base class for all Bandit failures.
- `BanditNotFoundError` — Bandit executable not found.
- `BanditTimeoutError` — subprocess exceeded the configured timeout.

### `aegis.scanner`

Orchestrator. Always attempts both scanners; a failure in one does not prevent the
other from running.

1. Resolves and validates the project root.
2. Calls `secret_scanner.scan()` and `bandit_runner.scan()`.
3. Deduplicates findings by `Finding.id`.
4. Clears `Finding.evidence` on every result so raw snippets cannot leak.
5. Sorts findings: CRITICAL first, then by `(file, line)` as tie-breakers.
6. Returns a `ScanResult` with:
   - `findings` — combined, sorted, deduplicated findings.
   - `status` — `SUCCESS`, `PARTIAL` (one scanner failed), or `FAILED` (both failed).
   - `errors` — one `ScannerError` per scanner that failed.

### `aegis.report`

Writes the final JSON report. Uses an atomic write pattern (write to `.tmp`, then
rename with `os.replace`) to avoid partial output files.

**Report schema (v1):**

```json
{
  "schema_version": "1",
  "aegis_version":  "<str>",
  "scan_timestamp": "<ISO 8601 UTC, e.g. 2024-01-15T12:34:56Z>",
  "scan_status":    "SUCCESS" | "PARTIAL" | "FAILED",
  "project_name":   "<last path component only — not the full absolute path>",
  "finding_count":  <int>,
  "severity_counts": { "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0 },
  "findings": [
    {
      "id":          "<rule_id:file:line>",
      "severity":    "HIGH",
      "file":        "src/config.py",
      "line":        12,
      "rule_id":     "AEGIS-SECRET-AWS-KEY-ID",
      "title":       "AWS Access Key ID detected",
      "description": "…",
      "evidence":    "aws_access_key_id = '[REDACTED]'",
      "remediation": "…"
    }
  ],
  "scanner_errors": [
    { "scanner": "bandit_runner", "error_type": "BanditNotFoundError", "message": "…" }
  ]
}
```

Rejects output paths that resolve to a location inside the scanned project root
(`UnsafeOutputPathError`) to prevent accidental overwriting of source files.

---

### `aegis.gui`

Optional PySide6 interface, enabled with `pip install -e ".[gui]"`.

- `main.py` creates the Qt application, loads the supplied icon, and starts the
  main window. `python -m aegis.gui` is the module entry point.
- `worker.py` runs one `run_scan()` call per scan in a `QThread`; exceptions are
  presented with sanitized messages.
- `main_window.py` validates project/report paths and presents ready, scanning,
  success, empty, partial, failed, and invalid-path states.
- `widgets/` contains the project/report path rows, findings table and controls,
  finding details, severity counters, and state banners.
- The details widget displays `Finding.redacted`, not raw `Finding.evidence`.
- `write_report()` is used for explicit JSON export. The GUI permits export for
  successful and partial results; a fully failed scan is not offered for export.

### Privacy and validation

| Property | Implementation | Test coverage |
|---|---|---|
| Raw evidence excluded from JSON | `Finding.to_dict()` exports `redacted` as `evidence`; the scanner clears raw `Finding.evidence` before returning | `tests/test_models.py`, `tests/test_report.py`, `tests/test_e2e.py` |
| Redacted output in GUI details | Detail widget reads only `Finding.redacted` | `tests/test_gui_results.py` |
| Safe CLI output | CLI summary omits source snippets and raw evidence | `tests/test_e2e.py` |
| Read-only scanning behavior | Scanner reads project files; report output is separately validated | `tests/test_e2e.py` |
| Report outside scanned project | Report writer rejects a destination within the project root | `tests/test_report.py`, `tests/test_gui_redesign.py` |

These tests exercise defined cases and synthetic fixtures; they do not prove that
all possible secrets or vulnerabilities will be detected or redacted.

**Not claimed (out of scope for MVP):**
- Side-channel leaks via OS telemetry.
- Security of the report file on disk after writing.
- Scanning of non-Python file types beyond secret detection.

---

## Path Containment

- User-supplied path is resolved with `Path.resolve()` before any traversal.
- Scanner candidates are checked against the resolved project root before reading.
- Report output path is checked: writing inside the scanned project is rejected.

---

## Exclusion Set

The following are never scanned, regardless of what the user provides as the project path:

```
.git/
__pycache__/
.tox/   .nox/   .eggs/
venv/   .venv/   env/   .env/   ENV/
node_modules/
dist/   build/
*.pyc   *.pyo   *.pyd
```

## Windows packaging

The Windows build is maintained separately from the application entry points:

- `packaging/aegis-cli.spec` creates a console-enabled CLI distribution.
- `packaging/aegis-gui.spec` creates a windowed GUI distribution and embeds the
  application icon assets.
- `packaging/build.ps1` requires 64-bit Python 3.13, stages the matching Python
  embeddable runtime and dependencies for Bandit's `sys.executable -m bandit`
  subprocess invocation, then builds both onedir distributions.
- `packaging/pyinstaller_runtime.py` directs the frozen application's Bandit
  subprocess to that bundled runtime.

The output directories are `dist/windows/aegis/` and
`dist/windows/aegis-gui/`. Each `.exe` depends on its adjacent `_internal`
directory and other generated files; it is not a standalone executable. The
build downloads Python and installs dependencies, so build-time network access
may be required. Keep build instructions in the README aligned with the script.
