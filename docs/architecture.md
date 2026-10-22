# AEGIS Architecture

## Overview

AEGIS is a Python CLI application that scans a local source-code project for security
issues. All processing is local. No data leaves the machine.

The pipeline has five stages:

```
CLI  →  Path Validation  →  Scanner Engines  →  Redactor  →  Report Writer
```

---

## Modules

### `aegis.cli`

Entry point. Parses command-line arguments using `argparse`. Validates that the
`--project` path exists and is a directory before passing control to the scanner.
Prints a human-readable summary to stdout (finding counts only — no secret values).

### `aegis.models`

Defines the `Severity` enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) and the
`Finding` dataclass. Each `Finding` carries:

- `id` — unique identifier for the finding
- `severity` — `Severity` enum value
- `file` — relative path from the project root
- `line` — line number (1-based)
- `rule_id` — scanner rule identifier
- `title` — short description
- `description` — detailed description
- `evidence` — raw matched snippet (**internal only, never written to output**)
- `redacted` — evidence with secret values replaced by `[REDACTED]`
- `remediation` — actionable fix guidance

`Finding.to_dict()` serialises for JSON export. The `evidence` field is **excluded**;
`redacted` is exported under the key `evidence`.

### `aegis.redactor`

Exposes a single `redact(text: str) -> str` function. Applies a list of compiled
regex patterns to replace secret values with `[REDACTED]`. Patterns cover:

- AWS Access Key IDs (`AKIA…`)
- AWS Secret Access Keys
- GitHub personal access tokens (`ghp_…`, `github_pat_…`)
- Generic API key / token assignments
- Hardcoded password / passwd / pwd assignments

### `aegis.secret_scanner`

File-based scanner. Walks the project directory with `Path.rglob("*")`. For each
text file, applies the redactor patterns line-by-line to detect secrets.
Skips binary files (`UnicodeDecodeError`), and hard-excludes:
`.git/`, `__pycache__/`, `venv/`, `.venv/`, `env/`, `node_modules/`.

Returns a list of `Finding` objects with `evidence` populated and `redacted` empty
(redaction is applied by the orchestrator).

### `aegis.bandit_runner`

Invokes Bandit via a safe subprocess argument list (`shell=False`) with JSON output.
Parses stdout and converts Bandit results into `Finding` objects. Maps Bandit severity
levels to `aegis.Severity`. Applies the same directory exclusions as `secret_scanner`.

### `aegis.scanner`

Orchestrator. Calls both `bandit_runner.scan()` and `secret_scanner.scan()`. For each
finding, calls `redactor.redact()` on the `evidence` field, stores the result in
`redacted`, then clears `evidence`. Returns findings sorted by severity (highest first).

### `aegis.report`

Writes the final JSON report to the user-specified output path. Uses an atomic write
pattern (write to `.tmp`, then rename) to avoid partial output files. The JSON envelope
includes `aegis_version`, `scan_timestamp` (ISO 8601), `project_path`, `finding_count`,
and `findings` (list of `Finding.to_dict()` results).

---

## Privacy Guarantees (Verified by Design)

| Guarantee | Mechanism |
|---|---|
| No outbound network calls | No network imports in `src/aegis/`; verified by static grep |
| No secret values in output | `evidence` excluded from `Finding.to_dict()`; e2e test asserts absence |
| No modification of scanned files | E2E test asserts file mtimes unchanged after scan |
| No mandatory credentials | All tests use synthetic fake data |

---

## Path Containment

- User-supplied path is resolved with `Path.resolve()` before any traversal.
- All discovered file paths are validated to be within the resolved project root.
- Symlinks outside the project root are not followed.

---

## Exclusion Set

The following are never scanned, regardless of what the user provides as the project path:

```
.git/
__pycache__/
venv/   .venv/   env/   ENV/
node_modules/
*.pyc   *.pyo   *.pyd
```
