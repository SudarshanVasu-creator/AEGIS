# AEGIS Architecture

## Overview

AEGIS is a Python CLI application that scans a local source-code project for security
issues. All processing is local. No data leaves the machine.

The pipeline has five stages:

```
CLI  →  Path Validation  →  Scanner Engines  →  Redactor  →  Report Writer
                                  ├── Bandit runner (Python AST)
                                  └── Regex secret scanner (all text files)
```

---

## Modules

### `aegis.cli`

Entry point. Parses command-line arguments using `argparse`.

- `scan --project <path> --output <file>` — runs the full pipeline.
- `--version` — prints the package version and exits.
- Validates that `--project` exists and is a directory before invoking the scanner.
- Prints a human-readable summary to stdout (finding counts only — no secret values).
- Exit codes: `0` success, `1` bad arguments, `2` scan failed, `3` report write failed.

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
text file, applies the redactor patterns line-by-line to detect secrets.

- Skips binary files (catches `UnicodeDecodeError`, logs a warning, continues).
- Hard-excludes: `.git/`, `__pycache__/`, `venv/`, `.venv/`, `env/`, `ENV/`,
  `node_modules/`, files with `.pyc`/`.pyo`/`.pyd` suffixes.
- All file paths in findings are relative to the project root.

Returns a list of `Finding` objects with `evidence` populated and `redacted` already
set by calling `redact()` internally.

### `aegis.bandit_runner`

Invokes Bandit via a safe subprocess argument list (`shell=False`) with JSON output
(`bandit -f json`). Parses stdout and converts Bandit results into `Finding` objects.

- Maps Bandit severity + confidence levels to `aegis.Severity`.
- Applies the same directory exclusions as `secret_scanner`.
- Bandit emits absolute paths; the runner relativises them against the project root.
- Redacts the `code` and `issue_text` fields from Bandit output before storing
  `evidence`, because Bandit's `issue_text` can contain raw secret values.

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

## Privacy Guarantees (Verified by Design and Tests)

| Guarantee | Mechanism | Verified by |
|---|---|---|
| No outbound network calls | No network-capable imports (`requests`, `urllib`, `socket`, `http`, `ftplib`, `smtplib`) in `src/aegis/` | Static `grep` (zero matches) |
| No raw secret values in report | `evidence` excluded from `Finding.to_dict()`; `redacted` exported under key `"evidence"` | `test_e2e.py::test_no_raw_secrets_in_report_json` |
| No raw secret values in console | CLI prints counts only; `redacted` field used if evidence is shown | `test_e2e.py::test_cli_scan_stdout_contains_no_raw_secrets` |
| No modification of scanned files | Scanners are read-only; report written outside project root | `test_e2e.py::test_fixture_files_not_modified` |
| No mandatory credentials required | All tests use synthetic fake data | All tests pass without real credentials |

**Not claimed (out of scope for MVP):**
- Side-channel leaks via OS telemetry.
- Security of the report file on disk after writing.
- Scanning of non-Python file types beyond secret detection.

---

## Path Containment

- User-supplied path is resolved with `Path.resolve()` before any traversal.
- All discovered file paths are validated to be within the resolved project root.
- Symlinks outside the project root are not followed.
- Report output path is checked: writing inside the scanned project is rejected.

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
