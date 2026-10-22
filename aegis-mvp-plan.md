# AEGIS MVP Implementation Plan

## Approved Design Decisions (post-review)

1. **Report evidence field:** Sanitised (redacted) evidence is exported under the JSON key
   `evidence`. The internal raw `evidence` field is never serialised.
2. **Bandit invocation:** Use subprocess with a safe argument list (`shell=False`) and
   `bandit -f json`. Do not use Bandit's internal Python API.
3. **Path containment:** Strengthen beyond `Path.resolve()` — validate all traversed paths
   remain inside the resolved project root; do not follow symlinks outside it.
   Privacy verification uses both static grep and runtime assertions in the e2e test.


## Top-Level Overview

**Goal:** Build a working CLI security scanner that accepts a local project path, runs
deterministic security checks, redacts sensitive evidence, and writes a structured JSON report.

**Scope:** Python CLI only. No frontend. No external API calls. No runtime dependency on IBM Bob.

**Approach:** Two scanning engines run on a user-selected directory:
1. **Bandit** — Python AST-based analysis (OWASP Top 10 patterns for Python).
2. **Custom regex scanner** — secret detection for AWS keys, GitHub tokens, generic API keys,
   and hardcoded passwords.

A redaction layer strips secret values before they appear in any output. A structured JSON
report is written to a user-specified local path.

---

## Architecture Diagram (described)

```
CLI entry point  ──►  Path validation  ──►  Scanner engine
                                                 ├── Bandit runner (Python files)
                                                 └── Regex secret scanner (all files)
                                             ↓
                                        Finding aggregator
                                             ↓
                                        Redactor (strips secret values)
                                             ↓
                                        Report writer (JSON)
```

---

## Repository Layout

```
AEGIS/
├── src/
│   └── aegis/
│       ├── __init__.py
│       ├── __main__.py          # python -m aegis entry point
│       ├── cli.py               # argparse CLI, path validation
│       ├── scanner.py           # orchestrates Bandit + regex scanner
│       ├── bandit_runner.py     # thin wrapper around Bandit API
│       ├── secret_scanner.py    # regex-based secret detection
│       ├── redactor.py          # evidence redaction
│       ├── models.py            # Finding dataclass + severity enum
│       └── report.py            # JSON report writer
├── tests/
│   ├── fixtures/
│   │   └── vulnerable_project/  # synthetic project with fake secrets
│   │       ├── app.py
│   │       └── config.py
│   ├── test_secret_scanner.py
│   ├── test_redactor.py
│   ├── test_report.py
│   └── test_e2e.py              # end-to-end: scan fixture, check JSON output
├── docs/
│   └── architecture.md
├── .env.example                 # AEGIS_REPORT_DIR only (optional output path config)
├── .gitignore
├── README.md
├── requirements.txt             # runtime: bandit
├── requirements-dev.txt         # pytest, pytest-cov
└── aegis-mvp-plan.md            # this file
```

---

## Sub-Tasks

### Sub-Task 1 — Repository Scaffold

**Status:** [x] done

**Intent:**
Establish the Python package, virtual environment instructions, dependency files, and
quality tooling so all subsequent sub-tasks have a runnable base.

**Expected Outcomes:**
- `python -m aegis --help` runs without error from the project root.
- `pytest tests/` discovers tests and exits with no failures (no tests yet — zero collected is OK).
- `requirements.txt` and `requirements-dev.txt` exist with pinned dependencies.
- `.gitignore` excludes venv, `__pycache__`, `*.pyc`, `.env`, `reports/`, and scanned projects.
- `README.md` contains project title, one-paragraph description, and setup instructions.

**Todo List:**
1. Create `src/aegis/__init__.py` (version string only).
2. Create `src/aegis/__main__.py` (calls `cli.main()`).
3. Create `src/aegis/cli.py` with a stub `main()` that prints `"AEGIS — not yet implemented"`.
4. Create `requirements.txt` with `bandit>=1.8.0`.
5. Create `requirements-dev.txt` with `pytest>=8.0`, `pytest-cov>=5.0`.
6. Create `.gitignore` (venv dirs, `__pycache__`, `*.pyc`, `.env`, `reports/`, `*.egg-info/`).
7. Create `README.md` with title, description, and setup instructions (venv + pip install).
8. Create `docs/architecture.md` (brief component descriptions — expand later).
9. Verify `python -m aegis --help` runs.

**Relevant Context:**
- Package entry point: `python -m aegis` via `src/aegis/__main__.py`.
- No `setup.py` or `pyproject.toml` yet — use `pip install -e .` with a minimal
  `pyproject.toml` (PEP 517, no build backend complexity).

---

### Sub-Task 2 — Data Models

**Status:** [x] done

**Intent:**
Define the `Finding` dataclass and `Severity` enum that every scanner and the report writer
share. Establishing this contract first prevents interface drift across sub-tasks.

**Expected Outcomes:**
- `models.py` defines `Severity` (CRITICAL, HIGH, MEDIUM, LOW, INFO) and `Finding`
  (id, severity, file, line, rule_id, title, description, evidence, redacted, remediation).
- `Finding` is serialisable to a plain dict (for JSON export).
- Unit tests cover serialisation round-trip.

**Todo List:**
1. Create `src/aegis/models.py` with `Severity` enum and `Finding` dataclass.
2. Add `to_dict()` method to `Finding`.
3. Write `tests/test_models.py` with at least one serialisation round-trip test.

**Relevant Context:**
- `evidence` field holds the raw matched snippet **before** redaction (internal use only).
- `redacted` field holds the evidence after the redactor runs (written to report).
- The `evidence` field must never be written to disk or console output.

---

### Sub-Task 3 — Redactor

**Status:** [x] done

**Intent:**
Implement a deterministic redaction layer that strips secret values from evidence strings
before they enter any output path.

**Expected Outcomes:**
- `redactor.py` exposes a single `redact(text: str) -> str` function.
- Patterns covered: AWS Access Key IDs (`AKIA…`), AWS Secret Access Keys, GitHub personal
  access tokens (`ghp_…`, `github_pat_…`), generic API keys (`api_key`, `apikey`, `token`
  patterns with assignment), hardcoded passwords (`password`, `passwd`, `pwd` with assignment).
- A matched value (right-hand side of assignment) is replaced with `[REDACTED]`.
- The key name / label is preserved so the finding remains actionable.
- Unit tests use only synthetic fake credentials.

**Todo List:**
1. Create `src/aegis/redactor.py` with `REDACTION_PATTERNS` list and `redact()` function.
2. Define regex patterns for each secret category (see Expected Outcomes).
3. Ensure patterns are case-insensitive and handle common assignment syntaxes
   (`=`, `:`, `="`).
4. Write `tests/test_redactor.py` with synthetic test cases for each pattern category.
5. Include a negative test: a string with no secrets must be returned unchanged.

**Relevant Context:**
- Bandit rule IDs B105/B106/B107 also detect hardcoded passwords; the redactor must
  handle their evidence snippets too.
- Never log or print the pre-redaction value.

---

### Sub-Task 4 — Regex Secret Scanner

**Status:** [ ] pending

**Intent:**
Implement the file-based regex scanner that walks the target directory and emits `Finding`
objects for detected secrets.

**Expected Outcomes:**
- `secret_scanner.py` exposes `scan(project_path: Path) -> list[Finding]`.
- Scans all text files; skips binary files gracefully.
- Applies hard exclusions: `.git/`, `__pycache__/`, `*.pyc`, `node_modules/`, common
  venv directory names (`venv`, `.venv`, `env`, `.env`).
- Each finding includes file path (relative to project root), line number, rule ID,
  and raw evidence (not yet redacted at this stage).
- Unit tests use the synthetic `tests/fixtures/vulnerable_project/` directory.

**Todo List:**
1. Create `tests/fixtures/vulnerable_project/config.py` with synthetic fake secrets
   (AWS key, GitHub token, hardcoded password — all fake, clearly labelled).
2. Create `src/aegis/secret_scanner.py` with `EXCLUSIONS` set and `scan()` function.
3. Implement file traversal using `Path.rglob("*")` with exclusion checks.
4. Handle `UnicodeDecodeError` on binary files — skip and continue.
5. Write `tests/test_secret_scanner.py` asserting each fake secret is detected and
   that clean files produce zero findings.

**Relevant Context:**
- Secret patterns used here mirror the patterns in `redactor.py` but are applied
  line-by-line to source files (match = finding).
- Relative file paths in findings prevent leaking absolute local directory structure
  in reports.

---

### Sub-Task 5 — Bandit Runner

**Status:** [ ] pending

**Intent:**
Wrap Bandit's Python API to run against the target directory and convert its output
into `Finding` objects.

**Expected Outcomes:**
- `bandit_runner.py` exposes `scan(project_path: Path) -> list[Finding]`.
- Uses Bandit's internal API (not subprocess) for clean integration and no shell dependency.
- Maps Bandit severity levels to `aegis.Severity`.
- Filters out findings from excluded directories (matching the exclusion set in
  `secret_scanner.py`).
- Unit tests use `tests/fixtures/vulnerable_project/app.py` which contains at least one
  deliberate Bandit-detectable issue (e.g. `subprocess` with `shell=True`, or `eval()`).

**Todo List:**
1. Create `tests/fixtures/vulnerable_project/app.py` with a synthetic Bandit-detectable
   issue (e.g. `subprocess.run(cmd, shell=True)` with a clearly fake command).
2. Research Bandit's internal API (`bandit.core.manager.BanditManager`) to confirm it
   works with Python 3.13.
3. Create `src/aegis/bandit_runner.py` implementing `scan()` using Bandit's API.
4. Map Bandit result severity/confidence to `aegis.Severity`.
5. Write `tests/test_bandit_runner.py` asserting the synthetic issue is detected.

**Relevant Context:**
- Bandit's public API: instantiate `BanditManager`, call `discover_files()`, then
  `run_tests()`, then read `results`.
- If Bandit's internal API proves unstable on 3.13, fall back to subprocess with
  `bandit -f json` and parse stdout — this is a known-safe fallback.

---

### Sub-Task 6 — Scanner Orchestrator

**Status:** [ ] pending

**Intent:**
Combine both scanners, run the redactor over all findings, and return a clean list of
redacted `Finding` objects ready for the report writer.

**Expected Outcomes:**
- `scanner.py` exposes `run_scan(project_path: Path) -> list[Finding]`.
- Calls both `bandit_runner.scan()` and `secret_scanner.scan()`.
- Runs `redactor.redact()` on each finding's `evidence` field; stores result in `redacted`.
- Clears the `evidence` field after redaction (sets to empty string) so it cannot leak.
- Returns findings sorted by severity (CRITICAL first).

**Todo List:**
1. Create `src/aegis/scanner.py` implementing `run_scan()`.
2. Import and call both scanner modules.
3. Apply redaction to each finding.
4. Clear `evidence` after redaction.
5. Sort findings by severity.
6. Write `tests/test_scanner.py` asserting: findings are returned, evidence field is empty,
   redacted field is not empty for secret findings.

---

### Sub-Task 7 — Report Writer

**Status:** [ ] pending

**Intent:**
Serialise findings to a structured JSON report and write it to the user-specified path.

**Expected Outcomes:**
- `report.py` exposes `write_report(findings: list[Finding], output_path: Path) -> None`.
- JSON schema: `{ "aegis_version": str, "scan_timestamp": ISO8601, "project_path": str,
  "finding_count": int, "findings": [ ...Finding.to_dict()... ] }`.
- `project_path` in the report is the absolute resolved path (privacy consideration:
  acceptable since this is a local report for the user who ran the scan).
- Output file is created atomically (write to `.tmp` then rename).
- Unit tests assert the JSON is valid, contains expected fields, and that `evidence`
  key is absent from each finding dict.

**Todo List:**
1. Create `src/aegis/report.py` with `write_report()`.
2. Build the report envelope dict.
3. Write to a `.tmp` file first, then `Path.rename()` to the final path.
4. Write `tests/test_report.py` asserting schema correctness and absence of `evidence`.

**Relevant Context:**
- `Finding.to_dict()` must explicitly exclude the `evidence` field.
- The `redacted` field IS included in the output under the key `evidence` (renamed on
  export) so the report is still actionable without exposing raw secrets.

---

### Sub-Task 8 — CLI Integration

**Status:** [ ] pending

**Intent:**
Wire the scanner and report writer to the CLI so the full vertical slice runs end-to-end
from the command line.

**Expected Outcomes:**
- `python -m aegis scan --project <path> --output <report.json>` runs the full pipeline.
- Console output shows: scan progress, finding count by severity, report path written.
- Console output never prints raw secret values (redacted field is printed if any
  evidence is shown at all).
- `--version` flag works.
- Non-zero exit code on scan error; zero exit code on successful scan (even if findings exist).

**Todo List:**
1. Update `src/aegis/cli.py` with argparse subcommands (`scan`, future placeholder).
2. Add `--project` (required) and `--output` (required) arguments to `scan` subcommand.
3. Add `--version` flag.
4. Validate `--project` path exists and is a directory; exit with clear message if not.
5. Call `scanner.run_scan()` and `report.write_report()`.
6. Print summary to stdout (counts only, no secret values).
7. Manually verify end-to-end run against `tests/fixtures/vulnerable_project/`.

---

### Sub-Task 9 — End-to-End Test

**Status:** [ ] pending

**Intent:**
Automated test that proves the full pipeline works: scan the synthetic project, validate
the JSON report, assert findings are present, assert no secrets appear in output.

**Expected Outcomes:**
- `tests/test_e2e.py` passes with `pytest tests/test_e2e.py`.
- Test scans `tests/fixtures/vulnerable_project/`, writes report to a temp directory.
- Assertions: report JSON is valid; at least one finding exists; `evidence` key is absent
  from finding dicts; no raw fake-secret strings appear anywhere in the report JSON.
- Fixture project files are unchanged after the scan (mtime comparison).

**Todo List:**
1. Create `tests/test_e2e.py`.
2. Use `tmp_path` pytest fixture for report output.
3. Assert JSON schema validity.
4. Assert finding count > 0.
5. Assert `evidence` key absent from all finding dicts.
6. Assert none of the known synthetic secret values appear in the report JSON string.
7. Assert all fixture file mtimes are unchanged.

---

### Sub-Task 10 — Privacy Verification & Documentation

**Status:** [ ] pending

**Intent:**
Statically verify the no-network-call guarantee, document the architecture, and finalise
the README so the project is handoff-ready.

**Expected Outcomes:**
- A grep/static check confirms no import of `requests`, `urllib`, `socket`, `http`,
  `ftplib`, or `smtplib` in `src/aegis/`.
- `docs/architecture.md` describes each module, the redaction flow, and exclusion logic.
- `README.md` is complete: purpose, privacy guarantees (with caveats), install, usage,
  test instructions, contributing notes.
- `.env.example` contains only `AEGIS_REPORT_DIR` (optional default output directory).

**Todo List:**
1. Run `grep -r "import requests\|import urllib\|import socket\|import http" src/aegis/`
   and confirm zero matches.
2. Write `docs/architecture.md`.
3. Finalise `README.md`.
4. Create `.env.example`.
5. Review `.gitignore` for completeness.

---

## Dependency Summary

| Package | Version Constraint | Purpose | Python 3.13 Compatible |
|---|---|---|---|
| `bandit` | `>=1.8.0` | Python AST security analysis | Yes (tested) |
| `pytest` | `>=8.0` | Test runner | Yes |
| `pytest-cov` | `>=5.0` | Coverage reporting | Yes |

**Deferred:** Gitleaks (Go binary, adds OS dependency), semgrep (large dependency tree).

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Bandit internal API unstable on Python 3.13 | Low | Medium | Fall back to `bandit -f json` subprocess |
| Regex patterns produce false positives | Medium | Low | Tune patterns with synthetic tests; document limitations |
| Binary file traversal causes crashes | Medium | Low | Catch `UnicodeDecodeError`, skip file, log warning |
| `pathlib.rename()` fails across drives | Low | Low | Use `shutil.move()` as fallback for atomic write |
| License not yet selected | — | Low | Do not add LICENSE file until discussed |

---

## Privacy Guarantee Scope

The following are **verified by design and tests**:
- No outbound network calls (static grep + no relevant imports).
- No secret values in JSON report (`evidence` field excluded from `to_dict()`).
- No modification of scanned files (mtime test in e2e suite).

The following are **not claimed** (out of scope for MVP):
- Side-channel leaks via OS telemetry.
- Security of the report file itself after it is written.
- Scanning of non-Python file types beyond secret detection.

---

## First Implementation Task

**Sub-Task 1 — Repository Scaffold** is the correct starting point.
It unblocks all other sub-tasks and can be verified immediately with
`python -m aegis --help` and `pytest tests/`.
