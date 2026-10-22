"""End-to-end tests for the full AEGIS scan pipeline.

These tests exercise the real scanners (no mocking) against the synthetic
fixture project at ``tests/fixtures/vulnerable_project/``.  They prove that:

1. The pipeline runs without error on a well-formed project directory.
2. At least one finding is produced.
3. The ``evidence`` key is absent from every finding dict in the JSON report
   (raw source-code snippets must never be serialised).
4. None of the known synthetic secret *values* appear anywhere in the report
   JSON (redaction is effective).
5. All fixture files are unchanged after the scan (no accidental writes).
6. The JSON report schema is structurally valid.
7. The scan exit path (via the CLI) produces the correct exit code.

No real credentials are used anywhere in this file.
Synthetic secret strings appear only in the _KNOWN_SECRETS list so they can
be checked for *absence* in the report — they are never printed to any output.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from aegis.report import write_report
from aegis.scanner import ScanStatus, run_scan

# ---------------------------------------------------------------------------
# Fixture path
# ---------------------------------------------------------------------------

VULNERABLE_PROJECT = Path(__file__).parent / "fixtures" / "vulnerable_project"

# ---------------------------------------------------------------------------
# Synthetic secret values defined in fixtures/vulnerable_project/config.py.
# These strings are listed here ONLY to assert their absence from the report.
# Do not log, print, or use these values for any other purpose.
# ---------------------------------------------------------------------------
_KNOWN_SECRETS = [
    "AKIAFAKEACCESSKEY001",
    "FakeAwsSecretKey1234567890abcdefghijABCD",
    "ghp_FakeGitHubTokenABCDEFGHIJKLMN1234",
    "fake-api-key-value-abc123xyz789",
    "FakeSuperSecretPwd99",
]


# ---------------------------------------------------------------------------
# Module-scoped shared fixtures  (run once for the whole module)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def scan_result():
    """Run a single real scan; share the result across all tests in this module."""
    return run_scan(VULNERABLE_PROJECT)


@pytest.fixture(scope="module")
def report_path(tmp_path_factory, scan_result):
    """Write the scan result to a temp JSON file; return its path."""
    out = tmp_path_factory.mktemp("reports") / "aegis-report.json"
    write_report(scan_result, out)
    return out


@pytest.fixture(scope="module")
def report_data(report_path) -> dict:
    """Parse the written JSON report once; share across all tests."""
    return json.loads(report_path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _collect_fixture_mtimes() -> dict[Path, float]:
    """Return a mapping of path → mtime for every file under VULNERABLE_PROJECT."""
    return {
        p: p.stat().st_mtime
        for p in VULNERABLE_PROJECT.rglob("*")
        if p.is_file()
    }


# ---------------------------------------------------------------------------
# 1. Pipeline runs without error
# ---------------------------------------------------------------------------

def test_scan_completes(scan_result):
    """run_scan() returns a ScanResult with status SUCCESS or PARTIAL."""
    assert scan_result.status in (ScanStatus.SUCCESS, ScanStatus.PARTIAL), (
        f"Scan failed entirely. Errors: {scan_result.errors}"
    )


def test_report_file_exists(report_path):
    """write_report() produces an output file."""
    assert report_path.exists()
    assert report_path.stat().st_size > 0


# ---------------------------------------------------------------------------
# 2. At least one finding is produced
# ---------------------------------------------------------------------------

def test_at_least_one_finding(scan_result):
    """The synthetic fixture must produce at least one finding."""
    assert scan_result.finding_count > 0, (
        "No findings were produced. "
        "The synthetic fixture project should contain detectable issues."
    )


def test_report_finding_count_positive(report_data):
    """The report's finding_count field is > 0."""
    assert report_data["finding_count"] > 0


def test_findings_list_not_empty(report_data):
    """The report's findings array is non-empty."""
    assert len(report_data["findings"]) > 0


# ---------------------------------------------------------------------------
# 3. Internal raw_evidence key absent from all finding dicts
# ---------------------------------------------------------------------------

def test_no_raw_evidence_key_in_findings(report_data):
    """No finding dict in the JSON report may contain the key 'raw_evidence'.

    The exported key 'evidence' holds only the *redacted* value.
    The internal Finding.evidence field must never be serialised.
    """
    for finding in report_data["findings"]:
        assert "raw_evidence" not in finding, (
            f"Finding {finding.get('id')} contains raw_evidence key"
        )


def test_evidence_key_is_redacted_value(report_data):
    """Where present, the 'evidence' field must not contain any raw secret."""
    for finding in report_data["findings"]:
        evidence_value = finding.get("evidence", "")
        for secret in _KNOWN_SECRETS:
            assert secret not in evidence_value, (
                # Do not include the secret value in the assertion message.
                f"Finding {finding.get('id')}: evidence field contains a raw secret value"
            )


# ---------------------------------------------------------------------------
# 4. No raw secret values anywhere in the report JSON
# ---------------------------------------------------------------------------

def test_no_raw_secrets_in_report_json(report_path):
    """The raw report JSON string must not contain any known synthetic secret."""
    report_text = report_path.read_text(encoding="utf-8")
    for secret in _KNOWN_SECRETS:
        assert secret not in report_text, (
            # Deliberately omit the secret value from the message.
            "A raw synthetic secret value was found in the report JSON. "
            "Redaction did not work correctly."
        )


# ---------------------------------------------------------------------------
# 5. Fixture files are unchanged after the scan
# ---------------------------------------------------------------------------

def test_fixture_files_not_modified():
    """All fixture files must have the same mtime before and after a scan."""
    before = _collect_fixture_mtimes()
    run_scan(VULNERABLE_PROJECT)
    after = _collect_fixture_mtimes()

    for path, mtime_before in before.items():
        assert path in after, f"Fixture file disappeared: {path}"
        assert after[path] == mtime_before, (
            f"Fixture file was modified during scan: {path}"
        )


# ---------------------------------------------------------------------------
# 6. JSON schema structural validity
# ---------------------------------------------------------------------------

def test_report_top_level_schema(report_data):
    """Report must contain all required top-level keys with correct types."""
    required = {
        "schema_version": str,
        "aegis_version":  str,
        "scan_timestamp": str,
        "scan_status":    str,
        "project_name":   str,
        "finding_count":  int,
        "severity_counts": dict,
        "findings":        list,
        "scanner_errors":  list,
    }
    for key, expected_type in required.items():
        assert key in report_data, f"Missing top-level key: {key}"
        assert isinstance(report_data[key], expected_type), (
            f"Key '{key}': expected {expected_type.__name__}, "
            f"got {type(report_data[key]).__name__}"
        )


def test_report_severity_counts_keys(report_data):
    """severity_counts must have entries for all five severity levels."""
    counts = report_data["severity_counts"]
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        assert level in counts, f"Missing severity level in severity_counts: {level}"
        assert isinstance(counts[level], int)


def test_report_finding_count_matches_list(report_data):
    """finding_count must equal the length of the findings list."""
    assert report_data["finding_count"] == len(report_data["findings"])


def test_each_finding_has_required_fields(report_data):
    """Each finding dict must contain the required fields with correct types."""
    required_fields = {
        "id":          str,
        "severity":    str,
        "file":        str,
        "rule_id":     str,
        "title":       str,
        "description": str,
        "remediation": str,
    }
    for finding in report_data["findings"]:
        for field, expected_type in required_fields.items():
            assert field in finding, (
                f"Finding missing required field '{field}': {finding.get('id')}"
            )
            assert isinstance(finding[field], expected_type), (
                f"Finding field '{field}': expected {expected_type.__name__}"
            )
        # 'line' may be int or None
        assert "line" in finding
        assert finding["line"] is None or isinstance(finding["line"], int)


def test_report_project_name_is_directory_name_only(report_data):
    """project_name must be just the final directory component, not a full path."""
    project_name = report_data["project_name"]
    assert project_name == VULNERABLE_PROJECT.name
    # Must not be an absolute path or contain path separators.
    assert "/" not in project_name
    assert "\\" not in project_name


# ---------------------------------------------------------------------------
# 7. CLI exit code test
# ---------------------------------------------------------------------------

def test_cli_scan_exits_zero(tmp_path):
    """python -m aegis scan --project <fixture> --output <tmp> exits 0."""
    output_file = tmp_path / "aegis-report.json"
    result = subprocess.run(
        [
            sys.executable, "-m", "aegis",
            "scan",
            "--project", str(VULNERABLE_PROJECT),
            "--output",  str(output_file),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"CLI exited with code {result.returncode}.\n"
        f"stdout: {result.stdout}\n"
        f"stderr: {result.stderr}"
    )
    assert output_file.exists(), "CLI did not produce the report file."


def test_cli_scan_stdout_contains_no_raw_secrets(tmp_path):
    """CLI stdout and stderr must not contain any known synthetic secret value."""
    output_file = tmp_path / "aegis-report.json"
    result = subprocess.run(
        [
            sys.executable, "-m", "aegis",
            "scan",
            "--project", str(VULNERABLE_PROJECT),
            "--output",  str(output_file),
        ],
        capture_output=True,
        text=True,
    )
    combined_output = result.stdout + result.stderr
    for secret in _KNOWN_SECRETS:
        assert secret not in combined_output, (
            "A raw synthetic secret value appeared in CLI output. "
            "Console output must only contain redacted values."
        )
