"""Tests for aegis.report (JSON report writer).

All test credentials are synthetic and clearly labelled as fake.
No real credentials are used anywhere in this file.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aegis import __version__
from aegis.models import Finding, Severity
from aegis.report import (
    SCHEMA_VERSION,
    ReportError,
    UnsafeOutputPathError,
    _build_report,
    write_report,
)
from aegis.scanner import ScanResult, ScanStatus, ScannerError

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULNERABLE_PROJECT = FIXTURES_DIR / "vulnerable_project"


def _make_finding(
    *,
    rule_id: str = "AEGIS-SECRET-PASSWORD",
    file: str = "src/app.py",
    line: int = 10,
    severity: Severity = Severity.HIGH,
    redacted: str = "password = '[REDACTED]'",
) -> Finding:
    """Return a Finding with evidence already cleared (as returned by run_scan)."""
    return Finding(
        id=f"{rule_id}:{file}:{line}",
        severity=severity,
        file=file,
        line=line,
        rule_id=rule_id,
        title="Test Finding",
        description="A test security finding.",
        evidence="",            # always cleared before report writing
        redacted=redacted,
        remediation="Fix this.",
    )


def _make_result(
    *,
    findings: list[Finding] | None = None,
    status: ScanStatus = ScanStatus.SUCCESS,
    errors: list[ScannerError] | None = None,
    project_path: Path | None = None,
) -> ScanResult:
    return ScanResult(
        project_path=project_path or VULNERABLE_PROJECT.resolve(),
        findings=findings or [],
        status=status,
        errors=errors or [],
    )


def _read_report(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Basic JSON generation and parsing
# ---------------------------------------------------------------------------

class TestBasicReport:
    def test_creates_json_file(self, tmp_path):
        result = _make_result()
        out = tmp_path / "report.json"
        write_report(result, out)
        assert out.exists()
        assert out.stat().st_size > 0

    def test_output_is_valid_json(self, tmp_path):
        result = _make_result()
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert isinstance(data, dict)

    def test_top_level_keys_present(self, tmp_path):
        result = _make_result()
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        required_keys = {
            "schema_version", "aegis_version", "scan_timestamp",
            "scan_status", "project_name", "finding_count",
            "severity_counts", "findings", "scanner_errors",
        }
        assert required_keys.issubset(set(data.keys()))

    def test_schema_version_is_string(self, tmp_path):
        result = _make_result()
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert data["schema_version"] == SCHEMA_VERSION
        assert isinstance(data["schema_version"], str)

    def test_aegis_version_matches_package(self, tmp_path):
        result = _make_result()
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert data["aegis_version"] == __version__

    def test_encoded_as_utf8(self, tmp_path):
        result = _make_result()
        out = tmp_path / "report.json"
        write_report(result, out)
        raw = out.read_bytes()
        # UTF-8 BOM must not be present
        assert not raw.startswith(b"\xef\xbb\xbf")
        # Must be valid UTF-8
        raw.decode("utf-8")


# ---------------------------------------------------------------------------
# Project identification
# ---------------------------------------------------------------------------

class TestProjectIdentification:
    def test_project_name_is_last_path_component(self, tmp_path):
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()
        result = _make_result(project_path=project_dir)
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert data["project_name"] == "my-project"

    def test_full_absolute_path_not_in_report(self, tmp_path):
        """The full absolute project path must not appear anywhere in the JSON."""
        project_dir = tmp_path / "sensitive-project"
        project_dir.mkdir()
        result = _make_result(project_path=project_dir)
        out = tmp_path / "report.json"
        write_report(result, out)
        json_str = out.read_text(encoding="utf-8")
        # The parent path components should not appear
        assert str(project_dir.parent) not in json_str


# ---------------------------------------------------------------------------
# Scan status
# ---------------------------------------------------------------------------

class TestScanStatus:
    def test_success_status_serialised(self, tmp_path):
        result = _make_result(status=ScanStatus.SUCCESS)
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert data["scan_status"] == "SUCCESS"

    def test_partial_status_serialised(self, tmp_path):
        err = ScannerError(scanner="bandit_runner", error_type="BanditError",
                           message="Bandit failed to start.")
        result = _make_result(status=ScanStatus.PARTIAL, errors=[err])
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert data["scan_status"] == "PARTIAL"

    def test_failed_status_serialised(self, tmp_path):
        result = _make_result(status=ScanStatus.FAILED)
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert data["scan_status"] == "FAILED"


# ---------------------------------------------------------------------------
# Timestamp
# ---------------------------------------------------------------------------

class TestTimestamp:
    def test_timestamp_present_and_string(self, tmp_path):
        result = _make_result()
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert isinstance(data["scan_timestamp"], str)
        assert len(data["scan_timestamp"]) > 0

    def test_timestamp_iso8601_utc_format(self, tmp_path):
        """Timestamp must follow YYYY-MM-DDTHH:MM:SSZ format."""
        result = _make_result()
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        ts = data["scan_timestamp"]
        # Must be parseable as UTC ISO 8601
        parsed = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        assert parsed.year >= 2024

    def test_timestamp_ends_with_z(self, tmp_path):
        result = _make_result()
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert data["scan_timestamp"].endswith("Z")


# ---------------------------------------------------------------------------
# Finding count and severity counts
# ---------------------------------------------------------------------------

class TestCounts:
    def test_empty_scan_zero_counts(self, tmp_path):
        result = _make_result(findings=[])
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert data["finding_count"] == 0
        assert all(v == 0 for v in data["severity_counts"].values())

    def test_finding_count_matches_findings_length(self, tmp_path):
        findings = [
            _make_finding(severity=Severity.CRITICAL, rule_id="R1", line=1),
            _make_finding(severity=Severity.HIGH,     rule_id="R2", line=2),
            _make_finding(severity=Severity.LOW,      rule_id="R3", line=3),
        ]
        result = _make_result(findings=findings)
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert data["finding_count"] == 3

    def test_severity_counts_correct(self, tmp_path):
        findings = [
            _make_finding(severity=Severity.CRITICAL, rule_id="R1", line=1),
            _make_finding(severity=Severity.CRITICAL, rule_id="R2", line=2),
            _make_finding(severity=Severity.HIGH,     rule_id="R3", line=3),
            _make_finding(severity=Severity.LOW,      rule_id="R4", line=4),
        ]
        result = _make_result(findings=findings)
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert data["severity_counts"]["CRITICAL"] == 2
        assert data["severity_counts"]["HIGH"] == 1
        assert data["severity_counts"]["MEDIUM"] == 0
        assert data["severity_counts"]["LOW"] == 1
        assert data["severity_counts"]["INFO"] == 0

    def test_severity_counts_has_all_levels(self, tmp_path):
        result = _make_result()
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert set(data["severity_counts"].keys()) == {
            "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
        }


# ---------------------------------------------------------------------------
# Finding serialisation
# ---------------------------------------------------------------------------

class TestFindingSerialisation:
    def test_finding_keys_present(self, tmp_path):
        result = _make_result(findings=[_make_finding()])
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        f = data["findings"][0]
        expected_keys = {
            "id", "severity", "file", "line", "rule_id",
            "title", "description", "evidence", "remediation",
        }
        assert expected_keys.issubset(set(f.keys()))

    def test_finding_severity_is_string(self, tmp_path):
        result = _make_result(findings=[_make_finding(severity=Severity.CRITICAL)])
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert data["findings"][0]["severity"] == "CRITICAL"
        assert isinstance(data["findings"][0]["severity"], str)

    def test_finding_line_none_serialises_as_null(self, tmp_path):
        f = Finding(
            id="R:file.py:None",
            severity=Severity.INFO,
            file="file.py",
            line=None,
            rule_id="R",
            title="T",
            description="D",
            evidence="",
            redacted="",
            remediation="Fix.",
        )
        result = _make_result(findings=[f])
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert data["findings"][0]["line"] is None

    def test_findings_order_preserved(self, tmp_path):
        f1 = _make_finding(rule_id="R1", line=1, severity=Severity.CRITICAL)
        f2 = _make_finding(rule_id="R2", line=2, severity=Severity.HIGH)
        result = _make_result(findings=[f1, f2])
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert data["findings"][0]["rule_id"] == "R1"
        assert data["findings"][1]["rule_id"] == "R2"

    def test_relative_file_path_preserved(self, tmp_path):
        result = _make_result(findings=[_make_finding(file="src/module.py")])
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert data["findings"][0]["file"] == "src/module.py"


# ---------------------------------------------------------------------------
# Redaction contract
# ---------------------------------------------------------------------------

class TestRedactionContract:
    # Synthetic fake credentials — clearly not real
    FAKE_PASSWORD = "FakeSuperSecretPwd99"
    FAKE_AWS_KEY = "AKIAFAKEACCESSKEY001"

    def test_redacted_evidence_in_report(self, tmp_path):
        """The 'evidence' field in the report must contain the redacted value."""
        f = _make_finding(redacted="password = '[REDACTED]'")
        result = _make_result(findings=[f])
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert "[REDACTED]" in data["findings"][0]["evidence"]

    def test_raw_fake_password_absent_from_report(self, tmp_path):
        """Raw fake password must not appear anywhere in the JSON report."""
        f = _make_finding(redacted="password = '[REDACTED]'")
        # Simulate what the orchestrator does: evidence is cleared before writing
        f.evidence = ""
        result = _make_result(findings=[f])
        out = tmp_path / "report.json"
        write_report(result, out)
        json_str = out.read_text(encoding="utf-8")
        assert self.FAKE_PASSWORD not in json_str, (
            "Raw fake password found in JSON report."
        )

    def test_raw_fake_aws_key_absent_from_report(self, tmp_path):
        f = _make_finding(
            rule_id="AEGIS-SECRET-AWS-KEY-ID",
            redacted=f"aws_access_key_id = '[REDACTED]'",
        )
        f.evidence = ""
        result = _make_result(findings=[f])
        out = tmp_path / "report.json"
        write_report(result, out)
        json_str = out.read_text(encoding="utf-8")
        assert self.FAKE_AWS_KEY not in json_str

    def test_evidence_field_never_contains_raw_value(self, tmp_path):
        """Even if evidence is not empty, to_dict() must not export it."""
        # Build a Finding that still has raw evidence set (before clearing)
        f = Finding(
            id="R:f.py:1",
            severity=Severity.HIGH,
            file="f.py",
            line=1,
            rule_id="R",
            title="T",
            description="D",
            evidence=self.FAKE_PASSWORD,    # intentionally NOT cleared
            redacted="password = '[REDACTED]'",
            remediation="Fix.",
        )
        result = _make_result(findings=[f])
        out = tmp_path / "report.json"
        write_report(result, out)
        json_str = out.read_text(encoding="utf-8")
        # to_dict() must export redacted under "evidence", not the raw value
        assert self.FAKE_PASSWORD not in json_str


# ---------------------------------------------------------------------------
# Scanner errors in report
# ---------------------------------------------------------------------------

class TestScannerErrors:
    def test_empty_errors_on_success(self, tmp_path):
        result = _make_result(status=ScanStatus.SUCCESS)
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert data["scanner_errors"] == []

    def test_scanner_error_serialised(self, tmp_path):
        err = ScannerError(
            scanner="bandit_runner",
            error_type="BanditTimeoutError",
            message="Bandit did not complete within 120 seconds.",
        )
        result = _make_result(status=ScanStatus.PARTIAL, errors=[err])
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert len(data["scanner_errors"]) == 1
        e = data["scanner_errors"][0]
        assert e["scanner"] == "bandit_runner"
        assert e["error_type"] == "BanditTimeoutError"
        assert "120" in e["message"]

    def test_multiple_errors_serialised(self, tmp_path):
        errors = [
            ScannerError("secret_scanner", "RuntimeError", "Disk read error."),
            ScannerError("bandit_runner", "BanditError", "Bandit crashed."),
        ]
        result = _make_result(status=ScanStatus.FAILED, errors=errors)
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert len(data["scanner_errors"]) == 2
        scanner_names = {e["scanner"] for e in data["scanner_errors"]}
        assert scanner_names == {"secret_scanner", "bandit_runner"}


# ---------------------------------------------------------------------------
# Unicode
# ---------------------------------------------------------------------------

class TestUnicode:
    def test_unicode_finding_text_preserved(self, tmp_path):
        """Unicode characters in titles and descriptions must round-trip cleanly."""
        f = Finding(
            id="R:src/módulo.py:1",
            severity=Severity.MEDIUM,
            file="src/módulo.py",       # Unicode filename
            line=1,
            rule_id="R",
            title="Contraseña expuesta",  # Spanish
            description="Une clé API exposée dans le code source.",  # French
            evidence="",
            redacted="api_key = '[REDACTED]'",
            remediation="Corriger immédiatement.",
        )
        result = _make_result(findings=[f])
        out = tmp_path / "report.json"
        write_report(result, out)
        data = _read_report(out)
        assert data["findings"][0]["file"] == "src/módulo.py"
        assert "clé" in data["findings"][0]["description"]

    def test_unicode_not_escaped_to_ascii(self, tmp_path):
        """ensure_ascii=False: non-ASCII chars must appear as-is in the JSON file."""
        f = _make_finding()
        f.title = "Señal de alerta"
        result = _make_result(findings=[f])
        out = tmp_path / "report.json"
        write_report(result, out)
        raw = out.read_bytes().decode("utf-8")
        assert "Señal" in raw
        assert r"\u00" not in raw  # no ASCII-escaped Unicode


# ---------------------------------------------------------------------------
# Output safety: invalid and unsafe destinations
# ---------------------------------------------------------------------------

class TestOutputSafety:
    def test_output_inside_project_root_rejected(self, tmp_path):
        """Writing to a path inside the project must raise UnsafeOutputPathError."""
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()
        result = _make_result(project_path=project_dir)
        # Attempt to write report inside the project
        inside_path = project_dir / "report.json"
        with pytest.raises(UnsafeOutputPathError):
            write_report(result, inside_path)

    def test_output_in_subdirectory_of_project_rejected(self, tmp_path):
        project_dir = tmp_path / "my-project"
        (project_dir / "reports").mkdir(parents=True)
        result = _make_result(project_path=project_dir)
        inside_path = project_dir / "reports" / "scan.json"
        with pytest.raises(UnsafeOutputPathError):
            write_report(result, inside_path)

    def test_output_outside_project_accepted(self, tmp_path):
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()
        result = _make_result(project_path=project_dir)
        outside_path = tmp_path / "reports" / "scan.json"
        write_report(result, outside_path)   # must not raise
        assert outside_path.exists()

    def test_parent_directory_created_automatically(self, tmp_path):
        result = _make_result()
        nested = tmp_path / "a" / "b" / "c" / "report.json"
        write_report(result, nested)
        assert nested.exists()

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="chmod read-only directories behave differently on Windows",
    )
    def test_unwritable_directory_raises_report_error(self, tmp_path):
        """A permission-denied output must raise ReportError."""
        locked_dir = tmp_path / "locked"
        locked_dir.mkdir()
        locked_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)
        try:
            result = _make_result()
            out = locked_dir / "report.json"
            with pytest.raises(ReportError):
                write_report(result, out)
        finally:
            locked_dir.chmod(stat.S_IRWXU)  # restore so tmp cleanup works


# ---------------------------------------------------------------------------
# Atomic write behaviour
# ---------------------------------------------------------------------------

class TestAtomicWrite:
    def test_no_tmp_file_left_on_success(self, tmp_path):
        result = _make_result()
        out = tmp_path / "report.json"
        write_report(result, out)
        tmp = out.with_suffix(".json.tmp")
        assert not tmp.exists(), "Temporary file must be removed after successful write"

    def test_output_file_exists_after_write(self, tmp_path):
        result = _make_result()
        out = tmp_path / "report.json"
        write_report(result, out)
        assert out.exists()

    def test_overwrite_existing_report(self, tmp_path):
        """A second write to the same path must replace the first."""
        result1 = _make_result(findings=[])
        out = tmp_path / "report.json"
        write_report(result1, out)
        first_count = _read_report(out)["finding_count"]

        f = _make_finding()
        result2 = _make_result(findings=[f])
        write_report(result2, out)
        second_count = _read_report(out)["finding_count"]

        assert first_count == 0
        assert second_count == 1


# ---------------------------------------------------------------------------
# Deterministic structure
# ---------------------------------------------------------------------------

class TestDeterministicOutput:
    def test_two_writes_produce_same_structure(self, tmp_path):
        """Two calls with the same data must produce the same JSON structure."""
        f = _make_finding()
        result = _make_result(findings=[f])
        out1 = tmp_path / "r1.json"
        out2 = tmp_path / "r2.json"
        write_report(result, out1)
        write_report(result, out2)
        d1 = _read_report(out1)
        d2 = _read_report(out2)
        # Timestamps will differ; exclude them for structural comparison
        d1.pop("scan_timestamp")
        d2.pop("scan_timestamp")
        assert d1 == d2

    def test_json_is_indented(self, tmp_path):
        """Report must be human-readable (indented), not minified."""
        result = _make_result()
        out = tmp_path / "report.json"
        write_report(result, out)
        raw = out.read_text(encoding="utf-8")
        assert "\n" in raw
        assert "  " in raw  # indent-2 spaces


# ---------------------------------------------------------------------------
# Fixture file immutability
# ---------------------------------------------------------------------------

class TestFilesUnchanged:
    def test_fixture_files_not_modified_by_report_write(self, tmp_path):
        """Writing a report must not modify any file in the fixture project."""
        fixture_files = list(VULNERABLE_PROJECT.rglob("*.py"))
        assert fixture_files

        mtimes_before = {f: f.stat().st_mtime for f in fixture_files}

        result = _make_result(project_path=VULNERABLE_PROJECT.resolve())
        out = tmp_path / "report.json"
        write_report(result, out)

        for f in fixture_files:
            assert f.stat().st_mtime == mtimes_before[f], (
                f"Fixture file modified during report write: {f}"
            )


# ---------------------------------------------------------------------------
# _build_report unit tests (internal helper)
# ---------------------------------------------------------------------------

class TestBuildReport:
    def test_build_report_returns_dict(self):
        result = _make_result()
        ts = datetime(2024, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        data = _build_report(result, ts)
        assert isinstance(data, dict)

    def test_build_report_timestamp_format(self):
        result = _make_result()
        ts = datetime(2024, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        data = _build_report(result, ts)
        assert data["scan_timestamp"] == "2024-06-15T10:30:00Z"

    def test_build_report_no_raw_evidence(self):
        """_build_report must not include raw evidence in any finding."""
        fake = "FakeSuperSecretPwd99"
        f = Finding(
            id="R:f.py:1",
            severity=Severity.HIGH,
            file="f.py",
            line=1,
            rule_id="R",
            title="T",
            description="D",
            evidence=fake,                    # raw — intentionally set for test
            redacted="password = '[REDACTED]'",
            remediation="Fix.",
        )
        result = _make_result(findings=[f])
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        data = _build_report(result, ts)
        report_str = json.dumps(data)
        assert fake not in report_str, "Raw fake secret found in _build_report output."
