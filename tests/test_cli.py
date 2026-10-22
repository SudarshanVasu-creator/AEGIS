"""Tests for aegis.cli (CLI integration).

Uses pytest's capsys/capfd for stdout/stderr capture and subprocess.run for
process-level exit code verification.  Scanner and report modules are mocked
in unit tests; integration tests run the real pipeline against the synthetic
fixture project.

No real credentials are used or printed anywhere in this file.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegis import __version__
from aegis.cli import (
    DEFAULT_OUTPUT,
    EXIT_BAD_ARGS,
    EXIT_OK,
    EXIT_REPORT_FAIL,
    EXIT_SCAN_FAIL,
    _run_scan_command,
    build_parser,
    main,
)
from aegis.models import Finding, Severity
from aegis.report import ReportError, UnsafeOutputPathError
from aegis.scanner import ScanResult, ScanStatus, ScannerError

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULNERABLE_PROJECT = FIXTURES_DIR / "vulnerable_project"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    *,
    rule_id: str = "AEGIS-SECRET-PASSWORD",
    file: str = "src/app.py",
    line: int = 10,
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        id=f"{rule_id}:{file}:{line}",
        severity=severity,
        file=file,
        line=line,
        rule_id=rule_id,
        title="Test Finding",
        description="A test finding description.",
        evidence="",         # always cleared before CLI sees it
        redacted="password = '[REDACTED]'",
        remediation="Fix it.",
    )


def _make_result(
    *,
    findings: list[Finding] | None = None,
    status: ScanStatus = ScanStatus.SUCCESS,
    errors: list[ScannerError] | None = None,
    project_path: Path | None = None,
) -> ScanResult:
    return ScanResult(
        project_path=(project_path or VULNERABLE_PROJECT).resolve(),
        findings=findings or [],
        status=status,
        errors=errors or [],
    )


def _make_args(
    project: str | None = None,
    output: str = DEFAULT_OUTPUT,
) -> object:
    """Return a simple namespace mimicking parsed argparse args."""
    class _Args:
        command = "scan"
    a = _Args()
    a.project = project or str(VULNERABLE_PROJECT)
    a.output = output
    return a


def _run_main_subprocess(*extra_args: str) -> subprocess.CompletedProcess:
    """Run `python -m aegis` as a real subprocess and return the result."""
    return subprocess.run(
        [sys.executable, "-m", "aegis", *extra_args],
        capture_output=True,
        text=True,
        timeout=120,
    )


# ---------------------------------------------------------------------------
# Parser / help / version
# ---------------------------------------------------------------------------

class TestParserHelp:
    def test_help_exits_zero(self):
        r = _run_main_subprocess("--help")
        assert r.returncode == 0

    def test_help_contains_scan_command(self):
        r = _run_main_subprocess("--help")
        assert "scan" in r.stdout

    def test_version_exits_zero(self):
        r = _run_main_subprocess("--version")
        assert r.returncode == 0

    def test_version_output_contains_version_string(self):
        r = _run_main_subprocess("--version")
        assert __version__ in r.stdout

    def test_scan_help_exits_zero(self):
        r = _run_main_subprocess("scan", "--help")
        assert r.returncode == 0

    def test_scan_help_mentions_project(self):
        r = _run_main_subprocess("scan", "--help")
        assert "--project" in r.stdout

    def test_scan_help_mentions_output(self):
        r = _run_main_subprocess("scan", "--help")
        assert "--output" in r.stdout

    def test_scan_help_mentions_default_output(self):
        r = _run_main_subprocess("scan", "--help")
        # argparse wraps long help strings and may break on hyphens
        # (e.g. "aegis-\n  report.json").  Strip all whitespace runs to one space.
        import re
        combined = re.sub(r"\s+", " ", r.stdout)
        # The filename may be broken as "aegis- report.json"; check both parts.
        assert "aegis" in combined and "report.json" in combined

    def test_no_subcommand_exits_zero(self):
        r = _run_main_subprocess()
        assert r.returncode == 0

    def test_no_subcommand_prints_help(self):
        r = _run_main_subprocess()
        assert "scan" in r.stdout


# ---------------------------------------------------------------------------
# Exit code constants
# ---------------------------------------------------------------------------

class TestExitCodes:
    def test_exit_ok_is_zero(self):
        assert EXIT_OK == 0

    def test_exit_bad_args_is_one(self):
        assert EXIT_BAD_ARGS == 1

    def test_exit_scan_fail_is_two(self):
        assert EXIT_SCAN_FAIL == 2

    def test_exit_report_fail_is_three(self):
        assert EXIT_REPORT_FAIL == 3


# ---------------------------------------------------------------------------
# Invalid project paths
# ---------------------------------------------------------------------------

class TestInvalidProjectPaths:
    def test_nonexistent_path_exits_bad_args(self, tmp_path, capsys):
        args = _make_args(project=str(tmp_path / "does_not_exist"),
                          output=str(tmp_path / "r.json"))
        code = _run_scan_command(args)
        assert code == EXIT_BAD_ARGS

    def test_nonexistent_path_error_to_stderr(self, tmp_path, capsys):
        args = _make_args(project=str(tmp_path / "nope"),
                          output=str(tmp_path / "r.json"))
        _run_scan_command(args)
        captured = capsys.readouterr()
        assert "aegis: error" in captured.err
        assert "does not exist" in captured.err

    def test_file_path_exits_bad_args(self, tmp_path, capsys):
        f = tmp_path / "notadir.py"
        f.write_text("x = 1\n", encoding="utf-8")
        args = _make_args(project=str(f), output=str(tmp_path / "r.json"))
        code = _run_scan_command(args)
        assert code == EXIT_BAD_ARGS

    def test_file_path_error_to_stderr(self, tmp_path, capsys):
        f = tmp_path / "notadir.py"
        f.write_text("x = 1\n", encoding="utf-8")
        args = _make_args(project=str(f), output=str(tmp_path / "r.json"))
        _run_scan_command(args)
        captured = capsys.readouterr()
        assert "aegis: error" in captured.err

    def test_missing_project_arg_exits_nonzero(self):
        r = _run_main_subprocess("scan")
        assert r.returncode != 0


# ---------------------------------------------------------------------------
# Successful scan — with findings (mocked)
# ---------------------------------------------------------------------------

class TestSuccessfulScanWithFindings:
    def test_exit_ok(self, tmp_path):
        result = _make_result(
            findings=[_make_finding(severity=Severity.CRITICAL)],
            project_path=tmp_path / "proj",
        )
        (tmp_path / "proj").mkdir()
        out = tmp_path / "report.json"
        args = _make_args(project=str(tmp_path / "proj"), output=str(out))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report"):
            code = _run_scan_command(args)
        assert code == EXIT_OK

    def test_summary_printed_to_stdout(self, tmp_path, capsys):
        result = _make_result(
            findings=[_make_finding(severity=Severity.CRITICAL)],
            project_path=tmp_path / "proj",
        )
        (tmp_path / "proj").mkdir()
        out = tmp_path / "report.json"
        args = _make_args(project=str(tmp_path / "proj"), output=str(out))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report"):
            _run_scan_command(args)
        captured = capsys.readouterr()
        assert "proj" in captured.out
        assert "CRITICAL" in captured.out
        assert "Findings" in captured.out

    def test_finding_count_in_output(self, tmp_path, capsys):
        findings = [
            _make_finding(rule_id="R1", line=1, severity=Severity.HIGH),
            _make_finding(rule_id="R2", line=2, severity=Severity.LOW),
        ]
        result = _make_result(findings=findings, project_path=tmp_path / "p")
        (tmp_path / "p").mkdir()
        args = _make_args(project=str(tmp_path / "p"),
                          output=str(tmp_path / "r.json"))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report"):
            _run_scan_command(args)
        captured = capsys.readouterr()
        assert "2" in captured.out

    def test_report_path_in_output(self, tmp_path, capsys):
        result = _make_result(project_path=tmp_path / "p")
        (tmp_path / "p").mkdir()
        out_path = tmp_path / "my_report.json"
        args = _make_args(project=str(tmp_path / "p"), output=str(out_path))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report"):
            _run_scan_command(args)
        captured = capsys.readouterr()
        assert "my_report.json" in captured.out


# ---------------------------------------------------------------------------
# Successful scan — zero findings (mocked)
# ---------------------------------------------------------------------------

class TestSuccessfulScanZeroFindings:
    def test_exit_ok_with_no_findings(self, tmp_path):
        result = _make_result(findings=[], project_path=tmp_path / "clean")
        (tmp_path / "clean").mkdir()
        args = _make_args(project=str(tmp_path / "clean"),
                          output=str(tmp_path / "r.json"))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report"):
            code = _run_scan_command(args)
        assert code == EXIT_OK

    def test_zero_finding_count_shown(self, tmp_path, capsys):
        result = _make_result(findings=[], project_path=tmp_path / "clean")
        (tmp_path / "clean").mkdir()
        args = _make_args(project=str(tmp_path / "clean"),
                          output=str(tmp_path / "r.json"))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report"):
            _run_scan_command(args)
        captured = capsys.readouterr()
        assert "0" in captured.out


# ---------------------------------------------------------------------------
# Partial scan (mocked)
# ---------------------------------------------------------------------------

class TestPartialScan:
    def test_partial_exits_ok(self, tmp_path):
        """PARTIAL with findings still exits EXIT_OK — scan produced results."""
        err = ScannerError("bandit_runner", "BanditError", "Bandit failed.")
        result = _make_result(
            findings=[_make_finding()],
            status=ScanStatus.PARTIAL,
            errors=[err],
            project_path=tmp_path / "p",
        )
        (tmp_path / "p").mkdir()
        args = _make_args(project=str(tmp_path / "p"),
                          output=str(tmp_path / "r.json"))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report"):
            code = _run_scan_command(args)
        assert code == EXIT_OK

    def test_partial_prints_warning(self, tmp_path, capsys):
        err = ScannerError("bandit_runner", "BanditError", "Bandit failed.")
        result = _make_result(
            status=ScanStatus.PARTIAL,
            errors=[err],
            project_path=tmp_path / "p",
        )
        (tmp_path / "p").mkdir()
        args = _make_args(project=str(tmp_path / "p"),
                          output=str(tmp_path / "r.json"))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report"):
            _run_scan_command(args)
        captured = capsys.readouterr()
        assert "WARNING" in captured.out
        assert "bandit_runner" in captured.out

    def test_partial_status_shown(self, tmp_path, capsys):
        err = ScannerError("secret_scanner", "RuntimeError", "IO error.")
        result = _make_result(
            status=ScanStatus.PARTIAL,
            errors=[err],
            project_path=tmp_path / "p",
        )
        (tmp_path / "p").mkdir()
        args = _make_args(project=str(tmp_path / "p"),
                          output=str(tmp_path / "r.json"))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report"):
            _run_scan_command(args)
        captured = capsys.readouterr()
        assert "PARTIAL" in captured.out


# ---------------------------------------------------------------------------
# Failed scan (mocked)
# ---------------------------------------------------------------------------

class TestFailedScan:
    def test_failed_scan_exits_scan_fail(self, tmp_path):
        result = _make_result(
            findings=[],
            status=ScanStatus.FAILED,
            errors=[
                ScannerError("secret_scanner", "RuntimeError", "crash"),
                ScannerError("bandit_runner", "BanditError", "crash"),
            ],
            project_path=tmp_path / "p",
        )
        (tmp_path / "p").mkdir()
        args = _make_args(project=str(tmp_path / "p"),
                          output=str(tmp_path / "r.json"))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report"):
            code = _run_scan_command(args)
        assert code == EXIT_SCAN_FAIL

    def test_failed_scan_status_in_output(self, tmp_path, capsys):
        result = _make_result(
            status=ScanStatus.FAILED,
            errors=[ScannerError("bandit_runner", "BanditError", "crash")],
            project_path=tmp_path / "p",
        )
        (tmp_path / "p").mkdir()
        args = _make_args(project=str(tmp_path / "p"),
                          output=str(tmp_path / "r.json"))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report"):
            _run_scan_command(args)
        captured = capsys.readouterr()
        assert "FAILED" in captured.out


# ---------------------------------------------------------------------------
# Report writing errors (mocked)
# ---------------------------------------------------------------------------

class TestReportWritingErrors:
    def test_unsafe_output_path_exits_bad_args(self, tmp_path):
        result = _make_result(project_path=tmp_path / "proj")
        (tmp_path / "proj").mkdir()
        # Output inside the project — unsafe
        inside = tmp_path / "proj" / "report.json"
        args = _make_args(project=str(tmp_path / "proj"), output=str(inside))
        with patch("aegis.cli.run_scan", return_value=result):
            code = _run_scan_command(args)
        assert code == EXIT_BAD_ARGS

    def test_unsafe_output_error_to_stderr(self, tmp_path, capsys):
        result = _make_result(project_path=tmp_path / "proj")
        (tmp_path / "proj").mkdir()
        inside = tmp_path / "proj" / "report.json"
        args = _make_args(project=str(tmp_path / "proj"), output=str(inside))
        with patch("aegis.cli.run_scan", return_value=result):
            _run_scan_command(args)
        captured = capsys.readouterr()
        assert "aegis: error" in captured.err

    def test_io_error_exits_report_fail(self, tmp_path):
        result = _make_result(project_path=tmp_path / "p")
        (tmp_path / "p").mkdir()
        args = _make_args(project=str(tmp_path / "p"),
                          output=str(tmp_path / "r.json"))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report",
                   side_effect=ReportError("disk full")):
            code = _run_scan_command(args)
        assert code == EXIT_REPORT_FAIL

    def test_io_error_to_stderr(self, tmp_path, capsys):
        result = _make_result(project_path=tmp_path / "p")
        (tmp_path / "p").mkdir()
        args = _make_args(project=str(tmp_path / "p"),
                          output=str(tmp_path / "r.json"))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report",
                   side_effect=ReportError("disk full")):
            _run_scan_command(args)
        captured = capsys.readouterr()
        assert "aegis: error" in captured.err


# ---------------------------------------------------------------------------
# No raw credentials in output
# ---------------------------------------------------------------------------

class TestNoCredentialsInOutput:
    # Synthetic fake values — clearly not real
    FAKE_PASSWORD = "FakeSuperSecretPwd99"
    FAKE_AWS_KEY  = "AKIAFAKEACCESSKEY001"

    def test_raw_fake_password_not_in_stdout(self, tmp_path, capsys):
        finding = _make_finding()
        finding.evidence = ""
        finding.redacted = "password = '[REDACTED]'"
        result = _make_result(findings=[finding], project_path=tmp_path / "p")
        (tmp_path / "p").mkdir()
        args = _make_args(project=str(tmp_path / "p"),
                          output=str(tmp_path / "r.json"))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report"):
            _run_scan_command(args)
        captured = capsys.readouterr()
        assert self.FAKE_PASSWORD not in captured.out
        assert self.FAKE_PASSWORD not in captured.err

    def test_raw_fake_aws_key_not_in_stdout(self, tmp_path, capsys):
        finding = _make_finding(rule_id="AEGIS-SECRET-AWS-KEY-ID",
                                severity=Severity.CRITICAL)
        finding.evidence = ""
        finding.redacted = "aws_access_key_id = '[REDACTED]'"
        result = _make_result(findings=[finding], project_path=tmp_path / "p")
        (tmp_path / "p").mkdir()
        args = _make_args(project=str(tmp_path / "p"),
                          output=str(tmp_path / "r.json"))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report"):
            _run_scan_command(args)
        captured = capsys.readouterr()
        assert self.FAKE_AWS_KEY not in captured.out
        assert self.FAKE_AWS_KEY not in captured.err


# ---------------------------------------------------------------------------
# Paths with spaces
# ---------------------------------------------------------------------------

class TestPathsWithSpaces:
    def test_project_path_with_spaces(self, tmp_path):
        """Paths containing spaces must be accepted without error."""
        project_dir = tmp_path / "my project with spaces"
        project_dir.mkdir()
        result = _make_result(project_path=project_dir)
        out = tmp_path / "report.json"
        args = _make_args(project=str(project_dir), output=str(out))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report"):
            code = _run_scan_command(args)
        assert code == EXIT_OK

    def test_output_path_with_spaces(self, tmp_path):
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        result = _make_result(project_path=project_dir)
        out = tmp_path / "my report with spaces.json"
        args = _make_args(project=str(project_dir), output=str(out))
        with patch("aegis.cli.run_scan", return_value=result), \
             patch("aegis.cli.write_report"):
            code = _run_scan_command(args)
        assert code == EXIT_OK


# ---------------------------------------------------------------------------
# Fixture file immutability
# ---------------------------------------------------------------------------

class TestFilesUnchanged:
    def test_cli_does_not_modify_fixture_files(self, tmp_path):
        fixture_files = list(VULNERABLE_PROJECT.rglob("*.py"))
        assert fixture_files
        mtimes_before = {f: f.stat().st_mtime for f in fixture_files}

        out = tmp_path / "report.json"
        args = _make_args(project=str(VULNERABLE_PROJECT), output=str(out))
        with patch("aegis.cli.run_scan", return_value=_make_result()), \
             patch("aegis.cli.write_report"):
            _run_scan_command(args)

        for f in fixture_files:
            assert f.stat().st_mtime == mtimes_before[f], (
                f"CLI modified fixture file: {f}"
            )


# ---------------------------------------------------------------------------
# Integration: real subprocess against the fixture project
# ---------------------------------------------------------------------------

class TestIntegration:
    def test_scan_fixture_exits_zero(self, tmp_path):
        out = tmp_path / "report.json"
        r = _run_main_subprocess(
            "scan",
            "--project", str(VULNERABLE_PROJECT),
            "--output", str(out),
        )
        assert r.returncode == EXIT_OK, (
            f"Expected exit 0, got {r.returncode}.\nstdout: {r.stdout}\nstderr: {r.stderr}"
        )

    def test_scan_fixture_creates_report(self, tmp_path):
        out = tmp_path / "report.json"
        _run_main_subprocess(
            "scan",
            "--project", str(VULNERABLE_PROJECT),
            "--output", str(out),
        )
        assert out.exists()

    def test_scan_fixture_report_is_valid_json(self, tmp_path):
        out = tmp_path / "report.json"
        _run_main_subprocess(
            "scan",
            "--project", str(VULNERABLE_PROJECT),
            "--output", str(out),
        )
        data = json.loads(out.read_text(encoding="utf-8"))
        assert isinstance(data, dict)
        assert data["finding_count"] > 0

    def test_scan_fixture_output_contains_finding_count(self, tmp_path):
        out = tmp_path / "report.json"
        r = _run_main_subprocess(
            "scan",
            "--project", str(VULNERABLE_PROJECT),
            "--output", str(out),
        )
        assert "Findings" in r.stdout

    def test_scan_fixture_no_fake_secrets_in_stdout(self, tmp_path):
        """Known synthetic fake secrets must not appear in terminal output."""
        fake_secrets = [
            "AKIAFAKEACCESSKEY001",
            "FakeAwsSecretKey1234567890abcdefghijABCD",
            "ghp_FakeGitHubTokenABCDEFGHIJKLMN1234",
            "FakeSuperSecretPwd99",
        ]
        out = tmp_path / "report.json"
        r = _run_main_subprocess(
            "scan",
            "--project", str(VULNERABLE_PROJECT),
            "--output", str(out),
        )
        for secret in fake_secrets:
            assert secret not in r.stdout, (
                f"Fake secret found in stdout: {secret}"
            )
            assert secret not in r.stderr, (
                f"Fake secret found in stderr: {secret}"
            )

    def test_fixture_files_unchanged_after_integration_scan(self, tmp_path):
        fixture_files = list(VULNERABLE_PROJECT.rglob("*.py"))
        assert fixture_files
        mtimes_before = {f: f.stat().st_mtime for f in fixture_files}

        out = tmp_path / "report.json"
        _run_main_subprocess(
            "scan",
            "--project", str(VULNERABLE_PROJECT),
            "--output", str(out),
        )

        for f in fixture_files:
            assert f.stat().st_mtime == mtimes_before[f], (
                f"Fixture file modified by integration scan: {f}"
            )

    def test_nonexistent_project_exits_bad_args(self, tmp_path):
        r = _run_main_subprocess(
            "scan",
            "--project", str(tmp_path / "does_not_exist"),
            "--output", str(tmp_path / "r.json"),
        )
        assert r.returncode == EXIT_BAD_ARGS

    def test_output_inside_project_exits_bad_args(self):
        """Report output inside the scanned project must be rejected."""
        inside = VULNERABLE_PROJECT / "report.json"
        r = _run_main_subprocess(
            "scan",
            "--project", str(VULNERABLE_PROJECT),
            "--output", str(inside),
        )
        assert r.returncode == EXIT_BAD_ARGS

    def test_default_output_used_when_omitted(self, tmp_path, monkeypatch):
        """When --output is omitted, the default filename must be used."""
        monkeypatch.chdir(tmp_path)
        r = _run_main_subprocess(
            "scan",
            "--project", str(VULNERABLE_PROJECT),
            # no --output
        )
        assert r.returncode == EXIT_OK
        assert (tmp_path / DEFAULT_OUTPUT).exists()
        (tmp_path / DEFAULT_OUTPUT).unlink(missing_ok=True)
