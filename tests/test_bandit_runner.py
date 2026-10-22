"""Tests for aegis.bandit_runner.

Subprocess execution is mocked in unit tests to ensure determinism.
An integration smoke-test exercises the real Bandit installation against
the synthetic fixture project.

No real credentials or source-code secrets are printed in this file.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegis.bandit_runner import (
    BANDIT_TIMEOUT,
    BanditError,
    BanditNotFoundError,
    BanditTimeoutError,
    _map_severity,
    _normalise_bandit_path,
    scan,
)
from aegis.models import Finding, Severity

# ---------------------------------------------------------------------------
# Fixture paths
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULNERABLE_PROJECT = FIXTURES_DIR / "vulnerable_project"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_bandit_result(
    *,
    filename: str = "./src/app.py",
    test_id: str = "B602",
    test_name: str = "subprocess_popen_with_shell_equals_true",
    issue_severity: str = "HIGH",
    issue_confidence: str = "HIGH",
    issue_text: str = "subprocess call with shell=True identified, security issue.",
    line_number: int = 14,
    code: str = "    result = subprocess.run(cmd, shell=True)\n",
) -> dict:
    return {
        "filename": filename,
        "test_id": test_id,
        "test_name": test_name,
        "issue_severity": issue_severity,
        "issue_confidence": issue_confidence,
        "issue_text": issue_text,
        "line_number": line_number,
        "line_range": [line_number],
        "code": code,
        "col_offset": 13,
        "end_col_offset": 65,
        "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
        "more_info": "https://bandit.readthedocs.io/en/1.9.4/plugins/b602.html",
    }


def _make_bandit_json(results: list[dict], errors: list | None = None) -> str:
    return json.dumps({
        "errors": errors or [],
        "generated_at": "2024-01-01T00:00:00Z",
        "metrics": {"_totals": {}},
        "results": results,
    })


def _mock_run(stdout: str, returncode: int = 1) -> MagicMock:
    """Return a mock subprocess.CompletedProcess with given stdout and returncode."""
    mock = MagicMock()
    mock.stdout = stdout
    mock.stderr = ""
    mock.returncode = returncode
    return mock


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

class TestSeverityMapping:
    def test_high_high_maps_to_critical(self):
        assert _map_severity("HIGH", "HIGH") == Severity.CRITICAL

    def test_high_medium_maps_to_high(self):
        assert _map_severity("HIGH", "MEDIUM") == Severity.HIGH

    def test_high_low_maps_to_high(self):
        assert _map_severity("HIGH", "LOW") == Severity.HIGH

    def test_medium_high_maps_to_high(self):
        assert _map_severity("MEDIUM", "HIGH") == Severity.HIGH

    def test_medium_medium_maps_to_medium(self):
        assert _map_severity("MEDIUM", "MEDIUM") == Severity.MEDIUM

    def test_medium_low_maps_to_medium(self):
        assert _map_severity("MEDIUM", "LOW") == Severity.MEDIUM

    def test_low_high_maps_to_medium(self):
        assert _map_severity("LOW", "HIGH") == Severity.MEDIUM

    def test_low_medium_maps_to_low(self):
        assert _map_severity("LOW", "MEDIUM") == Severity.LOW

    def test_low_low_maps_to_low(self):
        assert _map_severity("LOW", "LOW") == Severity.LOW

    def test_unknown_combo_maps_to_info(self):
        assert _map_severity("UNDEFINED", "UNDEFINED") == Severity.INFO

    def test_case_insensitive(self):
        assert _map_severity("high", "high") == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Path normalisation
# ---------------------------------------------------------------------------

class TestPathNormalisation:
    def test_strips_dot_slash_prefix(self):
        assert _normalise_bandit_path("./src/app.py") == "src/app.py"

    def test_strips_dot_backslash_prefix(self):
        assert _normalise_bandit_path(".\\src\\app.py") == "src/app.py"

    def test_converts_backslashes(self):
        assert _normalise_bandit_path("src\\sub\\file.py") == "src/sub/file.py"

    def test_no_prefix_unchanged(self):
        assert _normalise_bandit_path("src/app.py") == "src/app.py"


# ---------------------------------------------------------------------------
# Successful scan — no findings
# ---------------------------------------------------------------------------

class TestCleanScan:
    def test_exit_0_empty_results_returns_empty_list(self, tmp_path):
        payload = _make_bandit_json([])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=0)):
            findings = scan(tmp_path)
        assert findings == []

    def test_exit_0_no_stdout_returns_empty_list(self, tmp_path):
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run("", returncode=0)):
            findings = scan(tmp_path)
        assert findings == []


# ---------------------------------------------------------------------------
# Successful scan — with findings
# ---------------------------------------------------------------------------

class TestScanWithFindings:
    def test_single_finding_returned(self, tmp_path):
        result = _make_bandit_result(filename=f"./{tmp_path.name}/app.py")
        # Use a path relative to tmp_path's parent so resolve() keeps it inside
        result["filename"] = "./app.py"
        payload = _make_bandit_json([result])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=1)):
            findings = scan(tmp_path)
        assert len(findings) == 1

    def test_finding_fields_populated(self, tmp_path):
        result = _make_bandit_result(
            filename="./app.py",
            test_id="B602",
            issue_severity="HIGH",
            issue_confidence="HIGH",
            line_number=14,
        )
        payload = _make_bandit_json([result])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=1)):
            findings = scan(tmp_path)
        f = findings[0]
        assert f.rule_id == "B-B602"
        assert f.severity == Severity.CRITICAL
        assert f.line == 14
        assert f.file == "app.py"
        assert f.title != ""
        assert f.description != ""
        assert f.remediation != ""

    def test_finding_id_contains_rule_and_path(self, tmp_path):
        result = _make_bandit_result(filename="./app.py", test_id="B307", line_number=5)
        payload = _make_bandit_json([result])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=1)):
            findings = scan(tmp_path)
        assert "B-B307" in findings[0].id
        assert "app.py" in findings[0].id

    def test_multiple_findings_returned(self, tmp_path):
        results = [
            _make_bandit_result(filename="./a.py", test_id="B602", line_number=10),
            _make_bandit_result(filename="./b.py", test_id="B307", line_number=5),
        ]
        payload = _make_bandit_json(results)
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=1)):
            findings = scan(tmp_path)
        assert len(findings) == 2

    def test_findings_sorted_by_file_then_line(self, tmp_path):
        results = [
            _make_bandit_result(filename="./b.py", line_number=3),
            _make_bandit_result(filename="./a.py", line_number=10),
            _make_bandit_result(filename="./a.py", line_number=2),
        ]
        payload = _make_bandit_json(results)
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=1)):
            findings = scan(tmp_path)
        keys = [(f.file, f.line) for f in findings]
        assert keys == sorted(keys)

    def test_file_paths_are_relative(self, tmp_path):
        result = _make_bandit_result(filename="./src/app.py")
        payload = _make_bandit_json([result])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=1)):
            findings = scan(tmp_path)
        assert not Path(findings[0].file).is_absolute()

    def test_exit_1_is_treated_as_success(self, tmp_path):
        """Exit code 1 (findings present) must not raise an exception."""
        result = _make_bandit_result(filename="./app.py")
        payload = _make_bandit_json([result])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=1)):
            findings = scan(tmp_path)  # must not raise
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# Severity and confidence mapping via full scan path
# ---------------------------------------------------------------------------

class TestSeverityInFindings:
    @pytest.mark.parametrize("sev,conf,expected", [
        ("HIGH",   "HIGH",   Severity.CRITICAL),
        ("HIGH",   "MEDIUM", Severity.HIGH),
        ("MEDIUM", "HIGH",   Severity.HIGH),
        ("MEDIUM", "MEDIUM", Severity.MEDIUM),
        ("LOW",    "HIGH",   Severity.MEDIUM),
        ("LOW",    "LOW",    Severity.LOW),
    ])
    def test_severity_mapping_end_to_end(self, tmp_path, sev, conf, expected):
        result = _make_bandit_result(
            filename="./app.py",
            issue_severity=sev,
            issue_confidence=conf,
        )
        payload = _make_bandit_json([result])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=1)):
            findings = scan(tmp_path)
        assert findings[0].severity == expected


# ---------------------------------------------------------------------------
# Evidence redaction
# ---------------------------------------------------------------------------

class TestEvidenceRedaction:
    # Synthetic fake credential — clearly not real
    FAKE_PASSWORD = "FakeSuperSecretPwd99"

    def test_raw_evidence_is_populated(self, tmp_path):
        """Scanner must populate Finding.evidence (internal use)."""
        code_snippet = "    password = 'safe_placeholder_value_here'\n"
        result = _make_bandit_result(filename="./app.py", code=code_snippet)
        payload = _make_bandit_json([result])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=1)):
            findings = scan(tmp_path)
        assert findings[0].evidence != ""

    def test_redacted_field_populated(self, tmp_path):
        """Scanner must populate Finding.redacted."""
        result = _make_bandit_result(filename="./app.py")
        payload = _make_bandit_json([result])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=1)):
            findings = scan(tmp_path)
        # redacted may equal evidence if no patterns matched — that's OK
        assert isinstance(findings[0].redacted, str)

    def test_fake_password_not_in_serialised_output(self, tmp_path):
        """A fake password in the code snippet must be redacted in to_dict()."""
        code_snippet = f"    password = '{self.FAKE_PASSWORD}'\n"
        result = _make_bandit_result(filename="./app.py", code=code_snippet)
        payload = _make_bandit_json([result])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=1)):
            findings = scan(tmp_path)
        serialised = json.dumps(findings[0].to_dict())
        assert self.FAKE_PASSWORD not in serialised, (
            "Fake password appeared in serialised finding — redaction contract broken."
        )

    def test_evidence_key_in_to_dict_holds_redacted_value(self, tmp_path):
        """to_dict()['evidence'] must be the redacted value, not the raw snippet."""
        code_snippet = f"    password = '{self.FAKE_PASSWORD}'\n"
        result = _make_bandit_result(filename="./app.py", code=code_snippet)
        payload = _make_bandit_json([result])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=1)):
            findings = scan(tmp_path)
        d = findings[0].to_dict()
        assert self.FAKE_PASSWORD not in d.get("evidence", ""), (
            "Raw fake password found in exported evidence field."
        )


# ---------------------------------------------------------------------------
# Error handling: malformed JSON
# ---------------------------------------------------------------------------

class TestMalformedOutput:
    def test_malformed_json_raises_bandit_error(self, tmp_path):
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run("not json at all", returncode=1)):
            with pytest.raises(BanditError, match="malformed JSON"):
                scan(tmp_path)

    def test_results_not_list_raises_bandit_error(self, tmp_path):
        bad_json = json.dumps({"errors": [], "results": "should-be-a-list"})
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(bad_json, returncode=1)):
            with pytest.raises(BanditError, match="not a list"):
                scan(tmp_path)

    def test_top_level_not_dict_raises_bandit_error(self, tmp_path):
        bad_json = json.dumps(["unexpected", "list"])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(bad_json, returncode=1)):
            with pytest.raises(BanditError, match="not a dict"):
                scan(tmp_path)

    def test_missing_results_key_returns_empty(self, tmp_path):
        """JSON without a 'results' key should yield no findings (graceful)."""
        payload = json.dumps({"errors": [], "metrics": {}})
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=0)):
            findings = scan(tmp_path)
        assert findings == []

    def test_non_dict_result_item_skipped(self, tmp_path):
        """A result item that is not a dict must be skipped without crashing."""
        bad_payload = json.dumps({
            "errors": [],
            "results": ["not-a-dict", None, 42],
        })
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(bad_payload, returncode=1)):
            findings = scan(tmp_path)
        assert findings == []


# ---------------------------------------------------------------------------
# Error handling: missing Bandit / FileNotFoundError
# ---------------------------------------------------------------------------

class TestBanditNotFound:
    def test_file_not_found_raises_bandit_not_found_error(self, tmp_path):
        with patch(
            "aegis.bandit_runner.subprocess.run",
            side_effect=FileNotFoundError("bandit not found"),
        ):
            with pytest.raises(BanditNotFoundError):
                scan(tmp_path)

    def test_bandit_not_found_error_is_bandit_error(self):
        assert issubclass(BanditNotFoundError, BanditError)


# ---------------------------------------------------------------------------
# Error handling: timeout
# ---------------------------------------------------------------------------

class TestTimeout:
    def test_timeout_raises_bandit_timeout_error(self, tmp_path):
        with patch(
            "aegis.bandit_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["bandit"], timeout=5),
        ):
            with pytest.raises(BanditTimeoutError):
                scan(tmp_path)

    def test_bandit_timeout_error_is_bandit_error(self):
        assert issubclass(BanditTimeoutError, BanditError)

    def test_timeout_parameter_forwarded(self, tmp_path):
        """scan() must pass the timeout parameter to subprocess.run."""
        payload = _make_bandit_json([])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=0)) as mock_sub:
            scan(tmp_path, timeout=30)
        _, kwargs = mock_sub.call_args
        assert kwargs.get("timeout") == 30


# ---------------------------------------------------------------------------
# Error handling: unexpected exit codes
# ---------------------------------------------------------------------------

class TestUnexpectedExitCodes:
    def test_exit_code_2_raises_bandit_error(self, tmp_path):
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run("", returncode=2)):
            with pytest.raises(BanditError):
                scan(tmp_path)

    def test_exit_code_127_raises_bandit_error(self, tmp_path):
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run("", returncode=127)):
            with pytest.raises(BanditError):
                scan(tmp_path)

    def test_exit_code_0_with_findings_does_not_raise(self, tmp_path):
        """Exit 0 with results in JSON must not raise (defensive parse)."""
        result = _make_bandit_result(filename="./app.py")
        payload = _make_bandit_json([result])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=0)):
            findings = scan(tmp_path)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

class TestPathSafety:
    def test_nonexistent_path_raises_value_error(self):
        with pytest.raises(ValueError, match="does not exist"):
            scan(Path("/nonexistent/path/that/cannot/exist"))

    def test_file_path_raises_value_error(self, tmp_path):
        f = tmp_path / "notadir.py"
        f.write_text("x = 1\n", encoding="utf-8")
        with pytest.raises(ValueError, match="not a directory"):
            scan(f)

    def test_path_escaping_root_skipped(self, tmp_path):
        """A result with a filename that resolves outside the project root is skipped."""
        # Use an absolute path that points outside tmp_path
        outside_path = str(Path(sys.executable).parent / "outside.py")
        result = _make_bandit_result(filename=outside_path)
        payload = _make_bandit_json([result])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=1)):
            findings = scan(tmp_path)
        # Finding should be filtered out since the path escapes root
        assert all(f.file != outside_path for f in findings)

    def test_subprocess_called_with_shell_false(self, tmp_path):
        """subprocess.run must always be called with shell=False."""
        payload = _make_bandit_json([])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=0)) as mock_sub:
            scan(tmp_path)
        _, kwargs = mock_sub.call_args
        assert kwargs.get("shell") is False

    def test_subprocess_called_with_arg_list_not_string(self, tmp_path):
        """The subprocess command must be a list, not a shell string."""
        payload = _make_bandit_json([])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=0)) as mock_sub:
            scan(tmp_path)
        args, _ = mock_sub.call_args
        cmd = args[0]
        assert isinstance(cmd, list), "Command must be passed as a list"

    def test_excluded_dirs_filtered_from_results(self, tmp_path):
        """Findings from __pycache__ or venv must be excluded."""
        results = [
            _make_bandit_result(filename="./__pycache__/module.py"),
            _make_bandit_result(filename="./venv/lib/site.py"),
            _make_bandit_result(filename="./app.py"),
        ]
        payload = _make_bandit_json(results)
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=1)):
            findings = scan(tmp_path)
        assert all(
            "__pycache__" not in f.file and "venv" not in f.file
            for f in findings
        )

    def test_sys_executable_used_in_command(self, tmp_path):
        """Bandit must be invoked via sys.executable, not a bare 'bandit' string."""
        payload = _make_bandit_json([])
        with patch("aegis.bandit_runner.subprocess.run", return_value=_mock_run(payload, returncode=0)) as mock_sub:
            scan(tmp_path)
        args, _ = mock_sub.call_args
        cmd = args[0]
        assert cmd[0] == sys.executable


# ---------------------------------------------------------------------------
# Integration: real Bandit against the fixture project
# ---------------------------------------------------------------------------

class TestIntegration:
    """These tests invoke real Bandit; they depend on the fixture project."""

    def test_fixture_app_produces_findings(self):
        """Bandit must detect known issues in the synthetic app.py fixture."""
        findings = scan(VULNERABLE_PROJECT)
        rule_ids = {f.rule_id for f in findings}
        # B602 (subprocess shell=True) must be detected
        assert "B-B602" in rule_ids, (
            f"Expected B-B602 in findings but got: {rule_ids}"
        )

    def test_findings_have_correct_structure(self):
        findings = scan(VULNERABLE_PROJECT)
        for f in findings:
            assert isinstance(f, Finding)
            assert f.severity in Severity
            assert f.line is not None and f.line > 0
            assert not Path(f.file).is_absolute()
            assert f.rule_id.startswith("B-B")

    def test_finding_ids_unique(self):
        findings = scan(VULNERABLE_PROJECT)
        ids = [f.id for f in findings]
        assert len(ids) == len(set(ids))

    def test_fixture_files_not_modified(self):
        """Scanning must not alter any fixture file."""
        fixture_files = list(VULNERABLE_PROJECT.rglob("*.py"))
        mtimes_before = {f: f.stat().st_mtime for f in fixture_files}
        scan(VULNERABLE_PROJECT)
        for f in fixture_files:
            assert f.stat().st_mtime == mtimes_before[f], (
                f"File was modified during Bandit scan: {f}"
            )

    def test_no_fake_secrets_in_serialised_findings(self):
        """None of the synthetic fake secrets must appear in serialised output."""
        # These values appear in config.py which Bandit also scans
        fake_values = [
            "FakeAwsSecretKey1234567890abcdefghijABCD",
            "FakeSuperSecretPwd99",
            "ghp_FakeGitHubTokenABCDEFGHIJKLMN1234",
        ]
        findings = scan(VULNERABLE_PROJECT)
        for f in findings:
            serialised = json.dumps(f.to_dict())
            for fake in fake_values:
                assert fake not in serialised, (
                    f"Fake secret found in serialised output for finding {f.rule_id}."
                )
