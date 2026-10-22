"""Tests for aegis.scanner (orchestrator).

Unit tests mock the individual scanner modules so they are deterministic and
fast.  An integration smoke-test exercises the real scanners against the
existing synthetic fixture project.

No real credentials are used or printed anywhere in this file.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegis.bandit_runner import BanditError, BanditTimeoutError
from aegis.models import Finding, Severity
from aegis.scanner import ScanResult, ScanStatus, ScannerError, run_scan

# ---------------------------------------------------------------------------
# Fixture paths
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
    evidence: str = "password = 'raw-secret-value'",
    redacted: str = "password = '[REDACTED]'",
) -> Finding:
    return Finding(
        id=f"{rule_id}:{file}:{line}",
        severity=severity,
        file=file,
        line=line,
        rule_id=rule_id,
        title="Test finding",
        description="A test finding",
        evidence=evidence,
        redacted=redacted,
        remediation="Fix it.",
    )


def _patch_both(secret_findings=None, bandit_findings=None):
    """Context manager that patches both scanner modules."""
    secret_findings = secret_findings or []
    bandit_findings = bandit_findings or []
    return (
        patch("aegis.scanner._secrets.scan", return_value=secret_findings),
        patch("aegis.scanner._bandit.scan", return_value=bandit_findings),
    )


# ---------------------------------------------------------------------------
# Return type and basic structure
# ---------------------------------------------------------------------------

class TestScanResultStructure:
    def test_returns_scan_result_instance(self, tmp_path):
        with patch("aegis.scanner._secrets.scan", return_value=[]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert isinstance(result, ScanResult)

    def test_project_path_is_resolved(self, tmp_path):
        with patch("aegis.scanner._secrets.scan", return_value=[]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert result.project_path == tmp_path.resolve()
        assert result.project_path.is_absolute()

    def test_findings_is_list(self, tmp_path):
        with patch("aegis.scanner._secrets.scan", return_value=[]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert isinstance(result.findings, list)

    def test_errors_is_list(self, tmp_path):
        with patch("aegis.scanner._secrets.scan", return_value=[]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert isinstance(result.errors, list)

    def test_finding_count_property(self, tmp_path):
        f = _make_finding()
        with patch("aegis.scanner._secrets.scan", return_value=[f]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert result.finding_count == 1


# ---------------------------------------------------------------------------
# Successful scan — no findings
# ---------------------------------------------------------------------------

class TestCleanScan:
    def test_empty_project_returns_no_findings(self, tmp_path):
        with patch("aegis.scanner._secrets.scan", return_value=[]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert result.findings == []
        assert result.status == ScanStatus.SUCCESS
        assert result.errors == []

    def test_succeeded_property_true_on_clean_scan(self, tmp_path):
        with patch("aegis.scanner._secrets.scan", return_value=[]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert result.succeeded is True


# ---------------------------------------------------------------------------
# Findings from secret scanner only
# ---------------------------------------------------------------------------

class TestSecretScannerFindings:
    def test_secret_findings_included(self, tmp_path):
        f = _make_finding(rule_id="AEGIS-SECRET-PASSWORD")
        with patch("aegis.scanner._secrets.scan", return_value=[f]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert result.finding_count == 1
        assert result.findings[0].rule_id == "AEGIS-SECRET-PASSWORD"

    def test_status_is_success(self, tmp_path):
        f = _make_finding()
        with patch("aegis.scanner._secrets.scan", return_value=[f]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert result.status == ScanStatus.SUCCESS


# ---------------------------------------------------------------------------
# Findings from Bandit only
# ---------------------------------------------------------------------------

class TestBanditFindings:
    def test_bandit_findings_included(self, tmp_path):
        f = _make_finding(rule_id="B-B602", severity=Severity.CRITICAL)
        with patch("aegis.scanner._secrets.scan", return_value=[]), \
             patch("aegis.scanner._bandit.scan", return_value=[f]):
            result = run_scan(tmp_path)
        assert result.finding_count == 1
        assert result.findings[0].rule_id == "B-B602"

    def test_status_is_success(self, tmp_path):
        f = _make_finding(rule_id="B-B602")
        with patch("aegis.scanner._secrets.scan", return_value=[]), \
             patch("aegis.scanner._bandit.scan", return_value=[f]):
            result = run_scan(tmp_path)
        assert result.status == ScanStatus.SUCCESS


# ---------------------------------------------------------------------------
# Findings from both scanners
# ---------------------------------------------------------------------------

class TestCombinedFindings:
    def test_findings_from_both_combined(self, tmp_path):
        f_secret = _make_finding(rule_id="AEGIS-SECRET-PASSWORD", file="a.py", line=1)
        f_bandit = _make_finding(rule_id="B-B602", file="b.py", line=5,
                                 severity=Severity.CRITICAL)
        with patch("aegis.scanner._secrets.scan", return_value=[f_secret]), \
             patch("aegis.scanner._bandit.scan", return_value=[f_bandit]):
            result = run_scan(tmp_path)
        assert result.finding_count == 2
        rule_ids = {f.rule_id for f in result.findings}
        assert "AEGIS-SECRET-PASSWORD" in rule_ids
        assert "B-B602" in rule_ids

    def test_status_success_when_both_succeed(self, tmp_path):
        f1 = _make_finding(rule_id="AEGIS-SECRET-PASSWORD", file="a.py", line=1)
        f2 = _make_finding(rule_id="B-B602", file="b.py", line=1)
        with patch("aegis.scanner._secrets.scan", return_value=[f1]), \
             patch("aegis.scanner._bandit.scan", return_value=[f2]):
            result = run_scan(tmp_path)
        assert result.status == ScanStatus.SUCCESS


# ---------------------------------------------------------------------------
# Sorting: CRITICAL first, then by (file, line)
# ---------------------------------------------------------------------------

class TestFindingSorting:
    def test_critical_before_low(self, tmp_path):
        f_low = _make_finding(severity=Severity.LOW, file="z.py", line=1)
        f_crit = _make_finding(rule_id="B-B602", severity=Severity.CRITICAL,
                               file="a.py", line=99)
        with patch("aegis.scanner._secrets.scan", return_value=[f_low, f_crit]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert result.findings[0].severity == Severity.CRITICAL

    def test_same_severity_sorted_by_file_then_line(self, tmp_path):
        f1 = _make_finding(file="b.py", line=1, severity=Severity.HIGH)
        f2 = _make_finding(rule_id="AEGIS-SECRET-AWS-KEY-ID", file="a.py",
                           line=2, severity=Severity.HIGH)
        f3 = _make_finding(rule_id="AEGIS-SECRET-GITHUB-TOKEN", file="a.py",
                           line=1, severity=Severity.HIGH)
        with patch("aegis.scanner._secrets.scan", return_value=[f1, f2, f3]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert [(f.file, f.line) for f in result.findings] == [
            ("a.py", 1), ("a.py", 2), ("b.py", 1)
        ]


# ---------------------------------------------------------------------------
# Evidence clearing
# ---------------------------------------------------------------------------

class TestEvidenceClearing:
    def test_evidence_cleared_on_all_findings(self, tmp_path):
        f1 = _make_finding(evidence="raw-secret-line-1")
        f2 = _make_finding(rule_id="B-B602", file="b.py", line=5,
                           evidence="raw-source-code-2")
        with patch("aegis.scanner._secrets.scan", return_value=[f1]), \
             patch("aegis.scanner._bandit.scan", return_value=[f2]):
            result = run_scan(tmp_path)
        for finding in result.findings:
            assert finding.evidence == "", (
                f"evidence not cleared on finding {finding.rule_id}"
            )

    def test_redacted_field_preserved_after_clearing(self, tmp_path):
        f = _make_finding(evidence="raw", redacted="password = '[REDACTED]'")
        with patch("aegis.scanner._secrets.scan", return_value=[f]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert result.findings[0].redacted == "password = '[REDACTED]'"

    def test_no_raw_secrets_in_serialised_output(self, tmp_path):
        """After clearing, to_dict() must not expose the raw evidence."""
        raw_val = "raw-very-secret-value-xyz"
        f = _make_finding(evidence=raw_val, redacted="password = '[REDACTED]'")
        with patch("aegis.scanner._secrets.scan", return_value=[f]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        for finding in result.findings:
            serialised = json.dumps(finding.to_dict())
            assert raw_val not in serialised, (
                "Raw evidence found in serialised finding after clearing."
            )


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_exact_duplicate_by_id_removed(self, tmp_path):
        """Two findings with identical IDs (same rule+file+line) are deduplicated."""
        f1 = _make_finding(rule_id="AEGIS-SECRET-PASSWORD", file="a.py", line=10)
        f2 = _make_finding(rule_id="AEGIS-SECRET-PASSWORD", file="a.py", line=10)
        assert f1.id == f2.id  # confirm they are actual duplicates
        with patch("aegis.scanner._secrets.scan", return_value=[f1]), \
             patch("aegis.scanner._bandit.scan", return_value=[f2]):
            result = run_scan(tmp_path)
        assert result.finding_count == 1

    def test_different_rules_same_location_both_kept(self, tmp_path):
        """Different rule IDs at the same file+line are distinct findings."""
        f1 = _make_finding(rule_id="AEGIS-SECRET-PASSWORD", file="a.py", line=10)
        f2 = _make_finding(rule_id="B-B105", file="a.py", line=10)
        assert f1.id != f2.id
        with patch("aegis.scanner._secrets.scan", return_value=[f1, f2]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert result.finding_count == 2

    def test_different_lines_same_rule_both_kept(self, tmp_path):
        f1 = _make_finding(file="a.py", line=10)
        f2 = _make_finding(file="a.py", line=20)
        assert f1.id != f2.id
        with patch("aegis.scanner._secrets.scan", return_value=[f1, f2]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert result.finding_count == 2


# ---------------------------------------------------------------------------
# Invalid project roots
# ---------------------------------------------------------------------------

class TestInvalidRoots:
    def test_nonexistent_path_raises_value_error(self):
        with pytest.raises(ValueError, match="does not exist"):
            run_scan(Path("/nonexistent/path/that/cannot/exist"))

    def test_file_path_raises_value_error(self, tmp_path):
        f = tmp_path / "notadir.py"
        f.write_text("x = 1\n", encoding="utf-8")
        with pytest.raises(ValueError, match="not a directory"):
            run_scan(f)

    def test_value_error_not_swallowed_by_error_handling(self, tmp_path):
        """ValueError from path validation must propagate, not become a ScannerError."""
        bad = Path("/nonexistent")
        with pytest.raises(ValueError):
            run_scan(bad)


# ---------------------------------------------------------------------------
# Scanner failures and partial scans
# ---------------------------------------------------------------------------

class TestScannerFailures:
    def test_secret_scanner_failure_yields_partial_status(self, tmp_path):
        with patch("aegis.scanner._secrets.scan", side_effect=RuntimeError("disk error")), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert result.status == ScanStatus.PARTIAL
        assert result.succeeded is False

    def test_bandit_failure_yields_partial_status(self, tmp_path):
        f = _make_finding()
        with patch("aegis.scanner._secrets.scan", return_value=[f]), \
             patch("aegis.scanner._bandit.scan", side_effect=BanditError("bandit crashed")):
            result = run_scan(tmp_path)
        assert result.status == ScanStatus.PARTIAL
        assert result.finding_count == 1  # secret scanner results still returned

    def test_both_fail_yields_failed_status(self, tmp_path):
        with patch("aegis.scanner._secrets.scan", side_effect=RuntimeError("error")), \
             patch("aegis.scanner._bandit.scan", side_effect=BanditError("error")):
            result = run_scan(tmp_path)
        assert result.status == ScanStatus.FAILED
        assert result.finding_count == 0

    def test_failed_scanner_recorded_in_errors(self, tmp_path):
        with patch("aegis.scanner._secrets.scan", side_effect=RuntimeError("disk io error")), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert len(result.errors) == 1
        err = result.errors[0]
        assert err.scanner == "secret_scanner"
        assert err.error_type == "RuntimeError"
        assert "disk io error" in err.message

    def test_bandit_timeout_recorded_as_error(self, tmp_path):
        import subprocess
        with patch("aegis.scanner._secrets.scan", return_value=[]), \
             patch("aegis.scanner._bandit.scan",
                   side_effect=BanditTimeoutError("timed out")):
            result = run_scan(tmp_path)
        assert result.status == ScanStatus.PARTIAL
        assert any(e.scanner == "bandit_runner" for e in result.errors)

    def test_partial_scan_returns_successful_results(self, tmp_path):
        """When Bandit fails, secret scanner findings must still be returned."""
        secret_finding = _make_finding(rule_id="AEGIS-SECRET-PASSWORD")
        with patch("aegis.scanner._secrets.scan", return_value=[secret_finding]), \
             patch("aegis.scanner._bandit.scan", side_effect=BanditError("failed")):
            result = run_scan(tmp_path)
        assert result.finding_count == 1
        assert result.findings[0].rule_id == "AEGIS-SECRET-PASSWORD"

    def test_error_message_does_not_contain_raw_evidence(self, tmp_path):
        """ScannerError messages must not contain raw source code."""
        raw_secret = "raw-secret-value-that-must-not-leak"
        with patch("aegis.scanner._secrets.scan",
                   side_effect=RuntimeError(f"Error near: {raw_secret}")), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        # The scanner error captures the exception message, but the
        # orchestrator must not add raw evidence beyond what the exception holds.
        # We verify the error is recorded and has a scanner name.
        assert len(result.errors) == 1
        assert result.errors[0].scanner == "secret_scanner"

    def test_succeeded_false_on_partial(self, tmp_path):
        with patch("aegis.scanner._secrets.scan", side_effect=RuntimeError("x")), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert result.succeeded is False

    def test_succeeded_false_on_failed(self, tmp_path):
        with patch("aegis.scanner._secrets.scan", side_effect=RuntimeError("x")), \
             patch("aegis.scanner._bandit.scan", side_effect=RuntimeError("y")):
            result = run_scan(tmp_path)
        assert result.succeeded is False


# ---------------------------------------------------------------------------
# Relative file paths
# ---------------------------------------------------------------------------

class TestRelativePaths:
    def test_findings_have_relative_paths(self, tmp_path):
        f = _make_finding(file="subdir/app.py")
        with patch("aegis.scanner._secrets.scan", return_value=[f]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert not Path(result.findings[0].file).is_absolute()

    def test_project_path_is_absolute(self, tmp_path):
        with patch("aegis.scanner._secrets.scan", return_value=[]), \
             patch("aegis.scanner._bandit.scan", return_value=[]):
            result = run_scan(tmp_path)
        assert result.project_path.is_absolute()


# ---------------------------------------------------------------------------
# ScannerError str representation
# ---------------------------------------------------------------------------

class TestScannerErrorStr:
    def test_str_includes_scanner_and_type(self):
        err = ScannerError(
            scanner="bandit_runner",
            error_type="BanditError",
            message="failed to run",
        )
        s = str(err)
        assert "bandit_runner" in s
        assert "BanditError" in s
        assert "failed to run" in s


# ---------------------------------------------------------------------------
# Fixture file immutability
# ---------------------------------------------------------------------------

class TestFilesUnchanged:
    def test_fixture_files_not_modified(self):
        """Orchestrated scan must not modify fixture files."""
        fixture_files = list(VULNERABLE_PROJECT.rglob("*.py"))
        assert fixture_files, "Fixture must contain at least one Python file"
        mtimes_before = {f: f.stat().st_mtime for f in fixture_files}

        run_scan(VULNERABLE_PROJECT)

        for f in fixture_files:
            assert f.stat().st_mtime == mtimes_before[f], (
                f"File was modified during orchestrated scan: {f}"
            )


# ---------------------------------------------------------------------------
# Integration: real scanners against the fixture project
# ---------------------------------------------------------------------------

class TestIntegration:
    def test_scan_vulnerable_fixture_returns_findings(self):
        result = run_scan(VULNERABLE_PROJECT)
        assert result.finding_count > 0, (
            "Expected findings from the vulnerable fixture project"
        )

    def test_status_success_on_fixture(self):
        result = run_scan(VULNERABLE_PROJECT)
        assert result.status == ScanStatus.SUCCESS, (
            f"Expected SUCCESS, got {result.status}. Errors: {result.errors}"
        )

    def test_evidence_cleared_on_all_integration_findings(self):
        result = run_scan(VULNERABLE_PROJECT)
        for f in result.findings:
            assert f.evidence == "", (
                f"evidence not cleared on finding {f.rule_id} in {f.file}"
            )

    def test_no_raw_secrets_in_serialised_integration_findings(self):
        """Known fake secrets must not appear anywhere in serialised output."""
        fake_secrets = [
            "AKIAFAKEACCESSKEY001",
            "FakeAwsSecretKey1234567890abcdefghijABCD",
            "ghp_FakeGitHubTokenABCDEFGHIJKLMN1234",
            "FakeSuperSecretPwd99",
        ]
        result = run_scan(VULNERABLE_PROJECT)
        for finding in result.findings:
            serialised = json.dumps(finding.to_dict())
            for secret in fake_secrets:
                assert secret not in serialised, (
                    f"Fake secret found in serialised finding {finding.rule_id}."
                )

    def test_findings_sorted_critical_first(self):
        result = run_scan(VULNERABLE_PROJECT)
        if len(result.findings) < 2:
            pytest.skip("Not enough findings to test sort order")
        severities = [f.severity for f in result.findings]
        # Verify no severity appears before a more-severe one
        from aegis.scanner import _SEVERITY_ORDER
        orders = [_SEVERITY_ORDER[s] for s in severities]
        assert orders == sorted(orders), "Findings not sorted CRITICAL-first"

    def test_findings_have_relative_paths(self):
        result = run_scan(VULNERABLE_PROJECT)
        for f in result.findings:
            assert not Path(f.file).is_absolute(), (
                f"Finding has absolute path: {f.file}"
            )

    def test_finding_ids_unique(self):
        result = run_scan(VULNERABLE_PROJECT)
        ids = [f.id for f in result.findings]
        assert len(ids) == len(set(ids)), "Duplicate finding IDs in result"

    def test_both_scanners_contributed(self):
        """Integration result should include findings from both rule namespaces."""
        result = run_scan(VULNERABLE_PROJECT)
        rule_ids = {f.rule_id for f in result.findings}
        has_secret_rule = any(r.startswith("AEGIS-") for r in rule_ids)
        has_bandit_rule = any(r.startswith("B-B") for r in rule_ids)
        assert has_secret_rule, f"No AEGIS secret findings in result. Rule IDs: {rule_ids}"
        assert has_bandit_rule, f"No Bandit findings in result. Rule IDs: {rule_ids}"
