"""Tests for aegis.secret_scanner.

All fixture credentials are synthetic and clearly labelled as fake.
No real credentials are used anywhere in this file.
Raw secret values are never printed to stdout or included in assertion messages.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from aegis.models import Finding, Severity
from aegis.secret_scanner import EXCLUDED_DIRS, EXCLUDED_SUFFIXES, scan

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULNERABLE_PROJECT = FIXTURES_DIR / "vulnerable_project"

# ---------------------------------------------------------------------------
# Synthetic fake credential values — must match the fixture file exactly.
# These are used only to check ABSENCE in redacted output.
# ---------------------------------------------------------------------------

FAKE_AWS_KEY_ID = "AKIAFAKEACCESSKEY001"
FAKE_AWS_SECRET = "FakeAwsSecretKey1234567890abcdefghijABCD"
FAKE_GHP_TOKEN = "ghp_FakeGitHubTokenABCDEFGHIJKLMN1234"
FAKE_API_KEY = "fake-api-key-value-abc123xyz789"
FAKE_PASSWORD = "FakeSuperSecretPwd99"

# Map rule_id → expected fake value (for absence-in-redacted checks)
_RULE_TO_SECRET = {
    "AEGIS-SECRET-AWS-KEY-ID": FAKE_AWS_KEY_ID,
    "AEGIS-SECRET-AWS-SECRET": FAKE_AWS_SECRET,
    "AEGIS-SECRET-GITHUB-TOKEN": FAKE_GHP_TOKEN,
    "AEGIS-SECRET-API-KEY": FAKE_API_KEY,
    "AEGIS-SECRET-PASSWORD": FAKE_PASSWORD,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _findings_by_rule(findings: list[Finding]) -> dict[str, list[Finding]]:
    result: dict[str, list[Finding]] = {}
    for f in findings:
        result.setdefault(f.rule_id, []).append(f)
    return result


def _assert_redacted(finding: Finding, raw_secret: str) -> None:
    """Assert the raw secret is absent from redacted evidence and serialised output."""
    assert "[REDACTED]" in finding.redacted, (
        f"Expected [REDACTED] in finding.redacted for rule {finding.rule_id}"
    )
    assert raw_secret not in finding.redacted, (
        "Raw synthetic secret still present in finding.redacted — redaction failed."
    )
    serialised = json.dumps(finding.to_dict())
    assert raw_secret not in serialised, (
        "Raw synthetic secret present in serialised finding — contract broken."
    )


# ---------------------------------------------------------------------------
# Fixture project scan (shared across tests in this module)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def vulnerable_findings() -> list[Finding]:
    """Scan the vulnerable fixture project once and cache the result."""
    return scan(VULNERABLE_PROJECT)


@pytest.fixture(scope="module")
def findings_by_rule(vulnerable_findings) -> dict[str, list[Finding]]:
    return _findings_by_rule(vulnerable_findings)


# ---------------------------------------------------------------------------
# Basic: vulnerable project produces findings
# ---------------------------------------------------------------------------

class TestVulnerableProjectFindings:
    def test_at_least_five_findings(self, vulnerable_findings):
        """The vulnerable fixture must produce at least one finding per category."""
        assert len(vulnerable_findings) >= 5

    def test_all_findings_have_required_fields(self, vulnerable_findings):
        for f in vulnerable_findings:
            assert f.id, "Finding must have a non-empty id"
            assert f.severity in Severity, "Severity must be a valid Severity enum value"
            assert f.file, "Finding must have a non-empty file path"
            assert f.line is not None and f.line > 0, "Line number must be a positive integer"
            assert f.rule_id.startswith("AEGIS-"), "Rule ID must follow AEGIS- convention"
            assert f.title, "Finding must have a title"
            assert f.description, "Finding must have a description"
            assert f.remediation, "Finding must have remediation guidance"

    def test_findings_sorted_by_file_then_line(self, vulnerable_findings):
        keys = [(f.file, f.line) for f in vulnerable_findings]
        assert keys == sorted(keys), "Findings must be sorted by (file, line)"

    def test_file_paths_are_relative(self, vulnerable_findings):
        for f in vulnerable_findings:
            assert not Path(f.file).is_absolute(), (
                f"File path must be relative, got: {f.file}"
            )

    def test_finding_ids_are_unique(self, vulnerable_findings):
        ids = [f.id for f in vulnerable_findings]
        assert len(ids) == len(set(ids)), "Finding IDs must be unique"


# ---------------------------------------------------------------------------
# Per-category detection tests
# ---------------------------------------------------------------------------

class TestAwsKeyIdDetection:
    def test_rule_fires(self, findings_by_rule):
        assert "AEGIS-SECRET-AWS-KEY-ID" in findings_by_rule, (
            "AWS Access Key ID rule must fire on fixture"
        )

    def test_correct_line_number(self, findings_by_rule):
        f = findings_by_rule["AEGIS-SECRET-AWS-KEY-ID"][0]
        assert f.line == 10, f"Expected line 10, got {f.line}"

    def test_correct_relative_path(self, findings_by_rule):
        f = findings_by_rule["AEGIS-SECRET-AWS-KEY-ID"][0]
        assert f.file == "config.py", f"Expected config.py, got {f.file!r}"

    def test_severity_is_critical(self, findings_by_rule):
        f = findings_by_rule["AEGIS-SECRET-AWS-KEY-ID"][0]
        assert f.severity == Severity.CRITICAL

    def test_redaction(self, findings_by_rule):
        f = findings_by_rule["AEGIS-SECRET-AWS-KEY-ID"][0]
        _assert_redacted(f, FAKE_AWS_KEY_ID)

    def test_evidence_populated(self, findings_by_rule):
        """Raw evidence must be non-empty (scanner populates it internally)."""
        f = findings_by_rule["AEGIS-SECRET-AWS-KEY-ID"][0]
        assert f.evidence, "evidence field must be populated by the scanner"


class TestAwsSecretDetection:
    def test_rule_fires(self, findings_by_rule):
        assert "AEGIS-SECRET-AWS-SECRET" in findings_by_rule

    def test_correct_line_number(self, findings_by_rule):
        f = findings_by_rule["AEGIS-SECRET-AWS-SECRET"][0]
        assert f.line == 13, f"Expected line 13, got {f.line}"

    def test_severity_is_critical(self, findings_by_rule):
        f = findings_by_rule["AEGIS-SECRET-AWS-SECRET"][0]
        assert f.severity == Severity.CRITICAL

    def test_redaction(self, findings_by_rule):
        f = findings_by_rule["AEGIS-SECRET-AWS-SECRET"][0]
        _assert_redacted(f, FAKE_AWS_SECRET)


class TestGitHubTokenDetection:
    def test_rule_fires(self, findings_by_rule):
        assert "AEGIS-SECRET-GITHUB-TOKEN" in findings_by_rule

    def test_correct_line_number(self, findings_by_rule):
        f = findings_by_rule["AEGIS-SECRET-GITHUB-TOKEN"][0]
        assert f.line == 17, f"Expected line 17, got {f.line}"

    def test_severity_is_critical(self, findings_by_rule):
        f = findings_by_rule["AEGIS-SECRET-GITHUB-TOKEN"][0]
        assert f.severity == Severity.CRITICAL

    def test_redaction(self, findings_by_rule):
        f = findings_by_rule["AEGIS-SECRET-GITHUB-TOKEN"][0]
        _assert_redacted(f, FAKE_GHP_TOKEN)


class TestApiKeyDetection:
    def test_rule_fires(self, findings_by_rule):
        assert "AEGIS-SECRET-API-KEY" in findings_by_rule

    def test_correct_line_number(self, findings_by_rule):
        f = findings_by_rule["AEGIS-SECRET-API-KEY"][0]
        assert f.line == 21, f"Expected line 21, got {f.line}"

    def test_severity_is_high(self, findings_by_rule):
        f = findings_by_rule["AEGIS-SECRET-API-KEY"][0]
        assert f.severity == Severity.HIGH

    def test_redaction(self, findings_by_rule):
        f = findings_by_rule["AEGIS-SECRET-API-KEY"][0]
        _assert_redacted(f, FAKE_API_KEY)


class TestPasswordDetection:
    def test_rule_fires(self, findings_by_rule):
        assert "AEGIS-SECRET-PASSWORD" in findings_by_rule

    def test_correct_line_number(self, findings_by_rule):
        f = findings_by_rule["AEGIS-SECRET-PASSWORD"][0]
        assert f.line == 25, f"Expected line 25, got {f.line}"

    def test_severity_is_high(self, findings_by_rule):
        f = findings_by_rule["AEGIS-SECRET-PASSWORD"][0]
        assert f.severity == Severity.HIGH

    def test_redaction(self, findings_by_rule):
        f = findings_by_rule["AEGIS-SECRET-PASSWORD"][0]
        _assert_redacted(f, FAKE_PASSWORD)


# ---------------------------------------------------------------------------
# Redaction contract: raw values must never appear in any output
# ---------------------------------------------------------------------------

class TestRedactionContract:
    def test_no_raw_secrets_in_redacted_fields(self, vulnerable_findings):
        for f in vulnerable_findings:
            secret = _RULE_TO_SECRET.get(f.rule_id)
            if secret:
                assert secret not in f.redacted, (
                    f"Raw secret found in finding.redacted for {f.rule_id}"
                )

    def test_no_raw_secrets_in_serialised_output(self, vulnerable_findings):
        for f in vulnerable_findings:
            secret = _RULE_TO_SECRET.get(f.rule_id)
            if secret:
                assert secret not in json.dumps(f.to_dict()), (
                    f"Raw secret found in JSON output for {f.rule_id}"
                )

    def test_evidence_key_absent_from_dict(self, vulnerable_findings):
        """to_dict() must export 'evidence' as the redacted value, not the raw one."""
        for f in vulnerable_findings:
            d = f.to_dict()
            secret = _RULE_TO_SECRET.get(f.rule_id)
            if secret:
                assert secret not in d.get("evidence", ""), (
                    "Raw secret found under the 'evidence' key in serialised output"
                )


# ---------------------------------------------------------------------------
# Non-match tests: benign content must not produce findings
# ---------------------------------------------------------------------------

class TestNonMatches:
    def test_benign_prose_token_no_finding(self, tmp_path):
        """Plain prose use of 'token' must not trigger a finding."""
        f = tmp_path / "docs.py"
        f.write_text('# The token is used for authentication purposes.\n', encoding="utf-8")
        assert scan(tmp_path) == []

    def test_benign_token_count_no_finding(self, tmp_path):
        """Integer assignment to a variable with 'token' in the name must not fire."""
        f = tmp_path / "counters.py"
        f.write_text("token_count = 42\n", encoding="utf-8")
        assert scan(tmp_path) == []

    def test_benign_password_policy_no_finding(self, tmp_path):
        """A variable referencing password policy (not a value) must not fire."""
        f = tmp_path / "policy.py"
        f.write_text('the_password_policy = "must be 12 characters"\n', encoding="utf-8")
        # "must be 12 characters" is 22 chars with spaces — long enough to match,
        # so we test with a clearly non-secret policy description.
        # The fixture uses this exact string and we assert it produces no extra findings
        # beyond the known secrets.
        findings = scan(tmp_path)
        assert findings == []

    def test_api_key_noun_only_no_finding(self, tmp_path):
        """'api_key' without an assignment operator must not trigger a finding."""
        f = tmp_path / "docs.py"
        f.write_text("# Pass the api_key argument to authenticate().\n", encoding="utf-8")
        assert scan(tmp_path) == []

    def test_empty_project(self, tmp_path):
        """An empty directory must return no findings."""
        assert scan(tmp_path) == []

    def test_project_with_only_clean_files(self, tmp_path):
        """A project with no secrets must return no findings."""
        (tmp_path / "main.py").write_text(
            "def greet(name):\n    return f'Hello, {name}'\n",
            encoding="utf-8",
        )
        assert scan(tmp_path) == []


# ---------------------------------------------------------------------------
# Multiple findings in one file
# ---------------------------------------------------------------------------

class TestMultipleFindings:
    def test_multiple_rules_fire_on_same_file(self, vulnerable_findings):
        """The fixture config.py must contribute findings from multiple rules."""
        config_findings = [f for f in vulnerable_findings if f.file == "config.py"]
        rule_ids = {f.rule_id for f in config_findings}
        assert len(rule_ids) >= 3, (
            f"Expected findings from at least 3 rules in config.py, got: {rule_ids}"
        )

    def test_multiple_findings_in_tmp_file(self, tmp_path):
        """A single file with two secrets must yield two findings."""
        content = (
            "aws_access_key_id = 'AKIAFAKEKEY1234567890'\n"
            "password = 'FakePwd99999'\n"
        )
        (tmp_path / "multi.py").write_text(content, encoding="utf-8")
        findings = scan(tmp_path)
        rule_ids = {f.rule_id for f in findings}
        assert "AEGIS-SECRET-AWS-KEY-ID" in rule_ids
        assert "AEGIS-SECRET-PASSWORD" in rule_ids


# ---------------------------------------------------------------------------
# Unreadable / binary files
# ---------------------------------------------------------------------------

class TestUnreadableFiles:
    def test_binary_file_skipped_gracefully(self, tmp_path):
        """A binary file must be skipped without raising an exception."""
        binary_file = tmp_path / "data.bin"
        binary_file.write_bytes(bytes(range(256)))
        # Should not raise; should return empty findings (binary has no text secrets)
        findings = scan(tmp_path)
        assert isinstance(findings, list)

    def test_latin1_encoded_file_skipped(self, tmp_path):
        """A file with non-UTF-8 encoding must be skipped without crashing."""
        bad_file = tmp_path / "legacy.py"
        # Write Latin-1 encoded content that is invalid UTF-8
        bad_file.write_bytes("password = 'caf\xe9secret'\n".encode("latin-1"))
        findings = scan(tmp_path)
        assert isinstance(findings, list)

    def test_clean_utf8_file_still_scanned_after_bad_file(self, tmp_path):
        """A bad file must not prevent subsequent files from being scanned."""
        bad = tmp_path / "a_bad.py"
        bad.write_bytes(b"\xff\xfe bad utf-8 content\x00")
        good = tmp_path / "b_good.py"
        good.write_text("api_key = 'fake-api-key-value-abc123xyz789'\n", encoding="utf-8")
        findings = scan(tmp_path)
        assert any(f.rule_id == "AEGIS-SECRET-API-KEY" for f in findings), (
            "Clean file must still be scanned after a bad file"
        )


# ---------------------------------------------------------------------------
# Path safety and exclusions
# ---------------------------------------------------------------------------

class TestPathSafety:
    def test_dotgit_directory_excluded(self, tmp_path):
        """Files inside .git/ must not be scanned."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text(
            "password = 'FakeSuperSecretPwd99'\n", encoding="utf-8"
        )
        findings = scan(tmp_path)
        assert not any(".git" in f.file for f in findings), (
            ".git directory contents must be excluded from findings"
        )

    def test_pycache_excluded(self, tmp_path):
        """Files inside __pycache__/ must not be scanned."""
        cache = tmp_path / "__pycache__"
        cache.mkdir()
        (cache / "module.cpython-313.pyc").write_bytes(b"fake binary content")
        assert scan(tmp_path) == []

    def test_venv_excluded(self, tmp_path):
        """Files inside a venv/ directory must not be scanned."""
        venv_dir = tmp_path / "venv"
        venv_dir.mkdir()
        (venv_dir / "config.py").write_text(
            "password = 'FakeSuperSecretPwd99'\n", encoding="utf-8"
        )
        findings = scan(tmp_path)
        assert not any("venv" in f.file for f in findings)

    def test_dotenv_dir_excluded(self, tmp_path):
        """Files inside a .env/ directory must not be scanned."""
        env_dir = tmp_path / ".env"
        env_dir.mkdir()
        (env_dir / "secrets.py").write_text(
            "api_key = 'fake-api-key-value-abc123xyz789'\n", encoding="utf-8"
        )
        findings = scan(tmp_path)
        assert not any(".env" in f.file for f in findings)

    def test_pyc_suffix_excluded(self, tmp_path):
        """Files with .pyc suffix must not be scanned."""
        (tmp_path / "module.pyc").write_bytes(b"\x00\x00\x00\x00fake pyc")
        assert scan(tmp_path) == []

    def test_nonexistent_path_raises(self):
        with pytest.raises(ValueError, match="does not exist"):
            scan(Path("/nonexistent/path/that/cannot/exist"))

    def test_file_path_raises(self, tmp_path):
        f = tmp_path / "notadir.py"
        f.write_text("x = 1\n", encoding="utf-8")
        with pytest.raises(ValueError, match="not a directory"):
            scan(f)

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Symlink creation on Windows requires elevated privileges or Developer Mode",
    )
    def test_symlink_outside_root_skipped(self, tmp_path):
        """A symlink pointing outside the project root must be skipped.

        This guards against the symlink-escape vulnerability: a file inside
        the project that is a symlink to a path outside the project root must
        not be read.  _is_safe_path() checks is_symlink() on the *original*
        path (before resolve()) so that the check cannot be bypassed by the
        fact that the resolved target is itself a regular file.
        """
        outside = tmp_path.parent / "outside_secret.py"
        # Use a fake value that does not match any real credential format.
        outside.write_text("password = 'FakeSuperSecretPwd99'\n", encoding="utf-8")
        link = tmp_path / "link_to_outside.py"
        link.symlink_to(outside)
        findings = scan(tmp_path)
        # The symlink must be excluded by _is_safe_path().
        assert not any(f.file == "link_to_outside.py" for f in findings), (
            "Symlink pointing outside project root must not appear in findings"
        )
        # The secret value from the outside file must not appear in any finding.
        assert not any("FakeSuperSecretPwd99" in f.redacted for f in findings), (
            "Secret from symlink target outside root must not leak into findings"
        )
        outside.unlink(missing_ok=True)

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Symlink creation on Windows requires elevated privileges or Developer Mode",
    )
    def test_symlink_inside_root_also_skipped(self, tmp_path):
        """A symlink whose target is inside the project root must also be skipped.

        Symlinks are always rejected regardless of where their target resides,
        to prevent any path-traversal or double-read confusion.
        """
        real_file = tmp_path / "real_secret.py"
        real_file.write_text("api_key = 'fake-api-key-value-abc123xyz789'\n", encoding="utf-8")
        link = tmp_path / "link_to_real.py"
        link.symlink_to(real_file)
        findings = scan(tmp_path)
        # The real file is scanned normally; the symlink is rejected.
        assert not any(f.file == "link_to_real.py" for f in findings), (
            "Symlink inside project root must not appear as a separate finding"
        )
        # The real file itself is still scanned.
        assert any(f.file == "real_secret.py" for f in findings), (
            "Real file (not a symlink) inside project root must still be scanned"
        )


# ---------------------------------------------------------------------------
# File mutation: scanned files must be unchanged
# ---------------------------------------------------------------------------

class TestFilesUnchanged:
    def test_fixture_files_not_modified(self):
        """Scanning the fixture project must not modify any fixture file."""
        fixture_files = list(VULNERABLE_PROJECT.rglob("*.py"))
        assert fixture_files, "Fixture must contain at least one Python file"

        # Record modification times before scan
        mtimes_before = {f: f.stat().st_mtime for f in fixture_files}

        scan(VULNERABLE_PROJECT)

        # Assert modification times are identical after scan
        for f in fixture_files:
            assert f.stat().st_mtime == mtimes_before[f], (
                f"File was modified during scan: {f}"
            )

    def test_fixture_file_contents_not_modified(self):
        """Scanning must not alter the content of any fixture file."""
        fixture_file = VULNERABLE_PROJECT / "config.py"
        original_content = fixture_file.read_bytes()

        scan(VULNERABLE_PROJECT)

        assert fixture_file.read_bytes() == original_content, (
            "Fixture file content was changed by the scanner"
        )


# ---------------------------------------------------------------------------
# Exclusion constants
# ---------------------------------------------------------------------------

class TestExclusionConstants:
    def test_git_in_excluded_dirs(self):
        assert ".git" in EXCLUDED_DIRS

    def test_pycache_in_excluded_dirs(self):
        assert "__pycache__" in EXCLUDED_DIRS

    def test_venv_variants_in_excluded_dirs(self):
        for name in ("venv", ".venv", "env", ".env"):
            assert name in EXCLUDED_DIRS, f"{name!r} missing from EXCLUDED_DIRS"

    def test_pyc_in_excluded_suffixes(self):
        assert ".pyc" in EXCLUDED_SUFFIXES
