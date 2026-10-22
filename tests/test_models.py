"""Tests for aegis.models — Finding and Severity."""

import json

from aegis.models import Finding, Severity

# ---------------------------------------------------------------------------
# Synthetic test data — all secrets are fake and clearly labelled.
# Never use real credentials in tests.
# ---------------------------------------------------------------------------

FAKE_AWS_KEY = "AKIAFAKEKEY1234567890"  # noqa: S105 — synthetic test value
FAKE_SECRET = f'aws_secret_access_key = "{FAKE_AWS_KEY}__secret"'


def _make_finding(**overrides) -> Finding:
    """Return a minimal valid Finding, with optional field overrides."""
    defaults = {
        "id": "test-001",
        "severity": Severity.HIGH,
        "file": "src/config.py",
        "line": 42,
        "rule_id": "AEGIS-SECRET-AWS",
        "title": "Hardcoded AWS Access Key",
        "description": "An AWS access key was found hardcoded in source.",
        "evidence": FAKE_SECRET,
        "redacted": f'aws_secret_access_key = "[REDACTED]"',
        "remediation": "Remove the key and use environment variables or a secrets manager.",
    }
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Construction tests
# ---------------------------------------------------------------------------


class TestFindingConstruction:
    def test_basic_construction(self):
        f = _make_finding()
        assert f.id == "test-001"
        assert f.severity == Severity.HIGH
        assert f.file == "src/config.py"
        assert f.line == 42
        assert f.rule_id == "AEGIS-SECRET-AWS"
        assert f.title == "Hardcoded AWS Access Key"
        assert f.description == "An AWS access key was found hardcoded in source."
        assert f.remediation == "Remove the key and use environment variables or a secrets manager."

    def test_none_line_number(self):
        """Line number may be None when unavailable (e.g. file-level findings)."""
        f = _make_finding(line=None)
        assert f.line is None

    def test_default_evidence_is_empty_string(self):
        f = Finding(
            id="x",
            severity=Severity.INFO,
            file="app.py",
            line=1,
            rule_id="TEST",
            title="T",
            description="D",
        )
        assert f.evidence == ""
        assert f.redacted == ""
        assert f.remediation == ""

    def test_evidence_field_accessible_internally(self):
        """Internal evidence field must be readable before redaction."""
        f = _make_finding()
        assert FAKE_AWS_KEY in f.evidence


# ---------------------------------------------------------------------------
# Severity tests
# ---------------------------------------------------------------------------


class TestSeverity:
    def test_all_values_defined(self):
        values = {s.value for s in Severity}
        assert values == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def test_ordering_critical_gt_info(self):
        """CRITICAL > INFO when sorted descending."""
        assert not (Severity.CRITICAL < Severity.INFO)
        assert Severity.INFO < Severity.CRITICAL

    def test_sort_descending(self):
        """sorted() with reverse=True puts CRITICAL first."""
        severities = [Severity.LOW, Severity.CRITICAL, Severity.INFO, Severity.HIGH, Severity.MEDIUM]
        result = sorted(severities, reverse=True)
        assert result == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]


# ---------------------------------------------------------------------------
# Serialisation tests
# ---------------------------------------------------------------------------


class TestFindingToDict:
    def test_to_dict_returns_dict(self):
        f = _make_finding()
        assert isinstance(f.to_dict(), dict)

    def test_to_dict_contains_expected_keys(self):
        d = _make_finding().to_dict()
        expected_keys = {"id", "severity", "file", "line", "rule_id", "title",
                         "description", "evidence", "remediation"}
        assert set(d.keys()) == expected_keys

    def test_to_dict_severity_is_string(self):
        """Severity must be serialised as a plain string, not an enum."""
        d = _make_finding(severity=Severity.CRITICAL).to_dict()
        assert d["severity"] == "CRITICAL"
        assert isinstance(d["severity"], str)

    def test_to_dict_exports_redacted_under_evidence_key(self):
        """The 'evidence' key in the output must contain the redacted value."""
        f = _make_finding()
        d = f.to_dict()
        assert d["evidence"] == f.redacted
        assert "[REDACTED]" in d["evidence"]

    def test_to_dict_none_line_serialises_as_none(self):
        d = _make_finding(line=None).to_dict()
        assert d["line"] is None

    def test_to_dict_raw_evidence_key_absent(self):
        """The internal raw evidence field must not appear as a key in the output."""
        d = _make_finding().to_dict()
        # No key that could expose the raw value
        assert "raw_evidence" not in d
        # Confirm the 'evidence' key holds the redacted value, not the raw one
        assert d["evidence"] != FAKE_SECRET


# ---------------------------------------------------------------------------
# JSON round-trip tests
# ---------------------------------------------------------------------------


class TestJSONSerialization:
    def test_json_serializable(self):
        d = _make_finding().to_dict()
        serialised = json.dumps(d)
        assert isinstance(serialised, str)

    def test_json_round_trip(self):
        d = _make_finding().to_dict()
        recovered = json.loads(json.dumps(d))
        assert recovered["id"] == d["id"]
        assert recovered["severity"] == "HIGH"
        assert recovered["line"] == 42

    def test_json_none_line_round_trip(self):
        d = _make_finding(line=None).to_dict()
        recovered = json.loads(json.dumps(d))
        assert recovered["line"] is None


# ---------------------------------------------------------------------------
# Regression: raw synthetic secret must never appear in serialised output
# ---------------------------------------------------------------------------


class TestRawSecretNotInOutput:
    def test_raw_secret_absent_from_dict(self):
        """Regression: the fake AWS key must not appear in to_dict() output values."""
        d = _make_finding().to_dict()
        for key, value in d.items():
            if isinstance(value, str):
                assert FAKE_AWS_KEY not in value, (
                    f"Raw synthetic secret found in dict field '{key}'"
                )

    def test_raw_secret_absent_from_json(self):
        """Regression: the fake AWS key must not appear anywhere in the JSON string."""
        json_str = json.dumps(_make_finding().to_dict())
        assert FAKE_AWS_KEY not in json_str, (
            "Raw synthetic secret found in JSON output — redaction contract broken."
        )

    def test_raw_secret_absent_when_redacted_field_is_empty(self):
        """Even with an empty redacted field, raw evidence must not leak."""
        f = _make_finding(redacted="")
        d = f.to_dict()
        json_str = json.dumps(d)
        assert FAKE_AWS_KEY not in json_str
        # The evidence key should be empty (redacted field was empty)
        assert d["evidence"] == ""
