"""Tests for aegis.redactor.

All test credentials are synthetic and clearly labelled as fake.
No real credentials are used anywhere in this file.
Raw secret values are never printed — assertions check for their absence.
"""

from __future__ import annotations

import pytest

from aegis.redactor import redact

# ---------------------------------------------------------------------------
# Synthetic fake credentials (clearly not real)
# ---------------------------------------------------------------------------

# AWS — 20-char uppercase alphanumeric starting with AKIA
FAKE_AWS_KEY_ID = "AKIAFAKEACCESSKEY001"

# AWS secret — 40-char base64-ish string
FAKE_AWS_SECRET = "FakeAwsSecretKey1234567890abcdefghijABCD"

# GitHub classic personal access token
FAKE_GHP_TOKEN = "ghp_FakeGitHubTokenABCDEFGHIJKLMN1234"

# GitHub fine-grained personal access token
FAKE_GH_PAT = "github_pat_FakeFinegrainedToken_1234567890ABCDEF"

# Generic API key value
FAKE_API_KEY = "fake-api-key-value-abc123xyz789"

# Generic access token value
FAKE_ACCESS_TOKEN = "fake-access-token-value-abc123xyz789"

# Generic secret key value
FAKE_SECRET_KEY = "fake-secret-key-value-abc123xyz789"

# Generic client secret value
FAKE_CLIENT_SECRET = "fake-client-secret-value-abc123"

# Password values
FAKE_PASSWORD = "FakeSuperSecretPwd99"
FAKE_SHORT_PW  = "short"   # intentionally too short to match (< 6 chars)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _assert_redacted(result: str, raw_value: str) -> None:
    """Assert [REDACTED] is present and the raw secret value is absent."""
    assert "[REDACTED]" in result, f"Expected [REDACTED] in output but got: {result!r}"
    assert raw_value not in result, (
        "Raw synthetic secret still present in redacted output — redaction failed."
    )


# ---------------------------------------------------------------------------
# AWS Access Key ID
# ---------------------------------------------------------------------------

class TestAwsAccessKeyId:
    def test_bare_token_in_assignment(self):
        line = f"aws_access_key_id = '{FAKE_AWS_KEY_ID}'"
        result = redact(line)
        _assert_redacted(result, FAKE_AWS_KEY_ID)

    def test_bare_token_double_quote(self):
        line = f'aws_access_key_id = "{FAKE_AWS_KEY_ID}"'
        result = redact(line)
        _assert_redacted(result, FAKE_AWS_KEY_ID)

    def test_bare_token_no_quotes(self):
        line = f"aws_access_key_id = {FAKE_AWS_KEY_ID}"
        result = redact(line)
        _assert_redacted(result, FAKE_AWS_KEY_ID)

    def test_token_standalone_in_string(self):
        """AKIA token appearing without an assignment should still be redacted."""
        line = f"key: {FAKE_AWS_KEY_ID}"
        result = redact(line)
        _assert_redacted(result, FAKE_AWS_KEY_ID)

    def test_label_preserved_after_redaction(self):
        line = f"aws_access_key_id = '{FAKE_AWS_KEY_ID}'"
        result = redact(line)
        assert "aws_access_key_id" in result

    def test_non_akia_string_not_redacted(self):
        line = "some_id = 'BKIAFAKE1234567890AB'"
        result = redact(line)
        assert "[REDACTED]" not in result
        assert result == line


# ---------------------------------------------------------------------------
# AWS Secret Access Key
# ---------------------------------------------------------------------------

class TestAwsSecretAccessKey:
    def test_standard_assignment_single_quote(self):
        line = f"aws_secret_access_key = '{FAKE_AWS_SECRET}'"
        result = redact(line)
        _assert_redacted(result, FAKE_AWS_SECRET)

    def test_standard_assignment_double_quote(self):
        line = f'aws_secret_access_key = "{FAKE_AWS_SECRET}"'
        result = redact(line)
        _assert_redacted(result, FAKE_AWS_SECRET)

    def test_no_quotes(self):
        line = f"aws_secret_access_key = {FAKE_AWS_SECRET}"
        result = redact(line)
        _assert_redacted(result, FAKE_AWS_SECRET)

    def test_aws_secret_alias(self):
        line = f"aws_secret = '{FAKE_AWS_SECRET}'"
        result = redact(line)
        _assert_redacted(result, FAKE_AWS_SECRET)

    def test_secret_access_key_alias(self):
        line = f"secret_access_key = '{FAKE_AWS_SECRET}'"
        result = redact(line)
        _assert_redacted(result, FAKE_AWS_SECRET)

    def test_label_preserved(self):
        line = f"aws_secret_access_key = '{FAKE_AWS_SECRET}'"
        result = redact(line)
        assert "aws_secret_access_key" in result


# ---------------------------------------------------------------------------
# GitHub tokens
# ---------------------------------------------------------------------------

class TestGitHubTokens:
    def test_ghp_in_assignment(self):
        line = f"token = {FAKE_GHP_TOKEN}"
        result = redact(line)
        _assert_redacted(result, FAKE_GHP_TOKEN)

    def test_ghp_in_quoted_assignment(self):
        line = f"github_token = '{FAKE_GHP_TOKEN}'"
        result = redact(line)
        _assert_redacted(result, FAKE_GHP_TOKEN)

    def test_ghp_standalone(self):
        """A ghp_ token appearing bare should be redacted regardless of context."""
        line = f"Using {FAKE_GHP_TOKEN} for auth"
        result = redact(line)
        _assert_redacted(result, FAKE_GHP_TOKEN)

    def test_github_pat_fine_grained(self):
        line = f"token = {FAKE_GH_PAT}"
        result = redact(line)
        _assert_redacted(result, FAKE_GH_PAT)

    def test_github_pat_standalone(self):
        line = f"PAT: {FAKE_GH_PAT}"
        result = redact(line)
        _assert_redacted(result, FAKE_GH_PAT)

    def test_case_insensitive_label(self):
        line = f"TOKEN = {FAKE_GHP_TOKEN}"
        result = redact(line)
        _assert_redacted(result, FAKE_GHP_TOKEN)


# ---------------------------------------------------------------------------
# Generic API key and token assignments
# ---------------------------------------------------------------------------

class TestGenericApiKey:
    def test_api_key_single_quote(self):
        line = f"api_key = '{FAKE_API_KEY}'"
        result = redact(line)
        _assert_redacted(result, FAKE_API_KEY)

    def test_api_key_double_quote(self):
        line = f'api_key = "{FAKE_API_KEY}"'
        result = redact(line)
        _assert_redacted(result, FAKE_API_KEY)

    def test_apikey_no_separator(self):
        line = f"apikey = '{FAKE_API_KEY}'"
        result = redact(line)
        _assert_redacted(result, FAKE_API_KEY)

    def test_api_key_hyphenated(self):
        line = f"api-key = '{FAKE_API_KEY}'"
        result = redact(line)
        _assert_redacted(result, FAKE_API_KEY)

    def test_access_token_assignment(self):
        line = f"access_token = '{FAKE_ACCESS_TOKEN}'"
        result = redact(line)
        _assert_redacted(result, FAKE_ACCESS_TOKEN)

    def test_auth_token_assignment(self):
        line = f"auth_token = '{FAKE_ACCESS_TOKEN}'"
        result = redact(line)
        _assert_redacted(result, FAKE_ACCESS_TOKEN)

    def test_secret_key_assignment(self):
        line = f"secret_key = '{FAKE_SECRET_KEY}'"
        result = redact(line)
        _assert_redacted(result, FAKE_SECRET_KEY)

    def test_client_secret_assignment(self):
        line = f"client_secret = '{FAKE_CLIENT_SECRET}'"
        result = redact(line)
        _assert_redacted(result, FAKE_CLIENT_SECRET)

    def test_label_preserved(self):
        line = f"api_key = '{FAKE_API_KEY}'"
        result = redact(line)
        assert "api_key" in result

    def test_no_redaction_without_assignment(self):
        """The word 'token' alone in prose must not trigger redaction."""
        line = "The token is used for OAuth authentication."
        result = redact(line)
        assert "[REDACTED]" not in result
        assert result == line

    def test_no_redaction_api_key_noun_only(self):
        """'api_key' without an assignment operator must not trigger redaction."""
        line = "Pass the api_key argument to the function."
        result = redact(line)
        assert "[REDACTED]" not in result

    def test_case_insensitive_lhs(self):
        line = f"API_KEY = '{FAKE_API_KEY}'"
        result = redact(line)
        _assert_redacted(result, FAKE_API_KEY)

    def test_colon_separator(self):
        """YAML-style colon separators should be handled."""
        line = f"api_key: {FAKE_API_KEY}"
        result = redact(line)
        _assert_redacted(result, FAKE_API_KEY)


# ---------------------------------------------------------------------------
# Hardcoded password assignments
# ---------------------------------------------------------------------------

class TestHardcodedPassword:
    def test_password_single_quote(self):
        line = f"password = '{FAKE_PASSWORD}'"
        result = redact(line)
        _assert_redacted(result, FAKE_PASSWORD)

    def test_password_double_quote(self):
        line = f'password = "{FAKE_PASSWORD}"'
        result = redact(line)
        _assert_redacted(result, FAKE_PASSWORD)

    def test_passwd_alias(self):
        line = f"passwd = '{FAKE_PASSWORD}'"
        result = redact(line)
        _assert_redacted(result, FAKE_PASSWORD)

    def test_pwd_alias(self):
        line = f"pwd = '{FAKE_PASSWORD}'"
        result = redact(line)
        _assert_redacted(result, FAKE_PASSWORD)

    def test_db_password_prefix(self):
        line = f"db_password = '{FAKE_PASSWORD}'"
        result = redact(line)
        _assert_redacted(result, FAKE_PASSWORD)

    def test_case_insensitive_lhs(self):
        line = f"PASSWORD = '{FAKE_PASSWORD}'"
        result = redact(line)
        _assert_redacted(result, FAKE_PASSWORD)

    def test_label_preserved(self):
        line = f"password = '{FAKE_PASSWORD}'"
        result = redact(line)
        assert "password" in result

    def test_no_redaction_without_assignment(self):
        """'password' in plain prose must not trigger redaction."""
        line = "Forgot your password? Click here."
        result = redact(line)
        assert "[REDACTED]" not in result
        assert result == line

    def test_colon_separator(self):
        """YAML-style colon separator."""
        line = f"password: {FAKE_PASSWORD}"
        result = redact(line)
        _assert_redacted(result, FAKE_PASSWORD)

    def test_short_value_not_redacted(self):
        """Values shorter than the minimum length threshold are not redacted
        to avoid false-positives on empty or placeholder assignments."""
        line = f"password = '{FAKE_SHORT_PW}'"
        result = redact(line)
        # 'short' is 5 chars — below the 6-char minimum for bare values
        assert "[REDACTED]" not in result


# ---------------------------------------------------------------------------
# No-op: strings with no secrets must be returned unchanged
# ---------------------------------------------------------------------------

class TestNoOp:
    def test_plain_sentence_unchanged(self):
        line = "This is a normal log message with no secrets."
        assert redact(line) == line

    def test_import_statement_unchanged(self):
        line = "import os"
        assert redact(line) == line

    def test_function_call_unchanged(self):
        line = "result = authenticate(user, session_token=None)"
        assert redact(line) == line

    def test_empty_string_unchanged(self):
        assert redact("") == ""

    def test_comment_line_unchanged(self):
        line = "# Set the API key via environment variable"
        assert redact(line) == line

    def test_url_without_secret_unchanged(self):
        line = "BASE_URL = 'https://api.example.com/v1'"
        assert redact(line) == line


# ---------------------------------------------------------------------------
# Multiple secrets in one string
# ---------------------------------------------------------------------------

class TestMultipleSecrets:
    def test_both_aws_key_and_secret(self):
        line = (
            f"key_id = '{FAKE_AWS_KEY_ID}', "
            f"aws_secret_access_key = '{FAKE_AWS_SECRET}'"
        )
        result = redact(line)
        _assert_redacted(result, FAKE_AWS_KEY_ID)
        _assert_redacted(result, FAKE_AWS_SECRET)
        assert result.count("[REDACTED]") == 2

    def test_api_key_and_password(self):
        line = (
            f"api_key = '{FAKE_API_KEY}', "
            f"password = '{FAKE_PASSWORD}'"
        )
        result = redact(line)
        _assert_redacted(result, FAKE_API_KEY)
        _assert_redacted(result, FAKE_PASSWORD)
        assert result.count("[REDACTED]") == 2


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

class TestIdempotency:
    def test_already_redacted_string_unchanged(self):
        already = "api_key = '[REDACTED]'"
        assert redact(already) == already

    def test_double_redact_is_stable(self):
        line = f"api_key = '{FAKE_API_KEY}'"
        once = redact(line)
        twice = redact(once)
        assert once == twice


# ---------------------------------------------------------------------------
# Context preservation
# ---------------------------------------------------------------------------

class TestContextPreservation:
    def test_variable_name_preserved_password(self):
        line = f"db_password = '{FAKE_PASSWORD}'"
        result = redact(line)
        assert "db_password" in result
        assert "=" in result

    def test_variable_name_preserved_api_key(self):
        line = f"API_KEY = '{FAKE_API_KEY}'"
        result = redact(line)
        assert "API_KEY" in result

    def test_surrounding_text_preserved(self):
        line = f"config = dict(api_key='{FAKE_API_KEY}', debug=True)"
        result = redact(line)
        _assert_redacted(result, FAKE_API_KEY)
        assert "config = dict(" in result
        assert "debug=True)" in result
