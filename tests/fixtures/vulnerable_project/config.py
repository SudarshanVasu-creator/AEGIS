# tests/fixtures/vulnerable_project/config.py
#
# SYNTHETIC FIXTURE — NOT A REAL PROJECT
# All credentials below are fake and generated solely for testing AEGIS.
# These values must never be used in any real system.
# Do not treat these as examples of real secret formats.

# --- Fake AWS credentials (clearly synthetic) ---
# Rule: AEGIS-SECRET-AWS-KEY-ID
aws_access_key_id = 'AKIAFAKEACCESSKEY001'

# Rule: AEGIS-SECRET-AWS-SECRET
aws_secret_access_key = 'FakeAwsSecretKey1234567890abcdefghijABCD'

# --- Fake GitHub token (clearly synthetic) ---
# Rule: AEGIS-SECRET-GITHUB-TOKEN
github_token = 'ghp_FakeGitHubTokenABCDEFGHIJKLMN1234'

# --- Fake API key (clearly synthetic) ---
# Rule: AEGIS-SECRET-API-KEY
api_key = 'fake-api-key-value-abc123xyz789'

# --- Fake hardcoded password (clearly synthetic) ---
# Rule: AEGIS-SECRET-PASSWORD
password = 'FakeSuperSecretPwd99'

# --- Benign values that must NOT trigger findings ---
description = "This config file sets up the application."
token_count = 42
the_password_policy = "must be 12 characters"
