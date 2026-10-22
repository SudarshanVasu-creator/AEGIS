"""AEGIS redactor — strips secret values from evidence strings before output.

This module exposes a single public function, ``redact(text)``, which applies
a list of heuristic regex patterns to replace secret *values* with the literal
string ``[REDACTED]``.  Variable names, key labels, and surrounding context are
preserved so findings remain actionable.

Design notes
------------
- Patterns target the *value* portion of an assignment or bare token, not the
  entire line.  This keeps output readable.
- Patterns are heuristic, not exhaustive.  They are not proof that a matched
  value is a real credential.
- The function is deterministic and has no side-effects.
- No network calls, no file I/O, no logging of raw values.
"""

from __future__ import annotations

import re
from typing import NamedTuple


class _Pattern(NamedTuple):
    name: str
    regex: re.Pattern[str]
    replacement: str


# ---------------------------------------------------------------------------
# Pattern helpers
# ---------------------------------------------------------------------------

# Matches an assignment separator and captures everything before the value.
# Supported separators:  =  :  =>  (with optional surrounding whitespace).
# The value may optionally be wrapped in single or double quotes.
#
# Group structure used by _ASSIGNMENT_PATTERNS below:
#   Group 1 — everything up to and including the opening quote (if any)
#   Group 2 — the secret value itself  ← replaced with [REDACTED]
#   Group 3 — the closing quote (if any)

_SEP = r"""(?:\s*(?:=>|[:=])\s*)"""          # separator: = : => (no shell $)
_OPEN_QUOTE = r"""(?P<q>[\'"]?)"""            # optional opening quote (named)
_VAR_VALUE = r"""([^\s\'\"\\,;)]{6,})"""      # bare value ≥6 non-whitespace chars
_QUOTED_VALUE = r"""([^\'\"\\]{4,})"""        # quoted value ≥4 chars (no backslash)


def _asgn(lhs_pattern: str, value_group: str = _VAR_VALUE) -> re.Pattern[str]:
    """Build a compiled assignment pattern for a given LHS keyword pattern."""
    pattern = (
        r"(?i)"                                 # case-insensitive
        r"(" + lhs_pattern + _SEP + r"""[\'"]?)"""  # group 1: lhs + sep + optional quote
        + value_group                           # group 2: value to redact
        + r"""([\'"]?)"""                       # group 3: closing quote (if any)
    )
    return re.compile(pattern)


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

_PATTERNS: list[_Pattern] = [

    # --- AWS Access Key ID ---------------------------------------------------
    # Bare token beginning with AKIA (20 uppercase alphanumeric chars).
    # Matches whether it appears in an assignment, a string, or bare.
    _Pattern(
        name="aws-access-key-id",
        regex=re.compile(r"(AKIA[0-9A-Z]{16})", re.ASCII),
        replacement=r"[REDACTED]",
    ),

    # --- AWS Secret Access Key -----------------------------------------------
    # 40-character base64-ish string, typically in an assignment.
    # LHS keywords: aws_secret_access_key, aws_secret, secret_access_key.
    _Pattern(
        name="aws-secret-access-key",
        regex=_asgn(
            r"(?:aws_secret_access_key|aws_secret|secret_access_key)\b",
            value_group=r"([A-Za-z0-9+/]{30,}[=]{0,2})",
        ),
        replacement=r"\1[REDACTED]\3",
    ),

    # --- GitHub personal access tokens (classic and fine-grained) -----------
    # Bare tokens starting with ghp_, gho_, ghs_, ghr_, or github_pat_.
    _Pattern(
        name="github-token",
        regex=re.compile(
            r"(gh[poshrs]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})",
            re.ASCII,
        ),
        replacement=r"[REDACTED]",
    ),

    # --- Generic API key / token assignment ----------------------------------
    # LHS keywords: api_key, apikey, api-key, access_token, auth_token, secret_key,
    #               secret_token, private_key, client_secret.
    # Requires an assignment operator so bare uses of the word "token" are safe.
    _Pattern(
        name="generic-api-key",
        regex=_asgn(
            r"(?:api[-_]?key|access[-_]?token|auth[-_]?token|"
            r"secret[-_]?key|secret[-_]?token|private[-_]?key|"
            r"client[-_]?secret)\b",
        ),
        replacement=r"\1[REDACTED]\3",
    ),

    # --- Hardcoded password assignment ---------------------------------------
    # LHS keywords: password, passwd, pwd, db_password, db_pass, user_password.
    # Requires an assignment operator.
    _Pattern(
        name="hardcoded-password",
        regex=_asgn(
            r"(?:(?:db_|user_|admin_)?pass(?:word|wd)?|pwd)\b",
        ),
        replacement=r"\1[REDACTED]\3",
    ),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def redact(text: str) -> str:
    """Return *text* with detected secret values replaced by ``[REDACTED]``.

    Variable names, key labels, assignment operators, and surrounding context
    are preserved.  Only the value portion of a matched pattern is replaced.

    The function is idempotent: calling it on already-redacted output is safe.

    Parameters
    ----------
    text:
        The string to sanitise — typically a single evidence line from a scanner.

    Returns
    -------
    str
        The sanitised string.  Returned unchanged if no patterns match.
    """
    result = text
    for pat in _PATTERNS:
        result = pat.regex.sub(pat.replacement, result)
    return result
