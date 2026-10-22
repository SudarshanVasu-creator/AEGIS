"""AEGIS regex-based secret scanner.

Walks a project directory line-by-line, applies heuristic patterns to detect
common secret categories, and returns a list of :class:`~aegis.models.Finding`
objects with redacted evidence.

Design notes
------------
- Detection patterns mirror those in ``aegis.redactor`` but are used here for
  *detection* (does this line contain a secret?) rather than substitution.
- Each matched line produces one Finding per matched rule.
- ``Finding.evidence`` is populated with the raw line (internal only).
- ``Finding.redacted`` is populated immediately via :func:`aegis.redactor.redact`
  so the raw value never needs to travel further than this module.
- Relative file paths are used throughout to avoid leaking the local filesystem
  structure in reports.
- All scanning is read-only.  No file is modified.
- No network requests are made.

Known false-positive risks
--------------------------
- Generic API-key patterns require an assignment operator, but long values in
  YAML or .env files that happen to use a matching LHS keyword and long RHS
  may be flagged even when the value is not a real secret.
- The AWS AKIA pattern is highly specific (prefix + 16 uppercase alphanumeric)
  and has a low false-positive rate, but generated IDs in test fixtures or
  documentation could match.

Known false-negative risks
--------------------------
- Secrets split across multiple lines are not detected.
- Secrets inside binary files are skipped entirely.
- Obfuscated or base64-encoded secrets are not detected.
- Secrets stored in environment variables at runtime are not detected.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import NamedTuple

from aegis.models import Finding, Severity
from aegis.redactor import redact


# ---------------------------------------------------------------------------
# Exclusion set
# ---------------------------------------------------------------------------

#: Directory names that are always skipped during traversal.
EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "__pycache__",
        "node_modules",
        "venv",
        ".venv",
        "env",
        ".env",
        "ENV",
        ".tox",
        ".nox",
        "dist",
        "build",
        ".eggs",
    }
)

#: File suffixes that are always skipped (binary / compiled).
EXCLUDED_SUFFIXES: frozenset[str] = frozenset(
    {
        ".pyc",
        ".pyo",
        ".pyd",
        ".so",
        ".dll",
        ".exe",
        ".bin",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".whl",
    }
)


# ---------------------------------------------------------------------------
# Detection rule definitions
# ---------------------------------------------------------------------------

class _Rule(NamedTuple):
    rule_id: str
    severity: Severity
    title: str
    description: str
    remediation: str
    regex: re.Pattern[str]


# Separator pattern shared with redactor: = : => with optional whitespace
_SEP = r"(?:\s*(?:=>|[:=])\s*)"
_VAR_VALUE = r"([^\s'\"\\,;)]{6,})"      # bare value ≥6 non-whitespace chars


def _det(lhs_pattern: str, value_group: str = _VAR_VALUE) -> re.Pattern[str]:
    """Build a compiled *detection* pattern (returns the whole match)."""
    return re.compile(
        r"(?i)" + lhs_pattern + _SEP + r"""['"]?""" + value_group + r"""['"]?""",
        re.ASCII,
    )


RULES: list[_Rule] = [

    # --- AWS Access Key ID ---------------------------------------------------
    _Rule(
        rule_id="AEGIS-SECRET-AWS-KEY-ID",
        severity=Severity.CRITICAL,
        title="Hardcoded AWS Access Key ID",
        description=(
            "An AWS Access Key ID (beginning with 'AKIA') was found hardcoded "
            "in source. Committing this value exposes the associated AWS account "
            "to unauthorized access."
        ),
        remediation=(
            "Remove the key from source immediately. Rotate the key in the AWS "
            "IAM console. Use environment variables, AWS Secrets Manager, or an "
            "IAM role instead."
        ),
        regex=re.compile(r"AKIA[0-9A-Z]{16}", re.ASCII),
    ),

    # --- AWS Secret Access Key -----------------------------------------------
    _Rule(
        rule_id="AEGIS-SECRET-AWS-SECRET",
        severity=Severity.CRITICAL,
        title="Hardcoded AWS Secret Access Key",
        description=(
            "An assignment to a variable named 'aws_secret_access_key', "
            "'aws_secret', or 'secret_access_key' was found with a value "
            "that matches the expected format of an AWS Secret Access Key."
        ),
        remediation=(
            "Remove the secret from source immediately. Rotate the key in the "
            "AWS IAM console. Use environment variables or AWS Secrets Manager."
        ),
        regex=re.compile(
            r"(?i)(?:aws_secret_access_key|aws_secret|secret_access_key)"
            r"\s*(?:=>|[:=])\s*['\"]?([A-Za-z0-9+/]{30,}=?)['\"]?",
            re.ASCII,
        ),
    ),

    # --- GitHub tokens -------------------------------------------------------
    _Rule(
        rule_id="AEGIS-SECRET-GITHUB-TOKEN",
        severity=Severity.CRITICAL,
        title="Hardcoded GitHub Personal Access Token",
        description=(
            "A GitHub Personal Access Token (classic 'ghp_', 'gho_', 'ghs_', "
            "'ghr_', or fine-grained 'github_pat_') was found hardcoded in "
            "source. This grants the holder access to repositories and "
            "potentially to the GitHub account."
        ),
        remediation=(
            "Revoke the token immediately on GitHub (Settings → Developer "
            "Settings → Personal access tokens). Never hardcode tokens; use "
            "environment variables or a secrets manager."
        ),
        regex=re.compile(
            r"(?:gh[poshrs]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})",
            re.ASCII,
        ),
    ),

    # --- Generic API key / token assignment ----------------------------------
    _Rule(
        rule_id="AEGIS-SECRET-API-KEY",
        severity=Severity.HIGH,
        title="Hardcoded API Key or Token",
        description=(
            "A variable name associated with API keys or tokens "
            "(e.g. 'api_key', 'access_token', 'auth_token', 'secret_key', "
            "'client_secret') was found with a hardcoded value."
        ),
        remediation=(
            "Move the value to an environment variable or a secrets manager. "
            "Rotate the key or token if it may have been exposed."
        ),
        regex=_det(
            r"(?:api[-_]?key|access[-_]?token|auth[-_]?token|"
            r"secret[-_]?key|secret[-_]?token|private[-_]?key|"
            r"client[-_]?secret)\b",
        ),
    ),

    # --- Hardcoded password --------------------------------------------------
    _Rule(
        rule_id="AEGIS-SECRET-PASSWORD",
        severity=Severity.HIGH,
        title="Hardcoded Password",
        description=(
            "A variable name associated with passwords "
            "('password', 'passwd', 'pwd', 'db_password', etc.) was found "
            "with a hardcoded value."
        ),
        remediation=(
            "Replace the hardcoded password with an environment variable or a "
            "secrets manager reference. Never commit passwords to source control."
        ),
        regex=_det(
            r"(?:(?:db_|user_|admin_)?pass(?:word|wd)?|pwd)\b",
        ),
    ),
]


# ---------------------------------------------------------------------------
# Path safety helpers
# ---------------------------------------------------------------------------

def _is_safe_path(path: Path, root: Path) -> bool:
    """Return True only if *path* is inside *root* and is a regular file.

    Rejects symlinks by checking the *original* path before any resolution.
    Both *path* and *root* must already be resolved (absolute, no symlinks).
    """
    # Reject symlinks on the original (unresolved) path.  Checking after
    # resolve() would test whether the *target* is a symlink, not whether
    # the discovered entry itself is one — that check is always False for a
    # resolved target, making it useless as a guard.
    try:
        if path.is_symlink():
            return False
        resolved = path.resolve()
    except (OSError, ValueError):
        return False
    # is_relative_to available from Python 3.9
    try:
        resolved.relative_to(root)
    except ValueError:
        return False
    return resolved.is_file()


def _is_excluded_dir(part: str) -> bool:
    """Return True if the directory name component should be skipped."""
    return part in EXCLUDED_DIRS or part.endswith(".egg-info")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan(project_path: Path) -> list[Finding]:
    """Scan *project_path* for hardcoded secrets and return a list of findings.

    Parameters
    ----------
    project_path:
        Absolute or relative path to the directory to scan.  Resolved
        internally with :meth:`Path.resolve` before traversal.

    Returns
    -------
    list[Finding]
        Findings sorted by (file, line).  Each finding has ``evidence``
        populated with the raw matched line (internal only) and ``redacted``
        populated with the redactor output.  The caller (orchestrator) is
        responsible for clearing ``evidence`` before export.

    Raises
    ------
    ValueError
        If *project_path* does not exist or is not a directory.
    """
    root = project_path.resolve()
    if not root.exists():
        raise ValueError(f"Project path does not exist: {project_path}")
    if not root.is_dir():
        raise ValueError(f"Project path is not a directory: {project_path}")

    findings: list[Finding] = []

    for candidate in root.rglob("*"):
        # --- Skip excluded directories anywhere in the path ------------------
        # Check all parts relative to root for an excluded directory name.
        try:
            rel_parts = candidate.relative_to(root).parts
        except ValueError:
            continue

        if any(_is_excluded_dir(part) for part in rel_parts[:-1]):
            continue

        # --- Only process safe regular files ---------------------------------
        if not _is_safe_path(candidate, root):
            continue

        # --- Skip excluded suffixes ------------------------------------------
        if candidate.suffix.lower() in EXCLUDED_SUFFIXES:
            continue

        # --- Relative path for finding output --------------------------------
        rel_path = str(candidate.relative_to(root))

        # --- Read file, skipping unreadable or binary content ----------------
        try:
            lines = candidate.read_text(encoding="utf-8", errors="strict").splitlines()
        except UnicodeDecodeError:
            # Binary or non-UTF-8 file — skip silently
            continue
        except OSError:
            # Permission denied or other I/O error — skip silently
            continue

        # --- Apply each rule to each line ------------------------------------
        for line_number, line_text in enumerate(lines, start=1):
            for rule in RULES:
                if not rule.regex.search(line_text):
                    continue

                raw_evidence = line_text.rstrip()
                redacted_evidence = redact(raw_evidence)

                finding = Finding(
                    id=f"{rule.rule_id}:{rel_path}:{line_number}",
                    severity=rule.severity,
                    file=rel_path,
                    line=line_number,
                    rule_id=rule.rule_id,
                    title=rule.title,
                    description=rule.description,
                    evidence=raw_evidence,
                    redacted=redacted_evidence,
                    remediation=rule.remediation,
                )
                findings.append(finding)

    # Sort by file path then line number for deterministic output
    findings.sort(key=lambda f: (f.file, f.line or 0))
    return findings
