"""AEGIS Bandit runner — invokes Bandit via subprocess and converts results.

Bandit (https://bandit.readthedocs.io/) performs Python AST-based security
analysis.  This module invokes it as a subprocess with ``shell=False``, parses
its JSON output, and converts results into :class:`~aegis.models.Finding`
objects with redacted evidence.

Exit-code contract (Bandit 1.x)
--------------------------------
- **0** — scan completed, no findings.
- **1** — scan completed, one or more findings present.
- **2** — Bandit execution error (bad arguments, unreadable files, etc.).

Both exit codes 0 and 1 are treated as *successful* scans; only exit code 2
(or an ``OSError`` from the OS failing to launch the process) is an error.

Severity mapping
----------------
AEGIS maps ``(issue_severity, issue_confidence)`` from Bandit to
:class:`~aegis.models.Severity` as follows:

    HIGH   / HIGH       → CRITICAL
    HIGH   / *          → HIGH
    MEDIUM / HIGH       → HIGH
    MEDIUM / *          → MEDIUM
    LOW    / HIGH       → MEDIUM
    LOW    / *          → LOW
    *      / *          → INFO   (fallback)

Design notes
------------
- The subprocess is invoked with the current Python interpreter
  (``sys.executable -m bandit``) to guarantee the same Bandit version that
  was installed into the project's virtual environment is used.
- ``shell=False`` is always used; the argument list is constructed from
  validated ``Path`` objects — never from user-supplied strings.
- The ``code`` field in Bandit's JSON output may contain raw source-code
  snippets (including hardcoded secrets).  It is run through the redactor
  before being placed in ``Finding.redacted``.
- ``Finding.evidence`` is populated with the raw ``code`` value (internal
  only); the orchestrator is responsible for clearing it before export.
- Relative file paths are computed from the resolved project root to prevent
  leaking absolute filesystem paths in reports.
- No network requests are made.  No files are modified.

Known limitations
-----------------
- Bandit only analyses Python (``.py``) files; other file types are skipped.
- Bandit's ``UNDEFINED`` severity/confidence levels are treated as ``LOW``/
  ``LOW`` respectively.
- The ``code`` snippet spans several lines and may not redact perfectly if a
  secret spans a quote boundary.
- Findings from within the project's ``__pycache__``, ``venv``, ``.venv``
  and other generated directories are filtered out post-parse.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from aegis.models import Finding, Severity
from aegis.redactor import redact
from aegis.secret_scanner import EXCLUDED_DIRS

# Default timeout for the Bandit subprocess (seconds).
BANDIT_TIMEOUT: int = 120

# ---------------------------------------------------------------------------
# Severity / confidence → AEGIS severity mapping
# ---------------------------------------------------------------------------

_SEV_CONF_MAP: dict[tuple[str, str], Severity] = {
    ("HIGH",   "HIGH"):   Severity.CRITICAL,
    ("HIGH",   "MEDIUM"): Severity.HIGH,
    ("HIGH",   "LOW"):    Severity.HIGH,
    ("MEDIUM", "HIGH"):   Severity.HIGH,
    ("MEDIUM", "MEDIUM"): Severity.MEDIUM,
    ("MEDIUM", "LOW"):    Severity.MEDIUM,
    ("LOW",    "HIGH"):   Severity.MEDIUM,
    ("LOW",    "MEDIUM"): Severity.LOW,
    ("LOW",    "LOW"):    Severity.LOW,
}


def _map_severity(issue_severity: str, issue_confidence: str) -> Severity:
    """Map Bandit ``(issue_severity, issue_confidence)`` to :class:`Severity`."""
    sev = issue_severity.upper()
    conf = issue_confidence.upper()
    return _SEV_CONF_MAP.get((sev, conf), Severity.INFO)


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _normalise_bandit_path(raw: str) -> str:
    """Strip leading ``./`` or ``.\\`` from a Bandit-reported filename."""
    # Bandit on Windows emits paths like ".\\src\\file.py"; on POSIX "./src/file.py".
    p = raw.replace("\\", "/")
    if p.startswith("./"):
        p = p[2:]
    return p


def _is_excluded(rel_path: str) -> bool:
    """Return True if any path component is in the exclusion set."""
    parts = Path(rel_path).parts
    return any(part in EXCLUDED_DIRS or part.endswith(".egg-info") for part in parts)


# ---------------------------------------------------------------------------
# Remediation text by Bandit test ID
# ---------------------------------------------------------------------------

_REMEDIATION: dict[str, str] = {
    "B101": "Remove assert statements from production code; use proper error handling.",
    "B102": "Avoid exec(); use safer alternatives.",
    "B103": "Set file permissions explicitly; avoid overly permissive modes.",
    "B104": "Binding to all interfaces (0.0.0.0) exposes the service externally. Bind to a specific interface.",
    "B105": "Replace hardcoded passwords with environment variables or a secrets manager.",
    "B106": "Replace hardcoded passwords in function calls with environment variables.",
    "B107": "Replace hardcoded passwords in function arguments with environment variables.",
    "B108": "Use a secure, non-world-writable temporary directory.",
    "B110": "Avoid bare except/pass; handle exceptions explicitly.",
    "B112": "Avoid bare continue in except blocks; handle exceptions explicitly.",
    "B201": "Do not run Flask in debug mode in production.",
    "B301": "Avoid pickle; use safer serialisation formats such as JSON.",
    "B302": "Avoid marshal; use safer serialisation formats.",
    "B303": "Use modern hashing algorithms; MD5/SHA1 are not collision-resistant.",
    "B304": "Use modern ciphers; DES/Blowfish are considered weak.",
    "B305": "Use modern ciphers; RC4 is broken.",
    "B306": "mktemp() is insecure; use tempfile.mkstemp() instead.",
    "B307": "Replace eval() with ast.literal_eval() or a safer alternative.",
    "B308": "mark_safe() can introduce XSS; validate and escape content explicitly.",
    "B310": "Validate URLs before passing to urllib; reject unexpected schemes.",
    "B311": "random is not cryptographically secure; use secrets module instead.",
    "B312": "Use TLS-secured alternatives to telnetlib.",
    "B313": "Use defusedxml or lxml with resolve_entities=False to prevent XXE.",
    "B314": "Use defusedxml or lxml with resolve_entities=False to prevent XXE.",
    "B315": "Use defusedxml or lxml with resolve_entities=False to prevent XXE.",
    "B316": "Use defusedxml or lxml with resolve_entities=False to prevent XXE.",
    "B317": "Use defusedxml or lxml with resolve_entities=False to prevent XXE.",
    "B318": "Use defusedxml or lxml with resolve_entities=False to prevent XXE.",
    "B319": "Use defusedxml or lxml with resolve_entities=False to prevent XXE.",
    "B320": "Use defusedxml or lxml with resolve_entities=False to prevent XXE.",
    "B321": "Use SFTP or SCP instead of FTP; FTP transmits credentials in plain text.",
    "B322": "input() in Python 2 is unsafe; this is Python 3, but verify intent.",
    "B323": "Use ssl.match_hostname() for proper certificate validation.",
    "B324": "Use SHA-256 or stronger hashing algorithms.",
    "B325": "mktemp() is insecure; use tempfile.mkstemp() instead.",
    "B401": "Avoid importing telnetlib; use TLS-secured alternatives.",
    "B402": "Avoid importing ftplib; transmits credentials in plain text.",
    "B403": "Review subprocess usage carefully; prefer argument lists over shell strings.",
    "B404": "Review all subprocess usage for shell-injection risks.",
    "B405": "Use defusedxml to prevent XML attacks.",
    "B406": "Use defusedxml to prevent XML attacks.",
    "B407": "Use defusedxml to prevent XML attacks.",
    "B408": "Use defusedxml to prevent XML attacks.",
    "B409": "Use defusedxml to prevent XML attacks.",
    "B410": "Use defusedxml to prevent XML attacks.",
    "B411": "Avoid xmlrpclib in untrusted environments; it has known security issues.",
    "B412": "httpoxy is a vulnerability; avoid CGI_HTTP_PROXY environment variable usage.",
    "B413": "pycrypto is unmaintained; use cryptography or pynacl instead.",
    "B501": "Enable SSL/TLS certificate verification; never set verify=False.",
    "B502": "Remove ssl_version from ssl.wrap_socket(); use modern TLS.",
    "B503": "Remove ssl_version from ssl.wrap_socket(); use modern TLS.",
    "B504": "Remove ssl_version from ssl.wrap_socket(); use modern TLS.",
    "B505": "Use RSA keys of at least 2048 bits; EC keys of at least 224 bits.",
    "B506": "Use safe_load() instead of load() to parse YAML.",
    "B507": "Enable host key checking in Paramiko connections.",
    "B601": "Do not use shell=True with paramiko; use argument lists.",
    "B602": "Do not use shell=True with subprocess; use argument lists instead.",
    "B603": "Validate all arguments passed to subprocess; prefer argument lists.",
    "B604": "Avoid shell=True in function calls; use argument lists.",
    "B605": "os.system() uses a shell; use subprocess with shell=False instead.",
    "B606": "os.exec*() without shell is safer but still risky; validate inputs.",
    "B607": "os.exec*() partial path is risky; use an absolute path.",
    "B608": "Possible SQL injection; use parameterised queries instead.",
    "B609": "Wildcard injection in Unix shell calls; avoid shell=True.",
    "B610": "Use of django.db.models.expressions.RawSQL() risks SQL injection.",
    "B611": "Use of queryset.raw() risks SQL injection; use ORM methods instead.",
    "B701": "jinja2 autoescape is disabled; enable it to prevent XSS.",
    "B702": "Use autoescape in Mako templates to prevent XSS.",
    "B703": "Use Django's built-in auto-escaping to prevent XSS.",
}

_DEFAULT_REMEDIATION = (
    "Review the flagged code and consult the Bandit documentation at "
    "https://bandit.readthedocs.io/ for remediation guidance."
)


def _remediation_for(test_id: str) -> str:
    return _REMEDIATION.get(test_id, _DEFAULT_REMEDIATION)


# ---------------------------------------------------------------------------
# Result conversion
# ---------------------------------------------------------------------------

def _result_to_finding(result: dict[str, Any], root: Path) -> Finding | None:
    """Convert one Bandit result dict to a :class:`Finding`, or ``None`` to skip."""
    raw_filename = result.get("filename", "")
    normalised = _normalise_bandit_path(raw_filename)

    # If Bandit reported an absolute path (happens when we pass an absolute root),
    # make it relative to the project root.
    norm_path = Path(normalised)
    if norm_path.is_absolute():
        try:
            norm_path = norm_path.relative_to(root)
        except ValueError:
            return None  # escapes root — skip
        normalised = norm_path.as_posix()

    rel_path = normalised

    # Verify the resolved path stays inside the project root.
    candidate = (root / rel_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None  # path escapes root — skip

    # Filter excluded directories.
    if _is_excluded(rel_path):
        return None

    test_id: str = result.get("test_id", "UNKNOWN")
    test_name: str = result.get("test_name", "unknown")
    issue_severity: str = result.get("issue_severity", "LOW")
    issue_confidence: str = result.get("issue_confidence", "LOW")
    issue_text: str = result.get("issue_text", "")
    line_number: int | None = result.get("line_number")
    raw_code: str = result.get("code", "").rstrip()

    severity = _map_severity(issue_severity, issue_confidence)

    # Redact both the code snippet and issue_text — both may contain secret values.
    # Bandit's issue_text includes the matched value in messages like
    # "Possible hardcoded password: '<value>'".
    redacted_code = redact(raw_code)
    redacted_issue_text = redact(issue_text)

    rule_id = f"B-{test_id}"
    finding_id = f"{rule_id}:{rel_path}:{line_number}"

    return Finding(
        id=finding_id,
        severity=severity,
        file=rel_path,
        line=line_number,
        rule_id=rule_id,
        title=f"{test_id}: {test_name.replace('_', ' ').title()}",
        description=redacted_issue_text,   # issue_text may contain secret values
        evidence=raw_code,                 # raw — orchestrator clears this before export
        redacted=redacted_code,
        remediation=_remediation_for(test_id),
    )


# ---------------------------------------------------------------------------
# Public errors
# ---------------------------------------------------------------------------

class BanditError(Exception):
    """Raised when Bandit fails to run or returns an unexpected exit code."""


class BanditNotFoundError(BanditError):
    """Raised when the Bandit executable cannot be found."""


class BanditTimeoutError(BanditError):
    """Raised when Bandit exceeds the configured timeout."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan(
    project_path: Path,
    *,
    timeout: int = BANDIT_TIMEOUT,
) -> list[Finding]:
    """Run Bandit against *project_path* and return a list of findings.

    Parameters
    ----------
    project_path:
        Path to the directory to scan.  Resolved internally before use.
    timeout:
        Maximum seconds to allow Bandit to run.  Defaults to
        :data:`BANDIT_TIMEOUT`.  Pass a smaller value in tests.

    Returns
    -------
    list[Finding]
        Findings sorted by (file, line).  Each finding has ``evidence``
        populated with the raw Bandit code snippet and ``redacted``
        populated with the redactor output.

    Raises
    ------
    ValueError
        If *project_path* does not exist or is not a directory.
    BanditNotFoundError
        If the Bandit module cannot be found / executed.
    BanditTimeoutError
        If Bandit does not complete within *timeout* seconds.
    BanditError
        If Bandit exits with code 2 (execution error) or another
        unexpected non-zero code.
    """
    root = project_path.resolve()
    if not root.exists():
        raise ValueError(f"Project path does not exist: {project_path}")
    if not root.is_dir():
        raise ValueError(f"Project path is not a directory: {project_path}")

    cmd = [
        sys.executable,
        "-m", "bandit",
        "--recursive",
        "--format", "json",
        "--quiet",
        str(root),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise BanditNotFoundError(
            "Could not locate the Python interpreter or Bandit module. "
            "Ensure Bandit is installed in the active virtual environment."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise BanditTimeoutError(
            f"Bandit did not complete within {timeout} seconds."
        ) from exc

    # Exit code 2 signals a Bandit-level execution error.
    # Exit codes 0 and 1 both indicate a successful scan.
    if result.returncode not in (0, 1):
        raise BanditError(
            f"Bandit exited with unexpected code {result.returncode}. "
            "Check that the target directory is readable and the Bandit "
            "installation is intact."
        )

    # Parse JSON output defensively.
    stdout = result.stdout.strip()
    if not stdout:
        # Bandit produced no JSON output — treat as no findings.
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise BanditError(
            f"Bandit returned malformed JSON output: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise BanditError("Bandit JSON output was not a dict at the top level.")

    raw_results = data.get("results", [])
    if not isinstance(raw_results, list):
        raise BanditError("Bandit JSON 'results' field is not a list.")

    findings: list[Finding] = []
    for item in raw_results:
        if not isinstance(item, dict):
            continue
        finding = _result_to_finding(item, root)
        if finding is not None:
            findings.append(finding)

    findings.sort(key=lambda f: (f.file, f.line or 0))
    return findings
