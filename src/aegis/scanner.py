"""AEGIS scanner orchestrator — coordinates all scan engines.

This module is the single entry point for a complete AEGIS scan.  It:

1. Validates and resolves the project root.
2. Invokes :mod:`aegis.secret_scanner` (regex-based secret detection).
3. Invokes :mod:`aegis.bandit_runner` (Python AST analysis via Bandit).
4. Combines findings from both engines into a single, deduplicated list.
5. Clears the internal ``Finding.evidence`` field so no raw source-code
   snippets can leak into report output.
6. Returns a :class:`ScanResult` that explicitly distinguishes a successful
   scan with zero findings from a scan that could not complete.

Design notes
------------
- Both scanners are always attempted.  A failure in one does not prevent the
  other from running.  The caller receives the successful results alongside an
  explicit error record, so a partial scan is never silently treated as clean.
- Deduplication is based on ``Finding.id`` equality (rule_id + file + line).
  Two findings from different rules at the same location are kept because they
  represent genuinely different issues.
- Findings are sorted CRITICAL-first, with (file, line) as tie-breakers.
- No files are modified.  No network requests are made.
- The module does not implement any detection logic; it delegates entirely to
  the individual scanner modules.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path

import aegis.bandit_runner as _bandit
import aegis.secret_scanner as _secrets
from aegis.models import Finding, Severity
from aegis.redactor import redact


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class ScanStatus(enum.Enum):
    """Overall status of a completed :func:`run_scan` call."""

    SUCCESS = "SUCCESS"
    """Both scanners ran to completion (even if zero findings were produced)."""

    PARTIAL = "PARTIAL"
    """At least one scanner failed; results from the other scanner are included."""

    FAILED = "FAILED"
    """All scanners failed; no findings could be collected."""


@dataclass
class ScannerError:
    """Records a failure from one scan engine without exposing raw source code."""

    scanner: str
    """Human-readable scanner name (e.g. ``"secret_scanner"``)."""

    error_type: str
    """The exception class name (e.g. ``"BanditError"``)."""

    message: str
    """Safe, sanitised error message.  Must not include raw source code or secrets."""

    def __str__(self) -> str:
        return f"{self.scanner}: [{self.error_type}] {self.message}"


@dataclass
class ScanResult:
    """The complete result of a :func:`run_scan` call.

    Attributes
    ----------
    project_path:
        Resolved absolute path of the scanned project root.
    findings:
        All findings from successful scanner runs, sorted CRITICAL-first.
        ``Finding.evidence`` is always empty — cleared before this object
        is returned.
    status:
        Whether the scan completed fully, partially, or not at all.
    errors:
        One :class:`ScannerError` per scanner that failed.  Empty on full
        success.
    """

    project_path: Path
    findings: list[Finding] = field(default_factory=list)
    status: ScanStatus = ScanStatus.SUCCESS
    errors: list[ScannerError] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def succeeded(self) -> bool:
        """True if no scanner errors occurred."""
        return self.status == ScanStatus.SUCCESS


# ---------------------------------------------------------------------------
# Severity sort key (CRITICAL = 0, INFO = 4)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _sort_key(f: Finding) -> tuple[int, str, int]:
    return (_SEVERITY_ORDER.get(f.severity, 99), f.file, f.line or 0)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _clear_raw_evidence(findings: list[Finding]) -> None:
    """Erase the internal raw evidence field on every finding in-place.

    This ensures no unredacted source-code snippet can travel beyond this
    module into report output or console display.
    """
    for f in findings:
        f.evidence = ""


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings by ``Finding.id``.

    Two findings are considered identical only when their ``id`` values are
    equal (same rule_id + relative file + line).  Findings from different
    rules at the same location are kept.
    """
    seen: set[str] = set()
    result: list[Finding] = []
    for f in findings:
        if f.id not in seen:
            seen.add(f.id)
            result.append(f)
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_scan(
    project_path: Path,
    *,
    bandit_timeout: int = _bandit.BANDIT_TIMEOUT,
) -> ScanResult:
    """Scan *project_path* with all available engines and return a :class:`ScanResult`.

    Both the regex secret scanner and the Bandit AST scanner are always
    attempted.  A failure in one does not prevent the other from running.

    The returned :class:`ScanResult` distinguishes:

    - :attr:`ScanStatus.SUCCESS` — both scanners completed successfully.
    - :attr:`ScanStatus.PARTIAL` — one scanner failed; the other's results
      are included.
    - :attr:`ScanStatus.FAILED` — all scanners failed; no findings returned.

    ``Finding.evidence`` is always empty in the returned findings — cleared
    before this function returns so that raw source-code snippets cannot
    reach report or console output.

    Parameters
    ----------
    project_path:
        Path to the directory to scan.  Must exist and be a directory.
    bandit_timeout:
        Maximum seconds allowed for the Bandit subprocess.

    Returns
    -------
    ScanResult

    Raises
    ------
    ValueError
        If *project_path* does not exist or is not a directory.
    """
    # Validate and resolve once; both child scanners re-resolve internally,
    # but we want to surface a clear error before attempting either.
    root = project_path.resolve()
    if not root.exists():
        raise ValueError(f"Project path does not exist: {project_path}")
    if not root.is_dir():
        raise ValueError(f"Project path is not a directory: {project_path}")

    all_findings: list[Finding] = []
    errors: list[ScannerError] = []
    successful_scanners = 0
    total_scanners = 2

    # ------------------------------------------------------------------ #
    # 1. Regex secret scanner
    # ------------------------------------------------------------------ #
    try:
        secret_findings = _secrets.scan(root)
        all_findings.extend(secret_findings)
        successful_scanners += 1
    except ValueError:
        # Re-raise path validation errors — they indicate programmer error,
        # not a transient scanner failure.
        raise
    except Exception as exc:  # noqa: BLE001
        errors.append(ScannerError(
            scanner="secret_scanner",
            error_type=type(exc).__name__,
            message=str(exc),
        ))

    # ------------------------------------------------------------------ #
    # 2. Bandit runner
    # ------------------------------------------------------------------ #
    try:
        bandit_findings = _bandit.scan(root, timeout=bandit_timeout)
        all_findings.extend(bandit_findings)
        successful_scanners += 1
    except ValueError:
        raise
    except Exception as exc:  # noqa: BLE001
        errors.append(ScannerError(
            scanner="bandit_runner",
            error_type=type(exc).__name__,
            message=str(exc),
        ))

    # ------------------------------------------------------------------ #
    # 3. Deduplicate, sort, clear raw evidence
    # ------------------------------------------------------------------ #
    deduplicated = _deduplicate(all_findings)
    deduplicated.sort(key=_sort_key)
    _clear_raw_evidence(deduplicated)

    # ------------------------------------------------------------------ #
    # 4. Determine status
    # ------------------------------------------------------------------ #
    if successful_scanners == total_scanners:
        status = ScanStatus.SUCCESS
    elif successful_scanners > 0:
        status = ScanStatus.PARTIAL
    else:
        status = ScanStatus.FAILED

    return ScanResult(
        project_path=root,
        findings=deduplicated,
        status=status,
        errors=errors,
    )
