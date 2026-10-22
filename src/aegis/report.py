"""AEGIS JSON report writer.

Serialises a :class:`~aegis.scanner.ScanResult` to a structured JSON file.

JSON report schema (v1)
-----------------------
The top-level object contains:

.. code-block:: json

    {
        "schema_version": "1",
        "aegis_version":  "<package version string>",
        "scan_timestamp": "<ISO 8601 UTC datetime, e.g. 2024-01-15T12:34:56Z>",
        "scan_status":    "SUCCESS" | "PARTIAL" | "FAILED",
        "project_name":   "<last path component of the scanned directory>",
        "finding_count":  <int>,
        "severity_counts": {
            "CRITICAL": <int>,
            "HIGH":     <int>,
            "MEDIUM":   <int>,
            "LOW":      <int>,
            "INFO":     <int>
        },
        "findings": [
            {
                "id":          "<rule_id:relative_file:line>",
                "severity":    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
                "file":        "<relative path from project root>",
                "line":        <int | null>,
                "rule_id":     "<scanner rule identifier>",
                "title":       "<short description>",
                "description": "<detailed description>",
                "evidence":    "<redacted snippet — never the raw value>",
                "remediation": "<actionable fix guidance>"
            }
        ],
        "scanner_errors": [
            {
                "scanner":    "<scanner name>",
                "error_type": "<exception class name>",
                "message":    "<sanitised error message>"
            }
        ]
    }

Privacy notes
-------------
- ``project_name`` contains only the final directory component of the scanned
  path (e.g. ``"my-project"``), not the full absolute path.  Full paths are
  not included in reports to make them safer to share.
- ``findings[].evidence`` is always the *redacted* value from
  :attr:`~aegis.models.Finding.redacted`; raw source-code snippets are never
  written.  This is enforced by :meth:`~aegis.models.Finding.to_dict` which
  only exports ``redacted``.
- ``scanner_errors[].message`` comes from :class:`~aegis.scanner.ScannerError`
  which is designed not to contain raw source code.

Output safety
-------------
Writing a report to a path *inside* the scanned project is rejected to prevent
accidental overwriting of source files.  Reports must be written to a path
outside the project root.

The file is written atomically: content is first written to a ``.tmp`` sibling,
then renamed into place with :func:`os.replace` (best-effort atomic on all
platforms).  The ``.tmp`` file is removed on failure if it exists.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from aegis import __version__
from aegis.models import Severity
from aegis.scanner import ScanResult, ScanStatus


# ---------------------------------------------------------------------------
# Schema version — increment when the report format changes in a breaking way
# ---------------------------------------------------------------------------

SCHEMA_VERSION: str = "1"

# All severity levels in severity-descending order, for deterministic output.
_SEVERITY_LEVELS: list[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ReportError(Exception):
    """Raised when the report cannot be written."""


class UnsafeOutputPathError(ReportError):
    """Raised when the output path would write inside the scanned project."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _severity_counts(result: ScanResult) -> dict[str, int]:
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_LEVELS}
    for finding in result.findings:
        key = finding.severity.value
        counts[key] = counts.get(key, 0) + 1
    return counts


def _scanner_error_to_dict(err) -> dict[str, str]:  # ScannerError
    return {
        "scanner":    err.scanner,
        "error_type": err.error_type,
        "message":    err.message,
    }


def _build_report(
    result: ScanResult,
    timestamp: datetime,
) -> dict:
    """Build the report dict from a :class:`~aegis.scanner.ScanResult`.

    Parameters
    ----------
    result:
        The completed scan result.  ``Finding.evidence`` must already be
        cleared (as guaranteed by :func:`~aegis.scanner.run_scan`).
    timestamp:
        The UTC datetime to embed in the report.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "aegis_version":  __version__,
        "scan_timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scan_status":    result.status.value,
        # Only the final path component — not the full absolute path.
        "project_name":   result.project_path.name,
        "finding_count":  result.finding_count,
        "severity_counts": _severity_counts(result),
        # Each finding is serialised via Finding.to_dict(), which exports
        # the *redacted* value under the key "evidence" and excludes the raw
        # internal evidence field entirely.
        "findings": [f.to_dict() for f in result.findings],
        "scanner_errors": [_scanner_error_to_dict(e) for e in result.errors],
    }


def _validate_output_path(output_path: Path, project_root: Path) -> None:
    """Raise if *output_path* is unsafe.

    Rules
    -----
    1. The parent directory must not be a file.
    2. The output path must not resolve to a location inside *project_root*.
       Writing reports into the scanned project risks overwriting source files.
    """
    resolved_output = output_path.resolve()
    resolved_root   = project_root.resolve()

    # Rule 2: reject paths inside the scanned project.
    try:
        resolved_output.relative_to(resolved_root)
        # If relative_to succeeds, the output is inside the project.
        raise UnsafeOutputPathError(
            f"Output path '{output_path.name}' is inside the scanned project "
            f"directory. Write reports to a location outside the project to "
            f"prevent accidental overwriting of source files."
        )
    except ValueError:
        pass  # Output is outside the project root — safe.


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_report(
    result: ScanResult,
    output_path: Path,
) -> None:
    """Serialise *result* to a JSON file at *output_path*.

    The report is written atomically: content is first written to a ``.tmp``
    sibling of *output_path*, then renamed into place.  On failure the
    temporary file is removed.

    The parent directory of *output_path* is created if it does not exist.

    Parameters
    ----------
    result:
        The :class:`~aegis.scanner.ScanResult` to serialise.
    output_path:
        Destination file path.  Must be outside the scanned project root
        (``result.project_path``).  The ``.json`` extension is not enforced
        but is recommended.

    Raises
    ------
    UnsafeOutputPathError
        If *output_path* resolves to a location inside the scanned project.
    ReportError
        If the file cannot be written (permission denied, invalid path, etc.).
    """
    _validate_output_path(output_path, result.project_path)

    # Create the parent directory if needed.
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReportError(
            f"Could not create output directory '{output_path.parent}': {exc}"
        ) from exc

    timestamp = datetime.now(tz=timezone.utc)
    report = _build_report(result, timestamp)

    json_bytes = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")

    tmp_path = output_path.with_suffix(output_path.suffix + ".tmp")
    try:
        tmp_path.write_bytes(json_bytes)
        os.replace(tmp_path, output_path)  # atomic on POSIX; best-effort on Windows
    except OSError as exc:
        # Clean up the temporary file if it was created.
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise ReportError(
            f"Could not write report to '{output_path}': {exc}"
        ) from exc
