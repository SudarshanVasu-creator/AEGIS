"""AEGIS command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aegis import __version__
from aegis.report import ReportError, UnsafeOutputPathError, write_report
from aegis.scanner import ScanStatus, run_scan

# Exit codes — documented here as the single source of truth.
EXIT_OK = 0        # Scan completed; report written.  Findings may exist.
EXIT_BAD_ARGS = 1  # Invalid arguments, project path, or output destination.
EXIT_SCAN_FAIL = 2 # Scan failed completely; no findings could be collected.
EXIT_REPORT_FAIL = 3  # Scan succeeded but the report could not be written.

# Default output filename when --output is not supplied.
DEFAULT_OUTPUT = "aegis-report.json"

# Severity display order for the terminal summary.
_SEVERITY_DISPLAY = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description=(
            "AEGIS — Application Security & Inspection System.\n"
            "A privacy-first, local source-code security scanner.\n\n"
            "All scanning runs locally.  No source code or reports are sent anywhere."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"aegis {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # ------------------------------------------------------------------ #
    # scan subcommand
    # ------------------------------------------------------------------ #
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a project directory for security issues.",
        description=(
            "Scan a project directory with all available engines (regex secret\n"
            "detection and Bandit AST analysis) and write a structured JSON report.\n\n"
            "Example:\n"
            '  aegis scan --project "C:\\MyProject" --output report.json'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_parser.add_argument(
        "--project",
        required=True,
        metavar="PATH",
        help="Path to the project directory to scan.",
    )
    scan_parser.add_argument(
        "--output",
        required=False,
        default=DEFAULT_OUTPUT,
        metavar="FILE",
        help=(
            f"Path for the JSON report output file.  "
            f"Default: {DEFAULT_OUTPUT} (in the current directory).  "
            f"Must be outside the scanned project directory."
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# Console output helpers
# ---------------------------------------------------------------------------

def _print_summary(result, output_path: Path) -> None:
    """Print a concise, safe scan summary to stdout.

    Never prints raw evidence, credentials, or source-code snippets.
    Only counts, statuses, and safe metadata are displayed.
    """
    project_name = result.project_path.name
    status_label = result.status.value

    print()
    print(f"  Project : {project_name}")
    print(f"  Status  : {status_label}")
    print()

    if result.errors:
        for err in result.errors:
            print(f"  [WARNING] Scanner failure — {err.scanner}: {err.message}")
        print()

    # Severity breakdown — counts only, no evidence.
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_DISPLAY}
    for finding in result.findings:
        key = finding.severity.value
        counts[key] = counts.get(key, 0) + 1

    print(f"  Findings: {result.finding_count}")
    for sev in _SEVERITY_DISPLAY:
        n = counts[sev]
        if n > 0:
            print(f"    {sev:<10}: {n}")

    print()
    print(f"  Report  : {output_path}")
    print()


def _err(message: str) -> None:
    """Print a safe error message to stderr."""
    print(f"aegis: error: {message}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Scan command handler
# ---------------------------------------------------------------------------

def _run_scan_command(args: argparse.Namespace) -> int:
    """Execute the scan subcommand.  Returns an exit code."""
    project_path = Path(args.project)
    output_path = Path(args.output)

    # --- Validate project path -------------------------------------------
    if not project_path.exists():
        _err(f"Project path does not exist: {project_path}")
        return EXIT_BAD_ARGS
    if not project_path.is_dir():
        _err(f"Project path is not a directory: {project_path}")
        return EXIT_BAD_ARGS

    # --- Run scan -----------------------------------------------------------
    print(f"Scanning '{project_path.name}' …")
    try:
        result = run_scan(project_path)
    except ValueError as exc:
        _err(str(exc))
        return EXIT_BAD_ARGS
    except Exception as exc:  # noqa: BLE001 — unexpected errors from scanner stack
        _err(f"Unexpected error during scan: {type(exc).__name__}")
        return EXIT_SCAN_FAIL

    # --- Determine scan exit outcome before writing report -----------------
    # FAILED means all engines failed — no useful results.
    scan_failed = result.status == ScanStatus.FAILED

    # --- Write report -------------------------------------------------------
    try:
        write_report(result, output_path)
    except UnsafeOutputPathError as exc:
        _err(str(exc))
        return EXIT_BAD_ARGS
    except ReportError as exc:
        _err(f"Could not write report: {exc}")
        _print_summary(result, output_path)
        return EXIT_REPORT_FAIL
    except Exception as exc:  # noqa: BLE001
        _err(f"Unexpected error writing report: {type(exc).__name__}")
        return EXIT_REPORT_FAIL

    # --- Print summary ------------------------------------------------------
    _print_summary(result, output_path)

    # --- Return exit code ---------------------------------------------------
    if scan_failed:
        return EXIT_SCAN_FAIL
    return EXIT_OK


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(EXIT_OK)

    if args.command == "scan":
        code = _run_scan_command(args)
        sys.exit(code)
