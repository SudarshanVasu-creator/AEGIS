"""AEGIS command-line interface."""

import argparse
import sys

from aegis import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description=(
            "AEGIS — Application Security & Inspection System.\n"
            "A privacy-first, local source-code security scanner."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"aegis {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # --- scan subcommand (implementation in a later sub-task) ---
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a project directory for security issues.",
    )
    scan_parser.add_argument(
        "--project",
        required=True,
        metavar="PATH",
        help="Path to the project directory to scan.",
    )
    scan_parser.add_argument(
        "--output",
        required=True,
        metavar="FILE",
        help="Path for the JSON report output file.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        # Scanner not yet implemented — placeholder until Sub-Task 8.
        print("AEGIS scan — not yet implemented.")
        sys.exit(1)
