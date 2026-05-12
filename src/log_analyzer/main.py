"""Command-line entry point for the AI Security Log Analyzer MVP.

This module connects the pipeline layers:

Loader -> Parser -> Detector -> Formatter

It should stay small and avoid complex business logic.
"""

import argparse
from datetime import datetime

from .detector import detect_failed_login_bursts, detect_suspicious_usernames
from .formatter import print_alerts, print_summary
from .loader import load_log_lines
from .models import RunStats
from .parser import parse_lines


def build_arg_parser() -> argparse.ArgumentParser:
    """Build and return the command-line argument parser."""
    parser = argparse.ArgumentParser(description="AI Security Log Analyzer - MVP v1")

    parser.add_argument("--file", required=True, help="Path to local log file")
    parser.add_argument("--threshold", type=int, default=5, help="Failed login threshold")
    parser.add_argument(
        "--window",
        type=int,
        default=10,
        help="Detection window size in minutes",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=datetime.now().year,
        help="Year for syslog timestamps",
    )

    return parser


def run(file_path: str, threshold: int, window_minutes: int, year: int) -> int:
    """Run the analyzer pipeline and return a process-style exit code.

    Returns:
        0 when analysis succeeds, or 1 when an error occurs.
    """
    try:
        # Each step calls one layer of the pipeline, keeping responsibilities
        # clear and easy for beginners to trace.
        lines = load_log_lines(file_path)
        events, skipped_lines = parse_lines(lines, year)
        alerts = detect_failed_login_bursts(events, threshold, window_minutes)
        alerts.extend(detect_suspicious_usernames(events))

        print_alerts(alerts)

        stats = RunStats(
            total_lines=len(lines),
            parsed_events=len(events),
            skipped_lines=skipped_lines,
            alerts_generated=len(alerts),
        )
        print_summary(stats)

        return 0
    except Exception as error:
        # MVP-friendly error handling: show a clear message and return a
        # non-zero exit code instead of hiding the failure.
        print(f"Error: {error}")
        return 1


def main() -> None:
    """Parse CLI arguments and run the analyzer."""
    parser = build_arg_parser()
    args = parser.parse_args()

    exit_code = run(
        file_path=args.file,
        threshold=args.threshold,
        window_minutes=args.window,
        year=args.year,
    )
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
