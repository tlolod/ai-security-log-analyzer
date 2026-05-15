"""Command-line entry point for the AI Security Log Analyzer MVP.

This module connects the pipeline layers:

Loader -> Parser -> Detector -> Formatter

It should stay small and avoid complex business logic.
"""

import argparse
from datetime import datetime

from .config import load_config
from .detector import (
    detect_failed_login_bursts,
    detect_successful_login_after_failures,
    detect_suspicious_usernames,
)
from .formatter import (
    build_alert_summary,
    print_alert_summary,
    print_alerts,
    print_summary,
    write_alerts_to_json,
)
from .loader import load_log_lines
from .models import RunStats
from .parser import parse_lines


def build_arg_parser() -> argparse.ArgumentParser:
    """Build and return the command-line argument parser."""
    parser = argparse.ArgumentParser(description="AI Security Log Analyzer - MVP v1")

    parser.add_argument("--file", required=True, help="Path to local log file")
    parser.add_argument("--threshold", type=int, default=None, help="Failed login threshold")
    parser.add_argument(
        "--window",
        type=int,
        default=None,
        help="Detection window size in minutes",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=datetime.now().year,
        help="Year to attach to syslog timestamps that do not include a year",
    )
    parser.add_argument("--config", help="Optional path to JSON configuration file")
    parser.add_argument("--output", help="Optional path to write alerts as JSON")

    return parser


def run(
    file_path: str,
    threshold: int | None,
    window_minutes: int | None,
    year: int,
    config_path: str | None = None,
    output_path: str | None = None,
) -> int:
    """Run the analyzer pipeline and return a process-style exit code.

    Returns:
        0 when analysis succeeds, or 1 when an error occurs.
    """
    try:
        # Each step calls one layer of the pipeline, keeping responsibilities
        # clear and easy for beginners to trace.
        config = load_config(config_path)

        # CLI values intentionally override config file values.
        if threshold is not None:
            config.failed_login_threshold = threshold
        if window_minutes is not None:
            config.window_minutes = window_minutes

        lines = load_log_lines(file_path)
        events, skipped_lines = parse_lines(lines, year)
        alerts = detect_failed_login_bursts(
            events,
            config.failed_login_threshold,
            config.window_minutes,
            config.allowed_ips,
            config.severity_policy,
        )
        alerts.extend(
            detect_successful_login_after_failures(
                events,
                config.failed_login_threshold,
                config.window_minutes,
                config.allowed_ips,
                config.severity_policy,
            )
        )
        alerts.extend(
            detect_suspicious_usernames(
                events,
                config.targeted_usernames,
                config.allowed_ips,
                config.severity_policy,
            )
        )

        print_alerts(alerts)
        alert_summary = build_alert_summary(alerts)
        print_alert_summary(alert_summary)

        if output_path is not None:
            write_alerts_to_json(alerts, output_path)

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
        config_path=args.config,
        output_path=args.output,
    )
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
