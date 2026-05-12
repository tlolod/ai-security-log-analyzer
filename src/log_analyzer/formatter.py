"""Console formatting helpers for analyzer output.

The formatter layer turns structured data into readable output for humans.
It does not load files, parse logs, or detect suspicious activity.
"""

import json

from .models import Alert, RunStats


def format_alert(alert: Alert) -> dict[str, object]:
    """Convert an alert into a JSON-serializable dictionary.

    ``datetime`` objects cannot be directly printed as JSON, so timestamp
    fields are converted to ISO 8601 strings with ``.isoformat()``.
    """
    return {
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "message": alert.message,
        "source_ip": alert.source_ip,
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
        "failed_count": alert.failed_count,
        "evidence": alert.evidence,
    }


def print_alerts(alerts: list[Alert]) -> None:
    """Print alerts as readable pretty JSON."""
    if not alerts:
        print("No suspicious activity detected.")
        return

    print("=== ALERTS ===")
    for alert in alerts:
        print(json.dumps(format_alert(alert), indent=2))


def print_summary(stats: RunStats) -> None:
    """Print a short summary of one analyzer run."""
    print("=== RUN SUMMARY ===")
    print(f"Total lines: {stats.total_lines}")
    print(f"Parsed events: {stats.parsed_events}")
    print(f"Skipped lines: {stats.skipped_lines}")
    print(f"Alerts generated: {stats.alerts_generated}")
