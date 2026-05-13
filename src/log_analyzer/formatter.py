"""Console formatting helpers for analyzer output.

The formatter layer turns structured data into readable output for humans.
It does not load files, parse logs, or detect suspicious activity.
"""

import json
from collections import Counter
from pathlib import Path

from .models import Alert, RunStats


def format_alert(alert: Alert) -> dict[str, object]:
    """Convert an alert into a JSON-serializable dictionary.

    ``datetime`` objects cannot be directly printed as JSON, so timestamp
    fields are converted to ISO 8601 strings with ``.isoformat()``.
    """
    return {
        "alert_type": alert.alert_type,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "rule_version": alert.rule_version,
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


def build_alert_summary(alerts: list[Alert]) -> dict[str, object]:
    """Build aggregate counts for a list of alerts."""
    by_type = Counter(alert.alert_type for alert in alerts)
    by_severity = Counter(alert.severity for alert in alerts)
    unique_source_ips = len({alert.source_ip for alert in alerts})

    return {
        "by_type": dict(by_type),
        "by_severity": dict(by_severity),
        "unique_source_ips": unique_source_ips,
    }


def print_alert_summary(summary: dict[str, object]) -> None:
    """Print a readable summary of alert counts."""
    print("=== ALERT SUMMARY ===")
    print()

    print("Alerts by type:")
    by_type = summary["by_type"]
    if isinstance(by_type, dict) and by_type:
        for alert_type, count in by_type.items():
            print(f"- {alert_type}: {count}")
    else:
        print("- none")

    print()
    print("Alerts by severity:")
    by_severity = summary["by_severity"]
    if isinstance(by_severity, dict) and by_severity:
        for severity, count in by_severity.items():
            print(f"- {severity}: {count}")
    else:
        print("- none")

    print()
    print("Unique source IPs:")
    print(f"- {summary['unique_source_ips']}")


def print_summary(stats: RunStats) -> None:
    """Print a short summary of one analyzer run."""
    print("=== RUN SUMMARY ===")
    print(f"Total lines: {stats.total_lines}")
    print(f"Parsed events: {stats.parsed_events}")
    print(f"Skipped lines: {stats.skipped_lines}")
    print(f"Alerts generated: {stats.alerts_generated}")


def write_alerts_to_json(alerts: list[Alert], output_path: str) -> None:
    """Write alerts to a JSON file.

    The formatter owns this because JSON export is another output format.
    The detector still only creates alerts; it does not write files.
    """
    path = Path(output_path)

    if path.exists() and path.is_dir():
        raise ValueError(f"Output path is a directory: {output_path}")

    if path.parent != Path(".") and not path.parent.exists():
        raise FileNotFoundError(f"Output directory does not exist: {path.parent}")

    payload = {
        "alerts": [format_alert(alert) for alert in alerts],
        "alert_count": len(alerts),
        "summary": build_alert_summary(alerts),
    }

    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
