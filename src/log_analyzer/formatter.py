"""Console formatting helpers for analyzer output.

The formatter layer turns structured data into readable output for humans.
It does not load files, parse logs, or detect suspicious activity.
"""

import csv
import json
from collections import Counter
from pathlib import Path

from .models import Alert, MitreAttackMetadata, RunStats


CSV_ALERT_COLUMNS = [
    "alert_type",
    "rule_id",
    "rule_name",
    "rule_version",
    "severity",
    "mitre_tactic",
    "mitre_technique_id",
    "mitre_technique",
    "source_ip",
    "first_seen",
    "last_seen",
    "failed_count",
    "message",
    "evidence",
]


def format_mitre_attack(metadata: MitreAttackMetadata | None) -> dict[str, str] | None:
    """Convert MITRE ATT&CK metadata into a JSON-serializable dictionary."""
    if metadata is None:
        return None

    return {
        "tactic": metadata.tactic,
        "technique_id": metadata.technique_id,
        "technique": metadata.technique,
    }


def format_alert_for_csv(alert: Alert) -> dict[str, object]:
    """Convert an alert into a flat dictionary for CSV export."""
    mitre_attack = alert.mitre_attack

    return {
        "alert_type": alert.alert_type,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "rule_version": alert.rule_version,
        "severity": alert.severity,
        "mitre_tactic": mitre_attack.tactic if mitre_attack is not None else "",
        "mitre_technique_id": mitre_attack.technique_id if mitre_attack is not None else "",
        "mitre_technique": mitre_attack.technique if mitre_attack is not None else "",
        "source_ip": alert.source_ip,
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
        "failed_count": alert.failed_count,
        "message": alert.message,
        "evidence": " | ".join(alert.evidence),
    }


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
        "mitre_attack": format_mitre_attack(alert.mitre_attack),
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


def write_alerts_to_csv(alerts: list[Alert], output_path: str) -> None:
    """Write alerts to a CSV file.

    CSV export is useful for spreadsheet tools. Each alert becomes one row, and
    nested MITRE ATT&CK metadata is flattened into dedicated columns.
    """
    path = Path(output_path)

    if path.exists() and path.is_dir():
        raise ValueError(f"Output path is a directory: {output_path}")

    if path.parent != Path(".") and not path.parent.exists():
        raise FileNotFoundError(f"Output directory does not exist: {path.parent}")

    with path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_ALERT_COLUMNS)
        writer.writeheader()

        for alert in alerts:
            writer.writerow(format_alert_for_csv(alert))
