"""Tests for formatting and exporting analyzer output."""

import json
from datetime import datetime
from pathlib import Path

import pytest

from src.log_analyzer.formatter import format_alert, write_alerts_to_json
from src.log_analyzer.models import Alert


def make_alert() -> Alert:
    """Create a deterministic alert for formatter tests."""
    return Alert(
        alert_type="brute_force_suspected",
        severity="medium",
        message="Detected 5 failed login attempts from 203.0.113.10 within 10 minutes.",
        source_ip="203.0.113.10",
        first_seen=datetime(2026, 5, 11, 21, 33, 1),
        last_seen=datetime(2026, 5, 11, 21, 37, 55),
        failed_count=5,
        evidence=["sample sanitized log line"],
    )


def test_format_alert_returns_json_serializable_dict() -> None:
    """format_alert should convert datetime values into ISO strings."""
    alert = make_alert()

    alert_data = format_alert(alert)

    assert alert_data["alert_type"] == "brute_force_suspected"
    assert alert_data["severity"] == "medium"
    assert alert_data["source_ip"] == "203.0.113.10"
    assert alert_data["first_seen"] == "2026-05-11T21:33:01"
    assert alert_data["last_seen"] == "2026-05-11T21:37:55"
    assert alert_data["failed_count"] == 5
    assert alert_data["evidence"] == ["sample sanitized log line"]


def test_write_alerts_to_json_writes_alert_payload(tmp_path: Path) -> None:
    """JSON export should write alerts and alert_count to a file."""
    output_path = tmp_path / "alerts.json"
    alert = make_alert()

    write_alerts_to_json([alert], str(output_path))

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["alert_count"] == 1
    assert len(payload["alerts"]) == 1
    assert payload["alerts"][0]["source_ip"] == "203.0.113.10"
    assert payload["alerts"][0]["first_seen"] == "2026-05-11T21:33:01"


def test_write_alerts_to_json_handles_no_alerts(tmp_path: Path) -> None:
    """No alerts should still produce a predictable JSON structure."""
    output_path = tmp_path / "alerts.json"

    write_alerts_to_json([], str(output_path))

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload == {"alerts": [], "alert_count": 0}


def test_write_alerts_to_json_rejects_directory_path(tmp_path: Path) -> None:
    """A directory cannot be used as a JSON output file."""
    with pytest.raises(ValueError):
        write_alerts_to_json([], str(tmp_path))


def test_write_alerts_to_json_rejects_missing_parent_directory(tmp_path: Path) -> None:
    """Missing parent directories should fail clearly instead of being created."""
    output_path = tmp_path / "missing" / "alerts.json"

    with pytest.raises(FileNotFoundError):
        write_alerts_to_json([], str(output_path))