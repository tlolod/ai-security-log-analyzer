"""Tests for suspicious failed-login detection rules."""

from datetime import datetime, timedelta

from src.log_analyzer.detector import detect_failed_login_bursts
from src.log_analyzer.models import LogEvent


def make_log_event(
    timestamp: datetime,
    source_ip: str,
    event_type: str = "failed_login",
) -> LogEvent:
    """Create a small deterministic LogEvent for detector tests."""
    return LogEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        username="admin",
        event_type=event_type,
        raw_line=f"sample raw line from {source_ip} at {timestamp.isoformat()}",
    )


def test_detect_failed_login_bursts_creates_alert_when_threshold_met() -> None:
    """Five failures from one IP within the window should create an alert."""
    start_time = datetime(2026, 5, 11, 21, 33, 0)
    events = [
        make_log_event(start_time + timedelta(minutes=minute), "203.0.113.10")
        for minute in range(5)
    ]

    alerts = detect_failed_login_bursts(events, threshold=5, window_minutes=10)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "brute_force_suspected"
    assert alert.severity == "medium"
    assert alert.source_ip == "203.0.113.10"
    assert alert.first_seen == start_time
    assert alert.last_seen == start_time + timedelta(minutes=4)
    assert alert.failed_count == 5
    assert len(alert.evidence) == 3


def test_detect_failed_login_bursts_no_alert_below_threshold() -> None:
    """Four failures should not alert when the threshold is five."""
    start_time = datetime(2026, 5, 11, 21, 33, 0)
    events = [
        make_log_event(start_time + timedelta(minutes=minute), "203.0.113.10")
        for minute in range(4)
    ]

    alerts = detect_failed_login_bursts(events, threshold=5, window_minutes=10)

    assert alerts == []


def test_detect_failed_login_bursts_no_alert_outside_window() -> None:
    """Failures spread too far apart should not meet the time-window rule."""
    start_time = datetime(2026, 5, 11, 21, 0, 0)
    events = [
        make_log_event(start_time + timedelta(minutes=minute), "203.0.113.10")
        for minute in [0, 3, 6, 9, 20]
    ]

    alerts = detect_failed_login_bursts(events, threshold=5, window_minutes=10)

    assert alerts == []


def test_detect_failed_login_bursts_ignores_other_event_types() -> None:
    """Only failed_login events should count toward brute-force detection."""
    start_time = datetime(2026, 5, 11, 21, 33, 0)
    events = [
        make_log_event(
            start_time + timedelta(minutes=minute),
            "203.0.113.10",
            event_type="accepted_login",
        )
        for minute in range(5)
    ]

    alerts = detect_failed_login_bursts(events, threshold=5, window_minutes=10)

    assert alerts == []


def test_detect_failed_login_bursts_groups_by_source_ip() -> None:
    """Only the IP that reaches the threshold should generate an alert."""
    start_time = datetime(2026, 5, 11, 21, 33, 0)
    suspicious_events = [
        make_log_event(start_time + timedelta(minutes=minute), "203.0.113.10")
        for minute in range(5)
    ]
    normal_events = [
        make_log_event(start_time + timedelta(minutes=minute), "198.51.100.77")
        for minute in range(4)
    ]

    alerts = detect_failed_login_bursts(
        suspicious_events + normal_events,
        threshold=5,
        window_minutes=10,
    )

    assert len(alerts) == 1
    assert alerts[0].source_ip == "203.0.113.10"
