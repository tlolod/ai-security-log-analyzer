"""Tests for suspicious failed-login detection rules."""

from datetime import datetime, timedelta

from src.log_analyzer.detector import (
    detect_failed_login_bursts,
    detect_suspicious_usernames,
)
from src.log_analyzer.models import LogEvent


TARGETED_USERNAMES = ["root", "admin", "administrator", "oracle", "postgres", "guest", "test"]
NO_ALLOWED_IPS: list[str] = []
SEVERITY_POLICY = {
    "brute_force_suspected": "medium",
    "suspicious_username_targeted": "low",
}


def make_log_event(
    timestamp: datetime,
    source_ip: str,
    event_type: str = "failed_login",
    username: str | None = "admin",
) -> LogEvent:
    """Create a small deterministic LogEvent for detector tests."""
    return LogEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        username=username,
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

    alerts = detect_failed_login_bursts(
        events,
        threshold=5,
        window_minutes=10,
        allowed_ips=[],
        severity_policy=SEVERITY_POLICY,
    )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "brute_force_suspected"
    assert alert.rule_id == "AUTH-001"
    assert alert.rule_name == "SSH Brute Force Suspected"
    assert alert.rule_version == "1.0"
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

    alerts = detect_failed_login_bursts(
        events,
        threshold=5,
        window_minutes=10,
        allowed_ips=[],
        severity_policy=SEVERITY_POLICY,
    )

    assert alerts == []


def test_detect_failed_login_bursts_no_alert_outside_window() -> None:
    """Failures spread too far apart should not meet the time-window rule."""
    start_time = datetime(2026, 5, 11, 21, 0, 0)
    events = [
        make_log_event(start_time + timedelta(minutes=minute), "203.0.113.10")
        for minute in [0, 3, 6, 9, 20]
    ]

    alerts = detect_failed_login_bursts(
        events,
        threshold=5,
        window_minutes=10,
        allowed_ips=[],
        severity_policy=SEVERITY_POLICY,
    )

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

    alerts = detect_failed_login_bursts(
        events,
        threshold=5,
        window_minutes=10,
        allowed_ips=[],
        severity_policy=SEVERITY_POLICY,
    )

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
        allowed_ips=[],
        severity_policy=SEVERITY_POLICY,
    )

    assert len(alerts) == 1
    assert alerts[0].source_ip == "203.0.113.10"


def test_detect_suspicious_usernames_creates_alert_for_targeted_username() -> None:
    """A failed login to root should create a low-severity alert."""
    event = make_log_event(
        datetime(2026, 5, 11, 21, 33, 0),
        "203.0.113.10",
        username="root",
    )

    alerts = detect_suspicious_usernames([event], TARGETED_USERNAMES, NO_ALLOWED_IPS, SEVERITY_POLICY)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "suspicious_username_targeted"
    assert alert.rule_id == "AUTH-002"
    assert alert.rule_name == "Suspicious Username Targeted"
    assert alert.rule_version == "1.0"
    assert alert.severity == "low"
    assert alert.source_ip == "203.0.113.10"
    assert alert.first_seen == event.timestamp
    assert alert.last_seen == event.timestamp
    assert alert.failed_count == 1
    assert alert.evidence == [event.raw_line]


def test_detect_suspicious_usernames_no_alert_for_normal_username() -> None:
    """A normal username should not trigger the targeted-username rule."""
    event = make_log_event(
        datetime(2026, 5, 11, 21, 33, 0),
        "203.0.113.10",
        username="alice",
    )

    alerts = detect_suspicious_usernames([event], TARGETED_USERNAMES, NO_ALLOWED_IPS, SEVERITY_POLICY)

    assert alerts == []


def test_detect_suspicious_usernames_ignores_non_failed_login_events() -> None:
    """Targeted usernames should only alert for failed_login events."""
    event = make_log_event(
        datetime(2026, 5, 11, 21, 33, 0),
        "203.0.113.10",
        event_type="accepted_login",
        username="root",
    )

    alerts = detect_suspicious_usernames([event], TARGETED_USERNAMES, NO_ALLOWED_IPS, SEVERITY_POLICY)

    assert alerts == []


def test_detect_suspicious_usernames_is_case_insensitive() -> None:
    """Usernames should match even when log casing differs."""
    event = make_log_event(
        datetime(2026, 5, 11, 21, 33, 0),
        "203.0.113.10",
        username="Admin",
    )

    alerts = detect_suspicious_usernames([event], TARGETED_USERNAMES, NO_ALLOWED_IPS, SEVERITY_POLICY)

    assert len(alerts) == 1
    assert "admin" in alerts[0].message


def test_detect_suspicious_usernames_avoids_duplicate_ip_username_alerts() -> None:
    """Repeated attempts for the same IP and username should alert once."""
    start_time = datetime(2026, 5, 11, 21, 33, 0)
    events = [
        make_log_event(start_time + timedelta(minutes=minute), "203.0.113.10", username="admin")
        for minute in range(3)
    ]

    alerts = detect_suspicious_usernames(events, TARGETED_USERNAMES, NO_ALLOWED_IPS, SEVERITY_POLICY)

    assert len(alerts) == 1
    assert alerts[0].source_ip == "203.0.113.10"


def test_detect_suspicious_usernames_alerts_per_unique_ip_username_pair() -> None:
    """Different IP and username pairs should each receive their own alert."""
    timestamp = datetime(2026, 5, 11, 21, 33, 0)
    events = [
        make_log_event(timestamp, "203.0.113.10", username="admin"),
        make_log_event(timestamp + timedelta(minutes=1), "203.0.113.10", username="root"),
        make_log_event(timestamp + timedelta(minutes=2), "198.51.100.77", username="admin"),
    ]

    alerts = detect_suspicious_usernames(events, TARGETED_USERNAMES, NO_ALLOWED_IPS, SEVERITY_POLICY)

    assert len(alerts) == 3
    alert_pairs = {(alert.source_ip, alert.message) for alert in alerts}
    assert any(ip == "203.0.113.10" and "admin" in message for ip, message in alert_pairs)
    assert any(ip == "203.0.113.10" and "root" in message for ip, message in alert_pairs)
    assert any(ip == "198.51.100.77" and "admin" in message for ip, message in alert_pairs)


def test_detect_failed_login_bursts_ignores_allowed_ip() -> None:
    """Allowlisted IPs should not generate brute-force alerts."""
    start_time = datetime(2026, 5, 11, 21, 33, 0)
    events = [
        make_log_event(start_time + timedelta(minutes=minute), "203.0.113.10")
        for minute in range(5)
    ]

    alerts = detect_failed_login_bursts(
        events,
        threshold=5,
        window_minutes=10,
        allowed_ips=["203.0.113.10"],
        severity_policy=SEVERITY_POLICY,
    )

    assert alerts == []


def test_detect_suspicious_usernames_ignores_allowed_ip() -> None:
    """Allowlisted IPs should not generate suspicious-username alerts."""
    event = make_log_event(
        datetime(2026, 5, 11, 21, 33, 0),
        "203.0.113.10",
        username="root",
    )

    alerts = detect_suspicious_usernames(
        [event],
        TARGETED_USERNAMES,
        allowed_ips=["203.0.113.10"],
        severity_policy=SEVERITY_POLICY,
    )

    assert alerts == []


def test_allowed_ips_do_not_suppress_other_ips() -> None:
    """Only the exact allowlisted IP should be suppressed."""
    start_time = datetime(2026, 5, 11, 21, 33, 0)
    events = [
        make_log_event(start_time + timedelta(minutes=minute), "203.0.113.10")
        for minute in range(5)
    ]

    alerts = detect_failed_login_bursts(
        events,
        threshold=5,
        window_minutes=10,
        allowed_ips=["198.51.100.77"],
        severity_policy=SEVERITY_POLICY,
    )

    assert len(alerts) == 1
    assert alerts[0].source_ip == "203.0.113.10"


def test_detect_failed_login_bursts_uses_configured_severity() -> None:
    """Brute-force alerts should use severity from the config policy."""
    start_time = datetime(2026, 5, 11, 21, 33, 0)
    events = [
        make_log_event(start_time + timedelta(minutes=minute), "203.0.113.10")
        for minute in range(5)
    ]
    severity_policy = {
        "brute_force_suspected": "high",
        "suspicious_username_targeted": "low",
    }

    alerts = detect_failed_login_bursts(
        events,
        threshold=5,
        window_minutes=10,
        allowed_ips=[],
        severity_policy=severity_policy,
    )

    assert len(alerts) == 1
    assert alerts[0].severity == "high"


def test_detect_suspicious_usernames_uses_configured_severity() -> None:
    """Suspicious-username alerts should use severity from the config policy."""
    event = make_log_event(
        datetime(2026, 5, 11, 21, 33, 0),
        "203.0.113.10",
        username="root",
    )
    severity_policy = {
        "brute_force_suspected": "medium",
        "suspicious_username_targeted": "medium",
    }

    alerts = detect_suspicious_usernames(
        [event],
        TARGETED_USERNAMES,
        allowed_ips=[],
        severity_policy=severity_policy,
    )

    assert len(alerts) == 1
    assert alerts[0].severity == "medium"
