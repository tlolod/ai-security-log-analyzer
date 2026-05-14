"""Tests for converting raw authentication log lines into LogEvent objects."""

from datetime import datetime

from src.log_analyzer.parser import parse_auth_line, parse_lines


def test_parse_auth_line_failed_login_invalid_user() -> None:
    """Parser should extract key fields from an invalid-user SSH failure."""
    line = (
        "May 11 21:33:01 server sshd[1234]: Failed password for invalid user "
        "admin from 203.0.113.10 port 54231 ssh2"
    )

    event = parse_auth_line(line, year=2026)

    assert event is not None
    assert event.timestamp == datetime(2026, 5, 11, 21, 33, 1)
    assert event.source_ip == "203.0.113.10"
    assert event.username == "admin"
    assert event.event_type == "failed_login"
    assert event.raw_line == line


def test_parse_auth_line_failed_login_normal_user() -> None:
    """Parser should also handle normal SSH users such as root."""
    line = (
        "May 11 21:33:02 server sshd[1235]: Failed password for root "
        "from 198.51.100.77 port 54232 ssh2"
    )

    event = parse_auth_line(line, year=2026)

    assert event is not None
    assert event.timestamp == datetime(2026, 5, 11, 21, 33, 2)
    assert event.source_ip == "198.51.100.77"
    assert event.username == "root"
    assert event.event_type == "failed_login"
    assert event.raw_line == line


def test_parse_auth_line_successful_login() -> None:
    """Parser should extract key fields from an accepted SSH password login."""
    line = (
        "May 11 21:40:01 server sshd[1236]: Accepted password for alice "
        "from 203.0.113.10 port 54233 ssh2"
    )

    event = parse_auth_line(line, year=2026)

    assert event is not None
    assert event.timestamp == datetime(2026, 5, 11, 21, 40, 1)
    assert event.source_ip == "203.0.113.10"
    assert event.username == "alice"
    assert event.event_type == "successful_login"
    assert event.raw_line == line


def test_parse_auth_line_returns_none_for_unrelated_line() -> None:
    """Unrelated log lines should be skipped instead of becoming events."""
    line = "May 11 21:30:01 server CRON[1200]: session opened for user root"

    event = parse_auth_line(line, year=2026)

    assert event is None


def test_parse_lines_returns_events_and_skipped_count() -> None:
    """Mixed input should return parsed events and a clear skipped count."""
    lines = [
        (
            "May 11 21:33:01 server sshd[1234]: Failed password for invalid user "
            "admin from 203.0.113.10 port 54231 ssh2"
        ),
        "May 11 21:34:00 server systemd[1]: Started Daily apt download activities.",
        (
            "May 11 21:35:02 server sshd[1235]: Failed password for root "
            "from 198.51.100.77 port 54232 ssh2"
        ),
        (
            "May 11 21:40:01 server sshd[1236]: Accepted password for alice "
            "from 203.0.113.10 port 54233 ssh2"
        ),
        "May 11 21:36:00 server sudo: alice : COMMAND=/usr/bin/id",
    ]

    events, skipped_count = parse_lines(lines, year=2026)

    assert len(events) == 3
    assert skipped_count == 2
    assert events[0].source_ip == "203.0.113.10"
    assert events[1].source_ip == "198.51.100.77"
    assert events[2].event_type == "successful_login"
