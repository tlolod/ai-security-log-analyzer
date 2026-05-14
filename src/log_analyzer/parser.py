"""Parsing utilities for authentication log lines.

The parser layer converts raw text into structured ``LogEvent`` objects.
It does not decide whether activity is suspicious; that belongs to the
detector layer.
"""

import ipaddress
import re
from datetime import datetime

from .models import LogEvent


SOURCE_IP_PATTERN = r"(?P<source_ip>\S+)"


# Common Linux SSH failed-login examples include lines like:
#
# May 11 21:33:01 server sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port 54231 ssh2
# May 11 21:33:02 server sshd[1235]: Failed password for root from 203.0.113.10 port 54232 ssh2
#
# This regex intentionally focuses on the fields MVP v1 needs: date/time,
# username, and source IP address.
FAILED_LOGIN_PATTERN = re.compile(
    r"(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r".*Failed password for "
    r"(?:invalid user )?"
    r"(?P<username>\S+) "
    r"from "
    + SOURCE_IP_PATTERN
)

# Successful SSH logins often look like:
#
# May 11 21:40:01 server sshd[1236]: Accepted password for alice from 203.0.113.10 port 54233 ssh2
#
# This pattern intentionally supports the simple password-based success format
# needed by the current detection rules.
ACCEPTED_LOGIN_PATTERN = re.compile(
    r"(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r".*Accepted password for "
    r"(?P<username>\S+) "
    r"from "
    + SOURCE_IP_PATTERN
)


def parse_auth_line(line: str, year: int) -> LogEvent | None:
    """Parse one authentication log line.

    Args:
        line: A raw log line from a local file.
        year: The year to use with syslog-style timestamps, which often omit it.

    Returns:
        A ``LogEvent`` for recognized failed-login lines, otherwise ``None``.
    """
    failed_match = FAILED_LOGIN_PATTERN.search(line)
    if failed_match is not None:
        return _build_log_event(failed_match, year, "failed_login", line)

    accepted_match = ACCEPTED_LOGIN_PATTERN.search(line)
    if accepted_match is not None:
        return _build_log_event(accepted_match, year, "successful_login", line)

    return None


def _build_log_event(match: re.Match[str], year: int, event_type: str, line: str) -> LogEvent | None:
    """Build a LogEvent from a regex match with syslog timestamp fields."""
    source_ip = _normalize_ip_address(match.group("source_ip"))
    if source_ip is None:
        return None

    timestamp_text = (
        f"{match.group('month')} "
        f"{match.group('day')} "
        f"{match.group('time')} "
        f"{year}"
    )
    timestamp = datetime.strptime(timestamp_text, "%b %d %H:%M:%S %Y")

    return LogEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        username=match.group("username"),
        event_type=event_type,
        raw_line=line,
    )


def _normalize_ip_address(ip_text: str) -> str | None:
    """Validate and normalize an IPv4 or IPv6 address from a log line."""
    try:
        return str(ipaddress.ip_address(ip_text))
    except ValueError:
        return None


def parse_lines(lines: list[str], year: int) -> tuple[list[LogEvent], int]:
    """Parse many log lines and count lines that were skipped.

    A skipped line is not necessarily an error. It may simply be unrelated to
    failed logins, or it may use a log format MVP v1 does not support yet.
    """
    events: list[LogEvent] = []
    skipped_lines = 0

    for line in lines:
        event = parse_auth_line(line, year)

        if event is None:
            skipped_lines += 1
            continue

        events.append(event)

    return events, skipped_lines
