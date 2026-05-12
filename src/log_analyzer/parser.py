"""Parsing utilities for authentication log lines.

The parser layer converts raw text into structured ``LogEvent`` objects.
It does not decide whether activity is suspicious; that belongs to the
detector layer.
"""

import re
from datetime import datetime

from .models import LogEvent


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
    r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse_auth_line(line: str, year: int) -> LogEvent | None:
    """Parse one authentication log line.

    Args:
        line: A raw log line from a local file.
        year: The year to use with syslog-style timestamps, which often omit it.

    Returns:
        A ``LogEvent`` for recognized failed-login lines, otherwise ``None``.
    """
    match = FAILED_LOGIN_PATTERN.search(line)
    if match is None:
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
        source_ip=match.group("source_ip"),
        username=match.group("username"),
        event_type="failed_login",
        raw_line=line,
    )


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
