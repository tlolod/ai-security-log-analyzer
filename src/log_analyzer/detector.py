"""Detection rules for parsed security log events.

The detector layer looks at structured ``LogEvent`` objects and creates
``Alert`` objects when suspicious behavior is found.
"""

from collections import defaultdict
from datetime import timedelta

from .models import Alert, LogEvent


TARGETED_USERNAMES = {
    "root",
    "admin",
    "administrator",
    "oracle",
    "postgres",
    "guest",
    "test",
}


def detect_failed_login_bursts(
    events: list[LogEvent],
    threshold: int,
    window_minutes: int,
) -> list[Alert]:
    """Detect repeated failed logins from the same source IP address.

    Args:
        events: Parsed log events from the parser layer.
        threshold: Number of failed logins needed to create an alert.
        window_minutes: Time window, in minutes, used for counting failures.

    Returns:
        A list of alerts for suspicious failed-login bursts.
    """
    failed_events_by_ip: defaultdict[str, list[LogEvent]] = defaultdict(list)

    # Only failed-login events are relevant to this MVP detection rule.
    for event in events:
        if event.event_type == "failed_login":
            failed_events_by_ip[event.source_ip].append(event)

    alerts: list[Alert] = []
    detection_window = timedelta(minutes=window_minutes)

    for source_ip, ip_events in failed_events_by_ip.items():
        # Sorting makes the time-window logic predictable and easy to follow.
        ip_events.sort(key=lambda event: event.timestamp)

        window_start_index = 0
        window_end_index = 0

        while window_end_index < len(ip_events):
            # Move the start forward until the current window fits within the
            # configured number of minutes.
            while (
                ip_events[window_end_index].timestamp
                - ip_events[window_start_index].timestamp
                > detection_window
            ):
                window_start_index += 1

            failed_count = window_end_index - window_start_index + 1

            if failed_count >= threshold:
                suspicious_window = ip_events[window_start_index : window_end_index + 1]

                alerts.append(
                    Alert(
                        alert_type="brute_force_suspected",
                        severity="medium",
                        message=(
                            f"Detected {failed_count} failed login attempts from "
                            f"{source_ip} within {window_minutes} minutes."
                        ),
                        source_ip=source_ip,
                        first_seen=suspicious_window[0].timestamp,
                        last_seen=suspicious_window[-1].timestamp,
                        failed_count=failed_count,
                        evidence=[event.raw_line for event in suspicious_window[:3]],
                    )
                )

                # Avoid duplicate alert spam by moving past this detected window.
                window_end_index += 1
                window_start_index = window_end_index
                continue

            window_end_index += 1

    return alerts


def detect_suspicious_usernames(events: list[LogEvent]) -> list[Alert]:
    """Detect failed logins targeting commonly attacked usernames.

    One alert is created for each unique source IP and targeted username pair.
    This keeps the output useful without creating repeated duplicate alerts.
    """
    alerts: list[Alert] = []
    alerted_pairs: set[tuple[str, str]] = set()

    for event in events:
        # This rule only applies to failed login attempts with a username.
        if event.event_type != "failed_login" or event.username is None:
            continue

        username = event.username.lower()
        alert_key = (event.source_ip, username)

        if username not in TARGETED_USERNAMES or alert_key in alerted_pairs:
            continue

        alerts.append(
            Alert(
                alert_type="suspicious_username_targeted",
                severity="low",
                message=(
                    "Failed login attempt targeted commonly attacked username "
                    f"'{username}' from {event.source_ip}."
                ),
                source_ip=event.source_ip,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                failed_count=1,
                evidence=[event.raw_line],
            )
        )
        alerted_pairs.add(alert_key)

    return alerts
