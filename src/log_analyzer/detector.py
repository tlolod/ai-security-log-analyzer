"""Detection rules for parsed security log events.

The detector layer looks at structured ``LogEvent`` objects and creates
``Alert`` objects when suspicious behavior is found.
"""

from collections import defaultdict
from datetime import timedelta

from .models import Alert, LogEvent


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
