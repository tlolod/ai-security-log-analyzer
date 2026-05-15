"""Detection rules for parsed security log events.

The detector layer looks at structured ``LogEvent`` objects and creates
``Alert`` objects when suspicious behavior is found.
"""

from collections import defaultdict
from datetime import timedelta

from .models import Alert, LogEvent, MitreAttackMetadata


BRUTE_FORCE_RULE_ID = "AUTH-001"
BRUTE_FORCE_RULE_NAME = "SSH Brute Force Suspected"
BRUTE_FORCE_RULE_VERSION = "1.0"

SUSPICIOUS_USERNAME_RULE_ID = "AUTH-002"
SUSPICIOUS_USERNAME_RULE_NAME = "Suspicious Username Targeted"
SUSPICIOUS_USERNAME_RULE_VERSION = "1.0"

SUCCESSFUL_AFTER_FAILURES_RULE_ID = "AUTH-003"
SUCCESSFUL_AFTER_FAILURES_RULE_NAME = "Successful SSH Login After Failures"
SUCCESSFUL_AFTER_FAILURES_RULE_VERSION = "1.0"

BRUTE_FORCE_MITRE_ATTACK = MitreAttackMetadata(
    tactic="Credential Access",
    technique_id="T1110",
    technique="Brute Force",
)


def detect_failed_login_bursts(
    events: list[LogEvent],
    threshold: int,
    window_minutes: int,
    allowed_ips: list[str],
    severity_policy: dict[str, str],
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
    allowed_ip_set = set(allowed_ips)

    # Only failed-login events are relevant to this MVP detection rule.
    for event in events:
        if event.event_type == "failed_login" and event.source_ip not in allowed_ip_set:
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
                        rule_id=BRUTE_FORCE_RULE_ID,
                        rule_name=BRUTE_FORCE_RULE_NAME,
                        rule_version=BRUTE_FORCE_RULE_VERSION,
                        severity=severity_policy["brute_force_suspected"],
                        mitre_attack=BRUTE_FORCE_MITRE_ATTACK,
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


def detect_successful_login_after_failures(
    events: list[LogEvent],
    threshold: int,
    window_minutes: int,
    allowed_ips: list[str],
    severity_policy: dict[str, str],
) -> list[Alert]:
    """Detect a successful SSH login after repeated failures from one IP.

    A success after many failures can indicate that an attacker guessed a valid
    password. This rule is intentionally source-IP based and creates at most one
    alert per IP address to avoid duplicate alert spam.
    """
    events_by_ip: defaultdict[str, list[LogEvent]] = defaultdict(list)
    allowed_ip_set = set(allowed_ips)

    for event in events:
        if event.source_ip in allowed_ip_set:
            continue

        if event.event_type in {"failed_login", "successful_login"}:
            events_by_ip[event.source_ip].append(event)

    alerts: list[Alert] = []
    alerted_ips: set[str] = set()
    detection_window = timedelta(minutes=window_minutes)

    for source_ip, ip_events in events_by_ip.items():
        if source_ip in alerted_ips:
            continue

        ip_events.sort(key=lambda event: event.timestamp)

        for success_event in ip_events:
            if success_event.event_type != "successful_login":
                continue

            failed_events = [
                event
                for event in ip_events
                if event.event_type == "failed_login"
                and event.timestamp < success_event.timestamp
                and success_event.timestamp - event.timestamp <= detection_window
            ]

            if len(failed_events) < threshold:
                continue

            username_text = success_event.username or "unknown"
            evidence = [event.raw_line for event in failed_events[:3]]
            evidence.append(success_event.raw_line)

            alerts.append(
                Alert(
                    alert_type="successful_login_after_failures",
                    rule_id=SUCCESSFUL_AFTER_FAILURES_RULE_ID,
                    rule_name=SUCCESSFUL_AFTER_FAILURES_RULE_NAME,
                    rule_version=SUCCESSFUL_AFTER_FAILURES_RULE_VERSION,
                    severity=severity_policy["successful_login_after_failures"],
                    mitre_attack=BRUTE_FORCE_MITRE_ATTACK,
                    message=(
                        f"Detected successful login for '{username_text}' from {source_ip} "
                        f"after {len(failed_events)} failed login attempts within "
                        f"{window_minutes} minutes."
                    ),
                    source_ip=source_ip,
                    first_seen=failed_events[0].timestamp,
                    last_seen=success_event.timestamp,
                    failed_count=len(failed_events),
                    evidence=evidence,
                )
            )
            alerted_ips.add(source_ip)
            break

    return alerts


def detect_suspicious_usernames(
    events: list[LogEvent],
    targeted_usernames: list[str],
    allowed_ips: list[str],
    severity_policy: dict[str, str],
) -> list[Alert]:
    """Detect failed logins targeting commonly attacked usernames.

    One alert is created for each unique source IP and targeted username pair.
    This keeps the output useful without creating repeated duplicate alerts.
    """
    alerts: list[Alert] = []
    alerted_pairs: set[tuple[str, str]] = set()
    targeted_username_set = {username.lower() for username in targeted_usernames}
    allowed_ip_set = set(allowed_ips)

    for event in events:
        # This rule only applies to failed login attempts with a username.
        if event.event_type != "failed_login" or event.username is None:
            continue

        if event.source_ip in allowed_ip_set:
            continue

        username = event.username.lower()
        alert_key = (event.source_ip, username)

        if username not in targeted_username_set or alert_key in alerted_pairs:
            continue

        alerts.append(
            Alert(
                alert_type="suspicious_username_targeted",
                rule_id=SUSPICIOUS_USERNAME_RULE_ID,
                rule_name=SUSPICIOUS_USERNAME_RULE_NAME,
                rule_version=SUSPICIOUS_USERNAME_RULE_VERSION,
                severity=severity_policy["suspicious_username_targeted"],
                mitre_attack=BRUTE_FORCE_MITRE_ATTACK,
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
