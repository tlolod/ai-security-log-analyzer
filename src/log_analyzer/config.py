"""Configuration helpers for the AI Security Log Analyzer.

Configuration is treated as untrusted input. This module loads JSON safely,
validates expected fields, and returns a small dataclass used by the CLI.
"""

import ipaddress
import json
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path


ALLOWED_CONFIG_KEYS = {
    "failed_login_threshold",
    "window_minutes",
    "targeted_usernames",
    "allowed_ips",
    "severity_policy",
}

ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}

KNOWN_ALERT_TYPES = {
    "brute_force_suspected",
    "suspicious_username_targeted",
}


@dataclass
class AnalyzerConfig:
    """Runtime settings for analyzer detection behavior."""

    failed_login_threshold: int
    window_minutes: int
    targeted_usernames: list[str]
    allowed_ips: list[str]
    severity_policy: dict[str, str]


def default_config() -> AnalyzerConfig:
    """Return fresh default settings for the analyzer.

    A new list is created each time so callers cannot accidentally mutate a
    shared module-level list.
    """
    return AnalyzerConfig(
        failed_login_threshold=5,
        window_minutes=10,
        targeted_usernames=[
            "root",
            "admin",
            "administrator",
            "oracle",
            "postgres",
            "guest",
            "test",
        ],
        allowed_ips=[],
        severity_policy=default_severity_policy(),
    )


def default_severity_policy() -> dict[str, str]:
    """Return fresh default severity labels for known alert types."""
    return {
        "brute_force_suspected": "medium",
        "suspicious_username_targeted": "low",
    }


def load_config(config_path: str | None) -> AnalyzerConfig:
    """Load analyzer configuration from JSON, or return defaults.

    Args:
        config_path: Optional path to a local JSON configuration file.

    Returns:
        Validated analyzer configuration.
    """
    if config_path is None:
        return default_config()

    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    if not path.is_file():
        raise ValueError(f"Config path is not a file: {config_path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except JSONDecodeError as error:
        raise ValueError(f"Config file is not valid JSON: {config_path}") from error

    if not isinstance(data, dict):
        raise ValueError("Config file must contain a JSON object.")

    return config_from_dict(data)


def config_from_dict(data: dict[str, object]) -> AnalyzerConfig:
    """Create an AnalyzerConfig from a dictionary with validation."""
    unknown_keys = set(data) - ALLOWED_CONFIG_KEYS
    if unknown_keys:
        unknown = ", ".join(sorted(unknown_keys))
        raise ValueError(f"Unknown config key: {unknown}")

    config = default_config()

    if "failed_login_threshold" in data:
        config.failed_login_threshold = _validate_positive_int(
            data["failed_login_threshold"],
            "failed_login_threshold",
        )

    if "window_minutes" in data:
        config.window_minutes = _validate_positive_int(
            data["window_minutes"],
            "window_minutes",
        )

    if "targeted_usernames" in data:
        config.targeted_usernames = _validate_usernames(data["targeted_usernames"])

    if "allowed_ips" in data:
        config.allowed_ips = _validate_ip_addresses(data["allowed_ips"])

    if "severity_policy" in data:
        config.severity_policy = _validate_severity_policy(data["severity_policy"])

    return config


def _validate_positive_int(value: object, field_name: str) -> int:
    """Validate that a config value is a positive integer."""
    if not isinstance(value, int) or value <= 0:
        raise ValueError(f"Config value '{field_name}' must be a positive integer.")

    return value


def _validate_usernames(value: object) -> list[str]:
    """Validate and normalize targeted usernames."""
    if not isinstance(value, list):
        raise ValueError("Config value 'targeted_usernames' must be a list of strings.")

    usernames: list[str] = []
    for username in value:
        if not isinstance(username, str):
            raise ValueError("Config value 'targeted_usernames' must be a list of strings.")
        usernames.append(username.lower())

    return usernames


def _validate_ip_addresses(value: object) -> list[str]:
    """Validate and normalize exact IP addresses used for alert suppression."""
    if not isinstance(value, list):
        raise ValueError("Config value 'allowed_ips' must be a list of IP address strings.")

    allowed_ips: list[str] = []
    for ip_text in value:
        if not isinstance(ip_text, str):
            raise ValueError("Config value 'allowed_ips' must be a list of IP address strings.")

        try:
            allowed_ips.append(str(ipaddress.ip_address(ip_text)))
        except ValueError as error:
            raise ValueError(f"Invalid IP address in allowed_ips: {ip_text}") from error

    return allowed_ips


def _validate_severity_policy(value: object) -> dict[str, str]:
    """Validate and merge severity policy overrides with defaults."""
    if not isinstance(value, dict):
        raise ValueError("Config value 'severity_policy' must be a JSON object.")

    severity_policy = default_severity_policy()

    for alert_type, severity in value.items():
        if alert_type not in KNOWN_ALERT_TYPES:
            raise ValueError(f"Unknown severity policy alert type: {alert_type}")

        if not isinstance(severity, str):
            raise ValueError("Severity policy values must be strings.")

        normalized_severity = severity.lower()
        if normalized_severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"Invalid severity value: {severity}")

        severity_policy[alert_type] = normalized_severity

    return severity_policy
