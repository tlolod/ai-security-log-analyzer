"""Configuration helpers for the AI Security Log Analyzer.

Configuration is treated as untrusted input. This module loads JSON safely,
validates expected fields, and returns a small dataclass used by the CLI.
"""

import json
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path


ALLOWED_CONFIG_KEYS = {
    "failed_login_threshold",
    "window_minutes",
    "targeted_usernames",
}


@dataclass
class AnalyzerConfig:
    """Runtime settings for analyzer detection behavior."""

    failed_login_threshold: int
    window_minutes: int
    targeted_usernames: list[str]


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
    )


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
