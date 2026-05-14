"""Tests for JSON configuration loading and validation."""

from pathlib import Path

import pytest

from src.log_analyzer.config import default_config, load_config


def write_config_file(path: Path, content: str) -> Path:
    """Write a small config file for a test case."""
    path.write_text(content, encoding="utf-8")
    return path


def test_default_config_returns_expected_values() -> None:
    """Default settings should match the beginner-friendly MVP defaults."""
    config = default_config()

    assert config.failed_login_threshold == 5
    assert config.window_minutes == 10
    assert "root" in config.targeted_usernames
    assert "admin" in config.targeted_usernames
    assert config.allowed_ips == []
    assert config.severity_policy["brute_force_suspected"] == "medium"
    assert config.severity_policy["suspicious_username_targeted"] == "low"
    assert config.severity_policy["successful_login_after_failures"] == "high"


def test_load_config_none_returns_defaults() -> None:
    """A missing config path means the analyzer should use built-in defaults."""
    config = load_config(None)

    assert config.failed_login_threshold == 5
    assert config.window_minutes == 10
    assert config.allowed_ips == []
    assert config.severity_policy["brute_force_suspected"] == "medium"
    assert config.severity_policy["successful_login_after_failures"] == "high"


def test_load_config_reads_valid_json_file(tmp_path: Path) -> None:
    """A valid JSON config should override default values."""
    config_path = write_config_file(
        tmp_path / "config.json",
        """
        {
          "failed_login_threshold": 8,
          "window_minutes": 15,
          "targeted_usernames": ["Root", "Admin"],
          "allowed_ips": ["203.0.113.10"],
          "severity_policy": {
            "brute_force_suspected": "High"
          }
        }
        """,
    )

    config = load_config(str(config_path))

    assert config.failed_login_threshold == 8
    assert config.window_minutes == 15
    assert config.targeted_usernames == ["root", "admin"]
    assert config.allowed_ips == ["203.0.113.10"]
    assert config.severity_policy["brute_force_suspected"] == "high"
    assert config.severity_policy["suspicious_username_targeted"] == "low"
    assert config.severity_policy["successful_login_after_failures"] == "high"


def test_load_config_uses_defaults_for_missing_keys(tmp_path: Path) -> None:
    """Config files may provide only the values they want to change."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"failed_login_threshold": 7}',
    )

    config = load_config(str(config_path))

    assert config.failed_login_threshold == 7
    assert config.window_minutes == 10
    assert "root" in config.targeted_usernames
    assert config.allowed_ips == []
    assert config.severity_policy["suspicious_username_targeted"] == "low"


def test_load_config_rejects_invalid_json(tmp_path: Path) -> None:
    """Invalid JSON should fail with a clear ValueError."""
    config_path = write_config_file(tmp_path / "config.json", "{invalid json")

    with pytest.raises(ValueError):
        load_config(str(config_path))


def test_load_config_rejects_unknown_keys(tmp_path: Path) -> None:
    """Unknown keys are rejected to catch mistakes early."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"unknown_setting": true}',
    )

    with pytest.raises(ValueError):
        load_config(str(config_path))


def test_load_config_rejects_invalid_threshold(tmp_path: Path) -> None:
    """Threshold must be a positive integer."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"failed_login_threshold": 0}',
    )

    with pytest.raises(ValueError):
        load_config(str(config_path))


def test_load_config_rejects_invalid_window(tmp_path: Path) -> None:
    """Detection window must be a positive integer."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"window_minutes": -1}',
    )

    with pytest.raises(ValueError):
        load_config(str(config_path))


def test_load_config_rejects_invalid_usernames(tmp_path: Path) -> None:
    """Targeted usernames must be a list of strings."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"targeted_usernames": ["root", 123]}',
    )

    with pytest.raises(ValueError):
        load_config(str(config_path))


def test_load_config_rejects_allowed_ips_not_list(tmp_path: Path) -> None:
    """allowed_ips must be a list, not a single string."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"allowed_ips": "203.0.113.10"}',
    )

    with pytest.raises(ValueError):
        load_config(str(config_path))


def test_load_config_rejects_non_string_allowed_ip(tmp_path: Path) -> None:
    """Each allowed IP entry must be a string."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"allowed_ips": [123]}',
    )

    with pytest.raises(ValueError):
        load_config(str(config_path))


def test_load_config_rejects_invalid_allowed_ip(tmp_path: Path) -> None:
    """Invalid IP address strings should fail validation."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"allowed_ips": ["not-an-ip"]}',
    )

    with pytest.raises(ValueError):
        load_config(str(config_path))


def test_load_config_accepts_ipv6_allowed_ip(tmp_path: Path) -> None:
    """allowed_ips should support IPv6 address strings."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"allowed_ips": ["2001:db8::10"]}',
    )

    config = load_config(str(config_path))

    assert config.allowed_ips == ["2001:db8::10"]


def test_load_config_normalizes_ipv6_allowed_ip(tmp_path: Path) -> None:
    """IPv6 allowlist entries should be normalized for string matching."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"allowed_ips": ["2001:0db8:0000:0000:0000:0000:0000:0010"]}',
    )

    config = load_config(str(config_path))

    assert config.allowed_ips == ["2001:db8::10"]


def test_load_config_reads_partial_severity_policy_override(tmp_path: Path) -> None:
    """Severity policy can override one alert type while preserving defaults."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"severity_policy": {"brute_force_suspected": "high"}}',
    )

    config = load_config(str(config_path))

    assert config.severity_policy["brute_force_suspected"] == "high"
    assert config.severity_policy["suspicious_username_targeted"] == "low"
    assert config.severity_policy["successful_login_after_failures"] == "high"


def test_load_config_accepts_successful_after_failures_severity_override(tmp_path: Path) -> None:
    """The new successful-login-after-failures alert type should be configurable."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"severity_policy": {"successful_login_after_failures": "critical"}}',
    )

    config = load_config(str(config_path))

    assert config.severity_policy["successful_login_after_failures"] == "critical"


def test_load_config_normalizes_severity_values(tmp_path: Path) -> None:
    """Severity values should be normalized to lowercase."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"severity_policy": {"suspicious_username_targeted": "MEDIUM"}}',
    )

    config = load_config(str(config_path))

    assert config.severity_policy["suspicious_username_targeted"] == "medium"


def test_load_config_rejects_non_dict_severity_policy(tmp_path: Path) -> None:
    """severity_policy must be a JSON object."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"severity_policy": "high"}',
    )

    with pytest.raises(ValueError):
        load_config(str(config_path))


def test_load_config_rejects_unknown_severity_policy_key(tmp_path: Path) -> None:
    """Only known alert types may appear in severity_policy."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"severity_policy": {"unknown_alert": "low"}}',
    )

    with pytest.raises(ValueError):
        load_config(str(config_path))


def test_load_config_rejects_non_string_severity_value(tmp_path: Path) -> None:
    """Severity policy values must be strings."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"severity_policy": {"brute_force_suspected": 123}}',
    )

    with pytest.raises(ValueError):
        load_config(str(config_path))


def test_load_config_rejects_invalid_severity_value(tmp_path: Path) -> None:
    """Severity values must come from the approved severity set."""
    config_path = write_config_file(
        tmp_path / "config.json",
        '{"severity_policy": {"brute_force_suspected": "severe"}}',
    )

    with pytest.raises(ValueError):
        load_config(str(config_path))
