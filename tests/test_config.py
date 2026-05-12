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


def test_load_config_none_returns_defaults() -> None:
    """A missing config path means the analyzer should use built-in defaults."""
    config = load_config(None)

    assert config.failed_login_threshold == 5
    assert config.window_minutes == 10


def test_load_config_reads_valid_json_file(tmp_path: Path) -> None:
    """A valid JSON config should override default values."""
    config_path = write_config_file(
        tmp_path / "config.json",
        """
        {
          "failed_login_threshold": 8,
          "window_minutes": 15,
          "targeted_usernames": ["Root", "Admin"]
        }
        """,
    )

    config = load_config(str(config_path))

    assert config.failed_login_threshold == 8
    assert config.window_minutes == 15
    assert config.targeted_usernames == ["root", "admin"]


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
