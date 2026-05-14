"""Tests for loading local log files as text lines."""

from pathlib import Path

import pytest

from src.log_analyzer.loader import load_log_lines


def test_load_log_lines_reads_utf8_file(tmp_path: Path) -> None:
    """Loader should read common UTF-8 log files."""
    log_path = tmp_path / "auth.log"
    log_path.write_text(
        "May 11 21:33:01 server sshd[1234]: Failed password for root\n"
        "May 11 21:34:02 server sshd[1235]: Accepted password for alice\n",
        encoding="utf-8",
    )

    lines = load_log_lines(str(log_path))

    assert lines == [
        "May 11 21:33:01 server sshd[1234]: Failed password for root",
        "May 11 21:34:02 server sshd[1235]: Accepted password for alice",
    ]


def test_load_log_lines_falls_back_to_latin1_file(tmp_path: Path) -> None:
    """Loader should fall back to latin-1 for older system log files."""
    log_path = tmp_path / "auth-latin1.log"
    log_path.write_bytes(
        "May 11 21:33:01 server sshd[1234]: Failed password for josé\n".encode(
            "latin-1"
        )
    )

    lines = load_log_lines(str(log_path))

    assert lines == [
        "May 11 21:33:01 server sshd[1234]: Failed password for josé",
    ]


def test_load_log_lines_missing_file_raises_file_not_found(tmp_path: Path) -> None:
    """A missing log path should raise FileNotFoundError clearly."""
    missing_path = tmp_path / "missing-auth.log"

    with pytest.raises(FileNotFoundError):
        load_log_lines(str(missing_path))


def test_load_log_lines_directory_path_raises_value_error(tmp_path: Path) -> None:
    """A directory path is invalid because the loader only reads files."""
    log_directory = tmp_path / "logs"
    log_directory.mkdir()

    with pytest.raises(ValueError):
        load_log_lines(str(log_directory))