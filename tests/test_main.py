"""Tests for main.py orchestration behavior."""

import json
from pathlib import Path

from src.log_analyzer.main import build_arg_parser, run


def write_log_file(path: Path, lines: list[str]) -> Path:
    """Write deterministic auth log lines for main orchestration tests."""
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def failed_login_line(minute: int, source_ip: str = "203.0.113.10") -> str:
    """Create one sanitized SSH failed-login line."""
    return (
        f"May 11 21:{minute:02d}:00 server sshd[1234]: "
        f"Failed password for root from {source_ip} port 54231 ssh2"
    )


def test_run_returns_zero_and_prints_summaries_for_valid_log(
    tmp_path: Path,
    capsys,
) -> None:
    """A valid log file should run successfully and print summaries."""
    log_path = write_log_file(
        tmp_path / "auth.log",
        [
            failed_login_line(33),
            "May 11 21:34:00 server systemd[1]: Started Daily apt download activities.",
        ],
    )

    exit_code = run(
        file_path=str(log_path),
        threshold=None,
        window_minutes=None,
        year=2026,
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "=== ALERT SUMMARY ===" in captured.out
    assert "=== RUN SUMMARY ===" in captured.out
    assert "Total lines: 2" in captured.out
    assert "Parsed events: 1" in captured.out
    assert "Skipped lines: 1" in captured.out


def test_run_applies_threshold_and_window_overrides(tmp_path: Path, capsys) -> None:
    """CLI threshold and window values should override default detection settings."""
    log_path = write_log_file(
        tmp_path / "auth.log",
        [failed_login_line(minute) for minute in range(33, 36)],
    )

    exit_code = run(
        file_path=str(log_path),
        threshold=3,
        window_minutes=10,
        year=2026,
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "brute_force_suspected" in captured.out
    assert "Detected 3 failed login attempts" in captured.out


def test_run_returns_one_for_missing_log_file(tmp_path: Path, capsys) -> None:
    """A missing log file should be handled with a clear error and exit code 1."""
    missing_path = tmp_path / "missing-auth.log"

    exit_code = run(
        file_path=str(missing_path),
        threshold=None,
        window_minutes=None,
        year=2026,
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Error:" in captured.out
    assert "not found" in captured.out


def test_run_writes_json_output_file(tmp_path: Path) -> None:
    """When output_path is provided, run should write JSON alert output."""
    log_path = write_log_file(
        tmp_path / "auth.log",
        [failed_login_line(minute) for minute in range(33, 36)],
    )
    output_path = tmp_path / "alerts.json"

    exit_code = run(
        file_path=str(log_path),
        threshold=3,
        window_minutes=10,
        year=2026,
        output_path=str(output_path),
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload["alert_count"] >= 1
    assert "alerts" in payload
    assert "summary" in payload
    assert payload["alerts"][0]["alert_type"] == "brute_force_suspected"
    assert payload["alerts"][0]["mitre_attack"] == {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique": "Brute Force",
    }


def test_run_uses_config_file_values(tmp_path: Path, capsys) -> None:
    """Config file values should be used when CLI overrides are not provided."""
    log_path = write_log_file(
        tmp_path / "auth.log",
        [failed_login_line(minute) for minute in range(33, 36)],
    )
    config_path = tmp_path / "config.json"
    config_path.write_text('{"failed_login_threshold": 3}', encoding="utf-8")

    exit_code = run(
        file_path=str(log_path),
        threshold=None,
        window_minutes=None,
        year=2026,
        config_path=str(config_path),
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "brute_force_suspected" in captured.out
    assert "Detected 3 failed login attempts" in captured.out


def test_build_arg_parser_accepts_expected_arguments() -> None:
    """Argument parser should accept the public CLI options used in examples."""
    parser = build_arg_parser()

    args = parser.parse_args(
        [
            "--file",
            "sample_logs/auth_sample.log",
            "--threshold",
            "3",
            "--window",
            "10",
            "--year",
            "2026",
            "--config",
            "config/default_config.json",
            "--output",
            "alerts.json",
        ]
    )

    assert args.file == "sample_logs/auth_sample.log"
    assert args.threshold == 3
    assert args.window == 10
    assert args.year == 2026
    assert args.config == "config/default_config.json"
    assert args.output == "alerts.json"