"""File loading utilities for the AI Security Log Analyzer.

The loader layer has one job: read local log files as text.
It does not parse, analyze, or execute log content.
"""

from pathlib import Path


def load_log_lines(file_path: str) -> list[str]:
    """Load a local log file and return its lines.

    Args:
        file_path: Path to a local log file.

    Returns:
        A list of text lines from the log file.

    Raises:
        FileNotFoundError: If the path does not exist.
        ValueError: If the path exists but is not a file.
        OSError: If the file cannot be read.
    """
    path = Path(file_path)

    # Validate the path before reading. Log paths are user input, so we should
    # fail clearly instead of guessing what the user intended.
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    if not path.is_file():
        raise ValueError(f"Log path is not a file: {file_path}")

    # Most modern logs are UTF-8. Some older/system logs may use latin-1, so we
    # try that as a simple fallback if UTF-8 decoding fails.
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(encoding="latin-1")

    return text.splitlines()
