# AI Security Log Analyzer

A beginner-friendly Python cybersecurity project for parsing authentication logs, detecting suspicious failed-login patterns, and learning secure AI-assisted development workflows.

**Status:** MVP v1 in progress  
**Focus:** Python 3.12, cybersecurity log analysis, Docker Dev Containers, and safe AI-assisted development

## Project Overview

AI Security Log Analyzer is a learning-focused cybersecurity tool built with Python. The current MVP reads local authentication log files, parses common Linux SSH failed-login lines, detects repeated failures from the same source IP address, and prints structured alerts.

The goal is not to build a full SIEM or production security platform. Instead, this project focuses on the fundamentals of log analysis, detection engineering, secure coding, and clean software architecture.

## Current MVP Capabilities

The current MVP can:

- Load local log files
- Parse common Linux SSH failed-login log lines
- Extract timestamps, usernames, source IP addresses, event types, and raw log lines
- Detect repeated failed logins from the same IP address within a configurable time window
- Print structured JSON-style alerts
- Print a simple run summary
- Use a sanitized sample authentication log for testing

MVP v1 intentionally focuses on one detection rule so the architecture stays easy to understand.

## High-Level Architecture

The project follows a simple layered pipeline:

```text
Loader -> Parser -> Detector -> Formatter
```

Each layer has one clear responsibility:

| Layer | Module | Responsibility |
| --- | --- | --- |
| Loader | `loader.py` | Reads local log files safely |
| Parser | `parser.py` | Converts raw log lines into `LogEvent` objects |
| Detector | `detector.py` | Applies detection rules to parsed events |
| Formatter | `formatter.py` | Prints alerts and run summaries |
| Models | `models.py` | Defines shared dataclasses |
| CLI | `main.py` | Connects the pipeline through command-line arguments |

Raw log lines are treated as untrusted input. The tool reads them as text, parses only known patterns, skips unsupported lines, and never executes log content.

## Project Structure

```text
ai-security-log-analyzer/
├── docs/
│   ├── architecture.md
│   ├── dev-notes.md
│   └── mvp-v1-plan.md
├── sample_logs/
│   └── auth_sample.log
├── src/
│   └── log_analyzer/
│       ├── detector.py
│       ├── formatter.py
│       ├── loader.py
│       ├── main.py
│       ├── models.py
│       └── parser.py
├── AGENTS.md
├── README.md
└── .gitignore
```

## Setup

### Prerequisites

- Python 3.12
- Git
- VS Code recommended
- Docker recommended for the Dev Container workflow

### Dependencies

MVP v1 currently uses only the Python standard library. No package installation is required.

### Clone the Repository

```bash
git clone https://github.com/tlolod/ai-security-log-analyzer.git
cd ai-security-log-analyzer
```

## Docker Dev Container Workflow

This project is designed to be developed inside a Docker Dev Container. A containerized workflow helps keep the Python environment consistent and isolated from the host machine.

Recommended workflow:

1. Open the repository in VS Code.
2. Install the Dev Containers extension if needed.
3. Reopen the project in the container.
4. Develop and run the analyzer from inside the container terminal.

Using a Dev Container is especially useful for cybersecurity learning projects because it supports reproducible and isolated development.

## Example Usage

Analyze the included sample log:

```bash
PYTHONPATH=src python -m log_analyzer.main --file sample_logs/auth_sample.log --year 2026
```

Use a custom threshold and detection window:

```bash
PYTHONPATH=src python -m log_analyzer.main \
  --file sample_logs/auth_sample.log \
  --threshold 5 \
  --window 10 \
  --year 2026
```

## Example Output

Example alert output:

```text
=== ALERTS ===
{
  "alert_type": "brute_force_suspected",
  "severity": "medium",
  "message": "Detected 5 failed login attempts from 203.0.113.10 within 10 minutes.",
  "source_ip": "203.0.113.10",
  "first_seen": "2026-05-11T21:33:01",
  "last_seen": "2026-05-11T21:37:55",
  "failed_count": 5,
  "evidence": [
    "May 11 21:33:01 server sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port 54231 ssh2",
    "May 11 21:34:12 server sshd[1235]: Failed password for invalid user admin from 203.0.113.10 port 54232 ssh2",
    "May 11 21:35:25 server sshd[1236]: Failed password for invalid user admin from 203.0.113.10 port 54233 ssh2"
  ]
}
=== RUN SUMMARY ===
Total lines: 11
Parsed events: 7
Skipped lines: 4
Alerts generated: 1
```

Output may vary slightly as detection rules evolve.

## Security Notes

This project treats log data as untrusted input.

Safety principles:

- Never execute log content
- Never pass raw log content into shell commands
- Parse only known patterns
- Skip unsupported lines safely
- Use sanitized sample logs
- Keep detection logic deterministic and explainable

## Learning Goals

This project is designed to practice:

- Python 3.12 development
- Dataclasses and type hints
- File handling with `pathlib`
- Regular-expression-based log parsing
- Simple security detection rules
- CLI design with `argparse`
- Layered software architecture
- Docker Dev Container workflow
- Safe AI-assisted development practices

## Roadmap

Planned or possible future improvements:

- Add unit tests for parser and detector behavior
- Add JSON output mode
- Add configuration file support for thresholds
- Support more authentication log formats
- Add more detection rules
- Add structured error reporting
- Add AI-generated alert summaries after MVP is stable
- Add a small dashboard in a later version
- Expand Dev Container configuration as needed

## Documentation

Additional project notes:

- [Architecture](docs/architecture.md)
- [MVP v1 Plan](docs/mvp-v1-plan.md)
- [Development Notes](docs/dev-notes.md)
- [AI Assistant Guidance](AGENTS.md)

## License

This project is currently for educational and portfolio purposes. A license may be added later.