# AI Security Log Analyzer

A beginner-friendly Python cybersecurity project for parsing authentication logs, detecting suspicious failed-login patterns, and learning secure AI-assisted development workflows.

**Status:** MVP v1 functional learning foundation  
**Focus:** Python 3.12, cybersecurity log analysis, Docker Dev Containers, pytest, GitHub Actions, and safe AI-assisted development

## Project Overview

AI Security Log Analyzer is a learning-focused cybersecurity tool built with Python. The current system reads local authentication log files, parses common Linux SSH login lines, applies deterministic detection rules, and prints structured alerts with summary statistics.

The goal is not to build a full SIEM or production security platform. Instead, this project focuses on the fundamentals of log analysis, detection engineering, secure coding, clean software architecture, and reliable development workflows.

## Current Implemented Capabilities

The current MVP can:

- Load local log files safely
- Parse common Linux SSH failed-login and successful-login log lines
- Extract timestamps, usernames, source IP addresses, event types, and raw log lines
- Detect repeated failed logins from the same IP address within a configurable time window
- Detect failed logins targeting commonly attacked usernames
- Detect a successful SSH login after repeated failed logins from the same source IP
- Suppress alerts from configured allowed IP addresses
- Load and validate JSON configuration files
- Configure failed-login thresholds, detection windows, targeted usernames, allowed IPs, and severity policy
- Include detection rule metadata in alerts
- Print structured JSON-style alerts to the console
- Print alert summary statistics by alert type, severity, and unique source IP count
- Export alerts and summaries to JSON files
- Run a pytest unit test suite
- Run tests automatically in GitHub Actions CI on push and pull request

MVP v1 intentionally keeps the scope small so the architecture stays easy to understand.

## Detection Rules

| Rule ID | Alert Type | Rule Name | Purpose | Default Severity |
| --- | --- | --- | --- | --- |
| `AUTH-001` | `brute_force_suspected` | SSH Brute Force Suspected | Detects repeated failed logins from one source IP within a time window | `medium` |
| `AUTH-002` | `suspicious_username_targeted` | Suspicious Username Targeted | Detects failed logins against commonly attacked usernames such as `root` or `admin` | `low` |
| `AUTH-003` | `successful_login_after_failures` | Successful SSH Login After Failures | Detects a successful SSH login after repeated failed logins from the same source IP | `high` |

Alerts include stable rule metadata:

- `rule_id`
- `rule_name`
- `rule_version`
- `alert_type`
- `severity`
- `mitre_attack`

MITRE ATT&CK mapping metadata helps connect these beginner-friendly rules to a common security framework. This metadata makes alerts easier to understand, test, export, and extend later.

## High-Level Architecture

The project follows a simple layered pipeline:

```text
Config + CLI -> Loader -> Parser -> Detector -> Formatter
```

Each layer has one clear responsibility:

| Layer | Module | Responsibility |
| --- | --- | --- |
| Config | `config.py` | Loads defaults or validates JSON configuration |
| Loader | `loader.py` | Reads local log files safely |
| Parser | `parser.py` | Converts raw log lines into `LogEvent` objects |
| Detector | `detector.py` | Applies detection rules to parsed events |
| Formatter | `formatter.py` | Prints alerts, summaries, and JSON export data |
| Models | `models.py` | Defines shared dataclasses |
| CLI | `main.py` | Orchestrates the pipeline through command-line arguments |

Raw log lines and configuration files are treated as untrusted input. The tool reads them as text, validates expected fields, parses only known log patterns, skips unsupported lines, and never executes log content.

## Project Structure

```text
ai-security-log-analyzer/
├── .github/
│   └── workflows/
│       └── tests.yml
├── config/
│   └── default_config.json
├── docs/
│   ├── architecture.md
│   ├── dev-notes.md
│   └── mvp-v1-plan.md
├── sample_logs/
│   └── auth_sample.log
├── src/
│   └── log_analyzer/
│       ├── config.py
│       ├── detector.py
│       ├── formatter.py
│       ├── loader.py
│       ├── main.py
│       ├── models.py
│       └── parser.py
├── tests/
│   ├── test_config.py
│   ├── test_detector.py
│   ├── test_formatter.py
│   └── test_parser.py
├── AGENTS.md
├── README.md
├── requirements-dev.txt
└── .gitignore
```

## Setup

### Prerequisites

- Python 3.12
- Git
- VS Code recommended
- Docker recommended for the Dev Container workflow

### Dependencies

The analyzer itself currently uses the Python standard library.

For development and testing, install the development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

`pytest` and `ruff` are the current development dependencies.

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
4. Install development dependencies if needed.
5. Develop and run tests from inside the container terminal.

Using a Dev Container is especially useful for cybersecurity learning projects because it supports reproducible and isolated development.

## Configuration

The analyzer can use built-in defaults or load a JSON configuration file.

Default configuration lives in:

```text
config/default_config.json
```

Supported config keys:

| Key | Purpose |
| --- | --- |
| `failed_login_threshold` | Number of failed logins needed for failed-login-based alerts |
| `window_minutes` | Time window used by failed-login-based detectors |
| `targeted_usernames` | Usernames that trigger suspicious-username alerts |
| `allowed_ips` | Exact IP addresses that should be suppressed from alerts |
| `severity_policy` | Severity labels for known alert types |

Configuration is validated before use. Unknown keys, invalid JSON, invalid IP addresses, invalid severity values, and wrong value types fail clearly.

CLI values for `--threshold` and `--window` override config-file values so short experiments remain easy.

## Example Usage

Analyze the included sample log with built-in defaults:

```bash
PYTHONPATH=src python -m log_analyzer.main --file sample_logs/auth_sample.log --year 2026
```

The sample log uses syslog-style timestamps that do not include a year, so the examples pass `--year 2026` for deterministic demo output.

Use a custom threshold and detection window:

```bash
PYTHONPATH=src python -m log_analyzer.main \
  --file sample_logs/auth_sample.log \
  --threshold 5 \
  --window 10 \
  --year 2026
```

Use a JSON config file:

```bash
PYTHONPATH=src python -m log_analyzer.main \
  --file sample_logs/auth_sample.log \
  --config config/default_config.json \
  --year 2026
```

Export alerts to a JSON file:

```bash
PYTHONPATH=src python -m log_analyzer.main \
  --file sample_logs/auth_sample.log \
  --config config/default_config.json \
  --output alerts.json \
  --year 2026
```

## Example Output

The sample log intentionally includes repeated failed SSH logins, a successful login after those failures, and suspicious usernames. Abbreviated example output:

```text
=== ALERTS ===
{
  "alert_type": "brute_force_suspected",
  "rule_id": "AUTH-001",
  "rule_name": "SSH Brute Force Suspected",
  "rule_version": "1.0",
  "severity": "medium",
  "mitre_attack": {
    "tactic": "Credential Access",
    "technique_id": "T1110",
    "technique": "Brute Force"
  },
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
{
  "alert_type": "successful_login_after_failures",
  "rule_id": "AUTH-003",
  "rule_name": "Successful SSH Login After Failures",
  "rule_version": "1.0",
  "severity": "high",
  "mitre_attack": {
    "tactic": "Credential Access",
    "technique_id": "T1110",
    "technique": "Brute Force"
  },
  "message": "Detected successful login for 'alice' from 203.0.113.10 after 6 failed login attempts within 10 minutes.",
  "source_ip": "203.0.113.10",
  "first_seen": "2026-05-11T21:33:01",
  "last_seen": "2026-05-11T21:39:30",
  "failed_count": 6,
  "evidence": [
    "May 11 21:33:01 server sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port 54231 ssh2",
    "May 11 21:34:12 server sshd[1235]: Failed password for invalid user admin from 203.0.113.10 port 54232 ssh2",
    "May 11 21:35:25 server sshd[1236]: Failed password for invalid user admin from 203.0.113.10 port 54233 ssh2",
    "May 11 21:39:30 server sshd[1241]: Accepted password for alice from 203.0.113.10 port 54237 ssh2"
  ]
}
... additional suspicious_username_targeted alerts omitted ...
=== ALERT SUMMARY ===

Alerts by type:
- brute_force_suspected: 1
- successful_login_after_failures: 1
- suspicious_username_targeted: 2

Alerts by severity:
- medium: 1
- high: 1
- low: 2

Unique source IPs:
- 2
=== RUN SUMMARY ===
Total lines: 12
Parsed events: 9
Skipped lines: 3
Alerts generated: 4
```

Output may vary as sample data and detection rules evolve.

## JSON Export

When `--output` is provided, the formatter writes a JSON file with this structure:

```json
{
  "alerts": [],
  "alert_count": 0,
  "summary": {
    "by_type": {},
    "by_severity": {},
    "unique_source_ips": 0
  }
}
```

The same alert fields printed to the console are included in exported alerts.

## Testing

Install test dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

Run lint checks:

```bash
python -m ruff check .
```

Run the test suite:

```bash
PYTHONPATH=src python -m pytest
```

Current tests cover:

- Parser behavior
- Detector behavior
- Config loading and validation
- Formatter behavior, alert summaries, and JSON export

## Continuous Integration

GitHub Actions runs the test suite on:

- `push`
- `pull_request`

The CI workflow uses Python 3.12, installs `requirements-dev.txt`, and runs:

```bash
python -m ruff check .
PYTHONPATH=src python -m pytest
```

## Feature Branch Workflow

Recommended workflow for contributors:

1. Create a focused feature branch.
2. Keep changes small and easy to review.
3. Preserve the layered architecture.
4. Add or update tests for behavior changes.
5. Update documentation when CLI flags, config keys, alert schema, or detection rules change.
6. Run Ruff and pytest locally before opening a pull request.
7. Push the branch and open a pull request.
8. Let GitHub Actions confirm the test suite passes before merging.

## Security Notes

This project treats log data and config data as untrusted input.

Safety principles:

- Never execute log content
- Never pass raw log content into shell commands
- Parse only known patterns
- Skip unsupported lines safely
- Validate config values before use
- Use sanitized sample logs
- Keep detection logic deterministic and explainable
- Do not add automated blocking or remediation in MVP v1

## Learning Goals

This project is designed to practice:

- Python 3.12 development
- Dataclasses and type hints
- File handling with `pathlib`
- Regular-expression-based log parsing
- Simple security detection rules
- JSON configuration and validation
- CLI design with `argparse`
- Unit testing with pytest
- GitHub Actions CI
- Layered software architecture
- Docker Dev Container workflow
- Safe AI-assisted development practices

## Recommended Next Milestones

Good next improvements:

- Add tests for `loader.py`
- Add tests for `main.py` CLI orchestration and config override behavior
- Document the alert JSON schema more formally
- Add more sanitized sample logs for parser edge cases
- Add a small release checklist or changelog
- Consider simple linting or formatting guidance without adding unnecessary dependency complexity
- Add more authentication log formats only after the current SSH parser remains well tested

Still intentionally out of scope for MVP v1 unless explicitly requested:

- AI summaries
- Web dashboards
- Databases
- Real-time streaming
- External API calls
- SIEM integrations
- Machine learning
- Automated response actions

## Documentation

Additional project notes:

- [Architecture](docs/architecture.md)
- [MVP v1 Plan](docs/mvp-v1-plan.md)
- [Development Notes](docs/dev-notes.md)
- [AI Assistant Guidance](AGENTS.md)

## License

This project is currently for educational and portfolio purposes. A license may be added later.
