# AI Security Log Analyzer

A beginner-friendly Python 3.12 cybersecurity project for parsing SSH authentication logs, detecting suspicious login behavior, and practicing secure software delivery workflows.

**Status:** MVP v1 (learning-focused and intentionally small)

## Project Overview

AI Security Log Analyzer is an educational and portfolio-oriented project.
It reads local auth logs, parses known SSH patterns, applies deterministic detection rules, and produces structured alert output.

This project is **not** a full SIEM. It is designed to build practical foundations in log analysis, detection engineering, secure coding, and CI-supported development.


## Current Detection Features

| Rule ID | Detection | Description | Severity |
| --- | --- | --- | --- |
| `AUTH-001` | Brute-force failed login detection | Repeated failed logins from one source IP within a configurable time window. | Configurable (`severity_policy`) |
| `AUTH-002` | Suspicious username targeting | Failed logins against targeted usernames such as `root` and `admin`. | Configurable (`severity_policy`) |
| `AUTH-003` | Successful login after failures | Successful SSH login after repeated failures from the same source IP. | Configurable (`severity_policy`) |
| N/A | IP allowlist suppression | Suppresses alerts for exact IPs listed in `allowed_ips`. | N/A (suppressed) |
| N/A | Alert cooldown suppression | Suppresses repeated alerts with the same `(source_ip, alert_type)` during cooldown. | N/A (suppressed) |


## Configuration System

- Default config: `config/default_config.json`
- Optional custom config: `--config path/to/config.json`

| Config Key | Purpose |
| --- | --- |
| `failed_login_threshold` | Failed-login threshold used by failure-based detections |
| `window_minutes` | Time window for failure-based detections |
| `alert_cooldown_minutes` | Cooldown window for suppressing repeated alerts |
| `targeted_usernames` | Usernames monitored for suspicious targeting |
| `allowed_ips` | Exact source IPs excluded from alerts |
| `severity_policy` | Severity mapping per known alert type |

**Precedence:** CLI overrides config for `--threshold` and `--window`.


## JSON Export Support

Export structured alert data with `--output`:

```bash
PYTHONPATH=src python -m log_analyzer.main \
  --file sample_logs/auth_sample.log \
  --config config/default_config.json \
  --output alerts.json \
  --year 2026
```

Example JSON structure:

```json
{
  "alerts": [
    {
      "alert_type": "brute_force_suspected",
      "rule_id": "AUTH-001",
      "rule_name": "SSH Brute Force Suspected",
      "rule_version": "1.0",
      "severity": "medium",
      "source_ip": "203.0.113.10",
      "first_seen": "2026-05-11T21:33:01",
      "last_seen": "2026-05-11T21:37:55",
      "failed_count": 5,
      "message": "Detected 5 failed login attempts from 203.0.113.10 within 10 minutes.",
      "evidence": []
    }
  ],
  "alert_count": 1,
  "summary": {
    "by_type": {
      "brute_force_suspected": 1
    },
    "by_severity": {
      "medium": 1
    },
    "unique_source_ips": 1
  }
}
```


## Testing & CI

### Local Validation

```bash
PYTHONPATH=src python -m pytest
python -m ruff check .
```

### GitHub Actions CI

Workflow: `.github/workflows/tests.yml`

Automated validation runs on:

- `push`
- `pull_request`

CI steps include:

- install development dependencies
- run Ruff lint checks
- run pytest unit tests


## Project Architecture

```text
Config + CLI -> Loader -> Parser -> Detectors -> Formatter/Exporter
```

| Component | Responsibility |
| --- | --- |
| `config.py` | Loads and validates runtime configuration |
| `loader.py` | Reads local log files safely |
| `parser.py` | Converts raw lines into structured events |
| `detector.py` | Applies deterministic detection rules |
| `formatter.py` | Prints summaries and exports JSON/CSV output |
| `main.py` | Orchestrates pipeline execution from CLI |
| `tests/` | Validates behavior across parser, detector, config, formatter, loader, and CLI orchestration |
| `.github/workflows/tests.yml` | Runs CI linting and tests on push/pull request |


## Example Commands

```bash
# Default run
PYTHONPATH=src python -m log_analyzer.main --file sample_logs/auth_sample.log --year 2026

# Use JSON config (--config)
PYTHONPATH=src python -m log_analyzer.main \
  --file sample_logs/auth_sample.log \
  --config config/default_config.json \
  --year 2026

# Config + CLI overrides
PYTHONPATH=src python -m log_analyzer.main \
  --file sample_logs/auth_sample.log \
  --config config/default_config.json \
  --threshold 6 \
  --window 15 \
  --year 2026

# Export JSON (--output)
PYTHONPATH=src python -m log_analyzer.main \
  --file sample_logs/auth_sample.log \
  --output alerts.json \
  --year 2026
```


## Developer Workflow

1. Create a focused feature branch from `main`.
2. Implement small, reviewable changes.
3. Run local validation (`pytest` and Ruff).
4. Open a pull request and let GitHub Actions validate.
5. Merge stable, reviewed features back into `main`.


## Learning Goals

- Secure SDLC concepts
- CI/CD fundamentals with GitHub Actions
- Detection engineering basics
- DevSecOps practices for small projects
- Secure configuration management
- Python 3.12, type hints, and dataclasses
- Test-driven quality habits with pytest


## Roadmap (Realistic Next Steps)

- Additional deterministic detection rules
- Richer CSV export/reporting options
- Lightweight dashboard or web UI for local exploration
- Docker packaging for simplified execution
- Optional threat-intelligence enrichment
- CIDR-based allowlists (in addition to exact IP allowlists)
- Expanded log-source support beyond the current SSH auth focus


## Security Notes

The project treats logs and configuration as untrusted input:

- Never execute log content
- Validate configuration values before use
- Parse only known patterns and skip malformed lines safely
- Keep detection behavior deterministic and explainable
- Avoid automated blocking/remediation in MVP v1


## Documentation

- [Architecture](docs/architecture.md)
- [MVP v1 Plan](docs/mvp-v1-plan.md)
- [Development Notes](docs/dev-notes.md)
- [AI Assistant Guidance](AGENTS.md)


## License

Currently for educational and portfolio use. A formal license may be added later.
