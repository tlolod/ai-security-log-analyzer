# AI Security Log Analyzer

A beginner-friendly Python 3.12 cybersecurity project for parsing SSH authentication logs, detecting suspicious login behavior, and practicing secure software delivery workflows.

**Status:** MVP v1 (learning-focused and intentionally small)

## Project Overview

AI Security Log Analyzer is built as an educational and portfolio-oriented project. It reads local auth logs, parses known SSH patterns, applies deterministic detection rules, and produces structured alert output.

This project is **not** a full SIEM. The goal is to build strong fundamentals in log analysis, detection engineering, secure coding, and CI-supported development.

## Current Detection Features

The current detector set includes:

- **Brute-force failed login detection** (`AUTH-001`)
  - Repeated failed logins from the same source IP within a configurable time window.
- **Suspicious username targeting** (`AUTH-002`)
  - Failed logins for commonly targeted usernames (for example: `root`, `admin`).
- **Successful login after failures** (`AUTH-003`)
  - A successful SSH login after repeated failed attempts from the same IP.
- **IP allowlist suppression**
  - Alerts are suppressed for exact IP addresses configured in `allowed_ips`.
- **Alert cooldown suppression**
  - Repeated alerts with the same `(source_ip, alert_type)` are suppressed for a configurable cooldown period.

## Configuration System

Configuration can be loaded from JSON (default or custom file):

- Default file: `config/default_config.json`
- CLI flag: `--config path/to/config.json`

### Supported configuration areas

- Failed-login threshold (`failed_login_threshold`)
- Detection window in minutes (`window_minutes`)
- Cooldown window (`alert_cooldown_minutes`)
- Targeted usernames (`targeted_usernames`)
- Allowlisted IPs (`allowed_ips`)
- Severity policy per alert type (`severity_policy`)

### Precedence rules

CLI overrides take priority over config values for:

- `--threshold`
- `--window`

This makes quick experiments easy while keeping JSON config as the baseline.

## JSON Export Support

The analyzer can export structured alerts to JSON using `--output`.

### Example command

```bash
PYTHONPATH=src python -m log_analyzer.main \
  --file sample_logs/auth_sample.log \
  --config config/default_config.json \
  --output alerts.json \
  --year 2026
```

### Example output structure

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

### Local testing

Run the test suite with pytest:

```bash
PYTHONPATH=src python -m pytest
```

Optional lint check used by CI:

```bash
python -m ruff check .
```

### GitHub Actions CI

The workflow in `.github/workflows/tests.yml` runs automated validation on:

- `push`
- `pull_request`

Current CI steps include:

- Install dev dependencies
- Run Ruff lint checks
- Run pytest unit tests

## Project Architecture

The project follows a layered pipeline:

```text
Config + CLI -> Loader -> Parser -> Detectors -> Formatter/Exporter
```

Key components:

- **Configuration loader** (`config.py`) for JSON loading and validation
- **Parser** (`parser.py`) for converting raw lines into structured events
- **Detectors** (`detector.py`) for deterministic security rule evaluation
- **Formatter/Exporter** (`formatter.py`) for console summaries and JSON/CSV exports
- **Tests** (`tests/`) for parser, detector, config, formatter, loader, and CLI orchestration behavior
- **CI workflow** (`.github/workflows/tests.yml`) for automated quality checks

## Example Commands

Run with default settings:

```bash
PYTHONPATH=src python -m log_analyzer.main --file sample_logs/auth_sample.log --year 2026
```

Run with a custom config file (`--config`):

```bash
PYTHONPATH=src python -m log_analyzer.main \
  --file sample_logs/auth_sample.log \
  --config config/default_config.json \
  --year 2026
```

Run with custom threshold/window overrides plus config:

```bash
PYTHONPATH=src python -m log_analyzer.main \
  --file sample_logs/auth_sample.log \
  --config config/default_config.json \
  --threshold 6 \
  --window 15 \
  --year 2026
```

Export alerts to JSON (`--output`):

```bash
PYTHONPATH=src python -m log_analyzer.main \
  --file sample_logs/auth_sample.log \
  --output alerts.json \
  --year 2026
```

## Developer Workflow

A simple workflow for stable contributions:

1. Create a focused **feature branch** from `main`.
2. Implement small, reviewable changes.
3. Run **local pytest validation** (and Ruff lint checks) before pushing.
4. Open a pull request and let **GitHub Actions CI** validate changes.
5. Merge stable, reviewed features back into **`main`**.

## Learning Goals

This project is designed to help practice:

- Secure SDLC concepts
- CI/CD fundamentals with GitHub Actions
- Detection engineering basics
- DevSecOps practices for small projects
- Secure configuration management
- Python 3.12, type hints, and dataclasses
- Test-driven quality habits with pytest

## Roadmap (Realistic Next Steps)

Potential next improvements:

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
