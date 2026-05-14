# MVP v1 Plan and Status

## MVP Goals

The goal of MVP v1 is to build a small, understandable cybersecurity log analysis tool in Python.

MVP v1 should be able to:

- Load a local log file.
- Parse simple SSH authentication failure and success log lines.
- Detect repeated failed-login patterns.
- Detect failed logins against commonly attacked usernames.
- Detect successful SSH logins after repeated failures from the same source IP.
- Support a small JSON configuration system.
- Suppress alerts from known allowed IP addresses.
- Print structured alerts to the terminal.
- Provide alert summary statistics and a short run summary.
- Optionally export alerts to JSON.
- Be easy for a beginner developer to read, test, and extend.

The MVP is not meant to be a complete SIEM, threat intelligence platform, or AI product. It is a learning-focused foundation.

## Current MVP Status

MVP v1 is now a functional foundation. The core pipeline, configuration system, detection rules, formatter behavior, tests, and CI workflow are implemented.

Implemented capabilities include:

- Docker Dev Container workflow
- Python 3.12 project structure
- SSH authentication log parsing
- Failed-login event extraction
- Successful-login event extraction
- Brute-force detection rule
- Suspicious username detection rule
- Successful-login-after-failures detection rule
- IP allowlist suppression
- JSON configuration system
- Configurable severity policy
- Detection rule metadata
- JSON alert export
- Alert summary statistics
- pytest unit test suite
- GitHub Actions CI workflow
- Git feature-branch workflow

## Excluded Features for v1

To keep the first version focused and maintainable, the following features should stay out of MVP v1 unless explicitly requested:

- Real-time log streaming.
- Machine learning or anomaly detection.
- AI-generated summaries.
- Web dashboard or frontend.
- Database storage.
- User accounts or authentication.
- External threat intelligence API calls.
- SIEM integrations such as Splunk or Elastic.
- Automated blocking or remediation.
- Complex multi-host correlation.
- Plugin architecture.
- Support for many log formats at once.

These are good future ideas, but adding them too early would make the project harder to learn from.

## Completed Milestones

### Milestone 1: Documentation and Architecture

Status: complete.

The project uses a documented layered pipeline:

```text
Config + CLI -> Loader -> Parser -> Detector -> Formatter
```

Success criteria met:

- Documentation explains the architecture clearly.
- MVP boundaries are written down.
- AI assistant guidance exists in `AGENTS.md`.

### Milestone 2: Data Models

Status: complete.

Implemented dataclasses:

- `LogEvent`
- `Alert`
- `RunStats`

`Alert` includes detection metadata such as rule ID, rule name, rule version, alert type, and severity.

### Milestone 3: Log Loading

Status: complete.

`loader.py` safely reads local log files, validates paths, and returns raw text lines.

### Milestone 4: Parsing

Status: complete.

`parser.py` parses common Linux SSH failed-login and successful-login lines into `LogEvent` objects and safely skips unsupported lines.

### Milestone 5: Detection

Status: complete.

Implemented detection rules:

| Rule ID | Alert Type | Purpose |
| --- | --- | --- |
| `AUTH-001` | `brute_force_suspected` | Repeated failed logins from one source IP within a time window |
| `AUTH-002` | `suspicious_username_targeted` | Failed login against a commonly attacked username |
| `AUTH-003` | `successful_login_after_failures` | Successful SSH login after repeated failures from the same source IP |

All rules support allowed IP suppression and configurable severity policy.

### Milestone 6: Output Formatting

Status: complete.

`formatter.py` supports:

- Pretty JSON-style console alerts
- Alert summary statistics
- Run summary statistics
- Optional JSON alert export

### Milestone 7: Tests

Status: complete.

The pytest suite covers:

- Parser behavior
- Detector behavior
- Config loading and validation
- Formatter behavior

Tests include positive and negative cases and use deterministic sample data.

### Milestone 8: Configuration

Status: complete.

`config.py` and `config/default_config.json` support:

- Failed-login threshold
- Detection window
- Targeted usernames
- Allowed IPs
- Severity policy

Configuration input is validated before use.

### Milestone 9: Continuous Integration

Status: complete.

GitHub Actions runs pytest on push and pull request using Python 3.12.

## Current Success Criteria

MVP v1 is successful when:

- A local sample log file can be analyzed.
- Failed login lines are parsed into structured events.
- Successful login lines are parsed into structured events.
- Repeated failures from the same IP generate a brute-force alert.
- Failed logins against targeted usernames generate suspicious-username alerts.
- A successful login after repeated failures from the same IP generates a successful-after-failures alert.
- Alerts include useful details such as source IP, count, time range, evidence, severity, and rule metadata.
- Allowed IPs suppress supported alerts.
- Config files are validated clearly and safely.
- Non-matching lines are skipped safely.
- Console and JSON output are deterministic and easy to read.
- The code is beginner-friendly and uses type hints.
- Parser, detector, config, and formatter tests exist.
- GitHub Actions runs tests automatically.

## Development Workflow

Recommended workflow for future milestones:

1. Create a feature branch for each focused change.
2. Keep the MVP scope small.
3. Update or add tests with behavior changes.
4. Run pytest locally.
5. Update documentation when architecture, CLI flags, config schema, alert schema, or detection rules change.
6. Open a pull request and let GitHub Actions validate the test suite.

## Recommended Next Milestones

### Next Milestone 1: Loader Tests

Add tests for `loader.py`.

Useful cases:

- Existing file returns lines.
- Missing file raises a clear error.
- Directory path is rejected.
- Encoding fallback behavior remains safe.

### Next Milestone 2: CLI Orchestration Tests

Add tests for `main.py` behavior.

Useful cases:

- Config file values are used.
- CLI `--threshold` and `--window` override config values.
- Output file writing is called when `--output` is provided.
- Errors return exit code `1`.

### Next Milestone 3: Schema Documentation

Document the alert JSON export schema and config schema more formally.

This will help future contributors avoid accidental breaking changes.

### Next Milestone 4: Sample Log Expansion

Add more sanitized sample logs for parser edge cases.

Examples:

- Unsupported auth lines that should be skipped.
- Different valid usernames.
- Multiple source IPs.
- Allowed IP examples.

### Next Milestone 5: Release and Contribution Checklist

Add a small checklist for releases or pull requests.

The checklist should remind contributors to run tests, update docs, and confirm MVP boundaries.

## Beginner Learning Goals

This project should help a beginner learn:

- How cybersecurity logs are structured.
- How to parse text with simple regular expressions.
- How to model data using dataclasses.
- How to separate responsibilities across modules.
- How to write simple detection rules.
- How to validate JSON configuration safely.
- How to avoid unsafe handling of untrusted input.
- How to build and test software incrementally.
- How CI supports safer collaboration.
- How to work safely with AI coding assistants.

The most important learning goal is understanding the flow from raw logs to structured security alerts.
