# MVP v1 Plan

## MVP Goals

The goal of MVP v1 is to build a small, understandable cybersecurity log analysis tool in Python.

MVP v1 should be able to:

- Load a local log file.
- Parse simple authentication/security log lines.
- Detect repeated failed-login patterns.
- Print structured alerts to the terminal.
- Provide a short summary of the analysis run.
- Be easy for a beginner developer to read, test, and extend.

The MVP is not meant to be a complete SIEM, threat intelligence platform, or AI product. It is a learning-focused foundation.

## Excluded Features for v1

To keep the first version focused and maintainable, the following features should stay out of MVP v1:

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

## Milestone Roadmap

### Milestone 1: Documentation and Architecture

Define the project structure, architecture, module responsibilities, and MVP scope.

Success means:

- Documentation explains the architecture clearly.
- MVP boundaries are written down.
- AI assistant guidance exists in `AGENTS.md`.

### Milestone 2: Data Models

Create simple dataclasses for core concepts.

Expected models:

- `LogEvent`
- `Alert`
- `RunStats`

Success means each model has clear fields and type hints.

### Milestone 3: Log Loading

Add safe local file loading.

Success means the program can read a local sample log file and return raw lines.

### Milestone 4: Parsing

Parse a small set of authentication log lines.

Success means failed SSH login lines can become structured `LogEvent` objects.

### Milestone 5: Detection

Detect repeated failed logins from the same source IP.

Success means the detector can generate an alert when a threshold is exceeded.

### Milestone 6: Output Formatting

Print structured alerts and a run summary.

Success means a beginner can understand what was detected and why.

### Milestone 7: Tests

Add basic tests for parsing and detection.

Success means common success and failure cases are covered.

## Implementation Order

Recommended first implementation order:

1. `src/log_analyzer/models.py`
2. `src/log_analyzer/parser.py`
3. `src/log_analyzer/detector.py`
4. `src/log_analyzer/formatter.py`
5. `src/log_analyzer/loader.py`
6. `src/log_analyzer/main.py`
7. `sample_logs/auth_sample.log`
8. `tests/test_parser.py`
9. `tests/test_detector.py`

This order starts with data contracts, then core logic, then orchestration and tests.

## Success Criteria

MVP v1 is successful when:

- A local sample log file can be analyzed.
- Failed login lines are parsed into structured events.
- Repeated failures from the same IP generate an alert.
- Alerts include useful details such as source IP, count, time range, and evidence.
- Non-matching lines are skipped safely.
- The output is deterministic and easy to read.
- The code is beginner-friendly and uses type hints.
- Basic parser and detector tests exist.

## Beginner Learning Goals

This project should help a beginner learn:

- How cybersecurity logs are structured.
- How to parse text with simple regular expressions.
- How to model data using dataclasses.
- How to separate responsibilities across modules.
- How to write simple detection rules.
- How to avoid unsafe handling of untrusted input.
- How to build and test software incrementally.
- How to work safely with AI coding assistants.

The most important learning goal is understanding the flow from raw logs to structured security alerts.