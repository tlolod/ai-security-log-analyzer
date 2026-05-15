# AI Security Log Analyzer Architecture

## Project Purpose

AI Security Log Analyzer is a beginner-friendly cybersecurity learning project. Its first goal is to help a developer understand how security log analysis tools work before adding advanced features such as AI summaries, dashboards, or external integrations.

The current MVP focuses on a simple but realistic workflow:

1. Load local security log files.
2. Parse basic SSH authentication events.
3. Load validated runtime configuration.
4. Detect suspicious failed-login and successful-after-failures patterns.
5. Print structured alerts and summary statistics.
6. Optionally export alerts to JSON or CSV.
7. Keep the system easy to understand, test, and extend.

This project should teach both Python fundamentals and practical cybersecurity engineering habits.

## Layered Pipeline Architecture

The project uses a layered pipeline architecture. Each layer has one clear responsibility and passes data to the next layer.

```text
CLI Arguments
     |
     v
Config Layer  <--- optional JSON config file
     |
     v
Loader Layer
     |
     v
Parser Layer
     |
     v
Detection Layer
     |
     v
Formatting / Output Layer
     |
     +--> console alerts
     +--> alert summary statistics
     +--> optional JSON export
     +--> optional CSV export
```

A shorter way to describe the architecture is:

```text
Config + CLI -> Loader -> Parser -> Detector -> Formatter
```

This architecture is intentionally simple. A beginner should be able to trace the application from input to output without needing to understand complex frameworks.

## Runtime Data Flow

The current data flow is:

1. `main.py` receives command-line arguments.
2. `config.py` loads default settings or validates a JSON config file.
3. CLI values for `--threshold` and `--window` override config-file values when provided.
4. `loader.py` validates the local log path and reads raw text lines.
5. `parser.py` converts recognized SSH failed-login and successful-login lines into structured `LogEvent` objects.
6. `detector.py` applies detection rules to the parsed events.
7. Configured allowed IPs are suppressed from supported alerts.
8. `formatter.py` converts alerts into readable JSON-style console output.
9. `formatter.py` builds alert summary statistics by type, severity, and unique source IP count.
10. `formatter.py` optionally writes alerts and summary data to a JSON file.
11. `formatter.py` optionally writes alerts to a CSV file.
12. `main.py` prints run statistics and returns a process-style exit code.

The core idea is to separate raw text handling, configuration validation, detection logic, and output formatting. This makes the code easier to debug and safer to extend.

## Module Responsibilities

### `models.py`

Defines shared data structures:

- `LogEvent`
- `MitreAttackMetadata`
- `Alert`
- `RunStats`

These models use Python dataclasses and type hints so data is easy to inspect and understand.

`Alert` currently includes detection rule metadata:

- `alert_type`
- `rule_id`
- `rule_name`
- `rule_version`
- `severity`
- `mitre_attack`

Stable metadata helps future contributors understand which rule created each alert and how it maps to common security frameworks such as MITRE ATT&CK.

### `config.py`

Responsible for runtime configuration.

It should:

- Return safe default settings when no config path is provided.
- Load JSON config files as untrusted input.
- Reject invalid JSON.
- Reject unknown config keys.
- Validate positive integer settings.
- Validate and normalize exact IP addresses for `allowed_ips`.
- Validate and normalize targeted usernames.
- Validate severity policy values.
- Merge partial severity policy overrides with defaults.

It should not load logs, parse log lines, detect suspicious activity, or format output.

### `loader.py`

Responsible for safely reading local log files.

It should:

- Accept a file path.
- Validate that the path exists.
- Confirm the path points to a file.
- Read text lines using UTF-8 with a simple latin-1 fallback.
- Return raw lines to the parser.

It should not parse, analyze, or execute log content.

### `parser.py`

Responsible for converting raw log lines into normalized events.

It should:

- Look for known SSH authentication failure and success patterns.
- Extract fields such as timestamp, username, source IP, and event type.
- Return `LogEvent` objects for recognized lines.
- Skip unsupported or irrelevant lines safely.

It should not decide whether activity is suspicious.

### `detector.py`

Responsible for security detection rules.

Current rules:

| Rule ID | Alert Type | Rule Name | Version | Purpose |
| --- | --- | --- | --- | --- |
| `AUTH-001` | `brute_force_suspected` | SSH Brute Force Suspected | `1.0` | Detect repeated failed logins from one IP within a configured time window |
| `AUTH-002` | `suspicious_username_targeted` | Suspicious Username Targeted | `1.0` | Detect failed logins targeting commonly attacked usernames |
| `AUTH-003` | `successful_login_after_failures` | Successful SSH Login After Failures | `1.0` | Detect a successful SSH login after repeated failed logins from the same source IP |

The detector should:

- Receive parsed `LogEvent` objects.
- Apply deterministic detection rules.
- Respect configured allowed IP suppression where appropriate.
- Use configured severity policy values instead of hardcoded alert severities.
- Attach MITRE ATT&CK mapping metadata where appropriate.
- Return structured `Alert` objects.

It should not read files, parse raw log text, validate JSON config files, print output, or write export files.

### `formatter.py`

Responsible for output formatting.

It should:

- Convert alerts into JSON-serializable dictionaries.
- Serialize MITRE ATT&CK metadata in alert output.
- Print alert details consistently.
- Build alert summary statistics.
- Print alert summaries.
- Print run summaries.
- Write optional JSON alert export files.
- Write optional CSV alert export files.

It should not contain detection, parsing, or config-loading logic.

### `main.py`

Responsible for orchestration.

It should:

- Parse command-line arguments.
- Load configuration.
- Apply simple CLI overrides for threshold and window values.
- Call the loader, parser, detector, and formatter in order.
- Handle high-level errors gracefully.
- Return a clear success or failure exit code.

It should stay small and avoid complex business logic.

## Configuration Architecture

The config system is intentionally small and explicit.

Supported keys:

- `failed_login_threshold`
- `window_minutes`
- `targeted_usernames`
- `allowed_ips`
- `severity_policy`

The default config file is:

```text
config/default_config.json
```

Configuration is validated before use because config files are user-controlled input. This keeps behavior predictable and helps catch mistakes early.

## Detection Architecture

Detection is deterministic and rule-based. This makes alerts easier to explain, test, and reproduce.

The current detector supports:

- Brute-force detection using a failed-login threshold and time window.
- Suspicious username detection for commonly attacked usernames.
- Successful-login-after-failures detection using the same failed-login threshold and time window.
- Exact IP allowlist suppression through `allowed_ips`.
- Configurable severity labels through `severity_policy`.
- Stable rule metadata for every alert.
- MITRE ATT&CK mapping metadata for current credential attack rules.

Detection rules should continue to return structured `Alert` objects instead of printing or writing output directly.

## Output Architecture

Console output currently includes:

- Pretty JSON-style alert output
- Alert summary statistics
- Run summary statistics

Optional JSON export includes:

- `alerts`
- `alert_count`
- `summary`

Optional CSV export includes one row per alert with flattened MITRE ATT&CK columns and evidence joined into a single cell.

The formatter owns output behavior so detector rules can stay focused on security logic.

## Testing and CI Architecture

The project uses pytest for deterministic unit tests.

Current test coverage includes:

- Parser behavior for supported and unsupported log lines
- Detector behavior for positive and negative cases
- Allowlist suppression
- Configurable severity policy
- Config loading, validation, and normalization
- Formatter JSON serialization, summaries, and JSON export path validation

GitHub Actions runs the test suite on push and pull request using Python 3.12.

## Security and Safety Philosophy

Security log data and config data must always be treated as untrusted input.

Important safety rules:

- Never execute content from logs.
- Do not pass log content into shell commands.
- Keep parsing logic defensive and simple.
- Skip malformed or unsupported lines instead of crashing when possible.
- Validate config files before using their values.
- Avoid writing sensitive log data to unexpected locations.
- Use sanitized sample logs for development and tests.
- Prefer deterministic behavior so results are reproducible.
- Do not add automated blocking or remediation in MVP v1.

The tool should help developers learn safe cybersecurity engineering practices from the beginning.

## Extension Guidelines

The MVP should remain small, but the architecture supports careful growth.

When adding a new detection rule:

1. Keep the rule in `detector.py` unless the detector module becomes too large.
2. Give the rule stable metadata: `rule_id`, `rule_name`, `rule_version`, and `alert_type`.
3. Add a severity policy entry if the rule emits a new alert type.
4. Respect `allowed_ips` suppression when it applies.
5. Add positive and negative tests.
6. Update documentation and sample config if behavior changes.

Recommended next architecture improvements:

- Add tests for `loader.py`.
- Add tests for `main.py` orchestration and CLI override behavior.
- Document the alert JSON schema more formally.
- Add more sanitized sample logs for edge cases.
- Add more authentication log formats only when needed and tested.

Features such as AI summaries, dashboards, databases, external APIs, SIEM integrations, machine learning, real-time streaming, and automated response actions remain outside MVP v1 unless explicitly requested.
