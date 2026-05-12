# AI Security Log Analyzer Architecture

## Project Purpose

AI Security Log Analyzer is a beginner-friendly cybersecurity learning project. Its first goal is to help a developer understand how security log analysis tools work before adding advanced features such as AI summaries, dashboards, or external integrations.

The MVP focuses on a simple but realistic workflow:

1. Load local security log files.
2. Parse basic authentication events.
3. Detect suspicious failed-login patterns.
4. Print structured alerts.
5. Keep the system easy to understand, test, and extend.

This project should teach both Python fundamentals and practical cybersecurity engineering habits.

## Layered Pipeline Architecture

The project uses a layered pipeline architecture. Each layer has one clear responsibility and passes data to the next layer.

```text
Local Log File
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
```

This architecture is intentionally simple. A beginner should be able to trace the application from input to output without needing to understand complex frameworks.

## Data Flow Overview

The expected MVP data flow is:

1. `main.py` receives a local file path from the command line.
2. `loader.py` reads the log file and returns raw text lines.
3. `parser.py` converts matching log lines into structured `LogEvent` objects.
4. `detector.py` analyzes `LogEvent` objects for suspicious failed-login patterns.
5. `formatter.py` converts alerts into readable structured output.
6. `main.py` prints alerts and a short run summary.

The core idea is to separate raw text handling from security detection logic. This makes the code easier to debug and safer to extend.

## Module Responsibilities

### `models.py`

Defines shared data structures such as:

- `LogEvent`
- `Alert`
- `RunStats`

These models should use Python dataclasses and type hints so data is easy to inspect and understand.

### `loader.py`

Responsible for safely reading local log files.

It should:

- Accept a file path.
- Validate that the path exists.
- Confirm the path points to a file.
- Read text lines using safe encoding behavior.
- Return raw lines to the parser.

It should not parse or analyze log content.

### `parser.py`

Responsible for converting raw log lines into normalized events.

It should:

- Look for known authentication log patterns.
- Extract fields such as timestamp, username, source IP, and event type.
- Return `LogEvent` objects for recognized lines.
- Skip unsupported or irrelevant lines safely.

It should not decide whether activity is suspicious.

### `detector.py`

Responsible for security detection rules.

For MVP v1, it should detect repeated failed logins from the same IP address within a time window.

It should:

- Receive parsed `LogEvent` objects.
- Group relevant events by source IP.
- Apply simple threshold-based detection.
- Return structured `Alert` objects.

### `formatter.py`

Responsible for output formatting.

It should:

- Convert alerts into readable structured output.
- Print alert details consistently.
- Print a basic run summary.

It should not contain detection or parsing logic.

### `main.py`

Responsible for orchestration.

It should:

- Parse command-line arguments.
- Call the loader, parser, detector, and formatter in order.
- Handle high-level errors gracefully.
- Return a clear success or failure exit code.

## Security and Safety Philosophy

Security log data must always be treated as untrusted input.

Important safety rules:

- Never execute content from logs.
- Do not pass log content into shell commands.
- Keep parsing logic defensive and simple.
- Skip malformed lines instead of crashing when possible.
- Avoid writing sensitive log data to unexpected locations.
- Use sanitized sample logs for development.
- Prefer deterministic behavior so results are reproducible.

The tool should help developers learn safe cybersecurity engineering practices from the beginning.

## Why Docker Dev Containers Are Used

Docker Dev Containers provide a consistent development environment.

Benefits include:

- Everyone uses the same Python version and tooling.
- The project is isolated from the host machine.
- Setup is easier for beginners.
- Experiments can be contained and repeated safely.
- Future dependencies can be added in a controlled way.

For a cybersecurity learning project, isolation and reproducibility are especially useful.

## Future Extensibility Goals

The MVP should remain small, but the architecture should allow future growth.

Possible future improvements include:

- Additional parsers for more log formats.
- More detection rules.
- JSON output mode.
- Unit and integration test expansion.
- Configuration files for thresholds.
- AI-generated alert summaries.
- Dashboard or web interface.
- SIEM-style export formats.

These features should be added gradually after the MVP is stable and easy to understand.