# Development Notes

## Current Setup Status

The project is being developed as a Python 3.12 cybersecurity learning tool with a Docker Dev Container workflow.

Current known status:

- Project name: AI Security Log Analyzer
- Current focus: beginner-friendly cybersecurity log analysis in Python
- Source code exists under `src/log_analyzer/`
- Tests exist under `tests/`
- Default config exists at `config/default_config.json`
- Development dependencies are listed in `requirements-dev.txt`
- `pytest` and `ruff` are the current development dependencies
- GitHub Actions CI runs tests on push and pull request
- Architecture documentation exists in `docs/architecture.md`
- AI assistant guidance exists in `AGENTS.md`

## Docker / Container Workflow Notes

Docker Dev Containers are used to keep the development environment consistent and isolated.

General workflow concepts:

- Open the repository in VS Code.
- Use the Dev Container environment for development.
- Keep project dependencies inside the container.
- Avoid relying on host-machine-specific configuration.
- Prefer reproducible setup steps documented in the repository.

Important container practice:

- Do not install new packages without approval.
- Document any required dependency before adding it.
- Keep the environment simple while the MVP is small.

## Common Development Commands

Install development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

Run lint checks:

```bash
python -m ruff check .
```

Run tests:

```bash
PYTHONPATH=src python -m pytest
```

Run the analyzer against the sample log:

```bash
PYTHONPATH=src python -m log_analyzer.main --file sample_logs/auth_sample.log --year 2026
```

Run with the default JSON config file:

```bash
PYTHONPATH=src python -m log_analyzer.main \
  --file sample_logs/auth_sample.log \
  --config config/default_config.json \
  --year 2026
```

Run with JSON alert export:

```bash
PYTHONPATH=src python -m log_analyzer.main \
  --file sample_logs/auth_sample.log \
  --config config/default_config.json \
  --output alerts.json \
  --year 2026
```

## Git Feature-Branch Workflow

Recommended workflow:

1. Start from the latest main branch.
2. Create a focused feature branch.
3. Make small, reviewable changes.
4. Run Ruff and pytest locally.
5. Update documentation when behavior or workflow changes.
6. Push the branch.
7. Open a pull request.
8. Wait for GitHub Actions CI to pass before merging.

This workflow keeps changes understandable and helps prevent regressions.

## VS Code + Cline Workflow Notes

Cline is being used as an AI-assisted development partner.

Recommended workflow:

1. Plan the architecture before writing code.
2. Keep tasks small and specific.
3. Ask Cline to explain proposed changes before implementation.
4. Ask Cline to inspect relevant tests and docs before editing.
5. Review generated code carefully.
6. Prefer small commits or checkpoints after meaningful progress.
7. Keep MVP scope small.

Good prompts for this project:

- “Explain the architecture before editing files.”
- “Keep this beginner-friendly.”
- “Do not install packages without approval.”
- “Only modify the files needed for this milestone.”
- “Add comments that explain why the code exists.”
- “Update docs if CLI flags, config keys, alert fields, or detection rules change.”
- “Run Ruff and pytest after implementation changes.”

## Current Testing Strategy

The project uses pytest for deterministic unit tests.

Current coverage includes:

- `tests/test_parser.py`: supported SSH failed-login lines and unsupported skipped lines
- `tests/test_detector.py`: brute-force detection, suspicious username detection, allowed IP suppression, severity policy, duplicate suppression, and negative cases
- `tests/test_config.py`: default config, JSON loading, validation, normalization, unknown keys, allowed IPs, and severity policy
- `tests/test_formatter.py`: alert formatting, alert summary statistics, JSON export, and output path validation

Recommended next test additions:

- `loader.py` tests for missing files, directory paths, successful reads, and encoding behavior
- `main.py` tests for CLI orchestration, config overrides, output writing, and error exit codes

## Current Architecture Notes

The project follows this pipeline:

```text
Config + CLI -> Loader -> Parser -> Detector -> Formatter
```

Key module boundaries:

- `config.py` loads and validates runtime settings.
- `loader.py` reads local log files only.
- `parser.py` turns raw text into `LogEvent` objects only.
- `detector.py` applies security rules and returns `Alert` objects.
- `formatter.py` prepares console output, summaries, and JSON export.
- `main.py` orchestrates the pipeline and should stay small.

Keeping these boundaries clear makes the code easier for beginners and safer for future changes.

## Lessons Learned So Far

- A layered pipeline architecture makes log analysis easier to understand.
- Separating loading, parsing, detection, configuration, and formatting keeps modules small.
- Security logs and config files should always be treated as untrusted input.
- Deterministic detection rules are easier to test and explain.
- Rule metadata makes alerts easier to understand and extend.
- Alert summaries help users quickly understand a run.
- Documentation first helps prevent scope creep.
- AI assistants are most useful when given clear constraints.
- GitHub Actions CI provides a useful safety net for feature branches.

## Important Concepts

- **Dataclass**: a simple Python way to define structured data objects.
- **Type hint**: a way to describe expected input and output types.
- **Parser**: code that turns raw text into structured data.
- **Detector**: code that applies security rules to structured events.
- **Alert**: a structured finding that describes suspicious activity.
- **Rule metadata**: stable fields such as rule ID, rule name, and rule version.
- **Threshold**: the number of events needed before something is considered suspicious.
- **Time window**: the period in which events are counted together.
- **Allowlist**: trusted IP addresses that should be suppressed from supported alerts.
- **Severity policy**: config-controlled severity labels for known alert types.
- **Untrusted input**: data that should be handled carefully because it may be malformed or malicious.

## Future Notes

Use this section to record decisions, troubleshooting notes, and lessons from future milestones.

Examples to add later:

- Parser edge cases discovered during testing.
- Detection threshold changes.
- Config schema decisions.
- Alert schema decisions.
- Python dependency decisions.
- Test strategy updates.
- Dev Container improvements.
