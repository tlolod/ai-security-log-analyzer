# AI Assistant Guidance for AI Security Log Analyzer

This file guides AI assistants and contributors working on the AI Security Log Analyzer project.

The project is intended to be a beginner-friendly cybersecurity learning tool. Keep the code clear, safe, maintainable, and deterministic.

## Current Implemented System

The current MVP includes:

- Docker Dev Container workflow
- Python 3.12 project structure
- SSH authentication log parsing
- Failed-login event extraction
- Brute-force detection rule
- Suspicious username detection rule
- IP allowlist suppression
- JSON configuration system
- Configurable severity policy
- Detection rule metadata
- JSON alert export
- Alert summary statistics
- pytest unit test suite
- GitHub Actions CI workflow
- Git feature-branch workflow

## Project Principles

- Use Python 3.12.
- Keep code beginner-friendly.
- Prefer readability over cleverness or optimization.
- Keep the MVP scope small and maintainable.
- Explain architectural changes before implementing them.
- Favor security-conscious coding practices.
- Treat log data and config data as untrusted input.
- Prefer deterministic behavior that is easy to test and explain.

## Coding Style Rules

- Use type hints for functions and methods.
- Use dataclasses for simple data models.
- Prefer small, focused modules.
- Prefer small, focused functions.
- Avoid global mutable state.
- Avoid unnecessary abstractions in MVP v1.
- Use clear names that describe purpose.
- Add comments when they help beginners understand why code exists.

## Architecture Rules

Follow the layered pipeline architecture:

```text
Config + CLI -> Loader -> Parser -> Detector -> Formatter
```

Module responsibilities should remain separate:

- `config.py` should load and validate runtime settings.
- Loading code should only read input.
- Parsing code should only convert raw text into structured events.
- Detection code should only apply security rules.
- Formatting code should only prepare output for humans or machines.
- `main.py` should orchestrate the pipeline without holding complex business logic.

Do not move parsing, detection, config validation, and output responsibilities into the same module unless the architecture is intentionally revised and documented first.

## Security Rules

- Never execute log content.
- Never pass raw log content into shell commands.
- Do not add automated blocking or remediation in MVP v1.
- Validate local file paths before reading.
- Handle malformed log lines safely.
- Treat config files as untrusted input.
- Reject invalid config values clearly.
- Avoid printing secrets in examples or tests.
- Use sanitized sample logs only.
- Keep regular expressions simple and understandable.

## Config Rules

- Keep the config schema small and explicit.
- Update `config/default_config.json`, tests, and docs together when config behavior changes.
- Reject unknown config keys unless a deliberate schema change is being made.
- Validate value types before use.
- Validate IP address strings before adding them to `allowed_ips`.
- Normalize severity values and usernames consistently.
- Use `severity_policy` for alert severities instead of hardcoding severities inside detection alerts.

## Detection Rule Rules

- Keep detection behavior deterministic.
- Every detection rule should have stable metadata:
  - `rule_id`
  - `rule_name`
  - `rule_version`
  - `alert_type`
- Preserve existing rule IDs and alert types unless intentionally versioning behavior.
- Add positive and negative tests for each rule.
- Respect `allowed_ips` suppression where appropriate.
- Keep detection rules explainable for beginners.
- Do not add external threat intelligence, machine learning, or automated response actions in MVP v1 unless explicitly requested.

## Formatter and Output Rules

- Formatter code owns console output, alert summaries, run summaries, and JSON export.
- Keep alert JSON output deterministic.
- Do not write files from parser or detector modules.
- Update docs when alert fields or JSON export structure changes.
- Avoid adding output formats before the current formatter behavior is well tested.

## Dependency Rules

- Do not install packages without explicit approval.
- Prefer Python standard library tools for MVP v1.
- If a dependency is proposed, explain why it is needed first.
- Keep dependency files minimal.
- Current development dependencies are listed in `requirements-dev.txt`.
- `pytest` is currently the only development dependency.

## Testing Rules

- Add tests for parser behavior.
- Add tests for detector behavior.
- Add tests for config validation when config behavior changes.
- Add tests for formatter behavior when output behavior changes.
- Include positive and negative test cases.
- Keep tests readable for beginners.
- Prefer deterministic test data.
- Run tests before completing implementation changes:

```bash
PYTHONPATH=src python -m pytest
```

Recommended next test additions:

- Loader tests.
- CLI orchestration tests for `main.py`.

## Documentation Rules

- Update documentation when changing architecture, CLI flags, config keys, alert schema, detection rules, CI, or development workflow.
- Keep README examples aligned with real commands.
- Keep `docs/architecture.md` aligned with module responsibilities.
- Keep `docs/mvp-v1-plan.md` aligned with completed and upcoming milestones.
- Keep `docs/dev-notes.md` useful for future contributors.
- Do not create Python source code when the user asks for documentation only.

## AI Collaboration Rules

- Confirm scope before making changes.
- Explain the planned change before editing files.
- Modify only files relevant to the requested task.
- Do not create Python source code when the user asks for documentation only.
- Do not run commands when the user asks for planning or documentation-only work.
- Ask clarifying questions when requirements are ambiguous.
- Inspect relevant files before proposing broad changes.
- Avoid inventing unimplemented features in documentation.

## MVP v1 Boundaries

Keep the first version focused on:

- Loading local files.
- Parsing simple SSH authentication logs.
- Detecting repeated failed logins.
- Detecting failed logins against suspicious usernames.
- Supporting small JSON configuration.
- Suppressing known allowed IPs.
- Printing structured alerts and summaries.
- Exporting JSON alerts.
- Teaching beginner-friendly Python and cybersecurity concepts.

Do not add the following to MVP v1 unless explicitly requested:

- AI summaries.
- Web dashboards.
- Databases.
- Real-time streaming.
- External API calls.
- SIEM integrations.
- Machine learning.
- Automated response actions.
- Complex plugin systems.

The best MVP is small, understandable, and correct.
