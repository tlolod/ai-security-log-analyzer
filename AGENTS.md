# AI Assistant Guidance for AI Security Log Analyzer

This file guides AI assistants and contributors working on the AI Security Log Analyzer project.

The project is intended to be a beginner-friendly cybersecurity learning tool. Keep the code clear, safe, and maintainable.

## Project Principles

- Use Python 3.12.
- Keep code beginner-friendly.
- Prefer readability over cleverness or optimization.
- Keep the MVP scope small and maintainable.
- Explain architectural changes before implementing them.
- Favor security-conscious coding practices.
- Treat log data as untrusted input.

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
Loader -> Parser -> Detector -> Formatter
```

Module responsibilities should remain separate:

- Loading code should only read input.
- Parsing code should only convert raw text into structured events.
- Detection code should only apply security rules.
- Formatting code should only prepare output for humans or machines.
- `main.py` should orchestrate the pipeline without holding complex business logic.

## Security Rules

- Never execute log content.
- Never pass raw log content into shell commands.
- Do not add automated blocking or remediation in MVP v1.
- Validate local file paths before reading.
- Handle malformed log lines safely.
- Avoid printing secrets in examples or tests.
- Use sanitized sample logs only.
- Keep regular expressions simple and understandable.

## Dependency Rules

- Do not install packages without explicit approval.
- Prefer Python standard library tools for MVP v1.
- If a dependency is proposed, explain why it is needed first.
- Keep `requirements.txt` minimal.

## Testing Rules

- Add tests for parser behavior.
- Add tests for detector behavior.
- Include positive and negative test cases.
- Keep tests readable for beginners.
- Prefer deterministic test data.

## AI Collaboration Rules

- Confirm scope before making changes.
- Explain the planned change before editing files.
- Modify only files relevant to the requested task.
- Do not create Python source code when the user asks for documentation only.
- Do not run commands when the user asks for planning or documentation-only work.
- Ask clarifying questions when requirements are ambiguous.

## MVP v1 Boundaries

Keep the first version focused on:

- Loading local files.
- Parsing simple authentication logs.
- Detecting repeated failed logins.
- Printing structured alerts.
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

The best MVP is small, understandable, and correct.
