# Development Notes

## Current Setup Status

The project is being developed inside a Docker Dev Container.

Current known status:

- Project name: AI Security Log Analyzer
- Current focus: beginner-friendly cybersecurity log analysis in Python
- Existing repository documentation: `README.md`
- Initial architecture planning completed
- Python source code has not been created yet
- Package installation has not been performed yet

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

## VS Code + Cline Workflow Notes

Cline is being used as an AI-assisted development partner.

Recommended workflow:

1. Plan the architecture before writing code.
2. Keep tasks small and specific.
3. Ask Cline to explain proposed changes before implementation.
4. Review generated code carefully.
5. Prefer small commits or checkpoints after meaningful progress.
6. Keep MVP scope small.

Good prompts for this project:

- “Explain the architecture before editing files.”
- “Keep this beginner-friendly.”
- “Do not install packages without approval.”
- “Only modify the files needed for this milestone.”
- “Add comments that explain why the code exists.”

## Lessons Learned So Far

- A layered pipeline architecture makes log analysis easier to understand.
- Separating loading, parsing, detection, and formatting keeps modules small.
- Security logs should always be treated as untrusted input.
- The MVP should focus on one clear detection rule before expanding.
- Documentation first helps prevent scope creep.
- AI assistants are most useful when given clear constraints.

## Important Commands and Concepts

Commands have not been run as part of the current documentation task.

Important concepts to understand before implementation:

- **Dataclass**: a simple Python way to define structured data objects.
- **Type hint**: a way to describe expected input and output types.
- **Parser**: code that turns raw text into structured data.
- **Detector**: code that applies security rules to structured events.
- **Alert**: a structured finding that describes suspicious activity.
- **Threshold**: the number of events needed before something is considered suspicious.
- **Time window**: the period in which events are counted together.
- **Untrusted input**: data that should be handled carefully because it may be malformed or malicious.

Potential future commands may include running tests or executing the CLI, but those should be introduced only after source code exists.

## Future Notes

Use this section to record decisions, troubleshooting notes, and lessons from future milestones.

Examples to add later:

- Parser edge cases discovered during testing.
- Detection threshold changes.
- Python dependency decisions.
- Test strategy updates.
- Dev Container improvements.
