# Use the official Python 3.12 image based on Debian Bookworm.
# This provides Python + pip out of the box while keeping the base simple.
FROM python:3.12-bookworm

# Install only essential tooling for this project.
# - git: version control workflows inside the container
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for safer day-to-day development.
# UID/GID 1000 aligns with common local dev environments.
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid ${USER_GID} ${USERNAME} \
    && useradd --uid ${USER_UID} --gid ${USER_GID} -m ${USERNAME} \
    && chsh -s /bin/bash ${USERNAME}

# Default working directory inside the container.
WORKDIR /workspaces/ai-security-log-analyzer
