# Library Dependency Explorer — production image
# stdlib-only Python app; no pip install needed at runtime.
FROM --platform=linux/amd64 python:3.11-slim

# Non-root user for ECS/Fargate
RUN groupadd -r lde && useradd -r -g lde -d /app -s /sbin/nologin lde

WORKDIR /app

# Copy application source
COPY --chown=lde:lde . .

# /app/data is the EFS mount point for the SQLite DB and runs/ directory.
# Create it here so the volume mount works even without a pre-existing EFS.
RUN mkdir -p /app/data && chown lde:lde /app/data

USER lde

# Expose the default port; ECS task definition overrides via PORT env var.
EXPOSE 8002

# Environment defaults — overridden by ECS task definition / Secrets Manager
ENV PORT=8002 \
    LDE_DATA_DIR=/app/data

# Disable the filesystem watcher (inotify not needed; ECS restarts on deploy).
CMD ["python3", "server.py", "--host", "0.0.0.0", "--no-reload"]
