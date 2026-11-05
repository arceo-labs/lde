# Library Dependency Explorer — production image
# stdlib Python app plus one runtime package (cryptography, GitHub App JWTs).
FROM --platform=linux/amd64 python:3.11-slim

# Non-root user for ECS/Fargate
RUN groupadd -r lde && useradd -r -g lde -d /app -s /sbin/nologin lde

WORKDIR /app

# Install the one runtime dependency before copying source so the layer caches.
# --only-binary keeps the build to the published wheel (no compiler in -slim).
RUN pip install --no-cache-dir --only-binary=:all: cryptography==46.0.3

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
