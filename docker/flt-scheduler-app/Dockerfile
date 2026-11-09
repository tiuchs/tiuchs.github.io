FROM python:3.12-slim

# Build arguments for version tracking
ARG VERSION=0.10.2-beta
ARG BUILD_DATE
ARG VCS_REF

# Image metadata following OCI standards
LABEL org.opencontainers.image.title="1-227 AB Flight Scheduler"
LABEL org.opencontainers.image.description="Flight scheduling and management system for 1-227 AB"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${VCS_REF}"
LABEL org.opencontainers.image.vendor="1-227 AB"
LABEL maintainer="1-227 AB"

WORKDIR /app

# Install curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

# Use Gunicorn production server with 8 workers.
# --preload: import app.py once in the master before forking, so the
# module-level init_db()/create_backup()/start_backup_scheduler() calls run
# once instead of once per worker (concurrent workers racing on the same
# SQLite file during startup backup was the cause of prior DB corruption).
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "8", "--timeout", "120", "--preload", "app:app"]
