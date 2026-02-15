FROM python:3.12-slim

# Build arguments for version tracking
ARG VERSION=0.9.0-beta
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

# Use Gunicorn production server with 4 workers
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "4", "--timeout", "120", "app:app"]
