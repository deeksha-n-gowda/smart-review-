# docker/Dockerfile — Django Backend Container
# ==============================================
# Multi-stage build:
#   Stage 1 (builder): installs Python deps into a venv
#   Stage 2 (runtime): copies only the venv + app code — no build tools in final image
#
# This keeps the final image small (~300 MB vs ~900 MB with all build deps).
#
# Build (from project root):
#   docker build -f docker/Dockerfile -t codelens-django .
#
# Run standalone:
#   docker run -p 8000:8000 --env-file .env codelens-django

# ── Stage 1: Build / dependency installation ─────────────────────────────────
FROM python:3.11-slim-bookworm AS builder

WORKDIR /build

# Install system dependencies required by some Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first so Docker caches the pip install layer
COPY requirements.txt .

# Create a venv and install all deps into it
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip --quiet && \
    pip install --no-cache-dir -r requirements.txt --quiet

# ── Stage 2: Runtime image ────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS runtime

LABEL maintainer="Capstone Team"
LABEL description="CodeLens AI Code Review — Django Backend"
LABEL version="1.0"

# Runtime system dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the venv from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create non-root user for security
RUN groupadd --gid 1001 appgroup && \
    useradd  --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

# Set working directory
WORKDIR /app

# Copy the entire backend directory
COPY backend/ .

# Copy frontend (Django serves it in dev; nginx serves it in prod)
COPY frontend/ /app/frontend/

# Create directories for media/static files
RUN mkdir -p /app/staticfiles /app/mediafiles && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Environment defaults (override via docker-compose or --env-file)
ENV DJANGO_SETTINGS_MODULE=config.settings
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUTF8=1
# Keep collectstatic/media output inside /app. The bare settings values would
# resolve to /staticfiles and /mediafiles (root-owned → collectstatic failed
# silently, and the compose media volume never received uploads).
ENV STATIC_ROOT=/app/staticfiles
ENV MEDIA_ROOT=/app/mediafiles
ENV PORT=8000

# Collect static files — strict: a silent failure here means no admin CSS in
# production.
RUN python manage.py collectstatic --noinput --clear

# Expose Django port
EXPOSE 8000

# Health check — $PORT-aware for Render's dynamic port
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/api/v1/health/ || exit 1

# Entrypoint script handles migrations + gunicorn startup
USER root
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && chown appuser:appgroup /entrypoint.sh
USER appuser

# Shell form (not JSON) so $PORT / $GUNICORN_WORKERS expand at container start:
# Render assigns a dynamic port; local runs and compose fall back to the
# Dockerfile ENV PORT=8000. entrypoint.sh execs this via `sh -c`.
ENTRYPOINT ["/entrypoint.sh"]
CMD gunicorn config.wsgi:application \
    --bind 0.0.0.0:${PORT:-8000} \
    --workers ${GUNICORN_WORKERS:-4} \
    --timeout 120 \
    --access-logfile - \
    --error-logfile -
