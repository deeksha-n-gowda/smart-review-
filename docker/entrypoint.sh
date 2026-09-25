#!/bin/bash
# docker/entrypoint.sh — Django Container Entrypoint
# =====================================================
# Runs database migrations and optional dev data seeding before
# starting the main process (gunicorn or manage.py runserver).
#
# Environment variables:
#   SEED_DEV_DATA=true   — runs seed_dev_data management command on first start
#   RUN_MIGRATIONS=true  — runs migrate (default: true)

set -e  # Exit on any error

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║     CodeLens Django Container Starting               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Wait for PostgreSQL if DATABASE_URL is set ────────────────────────────────
if [ -n "$DATABASE_URL" ]; then
    echo "[entrypoint] DATABASE_URL is set — waiting for PostgreSQL..."
    
    # Extract host and port from DATABASE_URL
    # postgresql://user:pass@host:port/dbname
    DB_HOST=$(echo "$DATABASE_URL" | sed -n 's/.*@\([^:\/]*\).*/\1/p')
    DB_PORT=$(echo "$DATABASE_URL" | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')
    DB_PORT=${DB_PORT:-5432}
    
    MAX_RETRIES=30
    RETRY=0
    while ! curl -sf "http://$DB_HOST:$DB_PORT" > /dev/null 2>&1 && [ $RETRY -lt $MAX_RETRIES ]; do
        # Use Python to check TCP connectivity (more reliable than curl for non-HTTP)
        python -c "
import socket, sys
try:
    s = socket.create_connection(('$DB_HOST', $DB_PORT), timeout=2)
    s.close()
    sys.exit(0)
except (socket.error, OSError):
    sys.exit(1)
" && break
        RETRY=$((RETRY + 1))
        echo "[entrypoint] Waiting for PostgreSQL at $DB_HOST:$DB_PORT... (attempt $RETRY/$MAX_RETRIES)"
        sleep 2
    done
    
    if [ $RETRY -eq $MAX_RETRIES ]; then
        echo "[entrypoint] ERROR: PostgreSQL did not become available. Exiting."
        exit 1
    fi
    echo "[entrypoint] PostgreSQL is ready."
fi

# ── Run database migrations ───────────────────────────────────────────────────
RUN_MIGRATIONS="${RUN_MIGRATIONS:-true}"
if [ "$RUN_MIGRATIONS" = "true" ]; then
    echo "[entrypoint] Running database migrations..."
    python manage.py migrate --noinput
    echo "[entrypoint] Migrations complete."
fi

# ── Seed development data (once — skipped when data already exists) ──────────
SEED_DEV_DATA="${SEED_DEV_DATA:-false}"
if [ "$SEED_DEV_DATA" = "true" ]; then
    # Exit 0 = database has no projects (seed it); exit 1 = data exists (skip).
    if python manage.py shell -c \
        "from core.models import Project; import sys; sys.exit(1 if Project.objects.exists() else 0)" \
        >/dev/null 2>&1; then
        echo "[entrypoint] Seeding development data..."
        python manage.py seed_dev_data || \
            echo "[entrypoint] Warning: seed_dev_data failed (continuing)."
    else
        echo "[entrypoint] Projects already exist — skipping seed."
    fi
fi

# ── Create Django superuser if env vars are set ───────────────────────────────
if [ -n "$DJANGO_SUPERUSER_USERNAME" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ] && [ -n "$DJANGO_SUPERUSER_EMAIL" ]; then
    echo "[entrypoint] Creating superuser '$DJANGO_SUPERUSER_USERNAME'..."
    python manage.py createsuperuser \
        --noinput \
        --username "$DJANGO_SUPERUSER_USERNAME" \
        --email    "$DJANGO_SUPERUSER_EMAIL" 2>/dev/null || \
        echo "[entrypoint] Superuser already exists — skipping."
fi

echo "[entrypoint] Starting: $@"
echo ""

# ── Hand off to the main process (gunicorn or runserver) ─────────────────────
exec "$@"
