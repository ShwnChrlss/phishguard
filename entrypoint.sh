#!/bin/bash
# ─────────────────────────────────────────────────────────────
# PhishGuard Entrypoint Script
#
# Runs inside the container on every startup.
# ORDER MATTERS:
#   1. Wait for PostgreSQL to be ready
#      (DB container starts before app, but isn't immediately ready)
#   2. Run database migrations (create/update tables)
#   3. Start Gunicorn (production WSGI server)
#
# WHY NOT just start Gunicorn directly?
#   If the app starts before PostgreSQL is ready, it crashes.
#   This script adds a retry loop to wait for the DB.
# ─────────────────────────────────────────────────────────────

set -e  # exit immediately on any error

echo "⏳ Waiting for PostgreSQL..."

# Retry loop — try to connect every 2 seconds, up to 30 tries (60s)
until python3 -c "
import psycopg2, os
psycopg2.connect(os.environ['DATABASE_URL'])
print('✅ PostgreSQL is ready')
" 2>/dev/null; do
  echo "   PostgreSQL not ready yet — retrying in 2s..."
  sleep 2
done

echo "🔄 Running database migrations..."
flask db upgrade

echo "🌱 Seeding default users..."
python3 scripts/seed_db.py

echo "🚀 Starting Gunicorn..."
# Gunicorn flags:
#   --workers 4        : 4 parallel worker processes
#   --threads 2        : 2 threads per worker (handles I/O wait)
#   --bind 0.0.0.0:${PORT:-5000}: listen on all interfaces inside container
#   --access-logfile - : send access logs to stdout (docker logs)
#   --error-logfile -  : send error logs to stdout
#   run:app            : the 'app' object inside run.py
exec gunicorn \
  --workers 4 \
  --threads 2 \
  --bind 0.0.0.0:${PORT:-5000} \
  --access-logfile - \
  --error-logfile - \
  --log-level info \
  run:app
