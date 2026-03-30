# ─────────────────────────────────────────────────────────────
# PhishGuard AI — Dockerfile
#
# WHAT THIS FILE DOES:
#   Defines the container image for the Flask application.
#   Docker reads this file top-to-bottom and builds a layered
#   image. Each instruction = one layer. Layers are cached —
#   unchanged layers are reused on rebuild (fast builds).
#
# BUILD STAGES:
#   We use a single stage here (simple and clear for learning).
#   Production could use multi-stage to reduce image size.
# ─────────────────────────────────────────────────────────────

# BASE IMAGE
# python:3.12-slim is the official Python image stripped of
# unnecessary packages. Full python:3.12 is 1GB. Slim is 150MB.
FROM python:3.12-slim

# WORKING DIRECTORY
# All subsequent commands run from /app inside the container.
# This is like cd /app — but it also creates the dir if missing.
WORKDIR /app

# SYSTEM DEPENDENCIES
# Some Python packages need C compilers or OS libraries.
# psycopg2 needs libpq-dev (PostgreSQL client library).
# We clean apt cache after to keep the image small.
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# PYTHON DEPENDENCIES (separate layer — cached unless requirements change)
# Copy requirements FIRST before copying application code.
# WHY: Docker caches layers. If we copied all code first,
# any code change would invalidate the pip install cache.
# This way, pip only reruns when requirements.txt changes.
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# SECURITY: Don't run as root
# Create the runtime user before copying app code so we can assign
# ownership during COPY instead of doing a slow recursive chown later.
RUN useradd -m -u 1000 phishguard && \
    mkdir -p /app/instance /app/frontend && \
    chown -R phishguard:phishguard /app/instance /app/frontend

# APPLICATION CODE
# Copy the backend application into the container.
COPY --chown=phishguard:phishguard backend/ .

# FRONTEND
# Nginx serves static files directly, but Flask also needs
# the frontend path for its frontend_routes.py blueprint.
COPY --chown=phishguard:phishguard frontend/ /app/frontend/

# ENTRYPOINT SCRIPT
# A shell script that runs migrations then starts Gunicorn.
# Must be executable.
COPY --chown=phishguard:phishguard entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
USER phishguard

# EXPOSE
# Railway routes traffic to the port your container advertises.
# In production Railway injects PORT=8080, and Gunicorn binds to that
# value in entrypoint.sh. Expose 8080 here so Railway and the app agree.
#
# Local docker-compose still works because it explicitly targets port 5000
# on the container network, and Gunicorn keeps using 5000 locally when
# PORT is not set.
EXPOSE 8080

# ENTRYPOINT
# Runs our shell script instead of starting gunicorn directly.
# The script handles: wait for DB → run migrations → start server.
ENTRYPOINT ["/entrypoint.sh"]
