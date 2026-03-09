# =============================================================
#  backend/app/extensions.py
#  Shared Flask Extension Instances
# =============================================================
#
#  CONCEPT: Why this file exists — solving circular imports
#
#  The problem this file solves:
#
#  Imagine you put db = SQLAlchemy(app) inside __init__.py.
#  Then models/user.py does: from app import db
#  Then __init__.py does:    from app.models import User
#
#  That creates a CIRCULAR IMPORT:
#    __init__.py imports user.py
#    user.py imports __init__.py
#    __init__.py is not fully loaded yet... CRASH.
#
#  The fix — the Extensions Pattern:
#
#    extensions.py:   db = SQLAlchemy()        ← no app, just object
#    models/user.py:  from app.extensions import db  ← safe, no circle
#    __init__.py:     db.init_app(app)          ← attach app later
#
#  Visual flow:
#
#    extensions.py       →  db (unattached)
#    __init__.py         →  db.init_app(app)   (attaches config)
#    models/user.py      →  from extensions import db  (uses it)
#    routes/auth.py      →  from extensions import db  (uses it)
#
#  Everyone imports FROM extensions.py, not from __init__.py.
#  No file imports from __init__.py. Circle broken.
# =============================================================

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS


# ── DATABASE ORM ──────────────────────────────────────────────
# SQLAlchemy() created WITHOUT an app attached.
# The app gets attached later in create_app() via db.init_app(app).
#
# After init_app(), you can use:
#   db.session.add(obj)      → stage an INSERT or UPDATE
#   db.session.commit()      → write staged changes to the DB
#   db.session.rollback()    → undo all changes since last commit
#   db.session.delete(obj)   → stage a DELETE
#   User.query.all()         → SELECT * FROM users
#   User.query.filter_by(id=1).first()  → SELECT WHERE id=1 LIMIT 1
db = SQLAlchemy()


# ── DATABASE MIGRATIONS ───────────────────────────────────────
# Tracks changes to your database schema over time.
#
# SCENARIO without Migrate:
#   You add a "department" column to the User model.
#   You run the app. SQLAlchemy does NOT add the column
#   automatically to an existing database. You'd have to
#   delete the DB and recreate it — losing all your data.
#
# SCENARIO with Migrate:
#   You add the column to the model.
#   Run: flask db migrate -m "add department to users"
#   Run: flask db upgrade
#   The column is added to the live DB. No data lost.
#
# Think of it like Git commits for your database structure.
migrate = Migrate()


# ── CORS ──────────────────────────────────────────────────────
# Cross-Origin Resource Sharing.
#
# THE PROBLEM:
#   Your frontend HTML opens at http://localhost:5500.
#   Your Flask API runs at http://localhost:5000.
#   These are different "origins" (different port = different origin).
#   Browsers enforce the "Same-Origin Policy": JavaScript from
#   one origin CANNOT fetch from another origin. This is a
#   security feature to prevent malicious websites from reading
#   your banking data in the background.
#
# THE SOLUTION:
#   The server adds response headers like:
#     Access-Control-Allow-Origin: *
#   These headers signal to the browser: "I, the server, am okay
#   with requests from other origins. Please allow it."
#   CORS adds these headers automatically based on your config.
#
# NOTE: We restrict which origins in ProductionConfig.
cors = CORS()
# ── RATE LIMITER ──────────────────────────────────────────────
# Flask-Limiter controls how many requests a client can make
# in a given time window.
#
# CONCEPT: key_func — what identifies a "client"?
# get_remote_address  → limits by IP address
#                       used for public endpoints (login, register)
#                       because unauthenticated users have no user ID
#
# We use in-memory storage (default) for development.
# In production you'd use Redis:
#   storage_uri="redis://localhost:6379"
# Redis survives server restarts and works across multiple
# server processes. Memory storage resets on every restart.
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],          # no global limit — set per route
    storage_uri="memory://",
)

# ── EMAIL ─────────────────────────────────────────────────────
# Flask-Mail handles sending emails via SMTP.
# Config keys it reads from app.config:
#   MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD
#   MAIL_USE_TLS, MAIL_DEFAULT_SENDER
from flask_mail import Mail
mail = Mail()
