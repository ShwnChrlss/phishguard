# =============================================================
#  backend/app/__init__.py
#  The Flask Application Factory
# =============================================================
#
#  CONCEPT: The App Factory Pattern
#
#  WHY not just write app = Flask(__name__) at the top of a file?
#
#  The naive approach (works but has problems):
#    # myapp.py
#    app = Flask(__name__)           ← runs on import
#    app.config["DEBUG"] = True      ← hardcoded
#    from .routes import auth        ← imports at module load time
#
#  Problems:
#    1. Tests can't change the config — app is already created
#    2. You can only have one app instance — no test isolation
#    3. Import order issues cause circular import errors
#
#  The Factory Pattern (what we use):
#    # app/__init__.py
#    def create_app(config=None):    ← nothing runs until called
#        app = Flask(__name__)       ← created fresh each call
#        app.config.from_object(config)
#        return app
#
#  Benefits:
#    ✓ run.py calls create_app() → gets a development server app
#    ✓ pytest calls create_app(TestingConfig) → isolated test app
#    ✓ Extensions attach cleanly via init_app()
#    ✓ Blueprint imports happen INSIDE the function (no circular issues)
#
#  WHAT __init__.py DOES:
#    Making a folder a "package" (importable as a module) is
#    what __init__.py does. When Python sees:
#      from app import create_app
#    It looks for backend/app/__init__.py and runs it.
#    The function defined here becomes importable.
# =============================================================

import os
import logging
from flask import Flask, jsonify
from dotenv import load_dotenv

# Load .env BEFORE anything reads os.environ.
# load_dotenv() scans for a .env file starting from the current
# working directory, then parent directories.
# It sets os.environ["SECRET_KEY"] = "your-value", etc.
# for every KEY=VALUE line it finds.
load_dotenv()

from .extensions import db, migrate, cors, limiter, mail
from .config import get_config


def create_app(config_override=None):
    """
    Application factory — the single source of truth for
    creating a configured Flask application.

    Args:
        config_override: A config CLASS to use instead of reading
                         FLASK_ENV. Used in tests:
                           app = create_app(TestingConfig)
                         Pass None to auto-detect from FLASK_ENV.

    Returns:
        A fully configured, ready-to-serve Flask app instance.

    Usage:
        # run.py (start the server):
        app = create_app()
        app.run()

        # conftest.py (pytest setup):
        app = create_app(TestingConfig)
        client = app.test_client()
    """

    # ── 1. CREATE THE FLASK APP OBJECT ────────────────────────
    # __name__ here resolves to "app" (the package name).
    # Flask uses this to locate templates and static files
    # relative to this package's directory.
    app = Flask(__name__)

    # ── 2. LOAD CONFIGURATION ─────────────────────────────────
    # from_object() reads every UPPERCASE attribute from the
    # config class and stores it in app.config.
    # Example: BaseConfig.SECRET_KEY → app.config["SECRET_KEY"]
    if config_override is not None:
        # Tests pass a class directly.
        app.config.from_object(config_override)
    else:
        # Auto-detect from FLASK_ENV environment variable.
        app.config.from_object(get_config())

    # ── 3. SET UP LOGGING ─────────────────────────────────────
    # Python's logging module is better than print() because:
    #   - Logs have levels (DEBUG, INFO, WARNING, ERROR)
    #   - You can route logs to files in production
    #   - You can silence DEBUG logs in production easily
    #
    # getattr(logging, "DEBUG") returns the integer constant
    # logging.DEBUG (= 10). getattr lets us convert the string
    # "DEBUG" from config into the actual logging constant.
    log_level = getattr(logging, app.config.get("LOG_LEVEL", "DEBUG"))
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s  [%(levelname)-8s]  %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger = logging.getLogger(__name__)
    logger.info(
        "Creating PhishGuard app | env=%s | db=%s",
        os.environ.get("FLASK_ENV", "development"),
        app.config.get("SQLALCHEMY_DATABASE_URI", "unknown"),
    )
    if app.config.get("SQLALCHEMY_DATABASE_URI", "").startswith("sqlite:////"):
        logger.info("SQLite file resolved to: %s", app.config["SQLALCHEMY_DATABASE_URI"][10:])

    # ── 4. INITIALISE EXTENSIONS ──────────────────────────────
    # init_app() "attaches" each extension to this specific app.
    # It does NOT create a DB connection yet — that happens
    # lazily on the first request that needs the database.
    # This deferred connection is called "lazy initialisation".
    db.init_app(app)
    migrate.init_app(app, db)

    # CORS: only apply to /api/* routes.
    # resources={r"/api/*": {...}} means: "add CORS headers
    # only to URLs that start with /api/".
    # allow_headers lists which request headers the browser
    # is allowed to send (Content-Type for JSON bodies,
    # Authorization for the JWT token).
    cors.init_app(
        app,
        resources={
            r"/api/*": {
                "origins": app.config.get("CORS_ORIGINS", ["*"]),
                "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"],
            }
        },
    )
    limiter.init_app(app)
    mail.init_app(app)

    # ── 5. REGISTER BLUEPRINTS ────────────────────────────────
    # CONCEPT: Blueprints
    #
    # A Blueprint is a mini-application. Instead of one giant
    # file with every route, we split by domain:
    #   auth_bp   → /api/auth/login, /api/auth/register
    #   detect_bp → /api/detect
    #   chat_bp   → /api/chat
    #   admin_bp  → /api/admin/users, /api/admin/dashboard
    #
    # url_prefix="/api/auth" means every route defined inside
    # auth_bp automatically gets /api/auth prepended.
    # So @auth_bp.route("/login") becomes GET /api/auth/login.
    #
    # We import blueprints INSIDE this function (not at the
    # top of the file) to avoid circular imports. The blueprint
    # files import db from extensions — that's fine. But if we
    # imported them at module load time, before create_app runs,
    # we'd get errors because db isn't attached to an app yet.
    _register_blueprints(app)

    # ── 6. CREATE DATABASE TABLES ─────────────────────────────
    # app_context() is a Flask concept: many operations (like
    # DB access) need to know WHICH app they belong to.
    # Outside of a request, Flask doesn't set this automatically.
    # We push it manually here so db.create_all() works.
    #
    # with app.app_context(): ensures the context is cleaned up
    # when the block ends, even if an error occurs.
    with app.app_context():
        # Import models so SQLAlchemy "sees" their table definitions.
        # Without this import, db.create_all() doesn't know what
        # tables to create. The "noqa: F401" comment tells linters
        # not to warn about "imported but unused" — we DO use them,
        # just implicitly (SQLAlchemy reads the class definitions).
        from .models import user, email_scan, alert, training_record  # noqa: F401

        # Create all tables that don't exist yet.
        # Safe to call multiple times — skips existing tables.
        # For schema CHANGES to existing tables, use Flask-Migrate.
        db_url = app.config.get("SQLALCHEMY_DATABASE_URI", "")
        if db_url.startswith("sqlite"):
            db.create_all()
            logger.info("Database tables verified ✓")
        else:
            logger.info("Database tables verified ✓ (Alembic manages schema)")

    # ── 7. REGISTER ERROR HANDLERS ────────────────────────────
    # By default Flask returns HTML error pages.
    # Our API should always return JSON so the frontend can
    # parse error messages consistently.
    _register_error_handlers(app)

    # ── 8. HEALTH CHECK ROUTE ─────────────────────────────────
    # A simple endpoint to verify the server is alive.
    # Useful for monitoring tools, Docker HEALTHCHECK, load
    # balancers, and a quick manual sanity check.
    @app.route("/api/health")
    def health_check():
        """
        GET /api/health
        Returns 200 OK with basic app info if server is running.
        No authentication required.

        Test it: open http://localhost:5000/api/health in browser.
        """
        return jsonify({
            "status": "ok",
            "app": "PhishGuard AI",
            "version": "1.0.0",
            "environment": os.environ.get("FLASK_ENV", "development"),
        }), 200

    logger.info("PhishGuard AI application ready ✅")
    return app


# =============================================================
#  PRIVATE HELPERS
#  Prefixed with _ to signal they're internal to this module.
# =============================================================

def _register_blueprints(app: Flask) -> None:
    """Imports and registers all route blueprints."""
    try:
        from app.routes.auth   import auth_bp
        from app.routes.detect import detect_bp
        from app.routes.chat   import chat_bp
        from app.routes.admin  import admin_bp
        from app.routes.reports import reports_bp
        from app.frontend_routes import frontend_bp
        from app.routes.ml_dashboard import ml_dashboard_bp
        
        app.register_blueprint(ml_dashboard_bp)
        app.register_blueprint(auth_bp,   url_prefix="/api/auth")
        app.register_blueprint(detect_bp, url_prefix="/api")
        app.register_blueprint(chat_bp,   url_prefix="/api/chat")
        app.register_blueprint(admin_bp,  url_prefix="/api/admin")
        app.register_blueprint(reports_bp, url_prefix="/api")
        app.register_blueprint(frontend_bp)
        

        app.logger.info("All blueprints registered ✓")

    except ImportError as e:
        app.logger.error("Blueprint import failed: %s", e)
        raise

def _register_error_handlers(app: Flask) -> None:
    """
    Replaces Flask's default HTML error pages with JSON responses.

    Every handler returns a dict with:
      "error"   : a machine-readable error code string
      "message" : a human-readable explanation
    This lets the frontend display useful error messages.
    """

    @app.errorhandler(400)
    def bad_request(err):
        """400 — request was malformed (bad JSON, missing field)."""
        return jsonify({
            "error": "bad_request",
            "message": str(err.description),
        }), 400

    @app.errorhandler(401)
    def unauthorized(err):
        """401 — not logged in, or token is invalid/expired."""
        return jsonify({
            "error": "unauthorized",
            "message": "Authentication required. Please log in.",
        }), 401

    @app.errorhandler(403)
    def forbidden(err):
        """403 — logged in but your role can't do this action."""
        return jsonify({
            "error": "forbidden",
            "message": "You do not have permission to perform this action.",
        }), 403

    @app.errorhandler(404)
    def not_found(err):
        """404 — route or resource doesn't exist."""
        return jsonify({
            "error": "not_found",
            "message": "The requested resource was not found.",
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(err):
        """405 — route exists but wrong HTTP method (GET vs POST)."""
        return jsonify({
            "error": "method_not_allowed",
            "message": "HTTP method not allowed on this endpoint.",
        }), 405

    @app.errorhandler(500)
    def internal_error(err):
        """
        500 — unhandled server-side exception.
        We rollback any partial DB transaction first to avoid
        leaving the database in a broken half-written state.
        """
        db.session.rollback()
        app.logger.error("Internal server error: %s", err, exc_info=True)
        return jsonify({
            "error": "internal_server_error",
            "message": "An unexpected error occurred. Please try again.",
        }), 500
