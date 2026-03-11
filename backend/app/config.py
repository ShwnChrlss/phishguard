# =============================================================
#  backend/app/config.py
#  Application Configuration
# =============================================================
#
#  CONCEPT: Configuration Classes & Inheritance
#
#  Your app behaves differently depending on where it runs:
#
#    Your laptop      → debug ON, verbose errors, SQLite file
#    Running tests    → isolated in-memory DB, no Slack alerts
#    Real server      → debug OFF, PostgreSQL, strict security
#
#  We model this with Python class inheritance:
#
#    BaseConfig             ← settings TRUE in every environment
#        ├── DevelopmentConfig   ← your laptop
#        ├── TestingConfig       ← when pytest runs
#        └── ProductionConfig    ← real server
#
#  Inheritance means DevelopmentConfig has ALL of BaseConfig's
#  settings PLUS its own. It only overrides what differs.
#
#  HOW FLASK READS THIS:
#    app.config.from_object(DevelopmentConfig)
#    Flask reads every UPPERCASE attribute as a config value.
#    Lowercase attributes are ignored (use them for comments).
# =============================================================

import os
from datetime import timedelta


class BaseConfig:
    """
    Settings shared by every environment.
    Think: "always true, no matter where the app runs."

    IMPORTANT: Flask only reads UPPERCASE class attributes
    as configuration. That's a Flask convention, not Python.
    """

    # ── FLASK CORE ────────────────────────────────────────────
    # The secret key is used to CRYPTOGRAPHICALLY SIGN:
    #   - JWT login tokens
    #   - Session cookies
    # If an attacker learns this key, they can forge login tokens
    # for any user. It MUST come from the environment, never
    # be hardcoded in source code.
    #
    # os.environ.get("KEY", "fallback") means:
    #   "Read KEY from environment. If missing, use 'fallback'."
    SECRET_KEY: str = os.environ.get(
        "SECRET_KEY",
        "fallback-dev-only-key-never-use-in-production"
    )

    # ── DATABASE ──────────────────────────────────────────────
    # SQLAlchemy reads this URL to know what database to connect.
    # Format: dialect://user:password@host:port/database_name
    # SQLite shortcut: sqlite:///filename.db (3 slashes = relative path)
    # DATABASE_URL environment variable takes priority.
    # Docker sets: postgresql://phishguard:pass@db:5432/phishguard_db
    # Local dev falls back to SQLite (no Docker needed for dev).
    # NOTE: SQLAlchemy 1.4+ requires postgresql:// not postgres://
    # Heroku and some tools still output postgres:// — we fix it here.
    _db_url: str = os.environ.get("DATABASE_URL", "sqlite:///phishguard.db")
    SQLALCHEMY_DATABASE_URI: str = (
        _db_url.replace("postgres://", "postgresql://", 1)
        if _db_url.startswith("postgres://") else _db_url
    )

    # SQLAlchemy can fire events on every object modification.
    # We don't need this feature, and it wastes memory. Off.
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # ── JWT (JSON WEB TOKENS) ─────────────────────────────────
    # How long a login token stays valid before the user must
    # log in again. timedelta lets us express this clearly.
    # int() conversion: os.environ always returns strings,
    # timedelta(hours=) needs an integer.
    JWT_EXPIRY: timedelta = timedelta(
        hours=int(os.environ.get("JWT_EXPIRY_HOURS", "24"))
    )

    # The algorithm used to sign JWT tokens.
    # HS256 = HMAC with SHA-256. Fast and secure for our use.
    JWT_ALGORITHM: str = "HS256"

    # ── PHISHGUARD DETECTION THRESHOLDS ──────────────────────
    # When a risk score hits this value, the email is moved
    # to quarantine automatically.
    # 70 means: "if the model is 70% confident it's phishing,
    # quarantine it". Admins can review and release if wrong.
    QUARANTINE_THRESHOLD: int = 70

    # Risk score that triggers an immediate Slack/Teams alert.
    ALERT_THRESHOLD: int = 80

    # Maximum characters we'll process from one email body.
    # Protects against someone sending a 100MB email to crash us.
    MAX_EMAIL_LENGTH: int = 50_000

    # ── CORS ──────────────────────────────────────────────────
    # Which browser origins can call this API.
    # "*" = any origin (fine for development).
    # ProductionConfig overrides this to only your real domain.
    CORS_ORIGINS: list = ["*"]

    # ── LOGGING ───────────────────────────────────────────────
    # Controls how much the app prints.
    # DEBUG < INFO < WARNING < ERROR < CRITICAL
    # DEBUG shows everything. WARNING shows only problems.
    LOG_LEVEL: str = "INFO"


    # ── EMAIL (Flask-Mail) ───────────────────────────────────
    # CONCEPT: Mailtrap for development
    # Mailtrap is a fake SMTP inbox — catches all outgoing emails
    # without actually delivering them. Perfect for development.
    # Sign up free at https://mailtrap.io
    # Then set these in your .env file:
    #   MAIL_USERNAME=your_mailtrap_username
    #   MAIL_PASSWORD=your_mailtrap_password
    MAIL_SERVER:   str  = os.environ.get('MAIL_SERVER',   'sandbox.smtp.mailtrap.io')
    MAIL_PORT:     int  = int(os.environ.get('MAIL_PORT', '2525'))
    MAIL_USE_TLS:  bool = True
    MAIL_USERNAME: str  = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD: str  = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER: str = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@phishguard.local')


class DevelopmentConfig(BaseConfig):
    """
    Your LOCAL laptop environment.

    Key additions vs BaseConfig:
    - DEBUG = True  → Flask shows detailed error tracebacks
                      and restarts automatically on file save
    - SQLALCHEMY_ECHO → prints every SQL query (helpful to see
                        what queries your code generates)
    """

    DEBUG: bool = True
    TESTING: bool = False

    # Set to True to see every SQL statement in the terminal.
    # Useful when debugging slow queries, but noisy day-to-day.
    SQLALCHEMY_ECHO: bool = False

    LOG_LEVEL: str = "DEBUG"


class TestingConfig(BaseConfig):
    """
    Used ONLY when pytest runs your automated tests.

    Key differences:
    - In-memory SQLite database (":memory:") — created fresh
      for every test run, destroyed when tests finish.
      Your real dev database is never touched.
    - TESTING = True tells Flask to raise exceptions instead
      of returning 500 error pages (makes test failures clear).
    - Slack alerts disabled (don't ping your team during tests).
    - Short JWT expiry so token-expiry tests run fast.
    """

    TESTING: bool = True
    DEBUG: bool = True

    # ":memory:" = SQLite entirely in RAM.
    # Pros: blazing fast, perfectly isolated, auto-cleaned.
    # Cons: data is gone when tests finish (that's the point).
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"

    # Disable Slack/email notifications during tests.
    SLACK_WEBHOOK_URL: str = ""

    # Short expiry makes it practical to test "token expired" cases.
    JWT_EXPIRY: timedelta = timedelta(minutes=5)

    LOG_LEVEL: str = "ERROR"  # suppress output during test runs


class ProductionConfig(BaseConfig):
    """
    A real server with real users.

    Key differences:
    - DEBUG = False  → no error details shown to users
    - SECRET_KEY must exist (crashes loudly if missing rather
      than running insecurely — "fail loud" is safer)
    - Restricted CORS (only your actual frontend domain)
    - PostgreSQL recommended over SQLite for concurrent users
    """

    DEBUG: bool = False
    TESTING: bool = False

    # "Fail loud" on missing secret key.
    # If SECRET_KEY is not set in production, we crash at startup
    # with a clear error rather than running with a weak default.
    # This is intentional: a production app with no secret key
    # is a security disaster waiting to happen.
    @classmethod
    def validate(cls):
        """Call this at startup to assert all required vars exist."""
        required = ["SECRET_KEY", "DATABASE_URL"]
        missing = [k for k in required if not os.environ.get(k)]
        if missing:
            raise EnvironmentError(
                f"Missing required environment variables for production: {missing}\n"
                f"Set them in your server's environment or .env file."
            )

    # Lock CORS down to only your real frontend domain.
    # Replace with actual URL when deploying.
    CORS_ORIGINS: list = [
        os.environ.get("FRONTEND_URL", "https://yourdomain.com")
    ]

    LOG_LEVEL: str = "WARNING"


# =============================================================
#  CONFIG REGISTRY
#  Maps the FLASK_ENV string → config class.
#  Used by get_config() below.
# =============================================================

_config_map = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config():
    """
    Reads FLASK_ENV from the environment and returns the
    matching configuration class (not an instance).

    Defaults to DevelopmentConfig so that forgetting to set
    FLASK_ENV never accidentally puts you in production mode.

    Usage in create_app():
        app.config.from_object(get_config())

    Returns:
        A config CLASS (Flask calls from_object on it, reading
        all uppercase attributes as config values).
    """
    env = os.environ.get("FLASK_ENV", "development").lower().strip()
    config_class = _config_map.get(env)

    if config_class is None:
        print(
            f"⚠️  Unknown FLASK_ENV='{env}'. "
            f"Valid options: {list(_config_map.keys())}. "
            f"Defaulting to DevelopmentConfig."
        )
        config_class = DevelopmentConfig

    return config_class