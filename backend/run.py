# =============================================================
#  backend/run.py
#  Server Entry Point
# =============================================================
#
#  This is the ONLY file you run to start the server:
#    python run.py
#
#  CONCEPT: if __name__ == "__main__"
#
#  Every Python file has a built-in variable: __name__
#
#  When you RUN a file directly:
#    python run.py  →  __name__ is "__main__"
#
#  When a file is IMPORTED by another file:
#    from run import something  →  __name__ is "run"
#
#  The if __name__ == "__main__": check means:
#    "Only execute this block if this file is the entry point,
#     NOT if it was imported from somewhere else."
#
#  Without this guard, importing run.py from a test file would
#  start a live server in the middle of your test suite!
#
#  ORDER OF OPERATIONS IN THIS FILE:
#    1. load_dotenv() → populate os.environ from .env
#    2. create_app()  → build the configured Flask app
#    3. app.run()     → start the development server
#
#  Why load_dotenv() before create_app()?
#    create_app() calls get_config() which reads os.environ.
#    If .env hasn't been loaded yet, os.environ is empty and
#    all our config values fall back to their defaults.
#    So .env must be loaded FIRST.
# =============================================================

import os
import sys

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    print(
        "\nMissing python-dotenv. Use the project virtualenv and install deps:\n"
        "  cd <phishguard-root> && python3 -m venv .venv\n"
        "  source .venv/bin/activate\n"
        "  .venv/bin/pip install -r requirements.txt\n"
        "  cd backend && python3 run.py\n",
        file=sys.stderr,
    )
    raise SystemExit(1) from None

# Fail fast with a clear message if the interpreter is not the venv / deps missing.
try:
    import flask_sqlalchemy  # noqa: F401
except ModuleNotFoundError:
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    venv_py = os.path.join(root, ".venv", "bin", "python")
    print(
        "\nThis Python does not have PhishGuard dependencies (e.g. Flask-SQLAlchemy).\n"
        "You are probably using system `python3` instead of the project venv.\n\n"
        "Option A — activate venv, then run from backend/:\n"
        f"  cd {root}\n"
        "  source .venv/bin/activate\n"
        "  cd backend && python3 run.py\n\n"
        "Option B — one command from repo root (no activate):\n"
        f"  {venv_py} backend/run.py\n\n"
        "If `source .venv/bin/activate` shows (.venv) but imports still fail, the venv\n"
        "was probably copied/moved from another path. Recreate it:\n"
        f"  cd {root} && rm -rf .venv && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt\n\n"
        "If `.venv` does not exist yet:\n"
        f"  cd {root} && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt\n",
        file=sys.stderr,
    )
    raise SystemExit(1) from None

# Step 1: Load .env into os.environ BEFORE importing create_app.
# load_dotenv() looks for .env starting in the current directory
# and walking up until it finds one.
load_dotenv()

# Step 2: Now import create_app (it reads os.environ internally).
from app import create_app

# Step 3: Build the app object.
# create_app() with no arguments auto-reads FLASK_ENV from .env.
app = create_app()


if __name__ == "__main__":
    # Read server settings from .env (with sensible defaults).
    # "0.0.0.0" means "listen on all network interfaces".
    # This lets other devices on your network reach the server.
    # Use "127.0.0.1" if you only want localhost access.
    host  = os.environ.get("FLASK_HOST",  "0.0.0.0")
    port  = int(os.environ.get("FLASK_PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"

    # Pretty startup banner so you know the server is running.
    divider = "=" * 56
    print(f"\n{divider}")
    print("  🛡️  PhishGuard AI — Development Server")
    print(divider)
    print(f"  Server  : http://localhost:{port}")
    print(f"  Health  : http://localhost:{port}/api/health")
    print(f"  Debug   : {'ON — auto-reloads on file save' if debug else 'OFF'}")
    print(f"  Env     : {os.environ.get('FLASK_ENV', 'development')}")
    print(f"  DB      : {os.environ.get('DATABASE_URL', 'sqlite:///phishguard.db')}")
    print(divider)
    print("  Tip: open http://localhost:5000/api/health to verify")
    print("  Press CTRL+C to stop\n")

    # Start the Flask development server.
    #
    # use_reloader=debug:
    #   When debug=True, Flask watches all .py files and restarts
    #   the server automatically when you save changes.
    #   You don't need to manually restart while developing.
    #
    # use_debugger=debug:
    #   Shows the interactive Werkzeug debugger in the browser
    #   when an unhandled exception occurs. Very helpful for
    #   finding bugs. NEVER enable this in production.
    app.run(
        host=host,
        port=port,
        debug=debug,
        use_reloader=debug,
        use_debugger=debug,
    )