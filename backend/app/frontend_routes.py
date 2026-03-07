# =============================================================
#  backend/app/frontend_routes.py
#  Serves the frontend HTML/CSS/JS files through Flask
#
#  CONCEPT: Why serve frontend through Flask instead of opening
#  the .html file directly?
#
#  When you open file:///home/shwn/.../login.html in a browser,
#  the page's JavaScript tries to call http://localhost:5000/api.
#  The browser blocks this with a CORS error because:
#    Origin:  file://   (your local file)
#    Target:  http://localhost:5000  (a different origin)
#  Browsers treat file:// and http:// as different origins.
#
#  The fix: serve EVERYTHING through Flask on the same origin.
#  Now both the page AND the API are at http://localhost:5000,
#  so there's no cross-origin request at all.
#
#  URL structure:
#    http://localhost:5000/           → login.html
#    http://localhost:5000/dashboard  → dashboard.html
#    http://localhost:5000/detect     → analyzer.html
#    etc.
# =============================================================

import os
from flask import Blueprint, send_from_directory

# Absolute path to the frontend/ folder
# __file__ = backend/app/frontend_routes.py
# Two levels up = project root, then into frontend/
FRONTEND_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "frontend")
)

frontend_bp = Blueprint("frontend", __name__)


@frontend_bp.route("/")
def index():
    """Redirect root to the login page."""
    return send_from_directory(os.path.join(FRONTEND_DIR, "pages"), "login.html")


@frontend_bp.route("/login")
def login_page():
    return send_from_directory(os.path.join(FRONTEND_DIR, "pages"), "login.html")


@frontend_bp.route("/dashboard")
def dashboard_page():
    return send_from_directory(os.path.join(FRONTEND_DIR, "pages"), "dashboard.html")


@frontend_bp.route("/detect")
def detect_page():
    return send_from_directory(os.path.join(FRONTEND_DIR, "pages"), "analyzer.html")


@frontend_bp.route("/chat")
def chat_page():
    return send_from_directory(os.path.join(FRONTEND_DIR, "pages"), "chatbot.html")


@frontend_bp.route("/alerts")
def alerts_page():
    return send_from_directory(os.path.join(FRONTEND_DIR, "pages"), "admin_alerts.html")


@frontend_bp.route("/quarantine")
def quarantine_page():
    return send_from_directory(os.path.join(FRONTEND_DIR, "pages"), "quarantine.html")


@frontend_bp.route("/users")
def users_page():
    return send_from_directory(os.path.join(FRONTEND_DIR, "pages"), "admin_users.html")


@frontend_bp.route("/reports")
def reports_page():
    return send_from_directory(os.path.join(FRONTEND_DIR, "pages"), "reports.html")


# ── STATIC ASSETS ─────────────────────────────────────────────
# Serves frontend/css/*.css and frontend/js/*.js
# The browser requests these as relative paths like ../css/base.css
# which Flask translates to frontend/css/base.css

@frontend_bp.route("/css/<path:filename>")
def serve_css(filename):
    return send_from_directory(os.path.join(FRONTEND_DIR, "css"), filename)


@frontend_bp.route("/js/<path:filename>")
def serve_js(filename):
    return send_from_directory(os.path.join(FRONTEND_DIR, "js"), filename)


@frontend_bp.route("/assets/<path:filename>")
def serve_assets(filename):
    return send_from_directory(os.path.join(FRONTEND_DIR, "assets"), filename)