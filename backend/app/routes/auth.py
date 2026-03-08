# =============================================================
#  backend/app/routes/auth.py
#  Authentication routes: register, login, profile, logout
# =============================================================

import logging
from flask import Blueprint, request, g
from app.extensions import db, limiter
from app.models.user import User
from app.utils.auth_helpers import create_token, require_auth, get_current_user
from app.utils.responses import success, error, created

logger  = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    """
    POST /api/auth/register
    Public endpoint — any visitor can create a USER account.

    SECURITY: Role is ALWAYS forced to "user" regardless of
    what the client sends. Admins are created by existing
    admins via POST /api/admin/users — never via self-signup.
    This prevents privilege escalation at registration.
    """
    data = request.get_json(silent=True)
    if not data:
        return error("Request body must be JSON.", 400)

    username = data.get("username", "").strip()
    email    = data.get("email",    "").strip().lower()
    password = data.get("password", "")

    # Presence checks
    if not username:
        return error("Username is required.", 400)
    if not email:
        return error("Email is required.", 400)
    if not password:
        return error("Password is required.", 400)

    # Format checks
    if len(username) < 3:
        return error("Username must be at least 3 characters.", 400)
    if len(password) < 8:
        return error("Password must be at least 8 characters.", 400)
    if "@" not in email:
        return error("Invalid email address.", 400)

    # Uniqueness checks
    if User.query.filter_by(username=username).first():
        return error(f"Username '{username}' is already taken.", 409)
    if User.query.filter_by(email=email).first():
        return error(f"Email '{email}' is already registered.", 409)

    # SECURITY: force role = "user" — ignore any role in the request body
    user = User(
        username   = username,
        email      = email,
        role       = "user",           # ← always "user", never from client
        department = data.get("department"),
        full_name  = data.get("full_name"),
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    token = create_token(user.id, user.role)
    logger.info("New user registered: %s (%s)", username, email)

    return created({
        "user":  user.to_dict(include_sensitive=True),
        "token": token,
    }, message="Account created successfully.")


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10 per 15 minutes")
def login():
    """
    POST /api/auth/login
    Verifies credentials and returns a JWT token.

    SECURITY: Identical error for wrong username and wrong
    password — prevents username enumeration attacks.
    """
    data = request.get_json(silent=True)
    if not data:
        return error("Request body must be JSON.", 400)

    password = data.get("password", "")
    username = data.get("username", "").strip()
    email    = data.get("email",    "").strip().lower()

    if not password:
        return error("Password is required.", 400)
    if not username and not email:
        return error("Username or email is required.", 400)

    user = (
        User.query.filter_by(username=username).first()
        if username
        else User.query.filter_by(email=email).first()
    )

    # Same message for both cases (intentional)
    if not user or not user.check_password(password):
        return error("Invalid credentials.", 401)

    if not user.is_active:
        return error("This account has been deactivated. Contact your admin.", 401)

    user.record_login()
    db.session.commit()

    token = create_token(user.id, user.role)
    logger.info("User logged in: %s (role=%s)", user.username, user.role)

    return success({
        "user":  user.to_dict(include_sensitive=True),
        "token": token,
    }, message="Login successful.")


@auth_bp.route("/me", methods=["GET"])
@require_auth
def get_me():
    """
    GET /api/auth/me
    Returns the profile of the currently authenticated user.
    """
    user = get_current_user()
    if not user:
        return error("User not found.", 404)
    return success(user.to_dict(include_sensitive=True))


@auth_bp.route("/logout", methods=["POST"])
@require_auth
def logout():
    """
    POST /api/auth/logout
    JWT is stateless — logout is handled client-side by
    deleting the token from localStorage. Server just confirms.
    """
    logger.info("User logged out: user_id=%s", g.user_id)
    return success(message="Logged out. Please delete your token.")