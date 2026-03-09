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

# =============================================================
#  PASSWORD RESET ROUTES
#  Two endpoints:
#  1. POST /api/auth/forgot-password
#     Accepts email, generates token, sends reset email.
#
#  2. POST /api/auth/reset-password
#     Accepts token + new password, validates and updates.
# =============================================================

@auth_bp.route("/forgot-password", methods=["POST"])
@limiter.limit("5 per hour")
def forgot_password():
    """
    POST /api/auth/forgot-password
    Body: { "email": "user@example.com" }

    SECURITY CONCEPT: Always return the same response
    whether the email exists or not.

    BAD:
      "No account found" → attacker learns valid emails
      "Reset email sent" → attacker knows email is registered

    GOOD:
      Always: "If that email exists, a reset link was sent."
      Attacker learns nothing about which emails are registered.
      This is called "user enumeration prevention".
    """
    from app.services.password_reset import generate_reset_token, get_token_expiry
    from app.services.mailer import send_reset_email
    from flask import url_for

    data  = request.get_json() or {}
    email = data.get('email', '').strip().lower()

    if not email:
        return error("Email is required.", 400)

    # Always return success — never reveal if email exists
    SAFE_RESPONSE = success({
        "message": "If that email address is registered, a reset link has been sent."
    })

    user = User.query.filter_by(email=email).first()
    if not user:
        # User not found — return same response anyway
        logger.info("Password reset requested for unknown email: %s", email)
        return SAFE_RESPONSE

    if not user.is_active:
        logger.info("Password reset for inactive user: %s", user.username)
        return SAFE_RESPONSE

    # Generate secure token
    raw_token, token_hash = generate_reset_token()

    # Save hash to DB — never the raw token
    user.reset_token_hash   = token_hash
    user.reset_token_expiry = get_token_expiry()
    user.reset_token_used   = False
    db.session.commit()

    # Build reset URL — points to frontend reset page
    reset_url = f"{request.host_url}reset-password?token={raw_token}"

    # Send email — if it fails, log but don't crash
    sent = send_reset_email(user.email, user.username, reset_url)
    if not sent:
        logger.error("Failed to send reset email for user: %s", user.username)

    logger.info("Password reset initiated for user: %s", user.username)
    return SAFE_RESPONSE


@auth_bp.route("/reset-password", methods=["POST"])
@limiter.limit("10 per hour")
def reset_password():
    """
    POST /api/auth/reset-password
    Body: { "token": "raw_token", "password": "NewPass123!" }

    Validates the token then updates the password.
    Token is invalidated after use — cannot be replayed.
    """
    from app.services.password_reset import validate_reset_token, clear_reset_token

    data     = request.get_json() or {}
    token    = data.get('token', '').strip()
    password = data.get('password', '').strip()

    if not token or not password:
        return error("Token and new password are required.", 400)

    # Basic password strength check
    if len(password) < 8:
        return error("Password must be at least 8 characters.", 400)

    # Find user by hashing the submitted token and looking up the hash
    from app.services.password_reset import hash_token
    token_hash = hash_token(token)
    user = User.query.filter_by(reset_token_hash=token_hash).first()

    if not user:
        return error("Invalid or expired reset link.", 400)

    # Validate token fully
    is_valid, reason = validate_reset_token(user, token)
    if not is_valid:
        return error(reason, 400)

    # Update password
    user.set_password(password)

    # Invalidate token — one-time use only
    clear_reset_token(user)

    db.session.commit()

    logger.info("Password reset successful for user: %s", user.username)
    return success({"message": "Password updated successfully. You can now log in."})
