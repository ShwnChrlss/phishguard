# =============================================================
#  backend/app/utils/auth_helpers.py
#  JWT Authentication Helpers & Route Decorators
# =============================================================
#
#  CONCEPT: JWT (JSON Web Token)
#
#  The login flow:
#    1. User sends username + password to POST /api/auth/login
#    2. Server verifies password with bcrypt
#    3. Server creates a JWT token and sends it back
#    4. User stores the token (localStorage in the browser)
#    5. Every future request includes the token in the header:
#         Authorization: Bearer eyJhbGci...
#    6. Server verifies the token on every protected route
#
#  What a JWT looks like:
#    eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxfQ.abc123
#    |___ header ________|.___ payload ________|._ sig _|
#
#  Three parts separated by dots:
#    Header:  algorithm used (HS256)
#    Payload: your data {"user_id": 1, "exp": 1234567890}
#    Signature: HMAC(header + payload, SECRET_KEY)
#
#  The signature is what makes tokens secure. Without the
#  SECRET_KEY, an attacker cannot forge a valid token.
#  If they change the payload (e.g. user_id=999), the
#  signature won't match and verification fails.
#
#  CONCEPT: Python Decorators
#
#  A decorator wraps a function with extra behaviour:
#
#    @require_auth               ← decorator applied here
#    def get_profile():
#        ...
#
#  This is exactly equivalent to:
#    get_profile = require_auth(get_profile)
#
#  require_auth receives get_profile as an argument,
#  returns a NEW function that:
#    1. Checks the JWT token
#    2. If valid, calls the original get_profile()
#    3. If invalid, returns 401 without calling get_profile
#
#  This lets us protect routes with one line instead of
#  copying the token-checking code into every route.
# =============================================================

import jwt
import logging
from datetime import datetime, timezone
from functools import wraps
from typing import Optional, Callable

from flask import request, jsonify, current_app, g

logger = logging.getLogger(__name__)


# =============================================================
#  TOKEN FUNCTIONS
# =============================================================

def create_token(user_id: int, role: str) -> str:
    """
    Creates a signed JWT token for a successfully logged-in user.

    The token payload contains:
      user_id : int   → who this token belongs to
      role    : str   → their permission level
      iat     : int   → issued at (Unix timestamp)
      exp     : int   → expires at (Unix timestamp)

    CONCEPT: Why include role in the token?
      Without role: every protected route would need a DB query
      to look up the user's role. With role in the token, the
      server can check permissions without touching the database.
      Trade-off: if you change a user's role, old tokens still
      show the old role until they expire. Acceptable for 24hr tokens.

    Args:
        user_id: The user's database id.
        role:    Their role string ("admin", "analyst", "user").

    Returns:
        A signed JWT string ready to send to the client.
    """
    now = datetime.now(timezone.utc)
    expiry = current_app.config.get("JWT_EXPIRY")

    payload = {
        "user_id": user_id,
        "role":    role,
        "iat":     now,
        "exp":     now + expiry,
    }

    token = jwt.encode(
        payload,
        current_app.config["SECRET_KEY"],
        algorithm=current_app.config.get("JWT_ALGORITHM", "HS256"),
    )

    return token


def verify_token(token: str) -> Optional[dict]:
    """
    Verifies a JWT token and returns its payload if valid.

    Checks:
      1. Signature is valid (token wasn't tampered with)
      2. Token hasn't expired (exp timestamp in the future)
      3. Token was issued by us (correct SECRET_KEY)

    Args:
        token: The raw JWT string from the Authorization header.

    Returns:
        The decoded payload dict if valid, None if invalid/expired.
    """
    try:
        payload = jwt.decode(
            token,
            current_app.config["SECRET_KEY"],
            algorithms=[current_app.config.get("JWT_ALGORITHM", "HS256")],
        )
        return payload

    except jwt.ExpiredSignatureError:
        logger.debug("Token rejected: expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.debug("Token rejected: %s", e)
        return None


def get_token_from_request() -> Optional[str]:
    """
    Extracts the JWT token from the Authorization header.

    Expected header format:
        Authorization: Bearer eyJhbGci...

    Returns the token string, or None if header is missing/malformed.
    """
    auth_header = request.headers.get("Authorization", "")

    # Header must start with "Bearer " (note the space)
    if not auth_header.startswith("Bearer "):
        return None

    # Split "Bearer eyJhbGci..." → ["Bearer", "eyJhbGci..."]
    # [1] takes the token part
    parts = auth_header.split(" ", 1)
    if len(parts) != 2:
        return None

    return parts[1].strip()


# =============================================================
#  DECORATORS
# =============================================================
#
#  CONCEPT: functools.wraps
#
#  When you wrap a function with a decorator, the wrapper
#  function REPLACES the original. This causes a problem:
#
#    @require_auth
#    def get_profile():
#        """Gets the user profile."""
#        ...
#
#    print(get_profile.__name__)  → "wrapper" (WRONG!)
#    print(get_profile.__doc__)   → None      (WRONG!)
#
#  @wraps(func) copies the original function's __name__,
#  __doc__, and other metadata onto the wrapper:
#
#    print(get_profile.__name__)  → "get_profile" (correct)
#    print(get_profile.__doc__)   → "Gets the user profile." (correct)
#
#  This matters for Flask, which uses function names as
#  "endpoint names" for URL routing. Two routes with the
#  same __name__ would cause an AssertionError.
#
#  CONCEPT: Flask's `g` object
#
#  flask.g is a request-scoped storage object.
#  It exists for ONE request, then is discarded.
#  We store the verified user info in g so any code
#  called during this request can access it:
#
#    g.user_id  → int
#    g.role     → str
#    g.user     → User object (loaded from DB)
#
#  Without g, every function would need user_id passed
#  as a parameter through the entire call chain.

def require_auth(f: Callable) -> Callable:
    """
    Decorator: rejects requests with missing or invalid JWT tokens.

    Usage:
        @detect_bp.route("/detect", methods=["POST"])
        @require_auth
        def detect_email():
            user_id = g.user_id  ← available after auth passes
            ...

    Returns 401 if:
      - Authorization header is missing
      - Token is malformed
      - Token has expired
      - Token signature is invalid
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = get_token_from_request()

        if not token:
            return jsonify({
                "error":   "unauthorized",
                "message": "Authorization header missing or malformed. "
                           "Include: Authorization: Bearer <token>",
            }), 401

        payload = verify_token(token)
        if not payload:
            return jsonify({
                "error":   "unauthorized",
                "message": "Token is invalid or has expired. Please log in again.",
            }), 401

        # Store verified identity in Flask's request-scoped g object.
        # Any code running during this request can now access g.user_id.
        g.user_id = payload["user_id"]
        g.role    = payload.get("role", "user")

        return f(*args, **kwargs)

    return wrapper


def require_role(*roles: str) -> Callable:
    """
    Decorator factory: restricts a route to specific roles.

    Usage:
        @admin_bp.route("/users")
        @require_auth
        @require_role("admin")
        def list_users():
            ...

        @admin_bp.route("/scans")
        @require_auth
        @require_role("admin", "analyst")
        def list_scans():
            ...

    IMPORTANT: Always apply @require_auth BEFORE @require_role.
    require_role reads g.role which require_auth sets.

    Args:
        *roles: One or more allowed role strings.

    Returns 403 if the authenticated user's role is not in roles.
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(*args, **kwargs):
            user_role = getattr(g, "role", None)

            if user_role not in roles:
                return jsonify({
                    "error":   "forbidden",
                    "message": f"This action requires one of these roles: {list(roles)}. "
                               f"Your role: {user_role}",
                }), 403

            return f(*args, **kwargs)
        return wrapper
    return decorator


def get_current_user():
    """
    Loads and returns the full User object for the current request.

    Caches the result in g.user so we only query the DB once
    even if called multiple times during the same request.

    Returns:
        User object, or None if user_id is not in g or not found.
    """
    if hasattr(g, "user") and g.user is not None:
        return g.user  # already loaded this request

    user_id = getattr(g, "user_id", None)
    if not user_id:
        return None

    from app.models.user import User
    g.user = User.query.get(user_id)
    return g.user