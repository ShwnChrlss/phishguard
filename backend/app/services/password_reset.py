# =============================================================
#  backend/app/services/password_reset.py
#  Handles secure password reset token generation and validation
#
#  CONCEPT: secrets vs random
#  secrets.token_urlsafe(32) generates 32 bytes of randomness
#  from the OS entropy pool (/dev/urandom on Linux).
#  This gives 256 bits of entropy — effectively unguessable.
#
#  random.randint() is seeded by time and is PREDICTABLE.
#  Never use random for security tokens.
#
#  CONCEPT: Why we hash the token before storing
#  Raw token lives only in the email.
#  DB stores SHA256(token).
#  If DB is breached: attacker gets hashes, not tokens.
#  On reset: SHA256(submitted_token) == stored_hash → valid.
# =============================================================

import secrets
import hashlib
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

TOKEN_EXPIRY_HOURS = 1  # reset links expire after 1 hour


def generate_reset_token() -> tuple[str, str]:
    """
    Generate a cryptographically secure reset token.

    Returns:
        (raw_token, token_hash)
        raw_token  → goes in the email link
        token_hash → stored in the database

    CONCEPT: tuple return
    We return both values at once so the caller can:
    1. Save the hash to DB
    2. Send the raw token in the email
    Never store the raw token anywhere on the server.
    """
    raw_token  = secrets.token_urlsafe(32)   # 32 bytes = 256 bits
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    return raw_token, token_hash


def get_token_expiry() -> datetime:
    """
    Returns a timezone-aware datetime TOKEN_EXPIRY_HOURS from now.

    CONCEPT: timezone-aware datetimes
    datetime.utcnow() is naive — no timezone info attached.
    datetime.now(timezone.utc) is aware — has UTC attached.
    Always use aware datetimes when storing expiry times
    to avoid timezone confusion bugs.
    """
    return datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS)


def hash_token(raw_token: str) -> str:
    """Hash a raw token for database lookup."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def validate_reset_token(user, raw_token: str) -> tuple[bool, str]:
    """
    Validate a submitted reset token against the stored hash.

    Checks in order:
    1. Token exists on the user record
    2. Token hash matches
    3. Token has not expired
    4. Token has not already been used

    Args:
        user:      User model instance
        raw_token: Raw token from the URL query string

    Returns:
        (is_valid, error_message)
        (True, "")           → token is valid, proceed
        (False, "reason")    → token is invalid, show reason
    """
    # Check 1 — token exists
    if not user.reset_token_hash:
        return False, "No password reset was requested for this account."

    # Check 2 — hash matches
    submitted_hash = hash_token(raw_token)
    if submitted_hash != user.reset_token_hash:
        logger.warning("Reset token hash mismatch for user %s", user.username)
        return False, "Invalid or malformed reset link."

    # Check 3 — not expired
    now = datetime.now(timezone.utc)
    expiry = user.reset_token_expiry
    # Make expiry timezone-aware if stored as naive datetime
    if expiry and expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if not expiry or now > expiry:
        return False, "This reset link has expired. Please request a new one."

    # Check 4 — not already used
    if user.reset_token_used:
        return False, "This reset link has already been used."

    return True, ""


def clear_reset_token(user) -> None:
    """
    Invalidate the reset token after successful use.
    Called after password is successfully changed.
    Token is marked used — cannot be replayed.
    """
    user.reset_token_hash   = None
    user.reset_token_expiry = None
    user.reset_token_used   = True
