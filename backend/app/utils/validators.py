# =============================================================
#  backend/app/utils/validators.py
#  Input validation for all API routes
#
#  CONCEPT: Why validate?
#  Every value arriving from the internet is untrusted.
#  Validation is the "bouncer" — it checks input BEFORE it
#  reaches the database or ML model.
#
#  PATTERN: Each function returns a tuple:
#    (True,  None)            ← valid
#    (False, "error message") ← invalid, tell the user why
#
#  USAGE in a route:
#    ok, msg = validate_username(data["username"])
#    if not ok:
#        return error(msg, 400)
# =============================================================

import re


def validate_username(username):
    """3–50 chars, letters/numbers/underscores/hyphens only."""
    if not username or not username.strip():
        return False, "Username is required."
    username = username.strip()
    if len(username) < 3:
        return False, "Username must be at least 3 characters."
    if len(username) > 50:
        return False, "Username cannot exceed 50 characters."
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_\-]*[a-zA-Z0-9]$', username) and len(username) > 1:
        return False, "Username can only contain letters, numbers, underscores, and hyphens."
    return True, None


def validate_email(email):
    """Must look like a real email address."""
    if not email or not email.strip():
        return False, "Email is required."
    email = email.strip().lower()
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, f"'{email}' is not a valid email address."
    if len(email) > 254:
        return False, "Email address is too long."
    return True, None


def validate_password(password):
    """
    At least 8 chars, must include a letter and a number.

    CONCEPT: Why not check for special chars?
    Length is the biggest driver of password strength.
    Requiring special chars often makes people choose
    Password1! — weak but technically compliant.
    We keep it simple and sensible for a learning project.
    """
    if not password:
        return False, "Password is required."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    if not any(c.isalpha()  for c in password):
        return False, "Password must contain at least one letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."
    return True, None


def validate_email_text(text, max_length=50_000):
    """
    Validates the email body submitted for phishing analysis.
    Prevents empty or impossibly huge submissions.
    """
    if not text or not text.strip():
        return False, "Email text is required."
    if len(text.strip()) < 10:
        return False, "Email text is too short to analyse (minimum 10 characters)."
    if len(text) > max_length:
        return False, f"Email text too long (max {max_length:,} characters)."
    return True, None


def validate_role(role):
    """Must be one of the three allowed roles."""
    allowed = {"user", "analyst", "admin"}
    if role not in allowed:
        return False, f"Role must be one of: {', '.join(sorted(allowed))}."
    return True, None


def sanitise(value, max_length=200):
    """
    Strips whitespace and truncates to max_length.

    CONCEPT: Sanitisation vs Validation
      Validation  → reject bad input  (return error)
      Sanitisation → clean the input   (return safe version)
    Do BOTH: validate first, sanitise before storing.
    """
    if not value:
        return ""
    return str(value).strip()[:max_length]