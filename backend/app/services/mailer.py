# =============================================================
#  backend/app/services/mailer.py
#  Email sending service using Flask-Mail
#
#  CONCEPT: Flask-Mail vs smtplib
#  smtplib is Python's built-in SMTP library — low level.
#  Flask-Mail wraps it with Flask integration:
#  - Reads MAIL_* config from app.config automatically
#  - Provides a clean Message object
#  - Handles connection pooling
#
#  CONCEPT: SMTP (Simple Mail Transfer Protocol)
#  The protocol emails use to travel between servers.
#  Port 587 = STARTTLS (upgrades plain connection to encrypted)
#  Port 465 = SSL/TLS  (encrypted from the start)
#  Port 25  = plain    (no encryption — rejected by most servers)
#
#  FOR DEVELOPMENT: We use Mailtrap — a fake SMTP inbox
#  that catches all emails without delivering them.
#  No real emails sent during development.
#  Sign up free at https://mailtrap.io
# =============================================================

import logging
from flask import current_app, render_template_string
from flask_mail import Mail, Message

logger = logging.getLogger(__name__)
mail   = Mail()

RESET_EMAIL_TEMPLATE = """
<!DOCTYPE html>
<html>
<body style="font-family: monospace; background: #0a0e1a; color: #e0e0e0; padding: 2rem;">
  <div style="max-width: 500px; margin: 0 auto; border: 1px solid #1e3a5f;
              border-radius: 8px; padding: 2rem;">

    <h2 style="color: #00c8ff; margin-top: 0;">🛡 PhishGuard</h2>
    <p>You requested a password reset for your PhishGuard account.</p>

    <p>Click the button below to reset your password.
       This link expires in <strong>1 hour</strong>.</p>

    <div style="text-align: center; margin: 2rem 0;">
      <a href="{{ reset_url }}"
         style="background: #00c8ff; color: #000; padding: .75rem 2rem;
                border-radius: 4px; text-decoration: none;
                font-weight: bold; font-family: monospace;">
        Reset Password
      </a>
    </div>

    <p style="color: #888; font-size: .85rem;">
      If you didn't request this, ignore this email.
      Your password will not change.
    </p>

    <p style="color: #888; font-size: .85rem;">
      Or copy this link into your browser:<br>
      <span style="color: #00c8ff;">{{ reset_url }}</span>
    </p>

  </div>
</body>
</html>
"""


def send_reset_email(user_email: str, username: str, reset_url: str) -> bool:
    """
    Send a password reset email.

    Args:
        user_email: Recipient email address
        username:   For personalisation
        reset_url:  Full URL with token e.g.
                    http://localhost:5000/reset-password?token=abc123

    Returns:
        True if sent successfully, False if failed.
        We return bool not exception — callers shouldn't crash
        if email fails. Log the error and continue gracefully.
    """
    try:
        html_body = render_template_string(
            RESET_EMAIL_TEMPLATE,
            reset_url=reset_url,
            username=username,
        )

        msg = Message(
            subject   = "PhishGuard — Password Reset Request",
            recipients= [user_email],
            html      = html_body,
            sender    = current_app.config.get('MAIL_DEFAULT_SENDER',
                                               'noreply@phishguard.local'),
        )

        mail.send(msg)
        logger.info("Reset email sent to %s", user_email)
        return True

    except Exception as e:
        logger.error("Failed to send reset email to %s: %s", user_email, e)
        return False

