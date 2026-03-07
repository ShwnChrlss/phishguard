# =============================================================
#  backend/app/services/notifications.py
#  Slack webhook alerts for high-risk phishing detections
#
#  CONCEPT: Webhooks
#  A webhook is just a URL that accepts HTTP POST requests.
#  Slack creates one per channel. When we POST JSON to it,
#  Slack shows it as a message — no SDK needed, just requests.post()
#
#  SETUP (takes 2 minutes):
#  1. Go to api.slack.com/apps → Create New App → From scratch
#  2. Click "Incoming Webhooks" → turn it On
#  3. "Add New Webhook to Workspace" → pick a channel
#  4. Copy the Webhook URL
#  5. Add to backend/.env:
#       SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxx
#
#  If SLACK_WEBHOOK_URL is missing, notifications are silently
#  skipped — the app works fine without Slack configured.
# =============================================================

import logging
import os

logger = logging.getLogger(__name__)

try:
    import requests as _requests
    _requests_ok = True
except ImportError:
    _requests_ok = False
    logger.warning("'requests' not installed — Slack notifications disabled.")


def _webhook_url():
    """Returns the Slack URL from environment, or None if not set."""
    url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    return url or None


def send_slack_alert(title, message, severity="medium", risk_score=0, scan_id=None):
    """
    Posts a formatted alert to Slack.

    CONCEPT: Slack Block Kit
    Instead of plain text, Slack supports "blocks" — structured
    JSON that renders as rich messages with headers, bold text,
    columns, and dividers. We build the payload as a Python dict
    and requests.post(url, json=payload) converts it to JSON.

    Args:
        title      : Short alert headline
        message    : Full description of the threat
        severity   : "critical" | "high" | "medium" | "low"
        risk_score : 0-100 score from the ML model
        scan_id    : EmailScan database ID (for reference)

    Returns:
        True if Slack accepted the message, False otherwise.
    """
    url = _webhook_url()
    if not url:
        logger.debug("SLACK_WEBHOOK_URL not set — skipping notification.")
        return False
    if not _requests_ok:
        return False

    emoji = {"critical": "🚨", "high": "🔴", "medium": "⚠️", "low": "🔵"}.get(severity, "⚠️")

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} PhishGuard — {severity.upper()} Alert", "emoji": True},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{title}*"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Risk Score:*\n{risk_score}/100"},
                    {"type": "mrkdwn", "text": f"*Scan ID:*\n{'#' + str(scan_id) if scan_id else 'N/A'}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": message},
            },
            {"type": "divider"},
        ]
    }

    try:
        resp = _requests.post(url, json=payload, timeout=5)
        if resp.status_code == 200 and resp.text == "ok":
            logger.info("Slack alert sent: %s (risk=%d)", title, risk_score)
            return True
        logger.warning("Slack returned %d: %s", resp.status_code, resp.text[:80])
        return False
    except _requests.exceptions.RequestException as e:
        logger.warning("Slack notification failed: %s", e)
        return False


def notify_phishing_detected(scan):
    """
    Convenience wrapper: sends a Slack alert from an EmailScan object.
    Called automatically by detect.py when risk_score >= 65.

    Args:
        scan: EmailScan model instance (already saved to DB)
    """
    severity = "critical" if scan.risk_score >= 90 else "high"
    sender   = f" from *{scan.email_sender}*" if scan.email_sender else ""
    subject  = f" — _{scan.email_subject}_"   if scan.email_subject else ""

    lines = "\n".join(f"• {e}" for e in (scan.explanation or [])[:3])

    return send_slack_alert(
        title      = f"Phishing detected{sender}{subject}",
        message    = f"An email{sender} was flagged with risk score *{scan.risk_score}/100*.\n\n{lines}",
        severity   = severity,
        risk_score = scan.risk_score,
        scan_id    = scan.id,
    )