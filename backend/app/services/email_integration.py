# =============================================================
#  backend/app/services/email_integration.py
#  Gmail / Outlook API stubs — Phase 6+ extension point
#
#  CONCEPT: Why this file exists
#  The long-term vision for PhishGuard is to scan emails
#  automatically as they arrive in a real inbox, not just
#  when pasted manually. This requires OAuth2 API access
#  to Gmail or Microsoft Exchange.
#
#  This file provides:
#  1. A clean interface your routes can call NOW
#  2. Stub implementations that return example data
#  3. Clear instructions for wiring up real APIs later
#
#  CONCEPT: Stub / Mock pattern
#  A stub is a placeholder function that returns fake data
#  with the correct shape. It lets you build the calling code
#  (routes, frontend) before the real implementation exists.
#  When you're ready, swap the stub for real code — no other
#  files need to change.
# =============================================================

import logging
from datetime import datetime

logger = logging.getLogger(__name__)


# =============================================================
#  GMAIL INTEGRATION (stub)
#
#  To implement for real:
#  1. pip install google-auth google-auth-oauthlib google-api-python-client
#  2. Go to console.cloud.google.com → Create project
#  3. Enable Gmail API
#  4. Create OAuth2 credentials → Download credentials.json
#  5. Replace the stub below with actual API calls
#
#  Scopes needed:
#    https://www.googleapis.com/auth/gmail.readonly
#    https://www.googleapis.com/auth/gmail.modify  (to mark as read)
# =============================================================

def fetch_gmail_unread(max_results: int = 10) -> list:
    """
    Fetches unread emails from Gmail inbox.

    STUB: Returns example data so the app works without
    real Gmail credentials configured.

    Args:
        max_results: Maximum number of emails to fetch

    Returns:
        List of dicts with keys: id, subject, sender, snippet, date
    """
    logger.info("Gmail integration not configured — returning stub data.")
    return [
        {
            "id":      "stub_001",
            "subject": "Example: Your account requires verification",
            "sender":  "noreply@example-bank.com",
            "snippet": "Please verify your account details to avoid suspension...",
            "date":    datetime.utcnow().isoformat(),
            "source":  "gmail_stub",
        }
    ]


def mark_gmail_as_read(message_id: str) -> bool:
    """
    Marks a Gmail message as read.
    STUB: Always returns True without doing anything.
    """
    logger.debug("Gmail stub: would mark %s as read", message_id)
    return True


def move_gmail_to_label(message_id: str, label: str = "PhishGuard-Quarantine") -> bool:
    """
    Moves a Gmail message to a label (e.g. quarantine folder).
    STUB: Always returns True without doing anything.
    """
    logger.debug("Gmail stub: would move %s to label '%s'", message_id, label)
    return True


# =============================================================
#  MICROSOFT / OUTLOOK INTEGRATION (stub)
#
#  To implement for real:
#  1. pip install msal requests
#  2. Register app at portal.azure.com → Azure Active Directory
#  3. Add Microsoft Graph API permissions:
#     Mail.Read, Mail.ReadWrite
#  4. Replace the stub below with Microsoft Graph API calls:
#     GET https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages
# =============================================================

def fetch_outlook_unread(max_results: int = 10) -> list:
    """
    Fetches unread emails from Outlook/Exchange inbox.
    STUB: Returns example data.
    """
    logger.info("Outlook integration not configured — returning stub data.")
    return []


def get_integration_status() -> dict:
    """
    Returns the connection status of each email integration.
    Used by the admin API to show what's configured.

    Returns:
        Dict with provider → status information
    """
    import os
    return {
        "gmail": {
            "configured": bool(os.environ.get("GMAIL_CREDENTIALS_FILE")),
            "status":     "connected" if os.environ.get("GMAIL_CREDENTIALS_FILE") else "not configured",
            "docs":       "https://developers.google.com/gmail/api/quickstart/python",
        },
        "outlook": {
            "configured": bool(os.environ.get("AZURE_CLIENT_ID")),
            "status":     "connected" if os.environ.get("AZURE_CLIENT_ID") else "not configured",
            "docs":       "https://learn.microsoft.com/en-us/graph/api/user-list-messages",
        },
    }