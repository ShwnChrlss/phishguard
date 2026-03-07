# =============================================================
#  backend/app/services/email_parser.py
#  Parses raw .eml files into structured fields
#
#  CONCEPT: What is a .eml file?
#  When you "Save As" or export an email from Gmail/Outlook,
#  you get a .eml file — a text file following RFC 5322 format.
#  It contains headers (From, To, Subject, Date) and a body
#  (which may be plain text, HTML, or multipart with attachments).
#
#  Python's built-in `email` library handles all the parsing.
#  We just extract the parts we need for PhishGuard.
#
#  USAGE:
#    from app.services.email_parser import parse_eml_file
#    result = parse_eml_file("/path/to/email.eml")
#    # result = {"subject": "...", "sender": "...", "body": "..."}
# =============================================================

import email
import logging
import re
from email import policy
from email.parser import BytesParser

logger = logging.getLogger(__name__)


def parse_eml_bytes(raw_bytes: bytes) -> dict:
    """
    Parses a raw .eml file (as bytes) into a structured dict.

    CONCEPT: email.policy.default
    Python's email library has two modes:
    - Legacy mode: returns strings, handles encoding badly
    - policy.default: returns modern email objects, handles
      Unicode, MIME parts, and encoding correctly.
    Always use policy.default for new code.

    Args:
        raw_bytes: Raw content of the .eml file

    Returns:
        Dict with keys: sender, recipients, subject, date,
                        body_text, body_html, attachments, headers
    """
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception as e:
        logger.error("Failed to parse .eml: %s", e)
        return {"error": str(e)}

    # ── HEADERS ──────────────────────────────────────────────
    sender     = _decode_header(msg.get("From",    ""))
    recipients = _decode_header(msg.get("To",      ""))
    subject    = _decode_header(msg.get("Subject", ""))
    date       = _decode_header(msg.get("Date",    ""))
    reply_to   = _decode_header(msg.get("Reply-To",""))

    # ── BODY EXTRACTION ───────────────────────────────────────
    # CONCEPT: MIME multipart
    # Emails can have multiple "parts":
    #   text/plain  — what you read if images are disabled
    #   text/html   — the formatted version
    #   attachments — files embedded in the email
    # We extract all parts and separate them.

    body_text   = ""
    body_html   = ""
    attachments = []

    if msg.is_multipart():
        # Walk through every part of the email
        for part in msg.walk():
            content_type        = part.get_content_type()
            content_disposition = str(part.get_content_disposition() or "")

            if "attachment" in content_disposition:
                # It's a file attachment
                attachments.append({
                    "filename":     part.get_filename() or "unknown",
                    "content_type": content_type,
                    "size":         len(part.get_payload(decode=True) or b""),
                })
            elif content_type == "text/plain" and not body_text:
                body_text = _get_part_text(part)
            elif content_type == "text/html" and not body_html:
                body_html = _get_part_text(part)
    else:
        # Single-part email (simple plain text)
        content_type = msg.get_content_type()
        if content_type == "text/html":
            body_html = _get_part_text(msg)
        else:
            body_text = _get_part_text(msg)

    # If we only have HTML, extract plain text from it
    if not body_text and body_html:
        body_text = _html_to_text(body_html)

    # ── EXTRACT ALL URLs from body ────────────────────────────
    urls = _extract_urls(body_text + " " + body_html)

    return {
        "sender":      _extract_email_address(sender),
        "sender_name": _extract_display_name(sender),
        "reply_to":    _extract_email_address(reply_to),
        "recipients":  recipients,
        "subject":     subject,
        "date":        date,
        "body_text":   body_text.strip(),
        "body_html":   body_html,
        "attachments": attachments,
        "urls":        urls,
        "raw_headers": dict(msg.items()),
    }


def parse_eml_file(filepath: str) -> dict:
    """
    Convenience wrapper: reads a .eml file from disk and parses it.

    Args:
        filepath: Path to the .eml file

    Returns:
        Same dict as parse_eml_bytes, plus {"filepath": filepath}
    """
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
        result = parse_eml_bytes(raw)
        result["filepath"] = filepath
        return result
    except FileNotFoundError:
        return {"error": f"File not found: {filepath}"}
    except Exception as e:
        logger.error("Error reading %s: %s", filepath, e)
        return {"error": str(e)}


# =============================================================
#  PRIVATE HELPERS
# =============================================================

def _decode_header(value: str) -> str:
    """Safely decodes an email header value to a plain string."""
    if not value:
        return ""
    try:
        # email.header.decode_header handles encoded words like:
        # =?UTF-8?B?SGVsbG8gV29ybGQ=?= → "Hello World"
        from email.header import decode_header, make_header
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def _get_part_text(part) -> str:
    """Extracts text from a MIME part, handling encoding."""
    try:
        payload = part.get_payload(decode=True)
        if not payload:
            return ""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    except Exception:
        return ""


def _html_to_text(html: str) -> str:
    """
    Very simple HTML-to-text: strips tags.
    For production, use the 'html2text' library instead.
    """
    # Remove script and style blocks
    html = re.sub(r'<(script|style)[^>]*>.*?</\1>', ' ', html, flags=re.DOTALL | re.IGNORECASE)
    # Remove all other tags
    text = re.sub(r'<[^>]+>', ' ', html)
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def _extract_urls(text: str) -> list:
    """Finds all URLs in a block of text."""
    pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    return list(set(re.findall(pattern, text)))


def _extract_email_address(header_value: str) -> str:
    """Extracts just the email address from 'Display Name <email@domain.com>'."""
    match = re.search(r'<([^>]+)>', header_value)
    if match:
        return match.group(1).strip().lower()
    # No angle brackets — the whole thing might be an email
    raw = header_value.strip().lower()
    if "@" in raw:
        return raw
    return header_value


def _extract_display_name(header_value: str) -> str:
    """Extracts the display name from 'Display Name <email>'."""
    if "<" in header_value:
        return header_value[:header_value.index("<")].strip().strip('"')
    return ""