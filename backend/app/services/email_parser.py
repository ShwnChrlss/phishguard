# =============================================================
#  backend/app/services/email_parser.py
#  Parses a raw .eml file into a clean dict the detector
#  can use directly.
#
#  CONCEPT: MIME (Multipurpose Internet Mail Extensions)
#  Email was originally designed for plain ASCII text only.
#  MIME extends it to support: HTML, attachments, images,
#  multiple character sets (UTF-8, etc).
#
#  CONCEPT: Why we extract both text and HTML body
#  Phishing emails often hide malicious links only in the
#  HTML version, with innocent-looking plain text as cover.
#  We need both to detect all threats.
# =============================================================

import email
import re
import logging
from email import policy
from typing import Optional

logger = logging.getLogger(__name__)


def parse_eml(raw: bytes) -> dict:
    """
    Parse raw .eml bytes into a structured dict.

    CONCEPT: bytes vs string
    We accept bytes (not string) because uploaded files
    arrive as raw bytes from the browser. We let Python's
    email library handle encoding detection automatically.

    Args:
        raw: Raw .eml file bytes from request.files

    Returns:
        dict with keys: subject, sender, recipients,
        body, html_body, links, has_attachments,
        attachment_names, raw_headers
    """
    # policy=default gives us a modern email object
    # that handles encoding and unicode properly
    msg = email.message_from_bytes(raw, policy=policy.default)

    # ── Extract headers ───────────────────────────────────────
    subject    = _decode_header(msg.get('subject',  '(no subject)'))
    sender     = _decode_header(msg.get('from',     '(unknown)'))
    recipients = _decode_header(msg.get('to',       ''))
    date       = _decode_header(msg.get('date',     ''))
    message_id = _decode_header(msg.get('message-id', ''))

    # ── Extract body parts ────────────────────────────────────
    text_body  = ''
    html_body  = ''
    attachment_names = []

    for part in msg.walk():
        # Skip multipart containers — only process leaf parts
        if part.get_content_maintype() == 'multipart':
            continue

        content_type = part.get_content_type()
        disposition  = str(part.get('content-disposition', ''))

        # CONCEPT: Content-Disposition
        # 'attachment' means it's a file to download
        # 'inline' means it's part of the visible message
        if 'attachment' in disposition:
            fname = part.get_filename()
            if fname:
                attachment_names.append(_decode_header(fname))
            continue

        # Extract plain text body
        if content_type == 'text/plain' and not text_body:
            text_body = _decode_payload(part)

        # Extract HTML body
        elif content_type == 'text/html' and not html_body:
            html_body = _decode_payload(part)

    # ── Extract links from both body versions ─────────────────
    # CONCEPT: Why extract from both?
    # Attackers sometimes put a clean URL in plain text
    # and a malicious URL only in the HTML href attribute.
    # We check both to catch all links.
    links = _extract_links(text_body) + _extract_links(html_body)
    links = list(dict.fromkeys(links))  # deduplicate, preserve order

    # ── Choose best body for ML detector ──────────────────────
    # Prefer plain text — it's cleaner for the ML model.
    # Fall back to HTML stripped of tags if no plain text.
    if text_body:
        detector_body = text_body
    elif html_body:
        detector_body = _strip_html(html_body)
    else:
        detector_body = ''

    # ── Build subject + body combined string for detector ─────
    # The ML model was trained on combined subject + body text.
    # Replicating that here gives the most accurate results.
    combined = f"Subject: {subject}\n\n{detector_body}".strip()

    result = {
        'subject':          subject,
        'sender':           sender,
        'recipients':       recipients,
        'date':             date,
        'message_id':       message_id,
        'body':             detector_body,
        'combined':         combined,      # feeds into ML detector
        'html_body':        html_body,
        'links':            links,
        'has_attachments':  len(attachment_names) > 0,
        'attachment_names': attachment_names,
    }

    logger.info(
        "Parsed .eml | from=%s | subject=%s | links=%d | attachments=%d",
        sender[:40], subject[:40], len(links), len(attachment_names)
    )
    return result


def _decode_header(value: str) -> str:
    """
    CONCEPT: Encoded headers
    Email headers can be encoded in various charsets.
    Example: =?UTF-8?b?VVJHRU5U?= is base64 encoded 'URGENT'
    email.header.decode_header() handles this automatically.
    """
    if not value:
        return ''
    try:
        from email.header import decode_header as _dh
        parts = _dh(str(value))
        decoded = []
        for part, charset in parts:
            if isinstance(part, bytes):
                decoded.append(
                    part.decode(charset or 'utf-8', errors='replace')
                )
            else:
                decoded.append(str(part))
        return ' '.join(decoded).strip()
    except Exception:
        return str(value).strip()


def _decode_payload(part) -> str:
    """
    CONCEPT: Payload decoding
    Email bodies can be encoded as:
    - quoted-printable: =20 means space, =3D means equals
    - base64: entire body is base64 encoded
    get_payload(decode=True) handles both automatically.
    Returns raw bytes which we then decode to string.
    """
    try:
        payload = part.get_payload(decode=True)
        if not payload:
            return ''
        charset = part.get_content_charset() or 'utf-8'
        return payload.decode(charset, errors='replace').strip()
    except Exception as e:
        logger.warning("Payload decode failed: %s", e)
        return ''


def _extract_links(text: str) -> list:
    """
    CONCEPT: Regex for URL extraction
    URLs follow a pattern: protocol://domain/path?params
    We use regex to find all of them in the text.

    Pattern breakdown:
    https?://        → http:// or https://
    [^\s<>"{}|\\^`]+ → any char except whitespace and HTML chars
    """
    if not text:
        return []
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    links   = re.findall(pattern, text, re.IGNORECASE)
    # Also extract href values from HTML
    href_pattern = r'href=["\']?(https?://[^\s"\'<>]+)'
    hrefs        = re.findall(href_pattern, text, re.IGNORECASE)
    return list(set(links + hrefs))


def _strip_html(html: str) -> str:
    """
    CONCEPT: HTML stripping
    Removes all HTML tags leaving only visible text.
    Simple regex approach — good enough for email bodies.
    For production, BeautifulSoup would be more robust.
    """
    # Remove script and style blocks entirely
    text = re.sub(r'<(script|style)[^>]*>.*?</\1>', '', html,
                  flags=re.DOTALL | re.IGNORECASE)
    # Remove all remaining tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Decode common HTML entities
    text = text.replace('&amp;',  '&')
    text = text.replace('&lt;',   '<')
    text = text.replace('&gt;',   '>')
    text = text.replace('&nbsp;', ' ')
    text = text.replace('&#39;',  "'")
    text = text.replace('&quot;', '"')
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text)
    return text.strip()