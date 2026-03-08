# =============================================================
#  backend/app/routes/detect.py
#  Email Detection Route — The Core Endpoint
# =============================================================
#
#  THIS IS THE HEART OF PHISHGUARD.
#
#  POST /api/detect receives an email, runs it through the
#  ML model, saves the result to the database, creates an
#  alert if high risk, and returns the full analysis.
#
#  REQUEST → RESPONSE FLOW:
#
#    Browser/Client
#        │  POST /api/detect
#        │  {"email_text": "URGENT: verify now..."}
#        ▼
#    detect_email()
#        │
#        ├─ validate input
#        ├─ PhishingDetectorService.predict()   ← ML model
#        ├─ EmailScan.create_from_result()      ← save to DB
#        ├─ Alert.create_from_scan()            ← alert if risky
#        └─ return JSON result
#        │
#        ▼
#    {"status":"success", "data": {"label":"phishing",
#     "risk_score":93, "explanation":[...]}}
# =============================================================

import logging
from flask import Blueprint, request, g
from app.extensions import db
from app.models.email_scan import EmailScan
from app.models.alert import Alert
from app.utils.auth_helpers import require_auth, get_current_user
from app.utils.responses import success, error
from app.services.detector import PhishingDetectorService

logger = logging.getLogger(__name__)

detect_bp = Blueprint("detect", __name__)


@detect_bp.route("/detect", methods=["POST"])
@require_auth
def detect_email():
    """
    POST /api/detect
    Analyses an email for phishing indicators.

    Requires: Authorization: Bearer <token>

    Request body (JSON):
        {
            "email_text":    "Full email body here...",  (required)
            "email_subject": "Your account is suspended", (optional)
            "email_sender":  "security@paypa1.com"        (optional)
        }

    Response 200:
        {
            "status": "success",
            "data": {
                "scan_id":     42,
                "label":       "phishing",
                "is_phishing": true,
                "risk_score":  93,
                "confidence":  0.93,
                "explanation": ["🚨 IP address in URL...", ...],
                "alert_created": true,
                "status":      "quarantined"
            }
        }
    """
    # ── 1. PARSE REQUEST ──────────────────────────────────────
    data = request.get_json(silent=True)

    if not data:
        return error("Request body must be JSON.", 400)

    email_text    = data.get("email_text",    "").strip()
    email_subject = data.get("email_subject", "").strip() or None
    email_sender  = data.get("email_sender",  "").strip() or None

    if not email_text:
        return error("email_text is required.", 400, "missing_field")

    from flask import current_app
    max_len = current_app.config.get("MAX_EMAIL_LENGTH", 50_000)
    if len(email_text) > max_len:
        return error(
            f"Email text too long. Maximum {max_len} characters.",
            400, "too_long"
        )

    # ── 2. RUN ML MODEL ───────────────────────────────────────
    detector = PhishingDetectorService.get_instance()
    result   = detector.predict_safe(email_text)

    if not result.get("model_ready"):
        # Model not trained yet — still save the scan with
        # unknown result so the admin knows attempts are happening
        logger.warning("Detection attempted but model not ready.")

    # ── 3. SAVE SCAN TO DATABASE ──────────────────────────────
    # get_current_user() loads the User from the DB using g.user_id
    # set by @require_auth. Returns None if somehow not found.
    current_user = get_current_user()
    user_id = current_user.id if current_user else None

    scan = EmailScan.create_from_result(
        email_body    = email_text,
        result        = result,
        user_id       = user_id,
        email_subject = email_subject,
        email_sender  = email_sender,
        source        = "api",
    )
    db.session.add(scan)
    db.session.flush()   # assigns scan.id without committing yet
                         # flush() sends SQL to DB but keeps transaction open
                         # commit() would permanently write and close transaction
                         # We flush first so scan.id exists for Alert.scan_id

    # ── 4. CREATE ALERT IF HIGH RISK ──────────────────────────
    alert_created = False
    alert_threshold = 65  # create alert above this risk score

    if result.get("is_phishing") and result.get("risk_score", 0) >= alert_threshold:
        alert = Alert.create_from_scan(scan)

        # Tag the target's department if we know the user
        if current_user:
            alert.target_email      = current_user.email
            alert.target_department = current_user.department

        db.session.add(alert)
        alert_created = True
        logger.warning(
            "Alert created: risk=%d user=%s",
            result["risk_score"],
            user_id,
        )

    # ── 5. COMMIT EVERYTHING ──────────────────────────────────
    # One commit writes BOTH the scan and alert atomically.
    # CONCEPT: Atomic transactions
    # If anything fails between flush() and commit(), NEITHER
    # the scan NOR the alert is saved. The database stays
    # consistent — no orphaned alerts pointing to non-existent scans.
    db.session.commit()

    logger.info(
        "Scan complete: id=%d risk=%d label=%s",
        scan.id, result.get("risk_score", 0), result.get("label")
    )

    # ── 6. RETURN RESULT ──────────────────────────────────────
    return success({
        "scan_id":       scan.id,
        "label":         result.get("label", "unknown"),
        "is_phishing":   result.get("is_phishing", False),
        "risk_score":    result.get("risk_score", 0),
        "confidence":    result.get("confidence", 0.0),
        "explanation":   result.get("explanation", []),
        "alert_created": alert_created,
        "status":        scan.status,
        "model_ready":   result.get("model_ready", False),
    })


@detect_bp.route("/scans/history", methods=["GET"])
@require_auth
def scan_history():
    """
    GET /api/scans/history
    Returns the current user's scan history.

    Query params:
        page  (int, default 1)
        limit (int, default 20, max 100)
    """
    page  = request.args.get("page",  1,  type=int)
    limit = min(request.args.get("limit", 20, type=int), 100)

    current_user = get_current_user()
    if not current_user:
        return error("User not found.", 404)

    # CONCEPT: Pagination
    # .paginate() splits results into pages instead of loading
    # all rows at once. With 10,000 scans, loading all would
    # be slow and waste memory. Pagination keeps responses fast.
    pagination = (
        EmailScan.query
        .filter_by(user_id=current_user.id)
        .order_by(EmailScan.scanned_at.desc())
        .paginate(page=page, per_page=limit, error_out=False)
    )

    return success({
        "scans":       [s.to_dict() for s in pagination.items],
        "total":       pagination.total,
        "page":        page,
        "pages":       pagination.pages,
        "has_next":    pagination.has_next,
        "has_prev":    pagination.has_prev,
    })

# ── NEW: .eml file upload endpoint ───────────────────────────
import os
from werkzeug.utils import secure_filename
from app.services.email_parser import parse_eml

ALLOWED_EXTENSIONS = {'.eml', '.msg'}
MAX_FILE_SIZE_MB   = 5

@detect_bp.route('/detect/upload', methods=['POST'])
@require_auth
def upload_eml():
    """
    POST /api/detect/upload
    Accepts a .eml file, parses it, runs ML detection.

    CONCEPT: secure_filename()
    Never trust the filename from the user.
    "../../../../etc/passwd" is a valid filename browsers send.
    secure_filename() strips path traversal characters.

    CONCEPT: File size limit
    Without a size check, users could upload gigabyte files
    and crash the server. Always validate before reading.
    """
    # 1. Check file was actually attached
    if 'file' not in request.files:
        return error("No file attached — include file in multipart/form-data", 400)

    uploaded = request.files['file']

    if not uploaded.filename:
        return error("No file selected", 400)

    # 2. Validate file extension
    _, ext = os.path.splitext(secure_filename(uploaded.filename))
    if ext.lower() not in ALLOWED_EXTENSIONS:
        return error(f"Invalid file type '{ext}'. Only .eml files accepted.", 400)

    # 3. Validate file size
    uploaded.seek(0, 2)           # seek to end
    size_mb = uploaded.tell() / (1024 * 1024)
    uploaded.seek(0)              # seek back to start
    if size_mb > MAX_FILE_SIZE_MB:
        return error(f"File too large ({size_mb:.1f}MB). Maximum is {MAX_FILE_SIZE_MB}MB.", 400)

    # 4. Parse the .eml file
    try:
        raw    = uploaded.read()
        parsed = parse_eml(raw)
    except Exception as e:
        logger.error("EML parse failed: %s", e)
        return error("Could not parse the .eml file. Is it a valid email file?", 400)

    if not parsed['body']:
        return error("Could not extract email body from file.", 400)

    # 5. Run ML detection — same logic as /api/detect
    # We reuse the existing detector service directly
    detector = PhishingDetectorService.get_instance()
    
    result   = detector.predict_safe(parsed['combined'])

    # 6. Save scan to database
    current_user = get_current_user()
    user_id      = current_user.id if current_user else None

    scan = EmailScan(
        user_id          = user_id,
        email_body       = parsed['body'],
        email_subject    = parsed['subject'],
        email_sender     = parsed['sender'],
        is_phishing      = result['is_phishing'],
        risk_score       = result['risk_score'],
        confidence       = result.get('confidence', 0.0),
        source           = 'eml_upload',
        status           = 'quarantined' if result['is_phishing'] else 'safe',
        explanation_json = str(result.get('explanation', [])),
    )
    db.session.add(scan)
    db.session.flush()

    # 7. Create alert if phishing detected
    alert_created = False
    alert_threshold = 60
    if result.get('is_phishing') and result.get('risk_score', 0) >= alert_threshold:
        from app.models.alert import Alert
        alert = Alert.create_from_scan(scan)
        if current_user:
            alert.target_email      = current_user.email
            alert.target_department = current_user.department
        db.session.add(alert)
        alert_created = True

    db.session.commit()

    return success({
        'scan_id':       scan.id,
        'is_phishing':   result['is_phishing'],
        'risk_score':    result['risk_score'],
        'confidence':    result.get('confidence', 0.0),
        'explanation':   result.get('explanation', []),
        'alert_created': alert_created,
        'parsed_email':  {
            'subject':          parsed['subject'],
            'sender':           parsed['sender'],
            'recipients':       parsed['recipients'],
            'links':            parsed['links'],
            'has_attachments':  parsed['has_attachments'],
            'attachment_names': parsed['attachment_names'],
        }
    })