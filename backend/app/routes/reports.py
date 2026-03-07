# =============================================================
#  backend/app/routes/reports.py
#  Analytics and reporting API endpoints
#
#  Endpoints:
#    GET  /api/reports/summary    — Key stats for the reports page
#    GET  /api/reports/timeline   — Scan counts over time (for charts)
#    GET  /api/reports/top-senders — Most frequent phishing senders
#    GET  /api/reports/export     — Download data as JSON
#
#  All routes require at minimum analyst role.
# =============================================================

import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from flask import Blueprint

from app.models.alert import Alert
from app.models.email_scan import EmailScan
from app.models.user import User
from app.utils.auth_helpers import require_auth, require_role
from app.utils.responses import success, error

logger    = logging.getLogger(__name__)
reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/reports/summary", methods=["GET"])
@require_auth
@require_role("admin", "analyst")
def get_summary():
    """
    Returns high-level statistics for the reports page.

    CONCEPT: Aggregation in SQLAlchemy
    .count() runs SELECT COUNT(*) — it only returns a number,
    not the actual rows. This is much faster than loading all rows.

    Example:
        EmailScan.query.count()
        → SELECT COUNT(*) FROM email_scan;   → 1500
    """
    total_scans    = EmailScan.query.count()
    total_phishing = EmailScan.query.filter_by(is_phishing=True).count()
    total_safe     = EmailScan.query.filter_by(is_phishing=False).count()
    total_quarantine = EmailScan.query.filter_by(status="quarantined").count()
    total_users    = User.query.filter_by(is_active=True).count()
    total_alerts   = Alert.query.count()
    pending_alerts = Alert.query.filter_by(status="pending").count()
    critical_alerts = Alert.query.filter_by(severity="critical").count()

    detection_rate = round(
        (total_phishing / total_scans * 100) if total_scans > 0 else 0.0,
        1,
    )

    return success({
        "total_scans":      total_scans,
        "total_phishing":   total_phishing,
        "total_safe":       total_safe,
        "total_quarantine": total_quarantine,
        "total_users":      total_users,
        "total_alerts":     total_alerts,
        "pending_alerts":   pending_alerts,
        "critical_alerts":  critical_alerts,
        "detection_rate":   detection_rate,
        "generated_at":     datetime.utcnow().isoformat(),
    })


@reports_bp.route("/reports/timeline", methods=["GET"])
@require_auth
@require_role("admin", "analyst")
def get_timeline():
    """
    Returns daily scan counts for the past 30 days.
    Used to draw the bar chart on the reports page.

    CONCEPT: defaultdict
    A defaultdict(int) is a dict that returns 0 for any missing key.
    This means we don't need to check "is this date in my dict yet?"
    before incrementing — it just works.

    Normal dict:
        counts["2026-03-01"] += 1  ← KeyError if key missing!

    defaultdict(int):
        counts["2026-03-01"] += 1  ← starts at 0, becomes 1. Safe.
    """
    days = 30
    cutoff = datetime.utcnow() - timedelta(days=days)

    # Load only scans from the last 30 days
    scans = (
        EmailScan.query
        .filter(EmailScan.scanned_at >= cutoff)
        .with_entities(EmailScan.scanned_at, EmailScan.is_phishing)
        .all()
    )

    # Bucket by date string "YYYY-MM-DD"
    phishing_by_day = defaultdict(int)
    safe_by_day     = defaultdict(int)

    for scan in scans:
        day = scan.scanned_at.strftime("%Y-%m-%d")
        if scan.is_phishing:
            phishing_by_day[day] += 1
        else:
            safe_by_day[day] += 1

    # Build ordered list of the last 30 days
    labels   = []
    phishing = []
    safe     = []

    for i in range(days, -1, -1):
        day = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        labels.append(day)
        phishing.append(phishing_by_day[day])
        safe.append(safe_by_day[day])

    return success({
        "labels":   labels,
        "phishing": phishing,
        "safe":     safe,
        "days":     days,
    })


@reports_bp.route("/reports/top-senders", methods=["GET"])
@require_auth
@require_role("admin", "analyst")
def get_top_senders():
    """
    Returns the top 10 phishing sender addresses.

    CONCEPT: Counter
    Counter is a dict subclass from Python's collections module.
    Counter(["a", "b", "a", "a"]) → Counter({"a": 3, "b": 1})
    .most_common(10) returns the top 10 by count.
    """
    # Fetch sender addresses for phishing emails only
    rows = (
        EmailScan.query
        .filter_by(is_phishing=True)
        .with_entities(EmailScan.email_sender)
        .all()
    )

    senders = [r.email_sender for r in rows if r.email_sender]
    counts  = Counter(senders).most_common(10)

    return success({
        "top_senders": [
            {"sender": sender, "count": count}
            for sender, count in counts
        ]
    })


@reports_bp.route("/reports/export", methods=["GET"])
@require_auth
@require_role("admin")
def export_data():
    """
    Exports all scan data as a JSON download.
    Admin-only — contains full email content.

    CONCEPT: HTTP Content-Disposition header
    When we set Content-Disposition: attachment; filename="..."
    the browser treats the response as a file download rather
    than displaying it inline.

    We use flask.Response with the right headers to trigger this.
    """
    from flask import Response
    import json

    scans = EmailScan.query.order_by(EmailScan.scanned_at.desc()).all()

    export_data = {
        "exported_at":  datetime.utcnow().isoformat(),
        "total_records": len(scans),
        "scans": [s.to_dict(include_body=False) for s in scans],
    }

    json_string = json.dumps(export_data, indent=2, default=str)
    filename    = f"phishguard_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"

    return Response(
        json_string,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )