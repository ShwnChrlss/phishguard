# =============================================================
#  backend/app/models/alert.py
# =============================================================
#
#  CONCEPT: When to create a separate table vs add columns
#
#  We could store alert info directly on EmailScan.
#  But alerts have their own lifecycle:
#    - Created when high-risk email detected
#    - Assigned to an analyst
#    - Investigated and resolved
#    - Possibly linked to MULTIPLE scans (bulk campaign)
#
#  Separate table = cleaner data model + easier querying.
#  "Each table should represent ONE thing" — database design rule.
# =============================================================

from datetime import datetime, timezone
from app.extensions import db


class Alert(db.Model):
    """
    Security alert triggered by high-risk email detections.

    Severity levels:
      low      → risk 50-64  (monitor, low priority)
      medium   → risk 65-79  (investigate soon)
      high     → risk 80-89  (investigate today)
      critical → risk 90+    (immediate action)

    Alert types:
      phishing_detected → single high-risk email
      bulk_campaign     → multiple similar phishing emails
      repeat_target     → same user targeted multiple times
    """

    __tablename__ = "alerts"

    # ── PRIMARY KEY ───────────────────────────────────────────
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # ── LINKED SCAN ───────────────────────────────────────────
    # The EmailScan that triggered this alert.
    # ondelete="SET NULL": if the scan is deleted, keep the
    # alert but set scan_id to NULL (don't delete the alert).
    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("email_scans.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ── ALERT DETAILS ─────────────────────────────────────────
    alert_type = db.Column(
        db.String(30),
        nullable=False,
        default="phishing_detected",
        index=True,
    )

    severity = db.Column(
        db.String(10),
        nullable=False,
        default="medium",
        index=True,
    )

    title   = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text,        nullable=False)

    # Risk score from the scan that triggered this alert
    risk_score = db.Column(db.Integer, nullable=False, default=0)

    # ── TARGETING INFO ────────────────────────────────────────
    # Who was the target of this phishing attempt?
    target_email      = db.Column(db.String(200), nullable=True)
    target_department = db.Column(db.String(100), nullable=True)

    # ── STATUS / WORKFLOW ─────────────────────────────────────
    # pending      → alert created, no one has looked at it
    # acknowledged → analyst has seen it, investigating
    # resolved     → handled (false positive or real, dealt with)
    # dismissed    → determined to be a false positive
    status = db.Column(
        db.String(20),
        nullable=False,
        default="pending",
        server_default="pending",
        index=True,
    )

    # Who acknowledged / resolved this alert
    acknowledged_by = db.Column(db.String(80), nullable=True)
    resolved_by     = db.Column(db.String(80), nullable=True)
    resolution_note = db.Column(db.Text,       nullable=True)

    # Slack/Teams notification sent?
    notification_sent = db.Column(db.Boolean, default=False)
    notification_sent_at = db.Column(db.DateTime, nullable=True)

    # ── TIMESTAMPS ────────────────────────────────────────────
    created_at      = db.Column(
        db.DateTime, nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    resolved_at     = db.Column(db.DateTime, nullable=True)

    # ── RELATIONSHIPS ─────────────────────────────────────────
    scan = db.relationship("EmailScan", backref="alerts", lazy="joined")

    # ── CLASS METHODS ─────────────────────────────────────────
    # CONCEPT: @classmethod for querying
    # These are convenience methods on the class itself (not
    # an instance). Alert.get_pending() reads cleaner than
    # Alert.query.filter_by(status="pending").all() everywhere.

    @classmethod
    def get_pending(cls):
        """Returns all unacknowledged alerts, newest first."""
        return (
            cls.query
            .filter_by(status="pending")
            .order_by(cls.created_at.desc())
            .all()
        )

    @classmethod
    def get_critical(cls):
        """Returns all critical-severity unresolved alerts."""
        return (
            cls.query
            .filter(cls.severity == "critical", cls.status != "resolved")
            .order_by(cls.created_at.desc())
            .all()
        )

    @classmethod
    def create_from_scan(cls, scan: "EmailScan") -> "Alert":
        """
        Factory: creates an Alert from a high-risk EmailScan.

        Determines severity from risk_score:
          90+ → critical
          80+ → high
          65+ → medium
          50+ → low
        """
        score = scan.risk_score

        if score >= 90:
            severity = "critical"
        elif score >= 80:
            severity = "high"
        elif score >= 65:
            severity = "medium"
        else:
            severity = "low"

        sender_info = f" from {scan.email_sender}" if scan.email_sender else ""
        subject_info = f": '{scan.email_subject}'" if scan.email_subject else ""

        return cls(
            scan_id    = scan.id,
            alert_type = "phishing_detected",
            severity   = severity,
            risk_score = score,
            title      = f"{severity.upper()} — Phishing detected (risk {score}/100)",
            message    = (
                f"A phishing email{sender_info} was detected{subject_info} "
                f"with a risk score of {score}/100. "
                f"The email has been {'quarantined' if scan.status == 'quarantined' else 'flagged'}."
            ),
            target_email = scan.email_sender,
        )

    # ── SERIALISATION ─────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "id":               self.id,
            "scan_id":          self.scan_id,
            "alert_type":       self.alert_type,
            "severity":         self.severity,
            "title":            self.title,
            "message":          self.message,
            "risk_score":       self.risk_score,
            "status":           self.status,
            "target_email":     self.target_email,
            "target_department": self.target_department,
            "acknowledged_by":  self.acknowledged_by,
            "resolved_by":      self.resolved_by,
            "resolution_note":  self.resolution_note,
            "notification_sent": self.notification_sent,
            "created_at":       self.created_at.isoformat() + "Z" if self.created_at else None,
            "acknowledged_at":  self.acknowledged_at.isoformat() + "Z" if self.acknowledged_at else None,
            "resolved_at":      self.resolved_at.isoformat() + "Z" if self.resolved_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<Alert id={self.id} severity={self.severity!r} "
            f"type={self.alert_type!r} status={self.status!r}>"
        )