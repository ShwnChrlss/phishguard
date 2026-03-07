# =============================================================
#  backend/app/models/email_scan.py
# =============================================================
#
#  CONCEPT: Foreign Keys
#  A ForeignKey links one table to another.
#
#  user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
#
#  This means: "user_id in email_scans must match an id
#  in the users table." The database ENFORCES this —
#  you cannot create a scan for a user that doesn't exist.
#
#  Combined with backref="user" in User's relationship,
#  you get bidirectional navigation:
#    scan.user.username      → who submitted this scan
#    user.email_scans.all()  → all scans by this user
# =============================================================

import json
from datetime import datetime, timezone
from app.extensions import db


class EmailScan(db.Model):
    """
    Records every email that was analysed by the ML model.
    This is the audit trail — every scan is permanently logged.

    Why log everything?
      - Users can review their scan history
      - Admins can spot patterns (which department gets targeted most?)
      - Security teams can investigate incidents retrospectively
      - Model retraining: logs become future training data
    """

    __tablename__ = "email_scans"

    # ── PRIMARY KEY ───────────────────────────────────────────
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # ── FOREIGN KEY ───────────────────────────────────────────
    # CONCEPT: db.ForeignKey("users.id")
    # "users.id" means: "the id column in the users table".
    # nullable=True: allows anonymous scans (not logged in).
    # index=True: fast lookup of "all scans by user X".
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ── EMAIL CONTENT ─────────────────────────────────────────
    # db.Text: unlimited length string. Good for email bodies
    # which can be thousands of characters.
    # db.String(n): fixed max length. Good for short fields.
    email_subject = db.Column(db.String(500), nullable=True)
    email_sender  = db.Column(db.String(200), nullable=True)
    email_body    = db.Column(db.Text,        nullable=False)

    # Truncated preview for the dashboard list view.
    # Stored separately so we don't fetch the full body just
    # to show a preview in the admin table.
    email_preview = db.Column(db.String(300), nullable=True)

    # ── ML RESULTS ────────────────────────────────────────────
    is_phishing  = db.Column(db.Boolean, nullable=False, default=False)
    risk_score   = db.Column(db.Integer, nullable=False, default=0)
    # 0-100: 0=definitely safe, 100=definitely phishing
    confidence   = db.Column(db.Float,   nullable=False, default=0.0)
    # 0.0-1.0: model's certainty in its prediction

    # ── EXPLANATION ───────────────────────────────────────────
    # The list of human-readable reasons from detector.py.
    # We store it as a JSON string because SQLite doesn't have
    # a native array/list type. json.dumps() converts the Python
    # list to a string; json.loads() converts it back.
    # PostgreSQL has a native JSON column type — upgrade later.
    explanation_json = db.Column(db.Text, nullable=True)

    # The raw feature dict from the feature extractor.
    # Stored as JSON for the detailed analysis view.
    features_json = db.Column(db.Text, nullable=True)

    # ── STATUS ────────────────────────────────────────────────
    # Workflow states an email scan can be in:
    #   "pending"     → just submitted, not yet reviewed
    #   "quarantined" → auto-quarantined (risk >= threshold)
    #   "reviewed"    → analyst has looked at it
    #   "released"    → quarantine lifted, deemed safe
    #   "confirmed"   → confirmed as real phishing
    status = db.Column(
        db.String(20),
        nullable=False,
        default="pending",
        server_default="pending",
        index=True,
    )

    # Which analyst reviewed this scan (if any)
    reviewed_by = db.Column(db.String(80), nullable=True)
    reviewed_at = db.Column(db.DateTime,   nullable=True)

    # ── SOURCE ────────────────────────────────────────────────
    # How did this scan arrive?
    #   "api"     → submitted via the web dashboard
    #   "gmail"   → auto-scanned from Gmail integration (Phase 6)
    #   "outlook" → auto-scanned from Outlook integration (Phase 6)
    source = db.Column(db.String(20), nullable=True, default="api")

    # ── TIMESTAMPS ────────────────────────────────────────────
    scanned_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # ── PROPERTIES ────────────────────────────────────────────
    # CONCEPT: @property
    # These look like attributes but run code when accessed.
    # They handle the JSON encode/decode transparently so
    # callers never have to call json.loads() themselves.

    @property
    def explanation(self) -> list:
        """Returns explanation as a Python list (decoded from JSON)."""
        if not self.explanation_json:
            return []
        try:
            return json.loads(self.explanation_json)
        except (json.JSONDecodeError, TypeError):
            return []

    @explanation.setter
    def explanation(self, value: list) -> None:
        """Accepts a Python list and stores it as JSON string."""
        self.explanation_json = json.dumps(value) if value else "[]"

    @property
    def features(self) -> dict:
        """Returns features as a Python dict (decoded from JSON)."""
        if not self.features_json:
            return {}
        try:
            return json.loads(self.features_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    @features.setter
    def features(self, value: dict) -> None:
        """Accepts a Python dict and stores it as JSON string."""
        self.features_json = json.dumps(value) if value else "{}"

    # ── SERIALISATION ─────────────────────────────────────────

    def to_dict(self, include_body: bool = False) -> dict:
        """
        Convert to JSON-safe dict for API responses.

        Args:
            include_body: If True, include full email body.
                          Default False — body can be very large.
        """
        data = {
            "id":           self.id,
            "user_id":      self.user_id,
            "email_subject": self.email_subject,
            "email_sender":  self.email_sender,
            "email_preview": self.email_preview,
            "is_phishing":   self.is_phishing,
            "risk_score":    self.risk_score,
            "confidence":    self.confidence,
            "status":        self.status,
            "source":        self.source,
            "explanation":   self.explanation,
            "scanned_at":    self.scanned_at.isoformat() + "Z" if self.scanned_at else None,
            "reviewed_by":   self.reviewed_by,
            "reviewed_at":   self.reviewed_at.isoformat() + "Z" if self.reviewed_at else None,
        }
        if include_body:
            data["email_body"] = self.email_body
            data["features"]   = self.features
        return data

    @classmethod
    def create_from_result(
        cls,
        email_body:    str,
        result:        dict,
        user_id:       int  = None,
        email_subject: str  = None,
        email_sender:  str  = None,
        source:        str  = "api",
    ) -> "EmailScan":
        """
        Factory method: creates an EmailScan from a detector result.

        CONCEPT: Class methods as factories
          Instead of constructing the object and then setting all
          its fields in the caller, a factory method does it in
          one place. The caller just passes the raw data and gets
          back a ready-to-save object.

        Usage:
            result = detector.predict(email_text)
            scan = EmailScan.create_from_result(
                email_body=email_text,
                result=result,
                user_id=current_user.id,
            )
            db.session.add(scan)
            db.session.commit()
        """
        from app.config import BaseConfig

        scan = cls(
            user_id       = user_id,
            email_subject = email_subject,
            email_sender  = email_sender,
            email_body    = email_body,
            email_preview = email_body[:297] + "..." if len(email_body) > 300 else email_body,
            is_phishing   = result.get("is_phishing", False),
            risk_score    = result.get("risk_score",  0),
            confidence    = result.get("confidence",  0.0),
            source        = source,
        )

        # Use the property setters (handles JSON encoding)
        scan.explanation = result.get("explanation", [])
        scan.features    = result.get("features",    {})

        # Auto-quarantine high-risk emails
        threshold = getattr(BaseConfig, "QUARANTINE_THRESHOLD", 70)
        if scan.risk_score >= threshold:
            scan.status = "quarantined"

        return scan

    def __repr__(self) -> str:
        return (
            f"<EmailScan id={self.id} "
            f"risk={self.risk_score} "
            f"label={'phishing' if self.is_phishing else 'safe'} "
            f"status={self.status!r}>"
        )