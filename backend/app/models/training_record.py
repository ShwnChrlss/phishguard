# backend/app/models/training_record.py

from datetime import datetime, timezone
from app.extensions import db


class TrainingRecord(db.Model):
    """
    Records one completed quiz or training session per user.

    Each row = one quiz attempt.
    Multiple rows per user = tracks improvement over time:
      Attempt 1: 4/10 (40%)
      Attempt 2: 7/10 (70%)
      Attempt 3: 9/10 (90%) ← progress!
    """

    __tablename__ = "training_records"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # ── FOREIGN KEY ───────────────────────────────────────────
    # Links this record to the user who took the quiz.
    # ondelete="CASCADE": if the user is deleted, their
    # training records are deleted too (unlike SET NULL in alerts).
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── QUIZ DETAILS ──────────────────────────────────────────
    # quiz_type lets us have different quiz categories:
    #   "general"     → general phishing awareness
    #   "url_spotting" → identifying bad URLs
    #   "social_eng"  → social engineering tactics
    quiz_type     = db.Column(db.String(50), nullable=False, default="general")
    score         = db.Column(db.Integer,    nullable=False, default=0)
    total         = db.Column(db.Integer,    nullable=False, default=0)
    time_seconds  = db.Column(db.Integer,    nullable=True)   # how long it took
    badges_earned = db.Column(db.Text,       nullable=True)   # comma-separated

    # ── TIMESTAMP ─────────────────────────────────────────────
    completed_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # ── PROPERTIES ────────────────────────────────────────────
    # CONCEPT: @property
    # These look like attributes but run code when accessed.
    # record.percentage reads cleaner than a function call.

    @property
    def percentage(self) -> float:
        """Score as a percentage. 0.0 if no questions attempted."""
        if not self.total:
            return 0.0
        return round(self.score / self.total * 100, 1)

    @property
    def passed(self) -> bool:
        """True if score is 70% or above (standard passing threshold)."""
        return self.percentage >= 70.0

    @property
    def badge_list(self) -> list:
        """Badges earned as a Python list (decoded from comma-string)."""
        if not self.badges_earned:
            return []
        return [b.strip() for b in self.badges_earned.split(",") if b.strip()]

    # ── SERIALISATION ─────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "user_id":       self.user_id,
            "quiz_type":     self.quiz_type,
            "score":         self.score,
            "total":         self.total,
            "percentage":    self.percentage,
            "passed":        self.passed,
            "time_seconds":  self.time_seconds,
            "badges_earned": self.badge_list,
            "completed_at":  self.completed_at.isoformat() + "Z" if self.completed_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<TrainingRecord id={self.id} user_id={self.user_id} "
            f"score={self.score}/{self.total} ({self.percentage}%)>"
        )