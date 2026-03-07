# =============================================================
#  backend/app/models/user.py
# =============================================================
#
#  CONCEPT: ORM Model
#  The class IS the database table.
#  An instance of the class IS one row in that table.
#
#  class User(db.Model):          → defines the 'users' table
#      id = db.Column(...)        → defines one column
#
#  user = User(username="alice")  → creates one row (not saved yet)
#  db.session.add(user)           → stages it for saving
#  db.session.commit()            → writes it to the database
#
#  CONCEPT: Column options
#  primary_key=True  → unique id for each row (auto-assigned)
#  nullable=False    → field MUST have a value (NOT NULL in SQL)
#  unique=True       → no two rows can share this value
#  default=value     → value used when none is provided
#  index=True        → builds a fast-lookup index on this column
# =============================================================

import bcrypt
from datetime import datetime, timezone
from app.extensions import db


class User(db.Model):
    """
    One user account. Three roles:
      admin   → full access (manage users, train model)
      analyst → view scans/alerts, manage quarantine
      user    → submit emails, take quizzes, view own history
    """

    __tablename__ = "users"

    # ── IDENTITY ──────────────────────────────────────────────
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    username = db.Column(db.String(80),  unique=True, nullable=False, index=True)
    email    = db.Column(db.String(120), unique=True, nullable=False, index=True)

    # NEVER store a plain password — always store the bcrypt hash
    password_hash = db.Column(db.String(255), nullable=False)

    # ── ROLE & PROFILE ────────────────────────────────────────
    role       = db.Column(db.String(20),  nullable=False, default="user", server_default="user")
    department = db.Column(db.String(100), nullable=True)
    full_name  = db.Column(db.String(150), nullable=True)

    # ── STATUS ────────────────────────────────────────────────
    # Soft delete: is_active=False instead of deleting the row.
    # Preserves history. Reactivate by setting back to True.
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # ── TIMESTAMPS ────────────────────────────────────────────
    # Always store in UTC. Convert to local time in the frontend.
    created_at = db.Column(db.DateTime, nullable=False,
                           default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, nullable=True,
                           onupdate=lambda: datetime.now(timezone.utc))

    # ── QUIZ / TRAINING ───────────────────────────────────────
    quiz_score      = db.Column(db.Integer, default=0)
    quiz_total      = db.Column(db.Integer, default=0)
    training_badges = db.Column(db.Text, default="")  # comma-separated

    # ── RELATIONSHIPS ─────────────────────────────────────────
    # CONCEPT: db.relationship()
    # Links this model to another. "EmailScan" is a string to
    # avoid circular imports (the class is in another file).
    #
    # backref="user" adds scan.user attribute to EmailScan.
    # lazy="dynamic" → returns a query, not a loaded list.
    #   Good for: user.email_scans.filter_by(is_phishing=True)
    #   Without dynamic: would load ALL scans just to filter them.
    #
    # cascade="all, delete-orphan" → deleting a user also
    #   deletes all their email scans and training records.
    email_scans = db.relationship(
        "EmailScan", backref="user", lazy="dynamic",
        cascade="all, delete-orphan",
    )
    training_records = db.relationship(
        "TrainingRecord", backref="user", lazy="dynamic",
        cascade="all, delete-orphan",
    )

    # ── PASSWORD METHODS ──────────────────────────────────────

    def set_password(self, plain_password: str) -> None:
        """
        Hash and store a password with bcrypt.

        CONCEPT: Why bcrypt?
          Fast hash (MD5/SHA): attackers try billions/second with GPU.
          bcrypt (rounds=12): ~0.3 seconds per hash intentionally.
          Attacker can only try ~3 passwords/second. Centuries to crack.

          bcrypt also adds a random "salt" automatically.
          Same password → different hash each time.
          Defeats rainbow table (pre-computed hash lookup) attacks.
        """
        if not plain_password:
            raise ValueError("Password cannot be empty.")
        if len(plain_password) < 8:
            raise ValueError("Password must be at least 8 characters.")

        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(
            plain_password.encode("utf-8"), salt
        ).decode("utf-8")

    def check_password(self, plain_password: str) -> bool:
        """
        Verify a plain password against the stored hash.
        Returns True if correct, False otherwise.
        The original password is NEVER recoverable from the hash.
        """
        if not plain_password or not self.password_hash:
            return False
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            self.password_hash.encode("utf-8"),
        )

    def record_login(self) -> None:
        """Update last_login to now. Call on every successful login."""
        self.last_login = datetime.now(timezone.utc)

    # ── ROLE HELPERS ──────────────────────────────────────────
    # @property makes these read like attributes: user.is_admin
    # instead of user.role == "admin"

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_analyst(self) -> bool:
        return self.role in ("admin", "analyst")

    # ── SERIALISATION ─────────────────────────────────────────
    # CONCEPT: to_dict()
    # Flask's jsonify() cannot serialize SQLAlchemy objects.
    # to_dict() converts to a plain dict that jsonify() CAN handle.
    # NEVER include password_hash in any API response.

    def to_dict(self, include_sensitive: bool = False) -> dict:
        data = {
            "id":           self.id,
            "username":     self.username,
            "role":         self.role,
            "department":   self.department,
            "full_name":    self.full_name,
            "is_active":    self.is_active,
            "created_at":   self.created_at.isoformat() + "Z" if self.created_at else None,
            "last_login":   self.last_login.isoformat() + "Z"  if self.last_login  else None,
            "quiz_score":   self.quiz_score,
            "quiz_total":   self.quiz_total,
            "quiz_percent": round(
                (self.quiz_score / self.quiz_total * 100) if self.quiz_total else 0, 1
            ),
            "badges": [b for b in self.training_badges.split(",") if b],
        }
        if include_sensitive:
            data["email"] = self.email
        return data

    # ── __repr__ ──────────────────────────────────────────────
    # CONCEPT: __repr__
    # Python calls this when you print() an object.
    # Without it: <app.models.user.User object at 0x7f3a...>
    # With it:    <User id=1 username='admin' role='admin'>
    # Purely for debugging convenience.

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r} role={self.role!r}>"