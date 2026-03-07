# =============================================================
#  backend/app/routes/admin.py
#  Admin-only API routes
#
#  ENDPOINTS:
#    GET  /api/admin/dashboard          — stats overview
#    GET  /api/admin/scans              — all scans (filterable)
#    GET  /api/admin/scans/<id>         — single scan detail
#    GET  /api/admin/alerts             — all alerts
#    POST /api/admin/alerts/<id>/acknowledge
#    POST /api/admin/alerts/<id>/resolve
#    GET  /api/admin/users              — list all users
#    POST /api/admin/users              — create a user (admin only)
#    GET  /api/admin/users/<id>         — single user detail
#    PATCH /api/admin/users/<id>        — update role/dept/status
#    POST /api/admin/users/<id>/deactivate
#    POST /api/admin/users/<id>/reactivate
#    DELETE /api/admin/users/<id>       — hard delete (careful!)
#
#  ACCESS CONTROL:
#    admin   → all endpoints
#    analyst → dashboard, scans, alerts (read + ACK/resolve)
#    user    → 403 on everything here
#
#  CONCEPT: Soft delete vs Hard delete
#    Hard delete: row is gone forever, referential integrity breaks
#                 (scans reference user_id that no longer exists)
#    Soft delete: is_active = False, row stays, history preserved
#    We use soft delete (deactivate) as the default.
#    Hard delete is available but admin-only and logged.
# =============================================================

import logging
from datetime import datetime, timezone
from flask import Blueprint, request
from app.extensions import db
from app.models.user import User
from app.models.email_scan import EmailScan
from app.models.alert import Alert
from app.utils.auth_helpers import require_auth, require_role, get_current_user
from app.utils.responses import success, error, created

logger   = logging.getLogger(__name__)
admin_bp = Blueprint("admin", __name__)


# =============================================================
#  DASHBOARD
# =============================================================

@admin_bp.route("/dashboard", methods=["GET"])
@require_auth
@require_role("admin", "analyst")
def dashboard():
    """
    GET /api/admin/dashboard
    Returns aggregate stats + recent scans + recent alerts.
    Used to populate the dashboard page on load.
    """
    total_scans     = EmailScan.query.count()
    total_phishing  = EmailScan.query.filter_by(is_phishing=True).count()
    total_safe      = EmailScan.query.filter_by(is_phishing=False).count()
    total_quarantine= EmailScan.query.filter_by(status="quarantined").count()
    total_users     = User.query.filter_by(is_active=True).count()
    pending_alerts  = Alert.query.filter_by(status="pending").count()
    critical_alerts = Alert.query.filter_by(severity="critical").count()

    detection_rate = round(
        (total_phishing / total_scans * 100) if total_scans > 0 else 0.0, 1
    )

    recent_scans = (
        EmailScan.query
        .order_by(EmailScan.scanned_at.desc())
        .limit(5).all()
    )
    recent_alerts = (
        Alert.query
        .order_by(Alert.created_at.desc())
        .limit(5).all()
    )

    return success({
        "stats": {
            "total_scans":      total_scans,
            "total_phishing":   total_phishing,
            "total_safe":       total_safe,
            "total_quarantine": total_quarantine,
            "total_users":      total_users,
            "pending_alerts":   pending_alerts,
            "critical_alerts":  critical_alerts,
            "detection_rate":   detection_rate,
        },
        "recent_scans":  [s.to_dict() for s in recent_scans],
        "recent_alerts": [a.to_dict() for a in recent_alerts],
    })


# =============================================================
#  SCANS
# =============================================================

@admin_bp.route("/scans", methods=["GET"])
@require_auth
@require_role("admin", "analyst")
def get_scans():
    """
    GET /api/admin/scans
    Returns all scans with optional filters.

    Query params:
        page        (int, default 1)
        limit       (int, default 20)
        is_phishing (true/false)
        status      (quarantined/safe/pending/reviewed)
        user_id     (int)
    """
    page        = request.args.get("page",  1,     type=int)
    limit       = request.args.get("limit", 20,    type=int)
    is_phishing = request.args.get("is_phishing",  None)
    status      = request.args.get("status",       None)
    user_id     = request.args.get("user_id",      None, type=int)

    query = EmailScan.query

    if is_phishing is not None:
        query = query.filter_by(is_phishing=(is_phishing.lower() == "true"))
    if status:
        query = query.filter_by(status=status)
    if user_id:
        query = query.filter_by(user_id=user_id)

    query = query.order_by(EmailScan.scanned_at.desc())
    total = query.count()
    scans = query.offset((page - 1) * limit).limit(limit).all()

    return success({
        "scans": [s.to_dict() for s in scans],
        "total": total,
        "page":  page,
        "limit": limit,
        "pages": (total + limit - 1) // limit,
    })


@admin_bp.route("/scans/<int:scan_id>", methods=["GET"])
@require_auth
@require_role("admin", "analyst")
def get_scan(scan_id):
    """GET /api/admin/scans/<id> — single scan with full body."""
    scan = db.session.get(EmailScan, scan_id)
    if not scan:
        return error("Scan not found.", 404)
    return success(scan.to_dict(include_body=True))


# =============================================================
#  ALERTS
# =============================================================

@admin_bp.route("/alerts", methods=["GET"])
@require_auth
@require_role("admin", "analyst")
def get_alerts():
    """
    GET /api/admin/alerts
    Query params: status (pending/acknowledged/resolved), page, limit
    """
    page   = request.args.get("page",   1,  type=int)
    limit  = request.args.get("limit",  20, type=int)
    status = request.args.get("status", None)

    query = Alert.query
    if status:
        query = query.filter_by(status=status)

    query = query.order_by(Alert.created_at.desc())
    total  = query.count()
    alerts = query.offset((page - 1) * limit).limit(limit).all()

    return success({
        "alerts": [a.to_dict() for a in alerts],
        "total":  total,
        "page":   page,
        "pages":  (total + limit - 1) // limit,
    })


@admin_bp.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
@require_auth
@require_role("admin", "analyst")
def acknowledge_alert(alert_id):
    """Marks an alert as seen — analyst has reviewed it."""
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return error("Alert not found.", 404)
    if alert.status != "pending":
        return error("Alert is not in pending state.", 400)

    current = get_current_user()
    alert.status      = "acknowledged"
    alert.resolved_by = current.username if current else "unknown"
    alert.resolved_at = datetime.now(timezone.utc)
    db.session.commit()

    logger.info("Alert #%d acknowledged by %s", alert_id,
                current.username if current else "unknown")
    return success(alert.to_dict(), message="Alert acknowledged.")


@admin_bp.route("/alerts/<int:alert_id>/resolve", methods=["POST"])
@require_auth
@require_role("admin", "analyst")
def resolve_alert(alert_id):
    """Closes an alert with an optional resolution note."""
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return error("Alert not found.", 404)

    data    = request.get_json(silent=True) or {}
    current = get_current_user()

    alert.status      = "resolved"
    alert.resolved_by = current.username if current else "unknown"
    alert.resolved_at = datetime.now(timezone.utc)
    if data.get("note"):
        alert.message = alert.message + f"\n\nResolution note: {data['note']}"
    db.session.commit()

    logger.info("Alert #%d resolved by %s", alert_id,
                current.username if current else "unknown")
    return success(alert.to_dict(), message="Alert resolved.")


# =============================================================
#  USERS
# =============================================================

@admin_bp.route("/users", methods=["GET"])
@require_auth
@require_role("admin")
def get_users():
    """
    GET /api/admin/users
    Returns all users. Admin only — contains emails and roles.

    Query params: page, limit, role, is_active
    """
    page      = request.args.get("page",      1,    type=int)
    limit     = request.args.get("limit",     50,   type=int)
    role      = request.args.get("role",      None)
    is_active = request.args.get("is_active", None)

    query = User.query
    if role:
        query = query.filter_by(role=role)
    if is_active is not None:
        query = query.filter_by(is_active=(is_active.lower() == "true"))

    query = query.order_by(User.created_at.desc())
    total = query.count()
    users = query.offset((page - 1) * limit).limit(limit).all()

    return success({
        "users": [u.to_dict(include_sensitive=True) for u in users],
        "total": total,
        "page":  page,
        "pages": (total + limit - 1) // limit,
    })


@admin_bp.route("/users", methods=["POST"])
@require_auth
@require_role("admin")
def create_user():
    """
    POST /api/admin/users
    Admin creates a user with any role — including analyst/admin.
    This is the ONLY way to create non-user accounts.

    Body:
        username    (required)
        email       (required)
        password    (required)
        role        (optional, default "user") — admin can set any role
        department  (optional)
        full_name   (optional)
    """
    data = request.get_json(silent=True)
    if not data:
        return error("Request body must be JSON.", 400)

    username = data.get("username", "").strip()
    email    = data.get("email",    "").strip().lower()
    password = data.get("password", "")
    role     = data.get("role", "user").strip().lower()

    if not username:
        return error("Username is required.", 400)
    if not email:
        return error("Email is required.", 400)
    if not password:
        return error("Password is required.", 400)
    if len(password) < 8:
        return error("Password must be at least 8 characters.", 400)
    if role not in ("user", "analyst", "admin"):
        return error("Role must be user, analyst, or admin.", 400)

    if User.query.filter_by(username=username).first():
        return error(f"Username '{username}' is already taken.", 409)
    if User.query.filter_by(email=email).first():
        return error(f"Email '{email}' is already registered.", 409)

    current = get_current_user()
    user = User(
        username   = username,
        email      = email,
        role       = role,
        department = data.get("department"),
        full_name  = data.get("full_name"),
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    logger.info("Admin %s created user %s (role=%s)",
                current.username if current else "?", username, role)

    return created(
        user.to_dict(include_sensitive=True),
        message=f"User '{username}' created with role '{role}'."
    )


@admin_bp.route("/users/<int:user_id>", methods=["GET"])
@require_auth
@require_role("admin")
def get_user(user_id):
    """GET /api/admin/users/<id> — single user detail."""
    user = db.session.get(User, user_id)
    if not user:
        return error("User not found.", 404)
    return success(user.to_dict(include_sensitive=True))


@admin_bp.route("/users/<int:user_id>", methods=["PATCH"])
@require_auth
@require_role("admin")
def update_user(user_id):
    """
    PATCH /api/admin/users/<id>
    Update role, department, full_name, or is_active.

    CONCEPT: PATCH vs PUT
      PUT   → replace the entire resource (send all fields)
      PATCH → update only the fields you send (partial update)
    We use PATCH — send only what you want to change.

    Body (all optional):
        role        — "user" | "analyst" | "admin"
        department  — string
        full_name   — string
        is_active   — true | false

    SECURITY: Admins cannot demote themselves — prevents
    accidentally locking yourself out of the system.
    """
    user = db.session.get(User, user_id)
    if not user:
        return error("User not found.", 404)

    current = get_current_user()
    data    = request.get_json(silent=True) or {}
    changes = []

    # Role change
    if "role" in data:
        new_role = data["role"].strip().lower()
        if new_role not in ("user", "analyst", "admin"):
            return error("Role must be user, analyst, or admin.", 400)

        # Prevent self-demotion
        if current and current.id == user_id and new_role != "admin":
            return error(
                "You cannot change your own role. Ask another admin.", 400
            )

        old_role   = user.role
        user.role  = new_role
        changes.append(f"role: {old_role} → {new_role}")

    # Department
    if "department" in data:
        user.department = data["department"]
        changes.append("department updated")

    # Full name
    if "full_name" in data:
        user.full_name = data["full_name"]
        changes.append("full_name updated")

    # Active status
    if "is_active" in data:
        # Prevent self-deactivation
        if current and current.id == user_id:
            return error("You cannot deactivate your own account.", 400)
        user.is_active = bool(data["is_active"])
        changes.append(f"is_active → {user.is_active}")

    if not changes:
        return error("No valid fields provided to update.", 400)

    user.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    logger.info(
        "Admin %s updated user #%d: %s",
        current.username if current else "?", user_id, ", ".join(changes)
    )
    return success(
        user.to_dict(include_sensitive=True),
        message=f"User updated: {', '.join(changes)}"
    )


@admin_bp.route("/users/<int:user_id>/deactivate", methods=["POST"])
@require_auth
@require_role("admin")
def deactivate_user(user_id):
    """
    POST /api/admin/users/<id>/deactivate
    Soft-disables the account. User cannot log in.
    Their data (scans, history) is preserved.
    """
    user = db.session.get(User, user_id)
    if not user:
        return error("User not found.", 404)

    current = get_current_user()
    if current and current.id == user_id:
        return error("You cannot deactivate your own account.", 400)

    if not user.is_active:
        return error("User is already deactivated.", 400)

    user.is_active  = False
    user.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    logger.info("Admin %s deactivated user %s",
                current.username if current else "?", user.username)
    return success(
        user.to_dict(include_sensitive=True),
        message=f"User '{user.username}' deactivated."
    )


@admin_bp.route("/users/<int:user_id>/reactivate", methods=["POST"])
@require_auth
@require_role("admin")
def reactivate_user(user_id):
    """
    POST /api/admin/users/<id>/reactivate
    Re-enables a previously deactivated account.
    """
    user = db.session.get(User, user_id)
    if not user:
        return error("User not found.", 404)

    if user.is_active:
        return error("User is already active.", 400)

    current = get_current_user()
    user.is_active  = True
    user.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    logger.info("Admin %s reactivated user %s",
                current.username if current else "?", user.username)
    return success(
        user.to_dict(include_sensitive=True),
        message=f"User '{user.username}' reactivated."
    )


@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@require_auth
@require_role("admin")
def delete_user(user_id):
    """
    DELETE /api/admin/users/<id>
    Hard delete — permanently removes the user AND all their scans.
    Use deactivate instead unless you really need this.
    Cannot delete yourself.
    """
    user = db.session.get(User, user_id)
    if not user:
        return error("User not found.", 404)

    current = get_current_user()
    if current and current.id == user_id:
        return error("You cannot delete your own account.", 400)

    username = user.username
    db.session.delete(user)
    db.session.commit()

    logger.warning(
        "Admin %s HARD DELETED user %s (id=%d)",
        current.username if current else "?", username, user_id
    )
    return success(message=f"User '{username}' permanently deleted.")


@admin_bp.route("/scans/<int:scan_id>", methods=["PATCH"])
@require_auth
@require_role("admin", "analyst")
def update_scan(scan_id):
    """
    PATCH /api/admin/scans/<id>
    Update the status of a scan — used by quarantine review.

    Body:
        status: "safe" | "reviewed" | "quarantined"

    "safe"     → false positive, email released back to user
    "reviewed" → confirmed phishing, human has verified it
    """
    scan = db.session.get(EmailScan, scan_id)
    if not scan:
        return error("Scan not found.", 404)

    data       = request.get_json(silent=True) or {}
    new_status = data.get("status", "").strip()

    allowed = ("safe", "reviewed", "quarantined", "pending")
    if new_status not in allowed:
        return error(f"Status must be one of: {', '.join(allowed)}.", 400)

    old_status  = scan.status
    scan.status = new_status

    current = get_current_user()
    scan.reviewed_by = current.username if current else "unknown"
    scan.reviewed_at = datetime.now(timezone.utc)
    db.session.commit()

    logger.info(
        "Scan #%d status: %s → %s (by %s)",
        scan_id, old_status, new_status,
        current.username if current else "?"
    )
    return success(scan.to_dict(), message=f"Scan status updated to '{new_status}'.")
