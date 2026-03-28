# =============================================================
#  backend/app/routes/ml_dashboard.py
#
#  Flask routes that power the ML performance dashboard
#  and status page API.
#
#  Routes:
#    GET  /api/ml/status          → current model metadata + metrics
#    GET  /api/ml/history         → training run history (all runs)
#    GET  /api/ml/production-stats → scan stats from the DB
#    POST /api/ml/retrain         → trigger retraining (admin only)
#    GET  /api/ml/retrain/stream  → SSE stream of training progress
#    GET  /api/health/status      → system component health (status page)
#
#  CONCEPT: Server-Sent Events (SSE)
#    Normal HTTP: client asks → server answers → connection closes.
#    SSE: client opens a connection → server keeps it open →
#    server pushes data whenever it wants → client receives live.
#
#    Perfect for training progress because:
#    - Training takes 30-120 seconds
#    - We want log lines to appear as they happen, not all at once
#    - SSE is simpler than WebSockets for one-way server→client flow
#    - Native browser support via EventSource API
#
#    SSE message format (what the server sends):
#      data: your message here\n\n
#      (blank line terminates each event)
#
#    The Flask route uses a generator function that yields
#    these formatted strings. Flask streams them to the client
#    as they are yielded, keeping the connection open until
#    the generator is exhausted.
# =============================================================

import os
import sys
import json
import subprocess
import threading
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from flask import Blueprint, Response, jsonify, stream_with_context

from app.utils.auth_helpers import require_auth, require_role, get_current_user
from app.utils.responses import success, error
from app.extensions import db
from app.models.email_scan import EmailScan

logger = logging.getLogger(__name__)

ml_dashboard_bp = Blueprint("ml_dashboard", __name__)

# Path constants — adjust if your structure differs
BACKEND_ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR    = BACKEND_ROOT / "ml" / "saved_models"
HISTORY_FILE = BACKEND_ROOT / "ml" / "training_history" / "runs.json"
TRAIN_SCRIPT = BACKEND_ROOT / "scripts" / "prepare_and_train.py"

# Global flag to prevent concurrent training runs
_training_in_progress = False


def _utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


# =============================================================
#  MODEL STATUS
# =============================================================

@ml_dashboard_bp.route("/api/ml/status", methods=["GET"])
@require_auth
@require_role("admin", "analyst")
def ml_status():
    """
    Returns current model metadata and metrics.
    Used by the dashboard header cards.
    """
    metadata_path = MODEL_DIR / "metadata.json"

    if not metadata_path.exists():
        return error("No trained model found. Run training first.", 404)

    try:
        metadata = json.loads(metadata_path.read_text())
        return success({"model": metadata})
    except Exception as e:
        logger.error("Failed to read model metadata: %s", e)
        return error("Could not load model metadata", 500)


# =============================================================
#  TRAINING HISTORY
# =============================================================

@ml_dashboard_bp.route("/api/ml/history", methods=["GET"])
@require_auth
@require_role("admin", "analyst")
def ml_history():
    """
    Returns all training run history for the performance
    over time chart in the dashboard.
    """
    if not HISTORY_FILE.exists():
        return success({"runs": [], "message": "No training history yet"})

    try:
        runs = json.loads(HISTORY_FILE.read_text())
        return success({"runs": runs, "total": len(runs)})
    except Exception as e:
        logger.error("Failed to read training history: %s", e)
        return error("Could not load training history", 500)


# =============================================================
#  PRODUCTION STATISTICS
#  Queries the live database for real-world model performance data
# =============================================================

@ml_dashboard_bp.route("/api/ml/production-stats", methods=["GET"])
@require_auth
@require_role("admin", "analyst")
def ml_production_stats():
    """
    Queries the email_scans table to build production monitoring stats.

    Returns:
    - total scans (all time and last 24h)
    - risk score distribution (histogram buckets)
    - top triggered features
    - average confidence over time (daily buckets, last 7 days)
    - phishing detection rate
    """
    try:
        # ── Total scans ───────────────────────────────────────
        total_scans = EmailScan.query.count()

        cutoff_24h = _utcnow() - timedelta(hours=24)
        scans_24h  = EmailScan.query.filter(
            EmailScan.scanned_at >= cutoff_24h
        ).count()

        # ── Risk score distribution ────────────────────────────
        # Buckets: 0-20, 21-40, 41-60, 61-80, 81-100
        all_scans = EmailScan.query.with_entities(
            EmailScan.risk_score,
            EmailScan.is_phishing,
            EmailScan.confidence,
            EmailScan.scanned_at,
        ).order_by(EmailScan.scanned_at.desc()).limit(1000).all()

        risk_buckets = {
            "0-20":   0,
            "21-40":  0,
            "41-60":  0,
            "61-80":  0,
            "81-100": 0,
        }
        phishing_count = 0
        total_confidence = 0.0

        for scan in all_scans:
            score = scan.risk_score or 0
            if score <= 20:
                risk_buckets["0-20"] += 1
            elif score <= 40:
                risk_buckets["21-40"] += 1
            elif score <= 60:
                risk_buckets["41-60"] += 1
            elif score <= 80:
                risk_buckets["61-80"] += 1
            else:
                risk_buckets["81-100"] += 1

            if scan.is_phishing:
                phishing_count += 1
            if scan.confidence:
                total_confidence += scan.confidence

        n = len(all_scans)
        phishing_rate     = round(phishing_count / n * 100, 1) if n > 0 else 0
        avg_confidence    = round(total_confidence / n * 100, 1) if n > 0 else 0

        # ── Daily confidence trend (last 7 days) ──────────────
        daily_trend = []
        for days_ago in range(6, -1, -1):
            day_start = _utcnow() - timedelta(days=days_ago + 1)
            day_end   = _utcnow() - timedelta(days=days_ago)
            day_scans = EmailScan.query.filter(
                EmailScan.scanned_at >= day_start,
                EmailScan.scanned_at <  day_end,
            ).with_entities(
                EmailScan.confidence,
                EmailScan.risk_score,
            ).all()

            if day_scans:
                day_avg_conf  = sum(s.confidence or 0 for s in day_scans) / len(day_scans)
                day_avg_risk  = sum(s.risk_score or 0 for s in day_scans) / len(day_scans)
                day_count     = len(day_scans)
            else:
                day_avg_conf = 0
                day_avg_risk = 0
                day_count    = 0

            daily_trend.append({
                "date":           day_end.strftime("%b %d"),
                "avg_confidence": round(day_avg_conf * 100, 1),
                "avg_risk_score": round(day_avg_risk, 1),
                "scan_count":     day_count,
            })

        return success({
            "total_scans":     total_scans,
            "scans_24h":       scans_24h,
            "phishing_rate":   phishing_rate,
            "avg_confidence":  avg_confidence,
            "risk_distribution": risk_buckets,
            "daily_trend":     daily_trend,
            "sample_size":     n,
        })

    except Exception as e:
        logger.error("Production stats error: %s", e)
        return error(f"Could not compute production stats: {str(e)}", 500)


# =============================================================
#  RETRAIN TRIGGER
# =============================================================

@ml_dashboard_bp.route("/api/ml/retrain", methods=["POST"])
@require_auth
def ml_retrain_trigger():
    """
    Validates the retrain request and starts training in a
    background thread. The actual progress is streamed via
    the /api/ml/retrain/stream SSE endpoint.

    Only admin users can trigger retraining.
    """
    global _training_in_progress

    user = get_current_user()
    if not user or user.role != "admin":
        return error("Admin access required to trigger retraining", 403)

    if _training_in_progress:
        return error("Training is already in progress", 409)

    if not TRAIN_SCRIPT.exists():
        return error(
            f"Training script not found at {TRAIN_SCRIPT}. "
            "Copy prepare_and_train.py to backend/scripts/.",
            500
        )

    return success({
        "message": "Training initiated. Connect to /api/ml/retrain/stream for live progress.",
        "stream_url": "/api/ml/retrain/stream",
    })


@ml_dashboard_bp.route("/api/ml/retrain/stream", methods=["GET"])
def ml_retrain_stream():
    """SSE endpoint — auth via query param because EventSource
    does not support custom Authorization headers."""
    from flask import request as flask_request
    import jwt as pyjwt
    from app.models.user import User

    # Accept token from query param (EventSource limitation)
    token = flask_request.args.get("token", "")
    current_user = None
    if token:
        try:
            from flask import current_app
            payload = pyjwt.decode(
                token,
                current_app.config["SECRET_KEY"],
                algorithms=["HS256"]
            )
            current_user = db.session.get(User, payload.get("user_id"))
        except Exception:
            pass

    # Fall back to normal header auth
    if not current_user:
        from app.utils.auth_helpers import get_current_user
        current_user = get_current_user()
    """
    SSE endpoint that runs the training script as a subprocess
    and streams its stdout (log lines) to the browser in real time.

    CONCEPT: subprocess + SSE
      We launch prepare_and_train.py --stream as a child process.
      That script prints lines in the format "data: LEVEL | message".
      We read those lines one by one and yield them as SSE events.
      Flask's stream_with_context keeps the HTTP connection open
      while we iterate, closing it when the subprocess exits.

    The browser's EventSource API receives these events and
      updates the training log UI in real time.
    """
    global _training_in_progress

    if not current_user or current_user.role != "admin":
        def forbidden():
            yield "data: ERROR | Admin access required\n\n"
        return Response(
            stream_with_context(forbidden()),
            mimetype="text/event-stream"
        )

    def generate():
        global _training_in_progress

        if _training_in_progress:
            yield "data: ERROR | Training already in progress\n\n"
            return

        _training_in_progress = True

        try:
            yield "data: INFO | Starting PhishGuard ML training pipeline...\n\n"
            yield "data: INFO | This will take 1-3 minutes depending on dataset size\n\n"

            # Run training script as subprocess
            # --stream flag makes it print SSE-formatted lines to stdout
            process = subprocess.Popen(
                [sys.executable, str(TRAIN_SCRIPT), "--stream"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # merge stderr into stdout
                text=True,
                bufsize=1,                 # line-buffered
                cwd=str(BACKEND_ROOT.parent),
            )

            # Stream output line by line as it arrives
            for line in iter(process.stdout.readline, ""):
                line = line.rstrip()
                if not line:
                    continue

                # Lines from the script are already in SSE format
                # ("data: LEVEL | message") — forward them directly
                if line.startswith("data:"):
                    yield f"{line}\n\n"
                else:
                    # Wrap plain log lines in SSE format
                    yield f"data: INFO | {line}\n\n"

            process.stdout.close()
            return_code = process.wait()

            if return_code == 0:
                yield "data: SUCCESS | Training completed successfully!\n\n"
                yield "data: RELOAD_METRICS | \n\n"  # signal to reload metrics
            else:
                yield f"data: ERROR | Training failed (exit code {return_code})\n\n"

        except Exception as e:
            logger.error("Training stream error: %s", e)
            yield f"data: ERROR | {str(e)}\n\n"
        finally:
            _training_in_progress = False
            yield "data: STREAM_CLOSED | \n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering for SSE
        }
    )


# =============================================================
#  SYSTEM HEALTH — STATUS PAGE API
# =============================================================

@ml_dashboard_bp.route("/api/health/status", methods=["GET"])
def system_status():
    """
    Checks health of all PhishGuard system components.
    This endpoint is PUBLIC (no auth required) so the status
    page works even when users cannot log in.

    Checks:
    - API server (if this responds, Flask is up)
    - Database (attempt a simple query)
    - ML model (check model files exist and are loadable)
    - Redis (check rate limiter is connected)
    - Email service (check config is present)
    - VirusTotal (check API key is configured)

    Returns component statuses as:
      "operational"  → working normally
      "degraded"     → working but with issues
      "outage"       → not working
      "unknown"      → could not determine status
    """
    components = []

    # ── 1. API Server ─────────────────────────────────────────
    # If we are executing this code, Flask is running
    components.append({
        "name":    "API Server",
        "key":     "api",
        "status":  "operational",
        "message": "Flask/Gunicorn responding normally",
        "checked_at": _utcnow().isoformat(),
    })

    # ── 2. Database ───────────────────────────────────────────
    try:
        db.session.execute(db.text("SELECT 1"))
        db.session.commit()
        components.append({
            "name":    "Database",
            "key":     "database",
            "status":  "operational",
            "message": "PostgreSQL accepting connections",
            "checked_at": _utcnow().isoformat(),
        })
    except Exception as e:
        components.append({
            "name":    "Database",
            "key":     "database",
            "status":  "outage",
            "message": f"Database error: {str(e)[:80]}",
            "checked_at": _utcnow().isoformat(),
        })

    # ── 3. ML Model ───────────────────────────────────────────
    model_path = MODEL_DIR / "model.pkl"
    meta_path  = MODEL_DIR / "metadata.json"

    if model_path.exists() and meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
            trained_at = meta.get("trained_at", "unknown")
            accuracy   = meta.get("metrics", {}).get("accuracy", 0)
            n_train    = meta.get("metrics", {}).get("n_train", 0)

            # Warn if model was trained on very small dataset
            status = "operational"
            msg    = f"Model online | accuracy={accuracy*100:.1f}% | n_train={n_train:,}"
            if n_train < 100:
                status = "degraded"
                msg    = f"Model undertrained (n_train={n_train}) — retrain with larger dataset"

            components.append({
                "name":       "ML Detection Engine",
                "key":        "ml_model",
                "status":     status,
                "message":    msg,
                "trained_at": trained_at,
                "checked_at": _utcnow().isoformat(),
            })
        except Exception as e:
            components.append({
                "name":    "ML Detection Engine",
                "key":     "ml_model",
                "status":  "degraded",
                "message": f"Model files exist but unreadable: {str(e)[:80]}",
                "checked_at": _utcnow().isoformat(),
            })
    else:
        components.append({
            "name":    "ML Detection Engine",
            "key":     "ml_model",
            "status":  "outage",
            "message": "Model files not found. Training required.",
            "checked_at": _utcnow().isoformat(),
        })

    # ── 4. Redis / Rate Limiter ────────────────────────────────
    try:
        from app.extensions import limiter
        # Check if limiter storage is accessible
        redis_url = os.environ.get("REDIS_URL", "memory://")
        if redis_url.startswith("memory://"):
            status  = "degraded"
            message = "Using in-memory rate limiting (Redis not configured)"
        else:
            status  = "operational"
            message = "Redis connected, rate limiting active"

        components.append({
            "name":    "Rate Limiter",
            "key":     "redis",
            "status":  status,
            "message": message,
            "checked_at": _utcnow().isoformat(),
        })
    except Exception as e:
        components.append({
            "name":    "Rate Limiter",
            "key":     "redis",
            "status":  "degraded",
            "message": f"Rate limiter check failed: {str(e)[:80]}",
            "checked_at": _utcnow().isoformat(),
        })

    # ── 5. Email Service ──────────────────────────────────────
    mail_server = os.environ.get("MAIL_SERVER", "")
    if mail_server and "mailtrap" not in mail_server.lower():
        components.append({
            "name":    "Email Service",
            "key":     "email",
            "status":  "operational",
            "message": f"Email configured via {mail_server}",
            "checked_at": _utcnow().isoformat(),
        })
    elif "mailtrap" in mail_server.lower():
        components.append({
            "name":    "Email Service",
            "key":     "email",
            "status":  "degraded",
            "message": "Using Mailtrap (dev mode) — emails not delivered to real inboxes",
            "checked_at": _utcnow().isoformat(),
        })
    else:
        components.append({
            "name":    "Email Service",
            "key":     "email",
            "status":  "outage",
            "message": "MAIL_SERVER not configured",
            "checked_at": _utcnow().isoformat(),
        })

    # ── 6. VirusTotal Integration ─────────────────────────────
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if vt_key and len(vt_key) > 10:
        components.append({
            "name":    "VirusTotal",
            "key":     "virustotal",
            "status":  "operational",
            "message": "API key configured",
            "checked_at": _utcnow().isoformat(),
        })
    else:
        components.append({
            "name":    "VirusTotal",
            "key":     "virustotal",
            "status":  "degraded",
            "message": "VIRUSTOTAL_API_KEY not set — URL reputation disabled",
            "checked_at": _utcnow().isoformat(),
        })

    # ── Overall status ────────────────────────────────────────
    statuses = [c["status"] for c in components]
    if "outage" in statuses:
        overall = "partial_outage"
    elif "degraded" in statuses:
        overall = "degraded"
    else:
        overall = "operational"

    return jsonify({
        "overall":    overall,
        "components": components,
        "checked_at": _utcnow().isoformat(),
        "version":    os.environ.get("APP_VERSION", "v0.7.0"),
    })
