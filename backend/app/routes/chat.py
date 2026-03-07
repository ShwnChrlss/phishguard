# =============================================================
#  backend/app/routes/chat.py  (updated to use chatbot service)
#  Replace your existing chat.py with this version.
#
#  Change: instead of having keyword matching inline in this
#  file, it now calls chatbot.py which is the proper service.
#  This is the "separation of concerns" principle:
#    routes/ → handles HTTP (parse request, return response)
#    services/ → handles business logic (the actual answers)
# =============================================================

import logging
from flask import Blueprint, request
from app.utils.auth_helpers import require_auth
from app.utils.responses import success, error
from app.services.chatbot import get_response

logger  = logging.getLogger(__name__)
chat_bp = Blueprint("chat", __name__)


@chat_bp.route("/chat", methods=["POST"])
@require_auth
def chat():
    """
    POST /api/chat
    Body: { "message": "What is phishing?" }

    Returns a security awareness response from the chatbot service.
    """
    data    = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()

    if not message:
        return error("Message is required.", 400)

    if len(message) > 1000:
        return error("Message too long (max 1000 characters).", 400)

    logger.info("Chat message from user: %s...", message[:50])

    reply = get_response(message)

    return success({
        "message": message,
        "reply":   reply,
    })