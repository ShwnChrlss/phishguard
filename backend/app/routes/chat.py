# =============================================================
#  backend/app/routes/chat.py
#  Two endpoints:
#    POST /api/chat         — send a message, get a response
#    GET  /api/chat/topics  — get chip questions for the frontend
# =============================================================

from flask          import Blueprint, request
from app.utils.auth_helpers import require_auth
from app.utils.responses import success, error
from app.services.chatbot   import get_response, get_topics
import logging

logger   = logging.getLogger(__name__)
chat_bp  = Blueprint("chat", __name__)


@chat_bp.route("", methods=["POST"])
@require_auth
def chat():
    """
    POST /api/chat
    Body: { "message": "what is phishing?" }
    Returns the chatbot's response.
    """
    data    = request.get_json() or {}
    message = data.get("message", "").strip()

    if not message:
        return error("Message cannot be empty", 400)

    logger.info("Chat message from user: %s", message[:60])
    reply = get_response(message)

    return success({
        "message": message,
        "reply":   reply,
    })


@chat_bp.route("/topics", methods=["GET"])
@require_auth
def topics():
    """
    GET /api/chat/topics
    Returns the list of suggested chip questions.
    Frontend calls this on load to render chips dynamically.
    This keeps chips and the knowledge base always in sync —
    if a topic is added to chatbot.py, chips update automatically.
    """
    return success({"topics": get_topics()})
