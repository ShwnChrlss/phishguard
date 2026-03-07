# =============================================================
#  backend/app/utils/responses.py
#  Standardised API Response Helpers
# =============================================================
#
#  CONCEPT: DRY — Don't Repeat Yourself
#
#  Every API endpoint returns JSON. Without helpers:
#
#    return jsonify({"status": "success", "data": result}), 200
#    return jsonify({"status": "error", "message": "..."}), 400
#    return jsonify({"status": "error", "message": "..."}), 404
#
#  That "status" key and HTTP code appear in every route.
#  If you later decide to rename "status" to "result",
#  you'd have to change it in 30 places.
#
#  With helpers:
#    return success(result)
#    return error("Not found", 404)
#
#  ONE place to change the format. All routes stay clean.
#
#  CONCEPT: Consistent API responses
#  Every response from our API has the same shape:
#
#  Success:
#    {"status": "success", "data": {...}}
#
#  Error:
#    {"status": "error", "error": "error_code", "message": "..."}
#
#  The frontend can always check response.status to know
#  if a call succeeded without checking HTTP status codes.
# =============================================================

from flask import jsonify
from typing import Any, Optional


def success(data: Any = None, message: str = None, status_code: int = 200):
    """
    Returns a successful JSON response.

    Args:
        data:        The response payload (dict, list, or None).
        message:     Optional human-readable success message.
        status_code: HTTP status code (default 200).

    Returns:
        Flask Response object with JSON body and status code.

    Usage:
        return success({"user": user.to_dict()})
        return success(message="Email submitted for scanning", status_code=201)
    """
    body = {"status": "success"}

    if data is not None:
        body["data"] = data

    if message:
        body["message"] = message

    return jsonify(body), status_code


def error(
    message: str,
    status_code: int = 400,
    error_code: Optional[str] = None,
) :
    """
    Returns an error JSON response.

    Args:
        message:     Human-readable error description.
        status_code: HTTP status code (400, 401, 403, 404, 500).
        error_code:  Machine-readable error identifier (snake_case).

    Usage:
        return error("Email text is required", 400, "missing_field")
        return error("User not found", 404, "not_found")
    """
    # Auto-generate error_code from status if not provided
    if not error_code:
        codes = {
            400: "bad_request",
            401: "unauthorized",
            403: "forbidden",
            404: "not_found",
            409: "conflict",
            422: "validation_error",
            500: "server_error",
        }
        error_code = codes.get(status_code, "error")

    return jsonify({
        "status":  "error",
        "error":   error_code,
        "message": message,
    }), status_code


def created(data: Any = None, message: str = "Created successfully"):
    """Shortcut for 201 Created responses."""
    return success(data=data, message=message, status_code=201)


def no_content():
    """204 No Content — used for successful DELETE operations."""
    return "", 204