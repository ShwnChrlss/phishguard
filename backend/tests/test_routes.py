"""
backend/tests/test_routes.py

These are lightweight integration tests for route wiring.

Testing concept:
- A route test checks the contract between the browser and the
  Flask app: URL exists, auth is enforced, and the JSON or page
  shape is what the frontend expects.
- This is especially useful after UI and routing refactors,
  because a visually small change can still break navigation.
"""

from tests.conftest import auth_header


def test_status_page_is_served(client):
    res = client.get("/status")

    assert res.status_code == 200
    assert b"System Status" in res.data


def test_ml_dashboard_page_is_served(client):
    res = client.get("/ml-dashboard")

    assert res.status_code == 200
    assert b"ML Dashboard" in res.data


def test_system_status_api_is_public(client):
    res = client.get("/api/health/status")
    data = res.get_json()

    assert res.status_code == 200
    assert data["overall"] in {"operational", "degraded", "partial_outage"}


def test_ml_production_stats_returns_success(client, admin_token):
    res = client.get("/api/ml/production-stats", headers=auth_header(admin_token))
    data = res.get_json()

    assert res.status_code == 200
    assert data["status"] == "success"
    assert "total_scans" in data["data"]


def test_ml_status_requires_analyst_or_admin(client, user_token):
    res = client.get("/api/ml/status", headers=auth_header(user_token))
    data = res.get_json()

    assert res.status_code == 403
    assert data["status"] == "error"


def test_ml_history_requires_analyst_or_admin(client, user_token):
    res = client.get("/api/ml/history", headers=auth_header(user_token))
    data = res.get_json()

    assert res.status_code == 403
    assert data["status"] == "error"


def test_ml_production_stats_requires_analyst_or_admin(client, user_token):
    res = client.get("/api/ml/production-stats", headers=auth_header(user_token))
    data = res.get_json()

    assert res.status_code == 403
    assert data["status"] == "error"
