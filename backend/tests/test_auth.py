# =============================================================
#  backend/tests/test_auth.py
#  Tests for: register, login, /me, logout
#
#  CONCEPT: What makes a good test?
#  Each test should:
#    1. Arrange  — set up the data/state needed
#    2. Act      — call the thing being tested
#    3. Assert   — check the result is correct
#
#  Test names should read like sentences:
#    test_login_with_valid_credentials_returns_token
#  → instantly clear what's being tested, even months later.
#
#  RUN:  cd backend && pytest tests/test_auth.py -v
# =============================================================

import pytest
from tests.conftest import auth_header


class TestRegister:
    """Tests for POST /api/auth/register"""

    def test_register_new_user_returns_token(self, client):
        """Happy path: valid data → 201 Created, token in response."""
        res = client.post("/api/auth/register", json={
            "username": "newuser",
            "email":    "new@test.com",
            "password": "Pass1234!",
        })
        data = res.get_json()

        assert res.status_code == 201
        assert data["status"] == "success"
        assert "token" in data["data"]
        assert data["data"]["user"]["username"] == "newuser"
        assert data["data"]["user"]["role"] == "user"  # default role

    def test_register_duplicate_username_returns_error(self, client, admin_user):
        """Trying to register with an existing username → 409 Conflict."""
        res = client.post("/api/auth/register", json={
            "username": "testadmin",   # already exists (from admin_user fixture)
            "email":    "other@test.com",
            "password": "Pass1234!",
        })
        assert res.status_code == 409

    def test_register_missing_password_returns_400(self, client):
        """Missing required field → 400 Bad Request."""
        res = client.post("/api/auth/register", json={
            "username": "someuser",
            "email":    "some@test.com",
            # password missing
        })
        assert res.status_code == 400

    def test_register_weak_password_returns_400(self, client):
        """Password too short → validation error."""
        res = client.post("/api/auth/register", json={
            "username": "someuser",
            "email":    "some@test.com",
            "password": "abc",   # too short
        })
        assert res.status_code == 400

    def test_register_invalid_email_returns_400(self, client):
        """Invalid email format → 400."""
        res = client.post("/api/auth/register", json={
            "username": "someuser",
            "email":    "not-an-email",
            "password": "Pass1234!",
        })
        assert res.status_code == 400


class TestLogin:
    """Tests for POST /api/auth/login"""

    def test_login_valid_credentials_returns_token(self, client, admin_user):
        """Correct username + password → JWT token."""
        res = client.post("/api/auth/login", json={
            "username": "testadmin",
            "password": "Admin123!",
        })
        data = res.get_json()

        assert res.status_code == 200
        assert data["status"] == "success"
        assert "token" in data["data"]
        assert len(data["data"]["token"]) > 50  # JWT is always long

    def test_login_wrong_password_returns_401(self, client, admin_user):
        """Wrong password → 401 Unauthorized."""
        res = client.post("/api/auth/login", json={
            "username": "testadmin",
            "password": "WrongPassword1!",
        })
        assert res.status_code == 401

    def test_login_nonexistent_user_returns_401(self, client):
        """
        Non-existent user → 401 Unauthorized.

        IMPORTANT: The error message must be IDENTICAL to the
        wrong-password case. This prevents username enumeration —
        attackers can't probe which usernames exist by comparing
        error messages.
        """
        res_real   = client.post("/api/auth/login", json={"username": "testadmin", "password": "wrong"})
        res_fake   = client.post("/api/auth/login", json={"username": "nobody", "password": "wrong"})

        assert res_real.status_code == 401
        assert res_fake.status_code == 401
        # Both return the same message
        assert res_real.get_json()["message"] == res_fake.get_json()["message"]

    def test_login_missing_fields_returns_400(self, client):
        """Empty body → 400."""
        res = client.post("/api/auth/login", json={})
        assert res.status_code == 400

    def test_login_updates_last_login_timestamp(self, client, admin_user, db):
        """After a successful login, last_login should be set."""
        assert admin_user.last_login is None  # not logged in yet

        client.post("/api/auth/login", json={
            "username": "testadmin",
            "password": "Admin123!",
        })

        db.session.refresh(admin_user)
        assert admin_user.last_login is not None


class TestGetMe:
    """Tests for GET /api/auth/me"""

    def test_get_me_with_valid_token(self, client, admin_token):
        """Authenticated request → returns user profile."""
        res = client.get("/api/auth/me", headers=auth_header(admin_token))
        data = res.get_json()

        assert res.status_code == 200
        assert "username" in data["data"]
        assert "role" in data["data"]
        assert "password" not in data["data"]  # never expose passwords!

    def test_get_me_without_token_returns_401(self, client):
        """No token → 401."""
        res = client.get("/api/auth/me")
        assert res.status_code == 401

    def test_get_me_with_fake_token_returns_401(self, client):
        """Made-up token → 401."""
        res = client.get("/api/auth/me", headers={"Authorization": "Bearer faketoken123"})
        assert res.status_code == 401