# =============================================================
#  backend/tests/conftest.py
#  Shared test setup — fixtures available to ALL test files
#
#  CONCEPT: pytest fixtures
#  A fixture is a function that prepares something a test needs
#  (a database, a test client, a logged-in user) and cleans up
#  after the test finishes.
#
#  Fixtures are declared with @pytest.fixture.
#  Tests receive them by naming them as function parameters:
#
#    def test_login(client):   ← pytest sees "client", finds the
#        ...                     fixture named "client", runs it,
#                                passes the result in.
#
#  CONCEPT: scope
#  scope="function" (default) → fresh fixture for each test
#  scope="session"            → one fixture for the whole run
#  We use "function" for the DB so tests don't share state.
#
#  RUN TESTS:
#    cd backend
#    pytest tests/ -v
#    pytest tests/test_auth.py -v        ← single file
#    pytest tests/ -v -k "test_login"   ← single test by name
# =============================================================

import pytest
from app import create_app
from app.config import TestingConfig
from app.extensions import db as _db
from app.models.user import User


class PytestConfig(TestingConfig):
    """Test-specific config loaded before extensions initialise."""

    SECRET_KEY = "test-secret-key-not-for-production"


@pytest.fixture(scope="function")
def app():
    """
    Creates a Flask app configured for testing.

    CONCEPT: Test configuration
    We override the config with:
      TESTING = True          → Flask gives better error messages
      SQLALCHEMY_DATABASE_URI → in-memory SQLite (fast, disposable)
      WTF_CSRF_ENABLED = False → no CSRF tokens needed in tests
    """
    test_app = create_app(PytestConfig)

    # Create all tables in the in-memory database
    with test_app.app_context():
        _db.create_all()
        yield test_app          # ← test runs here
        _db.drop_all()          # ← cleanup after test


@pytest.fixture(scope="function")
def client(app):
    """
    Provides a Flask test client.

    CONCEPT: Test client
    app.test_client() creates a fake HTTP client that calls
    your Flask routes directly — no real network involved.
    Requests look like:
      client.post("/api/auth/login", json={"username": "..."})
    The response has .status_code, .json, .data etc.
    """
    return app.test_client()


@pytest.fixture(scope="function")
def db(app):
    """Provides the database session (for creating test data)."""
    with app.app_context():
        yield _db


@pytest.fixture(scope="function")
def admin_user(db):
    """
    Creates an admin user in the test database.
    Usable in any test that needs a real user to exist.
    """
    user = User(
        username   = "testadmin",
        email      = "admin@test.com",
        role       = "admin",
        department = "IT Security",
    )
    user.set_password("Admin123!")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture(scope="function")
def regular_user(db):
    """Creates a regular (non-admin) user for permission tests."""
    user = User(
        username = "testuser",
        email    = "user@test.com",
        role     = "user",
    )
    user.set_password("User1234!")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture(scope="function")
def admin_token(client, admin_user):
    """
    Logs in as admin and returns the JWT token.
    Lets tests make authenticated requests without repeating login code.

    USAGE:
        def test_something(client, admin_token):
            res = client.get("/api/admin/dashboard",
                             headers={"Authorization": f"Bearer {admin_token}"})
    """
    res = client.post("/api/auth/login", json={
        "username": "testadmin",
        "password": "Admin123!",
    })
    return res.get_json()["data"]["token"]


@pytest.fixture(scope="function")
def user_token(client, regular_user):
    """Logs in as a regular user and returns the JWT token."""
    res = client.post("/api/auth/login", json={
        "username": "testuser",
        "password": "User1234!",
    })
    return res.get_json()["data"]["token"]


def auth_header(token):
    """
    Helper: builds the Authorization header dict.
    Use inside tests:
        headers = auth_header(admin_token)
        client.get("/api/something", headers=headers)
    """
    return {"Authorization": f"Bearer {token}"}
