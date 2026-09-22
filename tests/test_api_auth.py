"""
API-level authentication and authorization tests for Gədr.
"""
import pytest
from fastapi.testclient import TestClient

from backend.api import app, _failed_logins
import backend.rate_limit as _rl

client = TestClient(app)


@pytest.fixture(autouse=True)
def _clear_rate_limits():
    """Reset the in-memory rate limiter between tests."""
    _rl._store.clear()
    _failed_logins.clear()
    yield
    _rl._store.clear()
    _failed_logins.clear()


def _register_and_login(username: str, password: str = "securepass123") -> str:
    """Register a user and return a valid JWT token."""
    client.post("/api/auth/register", data={"username": username, "password": password})
    resp = client.post("/api/auth/login", data={"username": username, "password": password})
    return resp.json()["access_token"]


# ─── Registration ───────────────────────────────────────────────
class TestRegistration:
    def test_register_success(self):
        resp = client.post(
            "/api/auth/register",
            data={"username": "testuser_reg", "password": "securepass123"},
        )
        assert resp.status_code == 200
        assert "user_id" in resp.json()

    def test_register_duplicate_username(self):
        client.post(
            "/api/auth/register",
            data={"username": "testuser_dup", "password": "securepass123"},
        )
        resp = client.post(
            "/api/auth/register",
            data={"username": "testuser_dup", "password": "securepass123"},
        )
        assert resp.status_code == 400

    def test_register_password_too_short(self):
        resp = client.post(
            "/api/auth/register",
            data={"username": "shortpwuser", "password": "ab"},
        )
        assert resp.status_code == 400
        assert "at least 8 characters" in resp.json()["detail"]

    def test_register_password_same_as_username(self):
        resp = client.post(
            "/api/auth/register",
            data={"username": "samepass", "password": "samepass"},
        )
        assert resp.status_code == 400
        assert "same as username" in resp.json()["detail"]

    def test_register_username_too_short(self):
        resp = client.post(
            "/api/auth/register",
            data={"username": "ab", "password": "securepass123"},
        )
        assert resp.status_code == 400

    def test_register_username_invalid_chars(self):
        resp = client.post(
            "/api/auth/register",
            data={"username": "user name!", "password": "securepass123"},
        )
        assert resp.status_code == 400

    def test_register_password_too_long(self):
        resp = client.post(
            "/api/auth/register",
            data={"username": "longpwuser", "password": "x" * 129},
        )
        assert resp.status_code == 400


# ─── Login ──────────────────────────────────────────────────────
class TestLogin:
    def test_login_success(self):
        client.post(
            "/api/auth/register",
            data={"username": "testuser_login", "password": "securepass123"},
        )
        resp = client.post(
            "/api/auth/login",
            data={"username": "testuser_login", "password": "securepass123"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_wrong_password(self):
        client.post(
            "/api/auth/register",
            data={"username": "testuser_wrongpw", "password": "securepass123"},
        )
        resp = client.post(
            "/api/auth/login",
            data={"username": "testuser_wrongpw", "password": "wrongpassword"},
        )
        assert resp.status_code == 401

    def test_login_nonexistent_user(self):
        resp = client.post(
            "/api/auth/login",
            data={"username": "nonexistent_user_xyz", "password": "whatever123"},
        )
        assert resp.status_code == 401


# ─── Authorization ──────────────────────────────────────────────
class TestAuthorization:
    def test_delete_project_requires_admin(self):
        token = _register_and_login("normaluser_del")
        resp = client.delete(
            "/api/projects/nonexistent",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403
        assert "Only admins" in resp.json()["detail"]

    def test_clear_history_requires_admin(self):
        token = _register_and_login("normaluser_hist")
        resp = client.delete(
            "/api/history",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403
        assert "Only admins" in resp.json()["detail"]

    def test_protected_endpoint_without_token(self):
        resp = client.delete("/api/projects/some-id")
        assert resp.status_code in (401, 403)

    def test_autofix_requires_admin(self):
        token = _register_and_login("normaluser_fix")
        resp = client.post(
            "/api/scans/fakeid/autofix",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403


# ─── Logout / Token Revocation ─────────────────────────────────
class TestTokenRevocation:
    def test_logout_revokes_token(self):
        token = _register_and_login("testuser_logout")
        headers = {"Authorization": f"Bearer {token}"}

        # Logout should succeed
        resp = client.post("/api/auth/logout", headers=headers)
        assert resp.status_code == 200

        # Token should no longer work for protected endpoints
        resp = client.delete("/api/history", headers=headers)
        assert resp.status_code == 401


# ─── Health Endpoint ────────────────────────────────────────────
class TestHealth:
    def test_health_no_internal_leaks(self):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        # Should NOT expose these internal details
        assert "db_error" not in data
        assert "ai_model" not in data
        assert "db_ok" not in data
        # Should expose these
        assert "status" in data
        assert "tools" in data
