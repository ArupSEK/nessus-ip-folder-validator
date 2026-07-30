from __future__ import annotations

from datetime import timedelta, timezone, datetime

import pytest
from sqlalchemy import select

from backend.app.models.auth import User, UserSession


@pytest.mark.anyio
async def test_successful_login(client, admin_user) -> None:
    response = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongPass123!"})
    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "admin"
    assert "audit.view" in body["permissions"]
    assert "ngis_session" in response.cookies


@pytest.mark.anyio
async def test_failed_login(client, admin_user) -> None:
    response = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong-pass"})
    assert response.status_code == 401


@pytest.mark.anyio
async def test_account_lockout(client, admin_user, db_session) -> None:
    for _ in range(5):
        await client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong-pass"})
    response = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongPass123!"})
    assert response.status_code == 401
    db_session.expire_all()
    refreshed = db_session.scalar(select(User).where(User.username == "admin"))
    assert refreshed.locked_until is not None


@pytest.mark.anyio
async def test_session_expiration(client, admin_user, db_session) -> None:
    await client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongPass123!"})
    session = db_session.scalar(select(UserSession))
    session.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.commit()
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401


@pytest.mark.anyio
async def test_authorization_denial(client, readonly_user) -> None:
    await client.post("/api/v1/auth/login", json={"username": "viewer", "password": "StrongPass123!"})
    response = await client.get("/api/v1/auth/audit-access-check")
    assert response.status_code == 403


@pytest.mark.anyio
async def test_password_reset_flow(client, admin_user) -> None:
    request_response = await client.post("/api/v1/auth/password-reset/request", json={"username": "admin"})
    assert request_response.status_code == 200
    token = request_response.json()["reset_token"]
    confirm_response = await client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "new_password": "NewStrongPass123!"},
    )
    assert confirm_response.status_code == 200
    login_response = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "NewStrongPass123!"})
    assert login_response.status_code == 200
