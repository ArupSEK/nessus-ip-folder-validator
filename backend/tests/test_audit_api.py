from __future__ import annotations

import pytest

from backend.app.services.audit import write_audit


async def _login(client, username: str, password: str) -> str:
    response = await client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["csrf_token"]


@pytest.mark.anyio
async def test_audit_list_and_filter(client, admin_user, db_session) -> None:
    write_audit(
        db_session,
        actor_user_id=admin_user.id,
        action="folders.create",
        object_type="folder",
        object_id="folder-1",
        object_name="Ops",
        source_ip="127.0.0.1",
        new_state={"name": "Ops"},
    )
    write_audit(
        db_session,
        actor_user_id=admin_user.id,
        action="scans.launch",
        object_type="scan",
        object_id="scan-1",
        object_name="Weekly",
        source_ip="127.0.0.1",
        result="failure",
    )
    db_session.commit()

    await _login(client, "admin", "StrongPass123!")
    response = await client.get("/api/v1/audit/events", params={"object_type": "folder", "search": "Ops"})
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["events"][0]["action"] == "folders.create"
    assert body["events"][0]["actor_username"] == "admin"


@pytest.mark.anyio
async def test_readonly_user_cannot_browse_audit(client, admin_user, readonly_user, db_session) -> None:
    write_audit(
        db_session,
        actor_user_id=admin_user.id,
        action="folders.create",
        object_type="folder",
        object_id="folder-2",
        object_name="Eng",
    )
    db_session.commit()
    await _login(client, "viewer", "StrongPass123!")
    response = await client.get("/api/v1/audit/events")
    assert response.status_code == 403


@pytest.mark.anyio
async def test_audit_report_export(client, admin_user, db_session) -> None:
    write_audit(
        db_session,
        actor_user_id=admin_user.id,
        action="auth.login",
        object_type="session",
        object_id="s-1",
        object_name="admin",
        source_ip="127.0.0.1",
    )
    db_session.commit()
    await _login(client, "admin", "StrongPass123!")
    response = await client.get("/api/v1/reports/export", params={"report_type": "audit_events", "export_format": "csv"})
    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert "auth.login" in response.text
