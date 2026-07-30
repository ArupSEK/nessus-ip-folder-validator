from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from backend.app.api.deps import get_nessus_client_factory
from backend.app.models.auth import AuditEvent
from backend.app.models.folder import FolderRecord
from backend.app.integrations.nessus.client import NessusClientFactory


class FolderMockState:
    def __init__(self) -> None:
        self.folders = [
            {"id": 1, "name": "My Scans", "type": "main", "custom": 0, "owner": "system"},
            {"id": 8, "name": "Ops Team", "type": "custom", "custom": 1, "owner": "admin"},
        ]


def build_folder_transport(state: FolderMockState):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/server/properties":
            return httpx.Response(200, json={"nessus_type": "manager", "server_version": "10.8.3"})
        if request.url.path == "/api/v3/access-control/permissions/users/me":
            return httpx.Response(200, json={"permissions": ["BASIC", "SYSTEM_ADMINISTRATOR"]})
        if request.url.path == "/folders" and request.method == "GET":
            return httpx.Response(200, json={"folders": state.folders})
        if request.url.path == "/scans" and request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "scans": [
                        {"id": 10, "uuid": "scan-1", "name": "Weekly Auth Scan", "folder_id": 8, "status": "completed"},
                        {"id": 11, "uuid": "scan-2", "name": "Internet Edge", "folder_id": 8, "status": "running"},
                    ]
                },
            )
        if request.url.path == "/folders" and request.method == "POST":
            payload = request.read().decode("utf-8")
            if "Duplicate" in payload:
                return httpx.Response(400, json={"error": "duplicate"})
            state.folders.append({"id": 12, "name": "OpsCreated", "type": "custom", "custom": 1, "owner": "admin"})
            return httpx.Response(200, json={"id": 12})
        if request.url.path == "/folders/8" and request.method == "PUT":
            return httpx.Response(200, json={"id": 8, "name": "OpsRenamed", "type": "custom", "custom": 1, "owner": "admin"})
        if request.url.path == "/folders/8" and request.method == "DELETE":
            return httpx.Response(200, json={})
        if request.url.path == "/folders/1" and request.method == "PUT":
            return httpx.Response(403, json={"error": "protected"})
        if request.url.path == "/folders/1" and request.method == "DELETE":
            return httpx.Response(403, json={"error": "protected"})
        return httpx.Response(404, json={})

    return handler


async def login_admin(client) -> str:
    response = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongPass123!"})
    assert response.status_code == 200
    return response.json()["csrf_token"]


async def save_nessus_profile(client, csrf_token: str) -> None:
    response = await client.put(
        "/api/v1/nessus/configuration",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "base_url": "https://scanner.example.com:8834",
            "access_key": "ACCESSKEY12345",
            "secret_key": "SECRETKEY12345",
            "verify_tls": True,
            "timeout_seconds": 15,
            "approved_hosts": [],
        },
    )
    assert response.status_code == 200


@pytest.mark.anyio
async def test_folder_creation(app, client, admin_user) -> None:
    state = FolderMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=httpx.MockTransport(build_folder_transport(state)), retries=0)
    csrf_token = await login_admin(client)
    await save_nessus_profile(client, csrf_token)
    response = await client.post("/api/v1/folders/refresh", headers={"X-CSRF-Token": csrf_token})
    assert response.status_code == 200
    create_response = await client.post("/api/v1/folders", headers={"X-CSRF-Token": csrf_token}, json={"name": "OpsCreated"})
    assert create_response.status_code == 200
    assert create_response.json()["nessus_folder_id"] == "12"
    assert create_response.json()["name"] == "OpsCreated"
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_duplicate_folder_denied(app, client, admin_user) -> None:
    state = FolderMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=httpx.MockTransport(build_folder_transport(state)), retries=0)
    csrf_token = await login_admin(client)
    await save_nessus_profile(client, csrf_token)
    await client.post("/api/v1/folders/refresh", headers={"X-CSRF-Token": csrf_token})
    response = await client.post("/api/v1/folders", headers={"X-CSRF-Token": csrf_token}, json={"name": "Ops Team"})
    assert response.status_code == 400
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_protected_folder_rename_denied(app, client, admin_user) -> None:
    state = FolderMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=httpx.MockTransport(build_folder_transport(state)), retries=0)
    csrf_token = await login_admin(client)
    await save_nessus_profile(client, csrf_token)
    refresh = await client.post("/api/v1/folders/refresh", headers={"X-CSRF-Token": csrf_token})
    protected_folder = next(folder for folder in refresh.json()["folders"] if folder["name"] == "My Scans")
    response = await client.put(f"/api/v1/folders/{protected_folder['id']}", headers={"X-CSRF-Token": csrf_token}, json={"name": "Nope"})
    assert response.status_code == 400
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_protected_folder_delete_denied(app, client, admin_user) -> None:
    state = FolderMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=httpx.MockTransport(build_folder_transport(state)), retries=0)
    csrf_token = await login_admin(client)
    await save_nessus_profile(client, csrf_token)
    refresh = await client.post("/api/v1/folders/refresh", headers={"X-CSRF-Token": csrf_token})
    protected_folder = next(folder for folder in refresh.json()["folders"] if folder["name"] == "My Scans")
    response = await client.post(
        f"/api/v1/folders/{protected_folder['id']}/delete",
        headers={"X-CSRF-Token": csrf_token},
        json={"confirmation_name": "My Scans", "current_password": "StrongPass123!"},
    )
    assert response.status_code == 400
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_custom_folder_delete(app, client, admin_user, db_session) -> None:
    state = FolderMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=httpx.MockTransport(build_folder_transport(state)), retries=0)
    csrf_token = await login_admin(client)
    await save_nessus_profile(client, csrf_token)
    refresh = await client.post("/api/v1/folders/refresh", headers={"X-CSRF-Token": csrf_token})
    custom_folder = next(folder for folder in refresh.json()["folders"] if folder["name"] == "Ops Team")
    response = await client.post(
        f"/api/v1/folders/{custom_folder['id']}/delete",
        headers={"X-CSRF-Token": csrf_token},
        json={"confirmation_name": "Ops Team", "current_password": "StrongPass123!"},
    )
    assert response.status_code == 200
    db_session.expire_all()
    stored = db_session.get(FolderRecord, custom_folder["id"])
    assert stored is not None
    assert stored.deleted_at is not None
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_folder_delete_preview_contains_scans(app, client, admin_user, db_session) -> None:
    state = FolderMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=httpx.MockTransport(build_folder_transport(state)), retries=0)
    csrf_token = await login_admin(client)
    await save_nessus_profile(client, csrf_token)
    refresh = await client.post("/api/v1/folders/refresh", headers={"X-CSRF-Token": csrf_token})
    custom_folder = next(folder for folder in refresh.json()["folders"] if folder["name"] == "Ops Team")
    preview = await client.get(f"/api/v1/folders/{custom_folder['id']}/delete-preview")
    assert preview.status_code == 200
    assert len(preview.json()["affected_scans"]) == 2
    await client.post(
        f"/api/v1/folders/{custom_folder['id']}/delete",
        headers={"X-CSRF-Token": csrf_token},
        json={"confirmation_name": "Ops Team", "current_password": "StrongPass123!"},
    )
    db_session.expire_all()
    audit = db_session.scalar(select(AuditEvent).where(AuditEvent.action == "folders.delete"))
    assert audit is not None
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_folder_creation_rejects_spaces(app, client, admin_user) -> None:
    state = FolderMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=httpx.MockTransport(build_folder_transport(state)), retries=0)
    csrf_token = await login_admin(client)
    await save_nessus_profile(client, csrf_token)
    response = await client.post("/api/v1/folders", headers={"X-CSRF-Token": csrf_token}, json={"name": "Ops Created"})
    assert response.status_code == 400
    assert "letters, numbers, dots, underscores and hyphens" in response.json()["detail"]
    app.dependency_overrides.clear()
