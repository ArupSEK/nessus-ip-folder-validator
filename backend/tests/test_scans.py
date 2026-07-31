from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy import select

from backend.app.api.deps import get_nessus_client_factory
from backend.app.integrations.nessus.client import NessusClientFactory
from backend.app.models.auth import AuditEvent
from backend.app.models.scan import ScanHistoryRecord, ScanRecord


class ScanMockState:
    def __init__(self) -> None:
        self.templates = [{"uuid": "tmpl-basic", "title": "Basic Network Scan"}]
        self.policies = [{"id": 31, "name": "Hardened Policy", "template_uuid": "tmpl-basic", "owner": "admin", "has_credentials": 1}]
        self.scanners = [{"id": 5, "name": "Primary Scanner", "type": "managed", "status": "online"}]
        self.folders = [
            {"id": 1, "name": "My Scans", "type": "main", "custom": 0, "owner": "system"},
            {"id": 8, "name": "Ops Team", "type": "custom", "custom": 1, "owner": "admin"},
            {"id": 9, "name": "Engineering", "type": "custom", "custom": 1, "owner": "admin"},
        ]
        self.scans = {
            "10": {
                "id": 10,
                "uuid": "scan-10",
                "name": "Weekly Auth Scan",
                "folder_id": 8,
                "status": "completed",
                "owner": "admin",
                "targets": "10.0.0.1,server.example.com",
                "scanner_id": 5,
                "schedule_type": "weekly",
                "history": [
                    {"history_id": 501, "status": "completed", "creation_date": 1710000000, "last_modification_date": 1710003600},
                    {"history_id": 502, "status": "completed", "creation_date": 1710100000, "last_modification_date": 1710103600},
                ],
            },
            "11": {
                "id": 11,
                "uuid": "scan-11",
                "name": "Internet Edge",
                "folder_id": 8,
                "status": "running",
                "owner": "admin",
                "targets": "192.168.1.10",
                "scanner_id": 5,
                "schedule_type": "on_demand",
                "history": [{"history_id": 601, "status": "running", "creation_date": 1710200000, "last_modification_date": 1710203600}],
            },
        }
        self.next_scan_id = 20
        self.deleted_histories: list[tuple[str, str]] = []

    def list_scans(self) -> list[dict]:
        return [
            {
                "id": data["id"],
                "uuid": data["uuid"],
                "name": data["name"],
                "folder_id": data["folder_id"],
                "status": data["status"],
                "owner": data["owner"],
            }
            for data in self.scans.values()
        ]

    def details(self, scan_id: str) -> dict:
        scan = self.scans[scan_id]
        return {
            "info": {
                "object_id": scan["id"],
                "uuid": scan["uuid"],
                "name": scan["name"],
                "folder_id": scan["folder_id"],
                "status": scan["status"],
                "owner": scan["owner"],
                "targets": scan["targets"],
                "scanner_id": scan["scanner_id"],
                "schedule_type": scan["schedule_type"],
            },
            "history": scan["history"],
        }


def build_scan_transport(state: ScanMockState):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method
        if path == "/server/properties":
            return httpx.Response(200, json={"nessus_type": "manager", "server_version": "10.8.3"})
        if path == "/api/v3/access-control/permissions/users/me":
            return httpx.Response(200, json={"permissions": ["BASIC", "SCAN_MANAGER", "SYSTEM_ADMINISTRATOR"]})
        if path == "/folders":
            return httpx.Response(200, json={"folders": state.folders})
        if path == "/editor/scan/templates":
            return httpx.Response(200, json={"templates": state.templates})
        if path == "/policies":
            return httpx.Response(200, json={"policies": state.policies})
        if path == "/scanners":
            return httpx.Response(200, json={"scanners": state.scanners})
        if path == "/scans" and method == "GET":
            return httpx.Response(200, json={"scans": state.list_scans()})
        if path == "/scans" and method == "POST":
            payload = json.loads(request.content.decode("utf-8"))
            scan_id = state.next_scan_id
            state.next_scan_id += 1
            settings = payload["settings"]
            state.scans[str(scan_id)] = {
                "id": scan_id,
                "uuid": f"scan-{scan_id}",
                "name": settings["name"],
                "folder_id": int(settings["folder_id"]),
                "status": "created",
                "owner": "admin",
                "targets": settings["text_targets"],
                "scanner_id": int(settings.get("scanner_id") or 5),
                "schedule_type": settings.get("schedule_type", "on_demand"),
                "history": [],
            }
            return httpx.Response(200, json={"scan": {"id": scan_id}})
        if path.startswith("/scans/") and method == "GET":
            scan_id = path.split("/")[2]
            if scan_id not in state.scans:
                return httpx.Response(404, json={})
            return httpx.Response(200, json=state.details(scan_id))
        if path.startswith("/scans/") and path.endswith("/copy") and method == "POST":
            source_id = path.split("/")[2]
            payload = json.loads(request.content.decode("utf-8"))
            source = dict(state.scans[source_id])
            scan_id = state.next_scan_id
            state.next_scan_id += 1
            source.update({"id": scan_id, "uuid": f"scan-{scan_id}", "name": payload["name"], "status": "created", "history": []})
            state.scans[str(scan_id)] = source
            return httpx.Response(200, json={"scan": {"id": scan_id}})
        if path.startswith("/scans/") and path.endswith("/launch") and method == "POST":
            scan_id = path.split("/")[2]
            state.scans[scan_id]["status"] = "running"
            return httpx.Response(200, json={"scan_uuid": state.scans[scan_id]["uuid"]})
        if path.startswith("/scans/") and path.endswith("/pause") and method == "POST":
            scan_id = path.split("/")[2]
            state.scans[scan_id]["status"] = "paused"
            return httpx.Response(200, json={"paused": True})
        if path.startswith("/scans/") and path.endswith("/resume") and method == "POST":
            scan_id = path.split("/")[2]
            state.scans[scan_id]["status"] = "running"
            return httpx.Response(200, json={"resumed": True})
        if path.startswith("/scans/") and path.endswith("/stop") and method == "POST":
            scan_id = path.split("/")[2]
            state.scans[scan_id]["status"] = "stopped"
            return httpx.Response(200, json={"stopped": True})
        if path.startswith("/scans/") and method == "PUT":
            scan_id = path.split("/")[2]
            payload = json.loads(request.content.decode("utf-8"))
            settings = payload["settings"]
            scan = state.scans[scan_id]
            scan["name"] = settings.get("name", scan["name"])
            scan["folder_id"] = int(settings.get("folder_id", scan["folder_id"]))
            scan["targets"] = settings.get("text_targets", scan["targets"])
            scan["scanner_id"] = int(settings.get("scanner_id") or scan["scanner_id"])
            scan["schedule_type"] = settings.get("schedule_type", scan["schedule_type"])
            return httpx.Response(200, json={"ok": True})
        if path.startswith("/scans/") and path.endswith("/history/502") and method == "DELETE":
            scan_id = path.split("/")[2]
            state.deleted_histories.append((scan_id, "502"))
            state.scans[scan_id]["history"] = [row for row in state.scans[scan_id]["history"] if str(row["history_id"]) != "502"]
            return httpx.Response(200, json={})
        if path.startswith("/scans/") and method == "DELETE":
            scan_id = path.split("/")[2]
            state.scans.pop(scan_id, None)
            return httpx.Response(200, json={})
        return httpx.Response(404, json={})

    return httpx.MockTransport(handler)


def build_scan_transport_with_scan_api_disabled(state: ScanMockState):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/server/properties":
            return httpx.Response(
                200,
                json={
                    "nessus_type": "manager",
                    "server_version": "10.12.2",
                    "license": {"type": "Nessus Professional", "features": {"scan_api": False}},
                },
            )
        return build_scan_transport(state).handle_request(request)

    return httpx.MockTransport(handler)


async def login_admin(client) -> str:
    response = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongPass123!"})
    assert response.status_code == 200
    return response.json()["csrf_token"]


async def save_profile_and_refresh_folders(client, csrf_token: str) -> None:
    save_response = await client.put(
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
    assert save_response.status_code == 200
    refresh_response = await client.post("/api/v1/folders/refresh", headers={"X-CSRF-Token": csrf_token})
    assert refresh_response.status_code == 200


@pytest.mark.anyio
async def test_scan_creation(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    folders = await client.get("/api/v1/folders")
    ops_folder = next(folder for folder in folders.json()["folders"] if folder["name"] == "Ops Team")
    response = await client.post(
        "/api/v1/scans",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "name": "New Internal Scan",
            "folder_record_id": ops_folder["id"],
            "template_uuid": "tmpl-basic",
            "scanner_id": "5",
            "targets": ["10.1.1.1", "Server.EXAMPLE.com"],
            "schedule_type": "on_demand",
            "launch_now": False,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "New Internal Scan"
    assert body["target_count"] == 2
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_scan_creation_without_targets(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    folders = await client.get("/api/v1/folders")
    ops_folder = next(folder for folder in folders.json()["folders"] if folder["name"] == "Ops Team")
    response = await client.post(
        "/api/v1/scans",
        headers={"X-CSRF-Token": csrf_token},
        json={"name": "Empty Scan", "folder_record_id": ops_folder["id"], "template_uuid": "tmpl-basic", "targets": []},
    )
    assert response.status_code == 400
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_invalid_scan_targets(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    folders = await client.get("/api/v1/folders")
    ops_folder = next(folder for folder in folders.json()["folders"] if folder["name"] == "Ops Team")
    response = await client.post(
        "/api/v1/scans",
        headers={"X-CSRF-Token": csrf_token},
        json={"name": "Bad Targets", "folder_record_id": ops_folder["id"], "template_uuid": "tmpl-basic", "targets": ["10.1.1.999"]},
    )
    assert response.status_code == 400
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_scheduled_scan(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    folders = await client.get("/api/v1/folders")
    ops_folder = next(folder for folder in folders.json()["folders"] if folder["name"] == "Ops Team")
    response = await client.post(
        "/api/v1/scans",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "name": "Weekly Scheduled",
            "folder_record_id": ops_folder["id"],
            "template_uuid": "tmpl-basic",
            "targets": ["10.1.2.0/24"],
            "schedule_type": "weekly",
        },
    )
    assert response.status_code == 200
    assert response.json()["schedule_type"] == "weekly"
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_scan_creation_from_policy(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    folders = await client.get("/api/v1/folders")
    ops_folder = next(folder for folder in folders.json()["folders"] if folder["name"] == "Ops Team")
    response = await client.post(
        "/api/v1/scans",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "name": "Policy Based Scan",
            "folder_record_id": ops_folder["id"],
            "policy_id": "31",
            "scanner_id": "5",
            "targets": ["10.1.4.4"],
            "schedule_type": "on_demand",
            "launch_now": False,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "Policy Based Scan"
    assert body["target_count"] == 1
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_scan_creation_from_master_template(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    await client.post("/api/v1/scans/refresh", headers={"X-CSRF-Token": csrf_token})
    scans = await client.get("/api/v1/scans")
    folders = await client.get("/api/v1/folders")
    source_scan = next(item for item in scans.json()["scans"] if item["name"] == "Weekly Auth Scan")
    engineering = next(folder for folder in folders.json()["folders"] if folder["name"] == "Engineering")
    response = await client.post(
        "/api/v1/scans",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "name": "Weekly Auth Scan Master Copy",
            "folder_record_id": engineering["id"],
            "clone_from_scan_record_id": source_scan["id"],
            "scanner_id": "5",
            "launch_now": False,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "Weekly Auth Scan Master Copy"
    assert body["folder_name"] == "Engineering"
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_scan_create_is_blocked_when_scan_api_is_disabled(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport_with_scan_api_disabled(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    folders = await client.get("/api/v1/folders")
    ops_folder = next(folder for folder in folders.json()["folders"] if folder["name"] == "Ops Team")
    response = await client.post(
        "/api/v1/scans",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "name": "Blocked Scan",
            "folder_record_id": ops_folder["id"],
            "template_uuid": "tmpl-basic",
            "targets": ["10.1.9.9"],
        },
    )
    assert response.status_code == 400
    assert "scan_api=false" in response.json()["detail"]
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_scan_edit_and_move(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    await client.post("/api/v1/scans/refresh", headers={"X-CSRF-Token": csrf_token})
    scans = await client.get("/api/v1/scans")
    folders = await client.get("/api/v1/folders")
    scan = next(item for item in scans.json()["scans"] if item["name"] == "Weekly Auth Scan")
    engineering = next(folder for folder in folders.json()["folders"] if folder["name"] == "Engineering")
    edit_response = await client.put(
        f"/api/v1/scans/{scan['id']}",
        headers={"X-CSRF-Token": csrf_token},
        json={"name": "Weekly Auth Scan Updated", "targets": ["10.2.2.2"], "schedule_type": "daily"},
    )
    assert edit_response.status_code == 200
    move_response = await client.post(
        f"/api/v1/scans/{scan['id']}/move",
        headers={"X-CSRF-Token": csrf_token},
        json={"folder_record_id": engineering["id"]},
    )
    assert move_response.status_code == 200
    assert move_response.json()["folder_name"] == "Engineering"
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_scan_clone(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    await client.post("/api/v1/scans/refresh", headers={"X-CSRF-Token": csrf_token})
    scans = await client.get("/api/v1/scans")
    scan = next(item for item in scans.json()["scans"] if item["name"] == "Weekly Auth Scan")
    clone_response = await client.post(
        f"/api/v1/scans/{scan['id']}/clone",
        headers={"X-CSRF-Token": csrf_token},
        json={"name": "Weekly Auth Clone"},
    )
    assert clone_response.status_code == 200
    assert clone_response.json()["name"] == "Weekly Auth Clone"
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_scan_launch_and_duplicate_launch_prevention(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    await client.post("/api/v1/scans/refresh", headers={"X-CSRF-Token": csrf_token})
    scans = await client.get("/api/v1/scans")
    scan = next(item for item in scans.json()["scans"] if item["name"] == "Weekly Auth Scan")
    first_launch = await client.post(f"/api/v1/scans/{scan['id']}/launch", headers={"X-CSRF-Token": csrf_token})
    assert first_launch.status_code == 200
    second_launch = await client.post(f"/api/v1/scans/{scan['id']}/launch", headers={"X-CSRF-Token": csrf_token})
    assert second_launch.status_code == 400
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_scan_stop(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    await client.post("/api/v1/scans/refresh", headers={"X-CSRF-Token": csrf_token})
    scans = await client.get("/api/v1/scans")
    running_scan = next(item for item in scans.json()["scans"] if item["name"] == "Internet Edge")
    response = await client.post(f"/api/v1/scans/{running_scan['id']}/stop", headers={"X-CSRF-Token": csrf_token})
    assert response.status_code == 200
    assert response.json()["status"] == "stopped"
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_scan_pause_and_resume(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    await client.post("/api/v1/scans/refresh", headers={"X-CSRF-Token": csrf_token})
    scans = await client.get("/api/v1/scans")
    running_scan = next(item for item in scans.json()["scans"] if item["name"] == "Internet Edge")
    pause_response = await client.post(f"/api/v1/scans/{running_scan['id']}/pause", headers={"X-CSRF-Token": csrf_token})
    assert pause_response.status_code == 200
    assert pause_response.json()["status"] == "paused"
    resume_response = await client.post(f"/api/v1/scans/{running_scan['id']}/resume", headers={"X-CSRF-Token": csrf_token})
    assert resume_response.status_code == 200
    assert resume_response.json()["status"] == "running"
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_running_scan_deletion_prevention(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    await client.post("/api/v1/scans/refresh", headers={"X-CSRF-Token": csrf_token})
    scans = await client.get("/api/v1/scans")
    running_scan = next(item for item in scans.json()["scans"] if item["name"] == "Internet Edge")
    response = await client.post(f"/api/v1/scans/{running_scan['id']}/trash", headers={"X-CSRF-Token": csrf_token})
    assert response.status_code == 400
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_move_to_trash(app, client, admin_user, db_session) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    await client.post("/api/v1/scans/refresh", headers={"X-CSRF-Token": csrf_token})
    scans = await client.get("/api/v1/scans")
    scan = next(item for item in scans.json()["scans"] if item["name"] == "Weekly Auth Scan")
    response = await client.post(f"/api/v1/scans/{scan['id']}/trash", headers={"X-CSRF-Token": csrf_token})
    assert response.status_code == 200
    db_session.expire_all()
    stored = db_session.get(ScanRecord, scan["id"])
    assert stored is not None
    assert stored.deleted_at is not None
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_restore_and_permanent_delete_flow(app, client, admin_user, db_session) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    await client.post("/api/v1/scans/refresh", headers={"X-CSRF-Token": csrf_token})
    scans = await client.get("/api/v1/scans")
    scan = next(item for item in scans.json()["scans"] if item["name"] == "Weekly Auth Scan")

    trash_response = await client.post(f"/api/v1/scans/{scan['id']}/trash", headers={"X-CSRF-Token": csrf_token})
    assert trash_response.status_code == 200

    state.scans["10"] = {
        "id": 10,
        "uuid": "scan-10",
        "name": "Weekly Auth Scan",
        "folder_id": 8,
        "status": "completed",
        "owner": "admin",
        "targets": "10.0.0.1,server.example.com",
        "scanner_id": 5,
        "schedule_type": "weekly",
        "history": [],
    }
    restore_response = await client.post(f"/api/v1/scans/{scan['id']}/restore", headers={"X-CSRF-Token": csrf_token})
    assert restore_response.status_code == 200
    assert restore_response.json()["deleted_at"] is None

    second_trash = await client.post(f"/api/v1/scans/{scan['id']}/trash", headers={"X-CSRF-Token": csrf_token})
    assert second_trash.status_code == 200
    state.scans.pop("10", None)
    permanent_delete_response = await client.post(
        f"/api/v1/scans/{scan['id']}/permanent-delete",
        headers={"X-CSRF-Token": csrf_token},
        json={"justification": "Retention window closed."},
    )
    assert permanent_delete_response.status_code == 200
    db_session.expire_all()
    stored = db_session.get(ScanRecord, scan["id"])
    assert stored is not None
    assert stored.permanently_deleted_at is not None
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_protected_scan_history_delete_denial_and_allowed_delete(app, client, admin_user, db_session) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    await client.post("/api/v1/scans/refresh", headers={"X-CSRF-Token": csrf_token})
    scans = await client.get("/api/v1/scans")
    scan = next(item for item in scans.json()["scans"] if item["name"] == "Weekly Auth Scan")
    history_response = await client.get(f"/api/v1/scans/{scan['id']}/history")
    assert history_response.status_code == 200
    db_session.expire_all()
    locked_history = db_session.scalar(select(ScanHistoryRecord).where(ScanHistoryRecord.scan_record_id == scan["id"], ScanHistoryRecord.nessus_history_id == "501"))
    deletable_history = db_session.scalar(select(ScanHistoryRecord).where(ScanHistoryRecord.scan_record_id == scan["id"], ScanHistoryRecord.nessus_history_id == "502"))
    locked_history.is_baseline_locked = True
    db_session.commit()
    deny_response = await client.post(
        f"/api/v1/scans/{scan['id']}/history/{locked_history.id}/delete",
        headers={"X-CSRF-Token": csrf_token},
        json={"justification": "baseline protected"},
    )
    assert deny_response.status_code == 400
    delete_response = await client.post(
        f"/api/v1/scans/{scan['id']}/history/{deletable_history.id}/delete",
        headers={"X-CSRF-Token": csrf_token},
        json={"justification": "cleanup"},
    )
    assert delete_response.status_code == 200
    db_session.expire_all()
    deleted_row = db_session.get(ScanHistoryRecord, deletable_history.id)
    assert deleted_row is not None
    assert deleted_row.deleted_at is not None
    audit = db_session.scalar(select(AuditEvent).where(AuditEvent.action == "scans.history.delete"))
    assert audit is not None
    app.dependency_overrides.clear()
