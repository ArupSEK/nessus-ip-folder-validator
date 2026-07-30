from __future__ import annotations

from io import BytesIO

import httpx
import pytest
from openpyxl import Workbook

from backend.app.api.deps import get_nessus_client_factory
from backend.app.integrations.nessus.client import NessusClientFactory
from backend.tests.test_scans import ScanMockState, build_scan_transport, login_admin, save_profile_and_refresh_folders


async def sync_scans(client, csrf_token: str) -> None:
    response = await client.post("/api/v1/scans/refresh", headers={"X-CSRF-Token": csrf_token})
    assert response.status_code == 200


@pytest.mark.anyio
async def test_valid_csv_upload(app, client, admin_user) -> None:
    state = ScanMockState()
    state.scans["21"] = {
        "id": 21,
        "uuid": "scan-21",
        "name": "Auxiliary Scan",
        "folder_id": 9,
        "status": "completed",
        "owner": "admin",
        "targets": "10.0.0.1",
        "scanner_id": 5,
        "schedule_type": "on_demand",
        "history": [],
    }
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    await sync_scans(client, csrf_token)
    files = {"file": ("targets.csv", b"10.0.0.1\n192.168.1.10\n", "text/csv")}
    response = await client.post("/api/v1/ip-search/upload", files=files)
    assert response.status_code == 200
    body = response.json()
    assert body["unique_inputs"] == 2
    target = next(item for item in body["results"] if item["normalized_ip"] == "10.0.0.1")
    assert len(target["matches"]) == 2
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_valid_excel_upload(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    await sync_scans(client, csrf_token)
    workbook = Workbook()
    sheet = workbook.active
    sheet["A1"] = "10.0.0.1"
    sheet["A2"] = "192.168.1.10"
    stream = BytesIO()
    workbook.save(stream)
    files = {"file": ("targets.xlsx", stream.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
    response = await client.post("/api/v1/ip-search/upload", files=files)
    assert response.status_code == 200
    assert response.json()["unique_inputs"] == 2
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_valid_text_upload(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    await sync_scans(client, csrf_token)
    files = {"file": ("targets.txt", b"10.0.0.1\nbad-value\n", "text/plain")}
    response = await client.post("/api/v1/ip-search/upload", files=files)
    assert response.status_code == 200
    assert "bad-value" in response.json()["invalid_inputs"]
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_invalid_ip_handling(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    await sync_scans(client, csrf_token)
    response = await client.post("/api/v1/ip-search/query", json={"entries": ["10.0.0.999", "not-an-ip"]})
    assert response.status_code == 200
    assert len(response.json()["invalid_inputs"]) == 2
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_duplicate_ip_removal(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    await sync_scans(client, csrf_token)
    response = await client.post("/api/v1/ip-search/query", json={"entries": ["10.0.0.1", "10.0.0.1", "10.0.0.1"]})
    assert response.status_code == 200
    assert response.json()["unique_inputs"] == 1
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_ip_not_found(app, client, admin_user) -> None:
    state = ScanMockState()
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_scan_transport(state), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    await sync_scans(client, csrf_token)
    response = await client.post("/api/v1/ip-search/query", json={"entries": ["203.0.113.10"]})
    assert response.status_code == 200
    assert response.json()["results"][0]["matches"] == []
    app.dependency_overrides.clear()
