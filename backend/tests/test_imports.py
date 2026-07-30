from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from backend.app.api.deps import get_nessus_client_factory
from backend.app.integrations.nessus.client import NessusClientFactory
from backend.app.models.asset import AssetRecord
from backend.app.models.finding import FindingRecord
from backend.app.models.import_job import ImportJob
from backend.app.models.scan import ScanHistoryRecord
from backend.tests.test_scans import ScanMockState, build_scan_transport, login_admin, save_profile_and_refresh_folders


NESSUS_EXPORT_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
  <Report name="Example Scan">
    <ReportHost name="server01.example.com">
      <HostProperties>
        <tag name="host-ip">10.0.0.1</tag>
        <tag name="host-fqdn">server01.example.com</tag>
        <tag name="hostname">server01</tag>
        <tag name="mac-address">00:11:22:33:44:55</tag>
        <tag name="operating-system">Linux</tag>
      </HostProperties>
      <ReportItem pluginID="19506" pluginName="Nessus Scan Information" severity="0" port="0" protocol="tcp" pluginFamily="Settings">
        <risk_factor>None</risk_factor>
        <synopsis>Informational</synopsis>
        <plugin_output>Credentialed checks : yes</plugin_output>
      </ReportItem>
      <ReportItem pluginID="1001" pluginName="Critical Finding" severity="4" port="443" protocol="tcp" pluginFamily="General">
        <risk_factor>Critical</risk_factor>
        <synopsis>Critical issue</synopsis>
        <plugin_output>OpenSSL outdated</plugin_output>
      </ReportItem>
    </ReportHost>
    <ReportHost name="db01.example.com">
      <HostProperties>
        <tag name="host-ip">192.168.1.10</tag>
        <tag name="host-fqdn">db01.example.com</tag>
        <tag name="hostname">db01</tag>
      </HostProperties>
      <ReportItem pluginID="2002" pluginName="Medium Finding" severity="2" port="22" protocol="tcp" pluginFamily="General">
        <risk_factor>Medium</risk_factor>
        <synopsis>SSH issue</synopsis>
        <plugin_output>Weak ciphers</plugin_output>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


def build_import_transport(*, fail_status: bool = False):
    base_state = ScanMockState()
    base_transport = build_scan_transport(base_state)

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/export") and request.method == "POST":
            return httpx.Response(200, json={"file": "file-1"})
        if path.endswith("/export/file-1/status") and request.method == "GET":
            if fail_status:
                return httpx.Response(200, json={"status": "processing"})
            return httpx.Response(200, json={"status": "ready"})
        if path.endswith("/export/file-1/download") and request.method == "GET":
            return httpx.Response(200, content=NESSUS_EXPORT_XML, headers={"content-type": "application/octet-stream"})
        return base_transport.handle_request(request)

    return httpx.MockTransport(handler)


async def refresh_scan_inventory(client, csrf_token: str) -> str:
    response = await client.post("/api/v1/scans/refresh", headers={"X-CSRF-Token": csrf_token})
    assert response.status_code == 200
    scan = next(item for item in response.json()["scans"] if item["name"] == "Weekly Auth Scan")
    return scan["id"]


@pytest.mark.anyio
async def test_duplicate_scan_import(app, client, admin_user, db_session) -> None:
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_import_transport(), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    scan_id = await refresh_scan_inventory(client, csrf_token)

    first = await client.post(f"/api/v1/imports/scans/{scan_id}", headers={"X-CSRF-Token": csrf_token}, json={})
    assert first.status_code == 200
    second = await client.post(f"/api/v1/imports/scans/{scan_id}", headers={"X-CSRF-Token": csrf_token}, json={})
    assert second.status_code == 400
    db_session.expire_all()
    assert db_session.scalar(select(AssetRecord)) is not None
    assert db_session.scalar(select(FindingRecord)) is not None
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_interrupted_import_recovery(app, client, admin_user, db_session) -> None:
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_import_transport(fail_status=True), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    scan_id = await refresh_scan_inventory(client, csrf_token)

    failed = await client.post(f"/api/v1/imports/scans/{scan_id}", headers={"X-CSRF-Token": csrf_token}, json={})
    assert failed.status_code == 400
    jobs = await client.get("/api/v1/imports/jobs")
    assert jobs.status_code == 200
    failed_job = jobs.json()["jobs"][0]
    assert failed_job["status"] == "failed"

    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_import_transport(fail_status=False), retries=0)
    recovered = await client.post(
        f"/api/v1/imports/jobs/{failed_job['id']}/recover",
        headers={"X-CSRF-Token": csrf_token},
        json={},
    )
    assert recovered.status_code == 200
    body = recovered.json()
    assert body["job"]["status"] == "completed"
    assert body["job"]["imported_asset_count"] == 2
    assert body["job"]["imported_finding_count"] == 3
    db_session.expire_all()
    job = db_session.get(ImportJob, failed_job["id"])
    assert job is not None
    assert job.status == "completed"
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_import_parses_assets_and_findings(app, client, admin_user, db_session) -> None:
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_import_transport(), retries=0)
    csrf_token = await login_admin(client)
    await save_profile_and_refresh_folders(client, csrf_token)
    scan_id = await refresh_scan_inventory(client, csrf_token)
    history_response = await client.get(f"/api/v1/scans/{scan_id}/history")
    assert history_response.status_code == 200
    histories = history_response.json()["histories"]
    target_history = next(item for item in histories if item["nessus_history_id"] == "501")

    result = await client.post(
        f"/api/v1/imports/scans/{scan_id}",
        headers={"X-CSRF-Token": csrf_token},
        json={"scan_history_record_id": target_history["id"]},
    )
    assert result.status_code == 200
    body = result.json()
    assert len(body["assets"]) == 2
    assert len(body["findings"]) == 3
    db_session.expire_all()
    assert db_session.scalar(select(ScanHistoryRecord).where(ScanHistoryRecord.id == target_history["id"])) is not None
    app.dependency_overrides.clear()
