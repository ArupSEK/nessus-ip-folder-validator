from __future__ import annotations

from uuid import uuid4

import pytest

from backend.app.models.finding import FindingRecord
from backend.app.models.scan import ScanRecord
from backend.app.services.auth import utc_now


def _seed_finding(db_session, *, finding_key: str) -> FindingRecord:
    scan = ScanRecord(
        nessus_scan_id=str(uuid4()),
        nessus_uuid=str(uuid4()),
        name=f"scan-{uuid4()}",
        status="completed",
    )
    db_session.add(scan)
    db_session.flush()
    finding = FindingRecord(
        finding_key=finding_key,
        source_import_job_id=str(uuid4()),
        source_scan_record_id=scan.id,
        asset_record_id=str(uuid4()),
        plugin_id=1001,
        plugin_name="Example",
        severity=3,
        port=443,
        protocol="tcp",
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)
    return finding


async def _login(client, username: str, password: str) -> str:
    response = await client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["csrf_token"]


@pytest.mark.anyio
async def test_csrf_rejection_for_workflow_update(client, admin_user, db_session) -> None:
    finding = _seed_finding(db_session, finding_key="csrf-asset:1001:443:tcp")
    await _login(client, "admin", "StrongPass123!")
    response = await client.put(
        f"/api/v1/workflows/findings/{finding.finding_key}",
        json={"workflow_status": "Assigned"},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "CSRF validation failed."


@pytest.mark.anyio
async def test_csrf_rejection_for_workflow_decision_request(client, admin_user, db_session) -> None:
    finding = _seed_finding(db_session, finding_key="csrf-decision-asset:1001:443:tcp")
    await _login(client, "admin", "StrongPass123!")
    response = await client.post(
        "/api/v1/workflows/decisions",
        json={"finding_key": finding.finding_key, "decision_type": "exception", "reason": "Missing header"},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "CSRF validation failed."


@pytest.mark.anyio
async def test_readonly_user_cannot_update_workflow(client, admin_user, readonly_user, db_session) -> None:
    finding = _seed_finding(db_session, finding_key="readonly-asset:1001:443:tcp")
    csrf = await _login(client, "viewer", "StrongPass123!")
    response = await client.put(
        f"/api/v1/workflows/findings/{finding.finding_key}",
        headers={"X-CSRF-Token": csrf},
        json={"workflow_status": "Assigned"},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions."


@pytest.mark.anyio
async def test_readonly_user_cannot_export_deleted_audit(client, admin_user, readonly_user) -> None:
    await _login(client, "viewer", "StrongPass123!")
    response = await client.get(
        "/api/v1/reports/export",
        params={"report_type": "deleted_objects_audit", "export_format": "csv"},
    )
    assert response.status_code == 403


@pytest.mark.anyio
async def test_destructive_action_replay_is_rejected(client, admin_user, db_session) -> None:
    scan = ScanRecord(
        nessus_scan_id=str(uuid4()),
        nessus_uuid=str(uuid4()),
        name="replay-scan",
        status="completed",
        deleted_at=utc_now(),
        permanently_deleted_at=utc_now(),
    )
    db_session.add(scan)
    db_session.commit()

    csrf = await _login(client, "admin", "StrongPass123!")
    response = await client.post(
        f"/api/v1/scans/{scan.id}/permanent-delete",
        headers={"X-CSRF-Token": csrf},
        json={"justification": "replay"},
    )
    assert response.status_code == 400
