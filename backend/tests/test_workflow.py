from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from backend.app.models.asset import AssetRecord
from backend.app.models.asset_review import AssetReviewRecord
from backend.app.models.auth import AuditEvent
from backend.app.models.finding import FindingRecord
from backend.app.models.scan import ScanRecord
from backend.app.models.workflow import FindingWorkflow, WorkflowDecision
from backend.app.services.auth import utc_now
from backend.app.services.workflow import queue_ambiguous_asset_reviews


def _seed_finding(db_session, *, finding_key: str, severity: int = 4) -> FindingRecord:
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
        severity=severity,
        port=443,
        protocol="tcp",
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)
    return finding


async def _login(client, username: str = "admin", password: str = "StrongPass123!") -> str:
    response = await client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["csrf_token"]


@pytest.mark.anyio
async def test_sla_calculation(client, admin_user, db_session) -> None:
    finding = _seed_finding(db_session, finding_key="asset-1:1001:443:tcp", severity=4)
    csrf = await _login(client)
    response = await client.put(
        f"/api/v1/workflows/findings/{finding.finding_key}",
        headers={"X-CSRF-Token": csrf},
        json={"owner": "alice", "remediation_team": "patching", "workflow_status": "Assigned"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["owner"] == "alice"
    assert body["workflow_status"] == "Assigned"
    assert body["sla_start_date"] is not None
    assert body["due_date"] is not None
    assert body["days_overdue"] == 0
    assert body["is_technically_open"] is True


@pytest.mark.anyio
async def test_expired_exception_returns_to_queue(client, admin_user, db_session) -> None:
    finding = _seed_finding(db_session, finding_key="asset-2:1001:443:tcp", severity=3)
    csrf = await _login(client)
    request_response = await client.post(
        "/api/v1/workflows/decisions",
        headers={"X-CSRF-Token": csrf},
        json={
            "finding_key": finding.finding_key,
            "decision_type": "exception",
            "reason": "Maintenance window delay",
            "expiry_date": (utc_now().date() - timedelta(days=1)).isoformat(),
        },
    )
    assert request_response.status_code == 200
    decision_id = request_response.json()["id"]

    approve_response = await client.post(
        f"/api/v1/workflows/decisions/{decision_id}/approve",
        headers={"X-CSRF-Token": csrf},
        json={"justification": "Approved for a short grace period."},
    )
    assert approve_response.status_code == 200
    expire_response = await client.post("/api/v1/workflows/maintenance/expire", headers={"X-CSRF-Token": csrf})
    assert expire_response.status_code == 200
    assert expire_response.json()["expired_count"] >= 1

    workflow = db_session.scalar(select(FindingWorkflow).where(FindingWorkflow.finding_key == finding.finding_key))
    decision = db_session.get(WorkflowDecision, decision_id)
    assert workflow is not None
    assert decision is not None
    assert workflow.workflow_status == "Open"
    assert decision.status == "expired"


@pytest.mark.anyio
async def test_accepted_risk_remains_open(client, admin_user, db_session) -> None:
    finding = _seed_finding(db_session, finding_key="asset-3:1001:443:tcp", severity=2)
    csrf = await _login(client)
    request_response = await client.post(
        "/api/v1/workflows/decisions",
        headers={"X-CSRF-Token": csrf},
        json={
            "finding_key": finding.finding_key,
            "decision_type": "risk_acceptance",
            "reason": "Legacy dependency",
            "business_justification": "Business cannot patch this quarter.",
        },
    )
    assert request_response.status_code == 200
    decision_id = request_response.json()["id"]
    approve_response = await client.post(
        f"/api/v1/workflows/decisions/{decision_id}/approve",
        headers={"X-CSRF-Token": csrf},
        json={"justification": "Risk accepted by owner."},
    )
    assert approve_response.status_code == 200

    workflow_response = await client.get(f"/api/v1/workflows/findings/{finding.finding_key}")
    assert workflow_response.status_code == 200
    workflow_body = workflow_response.json()
    assert workflow_body["workflow_status"] == "Risk accepted"
    assert workflow_body["is_technically_open"] is True
    assert workflow_body["actual_remediation_date"] is None


@pytest.mark.anyio
async def test_workflow_audit_generation(client, admin_user, db_session) -> None:
    finding = _seed_finding(db_session, finding_key="asset-4:1001:443:tcp", severity=1)
    csrf = await _login(client)
    update_response = await client.put(
        f"/api/v1/workflows/findings/{finding.finding_key}",
        headers={"X-CSRF-Token": csrf},
        json={"comments": "Queued for next patch cycle.", "workflow_status": "Open"},
    )
    assert update_response.status_code == 200
    decision_response = await client.post(
        "/api/v1/workflows/decisions",
        headers={"X-CSRF-Token": csrf},
        json={"finding_key": finding.finding_key, "decision_type": "false_positive", "reason": "Compensating control verified"},
    )
    assert decision_response.status_code == 200

    actions = {row.action for row in db_session.scalars(select(AuditEvent).where(AuditEvent.object_name == finding.finding_key)).all()}
    assert "findings.workflow.update" in actions
    assert "false_positive.request" in actions


@pytest.mark.anyio
async def test_asset_review_queue_and_merge_split(client, admin_user, db_session) -> None:
    scan = ScanRecord(
        nessus_scan_id=str(uuid4()),
        nessus_uuid=str(uuid4()),
        name="asset-review-scan",
        status="completed",
    )
    db_session.add(scan)
    db_session.flush()
    left = AssetRecord(
        stable_asset_key="asset-a",
        source_import_job_id=str(uuid4()),
        source_scan_record_id=scan.id,
        hostname="host-1",
        ipv4_address="10.0.0.10",
    )
    right = AssetRecord(
        stable_asset_key="asset-b",
        source_import_job_id=str(uuid4()),
        source_scan_record_id=scan.id,
        hostname="host-1",
        ipv4_address="10.0.0.10",
    )
    db_session.add_all([left, right])
    db_session.flush()
    queue_ambiguous_asset_reviews(db_session, [left, right])
    db_session.commit()

    csrf = await _login(client)
    pending = await client.get("/api/v1/workflows/asset-reviews")
    assert pending.status_code == 200
    assert pending.json()["total"] >= 1
    review_id = pending.json()["reviews"][0]["id"]

    merge_response = await client.post(
        f"/api/v1/workflows/asset-reviews/{review_id}/merge",
        headers={"X-CSRF-Token": csrf},
        json={"canonical_asset_key": "asset-a", "notes": "Same host after analyst review."},
    )
    assert merge_response.status_code == 200
    assert merge_response.json()["status"] == "merged"

    second_review = AssetReviewRecord(
        left_asset_key="asset-c",
        right_asset_key="asset-d",
        match_basis="hostname",
        status="pending",
    )
    db_session.add(second_review)
    db_session.commit()

    split_response = await client.post(
        f"/api/v1/workflows/asset-reviews/{second_review.id}/split",
        headers={"X-CSRF-Token": csrf},
        json={"notes": "Different systems behind reused DNS."},
    )
    assert split_response.status_code == 200
    assert split_response.json()["status"] == "split"
