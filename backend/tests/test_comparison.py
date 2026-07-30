from __future__ import annotations

import json
from uuid import uuid4

import pytest

from backend.app.models.asset import AssetRecord
from backend.app.models.finding import FindingRecord
from backend.app.models.import_job import ImportJob
from backend.app.models.scan import ScanRecord


def _seed_job(db_session, *, scan_name: str, template_uuid: str, status_meta: dict[str, str] | None = None):
    scan = ScanRecord(
        nessus_scan_id=str(uuid4()),
        nessus_uuid=str(uuid4()),
        name=scan_name,
        template_uuid=template_uuid,
        status="completed",
    )
    db_session.add(scan)
    db_session.flush()
    job = ImportJob(scan_record_id=scan.id, job_scope_key=str(uuid4()), status="completed", progress_percent=100)
    db_session.add(job)
    db_session.flush()
    asset = AssetRecord(
        stable_asset_key=f"{scan_name.lower()}-asset",
        source_import_job_id=job.id,
        source_scan_record_id=scan.id,
        hostname=scan_name.lower(),
        ipv4_address="10.0.0.1",
        raw_metadata=json.dumps(status_meta or {}, sort_keys=True),
    )
    db_session.add(asset)
    db_session.flush()
    return scan, job, asset


async def _login(client) -> str:
    response = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongPass123!"})
    assert response.status_code == 200
    return response.json()["csrf_token"]


@pytest.mark.anyio
async def test_comparable_scan_pair_and_existing_finding(client, admin_user, db_session) -> None:
    _, previous_job, previous_asset = _seed_job(db_session, scan_name="PrevScan", template_uuid="tmpl-a")
    _, latest_job, latest_asset = _seed_job(db_session, scan_name="PrevScan", template_uuid="tmpl-a")
    db_session.add(FindingRecord(finding_key="asset:1001:443:tcp", source_import_job_id=previous_job.id, source_scan_record_id=previous_job.scan_record_id, asset_record_id=previous_asset.id, plugin_id=1001, plugin_name="A", severity=3, port=443, protocol="tcp"))
    db_session.add(FindingRecord(finding_key="asset:1001:443:tcp", source_import_job_id=latest_job.id, source_scan_record_id=latest_job.scan_record_id, asset_record_id=latest_asset.id, plugin_id=1001, plugin_name="A", severity=3, port=443, protocol="tcp"))
    db_session.commit()

    csrf = await _login(client)
    response = await client.post("/api/v1/comparisons/run", headers={"X-CSRF-Token": csrf}, json={"previous_import_job_id": previous_job.id, "latest_import_job_id": latest_job.id})
    assert response.status_code == 200
    body = response.json()
    assert body["comparable_asset_count"] == 1
    assert body["existing_count"] == 1
    assert body["results"][0]["comparison_eligibility"] == "comparable"


@pytest.mark.anyio
async def test_unreachable_latest_asset_and_not_validated(client, admin_user, db_session) -> None:
    _, previous_job, previous_asset = _seed_job(db_session, scan_name="Unreach", template_uuid="tmpl-a")
    _, latest_job, _ = _seed_job(db_session, scan_name="Unreach", template_uuid="tmpl-a", status_meta={"reachability_status": "unreachable"})
    db_session.add(FindingRecord(finding_key="unreach-asset:1001:443:tcp", source_import_job_id=previous_job.id, source_scan_record_id=previous_job.scan_record_id, asset_record_id=previous_asset.id, plugin_id=1001, plugin_name="A", severity=3, port=443, protocol="tcp"))
    db_session.commit()

    csrf = await _login(client)
    response = await client.post("/api/v1/comparisons/run", headers={"X-CSRF-Token": csrf}, json={"previous_import_job_id": previous_job.id, "latest_import_job_id": latest_job.id})
    assert response.status_code == 200
    result = response.json()["results"][0]
    assert result["comparison_eligibility"] == "host_unreachable"
    assert result["lifecycle_status"] == "Not Validated"


@pytest.mark.anyio
async def test_auth_failure_latest_asset(client, admin_user, db_session) -> None:
    _, previous_job, previous_asset = _seed_job(db_session, scan_name="AuthFail", template_uuid="tmpl-a")
    _, latest_job, _ = _seed_job(db_session, scan_name="AuthFail", template_uuid="tmpl-a", status_meta={"authentication_status": "failed"})
    db_session.add(FindingRecord(finding_key="authfail-asset:1001:443:tcp", source_import_job_id=previous_job.id, source_scan_record_id=previous_job.scan_record_id, asset_record_id=previous_asset.id, plugin_id=1001, plugin_name="A", severity=3, port=443, protocol="tcp"))
    db_session.commit()

    csrf = await _login(client)
    response = await client.post("/api/v1/comparisons/run", headers={"X-CSRF-Token": csrf}, json={"previous_import_job_id": previous_job.id, "latest_import_job_id": latest_job.id})
    assert response.status_code == 200
    assert response.json()["results"][0]["comparison_eligibility"] == "authentication_failed"


@pytest.mark.anyio
async def test_policy_mismatch_and_closed_finding(client, admin_user, db_session) -> None:
    _, previous_job, previous_asset = _seed_job(db_session, scan_name="Policy", template_uuid="tmpl-a")
    _, latest_job, _ = _seed_job(db_session, scan_name="Policy", template_uuid="tmpl-b")
    db_session.add(FindingRecord(finding_key="policy-asset:1001:443:tcp", source_import_job_id=previous_job.id, source_scan_record_id=previous_job.scan_record_id, asset_record_id=previous_asset.id, plugin_id=1001, plugin_name="A", severity=3, port=443, protocol="tcp"))
    db_session.commit()

    csrf = await _login(client)
    response = await client.post("/api/v1/comparisons/run", headers={"X-CSRF-Token": csrf}, json={"previous_import_job_id": previous_job.id, "latest_import_job_id": latest_job.id})
    assert response.status_code == 200
    result = response.json()["results"][0]
    assert result["comparison_eligibility"] == "policy_mismatch"
    assert result["lifecycle_status"] == "Not Validated"


@pytest.mark.anyio
async def test_new_severity_changed_and_port_changed(client, admin_user, db_session) -> None:
    _, previous_job, previous_asset = _seed_job(db_session, scan_name="Diffs", template_uuid="tmpl-a")
    _, latest_job, latest_asset = _seed_job(db_session, scan_name="Diffs", template_uuid="tmpl-a")
    db_session.add(FindingRecord(finding_key="diffs-asset:1001:443:tcp", source_import_job_id=previous_job.id, source_scan_record_id=previous_job.scan_record_id, asset_record_id=previous_asset.id, plugin_id=1001, plugin_name="A", severity=2, port=443, protocol="tcp"))
    db_session.add(FindingRecord(finding_key="diffs-asset:1001:443:tcp", source_import_job_id=latest_job.id, source_scan_record_id=latest_job.scan_record_id, asset_record_id=latest_asset.id, plugin_id=1001, plugin_name="A", severity=4, port=443, protocol="tcp"))
    db_session.add(FindingRecord(finding_key="diffs-asset:2002:22:tcp", source_import_job_id=previous_job.id, source_scan_record_id=previous_job.scan_record_id, asset_record_id=previous_asset.id, plugin_id=2002, plugin_name="B", severity=2, port=22, protocol="tcp"))
    db_session.add(FindingRecord(finding_key="diffs-asset:2002:2222:tcp", source_import_job_id=latest_job.id, source_scan_record_id=latest_job.scan_record_id, asset_record_id=latest_asset.id, plugin_id=2002, plugin_name="B", severity=2, port=2222, protocol="tcp"))
    db_session.add(FindingRecord(finding_key="diffs-asset:3003:80:tcp", source_import_job_id=latest_job.id, source_scan_record_id=latest_job.scan_record_id, asset_record_id=latest_asset.id, plugin_id=3003, plugin_name="C", severity=1, port=80, protocol="tcp"))
    db_session.commit()

    csrf = await _login(client)
    response = await client.post("/api/v1/comparisons/run", headers={"X-CSRF-Token": csrf}, json={"previous_import_job_id": previous_job.id, "latest_import_job_id": latest_job.id})
    assert response.status_code == 200
    lifecycles = {item["lifecycle_status"] for item in response.json()["results"]}
    assert "Severity Changed" in lifecycles
    assert "Port Changed" in lifecycles
    assert "New" in lifecycles


@pytest.mark.anyio
async def test_reopened_finding(client, admin_user, db_session) -> None:
    _, baseline_job, baseline_asset = _seed_job(db_session, scan_name="Reopen", template_uuid="tmpl-a")
    _, mid_job, _ = _seed_job(db_session, scan_name="Reopen", template_uuid="tmpl-a")
    _, latest_job, latest_asset = _seed_job(db_session, scan_name="Reopen", template_uuid="tmpl-a")
    db_session.add(FindingRecord(finding_key="reopen-asset:1001:443:tcp", source_import_job_id=baseline_job.id, source_scan_record_id=baseline_job.scan_record_id, asset_record_id=baseline_asset.id, plugin_id=1001, plugin_name="A", severity=3, port=443, protocol="tcp"))
    db_session.add(FindingRecord(finding_key="reopen-asset:1001:443:tcp", source_import_job_id=latest_job.id, source_scan_record_id=latest_job.scan_record_id, asset_record_id=latest_asset.id, plugin_id=1001, plugin_name="A", severity=3, port=443, protocol="tcp"))
    db_session.commit()

    csrf = await _login(client)
    first = await client.post("/api/v1/comparisons/run", headers={"X-CSRF-Token": csrf}, json={"previous_import_job_id": baseline_job.id, "latest_import_job_id": mid_job.id})
    assert first.status_code == 200
    second = await client.post("/api/v1/comparisons/run", headers={"X-CSRF-Token": csrf}, json={"previous_import_job_id": mid_job.id, "latest_import_job_id": latest_job.id})
    assert second.status_code == 200
    lifecycles = {item["lifecycle_status"] for item in second.json()["results"]}
    assert "Reopened" in lifecycles
