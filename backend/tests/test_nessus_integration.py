from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from backend.app.api.routes.nessus import get_nessus_client_factory
from backend.app.integrations.nessus.client import NessusApiClient, NessusClientFactory, NessusResponseError
from backend.app.models.auth import AuditEvent
from backend.app.models.nessus import NessusConfiguration


def build_transport(handler):
    return httpx.MockTransport(handler)


async def login_admin(client) -> str:
    response = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "StrongPass123!"})
    assert response.status_code == 200
    return response.json()["csrf_token"]


def success_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/server/properties":
        return httpx.Response(200, json={"nessus_type": "manager", "server_version": "10.8.3", "uuid": "srv-1"})
    if request.url.path == "/api/v3/access-control/permissions/users/me":
        return httpx.Response(200, json={"permissions": ["SCAN_MANAGER", "SYSTEM_ADMINISTRATOR"]})
    if request.url.path == "/folders":
        return httpx.Response(200, json={"folders": [{"id": 1, "name": "My Scans", "type": "main"}]})
    if request.url.path == "/scans":
        return httpx.Response(200, json={"scans": [{"id": 10, "uuid": "scan-1", "name": "Weekly Scan", "status": "completed"}]})
    return httpx.Response(404, json={})


@pytest.mark.anyio
async def test_valid_mocked_nessus_connection(app, client, admin_user) -> None:
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_transport(success_handler), retries=0)
    csrf_token = await login_admin(client)
    response = await client.post(
        "/api/v1/nessus/configuration/test",
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
    body = response.json()
    assert body["server_info"]["server_version"] == "10.8.3"
    assert body["capabilities"]["folders.list"] is True
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_invalid_api_credentials(app, client, admin_user) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid"})

    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_transport(handler), retries=0)
    csrf_token = await login_admin(client)
    response = await client.post(
        "/api/v1/nessus/configuration/test",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "base_url": "https://scanner.example.com:8834",
            "access_key": "TOPSECRETACCESS",
            "secret_key": "TOPSECRETSECRET",
            "verify_tls": True,
            "timeout_seconds": 15,
            "approved_hosts": [],
        },
    )
    assert response.status_code == 400
    assert "TOPSECRETACCESS" not in response.text
    assert "TOPSECRETSECRET" not in response.text
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_timeout_error(app, client, admin_user) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_transport(handler), retries=0)
    csrf_token = await login_admin(client)
    response = await client.post(
        "/api/v1/nessus/configuration/test",
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
    assert response.status_code == 502
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_rate_limit_error(app, client, admin_user) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": "slow down"})

    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_transport(handler), retries=0)
    csrf_token = await login_admin(client)
    response = await client.post(
        "/api/v1/nessus/configuration/test",
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
    assert response.status_code == 503
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_missing_api_fields_are_handled(app, client, admin_user) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/server/properties":
            return httpx.Response(200, json={"nessus_type": "manager"})
        if request.url.path == "/api/v3/access-control/permissions/users/me":
            return httpx.Response(404, json={})
        if request.url.path == "/folders":
            return httpx.Response(200, json={"folders": []})
        if request.url.path == "/scans":
            return httpx.Response(200, json={"scans": []})
        return httpx.Response(404, json={})

    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_transport(handler), retries=0)
    csrf_token = await login_admin(client)
    response = await client.post(
        "/api/v1/nessus/configuration/test",
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
    body = response.json()
    assert body["server_info"]["nessus_type"] == "manager"
    assert body["api_permissions"] == []
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_server_properties_with_non_string_fields_are_normalized(app, client, admin_user) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/server/properties":
            return httpx.Response(
                200,
                json={
                    "nessus_type": "manager",
                    "server_version": "10.8.3",
                    "license": {"type": "Nessus Professional"},
                    "expiration": 1786018925,
                },
            )
        if request.url.path == "/api/v3/access-control/permissions/users/me":
            return httpx.Response(200, json={"permissions": ["SCAN_MANAGER"]})
        if request.url.path == "/folders":
            return httpx.Response(200, json={"folders": []})
        if request.url.path == "/scans":
            return httpx.Response(200, json={"scans": []})
        return httpx.Response(404, json={})

    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_transport(handler), retries=0)
    csrf_token = await login_admin(client)
    response = await client.post(
        "/api/v1/nessus/configuration/test",
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
    body = response.json()
    assert body["server_info"]["license"] == "Nessus Professional"
    assert body["server_info"]["expiration"] == "1786018925"
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_scan_api_capability_flag_is_exposed(app, client, admin_user) -> None:
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
        if request.url.path == "/api/v3/access-control/permissions/users/me":
            return httpx.Response(200, json={"permissions": ["SCAN_MANAGER"]})
        if request.url.path == "/folders":
            return httpx.Response(200, json={"folders": []})
        if request.url.path == "/scans":
            return httpx.Response(200, json={"scans": []})
        if request.url.path == "/editor/scan/templates":
            return httpx.Response(200, json={"templates": []})
        if request.url.path == "/policies":
            return httpx.Response(200, json={"policies": []})
        if request.url.path == "/scanners":
            return httpx.Response(200, json={"scanners": []})
        return httpx.Response(404, json={})

    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_transport(handler), retries=0)
    csrf_token = await login_admin(client)
    response = await client.post(
        "/api/v1/nessus/configuration/test",
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
    body = response.json()
    assert body["capabilities"]["scans.api"] is False
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_encrypted_credential_storage(app, client, admin_user, db_session) -> None:
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_transport(success_handler), retries=0)
    csrf_token = await login_admin(client)
    response = await client.put(
        "/api/v1/nessus/configuration",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "base_url": "https://scanner.example.com:8834",
            "access_key": "ACCESSKEY12345",
            "secret_key": "SECRETKEY12345",
            "verify_tls": True,
            "timeout_seconds": 20,
            "approved_hosts": ["scanner.example.com"],
        },
    )
    assert response.status_code == 200
    db_session.expire_all()
    config = db_session.scalar(select(NessusConfiguration))
    assert config is not None
    assert "ACCESSKEY12345" not in config.access_key_encrypted
    assert "SECRETKEY12345" not in config.secret_key_encrypted
    assert config.masked_access_key == "ACCE...2345"
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_reset_nessus_credentials_generates_audit(app, client, admin_user, db_session) -> None:
    app.dependency_overrides[get_nessus_client_factory] = lambda: NessusClientFactory(transport=build_transport(success_handler), retries=0)
    csrf_token = await login_admin(client)
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
    reset_response = await client.post(
        "/api/v1/nessus/configuration/reset",
        headers={"X-CSRF-Token": csrf_token},
        json={"current_password": "StrongPass123!", "confirmation_text": "RESET NESSUS CREDENTIALS"},
    )
    assert reset_response.status_code == 200
    db_session.expire_all()
    assert db_session.scalar(select(NessusConfiguration)) is None
    audit = db_session.scalar(select(AuditEvent).where(AuditEvent.action == "nessus.configuration.reset"))
    assert audit is not None
    app.dependency_overrides.clear()


@pytest.mark.anyio
async def test_ssrf_rejection(client, admin_user) -> None:
    csrf_token = await login_admin(client)
    response = await client.post(
        "/api/v1/nessus/configuration/test",
        headers={"X-CSRF-Token": csrf_token},
        json={
            "base_url": "https://127.0.0.1:8834",
            "access_key": "ACCESSKEY12345",
            "secret_key": "SECRETKEY12345",
            "verify_tls": True,
            "timeout_seconds": 15,
            "approved_hosts": [],
        },
    )
    assert response.status_code == 400


def test_redirect_responses_are_blocked() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://evil.example.com"})

    client = NessusApiClient(
        base_url="https://scanner.example.com:8834",
        access_key="ACCESSKEY12345",
        secret_key="SECRETKEY12345",
        transport=build_transport(handler),
        retries=0,
    )
    with pytest.raises(NessusResponseError, match="redirect"):
        client.validate_connection(approved_hosts=[])


def test_unexpected_status_includes_safe_error_details() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "Invalid 'name' field"})

    client = NessusApiClient(
        base_url="https://scanner.example.com:8834",
        access_key="ACCESSKEY12345",
        secret_key="SECRETKEY12345",
        verify_tls=True,
        timeout_seconds=15,
        transport=build_transport(handler),
        retries=0,
    )
    with pytest.raises(NessusResponseError) as exc_info:
        client.create_folder("bad name")
    assert "unexpected status 400" in str(exc_info.value)
    assert "Invalid 'name' field" in str(exc_info.value)


def test_empty_success_response_is_accepted_for_delete() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/folders/12":
            return httpx.Response(200, content=b"")
        return httpx.Response(404, json={})

    client = NessusApiClient(
        base_url="https://scanner.example.com:8834",
        access_key="ACCESSKEY12345",
        secret_key="SECRETKEY12345",
        verify_tls=True,
        timeout_seconds=15,
        transport=build_transport(handler),
        retries=0,
    )
    client.delete_folder("12")
