from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


class NessusClientError(RuntimeError):
    pass


class NessusConnectivityError(NessusClientError):
    pass


class NessusAuthenticationError(NessusClientError):
    pass


class NessusRateLimitError(NessusClientError):
    pass


class NessusResponseError(NessusClientError):
    pass


class ServerInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    nessus_type: str | None = None
    server_version: str | None = None
    uuid: str | None = None
    license: str | None = None
    expiration: str | None = None
    loaded_plugin_set: str | None = None

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "ServerInfo":
        def _coerce_text(value: Any) -> str | None:
            if value in (None, ""):
                return None
            if isinstance(value, dict):
                for key in ("title", "name", "type", "label", "product"):
                    candidate = value.get(key)
                    if candidate not in (None, ""):
                        return str(candidate)
            return str(value)

        normalized = {
            "nessus_type": _coerce_text(payload.get("nessus_type") or payload.get("product") or payload.get("type")),
            "server_version": _coerce_text(payload.get("server_version") or payload.get("version")),
            "uuid": _coerce_text(payload.get("uuid") or payload.get("server_uuid")),
            "license": _coerce_text(payload.get("license") or payload.get("license_type")),
            "expiration": _coerce_text(payload.get("expiration")),
            "loaded_plugin_set": _coerce_text(payload.get("loaded_plugin_set") or payload.get("plugin_set")),
        }
        return cls(**normalized)


class FolderSummary(BaseModel):
    id: int | str | None = None
    name: str = ""
    type: str | None = None
    custom: bool | None = None
    owner: str | None = None


class ScanSummary(BaseModel):
    id: int | str | None = None
    uuid: str | None = None
    name: str = ""
    folder_id: int | str | None = None
    status: str | None = None
    owner: str | None = None


class TemplateSummary(BaseModel):
    uuid: str = ""
    title: str = ""
    name: str | None = None


class PolicySummary(BaseModel):
    id: int | str | None = None
    name: str = ""
    template_uuid: str | None = None
    owner: str | None = None
    has_credentials: int | bool | None = None


class ScannerSummary(BaseModel):
    id: int | str | None = None
    name: str = ""
    type: str | None = None
    status: str | None = None


class ScanHistorySummary(BaseModel):
    history_id: int | str | None = None
    uuid: str | None = None
    status: str | None = None
    creation_date: int | str | None = None
    last_modification_date: int | str | None = None


class ConnectionValidationResult(BaseModel):
    base_url: str
    verify_tls: bool
    timeout_seconds: int
    approved_hosts: list[str] = Field(default_factory=list)
    server_info: dict = Field(default_factory=dict)
    api_permissions: list[str] = Field(default_factory=list)
    capabilities: dict = Field(default_factory=dict)


@dataclass(slots=True)
class NessusClientFactory:
    transport: httpx.BaseTransport | None = None
    retries: int = 2
    sleep_fn: Any = time.sleep

    def create(
        self,
        *,
        base_url: str,
        access_key: str,
        secret_key: str,
        verify_tls: bool,
        timeout_seconds: int,
    ) -> "NessusApiClient":
        return NessusApiClient(
            base_url=base_url,
            access_key=access_key,
            secret_key=secret_key,
            verify_tls=verify_tls,
            timeout_seconds=timeout_seconds,
            transport=self.transport,
            retries=self.retries,
            sleep_fn=self.sleep_fn,
        )


class NessusApiClient:
    def __init__(
        self,
        *,
        base_url: str,
        access_key: str,
        secret_key: str,
        verify_tls: bool = True,
        timeout_seconds: int = 15,
        transport: httpx.BaseTransport | None = None,
        retries: int = 2,
        sleep_fn: Any = time.sleep,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify_tls = verify_tls
        self.timeout_seconds = timeout_seconds
        self._transport = transport
        self._retries = retries
        self._sleep_fn = sleep_fn
        self._headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
        }

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.base_url,
            headers=self._headers,
            timeout=self.timeout_seconds,
            verify=self.verify_tls,
            follow_redirects=False,
            transport=self._transport,
        )

    @staticmethod
    def _summarize_error_response(response: httpx.Response) -> str:
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            for key in ("error", "message", "detail"):
                value = payload.get(key)
                if value not in (None, ""):
                    return str(value)[:200]
        text = response.text.strip()
        return text[:200] if text else ""

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        expected_statuses: tuple[int, ...] = (200,),
        allow_missing: bool = False,
    ) -> dict[str, Any]:
        backoff = 0.2
        for attempt in range(self._retries + 1):
            try:
                with self._client() as client:
                    response = client.request(method, path, params=params, json=json_body)
            except httpx.TimeoutException as exc:
                if attempt < self._retries:
                    self._sleep_fn(backoff)
                    backoff *= 2
                    continue
                raise NessusConnectivityError("Timed out while connecting to Nessus.") from exc
            except httpx.HTTPError as exc:
                if attempt < self._retries:
                    self._sleep_fn(backoff)
                    backoff *= 2
                    continue
                raise NessusConnectivityError("Could not connect to Nessus.") from exc

            if 300 <= response.status_code < 400:
                raise NessusResponseError("Nessus returned a redirect, which is blocked by policy.")
            if response.status_code == 401:
                raise NessusAuthenticationError("Nessus API authentication failed.")
            if response.status_code == 403:
                raise NessusAuthenticationError("The Nessus API account does not have permission for this action.")
            if response.status_code == 404 and allow_missing:
                return {}
            if response.status_code == 429:
                if attempt < self._retries:
                    self._sleep_fn(backoff)
                    backoff *= 2
                    continue
                raise NessusRateLimitError("Nessus rate limited the request.")
            if response.status_code >= 500:
                if attempt < self._retries:
                    self._sleep_fn(backoff)
                    backoff *= 2
                    continue
                error_summary = self._summarize_error_response(response)
                detail = f": {error_summary}" if error_summary else ""
                raise NessusResponseError(f"Nessus returned a server error ({response.status_code}){detail}.")
            if response.status_code not in expected_statuses:
                error_summary = self._summarize_error_response(response)
                detail = f": {error_summary}" if error_summary else ""
                raise NessusResponseError(f"Nessus returned unexpected status {response.status_code}{detail}.")
            if response.status_code == 204:
                return {}
            if not response.content or not response.text.strip():
                return {}
            try:
                return response.json()
            except ValueError:
                raise NessusResponseError("Nessus returned a non-JSON response.") from None

        raise NessusResponseError("Nessus request retry budget exhausted.")

    def get_server_info(self) -> ServerInfo:
        payload = self._request("GET", "/server/properties")
        return ServerInfo.from_payload(payload)

    def get_current_permissions(self) -> list[str]:
        payload = self._request("GET", "/api/v3/access-control/permissions/users/me", allow_missing=True)
        raw_permissions = payload.get("permissions") or payload.get("data") or []
        permissions: list[str] = []
        if isinstance(raw_permissions, list):
            for item in raw_permissions:
                if isinstance(item, str):
                    permissions.append(item)
                elif isinstance(item, dict):
                    name = item.get("name") or item.get("permission") or item.get("id")
                    if name:
                        permissions.append(str(name))
        return sorted(set(permissions))

    def list_folders(self) -> list[FolderSummary]:
        payload = self._request("GET", "/folders")
        folders = payload.get("folders") or []
        return [FolderSummary.model_validate(item) for item in folders if isinstance(item, dict)]

    def list_scans(self) -> list[ScanSummary]:
        payload = self._request("GET", "/scans")
        scans = payload.get("scans") or []
        return [ScanSummary.model_validate(item) for item in scans if isinstance(item, dict)]

    def create_folder(self, name: str) -> FolderSummary:
        payload = self._request("POST", "/folders", json_body={"name": name}, expected_statuses=(200, 201))
        folder_payload = payload.get("folder") if isinstance(payload.get("folder"), dict) else payload
        if not isinstance(folder_payload, dict):
            raise NessusResponseError("Nessus did not return folder data for the create request.")
        created = FolderSummary.model_validate(folder_payload)
        if created.id is not None and created.name:
            return created
        if created.id is not None:
            for folder in self.list_folders():
                if str(folder.id) == str(created.id):
                    return folder
        return FolderSummary(
            id=created.id,
            name=name,
            type=created.type or "custom",
            custom=True if created.custom is None else created.custom,
            owner=created.owner,
        )

    def rename_folder(self, folder_id: str, name: str) -> FolderSummary:
        payload = self._request("PUT", f"/folders/{folder_id}", json_body={"name": name})
        folder_payload = payload.get("folder") if isinstance(payload.get("folder"), dict) else payload
        if not isinstance(folder_payload, dict):
            raise NessusResponseError("Nessus did not return folder data for the rename request.")
        return FolderSummary.model_validate(folder_payload)

    def delete_folder(self, folder_id: str) -> None:
        self._request("DELETE", f"/folders/{folder_id}")

    def list_templates(self) -> list[TemplateSummary]:
        payload = self._request("GET", "/editor/scan/templates")
        templates = payload.get("templates") or []
        return [TemplateSummary.model_validate(item) for item in templates if isinstance(item, dict)]

    def list_policies(self) -> list[PolicySummary]:
        payload = self._request("GET", "/policies")
        policies = payload.get("policies") or []
        return [PolicySummary.model_validate(item) for item in policies if isinstance(item, dict)]

    def list_scanners(self) -> list[ScannerSummary]:
        payload = self._request("GET", "/scanners")
        scanners = payload.get("scanners") or []
        return [ScannerSummary.model_validate(item) for item in scanners if isinstance(item, dict)]

    def get_scan_details(self, scan_id: str) -> dict[str, Any]:
        return self._request("GET", f"/scans/{scan_id}")

    def scan_exists(self, scan_id: str) -> bool:
        return bool(self._request("GET", f"/scans/{scan_id}", allow_missing=True))

    def get_scan_history(self, scan_id: str) -> list[ScanHistorySummary]:
        payload = self._request("GET", f"/scans/{scan_id}")
        history = payload.get("history") or payload.get("histories") or []
        return [ScanHistorySummary.model_validate(item) for item in history if isinstance(item, dict)]

    def create_scan(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/scans", json_body=payload)

    def update_scan(self, scan_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("PUT", f"/scans/{scan_id}", json_body=payload)

    def copy_scan(self, scan_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/scans/{scan_id}/copy", json_body=payload)

    def launch_scan(self, scan_id: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._request("POST", f"/scans/{scan_id}/launch", json_body=payload or {})

    def pause_scan(self, scan_id: str) -> dict[str, Any]:
        return self._request("POST", f"/scans/{scan_id}/pause")

    def resume_scan(self, scan_id: str) -> dict[str, Any]:
        return self._request("POST", f"/scans/{scan_id}/resume")

    def stop_scan(self, scan_id: str) -> dict[str, Any]:
        return self._request("POST", f"/scans/{scan_id}/stop")

    def delete_scan(self, scan_id: str) -> None:
        self._request("DELETE", f"/scans/{scan_id}")

    def delete_scan_history(self, scan_id: str, history_id: str) -> None:
        self._request("DELETE", f"/scans/{scan_id}/history/{history_id}")

    def export_scan(self, scan_id: str, *, history_id: str | None = None, export_format: str = "nessus") -> dict[str, Any]:
        params = {"history_id": history_id} if history_id else None
        return self._request("POST", f"/scans/{scan_id}/export", params=params, json_body={"format": export_format})

    def get_scan_export_status(self, scan_id: str, file_id: str) -> dict[str, Any]:
        return self._request("GET", f"/scans/{scan_id}/export/{file_id}/status")

    def download_scan_export(self, scan_id: str, file_id: str) -> bytes:
        backoff = 0.2
        for attempt in range(self._retries + 1):
            try:
                with self._client() as client:
                    response = client.get(f"/scans/{scan_id}/export/{file_id}/download")
            except httpx.TimeoutException as exc:
                if attempt < self._retries:
                    self._sleep_fn(backoff)
                    backoff *= 2
                    continue
                raise NessusConnectivityError("Timed out while downloading the Nessus export.") from exc
            except httpx.HTTPError as exc:
                if attempt < self._retries:
                    self._sleep_fn(backoff)
                    backoff *= 2
                    continue
                raise NessusConnectivityError("Could not download the Nessus export.") from exc

            if response.status_code == 429 and attempt < self._retries:
                self._sleep_fn(backoff)
                backoff *= 2
                continue
            if response.status_code == 401:
                raise NessusAuthenticationError("Nessus API authentication failed.")
            if response.status_code == 403:
                raise NessusAuthenticationError("The Nessus API account does not have permission for this action.")
            if response.status_code >= 400:
                raise NessusResponseError(f"Nessus export download failed with status {response.status_code}.")
            return response.content

        raise NessusResponseError("Nessus export download retry budget exhausted.")

    def validate_connection(self, *, approved_hosts: list[str]) -> ConnectionValidationResult:
        raw_server_info = self._request("GET", "/server/properties")
        server_info = ServerInfo.from_payload(raw_server_info)
        permissions_supported = True
        try:
            permissions = self.get_current_permissions()
        except NessusAuthenticationError:
            raise
        except NessusClientError:
            permissions_supported = False
            permissions = []

        license_features = raw_server_info.get("license", {}).get("features", {}) if isinstance(raw_server_info.get("license"), dict) else {}
        scan_api_enabled = bool(license_features.get("scan_api")) if "scan_api" in license_features else True

        capabilities = {
            "server.properties": True,
            "permissions.current_user": permissions_supported,
            "folders.list": False,
            "scans.list": False,
            "scans.templates": False,
            "policies.list": False,
            "scanners.list": False,
            "scans.export": False,
            "scans.api": scan_api_enabled,
            "scans.create": scan_api_enabled,
            "scans.clone": scan_api_enabled,
            "scans.launch": scan_api_enabled,
            "scans.pause": scan_api_enabled,
            "scans.resume": scan_api_enabled,
            "scans.stop": scan_api_enabled,
            "scans.delete": scan_api_enabled,
            "scans.restore": False,
            "scans.permanent_delete": False,
        }

        try:
            self.list_folders()
            capabilities["folders.list"] = True
        except NessusClientError as exc:
            logger.info("Folder capability probe failed: %s", exc)

        try:
            self.list_scans()
            capabilities["scans.list"] = True
        except NessusClientError as exc:
            logger.info("Scan capability probe failed: %s", exc)

        try:
            self.list_templates()
            capabilities["scans.templates"] = True
        except NessusClientError as exc:
            logger.info("Template capability probe failed: %s", exc)

        try:
            self.list_policies()
            capabilities["policies.list"] = True
        except NessusClientError as exc:
            logger.info("Policy capability probe failed: %s", exc)

        try:
            self.list_scanners()
            capabilities["scanners.list"] = True
        except NessusClientError as exc:
            logger.info("Scanner capability probe failed: %s", exc)

        capabilities["scans.export"] = capabilities["scans.list"]

        return ConnectionValidationResult(
            base_url=self.base_url,
            verify_tls=self.verify_tls,
            timeout_seconds=self.timeout_seconds,
            approved_hosts=approved_hosts,
            server_info=server_info.model_dump(exclude_none=True),
            api_permissions=permissions,
            capabilities=capabilities,
        )

    def list_scan_exports(self) -> dict[str, Any]:
        return self._request("GET", "/scans/exports")
