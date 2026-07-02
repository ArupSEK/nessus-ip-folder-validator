from __future__ import annotations

import csv
import io
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

import pandas as pd
import requests

from auth_classifier import AuthFinding, classify_auth, is_auth_related
from ip_utils import extract_ips_from_text, normalize_ip


class NessusAPIError(RuntimeError):
    pass


@dataclass
class ScanRecord:
    scan_id: str
    schedule_uuid: str
    name: str
    folder_id: str
    folder_name: str
    status: str = ""
    created: str = ""
    modified: str = ""


class NessusClient:
    """Minimal Tenable/Nessus API client using X-ApiKeys.

    Works with Tenable Vulnerability Management documented endpoints and many
    standalone Nessus / Nessus Manager deployments that expose compatible paths.
    """

    def __init__(
        self,
        base_url: str,
        access_key: str,
        secret_key: str,
        verify_ssl: bool = True,
        timeout: int = 90,
        max_retries: int = 5,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers.update({
            "X-ApiKeys": f"accessKey={access_key.strip()}; secretKey={secret_key.strip()};",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "nessus-ip-validator/1.0",
        })

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = f"{self.base_url}{path}"
        for attempt in range(self.max_retries + 1):
            resp = self.session.request(method, url, timeout=self.timeout, verify=self.verify_ssl, **kwargs)
            if resp.status_code == 429 and attempt < self.max_retries:
                retry_after = resp.headers.get("retry-after") or resp.headers.get("Retry-After")
                try:
                    sleep_for = int(retry_after) if retry_after else min(60, 2 ** attempt)
                except Exception:
                    sleep_for = min(60, 2 ** attempt)
                time.sleep(sleep_for)
                continue
            if resp.status_code >= 400:
                body = resp.text[:1000]
                raise NessusAPIError(f"{method} {path} failed: HTTP {resp.status_code}: {body}")
            return resp
        raise NessusAPIError(f"{method} {path} failed after retries")

    def get_json(self, path: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        resp = self.request("GET", path, params=params)
        try:
            return resp.json()
        except Exception as exc:
            raise NessusAPIError(f"Expected JSON from {path}: {exc}") from exc

    def post_json(self, path: str, payload: dict[str, Any], params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        resp = self.request("POST", path, json=payload, params=params)
        try:
            return resp.json()
        except Exception as exc:
            raise NessusAPIError(f"Expected JSON from {path}: {exc}") from exc

    def test_connection(self) -> tuple[int, int]:
        folders = self.list_folders()
        scans = self.list_scans()
        return len(folders), len(scans)

    def list_folders(self) -> dict[str, str]:
        data = self.get_json("/folders")
        raw_folders = data.get("folders") if isinstance(data, dict) else []
        folder_map: dict[str, str] = {}
        for f in raw_folders or []:
            fid = str(f.get("id", f.get("folder_id", "")))
            name = str(f.get("name", f.get("folder_name", f"Folder {fid}")))
            if fid:
                folder_map[fid] = name
        # Some standalone outputs may return a plain list.
        if not folder_map and isinstance(data, list):
            for f in data:
                fid = str(f.get("id", f.get("folder_id", "")))
                if fid:
                    folder_map[fid] = str(f.get("name", f"Folder {fid}"))
        return folder_map

    def list_scans(
        self,
        folder_id: Optional[str] = None,
        started_from: Optional[int] = None,
        started_to: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {}
        if folder_id:
            params["folder_id"] = folder_id
        if started_from:
            params["started_from"] = started_from
        if started_to:
            params["started_to"] = started_to
        data = self.get_json("/scans", params=params or None)
        if isinstance(data, dict):
            scans = data.get("scans") or []
        elif isinstance(data, list):
            scans = data
        else:
            scans = []
        return scans

    def scan_history(self, scan_id: str, limit: int = 200) -> list[dict[str, Any]]:
        histories: list[dict[str, Any]] = []
        offset = 0
        while True:
            data = self.get_json(f"/scans/{scan_id}/history", params={"limit": limit, "offset": offset})
            chunk = data.get("history", data.get("histories", data.get("items", []))) if isinstance(data, dict) else []
            if not chunk:
                break
            histories.extend(chunk)
            if len(chunk) < limit:
                break
            offset += limit
        return histories

    def scan_details(self, scan_id: str, history_id: Optional[str] = None, history_uuid: Optional[str] = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if history_id:
            params["history_id"] = history_id
        if history_uuid:
            params["history_uuid"] = history_uuid
        return self.get_json(f"/scans/{scan_id}", params=params or None)

    def host_details(self, scan_uuid_or_id: str, host_id: str, history_id: Optional[str] = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if history_id:
            params["history_id"] = history_id
        return self.get_json(f"/scans/{scan_uuid_or_id}/hosts/{host_id}", params=params or None)

    def latest_status(self, scan_id: str) -> str:
        try:
            data = self.get_json(f"/scans/{scan_id}/latest-status")
            return str(data.get("status", data.get("latest_status", "")))
        except Exception:
            return ""

    def export_scan_csv(self, scan_id: str, history_id: Optional[str] = None, poll_seconds: int = 3, timeout_seconds: int = 900) -> bytes:
        params: dict[str, Any] = {}
        if history_id:
            params["history_id"] = history_id
        queued = self.post_json(f"/scans/{scan_id}/export", {"format": "csv"}, params=params or None)
        file_id = str(queued.get("file", queued.get("file_id", queued.get("id", ""))))
        if not file_id:
            raise NessusAPIError(f"Export response did not contain file id: {queued}")
        started = time.time()
        while True:
            status = self.get_json(f"/scans/{scan_id}/export/{file_id}/status")
            current = str(status.get("status", status.get("state", ""))).lower()
            if current == "ready":
                break
            if current in {"error", "failed", "canceled"}:
                raise NessusAPIError(f"Export failed for scan {scan_id}, file {file_id}: {status}")
            if time.time() - started > timeout_seconds:
                raise NessusAPIError(f"Export timeout for scan {scan_id}, file {file_id}")
            time.sleep(poll_seconds)
        resp = self.request("GET", f"/scans/{scan_id}/export/{file_id}/download", headers={"Accept": "application/octet-stream"})
        return resp.content


def unix_from_date(date_value: Optional[datetime]) -> Optional[int]:
    if not date_value:
        return None
    if date_value.tzinfo is None:
        date_value = date_value.replace(tzinfo=timezone.utc)
    return int(date_value.timestamp())


def _epoch_to_str(value: object) -> str:
    if value in (None, "", 0, "0"):
        return ""
    try:
        ivalue = int(float(value))
        return datetime.fromtimestamp(ivalue, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(value)


def make_scan_records(scans: list[dict[str, Any]], folder_map: dict[str, str]) -> list[ScanRecord]:
    records: list[ScanRecord] = []
    for scan in scans:
        scan_id = str(scan.get("id", scan.get("scan_id", "")))
        if not scan_id:
            continue
        folder_id = str(scan.get("folder_id", scan.get("folder", "")))
        records.append(ScanRecord(
            scan_id=scan_id,
            schedule_uuid=str(scan.get("schedule_uuid", scan.get("uuid", scan_id))),
            name=str(scan.get("name", scan.get("scan_name", f"Scan {scan_id}"))),
            folder_id=folder_id,
            folder_name=folder_map.get(folder_id, f"Folder {folder_id}" if folder_id else "Unknown Folder"),
            status=str(scan.get("status", scan.get("readable_status", ""))),
            created=_epoch_to_str(scan.get("creation_date", scan.get("created_at", ""))),
            modified=_epoch_to_str(scan.get("last_modification_date", scan.get("updated_at", ""))),
        ))
    return records


def _extract_scan_hosts(detail: dict[str, Any]) -> list[dict[str, Any]]:
    hosts = detail.get("hosts") or detail.get("hostgroups") or []
    if isinstance(hosts, dict):
        hosts = hosts.get("hosts", [])
    return hosts if isinstance(hosts, list) else []


def _history_date(history: dict[str, Any], detail: Optional[dict[str, Any]] = None) -> str:
    for key in ("start_date", "creation_date", "last_modification_date", "scan_start", "timestamp"):
        if key in history:
            return _epoch_to_str(history.get(key))
    if detail and isinstance(detail.get("info"), dict):
        info = detail.get("info")
        for key in ("scan_start", "scan_end", "timestamp", "starttime"):
            if info.get(key):
                return _epoch_to_str(info.get(key))
    return ""


def _history_status(history: dict[str, Any], scan_default_status: str = "") -> str:
    for key in ("status", "readable_status"):
        if history.get(key):
            return str(history.get(key))
    return scan_default_status


def _host_ip_from_host_object(host: dict[str, Any]) -> Optional[str]:
    for key in ("hostname", "host_name", "host-ip", "host_ip", "ip", "ipv4", "dns_name", "fqdn"):
        if key in host:
            ip = normalize_ip(host.get(key))
            if ip:
                return ip
    return None


def build_index_fast_api(
    client: NessusClient,
    input_ips: set[str],
    scan_records: list[ScanRecord],
    include_history: bool = True,
    fetch_host_details: bool = False,
    progress_callback=None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Build result rows using /scans and optional /hosts APIs."""
    matches: list[dict[str, Any]] = []
    auth_rows: list[dict[str, Any]] = []
    total = max(len(scan_records), 1)
    for idx, scan in enumerate(scan_records, start=1):
        if progress_callback:
            progress_callback(idx, total, f"Reading scan details: {scan.name}")
        histories = []
        if include_history:
            try:
                histories = client.scan_history(scan.schedule_uuid or scan.scan_id)
            except Exception:
                histories = []
        if not histories:
            histories = [{"id": None, "status": scan.status, "start_date": scan.modified}]
        for hist in histories:
            history_id = hist.get("id") or hist.get("history_id")
            history_uuid = hist.get("uuid") or hist.get("scan_uuid")
            try:
                detail = client.scan_details(scan.schedule_uuid or scan.scan_id, str(history_id) if history_id else None, str(history_uuid) if history_uuid else None)
            except Exception as exc:
                matches.append({
                    "normalized_ip": "",
                    "folder_name": scan.folder_name,
                    "scan_name": scan.name,
                    "scan_id": scan.scan_id,
                    "history_id": str(history_id or ""),
                    "scan_date": _history_date(hist),
                    "scan_status": _history_status(hist, scan.status),
                    "evidence_source": f"API error: {exc}",
                })
                continue
            scan_date = _history_date(hist, detail)
            scan_status = _history_status(hist, scan.status)
            for host in _extract_scan_hosts(detail):
                ip = _host_ip_from_host_object(host)
                host_id = str(host.get("host_id", host.get("id", "")))
                host_detail = None
                if fetch_host_details and host_id:
                    try:
                        host_detail = client.host_details(scan.schedule_uuid or scan.scan_id, host_id, str(history_id) if history_id else None)
                        # Try to improve IP from info/host properties.
                        for container in (host_detail.get("info", {}), host_detail.get("host", {}), host_detail):
                            if isinstance(container, dict):
                                for key, value in container.items():
                                    if key.lower() in {"host-ip", "host_ip", "ip", "ipv4", "hostname", "host-fqdn"}:
                                        maybe = normalize_ip(value)
                                        if maybe:
                                            ip = maybe
                                            break
                    except Exception:
                        host_detail = None
                if not ip or ip not in input_ips:
                    continue
                matches.append({
                    "normalized_ip": ip,
                    "folder_name": scan.folder_name,
                    "scan_name": scan.name,
                    "scan_id": scan.scan_id,
                    "history_id": str(history_id or ""),
                    "scan_date": scan_date,
                    "scan_status": scan_status,
                    "evidence_source": "Fast API",
                })
                # Pull auth-related plugin names if host detail was fetched.
                if host_detail:
                    for vuln in host_detail.get("vulnerabilities", []) or []:
                        plugin_id = str(vuln.get("plugin_id", vuln.get("id", "")))
                        plugin_name = str(vuln.get("plugin_name", vuln.get("name", "")))
                        if is_auth_related(plugin_id, plugin_name):
                            auth_rows.append({
                                "normalized_ip": ip,
                                "scan_id": scan.scan_id,
                                "history_id": str(history_id or ""),
                                "plugin_id": plugin_id,
                                "plugin_name": plugin_name,
                                "plugin_output": str(vuln.get("plugin_output", vuln.get("output", ""))),
                                "risk": str(vuln.get("risk", vuln.get("severity", ""))),
                            })
    return pd.DataFrame(matches), pd.DataFrame(auth_rows)


def _read_export_csv(csv_bytes: bytes) -> pd.DataFrame:
    if not csv_bytes:
        return pd.DataFrame()
    # Nessus CSV is usually UTF-8 with quoted fields and embedded newlines.
    for encoding in ("utf-8-sig", "utf-8", "latin1"):
        try:
            return pd.read_csv(io.BytesIO(csv_bytes), encoding=encoding, dtype=str, keep_default_na=False)
        except Exception:
            continue
    # Last fallback through Python CSV module.
    text = csv_bytes.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    return pd.DataFrame(list(reader))


def build_index_csv_export(
    client: NessusClient,
    input_ips: set[str],
    scan_records: list[ScanRecord],
    include_history: bool = True,
    progress_callback=None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    matches: list[dict[str, Any]] = []
    auth_rows: list[dict[str, Any]] = []
    total = max(len(scan_records), 1)
    for idx, scan in enumerate(scan_records, start=1):
        if progress_callback:
            progress_callback(idx, total, f"Exporting scan CSV: {scan.name}")
        histories = []
        if include_history:
            try:
                histories = client.scan_history(scan.schedule_uuid or scan.scan_id)
            except Exception:
                histories = []
        if not histories:
            histories = [{"id": None, "status": scan.status, "start_date": scan.modified}]
        for hist in histories:
            history_id = hist.get("id") or hist.get("history_id")
            try:
                data = client.export_scan_csv(scan.schedule_uuid or scan.scan_id, str(history_id) if history_id else None)
                df = _read_export_csv(data)
            except Exception as exc:
                matches.append({
                    "normalized_ip": "",
                    "folder_name": scan.folder_name,
                    "scan_name": scan.name,
                    "scan_id": scan.scan_id,
                    "history_id": str(history_id or ""),
                    "scan_date": _history_date(hist),
                    "scan_status": _history_status(hist, scan.status),
                    "evidence_source": f"CSV export error: {exc}",
                })
                continue
            if df.empty:
                continue
            # Identify common Nessus CSV columns.
            lower_cols = {c.lower().strip(): c for c in df.columns}
            host_col = lower_cols.get("host") or lower_cols.get("hostname") or lower_cols.get("ip address") or lower_cols.get("asset ip address")
            plugin_col = lower_cols.get("plugin id") or lower_cols.get("plugin_id") or lower_cols.get("id")
            name_col = lower_cols.get("name") or lower_cols.get("plugin name") or lower_cols.get("plugin_name")
            output_col = lower_cols.get("plugin output") or lower_cols.get("plugin_output") or lower_cols.get("output")
            risk_col = lower_cols.get("risk") or lower_cols.get("risk factor") or lower_cols.get("severity")
            if not host_col:
                continue
            df["__normalized_ip"] = df[host_col].map(normalize_ip)
            matched_df = df[df["__normalized_ip"].isin(input_ips)]
            if matched_df.empty:
                continue
            scan_date = _history_date(hist)
            scan_status = _history_status(hist, scan.status)
            for ip in sorted(set(matched_df["__normalized_ip"].dropna().astype(str))):
                matches.append({
                    "normalized_ip": ip,
                    "folder_name": scan.folder_name,
                    "scan_name": scan.name,
                    "scan_id": scan.scan_id,
                    "history_id": str(history_id or ""),
                    "scan_date": scan_date,
                    "scan_status": scan_status,
                    "evidence_source": "CSV Export",
                })
            if plugin_col:
                for _, row in matched_df.iterrows():
                    pid = str(row.get(plugin_col, "")).strip()
                    pname = str(row.get(name_col, "")) if name_col else ""
                    if not is_auth_related(pid, pname):
                        continue
                    auth_rows.append({
                        "normalized_ip": str(row["__normalized_ip"]),
                        "scan_id": scan.scan_id,
                        "history_id": str(history_id or ""),
                        "plugin_id": pid,
                        "plugin_name": pname,
                        "plugin_output": str(row.get(output_col, "")) if output_col else "",
                        "risk": str(row.get(risk_col, "")) if risk_col else "",
                    })
    return pd.DataFrame(matches), pd.DataFrame(auth_rows)


def summarize_results(input_ip_rows: pd.DataFrame, matches: pd.DataFrame, auth_rows: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Create summary table and detail table for GUI/export."""
    if matches.empty:
        detail = pd.DataFrame(columns=["normalized_ip", "folder_name", "scan_name", "scan_id", "history_id", "scan_date", "scan_status", "evidence_source"])
    else:
        detail = matches.copy()
        detail = detail[detail["normalized_ip"].astype(str).str.len() > 0].drop_duplicates()

    summary_rows: list[dict[str, Any]] = []
    for _, ip_row in input_ip_rows.iterrows():
        input_ip = str(ip_row.get("Input IP", ""))
        normalized_ip = str(ip_row.get("Normalized IP", ""))
        ip_matches = detail[detail["normalized_ip"] == normalized_ip] if not detail.empty else pd.DataFrame()
        ip_auth = auth_rows[auth_rows["normalized_ip"] == normalized_ip] if not auth_rows.empty else pd.DataFrame()
        if not ip_auth.empty:
            findings = [
                AuthFinding(
                    plugin_id=str(r.get("plugin_id", "")),
                    plugin_name=str(r.get("plugin_name", "")),
                    plugin_output=str(r.get("plugin_output", "")),
                    risk=str(r.get("risk", "")),
                )
                for _, r in ip_auth.iterrows()
            ]
            auth = classify_auth(findings)
        else:
            auth = classify_auth([])

        if ip_matches.empty:
            summary_rows.append({
                "Input IP": input_ip,
                "Normalized IP": normalized_ip,
                "Present in Nessus": "No",
                "Primary Folder Name": "",
                "All Folder Names": "",
                "Latest Scan Name": "",
                "All Scan Names": "",
                "Latest Scan Date": "",
                "Latest Scan Status": "",
                "Authentication Status": "Not validated",
                "Authentication Failure Reason": "IP was not found in selected Nessus scans/folders",
                "Auth Evidence Plugin": "",
                "Protocol Summary": "",
                "Confidence": "Low",
                "Match Count": 0,
                "Evidence Source": "",
            })
            continue

        sortable = ip_matches.copy()
        sortable["__dt"] = pd.to_datetime(sortable["scan_date"], errors="coerce", utc=True)
        sortable = sortable.sort_values("__dt", ascending=False, na_position="last")
        latest = sortable.iloc[0]
        folders = sorted(set(ip_matches["folder_name"].dropna().astype(str)))
        scans = sorted(set(ip_matches["scan_name"].dropna().astype(str)))
        evidence_sources = sorted(set(ip_matches["evidence_source"].dropna().astype(str)))
        summary_rows.append({
            "Input IP": input_ip,
            "Normalized IP": normalized_ip,
            "Present in Nessus": "Yes",
            "Primary Folder Name": str(latest.get("folder_name", "")),
            "All Folder Names": " | ".join(folders),
            "Latest Scan Name": str(latest.get("scan_name", "")),
            "All Scan Names": " | ".join(scans),
            "Latest Scan Date": str(latest.get("scan_date", "")),
            "Latest Scan Status": str(latest.get("scan_status", "")),
            "Authentication Status": auth["auth_status"],
            "Authentication Failure Reason": auth["auth_reason"],
            "Auth Evidence Plugin": auth["auth_plugin"],
            "Protocol Summary": auth["protocol_summary"],
            "Confidence": auth["confidence"],
            "Match Count": int(len(ip_matches)),
            "Evidence Source": " | ".join(evidence_sources),
        })
    return pd.DataFrame(summary_rows), detail
