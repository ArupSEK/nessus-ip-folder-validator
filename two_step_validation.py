from __future__ import annotations

from typing import Any, Optional

import pandas as pd

from ip_utils import extract_ips_from_text
from nessus_fixed import (
    HOST_KEYS,
    TARGET_KEYS,
    NessusAPIError,
    NessusClient as _BaseNessusClient,
    ScanRecord,
    _auth_from_host,
    _csv_fields,
    _history_date,
    _history_id,
    _history_status,
    _history_uuid,
    _hosts,
    _ips_for_keys,
    _match,
    _read_csv,
    _target_note,
)


class NessusClient(_BaseNessusClient):
    """Nessus client that records logical API requests for the dashboard."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.request_count = 0

    def request(self, method: str, path: str, **kwargs: Any):
        self.request_count += 1
        return super().request(method, path, **kwargs)


def _scan_hints(scan: ScanRecord) -> set[str]:
    return (
        set(scan.configured_ips)
        | set(scan.name_ips)
        | extract_ips_from_text(scan.folder_name)
    )


def candidate_scan_records(
    input_ips: set[str],
    scan_records: list[ScanRecord],
) -> list[ScanRecord]:
    """Return scans whose lightweight list metadata references an input IP."""
    return [scan for scan in scan_records if _scan_hints(scan) & input_ips]


def _history_from_detail(
    scan: ScanRecord,
    detail: dict[str, Any],
    history_id: str = "",
    history_uuid: str = "",
) -> dict[str, Any]:
    info = detail.get("info", {}) if isinstance(detail, dict) else {}
    if not isinstance(info, dict):
        info = {}
    return {
        "id": history_id
        or str(detail.get("history_id") or info.get("history_id") or ""),
        "scan_uuid": history_uuid
        or str(
            detail.get("history_uuid")
            or detail.get("scan_uuid")
            or info.get("history_uuid")
            or info.get("scan_uuid")
            or info.get("uuid")
            or ""
        ),
        "status": str(
            info.get("status")
            or detail.get("status")
            or scan.status
            or ""
        ),
        "start_date": (
            info.get("scan_end")
            or info.get("scan_start")
            or info.get("timestamp")
            or scan.modified
            or scan.created
        ),
    }


def _location_match(
    ip: str,
    scan: ScanRecord,
    history: dict[str, Any],
    scan_date: str,
    scan_status: str,
    source: str,
    presence: str,
    note: str = "",
    host_id: str = "",
) -> dict[str, Any]:
    row = _match(
        ip,
        scan,
        history,
        scan_date,
        scan_status,
        source,
        presence,
        note,
        host_id,
    )
    row["api_id"] = scan.api_id
    return row


def build_location_index(
    client: NessusClient,
    input_ips: set[str],
    scan_records: list[ScanRecord],
    fallback_all_scans: bool = False,
    progress_callback=None,
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    """Locate newest folder/scan matches with one detail call per candidate."""
    matches: list[dict[str, Any]] = []
    unresolved = set(input_ips)
    candidates = candidate_scan_records(input_ips, scan_records)
    candidate_ids = {scan.scan_id for scan in candidates}
    fallback = [scan for scan in scan_records if scan.scan_id not in candidate_ids]
    worklist = candidates + (fallback if fallback_all_scans else [])
    stats: dict[str, Any] = {
        "scans_available": len(scan_records),
        "candidate_scans": len(candidates),
        "scans_opened": 0,
        "fallback_enabled": fallback_all_scans,
        "fallback_scans_opened": 0,
        "located_ips": 0,
        "unresolved_ips": len(unresolved),
    }

    total = max(len(worklist), 1)
    for position, scan in enumerate(worklist, 1):
        if not unresolved:
            break
        is_fallback = scan.scan_id not in candidate_ids
        if not is_fallback and not (_scan_hints(scan) & unresolved):
            continue
        if progress_callback:
            phase = "Fallback discovery" if is_fallback else "Candidate discovery"
            progress_callback(position, total, f"{phase}: {scan.name}")

        detail_error = ""
        try:
            detail = client.scan_details(scan.api_id)
        except Exception as exc:
            detail = {}
            detail_error = f"Latest scan details API error: {exc}"
        stats["scans_opened"] += 1
        if is_fallback:
            stats["fallback_scans_opened"] += 1

        history = _history_from_detail(scan, detail)
        scan_date = _history_date(history, detail) or scan.modified or scan.created
        scan_status = _history_status(history, scan.status)
        targets = set(scan.configured_ips) | _ips_for_keys(detail, TARGET_KEYS)
        host_rows = _hosts(detail)
        result_ips: set[str] = set()

        for host in host_rows:
            found = _ips_for_keys(host, HOST_KEYS) & unresolved
            if not found:
                continue
            result_ips |= found
            host_id = str(host.get("host_id", host.get("id", "")))
            for ip in sorted(found):
                matches.append(
                    _location_match(
                        ip,
                        scan,
                        history,
                        scan_date,
                        scan_status,
                        "Low API Discovery",
                        "Scan result",
                        host_id=host_id,
                    )
                )

        configured_only = (targets & unresolved) - result_ips
        for ip in sorted(configured_only):
            matches.append(
                _location_match(
                    ip,
                    scan,
                    history,
                    scan_date,
                    scan_status,
                    "Configured Scan Target",
                    "Configured target",
                    _target_note(False, len(host_rows), detail_error),
                )
            )

        name_only = (
            set(scan.name_ips) & unresolved - result_ips - configured_only
        )
        for ip in sorted(name_only):
            suffix = f" {detail_error}" if detail_error else ""
            matches.append(
                _location_match(
                    ip,
                    scan,
                    history,
                    scan_date,
                    scan_status,
                    "Scan Name Candidate",
                    "Scan name only",
                    (
                        "IP was found in the scan name, but the latest scan "
                        "summary did not return a matching target or host. "
                        "Use Deep Validation for this selected result."
                        f"{suffix}"
                    ).strip(),
                )
            )
        unresolved -= result_ips | configured_only | name_only

    stats["located_ips"] = len(input_ips) - len(unresolved)
    stats["unresolved_ips"] = len(unresolved)
    return pd.DataFrame(matches), pd.DataFrame(), stats


def _preserve_rows(
    group: pd.DataFrame,
    unresolved: set[str],
    note: str,
    source: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for ip in sorted(unresolved):
        source_rows = group[group["normalized_ip"].astype(str) == ip]
        if source_rows.empty:
            continue
        row = source_rows.iloc[0].to_dict()
        row["result_note"] = note
        row["evidence_source"] = source
        rows.append(row)
    return rows


def _deep_host_group(
    client: NessusClient,
    scan: ScanRecord,
    group: pd.DataFrame,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    selected_ips = set(group["normalized_ip"].astype(str))
    first = group.iloc[0]
    history_id = str(first.get("history_id", "") or "")
    history_uuid = str(first.get("history_uuid", "") or "")
    detail = client.scan_details(
        scan.api_id,
        history_id=history_id or None,
        history_uuid=history_uuid or None,
    )
    history = _history_from_detail(scan, detail, history_id, history_uuid)
    scan_date = _history_date(history, detail) or str(first.get("scan_date", ""))
    scan_status = _history_status(history, scan.status)
    host_rows = _hosts(detail)
    matches: list[dict[str, Any]] = []
    auth_rows: list[dict[str, Any]] = []
    found_ips: set[str] = set()
    processed: set[str] = set()

    def inspect(host: dict[str, Any], resolve_unmatched: bool) -> None:
        host_id = str(host.get("host_id", host.get("id", "")))
        summary_ips = _ips_for_keys(host, HOST_KEYS)
        if not (summary_ips & selected_ips) and not resolve_unmatched:
            return
        host_detail: Optional[dict[str, Any]] = None
        if host_id:
            processed.add(host_id)
            try:
                host_detail = client.host_details(
                    scan.api_id,
                    host_id,
                    history_id=history_id or None,
                    history_uuid=history_uuid or None,
                )
            except Exception:
                host_detail = None
        all_ips = set(summary_ips)
        if host_detail:
            all_ips |= _ips_for_keys(host_detail, HOST_KEYS)
        matched = (all_ips & selected_ips) - found_ips
        if not matched:
            return
        found_ips.update(matched)
        for ip in sorted(matched):
            matches.append(
                _location_match(
                    ip,
                    scan,
                    history,
                    scan_date,
                    scan_status,
                    "Deep Host Validation",
                    "Scan result",
                    host_id=host_id,
                )
            )
        auth_rows.extend(_auth_from_host(host_detail, matched, scan, history))

    for host in host_rows:
        inspect(host, False)
    for host in host_rows:
        if found_ips == selected_ips:
            break
        host_id = str(host.get("host_id", host.get("id", "")))
        if host_id and host_id in processed:
            continue
        inspect(host, True)

    matches.extend(
        _preserve_rows(
            group,
            selected_ips - found_ips,
            (
                "Deep host validation completed, but Nessus did not return a "
                "matching host result for this IP in the selected scan run."
            ),
            "Deep Host Validation",
        )
    )
    return matches, auth_rows


def _deep_csv_group(
    client: NessusClient,
    scan: ScanRecord,
    group: pd.DataFrame,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    selected_ips = set(group["normalized_ip"].astype(str))
    first = group.iloc[0]
    history_id = str(first.get("history_id", "") or "")
    history_uuid = str(first.get("history_uuid", "") or "")
    frame = _read_csv(client.export_scan_csv(scan.api_id, history_id or None))
    fields = _csv_fields(frame) if not frame.empty else {"hosts": []}
    history = {
        "id": history_id,
        "scan_uuid": history_uuid,
        "status": str(first.get("scan_status", "") or scan.status),
        "start_date": str(first.get("scan_date", "")),
    }
    matches: list[dict[str, Any]] = []
    auth_rows: list[dict[str, Any]] = []
    found_ips: set[str] = set()

    for _, row in frame.iterrows():
        row_ips: set[str] = set()
        for column in fields.get("hosts", []):
            row_ips |= extract_ips_from_text(row.get(column, ""))
        matched = row_ips & selected_ips
        if not matched:
            continue
        found_ips.update(matched)
        for ip in sorted(matched):
            matches.append(
                _location_match(
                    ip,
                    scan,
                    history,
                    str(first.get("scan_date", "")),
                    str(first.get("scan_status", "") or scan.status),
                    "Deep CSV Validation",
                    "Scan result",
                )
            )
        plugin_column = fields.get("plugin")
        if not isinstance(plugin_column, str):
            continue
        plugin_id = str(row.get(plugin_column, "")).strip()
        name_column = fields.get("name")
        plugin_name = (
            str(row.get(name_column, ""))
            if isinstance(name_column, str)
            else ""
        )
        from auth_classifier import is_auth_related

        if not is_auth_related(plugin_id, plugin_name):
            continue
        output_column = fields.get("output")
        risk_column = fields.get("risk")
        for ip in matched:
            auth_rows.append(
                {
                    "normalized_ip": ip,
                    "scan_id": scan.scan_id,
                    "history_id": history_id,
                    "history_uuid": history_uuid,
                    "plugin_id": plugin_id,
                    "plugin_name": plugin_name,
                    "plugin_output": (
                        str(row.get(output_column, ""))
                        if isinstance(output_column, str)
                        else ""
                    ),
                    "risk": (
                        str(row.get(risk_column, ""))
                        if isinstance(risk_column, str)
                        else ""
                    ),
                }
            )

    matches.extend(
        _preserve_rows(
            group,
            selected_ips - found_ips,
            (
                "Deep CSV validation completed, but the selected IP was not "
                "present in the exported scan result."
            ),
            "Deep CSV Validation",
        )
    )
    return matches, auth_rows


def deep_validate_selected(
    client: NessusClient,
    selected_matches: pd.DataFrame,
    scan_records: list[ScanRecord],
    method: str = "host_details",
    progress_callback=None,
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    """Deep-validate selected rows, grouped by exact scan and history."""
    if selected_matches.empty:
        return pd.DataFrame(), pd.DataFrame(), {
            "selected_ips": 0,
            "scan_groups": 0,
        }
    required = {"normalized_ip", "scan_id"}
    missing = required - set(selected_matches.columns)
    if missing:
        raise ValueError(
            "Selected result data is missing: " + ", ".join(sorted(missing))
        )

    rows = selected_matches.copy()
    for column in ("history_id", "history_uuid"):
        if column not in rows.columns:
            rows[column] = ""
        rows[column] = rows[column].fillna("").astype(str)
    rows["scan_id"] = rows["scan_id"].fillna("").astype(str)
    rows["normalized_ip"] = rows["normalized_ip"].fillna("").astype(str)

    lookup = {scan.scan_id: scan for scan in scan_records}
    grouped = list(
        rows.groupby(
            ["scan_id", "history_id", "history_uuid"],
            dropna=False,
            sort=False,
        )
    )
    matches: list[dict[str, Any]] = []
    auth_rows: list[dict[str, Any]] = []
    total = max(len(grouped), 1)

    for position, ((scan_id, _, _), group) in enumerate(grouped, 1):
        scan = lookup.get(str(scan_id))
        if scan is None:
            first = group.iloc[0]
            scan = ScanRecord(
                scan_id=str(scan_id),
                schedule_uuid=str(first.get("api_id", scan_id) or scan_id),
                name=str(first.get("scan_name", f"Scan {scan_id}")),
                folder_id="",
                folder_name=str(first.get("folder_name", "Unknown Folder")),
                status=str(first.get("scan_status", "")),
            )
        if progress_callback:
            progress_callback(position, total, f"Deep validating: {scan.name}")
        try:
            if method == "csv_export":
                group_matches, group_auth = _deep_csv_group(client, scan, group)
            else:
                group_matches, group_auth = _deep_host_group(client, scan, group)
        except Exception as exc:
            group_matches = _preserve_rows(
                group,
                set(group["normalized_ip"].astype(str)),
                f"Deep validation error: {exc}",
                "Deep Validation Error",
            )
            group_auth = []
        matches.extend(group_matches)
        auth_rows.extend(group_auth)

    return (
        pd.DataFrame(matches),
        pd.DataFrame(auth_rows),
        {
            "selected_ips": int(rows["normalized_ip"].nunique()),
            "scan_groups": len(grouped),
            "method": method,
        },
    )
