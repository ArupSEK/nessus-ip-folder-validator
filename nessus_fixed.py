from __future__ import annotations
import csv
import io
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
import pandas as pd
from auth_classifier import AuthFinding, classify_auth, is_auth_related
from ip_utils import extract_ips_from_text, normalize_ip
from nessus_client import NessusAPIError, NessusClient as _LegacyNessusClient

class NessusClient(_LegacyNessusClient):
    """Compatibility client with corrected historical scan lookups."""

    def scan_details(self, scan_id: str, history_id: Optional[str]=None, history_uuid: Optional[str]=None) -> dict[str, Any]:
        if history_id:
            data = self.get_json(f'/scans/{scan_id}', params={'history_id': history_id})
        elif history_uuid:
            try:
                data = self.get_json(f'/scans/{scan_id}/history/{history_uuid}')
            except NessusAPIError:
                data = self.get_json(f'/scans/{scan_id}', params={'history_uuid': history_uuid})
        else:
            data = self.get_json(f'/scans/{scan_id}')
        return data if isinstance(data, dict) else {}

    def host_details(self, scan_id: str, host_id: str, history_id: Optional[str]=None, history_uuid: Optional[str]=None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if history_id:
            params['history_id'] = history_id
        elif history_uuid:
            params['history_uuid'] = history_uuid
        data = self.get_json(f'/scans/{scan_id}/hosts/{host_id}', params=params or None)
        return data if isinstance(data, dict) else {}

@dataclass
class ScanRecord:
    scan_id: str
    schedule_uuid: str
    name: str
    folder_id: str
    folder_name: str
    status: str = ''
    created: str = ''
    modified: str = ''
    configured_ips: tuple[str, ...] = ()
    name_ips: tuple[str, ...] = ()

    @property
    def api_id(self) -> str:
        return self.schedule_uuid or self.scan_id

def unix_from_date(value: Optional[datetime]) -> Optional[int]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return int(value.timestamp())

def _date_string(value: object) -> str:
    if value in (None, '', 0, '0'):
        return ''
    try:
        return datetime.fromtimestamp(int(float(value)), timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return str(value)

def _timestamp(value: object) -> pd.Timestamp:
    if value in (None, '', 0, '0'):
        return pd.NaT
    try:
        return pd.to_datetime(int(float(value)), unit='s', utc=True)
    except Exception:
        return pd.to_datetime(value, errors='coerce', utc=True)

def make_scan_records(scans: list[dict[str, Any]], folder_map: dict[str, str]) -> list[ScanRecord]:
    records: list[ScanRecord] = []
    for scan in scans:
        scan_id = str(scan.get('id', scan.get('scan_id', '')))
        if not scan_id:
            continue
        folder_id = str(scan.get('folder_id', scan.get('folder', '')))
        name = str(scan.get('name', scan.get('scan_name', f'Scan {scan_id}')))
        configured: set[str] = set()
        for key in ('targets', 'target', 'text_targets', 'alt_targets'):
            configured.update(extract_ips_from_text(scan.get(key)))
        records.append(ScanRecord(scan_id=scan_id, schedule_uuid=str(scan.get('schedule_uuid', scan.get('uuid', scan_id))), name=name, folder_id=folder_id, folder_name=folder_map.get(folder_id, f'Folder {folder_id}' if folder_id else 'Unknown Folder'), status=str(scan.get('status', scan.get('readable_status', ''))), created=_date_string(scan.get('creation_date', scan.get('created_at', ''))), modified=_date_string(scan.get('last_modification_date', scan.get('updated_at', ''))), configured_ips=tuple(sorted(configured)), name_ips=tuple(sorted(extract_ips_from_text(name)))))

    def order(record: ScanRecord) -> pd.Timestamp:
        parsed = _timestamp(record.modified or record.created)
        return parsed if not pd.isna(parsed) else pd.Timestamp.min.tz_localize('UTC')
    return sorted(records, key=order, reverse=True)

def _key(value: object) -> str:
    return str(value).strip().lower().replace('-', '_').replace(' ', '_')
HOST_KEYS = {'hostname', 'host_name', 'host_ip', 'ip', 'ipv4', 'ipv6', 'fqdn', 'host_fqdn', 'dns_name', 'asset_ip', 'asset_ip_address', 'ip_address', 'address'}
TARGET_KEYS = {'target', 'targets', 'text_targets', 'alt_targets', 'target_list', 'scan_targets', 'host_targets', 'asset_targets'}

def _ips_for_keys(value: object, accepted: set[str], depth: int=0) -> set[str]:
    if depth > 6:
        return set()
    found: set[str] = set()
    if isinstance(value, dict):
        descriptor = next((value.get(name) for name in ('name', 'key', 'attribute_name', 'property', 'label') if value.get(name) not in (None, '')), None)
        if descriptor is not None and _key(descriptor) in accepted:
            for name in ('value', 'attribute_value', 'property_value', 'content'):
                found.update(extract_ips_from_text(value.get(name)))
        for name, child in value.items():
            normalized = _key(name)
            if normalized in accepted and (not isinstance(child, (dict, list, tuple, set))):
                found.update(extract_ips_from_text(child))
            if isinstance(child, (dict, list, tuple, set)):
                found.update(_ips_for_keys(child, accepted, depth + 1))
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            if isinstance(child, (dict, list, tuple, set)):
                found.update(_ips_for_keys(child, accepted, depth + 1))
            else:
                found.update(extract_ips_from_text(child))
    return found

def _hosts(detail: dict[str, Any]) -> list[dict[str, Any]]:
    hosts = detail.get('hosts') or detail.get('hostgroups') or []
    if isinstance(hosts, dict):
        hosts = hosts.get('hosts', [])
    return [item for item in hosts if isinstance(item, dict)] if isinstance(hosts, list) else []

def _history_id(history: dict[str, Any]) -> str:
    return str(history.get('id') or history.get('history_id') or '')

def _history_uuid(history: dict[str, Any]) -> str:
    return str(history.get('scan_uuid') or history.get('history_uuid') or history.get('uuid') or '')

def _history_date(history: dict[str, Any], detail: Optional[dict[str, Any]]=None) -> str:
    for name in ('last_modification_date', 'end_date', 'scan_end', 'start_date', 'creation_date', 'scan_start', 'timestamp'):
        if history.get(name) not in (None, '', 0, '0'):
            return _date_string(history.get(name))
    info = detail.get('info', {}) if isinstance(detail, dict) else {}
    if isinstance(info, dict):
        for name in ('scan_end', 'scan_start', 'timestamp', 'starttime'):
            if info.get(name) not in (None, '', 0, '0'):
                return _date_string(info.get(name))
    return ''

def _history_status(history: dict[str, Any], default: str) -> str:
    return str(history.get('status') or history.get('readable_status') or default or '')

def _selected_histories(client: NessusClient, scan: ScanRecord, include_history: bool) -> tuple[list[dict[str, Any]], str]:
    try:
        histories = client.scan_history(scan.api_id)
    except Exception as exc:
        histories = []
        error = f'Scan history API error: {exc}'
    else:
        error = ''
    if not histories:
        return ([{'id': None, 'scan_uuid': None, 'status': scan.status, 'start_date': scan.modified, '__no_history': True}], error)
    histories = sorted(histories, key=lambda item: _timestamp(_history_date(item)), reverse=True)
    return (histories if include_history else histories[:1], error)

def _match(ip: str, scan: ScanRecord, history: dict[str, Any], scan_date: str, scan_status: str, source: str, presence: str, note: str='', host_id: str='') -> dict[str, Any]:
    return {'normalized_ip': ip, 'folder_name': scan.folder_name, 'scan_name': scan.name, 'scan_id': scan.scan_id, 'history_id': _history_id(history), 'history_uuid': _history_uuid(history), 'scan_date': scan_date, 'scan_status': scan_status, 'history_available': not bool(history.get('__no_history')), 'presence_type': presence, 'result_note': note, 'evidence_source': source, 'host_id': host_id}

def _target_note(no_history: bool, host_count: int, error: str='') -> str:
    if no_history:
        message = 'IP is configured as a scan target, but no scan history was found (scan not performed).'
    elif error:
        message = 'IP is configured as a scan target, but the scan result could not be read.'
    elif host_count == 0:
        message = 'Latest scan history exists, but Nessus returned no host result for this configured target.'
    else:
        message = 'IP is configured as a scan target, but the host result was returned under a hostname or could not be mapped to this IP.'
    return f'{message} {error}'.strip()

def _base_detail(client: NessusClient, scan: ScanRecord) -> tuple[dict[str, Any], str]:
    try:
        return (client.scan_details(scan.api_id), '')
    except Exception as exc:
        return ({}, f'Latest scan details API error: {exc}')

def _auth_from_host(detail: Optional[dict[str, Any]], ips: set[str], scan: ScanRecord, history: dict[str, Any]) -> list[dict[str, Any]]:
    if not detail or not ips:
        return []
    rows: list[dict[str, Any]] = []
    vulnerabilities = detail.get('vulnerabilities', []) or []
    if not isinstance(vulnerabilities, list):
        return rows
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        plugin_id = str(vuln.get('plugin_id', vuln.get('id', '')))
        plugin_name = str(vuln.get('plugin_name', vuln.get('name', '')))
        if not is_auth_related(plugin_id, plugin_name):
            continue
        for ip in ips:
            rows.append({'normalized_ip': ip, 'scan_id': scan.scan_id, 'history_id': _history_id(history), 'history_uuid': _history_uuid(history), 'plugin_id': plugin_id, 'plugin_name': plugin_name, 'plugin_output': str(vuln.get('plugin_output', vuln.get('output', ''))), 'risk': str(vuln.get('risk', vuln.get('severity', '')))})
    return rows

def build_index_fast_api(client: NessusClient, input_ips: set[str], scan_records: list[ScanRecord], include_history: bool=False, fetch_host_details: bool=False, progress_callback=None) -> tuple[pd.DataFrame, pd.DataFrame]:
    matches: list[dict[str, Any]] = []
    auth_rows: list[dict[str, Any]] = []
    total = max(len(scan_records), 1)
    for position, scan in enumerate(scan_records, 1):
        if progress_callback:
            progress_callback(position, total, f'Reading scan details: {scan.name}')
        base, base_error = _base_detail(client, scan)
        targets = set(scan.configured_ips) | _ips_for_keys(base, TARGET_KEYS)
        name_ips = set(scan.name_ips)
        histories, history_error = _selected_histories(client, scan, include_history)
        for history in histories:
            history_id = _history_id(history)
            history_uuid = _history_uuid(history)
            no_history = bool(history.get('__no_history'))
            detail_error = ''
            if no_history and base:
                detail = base
            else:
                try:
                    detail = client.scan_details(scan.api_id, history_id=history_id or None, history_uuid=history_uuid or None)
                except Exception as exc:
                    detail = {}
                    detail_error = f'Scan detail API error: {exc}'
            current_targets = targets | _ips_for_keys(detail, TARGET_KEYS)
            scan_date = _history_date(history, detail) or scan.modified or scan.created
            scan_status = _history_status(history, scan.status)
            host_rows = _hosts(detail)
            result_ips: set[str] = set()
            for host in host_rows:
                host_id = str(host.get('host_id', host.get('id', '')))
                host_ips = _ips_for_keys(host, HOST_KEYS)
                matched = host_ips & input_ips
                host_detail: Optional[dict[str, Any]] = None
                if host_id and (fetch_host_details or not matched):
                    try:
                        host_detail = client.host_details(scan.api_id, host_id, history_id=history_id or None, history_uuid=history_uuid or None)
                        host_ips |= _ips_for_keys(host_detail, HOST_KEYS)
                        matched = host_ips & input_ips
                    except Exception:
                        host_detail = None
                if not matched:
                    continue
                result_ips |= matched
                for ip in sorted(matched):
                    matches.append(_match(ip, scan, history, scan_date, scan_status, 'Fast API + Host Details' if host_detail else 'Fast API', 'Scan result', host_id=host_id))
                auth_rows.extend(_auth_from_host(host_detail, matched, scan, history))
            errors = ' '.join((item for item in (history_error, base_error, detail_error) if item))
            configured_only = (current_targets & input_ips) - result_ips
            for ip in sorted(configured_only):
                matches.append(_match(ip, scan, history, scan_date, scan_status, 'Configured Scan Target', 'Configured target', _target_note(no_history, len(host_rows), errors)))
            name_only = (name_ips & input_ips) - result_ips - configured_only
            for ip in sorted(name_only):
                suffix = f' {errors}' if errors else ''
                matches.append(_match(ip, scan, history, scan_date, scan_status, 'Scan Name Fallback', 'Scan name only', f'IP was found in the scan name, but Nessus did not return a matching configured target or host result. Verify the scan target in Nessus.{suffix}'.strip()))
    return (pd.DataFrame(matches), pd.DataFrame(auth_rows))

def _read_csv(data: bytes) -> pd.DataFrame:
    for encoding in ('utf-8-sig', 'utf-8', 'latin1'):
        try:
            return pd.read_csv(io.BytesIO(data), encoding=encoding, dtype=str, keep_default_na=False)
        except Exception:
            pass
    return pd.DataFrame(list(csv.DictReader(io.StringIO(data.decode('utf-8', errors='replace')))))

def _csv_fields(df: pd.DataFrame) -> dict[str, Any]:
    columns = {_key(column): column for column in df.columns}
    aliases = ('host', 'hostname', 'host_ip', 'ip_address', 'asset_ip', 'asset_ip_address', 'ipv4_address', 'address')
    hosts = [columns[name] for name in aliases if name in columns]
    for column in df.columns:
        normalized = _key(column)
        if column not in hosts and (normalized.startswith('host_') or normalized.endswith('_ip') or normalized.endswith('_ip_address')):
            hosts.append(column)
    return {'hosts': hosts, 'plugin': columns.get('plugin_id') or columns.get('id'), 'name': columns.get('name') or columns.get('plugin_name'), 'output': columns.get('plugin_output') or columns.get('output'), 'risk': columns.get('risk') or columns.get('risk_factor') or columns.get('severity')}

def build_index_csv_export(client: NessusClient, input_ips: set[str], scan_records: list[ScanRecord], include_history: bool=False, progress_callback=None) -> tuple[pd.DataFrame, pd.DataFrame]:
    matches: list[dict[str, Any]] = []
    auth_rows: list[dict[str, Any]] = []
    total = max(len(scan_records), 1)
    for position, scan in enumerate(scan_records, 1):
        if progress_callback:
            progress_callback(position, total, f'Exporting scan CSV: {scan.name}')
        base, base_error = _base_detail(client, scan)
        targets = set(scan.configured_ips) | _ips_for_keys(base, TARGET_KEYS)
        histories, history_error = _selected_histories(client, scan, include_history)
        for history in histories:
            no_history = bool(history.get('__no_history'))
            scan_date = _history_date(history, base) or scan.modified or scan.created
            scan_status = _history_status(history, scan.status)
            result_ips: set[str] = set()
            export_error = ''
            frame = pd.DataFrame()
            if not no_history:
                try:
                    frame = _read_csv(client.export_scan_csv(scan.api_id, _history_id(history) or None))
                except Exception as exc:
                    export_error = f'CSV export error: {exc}'
            if not frame.empty:
                fields = _csv_fields(frame)
                for _, row in frame.iterrows():
                    row_ips: set[str] = set()
                    for column in fields['hosts']:
                        row_ips |= extract_ips_from_text(row.get(column, ''))
                    matched = row_ips & input_ips
                    if not matched:
                        continue
                    result_ips |= matched
                    for ip in sorted(matched):
                        matches.append(_match(ip, scan, history, scan_date, scan_status, 'CSV Export', 'Scan result'))
                    plugin_column = fields['plugin']
                    if not isinstance(plugin_column, str):
                        continue
                    plugin_id = str(row.get(plugin_column, '')).strip()
                    name_column = fields['name']
                    plugin_name = str(row.get(name_column, '')) if isinstance(name_column, str) else ''
                    if not is_auth_related(plugin_id, plugin_name):
                        continue
                    for ip in matched:
                        output_column = fields['output']
                        risk_column = fields['risk']
                        auth_rows.append({'normalized_ip': ip, 'scan_id': scan.scan_id, 'history_id': _history_id(history), 'history_uuid': _history_uuid(history), 'plugin_id': plugin_id, 'plugin_name': plugin_name, 'plugin_output': str(row.get(output_column, '')) if isinstance(output_column, str) else '', 'risk': str(row.get(risk_column, '')) if isinstance(risk_column, str) else ''})
            errors = ' '.join((item for item in (history_error, base_error, export_error) if item))
            configured_only = (targets & input_ips) - result_ips
            for ip in sorted(configured_only):
                matches.append(_match(ip, scan, history, scan_date, scan_status, 'Configured Scan Target', 'Configured target', _target_note(no_history, len(frame), errors)))
            name_only = set(scan.name_ips) & input_ips - result_ips - configured_only
            for ip in sorted(name_only):
                suffix = f' {errors}' if errors else ''
                matches.append(_match(ip, scan, history, scan_date, scan_status, 'Scan Name Fallback', 'Scan name only', f'IP was found in the scan name, but the CSV result and configured target fields did not return it. Verify the scan target in Nessus.{suffix}'.strip()))
    return (pd.DataFrame(matches), pd.DataFrame(auth_rows))
DETAIL_COLUMNS = ['normalized_ip', 'folder_name', 'scan_name', 'scan_id', 'history_id', 'history_uuid', 'scan_date', 'scan_status', 'history_available', 'presence_type', 'result_note', 'evidence_source', 'host_id']

def summarize_results(input_rows: pd.DataFrame, matches: pd.DataFrame, auth_rows: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    detail = matches.copy() if not matches.empty else pd.DataFrame(columns=DETAIL_COLUMNS)
    for column in DETAIL_COLUMNS:
        if column not in detail.columns:
            detail[column] = ''
    detail = detail[detail['normalized_ip'].astype(str).str.len() > 0].drop_duplicates()
    summary: list[dict[str, Any]] = []
    ranks = {'Scan result': 3, 'Configured target': 2, 'Scan name only': 1}
    for _, input_row in input_rows.iterrows():
        original = str(input_row.get('Input IP', ''))
        ip = str(input_row.get('Normalized IP', ''))
        found = detail[detail['normalized_ip'] == ip]
        if found.empty:
            summary.append({'Input IP': original, 'Normalized IP': ip, 'Present in Nessus': 'No', 'Presence Type': 'Not found', 'Primary Folder Name': '', 'All Folder Names': '', 'Latest Scan Name': '', 'All Scan Names': '', 'Latest Scan Date': '', 'Latest Scan Status': '', 'History Available': 'No', 'Result Note': 'IP was not found in scan-result hosts, configured scan targets, CSV host fields, or scan names in the selected scope.', 'Authentication Status': 'Not validated', 'Authentication Failure Reason': 'IP was not found in selected Nessus scans/folders', 'Auth Evidence Plugin': '', 'Protocol Summary': '', 'Confidence': 'Low', 'Match Count': 0, 'Evidence Source': ''})
            continue
        ordered = found.copy()
        ordered['__date'] = pd.to_datetime(ordered['scan_date'], errors='coerce', utc=True)
        ordered['__rank'] = ordered['presence_type'].map(ranks).fillna(0)
        ordered = ordered.sort_values(['__date', '__rank'], ascending=[False, False], na_position='last')
        latest = ordered.iloc[0]
        evidence = pd.DataFrame()
        if not auth_rows.empty and 'normalized_ip' in auth_rows.columns:
            evidence = auth_rows[auth_rows['normalized_ip'].astype(str) == ip]
            if 'scan_id' in evidence.columns:
                evidence = evidence[evidence['scan_id'].astype(str) == str(latest.get('scan_id', ''))]
            history_id = str(latest.get('history_id', ''))
            history_uuid = str(latest.get('history_uuid', ''))
            if history_id and 'history_id' in evidence.columns:
                evidence = evidence[evidence['history_id'].astype(str) == history_id]
            elif history_uuid and 'history_uuid' in evidence.columns:
                evidence = evidence[evidence['history_uuid'].astype(str) == history_uuid]
        findings = [AuthFinding(plugin_id=str(row.get('plugin_id', '')), plugin_name=str(row.get('plugin_name', '')), plugin_output=str(row.get('plugin_output', '')), risk=str(row.get('risk', ''))) for _, row in evidence.iterrows()]
        auth = classify_auth(findings)
        presence = str(latest.get('presence_type', ''))
        note = str(latest.get('result_note', ''))
        if presence != 'Scan result':
            auth = {'auth_status': 'Not validated', 'auth_reason': note or 'No matching host result was available for authentication validation', 'auth_plugin': '', 'protocol_summary': '', 'confidence': 'Low'}
        history_available = latest.get('history_available', False)
        if isinstance(history_available, str):
            history_available = history_available.lower() in {'true', 'yes', '1'}
        summary.append({'Input IP': original, 'Normalized IP': ip, 'Present in Nessus': 'Yes', 'Presence Type': presence, 'Primary Folder Name': str(latest.get('folder_name', '')), 'All Folder Names': ' | '.join(sorted(set(found['folder_name'].astype(str)) - {''})), 'Latest Scan Name': str(latest.get('scan_name', '')), 'All Scan Names': ' | '.join(sorted(set(found['scan_name'].astype(str)) - {''})), 'Latest Scan Date': str(latest.get('scan_date', '')), 'Latest Scan Status': str(latest.get('scan_status', '')), 'History Available': 'Yes' if history_available else 'No', 'Result Note': note, 'Authentication Status': auth['auth_status'], 'Authentication Failure Reason': auth['auth_reason'], 'Auth Evidence Plugin': auth['auth_plugin'], 'Protocol Summary': auth['protocol_summary'], 'Confidence': auth['confidence'], 'Match Count': int(len(found)), 'Evidence Source': ' | '.join(sorted(set(found['evidence_source'].astype(str)) - {''}))})
    return (pd.DataFrame(summary), detail)
