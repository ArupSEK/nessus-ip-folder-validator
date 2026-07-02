# Nessus IP-to-Folder Validator

A modern Streamlit GUI tool to validate a CSV/Excel list of IP addresses against Nessus / Tenable scan folders and scan histories.

## What it shows

For each input IP address, the tool reports:

- Whether the IP is present in Nessus scan results
- Primary folder name where the latest match is found
- All folder names if the IP is present in multiple folders
- Latest scan name, scan date, and scan status
- Authentication status
- Authentication failure reason, where plugin output is available
- Auth evidence plugin ID/name
- Protocol summary
- Match count
- Evidence source: Fast API or CSV Export

## Best mode to use

Use **Fast API mode** first for quick lookup.

Use **Reliable CSV export mode** for final VAPT validation because it exports the scan result CSV and parses the `Host`, `Plugin ID`, `Name`, and `Plugin Output` columns. This gives the best authentication failure reason.

## API endpoints used

The tool uses the common Tenable/Nessus API flow:

```text
GET    /folders
GET    /scans
GET    /scans/{scan_id}/history
GET    /scans/{scan_id}?history_id=<history_id>
GET    /scans/{scan_uuid}/hosts/{host_id}?history_id=<history_id>   # optional
POST   /scans/{scan_id}/export?history_id=<history_id>              # CSV mode
GET    /scans/{scan_id}/export/{file_id}/status
GET    /scans/{scan_id}/export/{file_id}/download
```

## Install on Kali / Linux

```bash
cd nessus_ip_validator_tool
chmod +x run_linux.sh
./run_linux.sh
```

Manual method:

```bash
cd nessus_ip_validator_tool
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Install on Windows

Double-click:

```text
run_windows.bat
```

Manual method:

```powershell
cd nessus_ip_validator_tool
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Input file format

CSV or Excel is supported.

Minimum column:

```csv
IP Address
192.168.1.10
192.168.1.11
10.10.10.25
```

The column can be named `IP`, `IP Address`, `Host`, `Hostname`, or similar. The GUI lets you select the column.

## Connection settings

For Tenable Vulnerability Management cloud:

```text
Base URL: https://cloud.tenable.com
```

For standalone Nessus / Nessus Manager:

```text
Base URL: https://<nessus-ip>:8834
```

Use your Nessus/Tenable Access Key and Secret Key.

If your Nessus uses a self-signed certificate, uncheck **Verify SSL certificate**.

## Authentication status logic

The tool classifies authentication status using evidence plugins, especially:

| Status | Evidence examples |
|---|---|
| Authenticated | 141118, 110095, or plugin 19506 showing Credentialed Checks: yes |
| Valid with limitations | 110385, 117885 |
| Failed | 104410, 122503, 21745, 24786, 10428, 26917, 91822, 11149 |
| No credentials | 110723, or plugin 19506 showing Credentialed Checks: no |
| Unknown | No authentication evidence found |

## Important notes

1. Nessus/Tenable does not provide one direct endpoint like “find IP in any folder”. The tool builds a local match table by joining folders, scans, scan histories, and hosts.
2. CSV export mode is slower but more reliable for final evidence.
3. Very old scans may require export mode because host details can be unavailable through direct host APIs.
4. Folder visibility depends on the API user's permission. If your API key cannot view a folder/scan, the tool cannot report it.
5. Do not share your API keys. Enter them only in the local GUI.

## Troubleshooting

### 401 invalid API key
Check Access Key and Secret Key. Do not include extra spaces.

### 403 permission issue
The API user may not have permission to view or export scans.

### 429 rate limit
Reduce the number of scans, use date filter, or wait and run again.

### Standalone Nessus certificate error
Uncheck **Verify SSL certificate** in the sidebar.

### CSV export is slow
Use Fast API mode first. Then use CSV Export mode only for the final selected date/folder scope.
