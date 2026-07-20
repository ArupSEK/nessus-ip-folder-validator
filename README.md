# Nessus IP-to-Folder Validator

A Streamlit GUI that checks a CSV/Excel IP list against Nessus or Tenable scans, folders, latest scan history, configured targets, host results, and authentication evidence.

## Fixed IP-detection logic

The validator no longer marks an IP as **Not Found** only because the scan-details API returned an empty host list or returned the host as a DNS name.

For each input IP, it now checks in this order:

1. The latest scan-result host list.
2. Host details when the summary host is a DNS name/FQDN.
3. Configured scan target fields such as `text_targets`, `targets`, and `alt_targets`.
4. Nessus CSV export host/IP columns.
5. The scan name as a clearly labelled last-resort fallback.

The output shows a **Presence Type**:

| Presence Type | Meaning |
|---|---|
| Scan result | The IP was found in the actual scan-result host data. |
| Configured target | The IP is configured in the scan, but Nessus did not return a directly mappable host result. |
| Scan name only | The IP appears only in the scan name; verify the configured target. |
| Not found | No matching result, target, CSV host field, or scan-name evidence was found. |

When a configured IP has no history, the result states **scan not performed** instead of incorrectly showing the IP as absent from Nessus.

## Latest-history behaviour

By default, the tool checks only the latest scan run. Enable **Include older scan histories** only when you need historical matches.

Authentication is classified using evidence from the selected latest scan/history only. An old authentication failure no longer overrides a newer successful run.

## What the report contains

- Present in Nessus
- Presence type and result note
- Primary and all matching folders
- Latest scan name, date, and status
- Whether scan history exists
- Authentication status and failure reason
- Authentication evidence plugin
- Protocol summary and confidence
- Match count and evidence source

## Collection modes

### Fast API mode

Recommended for normal lookup. If a host is returned only as a DNS name, the tool automatically requests host details to recover the IP.

### Fast API + host details

Reads host details for every matched host. Use it when you need additional host-level evidence.

### Reliable CSV export mode

Slower, but best for final VAPT validation and exact authentication failure reasons because it parses plugin output from exported results. It is also useful for archived results.

## API flow

```text
GET    /folders
GET    /scans
GET    /scans/{scan_id}/history
GET    /scans/{scan_id}?history_id=<history_id>
GET    /scans/{scan_id}/history/{history_uuid}                 # UUID fallback
GET    /scans/{scan_uuid}/hosts/{host_id}?history_id=<id>
POST   /scans/{scan_id}/export?history_id=<history_id>
GET    /scans/{scan_id}/export/{file_id}/status
GET    /scans/{scan_id}/export/{file_id}/download
```

## Install and run

```bash
git clone https://github.com/ArupSEK/nessus-ip-folder-validator.git
cd nessus-ip-folder-validator
```

### Kali/Linux

```bash
chmod +x run_linux.sh
./run_linux.sh
```

Manual method:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

### Windows

Double-click `run_windows.bat`, or run:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Input format

```csv
IP Address
192.168.1.10
192.168.1.11
10.10.10.25
```

The validator also accepts IP values such as `192.168.1.10/32`, mixed text like `server01 / 192.168.1.10`, IPv4 with a port, and IPv6.

## Connection settings

Tenable Vulnerability Management:

```text
https://cloud.tenable.com
```

Standalone Nessus/Nessus Manager:

```text
https://<nessus-ip>:8834
```

Use an API account that can view the required folders and scans. For a self-signed standalone certificate, clear **Verify SSL certificate**.

## Run regression tests

```bash
python -m unittest discover -s tests -v
```

The tests cover configured-target fallback, DNS-name host resolution, no-history reporting, CIDR normalization, and latest-history authentication selection.

## Troubleshooting

- **IP shows Configured target:** The scan exists and contains the IP, but the selected history did not return a directly mappable host result. Check the Result Note and try CSV export mode.
- **IP shows Scan name only:** Open the scan and verify that the configured target is the same IP.
- **401:** Check the access and secret keys.
- **403:** The API account cannot view or export that scan.
- **429:** Reduce the scan scope or retry after the rate-limit window.
- **Archived scan:** Use Reliable CSV export mode.
