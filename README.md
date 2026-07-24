# Nessus IP-to-Folder Validator

A Streamlit GUI that checks a CSV/Excel IP list against Nessus or Tenable scans, folders, latest scan history, configured targets, host results, and authentication evidence.

## Secure local login

The application now opens with a Trinetra-style login page.

- On the first launch, create a local administrator username and password.
- Later launches require that account before the Nessus dashboard is displayed.
- The plaintext password is never stored.
- A random salt and PBKDF2-HMAC-SHA256 password hash are stored in the local user profile.
- After five incorrect attempts, the current browser session is temporarily locked for 30 seconds.
- The sidebar provides a **Sign Out** button that also clears Nessus API keys and generated results from the Streamlit session.

Default local login file:

```text
Linux/macOS: ~/.nessus_ip_validator_auth.json
Windows:     %USERPROFILE%\.nessus_ip_validator_auth.json
```

The file is created with restricted permissions where the operating system supports them. It is outside the repository and is also covered by `.gitignore` patterns.

To use a different location, set this environment variable before starting Streamlit:

```bash
export NESSUS_VALIDATOR_AUTH_FILE=/secure/path/nessus-validator-auth.json
```

To reset a forgotten local login, stop the application and delete the login file. The next launch will show the first-run account creation page again.

Linux/macOS:

```bash
rm ~/.nessus_ip_validator_auth.json
```

Windows PowerShell:

```powershell
Remove-Item "$HOME\.nessus_ip_validator_auth.json"
```

Deleting this file resets only the dashboard login. It does not modify Nessus, Tenable, scans, or API accounts.

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

## Two-step low-API workflow

The application now separates discovery from detailed authentication validation.

### Step 1: Find Folder and Scan

**Find Folder and Scan (Low API)** calls `/folders` and `/scans` once, filters candidate scans locally using configured targets and IPs in scan names, and opens only the newest relevant scan summaries. It does not paginate scan history, request host details, or create CSV export jobs.

If the lightweight scan-list metadata does not identify a candidate, enable **Fallback search across all scans** and run discovery again. This is optional because it can substantially increase API use.

### Step 2: Deep Validate Selected IPs

After discovery shows the exact folder, scan, and latest run, select only the required IPs and click **Deep Validate Selected IPs**. Selected IPs are grouped by scan ID and history ID so multiple IPs in one scan share a single scan-detail request or CSV export operation.

Two deep-validation methods are available:

- **Host details (lower API usage):** reads the selected scan once and opens host details only inside that scan.
- **CSV export (exact plugin output):** exports only the selected scan/history group and parses exact authentication-related plugin output.

Authentication is classified using evidence from the selected latest scan/history only. An old authentication failure does not override a newer successful run.

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

## API consumption design

The default discovery path is candidate-first and stops searching an IP after its newest folder/scan match is located. The dashboard displays the number of logical API requests used. Deep validation is never run automatically.

Recommended usage:

1. Run low-API discovery with fallback disabled.
2. Review the located folder and scan.
3. Select only IPs that require authentication evidence.
4. Use host details for routine checks or CSV export when exact plugin output is required.

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

The tests cover local login hashing and verification, configured-target fallback, DNS-name host resolution, no-history reporting, CIDR normalization, latest-history authentication selection, candidate-only discovery, and scan-grouped deep validation.

## Troubleshooting

- **Forgot local login:** Stop Streamlit, delete `~/.nessus_ip_validator_auth.json`, and start it again.
- **Login temporarily locked:** Wait 30 seconds or open a fresh browser session.
- **IP shows Configured target:** The scan exists and contains the IP, but discovery did not return a directly mappable host result. Select it and run Deep Validation.
- **IP is not located in low-API discovery:** Enable Fallback search across all scans and run discovery again.
- **IP shows Scan name only:** Open the scan and verify that the configured target is the same IP.
- **401:** Check the access and secret keys.
- **403:** The API account cannot view or export that scan.
- **429:** Reduce the scan scope or retry after the rate-limit window.
- **Archived scan:** Use Reliable CSV export mode.
