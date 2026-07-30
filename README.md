# AegisMap

AegisMap is a clean restart of the Nessus IP validation tool.

The current version is a focused starter workspace for:

- CSV / Excel intake
- automatic IP-column detection
- IP normalization
- invalid-row separation
- cleaned CSV export

It is intentionally narrow at this stage. The Nessus / Tenable integration layer will be rebuilt on top of this simpler foundation.

## Current Workflow

1. Upload a CSV or Excel file
2. Select or confirm the IP column
3. Normalize valid IP values
4. Review valid and invalid rows
5. Export the cleaned result set

## UI Direction

The app is being rebuilt as a modern, professional operator tool with:

- compact workflow-oriented layout
- dark and light themes
- cleaner data review surfaces
- staged expansion for Nessus validation features

## Run Locally

### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

### Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Project Files

```text
app.py               Streamlit application
ip_utils.py          IP normalization helpers
sample_ips.csv       Sample upload file
tests/test_ip_utils.py
```

## Preserved Previous Version

The earlier full-featured build was preserved before this reset:

```text
C:\Users\gsaru\Github-ArupSEK\nessus-ip-folder-validator-backup-2026-07-30
```

That backup remains available if you need to reference or recover the older implementation.

## Planned Build Phases

1. Harden the intake and review workflow
2. Add Nessus / Tenable connection validation
3. Add scan and folder discovery
4. Add IP-to-scan matching
5. Add authentication evidence parsing
6. Add report exports

## Status

As of July 30, 2026, this repository is the new starter codebase, not the old production-style build.
