# AegisMap

A fresh restart of the Nessus IP validation tool.

This initial scaffold currently provides:

- CSV / Excel upload
- automatic IP-column detection
- IP normalization
- cleaned CSV export
- starter layout for later Nessus integration

## Preserved previous version

The earlier full-featured version was preserved here before the reset:

```text
C:\Users\gsaru\Github-ArupSEK\nessus-ip-folder-validator-backup-2026-07-30
```

## Run

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Next planned modules

1. Connection validation against Nessus / Tenable
2. Scan and folder discovery
3. IP-to-scan matching
4. Authentication evidence parsing
5. Exportable validation report
