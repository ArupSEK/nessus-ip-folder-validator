# Known Limitations

## Current

- PostgreSQL runtime verification is still pending; automated validation currently runs on SQLite for local tests.
- Redis runtime verification is still pending.
- Celery runtime verification is still pending.
- Docker Compose runtime could not be executed because Docker is not installed in this environment.
- The frontend now includes live dashboard, workflow, audit, reporting, Nessus settings, folder management, scan management and IP search surfaces, but import/comparison operator pages and several advanced scan actions are still pending.
- IP search currently matches synchronized scan targets and CIDR scopes; imported results, host records and vulnerability-result matching still depend on later import phases.
- Folder deletion behavior text is aligned to the mocked Tenable VM workflow and should be re-verified against the exact connected Nessus product/version before production rollout.
- Live validation against the local Nessus instance on July 30, 2026 required `verify_tls=False` for `https://localhost:8834`; production deployment should use a trusted certificate chain so TLS verification can remain enabled.
- Live validation against the same local Nessus instance on July 30, 2026 showed that the server reports `license.features.scan_api=false`; the application now blocks unsupported scan-control actions before issuing live POST requests.
- Direct upstream validation against the same local Nessus instance on July 30, 2026 still showed that `POST /scans` resets the TCP connection even for invalid, policy-based, or minimal JSON bodies and does not create a scan.
- Direct upstream validation against the same local Nessus instance on July 30, 2026 also showed that `POST /scans/{scan_id}/copy` resets the TCP connection and does not create a cloned scan from the master template path.
- Existing Streamlit starter remains present during transition until later cleanup is safe.
