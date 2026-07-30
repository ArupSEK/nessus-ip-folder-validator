# Nessus API Mapping

## Implemented Endpoint Mapping Through Phase 6

| Local Capability | Tenable Endpoint | Notes |
|---|---|---|
| Connection test | `GET /server/properties` | used to validate base connectivity and retrieve product metadata |
| Current-user permissions | `GET /api/v3/access-control/permissions/users/me` | handled as optional capability because support can vary by product/version |
| Folder inventory probe | `GET /folders` | used for capability detection and folder synchronization |
| Scan inventory probe | `GET /scans` | used for synchronization, folder previews and IP search backing data |
| Create custom folder | `POST /folders` | used for local folder creation only after Nessus confirms success |
| Rename custom folder | `PUT /folders/{folder_id}` | used only for locally tracked custom folders |
| Delete custom folder | `DELETE /folders/{folder_id}` | wrapped with local preview, confirmation and audit logging |
| Scan templates | `GET /editor/scan/templates` | used for validated scan-creation choices |
| Scanners | `GET /scanners` | used for scan-creation and scan-edit choices |
| Scan details and histories | `GET /scans/{scan_id}` | used to hydrate local scan state and history inventory |
| Create scan | `POST /scans` | used for validated scan creation |
| Edit or move scan | `PUT /scans/{scan_id}` | used for name, folder, target, scanner and schedule changes |
| Clone scan | `POST /scans/{scan_id}/copy` | used for scan cloning |
| Launch scan | `POST /scans/{scan_id}/launch` | used for explicit launch actions only |
| Stop scan | `POST /scans/{scan_id}/stop` | used when scan state permits stop |
| Move scan to Trash | `DELETE /scans/{scan_id}` | wrapped with local state and audit preservation |
| Delete scan history | `DELETE /scans/{scan_id}/history/{history_id}` | wrapped with local protection checks and audit logging |

## Notes

- The client is kept inside `backend/app/integrations/nessus/client.py` as the dedicated Nessus communication boundary.
- Unsupported or unavailable probes are recorded in local capabilities instead of being guessed.
