# Data Model

## Phase 1 Scope

Phase 1 does not implement full business models yet. It defines the initial database foundation and prepares for the following core entities:

- users
- roles
- permissions
- sessions
- audit events
- nessus configurations
- folders
- scans
- scan histories
- assets
- findings
- lifecycle states
- remediation records
- exceptions
- risk acceptances

## Implemented Models Through Phase 10 Backend Work

- `User`
- `Role`
- `Permission`
- `UserRole`
- `RolePermission`
- `UserSession`
- `PasswordResetToken`
- `AuditEvent`
- `NessusConfiguration`
- `FolderRecord`
- `ScanRecord`
- `ScanHistoryRecord`
- `ImportJob`
- `AssetRecord`
- `FindingRecord`
- `ComparisonRun`
- `ComparisonResultRecord`
- `SlaPolicy`
- `FindingWorkflow`
- `WorkflowDecision`

## Notes

- Authentication timestamps are stored in UTC.
- Session tokens and reset tokens are stored as hashes, not plaintext values.
- Nessus access and secret keys are stored only as encrypted payloads plus masked display values.
- Session records track `reauthenticated_at` to support recent-password confirmation for destructive actions.
- Folder and scan records use `deleted_at` rather than destructive local removal so historical audit evidence can remain intact.
- Import jobs persist export progress, recovery state and import counts.
- Asset records preserve per-import history snapshots and enforce uniqueness only within a single import job.
- Finding records preserve per-import history snapshots and enforce uniqueness only within a single import job.
- Asset records use a stable key derived from the strongest available exported host identifiers in the current import layer.
- Finding records use a deterministic key based on stable asset key, plugin ID, port and protocol.
- Comparison runs store lifecycle counters for summary dashboards.
- Comparison result records preserve per-finding lifecycle decisions, eligibility status and explanatory reasons.
- SLA policies persist severity-to-due-date rules.
- Finding workflows persist assignment, ticketing, evidence, validation state and computed overdue status per deterministic `finding_key`.
- Workflow decisions persist exception, risk-acceptance and false-positive requests and approvals, including expiry tracking and renewal history.
