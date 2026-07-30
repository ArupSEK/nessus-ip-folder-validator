# Threat Model

## Primary Risks

- credential leakage
- authorization bypass
- SSRF through Nessus URL configuration
- CSRF against destructive actions
- insecure direct object reference
- unsafe file upload handling
- exported report formula injection
- false vulnerability closure caused by weak scan validation

## Phase 1 Threat Focus

Phase 1 primarily addresses structural groundwork:

- isolated configuration
- clear backend/frontend separation
- health endpoints only
- no secret persistence yet

## Deferred to Later Phases

- session threat handling
- Nessus credential encryption
- RBAC enforcement
- audit tamper resistance
- import/export abuse cases
