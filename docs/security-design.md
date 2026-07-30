# Security Design

## Core Security Principles

- secure defaults
- no plaintext secrets in source control
- no secret values returned to the browser
- server-side authorization for sensitive actions
- secret redaction in logs and errors
- least privilege

## Planned Controls

- Argon2id password hashing
- session-based auth with HTTP-only cookies
- CSRF protection
- login rate limiting
- account lockout
- configurable session timeout
- encrypted Nessus credential storage
- role-based access control
- audit logging

## Phase 1 Security Goal

Phase 1 establishes:

- environment-driven config
- service separation
- logging foundation
- explicit placeholders for secrets and security-sensitive settings

## Phase 2 Security Controls Implemented

- Argon2id password hashing for application passwords
- server-side session records with HTTP-only session cookies
- CSRF token validation for authenticated write endpoints
- configurable lockout and session timeout handling
- role and permission checks enforced on the server
- audit events for login, logout and password operations

## Phase 3 Security Controls Implemented

- authenticated encryption for stored Nessus API credentials
- SSRF checks for Nessus host configuration
- redirect blocking and secret-safe Nessus client error handling
- administrator-only Nessus configuration and credential reset routes
- recent re-authentication requirement for destructive Nessus credential reset

## Security Gaps Still Open

- no MFA implementation yet
- no dedicated rate-limit middleware yet beyond account lockout logic
- destructive folder and scan operations still need recent re-authentication flows
