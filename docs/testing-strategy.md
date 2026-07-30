# Testing Strategy

## Backend

- Pytest
- route tests
- service tests
- mocked Nessus API client tests
- migration checks

## Frontend

- Vitest
- component tests
- Playwright end-to-end tests

## Quality Gates

- tests must run after each phase
- do not mark a phase complete without executed tests
- no unverified claims of passing builds

## Phase 1 Validation Goal

- backend health route tests
- settings import test
- database metadata smoke test
- existing helper tests retained where still relevant
