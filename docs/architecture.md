# Architecture

## Target Stack

### Backend

- FastAPI
- SQLAlchemy 2
- Alembic
- PostgreSQL
- Redis
- Celery

### Frontend

- React
- TypeScript
- Vite
- Material UI

## High-Level Components

1. `backend/`
   - HTTP API
   - security and session handling
   - service layer
   - data-access layer
   - Nessus API client
   - background task orchestration

2. `frontend/`
   - authenticated SPA
   - dashboards
   - management pages
   - data grids and filters

3. `worker/`
   - long-running sync/import/export jobs
   - comparison jobs
   - reporting jobs

4. `postgres`
   - application relational data

5. `redis`
   - queue broker
   - caching
   - rate-limiting/session support where applicable

## Phase 1 Architecture Goal

Phase 1 only establishes the runnable skeleton:

- backend health routes
- base configuration
- base DB metadata
- migration scaffold
- service containers
- frontend shell

Detailed feature architecture will be extended in later phases.
