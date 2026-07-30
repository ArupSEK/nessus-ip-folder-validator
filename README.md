# AegisMap 2.0

Internal Nessus operations console for inventory search, scan management, vulnerability lifecycle tracking, reporting, and audit review.

This repository contains the active FastAPI + React application. It is intended for internal deployment, especially in restricted or closed client environments.

## At a Glance

- Secure login with server-side sessions
- Nessus connection setup with encrypted credential storage
- Folder sync, create, rename, delete preview, and delete
- Scan inventory, create, edit, clone, move, launch, stop, Trash, and history delete for supported Nessus environments
- Global IP search from manual input, CSV, Excel, and text files
- Vulnerability import, comparison, lifecycle, dashboard, workflow, reports, and audit views
- Dark and light themes

## Current State

As of Thursday, July 30, 2026:

- Backend and frontend application layers are implemented in this repository.
- Backend automated tests are passing.
- Frontend tests and production build are passing.
- The scan creation flow uses a guided wizard.

Known live limitation:

- On the local Nessus instance used for validation on July 30, 2026, `license.features.scan_api=false`. That blocks live scan create, clone, launch, stop, and delete operations even though the application-side flows are implemented.

Detailed status:

- [docs/implementation-status.md](docs/implementation-status.md)
- [docs/known-limitations.md](docs/known-limitations.md)
- [docs/requirements-traceability.md](docs/requirements-traceability.md)

## Stack

### Backend

- Python
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

## Repository Layout

```text
backend/                 FastAPI app, services, models, routes
frontend/                React UI
alembic/                 database migrations
docs/                    architecture, status, security, traceability
tests/                   legacy utility tests
docker-compose.yml       local multi-service stack
.env.example             environment variable template
```

## How the App Is Used

Typical operator flow:

1. Open the UI in a browser
2. Sign in with an application account
3. Open `Nessus`
4. Enter the internal Nessus URL, Access Key, and Secret Key
5. Test and save the connection
6. Use:
   - `Folders`
   - `Scans`
   - `IP Search`
   - `Overview`
   - `Findings`
   - `Reports`
   - `Audit`

Recommended internal deployment model:

```text
User Browser
   -> AegisMap server
   -> PostgreSQL / Redis
   -> Internal Nessus
```

Run the app on one internal server and let users access it through the browser. That is simpler and more supportable than installing the full stack on every client machine.

## Quick Start

### URLs

- Backend health: `http://localhost:8000/health/live`
- Application UI: `http://localhost:8000/ui`

### First-time setup summary

1. Create `.env`
2. Install dependencies
3. Build the frontend
4. Run migrations
5. Create the first administrator
6. Start backend
7. Start worker
8. Open `/ui`

## Environment File

Copy `.env.example` to `.env` and review the values before startup.

Minimum variables to change:

```env
APP_ENV=production
APP_DEBUG=false
SECRET_KEY=<strong-random-secret>
DATABASE_URL=postgresql+psycopg://postgres:<password>@<db-host>:5432/nessus_tracker
REDIS_URL=redis://<redis-host>:6379/0
CELERY_BROKER_URL=redis://<redis-host>:6379/1
CELERY_RESULT_BACKEND=redis://<redis-host>:6379/2
NESSUS_MASTER_KEY=<base64-random-key>
TIMEZONE=UTC
```

Cookie guidance:

- If the app is behind internal HTTPS, set `SESSION_COOKIE_SECURE=true`
- If the app is served only over plain internal HTTP, keep `SESSION_COOKIE_SECURE=false`

## Run With Docker Compose

Use this when Docker is allowed on the internal server.

### Start services

```powershell
docker compose up --build
```

### Run migrations

```powershell
docker compose exec backend alembic upgrade head
```

### Create the first administrator

```powershell
docker compose exec backend python -m backend.app.cli bootstrap-admin --username admin
```

### Open the app

```text
http://localhost:8000/ui
```

### Notes

- The compose stack includes PostgreSQL, Redis, backend, worker, and frontend service definitions.
- The backend serves the built UI from `/ui` when `frontend/dist` exists.
- Docker runtime was not validated in this workspace because Docker is not installed here.

## Run Natively on Windows

Use this path when Docker is not available.

### Prerequisites

- Python 3.12 or newer
- Node.js and npm
- PostgreSQL
- Redis

### 1. Create the virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install Python dependencies

```powershell
pip install -r requirements.txt
```

### 3. Build the frontend

```powershell
cd frontend
npm install
npm run build
cd ..
```

### 4. Run database migrations

```powershell
alembic upgrade head
```

### 5. Create the first administrator

```powershell
python -m backend.app.cli bootstrap-admin --username admin
```

### 6. Start the backend

```powershell
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

### 7. Start the worker

Open a second PowerShell window:

```powershell
.\.venv\Scripts\Activate.ps1
celery -A backend.app.worker.celery_app worker --loglevel=INFO
```

### 8. Open the UI

```text
http://localhost:8000/ui
```

## Run Natively on Kali Linux

### Prerequisites

- Python 3.12 or newer
- Node.js and npm
- PostgreSQL
- Redis

### 1. Create the virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Build the frontend

```bash
cd frontend
npm install
npm run build
cd ..
```

### 4. Run database migrations

```bash
alembic upgrade head
```

### 5. Create the first administrator

```bash
python -m backend.app.cli bootstrap-admin --username admin
```

### 6. Start the backend

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

### 7. Start the worker

Open a second terminal:

```bash
source .venv/bin/activate
celery -A backend.app.worker.celery_app worker --loglevel=INFO
```

### 8. Open the UI

```text
http://localhost:8000/ui
```

## Closed or Restricted Environment Deployment

This is the recommended model for client internal networks.

### Goal

Prepare everything outside the client network, then transfer a ready-to-run bundle inside.

### Best approach

1. Build `frontend/dist` outside the restricted network
2. Download Python dependencies outside the restricted network
3. Transfer:
   - repository files
   - `.env`
   - built frontend
   - offline Python packages
4. Run the app on one internal server
5. Let users access only the browser URL

### Why this is easier

- No public npm access is needed inside the client network
- No public Python package download is needed inside the client network
- UI can be served directly by the backend from `/ui`

### Suggested transfer bundle

```text
deployment/
  app/
  .env
  frontend-dist/
  wheelhouse/
  setup-notes.txt
```

### Prepare offline Python packages outside the client network

For Windows target:

```powershell
python -m pip download -r requirements.txt -d wheelhouse-win
```

For Kali/Linux target:

```bash
python3 -m pip download -r requirements.txt -d wheelhouse-linux
```

### Install offline dependencies inside the client network

Windows:

```powershell
pip install --no-index --find-links wheelhouse-win -r requirements.txt
```

Kali/Linux:

```bash
pip install --no-index --find-links wheelhouse-linux -r requirements.txt
```

### Recommended server model

```text
Client browsers
    ->
Internal app server
    ->
Internal PostgreSQL / Redis / Nessus
```

Do not run Vite dev mode for end users in production. Use the built frontend and backend-served `/ui` path.

## First Login and Initial Configuration

After the first administrator account is created:

1. Open `http://<server>:8000/ui`
2. Sign in
3. Open `Nessus`
4. Enter:
   - Nessus URL
   - Access Key
   - Secret Key
   - TLS verification preference
   - timeout
   - approved hosts if required
5. Use `Test Connection`
6. Save only after validation succeeds

Then:

1. Open `Folders`
2. Sync Nessus folders
3. Open `Scans`
4. Sync scans and templates
5. Use the wizard to create or clone scans where the Nessus environment supports scan API actions

## Testing

Backend:

```powershell
python -m pytest backend/tests tests
```

Frontend:

```powershell
cd frontend
npm run test -- --run
npm run build
```

Most recent verified results in this workspace:

- `python -m pytest backend/tests tests` -> 75 passed
- `cd frontend && npm run test -- --run` -> 4 passed
- `cd frontend && npm run build` -> passed

## Security Notes

- Nessus API secrets are stored encrypted
- Application credentials and Nessus credentials are separate
- State-changing routes use CSRF validation
- Sensitive actions use server-side authorization checks
- The app is designed for internal deployment, not direct public internet exposure

## Important Notes

- The current primary application entry point is the FastAPI backend, not `app.py`
- Legacy files such as `app.py` and `ip_utils.py` remain in the repository but are not the main runtime path for this build
- This README reflects the active application state on July 30, 2026
