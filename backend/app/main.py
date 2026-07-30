from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.app.api.routes.auth import router as auth_router
from backend.app.api.routes.audit import router as audit_router
from backend.app.api.routes.comparison import router as comparison_router
from backend.app.api.routes.dashboard import router as dashboard_router
from backend.app.api.routes.folders import router as folders_router
from backend.app.api.routes.health import router as health_router
from backend.app.api.routes.imports import router as imports_router
from backend.app.api.routes.ip_search import router as ip_search_router
from backend.app.api.routes.nessus import router as nessus_router
from backend.app.api.routes.reports import router as reports_router
from backend.app.api.routes.scans import router as scans_router
from backend.app.api.routes.workflow import router as workflow_router
from backend.app.core.config import get_settings
from backend.app.core.logging import configure_logging


def _frontend_dist_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "frontend" / "dist"


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    app = FastAPI(
        title=settings.app_name,
        version="0.2.0",
    )
    app.include_router(health_router)
    app.include_router(auth_router, prefix="/api/v1/auth")
    app.include_router(audit_router, prefix="/api/v1/audit")
    app.include_router(comparison_router, prefix="/api/v1/comparisons")
    app.include_router(dashboard_router, prefix="/api/v1/dashboard")
    app.include_router(nessus_router, prefix="/api/v1/nessus")
    app.include_router(folders_router, prefix="/api/v1/folders")
    app.include_router(reports_router, prefix="/api/v1/reports")
    app.include_router(scans_router, prefix="/api/v1/scans")
    app.include_router(workflow_router, prefix="/api/v1/workflows")
    app.include_router(ip_search_router, prefix="/api/v1/ip-search")
    app.include_router(imports_router, prefix="/api/v1/imports")

    dist_dir = _frontend_dist_dir()
    assets_dir = dist_dir / "assets"
    index_file = dist_dir / "index.html"
    if assets_dir.exists():
        app.mount("/ui/assets", StaticFiles(directory=assets_dir), name="ui-assets")
    if index_file.exists():

        @app.get("/ui", include_in_schema=False)
        @app.get("/ui/{path:path}", include_in_schema=False)
        def serve_ui(path: str = "") -> FileResponse:
            requested = (dist_dir / path).resolve() if path else index_file
            if path and requested.exists() and requested.is_file() and dist_dir in requested.parents:
                return FileResponse(requested)
            return FileResponse(index_file)

    return app


app = create_app()
