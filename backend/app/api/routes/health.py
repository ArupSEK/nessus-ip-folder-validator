from __future__ import annotations

from fastapi import APIRouter

from backend.app.core.config import get_settings

router = APIRouter(tags=["health"])


@router.get("/health/live")
def liveness() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready")
def readiness() -> dict[str, str]:
    settings = get_settings()
    return {
        "status": "ready",
        "environment": settings.app_env,
        "database_url_configured": "yes" if settings.database_url else "no",
        "redis_url_configured": "yes" if settings.redis_url else "no",
    }
