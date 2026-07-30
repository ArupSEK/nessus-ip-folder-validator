from __future__ import annotations

from celery import Celery

from backend.app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "nessus_tracker",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)
