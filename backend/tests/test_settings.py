from __future__ import annotations

from backend.app.core.config import Settings


def test_settings_defaults() -> None:
    settings = Settings()
    assert settings.app_name
    assert settings.database_url.startswith("postgresql+psycopg://")
    assert settings.redis_url.startswith("redis://")
