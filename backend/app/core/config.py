from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = Field(default="Nessus Global IP Search and Vulnerability Lifecycle Tracker", alias="APP_NAME")
    app_env: str = Field(default="development", alias="APP_ENV")
    app_debug: bool = Field(default=True, alias="APP_DEBUG")
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")
    log_level: str = "INFO"
    database_url: str = Field(
        default="postgresql+psycopg://postgres:postgres@localhost:5432/nessus_tracker",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    celery_broker_url: str = Field(default="redis://localhost:6379/1", alias="CELERY_BROKER_URL")
    celery_result_backend: str = Field(default="redis://localhost:6379/2", alias="CELERY_RESULT_BACKEND")
    secret_key: str = Field(default="replace-me", alias="SECRET_KEY")
    session_cookie_name: str = Field(default="ngis_session", alias="SESSION_COOKIE_NAME")
    csrf_cookie_name: str = Field(default="ngis_csrf", alias="CSRF_COOKIE_NAME")
    session_cookie_secure: bool = Field(default=False, alias="SESSION_COOKIE_SECURE")
    session_cookie_samesite: str = Field(default="lax", alias="SESSION_COOKIE_SAMESITE")
    session_timeout_minutes: int = Field(default=60, alias="SESSION_TIMEOUT_MINUTES")
    login_max_attempts: int = Field(default=5, alias="LOGIN_MAX_ATTEMPTS")
    lockout_minutes: int = Field(default=30, alias="LOCKOUT_MINUTES")
    password_reset_token_minutes: int = Field(default=60, alias="PASSWORD_RESET_TOKEN_MINUTES")
    nessus_master_key: str = Field(default="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", alias="NESSUS_MASTER_KEY")
    nessus_default_timeout_seconds: int = Field(default=15, alias="NESSUS_DEFAULT_TIMEOUT_SECONDS")
    nessus_reauth_window_minutes: int = Field(default=15, alias="NESSUS_REAUTH_WINDOW_MINUTES")
    timezone: str = Field(default="UTC", alias="TIMEZONE")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
