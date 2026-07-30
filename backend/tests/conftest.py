from __future__ import annotations

import os
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from backend.app.core.config import get_settings
from backend.app.db.base import Base
from backend.app.db.session import get_engine, get_session_factory, reset_engine
from backend.app.main import create_app
from backend.app.services.auth import create_user, seed_authorization_data


@pytest.fixture()
def db_file(tmp_path: Path) -> Path:
    return tmp_path / "test_auth.db"


@pytest.fixture()
def setup_database(db_file: Path):
    os.environ["DATABASE_URL"] = f"sqlite:///{db_file.as_posix()}"
    os.environ["APP_DEBUG"] = "true"
    os.environ["NESSUS_MASTER_KEY"] = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    get_settings.cache_clear()
    reset_engine()
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    session = get_session_factory()()
    try:
        seed_authorization_data(session)
        session.commit()
    finally:
        session.close()
    yield
    reset_engine()
    get_settings.cache_clear()
    os.environ.pop("DATABASE_URL", None)
    os.environ.pop("APP_DEBUG", None)
    os.environ.pop("NESSUS_MASTER_KEY", None)


@pytest.fixture()
def app(setup_database):
    return create_app()


@pytest.fixture()
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as test_client:
        yield test_client


@pytest.fixture()
def db_session(setup_database):
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def admin_user(db_session):
    user = create_user(
        db_session,
        username="admin",
        password="StrongPass123!",
        role_names=["Administrator"],
        is_superuser=True,
    )
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture()
def readonly_user(db_session):
    user = create_user(
        db_session,
        username="viewer",
        password="StrongPass123!",
        role_names=["Read-only User"],
        is_superuser=False,
    )
    db_session.commit()
    db_session.refresh(user)
    return user
