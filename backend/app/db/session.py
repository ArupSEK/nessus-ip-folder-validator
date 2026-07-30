from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.config import get_settings

_engine = None
_session_factory = None


def init_engine(database_url: str | None = None) -> None:
    global _engine, _session_factory
    settings = get_settings()
    url = database_url or settings.database_url
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    _engine = create_engine(url, future=True, connect_args=connect_args)
    _session_factory = sessionmaker(bind=_engine, autoflush=False, autocommit=False, future=True)


def get_engine():
    global _engine
    if _engine is None:
        init_engine()
    return _engine


def get_session_factory():
    global _session_factory
    if _session_factory is None:
        init_engine()
    return _session_factory


def get_db():
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def reset_engine() -> None:
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None
