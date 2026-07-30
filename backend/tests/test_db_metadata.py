from __future__ import annotations

from backend.app.db.base import Base


def test_metadata_available() -> None:
    assert Base.metadata is not None
