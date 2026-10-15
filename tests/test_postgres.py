"""Runs only when TEST_DATABASE_URL points at a disposable PostgreSQL (CI service container)."""
import os

import pytest
from sqlalchemy import func, select

TEST_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="TEST_DATABASE_URL not set")


def test_init_db_idempotent_and_varchar_limits(monkeypatch):
    from hunter import db
    from hunter.models import Base, Job, SearchProfile
    from hunter.settings import get_settings

    monkeypatch.setenv("DATABASE_URL", TEST_URL)
    monkeypatch.setenv("PROFILES_PATH", "config/search_profiles.yaml")
    get_settings.cache_clear()
    db.engine.cache_clear()
    Base.metadata.drop_all(db.engine())
    db.init_db()
    db.init_db()
    with db.session_scope() as s:
        assert s.scalar(select(func.count()).select_from(SearchProfile)) == 2
        s.add(Job(canonical_key="k", source="lever", source_url="https://x", title="t",
                  company="c", location="", description="d"))
    with db.session_scope() as s:
        assert s.scalar(select(func.count()).select_from(Job)) == 1
    db.engine.cache_clear()
    get_settings.cache_clear()
