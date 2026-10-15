"""Runs only when TEST_DATABASE_URL points at a disposable PostgreSQL (CI service / local)."""
import os
import threading

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

TEST_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="TEST_DATABASE_URL not set")


@pytest.fixture
def pg(monkeypatch):
    from hunter import db
    from hunter.settings import get_settings

    monkeypatch.setenv("DATABASE_URL", TEST_URL)
    monkeypatch.setenv("PROFILES_PATH", "config/search_profiles.yaml")
    get_settings.cache_clear()
    db.engine.cache_clear()
    with db.engine().begin() as c:
        c.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
    db.init_db()
    yield db
    db.engine.cache_clear()
    get_settings.cache_clear()


def test_init_idempotent_and_seeded(pg):
    from hunter.models import SearchProfile
    pg.init_db()
    with pg.session_scope() as s:
        assert s.scalar(select(func.count()).select_from(SearchProfile)) == 2


def test_varchar_limits_are_enforced_so_clipping_matters(pg):
    from hunter.models import Job
    with pytest.raises(Exception):
        with pg.session_scope() as s:
            s.add(Job(canonical_key="k", source="lever", source_url="https://x",
                      title="t" * 400, company="c", location="", description=""))


def test_one_active_scan_per_profile_is_a_database_guarantee(pg):
    from hunter.models import Scan
    with pg.session_scope() as s:
        s.add(Scan(profile_id=1, state="queued"))
    with pytest.raises(IntegrityError):
        with pg.session_scope() as s:
            s.add(Scan(profile_id=1, state="running"))
    with pg.session_scope() as s:  # finished scans are not constrained
        s.add(Scan(profile_id=1, state="finished"))
        s.add(Scan(profile_id=1, state="finished"))


def test_concurrent_enqueue_race_on_real_postgres(pg, monkeypatch):
    import fakeredis

    from hunter import orchestrator, queueing
    server = fakeredis.FakeServer()
    monkeypatch.setattr(queueing, "redis_connection",
                        lambda: fakeredis.FakeStrictRedis(server=server))
    ids, errors = [], []

    def go():
        try:
            ids.append(orchestrator.enqueue_scan(1))
        except Exception as exc:
            errors.append(repr(exc))

    threads = [threading.Thread(target=go) for _ in range(12)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors, errors
    assert len(set(ids)) == 1


def test_concurrent_job_insert_race(pg):
    from hunter import orchestrator
    from hunter.models import Job, Scan
    with pg.session_scope() as s:
        s.add(Scan(profile_id=1, state="running"))
        s.flush()
        scan_id = s.scalar(select(Scan.id))
    data = {"canonical_key": "same", "source": "lever", "source_url": "https://x/1",
            "title": "T", "company": "c", "location": "", "description": ""}
    errors = []

    def go():
        try:
            orchestrator._store_jobs(scan_id, [dict(data)])
        except Exception as exc:
            errors.append(repr(exc))

    threads = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors, errors
    with pg.session_scope() as s:
        assert s.scalar(select(func.count()).select_from(Job)) == 1
