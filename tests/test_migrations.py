import os

import pytest
import yaml
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect, select, text

from hunter import db as db_module
from hunter.models import Base, SearchProfile
from hunter.settings import get_settings

PG_URL = os.environ.get("TEST_DATABASE_URL")
URLS = ["sqlite"] + (["postgres"] if PG_URL else [])


@pytest.fixture(params=URLS)
def fresh_db(request, tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'm.db'}" if request.param == "sqlite" else PG_URL
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("PROFILES_PATH", "config/search_profiles.yaml")
    get_settings.cache_clear()
    db_module.engine.cache_clear()
    with db_module.engine().begin() as c:
        if request.param == "postgres":
            c.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
    yield db_module.engine()
    db_module.engine.cache_clear()
    get_settings.cache_clear()


def test_upgrade_from_empty_matches_models(fresh_db):
    db_module.run_migrations()
    with fresh_db.connect() as c:
        diff = compare_metadata(MigrationContext.configure(c), Base.metadata)
    assert diff == [], f"models and migrations drifted: {diff}"


def test_upgrade_is_idempotent_and_downgrade_roundtrips(fresh_db):
    from alembic import command
    db_module.run_migrations()
    db_module.run_migrations()
    with fresh_db.begin() as c:
        cfg = db_module._alembic_config(c)
        command.downgrade(cfg, "base")
        assert inspect(c).get_table_names() == ["alembic_version"]
        command.upgrade(cfg, "head")
        assert "scans" in inspect(c).get_table_names()


def test_legacy_create_all_database_is_stamped_then_upgraded(fresh_db):
    """A DB made by the pre-Alembic bootstrap (create_all, no index) must upgrade cleanly."""
    Base.metadata.create_all(fresh_db)
    with fresh_db.begin() as c:
        c.execute(text("DROP INDEX uq_scans_one_active_per_profile"))
        c.execute(text("INSERT INTO search_profiles (slug,name,kind,enabled,filters) "
                       "VALUES ('legacy','Legacy','internship',1,'{}')"
                       if fresh_db.dialect.name == "sqlite" else
                       "INSERT INTO search_profiles (slug,name,kind,enabled,filters) "
                       "VALUES ('legacy','Legacy','internship',true,'{}')"))
    db_module.run_migrations()
    with fresh_db.connect() as c:
        assert c.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0002"
        assert c.execute(text("SELECT count(*) FROM search_profiles")).scalar() == 1  # data kept
        names = {i["name"] for i in inspect(c).get_indexes("scans")}
        assert "uq_scans_one_active_per_profile" in names


def test_seed_updates_definition_but_keeps_operator_enabled_flag(fresh_db):
    db_module.init_db()
    with db_module.session_scope() as s:
        row = s.scalar(select(SearchProfile).where(SearchProfile.slug == "part-time-europe"))
        row.enabled = False
        row.name = "stale name"
    db_module.init_db()
    with db_module.session_scope() as s:
        row = s.scalar(select(SearchProfile).where(SearchProfile.slug == "part-time-europe"))
        assert row.enabled is False and row.name != "stale name"
        assert row.filters["earliest_start"] == "2026-10-14"


def test_profiles_file_matches_expected_windows():
    data = yaml.safe_load(open("config/search_profiles.yaml"))["profiles"]
    by_slug = {p["slug"]: p for p in data}
    assert by_slug["internship-summer-2027"]["earliest_start"] == "2027-07-01"
    assert by_slug["internship-summer-2027"]["latest_start"] == "2027-08-01"
    assert by_slug["part-time-europe"]["earliest_start"] == "2026-10-14"
