from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

import yaml
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

from hunter.models import SearchProfile
from hunter.settings import get_settings

BASELINE_REVISION = "0001"


@lru_cache
def engine():
    return create_engine(get_settings().database_url, pool_pre_ping=True)


@contextmanager
def session_scope():
    db = Session(engine())
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _alembic_config(connection) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    cfg.attributes["connection"] = connection
    return cfg


class SchemaMismatch(RuntimeError):
    """The database revision is not one this release can run against. Never ignored."""


def _script(cfg: Config) -> ScriptDirectory:
    return ScriptDirectory.from_config(cfg)


def code_head() -> str:
    with engine().connect() as connection:
        return _script(_alembic_config(connection)).get_current_head()


def schema_state() -> tuple[str, str | None, str]:
    """Returns (status, db_revision, code_head).

    status: ``ok`` (db == head), ``accepted`` (db is newer but explicitly accepted via
    HUNTER_ACCEPT_SCHEMA_REVISION by a verified rollback), ``behind`` (migrations pending),
    ``unknown`` (db revision this release has never heard of, not accepted),
    ``empty`` (no schema yet).
    """
    with engine().connect() as connection:
        script = _script(_alembic_config(connection))
        head = script.get_current_head()
        db_rev = MigrationContext.configure(connection).get_current_revision()
        known = {r.revision for r in script.walk_revisions()}
    if db_rev is None:
        return "empty", None, head
    if db_rev == head:
        return "ok", db_rev, head
    if db_rev in known:
        return "behind", db_rev, head
    if db_rev == get_settings().hunter_accept_schema_revision:
        return "accepted", db_rev, head
    return "unknown", db_rev, head


def run_migrations(revision: str = "head") -> None:
    """Upgrades the schema, or fails loudly.

    Unknown (newer) revisions are an error unless the deploy tooling has verified rollback
    compatibility and passed that exact revision in HUNTER_ACCEPT_SCHEMA_REVISION.
    """
    status, db_rev, head = schema_state()
    if status == "unknown":
        raise SchemaMismatch(
            f"database is at revision {db_rev!r}, which this release ({head!r}) does not "
            "know. Refusing to continue. If this is a verified rollback, the deploy tooling "
            "sets HUNTER_ACCEPT_SCHEMA_REVISION; otherwise see docs/backup-restore.md."
        )
    if status == "accepted":
        print(f"schema {db_rev!r} is newer than this release's head {head!r} but explicitly "
              "accepted; not migrating", flush=True)
        return
    with engine().begin() as connection:
        cfg = _alembic_config(connection)
        tables = set(inspect(connection).get_table_names())
        if "search_profiles" in tables and "alembic_version" not in tables:
            command.stamp(cfg, BASELINE_REVISION)
        command.upgrade(cfg, revision)


def seed_profiles() -> None:
    """Config is the source of truth for definition; ``enabled`` is operator state in the DB."""
    path = Path(get_settings().profiles_path)
    if not path.exists():
        raise FileNotFoundError(f"Missing search profiles: {path}")
    entries = yaml.safe_load(path.read_text(encoding="utf-8"))["profiles"]
    with session_scope() as session:
        for entry in entries:
            row = session.scalar(select(SearchProfile).where(SearchProfile.slug == entry["slug"]))
            if row is None:
                session.add(SearchProfile(
                    slug=entry["slug"], name=entry["name"], kind=entry["kind"],
                    enabled=entry["enabled"], filters=entry,
                ))
            else:
                row.name, row.kind, row.filters = entry["name"], entry["kind"], entry


def init_db() -> None:
    run_migrations()
    if schema_state()[0] == "accepted":
        return  # rollback on a newer schema: never write profile data through an old model
    seed_profiles()


if __name__ == "__main__":
    init_db()
