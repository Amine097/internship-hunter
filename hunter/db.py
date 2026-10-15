from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

import yaml
from alembic import command
from alembic.config import Config
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


def run_migrations(revision: str = "head") -> None:
    """Upgrades the schema. Databases created by the pre-Alembic bootstrap are stamped first."""
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
    seed_profiles()


if __name__ == "__main__":
    init_db()
