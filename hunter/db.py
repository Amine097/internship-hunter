from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

import yaml
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from hunter.models import Base, SearchProfile
from hunter.settings import get_settings


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


def init_db() -> None:
    Base.metadata.create_all(bind=engine())
    path = Path(get_settings().profiles_path)
    if not path.exists():
        raise FileNotFoundError(f"Missing search profiles: {path}")
    entries = yaml.safe_load(path.read_text(encoding="utf-8"))["profiles"]
    with session_scope() as session:
        for entry in entries:
            if session.scalar(select(SearchProfile).where(SearchProfile.slug == entry["slug"])):
                continue  # Changes to active profiles should be made through future config editor.
            session.add(SearchProfile(
                slug=entry["slug"], name=entry["name"], kind=entry["kind"],
                enabled=entry["enabled"], filters=entry,
            ))


if __name__ == "__main__":
    init_db()
