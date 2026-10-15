from sqlalchemy import func, select

from hunter.db import engine, init_db, session_scope
from hunter.models import SearchProfile
from hunter.settings import get_settings


def test_bootstrap_seeds_two_profiles_without_duplicates(tmp_path, monkeypatch):
    root = __import__("pathlib").Path(__file__).resolve().parents[1]
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("PROFILES_PATH", str(root / "config/search_profiles.yaml"))
    get_settings.cache_clear()
    engine.cache_clear()
    try:
        init_db()
        init_db()
        with session_scope() as db:
            assert db.scalar(select(func.count()).select_from(SearchProfile)) == 2
            internships = db.scalar(select(SearchProfile).where(
                SearchProfile.slug == "internship-summer-2027"
            ))
            assert internships.filters["min_duration_months"] == 2
            assert internships.filters["max_duration_months"] == 3
            assert internships.filters["earliest_start"] == "2027-07-01"
    finally:
        engine.cache_clear()
        get_settings.cache_clear()
