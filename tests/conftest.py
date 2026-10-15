import pathlib
import threading

import fakeredis
import pytest
from rq import Queue, SimpleWorker
from rq.timeouts import TimerDeathPenalty

from hunter import db as db_module
from hunter import orchestrator
from hunter.settings import get_settings

ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture
def database(tmp_path, monkeypatch):
    """Fresh, seeded SQLite database (PostgreSQL is covered by tests/test_postgres.py)."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("PROFILES_PATH", str(ROOT / "config/search_profiles.yaml"))
    monkeypatch.setenv("SOURCES_PATH", str(tmp_path / "sources.yaml"))
    monkeypatch.setenv("ADMIN_TOKEN", "t" * 40)
    monkeypatch.setenv("AGENT_MODE", "demo")
    (tmp_path / "sources.yaml").write_text("sources: []\n")
    get_settings.cache_clear()
    db_module.engine.cache_clear()
    db_module.init_db()
    yield
    db_module.engine.cache_clear()
    get_settings.cache_clear()


@pytest.fixture
def fake_redis(monkeypatch):
    server = fakeredis.FakeServer()

    def connect():
        return fakeredis.FakeStrictRedis(server=server)

    monkeypatch.setattr(orchestrator, "redis_connection", connect)
    return connect


@pytest.fixture
def agent_workers(fake_redis):
    """One in-process worker per agent queue, standing in for the three isolated containers."""
    stop = threading.Event()

    def serve(queue_name):
        conn = fake_redis()
        worker = SimpleWorker([Queue(queue_name, connection=conn)], connection=conn)
        worker.death_penalty_class = TimerDeathPenalty
        worker._install_signal_handlers = lambda: None  # not the main thread
        while not stop.is_set():
            worker.work(burst=True, with_scheduler=False)
            stop.wait(0.05)

    threads = [
        threading.Thread(target=serve, args=(name,), daemon=True)
        for name in ("claude-1", "claude-2", "codex")
    ]
    for t in threads:
        t.start()
    yield
    stop.set()
    for t in threads:
        t.join(timeout=5)
