import os
import pathlib
import socket
import threading
import time

import pytest
import uvicorn

from hunter import db as db_module
from hunter import orchestrator
from hunter.agent_runner import create_app
from hunter.settings import get_settings
from hunter.taskqueue import TaskQueue

ROOT = pathlib.Path(__file__).resolve().parents[1]
AGENT_NAMES = ("claude-1", "claude-2", "codex")
TOKENS = {name: (name.replace("-", "") + "-token-").ljust(40, "x") for name in AGENT_NAMES}


@pytest.fixture
def database(tmp_path, monkeypatch):
    """Fresh, migrated, seeded SQLite database (PostgreSQL: tests/test_postgres.py)."""
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


class FakeClock:
    """Injectable clock so lease expiry can be tested deterministically."""

    def __init__(self):
        from datetime import datetime, timezone
        self.t = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.t

    def advance(self, seconds: float):
        from datetime import timedelta
        self.t += timedelta(seconds=seconds)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def run_tasks():
    """Drains the queue in this thread: claim -> process, like one worker in burst mode."""
    def go(queue: TaskQueue | None = None, **kw) -> int:
        queue = queue or TaskQueue()
        done = 0
        while (claim := queue.claim()) is not None:
            orchestrator.process_claim(queue, claim, **kw)
            done += 1
        return done
    return go


class _Server(uvicorn.Server):
    def install_signal_handlers(self):  # not the main thread
        pass


def _bound_socket() -> socket.socket:
    """Bind in the test thread (no free-port race) and hand the socket to uvicorn."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)
    return sock


@pytest.fixture
def agent_fleet(monkeypatch):
    """Three real HTTP agent runners (demo planners) on loopback, wired into settings.

    Returns {name: (app_factory_args, server)}; tests may swap planners via ``planners``.
    """
    planners: dict = {}
    servers, threads = [], []
    for name in AGENT_NAMES:
        from hunter.agents import run_plan

        def planner(agent, profile, _n=name):
            return planners.get(_n, run_plan)(agent, profile)

        sock = _bound_socket()
        port = sock.getsockname()[1]
        app = create_app(name, TOKENS[name], planner=planner)
        server = _Server(uvicorn.Config(app, log_level="warning"))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        servers.append(server)
        threads.append(thread)
        key = name.replace("-", "_")
        monkeypatch.setenv(f"AGENT_URL_{key.upper()}", f"http://127.0.0.1:{port}")
        monkeypatch.setenv(f"AGENT_TOKEN_{key.upper()}", TOKENS[name])
    get_settings.cache_clear()
    deadline = time.monotonic() + 10
    while not all(s.started for s in servers) and time.monotonic() < deadline:
        time.sleep(0.02)
    yield planners
    for s in servers:
        s.should_exit = True
    for t in threads:
        t.join(timeout=5)
    get_settings.cache_clear()


def pytest_sessionstart(session):
    """In CI the service-backed tests must run; a silent skip would hide a broken service."""
    if os.environ.get("CI_REQUIRE_SERVICES") and not os.environ.get("TEST_DATABASE_URL"):
        raise pytest.UsageError("CI_REQUIRE_SERVICES is set but TEST_DATABASE_URL is missing")


def _prepare_db(kind, tmp_path, monkeypatch):
    from sqlalchemy import text
    url = f"sqlite:///{tmp_path / 'q.db'}" if kind == "sqlite" else os.environ["TEST_DATABASE_URL"]
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("PROFILES_PATH", str(ROOT / "config/search_profiles.yaml"))
    monkeypatch.setenv("SOURCES_PATH", str(tmp_path / "sources.yaml"))
    monkeypatch.setenv("ADMIN_TOKEN", "t" * 40)
    (tmp_path / "sources.yaml").write_text("sources: []\n")
    get_settings.cache_clear()
    db_module.engine.cache_clear()
    if kind == "postgres":
        with db_module.engine().begin() as c:
            c.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
    db_module.init_db()


@pytest.fixture(params=["sqlite"] + (["postgres"] if os.environ.get("TEST_DATABASE_URL") else []))
def any_db(request, tmp_path, monkeypatch):
    """Migrated + seeded database on SQLite and (when configured) real PostgreSQL."""
    _prepare_db(request.param, tmp_path, monkeypatch)
    yield request.param
    db_module.engine.cache_clear()
    get_settings.cache_clear()


@pytest.fixture
def pg_db(tmp_path, monkeypatch):
    """Real PostgreSQL only; the module-level skipif covers a missing TEST_DATABASE_URL."""
    _prepare_db("postgres", tmp_path, monkeypatch)
    yield "postgres"
    db_module.engine.cache_clear()
    get_settings.cache_clear()
