import os
import pathlib
import socket
import threading
import time

import fakeredis
import pytest
import uvicorn
from rq import SimpleWorker
from rq.timeouts import TimerDeathPenalty

from hunter import db as db_module
from hunter import queueing
from hunter.agent_runner import create_app
from hunter.settings import get_settings

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


@pytest.fixture
def fake_redis(monkeypatch):
    server = fakeredis.FakeServer()

    def connect():
        return fakeredis.FakeStrictRedis(server=server)

    monkeypatch.setattr(queueing, "redis_connection", connect)
    return connect


def _drain(connection, worker_class=SimpleWorker):
    """Runs the hardened worker until the queue is empty (in this thread)."""
    worker = queueing.make_worker(connection, worker_class=worker_class)
    worker.death_penalty_class = TimerDeathPenalty
    worker.work(burst=True, with_scheduler=False)


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


@pytest.fixture
def real_redis_url():
    url = os.environ.get("TEST_REDIS_URL")
    if not url:
        pytest.skip("TEST_REDIS_URL not set")
    return url


@pytest.fixture
def drain():
    return _drain


def pytest_sessionstart(session):
    """In CI the service-backed tests must run; a silent skip would hide a broken service."""
    if os.environ.get("CI_REQUIRE_SERVICES") and not (
        os.environ.get("TEST_DATABASE_URL") and os.environ.get("TEST_REDIS_URL")
    ):
        raise pytest.UsageError(
            "CI_REQUIRE_SERVICES is set but TEST_DATABASE_URL/TEST_REDIS_URL are missing")
