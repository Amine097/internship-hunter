import threading

import httpx
import pytest
from sqlalchemy import func, select

from hunter import orchestrator
from hunter.db import session_scope
from hunter.models import AgentRun, Job, Scan, ScanJob, SearchProfile

LEVER = [{"id": "aa", "text": "Systems Intern", "hostedUrl": "https://jobs.lever.co/x/aa",
          "categories": {"location": "Zurich"}, "descriptionPlain": "Linux"}]


@pytest.fixture
def sources(tmp_path, monkeypatch):
    """A real sources.yaml; HTTP to the ATS goes through a MockTransport (not fake jobs in DB)."""
    (tmp_path / "sources.yaml").write_text(
        "sources:\n  - kind: lever\n    token: acme\n")
    monkeypatch.setattr(
        orchestrator, "fetch_all",
        lambda srcs, deadline=None, transport=None, _orig=orchestrator.fetch_all: _orig(
            srcs, deadline, httpx.MockTransport(lambda r: httpx.Response(200, json=LEVER))),
    )


def run_one(run_tasks, profile_id=1):
    scan_id = orchestrator.enqueue_scan(profile_id)
    assert run_tasks() == 1
    return scan_id


def test_enqueue_unknown_profile(database):
    with pytest.raises(ValueError):
        orchestrator.enqueue_scan(9999)


def test_full_scan_through_queue_and_http_agents(database, agent_fleet, sources, run_tasks):
    scan_id = run_one(run_tasks)
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        assert scan.state == "finished" and scan.discovered == 1
        runs = list(db.scalars(select(AgentRun).where(AgentRun.scan_id == scan_id)))
        assert sorted(r.agent for r in runs) == ["claude-1", "claude-2", "codex"]
        assert all(r.state == "finished" and r.output["mode"] == "demo" for r in runs)
        assert db.scalar(select(ScanJob.decision)) == "unassessed"  # nothing pre-judged


def test_repeated_scans_do_not_duplicate_jobs(database, agent_fleet, sources, run_tasks):
    for _ in range(2):
        run_one(run_tasks)
    with session_scope() as db:
        assert db.scalar(select(func.count()).select_from(Job)) == 1
        assert db.scalar(select(func.count()).select_from(ScanJob)) == 2


def test_failed_agent_makes_scan_partial(database, agent_fleet, run_tasks):
    def broken(agent, profile):
        raise RuntimeError("cli exploded: secret-from-stderr")

    agent_fleet["claude-2"] = broken
    scan_id = run_one(run_tasks)
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        assert scan.state == "partial"
        bad = db.scalar(select(AgentRun).where(AgentRun.agent == "claude-2"))
        assert bad.state == "failed"
        assert "secret" not in str(bad.output)  # CLI output never reaches the DB
        good = db.scalars(select(AgentRun).where(AgentRun.state == "finished")).all()
        assert len(good) == 2


def test_agent_answering_as_another_identity_is_rejected(database, agent_fleet, run_tasks):
    agent_fleet["codex"] = lambda a, p: {"agent": "claude-1", "mode": "cli", "queries": ["x"]}
    scan_id = run_one(run_tasks)
    with session_scope() as db:
        run = db.scalar(select(AgentRun).where(
            AgentRun.scan_id == scan_id, AgentRun.agent == "codex"))
        assert run.state == "failed"


def test_agent_timeout_is_recorded_without_orphan_jobs(database, agent_fleet, run_tasks,
                                                       monkeypatch):
    release = threading.Event()

    def hang(agent, profile):
        release.wait(10)
        return {"agent": agent, "mode": "demo", "queries": []}

    monkeypatch.setattr(orchestrator, "AGENT_TIMEOUT_S", 1)
    agent_fleet["codex"] = hang
    try:
        scan_id = run_one(run_tasks)
    finally:
        release.set()
    with session_scope() as db:
        assert db.get(Scan, scan_id).state == "partial"
        run = db.scalar(select(AgentRun).where(AgentRun.agent == "codex"))
        assert run.state == "failed"


def test_unconfigured_token_fails_closed(database, monkeypatch, run_tasks):
    for name in ("CLAUDE_1", "CLAUDE_2", "CODEX"):
        monkeypatch.setenv(f"AGENT_TOKEN_{name}", "")
    from hunter.settings import get_settings
    get_settings.cache_clear()
    scan_id = run_one(run_tasks)
    with session_scope() as db:
        assert db.get(Scan, scan_id).state == "partial"
        assert {r.state for r in db.scalars(select(AgentRun))} == {"failed"}


def test_active_scan_is_reused_not_duplicated(database):
    first = orchestrator.enqueue_scan(1)
    assert orchestrator.enqueue_scan(1) == first
    with session_scope() as db:
        assert db.scalar(select(func.count()).select_from(Scan)) == 1


def test_concurrent_enqueue_creates_single_active_scan(database):
    ids, errors = [], []

    def go():
        try:
            ids.append(orchestrator.enqueue_scan(1))
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=go) for _ in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors and len(set(ids)) == 1






def test_enqueue_all_reports_partial_failure(database):
    with session_scope() as db:
        db.get(SearchProfile, 2).enabled = False
    queued, errors = orchestrator.enqueue_all_profiles()
    assert len(queued) == 1 and errors == []


def test_oversized_agent_response_is_rejected(database, monkeypatch):
    big = b'{"agent":"codex","mode":"demo","queries":[],"note":"' + b"a" * 40_000 + b'"}'
    transport = httpx.MockTransport(lambda r: httpx.Response(200, content=big))
    monkeypatch.setenv("AGENT_TOKEN_CODEX", "z" * 32)
    from hunter.settings import get_settings
    get_settings.cache_clear()
    client = httpx.Client(transport=transport)
    with pytest.raises(ValueError, match="too large"):
        orchestrator.call_agent("codex", {"kind": "internship"}, client)


def test_two_workers_cannot_run_the_same_scan(database, agent_fleet, run_tasks):
    from hunter.taskqueue import TaskQueue
    q = TaskQueue()
    orchestrator.enqueue_scan(1, q)
    first, second = q.claim(), q.claim()
    assert first is not None and second is None
    assert run_tasks() == 0  # nothing claimable while the first lease is live
