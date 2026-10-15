import pytest
from sqlalchemy import func, select

from hunter import orchestrator
from hunter.db import session_scope
from hunter.models import AgentRun, Job, Scan, ScanJob, SearchProfile

JOB = {
    "canonical_key": "k1", "source": "lever", "source_url": "https://jobs.lever.co/x/1",
    "title": "Systems Intern", "company": "x", "location": "Zurich", "description": "Linux",
}


def test_enqueue_unknown_profile(database, fake_redis):
    with pytest.raises(ValueError):
        orchestrator.enqueue_scan(9999)


def test_enqueue_failure_marks_scan_failed(database, monkeypatch):
    def broken():
        raise ConnectionError("redis down")

    monkeypatch.setattr(orchestrator, "redis_connection", broken)
    with pytest.raises(RuntimeError):
        orchestrator.enqueue_scan(1)
    with session_scope() as db:
        scan = db.scalar(select(Scan))
        assert scan.state == "failed"
        assert "ConnectionError" in scan.error


def test_scan_runs_three_isolated_demo_agents(database, agent_workers, monkeypatch):
    monkeypatch.setattr(orchestrator, "fetch_all", lambda sources: ([dict(JOB)], []))
    scan_id = orchestrator.enqueue_scan(1)
    result = orchestrator._run_scan(scan_id)
    assert result["discovered"] == 1
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        assert scan.state == "finished"
        runs = list(db.scalars(select(AgentRun).where(AgentRun.scan_id == scan_id)))
        assert sorted(r.agent for r in runs) == ["claude-1", "claude-2", "codex"]
        assert all(r.state == "finished" and r.output["mode"] == "demo" for r in runs)
        assert db.scalar(select(func.count()).select_from(Job)) == 1


def test_repeated_scans_do_not_duplicate_jobs(database, agent_workers, monkeypatch):
    monkeypatch.setattr(orchestrator, "fetch_all", lambda sources: ([dict(JOB)], []))
    for _ in range(2):
        orchestrator._run_scan(orchestrator.enqueue_scan(1))
    with session_scope() as db:
        assert db.scalar(select(func.count()).select_from(Job)) == 1
        assert db.scalar(select(func.count()).select_from(ScanJob)) == 2
        assert db.scalar(select(ScanJob.decision)) == "unassessed"  # nothing pre-judged


def test_source_errors_make_scan_partial(database, agent_workers, monkeypatch):
    monkeypatch.setattr(orchestrator, "fetch_all", lambda s: ([], ["lever:x: HTTPStatusError"]))
    scan_id = orchestrator.enqueue_scan(1)
    orchestrator._run_scan(scan_id)
    with session_scope() as db:
        assert db.get(Scan, scan_id).state == "partial"


def test_enqueue_all_skips_disabled_profiles(database, fake_redis):
    with session_scope() as db:
        db.get(SearchProfile, 2).enabled = False
    assert len(orchestrator.enqueue_all_profiles()) == 1
