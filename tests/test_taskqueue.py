"""Queue semantics on SQLite and, when TEST_DATABASE_URL is set, real PostgreSQL."""
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from hunter import orchestrator
from hunter.db import session_scope
from hunter.models import AgentRun, Scan, Task
from hunter.taskqueue import LeaseLost, TaskCancelled, TaskQueue


@pytest.fixture
def q(any_db, clock):
    return TaskQueue(clock=clock)


def task_of(scan_id):
    with session_scope() as db:
        t = db.scalar(select(Task).where(Task.scan_id == scan_id))
        db.expunge(t)
        return t


def scan_state(scan_id):
    with session_scope() as db:
        return db.get(Scan, scan_id).state


def test_enqueue_creates_scan_and_task_atomically(q):
    sid = orchestrator.enqueue_scan(1, q)
    t = task_of(sid)
    assert (t.kind, t.state, t.attempts) == ("scan", "queued", 0)
    assert scan_state(sid) == "queued"


def test_enqueue_is_atomic_on_failure(q, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("db hiccup")

    monkeypatch.setattr(q, "enqueue", boom)
    with pytest.raises(RuntimeError):
        orchestrator.enqueue_scan(1, q)
    with session_scope() as db:
        assert db.scalar(select(Scan.id)) is None  # no orphan scan without a task


def test_claim_is_exclusive_and_ordered(q):
    a, b = orchestrator.enqueue_scan(1, q), orchestrator.enqueue_scan(2, q)
    c1, c2, c3 = q.claim(), q.claim(), q.claim()
    assert (c1.scan_id, c2.scan_id, c3) == (a, b, None)
    assert c1.token != c2.token and c1.attempt == 1
    assert scan_state(a) == "running"


def test_one_active_scan_per_profile_is_enforced_by_the_database(q):
    sid = orchestrator.enqueue_scan(1, q)
    assert orchestrator.enqueue_scan(1, q) == sid  # idempotent
    with pytest.raises(IntegrityError):
        with session_scope() as db:  # bypass the application: the index still holds
            db.add(Scan(profile_id=1, state="queued"))


def test_database_rejects_unknown_task_kinds_and_states(q):
    sid = orchestrator.enqueue_scan(1, q)
    for field, value in [("kind", "os.system"), ("state", "pwned"), ("max_attempts", 0)]:
        with pytest.raises(IntegrityError):
            with session_scope() as db:
                setattr(db.scalar(select(Task).where(Task.scan_id == sid)), field, value)


def test_complete_requires_the_lease(q):
    sid = orchestrator.enqueue_scan(1, q)
    claim = q.claim()
    wrong = claim.__class__(**{**claim.__dict__, "token": "f" * 32})
    with pytest.raises(LeaseLost):
        with session_scope() as db:
            q.complete(db, wrong)
    with session_scope() as db:
        q.fence(db, claim)
        q.complete(db, claim)
    assert task_of(sid).state == "completed"
    with pytest.raises(LeaseLost):  # double completion is not possible
        with session_scope() as db:
            q.complete(db, claim)


def test_expired_lease_is_reaped_and_old_worker_is_fenced_out(q, clock):
    sid = orchestrator.enqueue_scan(1, q)
    a = q.claim()
    clock.advance(121)
    assert q.reap() == {"retried": 1, "failed": 0, "expired_in_queue": 0}
    assert task_of(sid).state == "queued" and scan_state(sid) == "queued"
    with pytest.raises(LeaseLost):  # A noticed too late: cannot heartbeat or write
        q.heartbeat(a)
    clock.advance(31 * 1)  # backoff 30s * attempts
    b = q.claim()
    assert b.attempt == 2 and b.token != a.token
    with pytest.raises(LeaseLost):
        with session_scope() as db:
            q.fence(db, a)
            q.complete(db, a)
    with session_scope() as db:
        q.fence(db, b)
        q.complete(db, b)
    assert task_of(sid).state == "completed"


def test_expired_worker_cannot_overwrite_newer_results(q, clock, monkeypatch, agent_fleet):
    """Fencing end to end: worker A stalls past its lease; B finishes; A's write is refused."""
    sid = orchestrator.enqueue_scan(1, q)
    a = q.claim()
    original = orchestrator.run_agents
    calls = {"n": 0}

    def stalled(filters, client_factory=None):
        calls["n"] += 1
        if calls["n"] == 1:
            clock.advance(200)           # A stalls past its lease...
            q.reap()
            clock.advance(31)
            b = q.claim()                # ...B takes over and completes the scan
            orchestrator.execute_scan(q, b)
            return [{"agent": "claude-1", "state": "failed", "output": {"error": "STALE"}}]
        return original(filters, client_factory)

    monkeypatch.setattr(orchestrator, "run_agents", stalled)
    orchestrator.process_claim(q, a)     # A resumes: must lose the lease, write nothing
    with session_scope() as db:
        runs = list(db.scalars(select(AgentRun).where(AgentRun.scan_id == sid)))
        assert len(runs) == 3 and all(r.output.get("error") != "STALE" for r in runs)
        assert db.get(Scan, sid).state == "finished"


def test_retries_are_bounded_then_scan_fails(q, clock, monkeypatch):
    sid = orchestrator.enqueue_scan(1, q)

    def crash(*a, **k):
        raise KeyError("boom")

    monkeypatch.setattr(orchestrator, "run_agents", crash)
    for attempt in (1, 2, 3):
        clock.advance(31 * attempt)
        claim = q.claim()
        assert claim is not None and claim.attempt == attempt
        orchestrator.process_claim(q, claim)
    t = task_of(sid)
    assert (t.state, t.attempts, t.last_error) == ("failed", 3, "KeyError")
    assert scan_state(sid) == "failed"
    clock.advance(10_000)
    assert q.claim() is None
    # the profile is free again
    assert orchestrator.enqueue_scan(1, q) != sid


def test_cancel_queued_and_running(q):
    s1 = orchestrator.enqueue_scan(1, q)
    assert q.cancel(s1) == "cancelled"
    assert (task_of(s1).state, scan_state(s1)) == ("cancelled", "cancelled")
    s2 = orchestrator.enqueue_scan(1, q)
    claim = q.claim()
    assert q.cancel(s2) == "cancel_requested"
    with pytest.raises(TaskCancelled):
        with session_scope() as db:
            q.fence(db, claim)
    orchestrator.process_claim(q, claim)  # honours the request
    assert (task_of(s2).state, scan_state(s2)) == ("cancelled", "cancelled")
    assert q.cancel(s2) == "noop"


def test_queued_task_nobody_picks_up_expires(q, clock):
    sid = orchestrator.enqueue_scan(1, q)
    clock.advance(3601)
    assert q.reap()["expired_in_queue"] == 1
    assert scan_state(sid) == "failed" and q.claim() is None


def test_forged_rows_cannot_execute_anything(q, monkeypatch):
    """No payload, no function name: whatever is written to a task row, the only code a
    worker can run is the fixed scan handler."""
    sid = orchestrator.enqueue_scan(1, q)
    assert not any(c.name in {"payload", "func", "func_name", "args", "callback"}
                   for c in Task.__table__.columns)
    seen = []
    monkeypatch.setattr(orchestrator, "execute_scan",
                        lambda queue, claim, **k: seen.append(claim.kind))
    orchestrator.process_claim(q, q.claim())
    assert seen == ["scan"] and task_of(sid).scan_id == sid
