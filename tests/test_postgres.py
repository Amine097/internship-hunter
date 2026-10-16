"""Real-PostgreSQL tests: true concurrency, SKIP LOCKED, and crash recovery with SIGKILL.

Run when TEST_DATABASE_URL points at a disposable database (CI service / local container).
"""
import os
import subprocess
import sys
import textwrap
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from hunter import orchestrator
from hunter.db import session_scope
from hunter.models import Job, Scan, SearchProfile, Task
from hunter.taskqueue import Heartbeater, LeaseLost, TaskQueue

TEST_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="TEST_DATABASE_URL not set")


def make_tasks(n: int, q: TaskQueue) -> list[int]:
    """n independent queued scans (each on its own profile: one active scan per profile)."""
    ids = []
    with session_scope() as db:
        for i in range(n):
            p = SearchProfile(slug=f"load-{i}", name=f"Load {i}", kind="internship",
                              enabled=True, filters={"kind": "internship"})
            db.add(p)
            db.flush()
            s = Scan(profile_id=p.id, state="queued")
            db.add(s)
            db.flush()
            q.enqueue(db, s.id)
            ids.append(s.id)
    return ids


def test_varchar_limits_are_enforced_so_clipping_matters(pg_db):
    with pytest.raises(Exception):
        with session_scope() as s:
            s.add(Job(canonical_key="k", source="lever", source_url="https://x",
                      title="t" * 400, company="c", location="", description=""))


def test_one_active_scan_per_profile_under_concurrent_enqueue(pg_db):
    ids, errors = [], []

    def go():
        try:
            ids.append(orchestrator.enqueue_scan(1))
        except Exception as exc:
            errors.append(repr(exc))

    threads = [threading.Thread(target=go) for _ in range(16)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors, errors
    assert len(set(ids)) == 1
    with session_scope() as db:
        assert db.scalar(select(func.count()).select_from(Task)) == 1


def test_concurrent_job_insert_race(pg_db):
    with session_scope() as s:
        s.add(Scan(profile_id=1, state="running"))
    with session_scope() as s:
        scan_id = s.scalar(select(Scan.id))
    data = {"canonical_key": "same", "source": "lever", "source_url": "https://x/1",
            "title": "T", "company": "c", "location": "", "description": ""}
    errors = []

    def go():
        try:
            with session_scope() as db:
                orchestrator._store_jobs(db, scan_id, [dict(data)])
        except Exception as exc:
            errors.append(repr(exc))

    threads = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors, errors
    with session_scope() as s:
        assert s.scalar(select(func.count()).select_from(Job)) == 1


def test_eight_threads_claim_every_task_exactly_once(pg_db):
    q = TaskQueue()
    ids = make_tasks(60, q)
    claimed, lock = [], threading.Lock()

    def worker():
        while (c := q.claim()) is not None:
            with lock:
                claimed.append(c.scan_id)
            with session_scope() as db:
                q.fence(db, c)
                q.complete(db, c)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(claimed) == sorted(ids)            # all done, none twice
    with session_scope() as db:
        rows = db.execute(select(Task.state, Task.attempts)).all()
    assert set(rows) == {("completed", 1)}


CLAIMER = textwrap.dedent("""
    import sys
    from hunter.taskqueue import TaskQueue
    q = TaskQueue()
    while (c := q.claim()) is not None:
        print(c.scan_id, flush=True)
""")


def test_separate_processes_never_double_claim(pg_db):
    q = TaskQueue()
    ids = make_tasks(40, q)
    procs = [subprocess.Popen([sys.executable, "-c", CLAIMER], stdout=subprocess.PIPE,
                              text=True, env=os.environ) for _ in range(4)]
    out = []
    for p in procs:
        stdout, _ = p.communicate(timeout=60)
        assert p.returncode == 0
        out += [int(x) for x in stdout.split()]
    assert sorted(out) == sorted(ids)


def test_skip_locked_does_not_block_behind_a_locked_row(pg_db):
    q = TaskQueue()
    first, second = make_tasks(2, q)
    from hunter.db import engine
    with engine().connect() as holder:
        holder.execute(text("BEGIN"))
        holder.execute(text("SELECT id FROM tasks WHERE scan_id = :s FOR UPDATE"), {"s": first})
        started = time.monotonic()
        claim = q.claim()           # must skip the locked row, not wait for it
        elapsed = time.monotonic() - started
        holder.execute(text("ROLLBACK"))
    assert claim is not None and claim.scan_id == second
    assert elapsed < 3


CRASHER = textwrap.dedent("""
    import os, signal
    from datetime import datetime, timedelta, timezone
    from hunter.taskqueue import TaskQueue
    off = timedelta(seconds=float(os.environ["CLOCK_OFFSET"]))
    q = TaskQueue(clock=lambda: datetime.now(timezone.utc) + off, lease=timedelta(seconds=2))
    c = q.claim()
    assert c is not None
    print(c.attempt, flush=True)
    os.kill(os.getpid(), signal.SIGKILL)     # crash while holding the lease
""")


def _crash(offset: float) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", CRASHER], capture_output=True, text=True,
                          env={**os.environ, "CLOCK_OFFSET": str(offset)}, timeout=60)


def test_sigkilled_worker_is_recovered_then_retries_are_bounded(pg_db):
    q0 = TaskQueue()
    sid = orchestrator.enqueue_scan(1, q0)
    offset = 0.0
    for attempt in (1, 2, 3):
        r = _crash(offset)
        assert r.returncode == -9 and r.stdout.strip() == str(attempt)
        with session_scope() as db:
            t = db.scalar(select(Task).where(Task.scan_id == sid))
            assert (t.state, t.attempts) == ("running", attempt)   # abandoned, lease dangling
        reap_at = offset + 3                      # past the 2s lease
        recovered = TaskQueue(
            clock=lambda o=reap_at: datetime.now(timezone.utc) + timedelta(seconds=o)).reap()
        assert recovered["retried" if attempt < 3 else "failed"] == 1
        offset = reap_at + 30 * attempt + 1       # past the retry backoff (30s * attempts)
    with session_scope() as db:
        t = db.scalar(select(Task).where(Task.scan_id == sid))
        assert (t.state, t.attempts) == ("failed", 3)
        assert db.get(Scan, sid).state == "failed"
        assert "lease expired" in db.get(Scan, sid).error


def test_recovered_task_completes_on_a_healthy_worker(pg_db, run_tasks, agent_fleet):
    sid = orchestrator.enqueue_scan(1)
    assert _crash(0).returncode == -9
    time.sleep(2.2)                                   # real lease expiry
    def at(offset):
        return TaskQueue(clock=lambda: datetime.now(timezone.utc) + timedelta(seconds=offset))

    assert at(60).reap()["retried"] == 1       # backoff pushes availability to ~now+90s
    assert run_tasks(at(200)) == 1
    with session_scope() as db:
        assert db.get(Scan, sid).state == "finished"
        t = db.scalar(select(Task).where(Task.scan_id == sid))
        assert (t.state, t.attempts) == ("completed", 2)


def test_heartbeat_keeps_a_slow_task_alive_and_silence_does_not(pg_db):
    q = TaskQueue(lease=timedelta(seconds=2))
    make_tasks(2, q)
    alive, silent = q.claim(), q.claim()
    stop = threading.Event()
    reaped = []

    def reaper():
        while not stop.is_set():
            reaped.append(TaskQueue().reap())
            stop.wait(0.3)

    t = threading.Thread(target=reaper)
    t.start()
    with Heartbeater(q, alive, interval=0.5) as beat:
        time.sleep(4.5)
        beat.check()
    stop.set()
    t.join()
    with session_scope() as db:
        st = {x.id: (x.state, x.attempts) for x in db.scalars(select(Task))}
    assert st[alive.task_id] == ("running", 1)
    assert st[silent.task_id][0] == "queued"         # reaped: no heartbeat
    with session_scope() as db:                      # the silent worker is fenced out
        with pytest.raises(LeaseLost):
            q.fence(db, silent)


def test_reaper_skips_a_row_locked_by_a_fencing_worker_even_with_an_expired_lease(pg_db):
    """The strong version. The lease is EXPIRED by the clock while the worker is mid-
    transaction (fence taken, not yet committed). Only the row lock stands between the
    reaper and a double execution; SKIP LOCKED must make the reaper leave the row alone, and
    the worker's completion must win."""
    q = TaskQueue(lease=timedelta(seconds=1))
    make_tasks(1, q)
    claim = q.claim()
    session_ctx = session_scope()
    db = session_ctx.__enter__()
    try:
        q.fence(db, claim)                   # renews to now+1s and takes the row lock
        time.sleep(1.4)                      # the renewed lease is now expired
        reaper_result = TaskQueue().reap()   # separate connection, real clock
        assert reaper_result == {"retried": 0, "failed": 0, "expired_in_queue": 0}
        q.complete(db, claim)
    finally:
        session_ctx.__exit__(None, None, None)
    with session_scope() as s:
        t = s.scalar(select(Task))
        assert (t.state, t.attempts) == ("completed", 1)
    assert TaskQueue().reap() == {"retried": 0, "failed": 0, "expired_in_queue": 0}


def test_expired_worker_loses_to_an_in_flight_reaper_without_writing(pg_db):
    """Reverse ordering: the reaper has taken the expired row and is still inside its
    transaction when the stale worker tries to fence and write. The worker must fail with
    LeaseLost, its write must not land, and the reaper's outcome must stand."""
    q = TaskQueue(lease=timedelta(seconds=1))
    make_tasks(1, q)
    claim = q.claim()
    time.sleep(1.2)                                  # lease expired
    holding, release = threading.Event(), threading.Event()

    def slow_reaper():
        with session_scope() as db:
            t = db.scalar(select(Task).with_for_update())
            db.execute(text("UPDATE tasks SET state='queued', lease_token=NULL, "
                            "lease_expires_at=NULL WHERE id=:i"), {"i": t.id})
            holding.set()
            release.wait(5)                          # commit only when told to

    th = threading.Thread(target=slow_reaper)
    th.start()
    assert holding.wait(5)
    threading.Timer(0.5, release.set).start()
    with pytest.raises(LeaseLost):
        with session_scope() as db:
            q.fence(db, claim)                       # expired: refused, never blocks into a write
            db.execute(text("UPDATE scans SET state='finished'"))   # must never be reached
    th.join()
    with session_scope() as s:
        t = s.scalar(select(Task))
        assert (t.state, t.lease_token) == ("queued", None)
        assert s.scalar(select(Scan.state)) != "finished"   # the stale worker wrote nothing


def test_database_constraints_reject_forged_tasks(pg_db):
    q = TaskQueue()
    make_tasks(1, q)
    for stmt in ("UPDATE tasks SET kind = 'subprocess.run'",
                 "UPDATE tasks SET state = 'exploded'"):
        with pytest.raises(IntegrityError):
            with session_scope() as db:
                db.execute(text(stmt))
