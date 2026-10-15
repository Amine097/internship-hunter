"""PostgreSQL task queue: transactional claiming, leases, heartbeats, fencing.

Design rules
* The only inputs to a task are its kind (CHECK-constrained enum) and ``scan_id``. Nothing
  executable or serialised is ever stored, so there is nothing to forge or deserialise.
* A worker may act on a task only while it holds the unexpired ``lease_token``.
  ``fence()`` re-validates (and renews) the lease *inside* the transaction that writes the
  task's results, taking the task row lock; an expired or superseded worker therefore fails
  with ``LeaseLost`` and its writes roll back. This is the fencing check.
* ``claim()`` uses ``SELECT ... FOR UPDATE SKIP LOCKED`` and holds the row lock only for the
  duration of one short transaction; the lease, not the lock, protects the long-running work.
* Clock: lease arithmetic uses the application clock (injectable for tests). Workers need
  clocks within a few seconds of each other; leases are minutes long.
"""
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from hunter.db import session_scope
from hunter.models import Scan, Task

LEASE = timedelta(seconds=120)
HEARTBEAT_EVERY = 30.0
MAX_ATTEMPTS = 3
RETRY_BACKOFF = timedelta(seconds=30)
QUEUE_TTL = timedelta(hours=1)  # a task nobody picked up for this long is failed, not run


class LeaseLost(Exception):
    """This worker no longer owns the task (expired, reaped, reclaimed or finished)."""


class TaskCancelled(Exception):
    """Cancellation was requested; the handler must stop and call ``cancel_running``."""


@dataclass(frozen=True)
class Claim:
    task_id: int
    scan_id: int
    kind: str
    token: str
    attempt: int
    max_attempts: int


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TaskQueue:
    def __init__(self, clock: Callable[[], datetime] = _utcnow, lease: timedelta = LEASE):
        self.now = clock
        self.lease = lease

    # -- producing ----------------------------------------------------------------------
    def enqueue(self, db, scan_id: int, kind: str = "scan",
                max_attempts: int = MAX_ATTEMPTS) -> Task:
        """Adds a task in the caller's transaction (atomic with creating the scan row)."""
        task = Task(kind=kind, scan_id=scan_id, state="queued", attempts=0,
                    max_attempts=max_attempts, available_at=self.now(), created_at=self.now())
        db.add(task)
        db.flush()
        return task

    # -- consuming ----------------------------------------------------------------------
    def claim(self) -> Claim | None:
        now = self.now()
        with session_scope() as db:
            row = db.execute(
                select(Task).where(Task.state == "queued", Task.available_at <= now)
                .order_by(Task.id).limit(1).with_for_update(skip_locked=True)
            ).scalar_one_or_none()
            if row is None:
                return None
            token = uuid.uuid4().hex
            task_id, scan_id, kind = row.id, row.scan_id, row.kind
            attempt, max_attempts = row.attempts + 1, row.max_attempts  # before the UPDATE
            won = db.execute(
                update(Task).where(Task.id == task_id, Task.state == "queued").values(
                    state="running", lease_token=token, lease_expires_at=now + self.lease,
                    heartbeat_at=now, started_at=now, attempts=attempt, finished_at=None)
                .execution_options(synchronize_session=False)
            ).rowcount
            if won != 1:
                return None
            db.execute(update(Scan).where(Scan.id == scan_id, Scan.state == "queued")
                       .values(state="running", started_at=now))
            return Claim(task_id, scan_id, kind, token, attempt, max_attempts)

    def fence(self, db, claim: Claim) -> None:
        """Validate + renew the lease inside ``db``'s transaction (row-locks the task)."""
        now = self.now()
        rows = db.execute(
            update(Task).where(
                Task.id == claim.task_id, Task.lease_token == claim.token,
                Task.state == "running", Task.lease_expires_at > now,
            ).values(heartbeat_at=now, lease_expires_at=now + self.lease)
        ).rowcount
        if rows != 1:
            raise LeaseLost(f"task {claim.task_id}: lease lost")
        if db.scalar(select(Task.cancel_requested).where(Task.id == claim.task_id)):
            raise TaskCancelled(f"task {claim.task_id}: cancel requested")

    def heartbeat(self, claim: Claim) -> None:
        with session_scope() as db:
            self.fence(db, claim)

    def complete(self, db, claim: Claim) -> None:
        """Terminal success, in the same transaction as the results (call after fence)."""
        self._terminal(db, claim, "completed", None)

    def _terminal(self, db, claim: Claim, state: str, error: str | None) -> None:
        rows = db.execute(
            update(Task).where(Task.id == claim.task_id, Task.lease_token == claim.token,
                               Task.state == "running")
            .values(state=state, finished_at=self.now(), lease_token=None,
                    lease_expires_at=None, last_error=error)
        ).rowcount
        if rows != 1:
            raise LeaseLost(f"task {claim.task_id}: cannot finish, lease lost")

    def fail_or_retry(self, claim: Claim, error: str) -> str:
        """Handler crashed. Retry with backoff while attempts remain, else fail the scan."""
        with session_scope() as db:
            self.fence_loose(db, claim)
            return self._retry_or_fail(db, claim.task_id, claim.scan_id, claim.attempt,
                                       claim.max_attempts, error, expect_token=claim.token)

    def fence_loose(self, db, claim: Claim) -> None:
        """Like fence() but tolerates an expired-but-unreclaimed lease (still ours)."""
        ok = db.scalar(select(Task.id).where(
            Task.id == claim.task_id, Task.lease_token == claim.token,
            Task.state == "running").with_for_update())
        if ok is None:
            raise LeaseLost(f"task {claim.task_id}: not owned")

    def _retry_or_fail(self, db, task_id, scan_id, attempts, max_attempts, error,
                       expect_token: str | None) -> str:
        now = self.now()
        cond = [Task.id == task_id, Task.state == "running"]
        if expect_token is not None:
            cond.append(Task.lease_token == expect_token)
        if attempts < max_attempts:
            rows = db.execute(update(Task).where(*cond).values(
                state="queued", lease_token=None, lease_expires_at=None, last_error=error,
                available_at=now + RETRY_BACKOFF * attempts)).rowcount
            if rows == 1:
                db.execute(update(Scan).where(Scan.id == scan_id, Scan.state == "running")
                           .values(state="queued"))
                return "retry"
        else:
            rows = db.execute(update(Task).where(*cond).values(
                state="failed", lease_token=None, lease_expires_at=None, finished_at=now,
                last_error=error)).rowcount
            if rows == 1:
                db.execute(update(Scan).where(
                    Scan.id == scan_id, Scan.state.in_(("queued", "running")),
                ).values(state="failed", error=error, finished_at=now))
                return "failed"
        raise LeaseLost(f"task {task_id}: state changed concurrently")

    def release(self, db, claim: Claim) -> None:
        """Graceful shutdown: hand the task back WITHOUT consuming an attempt.

        A routine deploy stops workers; that must not use up the bounded retries meant for
        crashes. (A worker that is SIGKILLed after the grace period still goes through lease
        expiry and does consume one.)
        """
        now = self.now()
        rows = db.execute(
            update(Task).where(Task.id == claim.task_id, Task.lease_token == claim.token,
                               Task.state == "running")
            .values(state="queued", lease_token=None, lease_expires_at=None, available_at=now,
                    attempts=max(claim.attempt - 1, 0),
                    last_error="released: worker shutting down")
        ).rowcount
        if rows != 1:
            raise LeaseLost(f"task {claim.task_id}: cannot release, lease lost")
        db.execute(update(Scan).where(Scan.id == claim.scan_id, Scan.state == "running")
                   .values(state="queued"))

    def cancel_running(self, db, claim: Claim) -> None:
        self._terminal(db, claim, "cancelled", "cancelled")
        db.execute(update(Scan).where(Scan.id == claim.scan_id, Scan.state == "running")
                   .values(state="cancelled", finished_at=self.now(), error="cancelled"))

    # -- control / maintenance ------------------------------------------------------------
    def cancel(self, scan_id: int) -> str:
        """queued -> cancelled immediately; running -> flagged, honoured at the next fence."""
        now = self.now()
        with session_scope() as db:
            queued = db.execute(update(Task).where(
                Task.scan_id == scan_id, Task.state == "queued"
            ).values(state="cancelled", finished_at=now, last_error="cancelled")).rowcount
            if queued:
                db.execute(update(Scan).where(Scan.id == scan_id, Scan.state == "queued")
                           .values(state="cancelled", finished_at=now, error="cancelled"))
                return "cancelled"
            running = db.execute(update(Task).where(
                Task.scan_id == scan_id, Task.state == "running"
            ).values(cancel_requested=True)).rowcount
            return "cancel_requested" if running else "noop"

    def reap(self) -> dict[str, int]:
        """Recovers abandoned work. Safe to run from every worker at any time."""
        now = self.now()
        out = {"retried": 0, "failed": 0, "expired_in_queue": 0}
        with session_scope() as db:
            stale = db.execute(
                select(Task).where(Task.state == "running", Task.lease_expires_at < now)
                .order_by(Task.id).with_for_update(skip_locked=True)
            ).scalars().all()
            for t in stale:
                outcome = self._retry_or_fail(
                    db, t.id, t.scan_id, t.attempts, t.max_attempts,
                    "lease expired (worker crashed or stalled)", expect_token=t.lease_token)
                out["retried" if outcome == "retry" else "failed"] += 1
            old = db.execute(
                select(Task).where(Task.state == "queued", Task.created_at < now - QUEUE_TTL)
                .with_for_update(skip_locked=True)
            ).scalars().all()
            for t in old:
                db.execute(update(Task).where(Task.id == t.id, Task.state == "queued").values(
                    state="failed", finished_at=now, last_error="expired in queue"))
                db.execute(update(Scan).where(Scan.id == t.scan_id, Scan.state == "queued")
                           .values(state="failed", finished_at=now,
                                   error="expired in queue: no worker picked it up"))
                out["expired_in_queue"] += 1
        return out


class Heartbeater:
    """Background lease renewal while a handler runs. ``check()`` surfaces loss/cancel."""

    def __init__(self, queue: TaskQueue, claim: Claim, interval: float | None = None):
        self.queue, self.claim = queue, claim
        self.interval = interval or HEARTBEAT_EVERY  # module value read at runtime (tests)
        self._stop = threading.Event()
        self._error: Exception | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.queue.heartbeat(self.claim)
            except (LeaseLost, TaskCancelled) as exc:
                self._error = exc
                return
            except Exception:  # transient DB error: the next beat retries; lease still valid
                continue

    def check(self) -> None:
        if self._error is not None:
            raise self._error

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(timeout=5)
