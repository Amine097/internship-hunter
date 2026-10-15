"""Scan orchestration (trusted side).

A scan and its task are created in one transaction. A worker claims the task under a lease
and drives: agents -> persist -> ATS -> persist+finish. Agents are *called* over a narrow HTTP
interface and their replies are validated; they never touch the queue or the database.

Scan states:  queued -> running -> finished | partial | failed | cancelled
(``partial`` = completed, but an agent or a source failed.) Every write made by a worker is
fenced by its task lease (hunter.taskqueue), so an expired worker cannot overwrite results.
"""
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import httpx
from pydantic import ValidationError
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from hunter.agents import AGENTS
from hunter.db import session_scope
from hunter.models import ACTIVE_STATES, AgentRun, Job, Scan, ScanJob, SearchProfile
from hunter.schemas import MAX_RESPONSE_BYTES, AgentPlan, AgentProfile
from hunter.settings import get_settings
from hunter.sources import fetch_all, read_sources
from hunter.taskqueue import Claim, Heartbeater, LeaseLost, TaskCancelled, TaskQueue

log = logging.getLogger("hunter.orchestrator")
AGENT_TIMEOUT_S = 110
ATS_BUDGET_S = 240


def now() -> datetime:
    return datetime.now(timezone.utc)


def _active_scan_id(db, profile_id: int) -> int | None:
    return db.scalar(select(Scan.id).where(
        Scan.profile_id == profile_id, Scan.state.in_(ACTIVE_STATES),
    ))


def enqueue_scan(profile_id: int, queue: TaskQueue | None = None) -> int:
    """Returns the scan id. A profile with an active scan returns that scan (idempotent).

    The scan row and its task are created in ONE transaction: there is no window in which a
    scan exists without work behind it, and the partial unique index makes concurrent calls
    converge on a single active scan.
    """
    queue = queue or TaskQueue()
    with session_scope() as db:
        profile = db.get(SearchProfile, profile_id)
        if profile is None or not profile.enabled:
            raise ValueError("Search profile not found or disabled")
        active = _active_scan_id(db, profile_id)
        if active is not None:
            return active
        scan = Scan(profile_id=profile.id, state="queued")
        db.add(scan)
        try:
            db.flush()
            queue.enqueue(db, scan.id)
            return scan.id
        except IntegrityError:  # lost the race against a concurrent enqueue
            db.rollback()
            return _active_scan_id(db, profile_id)


def enqueue_all_profiles() -> tuple[list[int], list[str]]:
    """Queues every enabled profile; one failure does not hide the others."""
    with session_scope() as db:
        ids = list(db.scalars(select(SearchProfile.id).where(SearchProfile.enabled.is_(True))))
    queued, errors = [], []
    for profile_id in ids:
        try:
            queued.append(enqueue_scan(profile_id))
        except (ValueError, RuntimeError) as exc:
            errors.append(f"profile {profile_id}: {exc}")
    return queued, errors


# --- agent fan-out ---------------------------------------------------------------------

def _agent_endpoint(agent: str) -> tuple[str, str]:
    key = agent.replace("-", "_")
    s = get_settings()
    return getattr(s, f"agent_url_{key}"), getattr(s, f"agent_token_{key}")


def call_agent(agent: str, profile: dict, client: httpx.Client | None = None) -> dict:
    """One planner call. Raises on any error or schema violation; the caller records it."""
    url, token = _agent_endpoint(agent)
    if len(token) < 24:
        raise RuntimeError("agent token not configured")
    body = {"profile": AgentProfile.model_validate(profile).model_dump(mode="json")}
    owned = client is None
    client = client or httpx.Client(timeout=httpx.Timeout(AGENT_TIMEOUT_S, connect=5.0),
                                    follow_redirects=False)
    try:
        with client.stream(
            "POST", f"{url}/plan", json=body, headers={"Authorization": f"Bearer {token}"},
        ) as response:
            response.raise_for_status()
            raw = bytearray()
            for chunk in response.iter_bytes():
                raw += chunk
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ValueError("agent response too large")
        plan = AgentPlan.model_validate_json(bytes(raw))
        if plan.agent != agent:  # an agent must not answer under another identity
            raise ValueError("agent identity mismatch")
        return plan.model_dump()
    finally:
        if owned:
            client.close()


def run_agents(profile: dict, client_factory=None) -> list[dict]:
    def one(agent: str) -> dict:
        try:
            output = call_agent(agent, profile, client_factory(agent) if client_factory else None)
            return {"agent": agent, "state": "finished", "output": output}
        except (httpx.HTTPError, ValidationError, ValueError, RuntimeError) as exc:
            # Only the exception class is stored: CLI output is never echoed into the DB.
            return {"agent": agent, "state": "failed",
                    "output": {"error": f"{type(exc).__name__}"}}

    with ThreadPoolExecutor(max_workers=len(AGENTS)) as pool:
        return list(pool.map(one, AGENTS))


# --- the scan task -------------------------------------------------------------------

def _store_jobs(db, scan_id: int, jobs: list[dict]) -> None:
    for data in jobs:
        job = db.scalar(select(Job).where(Job.canonical_key == data["canonical_key"]))
        if job is None:
            try:
                with db.begin_nested():
                    job = Job(**data)
                    db.add(job)
                    db.flush()
            except IntegrityError:  # another writer inserted it first
                job = db.scalar(select(Job).where(Job.canonical_key == data["canonical_key"]))
        link = db.scalar(select(ScanJob).where(
            ScanJob.scan_id == scan_id, ScanJob.job_id == job.id))
        if link is None:
            db.add(ScanJob(scan_id=scan_id, job_id=job.id))


def execute_scan(queue: TaskQueue, claim: Claim, client_factory=None, transport=None) -> dict:
    """Runs one claimed scan. Raises LeaseLost / TaskCancelled if ownership ends."""
    with session_scope() as db:
        scan = db.get(Scan, claim.scan_id)
        filters = dict(db.get(SearchProfile, scan.profile_id).filters)

    with Heartbeater(queue, claim) as beat:
        reports = run_agents(filters, client_factory)
        beat.check()
        with session_scope() as db:  # agent results are persisted before slow ATS I/O
            queue.fence(db, claim)
            db.execute(delete(AgentRun).where(AgentRun.scan_id == claim.scan_id))  # retry-safe
            db.get(Scan, claim.scan_id).agent_reports = reports
            for r in reports:
                db.add(AgentRun(scan_id=claim.scan_id, agent=r["agent"], state=r["state"],
                                output=r["output"]))

        sources = read_sources(get_settings().sources_path)
        jobs, errors = fetch_all(sources, deadline=time.monotonic() + ATS_BUDGET_S,
                                 transport=transport)
        beat.check()
        with session_scope() as db:
            queue.fence(db, claim)  # fencing: an expired worker fails here and rolls back
            _store_jobs(db, claim.scan_id, jobs)
            state = ("partial" if errors or any(r["state"] != "finished" for r in reports)
                     else "finished")
            done = db.execute(update(Scan).where(
                Scan.id == claim.scan_id, Scan.state == "running",
            ).values(state=state, discovered=len(jobs), finished_at=now(),
                     error="; ".join(errors) if errors else None)).rowcount
            if done != 1:
                raise LeaseLost("scan is no longer running")
            queue.complete(db, claim)
    return {"scan_id": claim.scan_id, "state": state, "discovered": len(jobs),
            "sources": len(sources), "errors": errors}


def process_claim(queue: TaskQueue, claim: Claim, **kw) -> dict | None:
    """Worker entry point for one claimed task; never raises for expected conditions."""
    if claim.kind != "scan":  # unreachable (DB CHECK), kept as defence in depth
        queue.fail_or_retry(claim, "unsupported task kind")
        return None
    try:
        return execute_scan(queue, claim, **kw)
    except LeaseLost as exc:
        log.warning("lease lost, abandoning task %s: %s", claim.task_id, exc)
    except TaskCancelled:
        try:
            with session_scope() as db:
                queue.fence_loose(db, claim)
                queue.cancel_running(db, claim)
        except LeaseLost:
            pass
    except Exception as exc:  # unexpected: bounded retry, then the scan is failed
        try:
            outcome = queue.fail_or_retry(claim, type(exc).__name__)
            log.error("task %s attempt %s crashed (%s): %s", claim.task_id, claim.attempt,
                      type(exc).__name__, outcome)
        except LeaseLost:
            pass
    return None
