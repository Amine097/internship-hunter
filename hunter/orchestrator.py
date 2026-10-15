"""Scan orchestration (trusted side).

A scan row is recorded before a job is enqueued. Agents are *called* over a narrow HTTP
interface and their replies are validated; they never touch Redis or the database.

State machine: queued -> running -> finished | partial | failed
(``queued``/``running`` older than STALE_AFTER are swept to ``failed``.)
"""
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import httpx
from pydantic import ValidationError
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from hunter import queueing
from hunter.agents import AGENTS
from hunter.db import session_scope
from hunter.models import ACTIVE_STATES, AgentRun, Job, Scan, ScanJob, SearchProfile
from hunter.schemas import MAX_RESPONSE_BYTES, AgentPlan, AgentProfile
from hunter.settings import get_settings
from hunter.sources import fetch_all, read_sources

STALE_AFTER = timedelta(minutes=20)  # > RQ job_timeout (10 min) + slack
AGENT_TIMEOUT_S = 110
ATS_BUDGET_S = 240


def redis_connection():
    return queueing.redis_connection()


def now() -> datetime:
    return datetime.now(timezone.utc)


def sweep_stale_scans() -> int:
    """Closes scans orphaned by a crashed/OOM-killed worker or a lost Redis job."""
    with session_scope() as db:
        result = db.execute(
            update(Scan)
            .where(Scan.state.in_(ACTIVE_STATES), Scan.created_at < now() - STALE_AFTER)
            .values(state="failed", error="stale: no worker completed this scan",
                    finished_at=now())
        )
        return result.rowcount or 0


def _active_scan_id(db, profile_id: int) -> int | None:
    return db.scalar(select(Scan.id).where(
        Scan.profile_id == profile_id, Scan.state.in_(ACTIVE_STATES),
    ))


def enqueue_scan(profile_id: int) -> int:
    """Returns the scan id. A profile with an active scan returns that scan (idempotent)."""
    sweep_stale_scans()
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
        except IntegrityError:  # lost the race against a concurrent enqueue
            db.rollback()
            return _active_scan_id(db, profile_id)
        scan_id = scan.id
    try:
        queueing.enqueue_scan_job(scan_id)
    except Exception as exc:  # e.g. Redis down: never leave a phantom "queued" scan behind
        with session_scope() as db:
            db.execute(update(Scan).where(Scan.id == scan_id, Scan.state == "queued").values(
                state="failed", error=f"enqueue failed: {type(exc).__name__}",
                finished_at=now(),
            ))
        raise RuntimeError("Could not enqueue scan; is Redis reachable?") from exc
    return scan_id


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


# --- the scan job ----------------------------------------------------------------------

def _claim(scan_id: int) -> dict | None:
    """queued -> running, atomically. Returns the profile filters or None if not claimable."""
    with session_scope() as db:
        claimed = db.execute(
            update(Scan).where(Scan.id == scan_id, Scan.state == "queued").values(state="running")
        ).rowcount
        if not claimed:
            return None
        scan = db.get(Scan, scan_id)
        return dict(db.get(SearchProfile, scan.profile_id).filters)


def _store_jobs(scan_id: int, jobs: list[dict]) -> None:
    with session_scope() as db:
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


def _run_scan(scan_id: int, client_factory=None, transport=None) -> dict:
    filters = _claim(scan_id)
    if filters is None:
        return {"scan_id": scan_id, "skipped": True}

    reports = run_agents(filters, client_factory)
    with session_scope() as db:  # agent results are persisted before slow ATS I/O starts
        scan = db.get(Scan, scan_id)
        scan.agent_reports = reports
        for report in reports:
            db.add(AgentRun(scan_id=scan_id, agent=report["agent"], state=report["state"],
                            output=report["output"]))

    sources = read_sources(get_settings().sources_path)
    jobs, errors = fetch_all(sources, deadline=time.monotonic() + ATS_BUDGET_S,
                             transport=transport)
    _store_jobs(scan_id, jobs)
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        scan.discovered = len(jobs)
        scan.error = "; ".join(errors) if errors else None
        scan.state = (
            "partial" if errors or any(r["state"] != "finished" for r in reports) else "finished"
        )
        scan.finished_at = now()
    return {"scan_id": scan_id, "discovered": len(jobs), "sources": len(sources),
            "errors": errors}


def run_scan(scan_id: int) -> dict:
    """RQ entry point (allowlisted in hunter.queueing)."""
    try:
        return _run_scan(scan_id)
    except Exception as exc:
        with session_scope() as db:  # never leave a scan stuck in "running"
            db.execute(update(Scan).where(Scan.id == scan_id, Scan.state == "running").values(
                state="failed", error=type(exc).__name__, finished_at=now()))
        raise
