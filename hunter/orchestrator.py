"""RQ orchestration. A scan is recorded before a job is enqueued."""
import time
from datetime import datetime, timezone

from redis import Redis
from rq import Queue
from sqlalchemy import select

from hunter.agents import AGENTS
from hunter.db import session_scope
from hunter.models import AgentRun, Job, Scan, ScanJob, SearchProfile
from hunter.settings import get_settings
from hunter.sources import fetch_all, read_sources


def redis_connection() -> Redis:
    return Redis.from_url(get_settings().redis_url)


def enqueue_scan(profile_id: int) -> int:
    with session_scope() as db:
        profile = db.get(SearchProfile, profile_id)
        if profile is None or not profile.enabled:
            raise ValueError("Search profile not found or disabled")
        scan = Scan(profile_id=profile.id, state="queued")
        db.add(scan)
        db.flush()
        scan_id = scan.id
    Queue("discovery", connection=redis_connection()).enqueue(
        run_scan, scan_id, job_timeout=300, result_ttl=3600,
    )
    return scan_id


def enqueue_all_profiles() -> list[int]:
    with session_scope() as db:
        ids = list(db.scalars(select(SearchProfile.id).where(SearchProfile.enabled.is_(True))))
    return [enqueue_scan(profile_id) for profile_id in ids]


def _run_scan(scan_id: int) -> dict:
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise ValueError("Unknown scan")
        scan.state = "running"
        profile = db.get(SearchProfile, scan.profile_id)
        filters = profile.filters

    agent_queue_jobs = {
        agent: Queue(agent, connection=redis_connection()).enqueue(
            "hunter.agents.agent_task", agent, filters, job_timeout=100, result_ttl=3600,
        )
        for agent in AGENTS
    }
    reports: list[dict] = []
    deadline = time.monotonic() + 115
    while time.monotonic() < deadline:
        statuses = [job.get_status(refresh=True) for job in agent_queue_jobs.values()]
        if all(status in ("finished", "failed", "stopped") for status in statuses):
            break
        time.sleep(0.75)

    for agent, rq_job in agent_queue_jobs.items():
        rq_job.refresh()
        if rq_job.is_finished:
            output = rq_job.return_value() or {}
            state = "finished"
        else:
            state = "failed" if rq_job.is_failed else "timeout"
            output = {"error": "Agent did not complete; inspect worker logs"}
        reports.append({"agent": agent, "state": state, "output": output})

    sources = read_sources(get_settings().sources_path)
    jobs, errors = fetch_all(sources)
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        for report in reports:
            db.add(AgentRun(
                scan_id=scan_id, agent=report["agent"], state=report["state"],
                output=report["output"],
            ))
        for data in jobs:
            job = db.scalar(select(Job).where(Job.canonical_key == data["canonical_key"]))
            if job is None:
                job = Job(**data)
                db.add(job)
                db.flush()
            linked = db.scalar(select(ScanJob).where(
                ScanJob.scan_id == scan_id, ScanJob.job_id == job.id,
            ))
            if linked is None:
                db.add(ScanJob(scan_id=scan_id, job_id=job.id))
        scan.discovered = len(jobs)
        scan.agent_reports = reports
        scan.error = "; ".join(errors) if errors else None
        scan.state = (
            "partial" if errors or any(r["state"] != "finished" for r in reports)
            else "finished"
        )
        scan.finished_at = datetime.now(timezone.utc)
    return {"scan_id": scan_id, "discovered": len(jobs), "sources": len(sources), "errors": errors}


# Record unexpected failures rather than leaving a scan forever in the "running" state.
def run_scan(scan_id: int) -> dict:
    try:
        return _run_scan(scan_id)
    except Exception as exc:
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            if scan is not None:
                scan.state = "failed"
                scan.error = type(exc).__name__
                scan.finished_at = datetime.now(timezone.utc)
        raise
