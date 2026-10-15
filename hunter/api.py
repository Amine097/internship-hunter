"""Local-only control plane. Keep behind localhost and Tailscale."""
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException
from sqlalchemy import func, select, text

from hunter import db as database
from hunter.db import session_scope
from hunter.models import AgentRun, Application, Job, Scan, SearchProfile
from hunter.orchestrator import enqueue_scan
from hunter.policy import SUBMISSION_ENABLED
from hunter.settings import get_settings

app = FastAPI(
    title="Internship Hunter", version="0.1.0",
    docs_url=None, redoc_url=None, openapi_url=None,  # no unauthenticated schema
)


def require_admin(x_admin_token: str | None = Header(default=None)) -> None:
    expected = get_settings().admin_token
    if (
        len(expected) < 24 or not x_admin_token
        or not secrets.compare_digest(expected, x_admin_token)
    ):
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/health")
def health():
    return {
        "status": "ok", "submission_enabled": SUBMISSION_ENABLED,
        "mode": get_settings().agent_mode,
    }


@app.get("/ready")
def ready():
    """PostgreSQL reachable and the schema matches (or is explicitly accepted by) this code."""
    try:
        with session_scope() as db:
            db.execute(text("SELECT 1"))
        status = database.schema_state()[0]
    except Exception as exc:  # no detail: this endpoint is unauthenticated
        raise HTTPException(status_code=503, detail="not ready") from exc
    if status not in ("ok", "accepted"):
        raise HTTPException(status_code=503, detail="schema not ready")
    return {"status": "ready"}


@app.get("/status", dependencies=[Depends(require_admin)])
def status():
    with session_scope() as db:
        return {
            "profiles": db.scalar(select(func.count()).select_from(SearchProfile)),
            "jobs": db.scalar(select(func.count()).select_from(Job)),
            "scans": db.scalar(select(func.count()).select_from(Scan)),
            "applications": db.scalar(select(func.count()).select_from(Application)),
            "submission_enabled": SUBMISSION_ENABLED,
        }


@app.get("/profiles", dependencies=[Depends(require_admin)])
def profiles():
    with session_scope() as db:
        return [
            {"id": p.id, "slug": p.slug, "name": p.name, "kind": p.kind,
             "enabled": p.enabled, "filters": p.filters}
            for p in db.scalars(select(SearchProfile).order_by(SearchProfile.id))
        ]


@app.get("/jobs", dependencies=[Depends(require_admin)])
def jobs():
    with session_scope() as db:
        return [
            {"id": j.id, "title": j.title, "company": j.company,
             "location": j.location, "source": j.source, "url": j.source_url}
            for j in db.scalars(select(Job).order_by(Job.id.desc()).limit(100))
        ]


@app.get("/scans", dependencies=[Depends(require_admin)])
def scans():
    with session_scope() as db:
        return [
            {"id": s.id, "profile_id": s.profile_id, "state": s.state,
             "discovered": s.discovered, "error": s.error, "agents": s.agent_reports}
            for s in db.scalars(select(Scan).order_by(Scan.id.desc()).limit(25))
        ]


@app.get("/agents", dependencies=[Depends(require_admin)])
def agents():
    with session_scope() as db:
        return [
            {"agent": r.agent, "state": r.state, "scan_id": r.scan_id, "output": r.output}
            for r in db.scalars(select(AgentRun).order_by(AgentRun.id.desc()).limit(25))
        ]


@app.post("/scan/{profile_id}", dependencies=[Depends(require_admin)])
def scan(profile_id: int):
    try:
        scan_id = enqueue_scan(profile_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"scan_id": scan_id, "state": "queued"}
