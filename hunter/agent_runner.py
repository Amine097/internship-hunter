"""Planner service that runs *inside* one agent container.

This process is the whole interface of an untrusted agent runtime: it accepts one
authenticated POST /plan from the orchestrator and returns a schema-validated plan. It holds
no database credentials, and it never initiates a connection to infrastructure.
"""
import logging
import secrets
import threading
from collections.abc import Callable

from fastapi import FastAPI, Header, HTTPException
from pydantic import ValidationError

from hunter.agents import AGENTS, run_plan
from hunter.schemas import AgentPlan, PlanRequest
from hunter.settings import get_settings

log = logging.getLogger("hunter.agent_runner")


def create_app(
    agent_name: str, token: str,
    planner: Callable[[str, dict], dict] = run_plan,
) -> FastAPI:
    if agent_name not in AGENTS:
        raise ValueError(f"Unknown agent identity {agent_name!r}")
    if len(token) < 24:
        raise ValueError("AGENT_TOKEN must be at least 24 characters")
    app = FastAPI(title=f"agent-runner {agent_name}", docs_url=None, redoc_url=None,
                  openapi_url=None)
    busy = threading.Lock()  # one CLI run at a time per credential

    @app.get("/health")
    def health():
        return {"agent": agent_name, "status": "ok"}

    @app.post("/plan")
    def plan(body: PlanRequest, authorization: str | None = Header(default=None)):
        expected = f"Bearer {token}"
        if not authorization or not secrets.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="Unauthorized")
        if not busy.acquire(blocking=False):
            raise HTTPException(status_code=503, detail="agent busy")
        try:
            raw = planner(agent_name, body.profile.model_dump(mode="json"))
            return AgentPlan.model_validate(raw).model_dump()
        except (ValidationError, ValueError, OSError) as exc:
            log.warning("plan failed: %s", type(exc).__name__)
            raise HTTPException(status_code=502, detail="agent run failed") from exc
        except Exception as exc:  # subprocess errors/timeouts; never leak CLI output
            log.warning("plan failed: %s", type(exc).__name__)
            raise HTTPException(status_code=502, detail="agent run failed") from exc
        finally:
            busy.release()

    return app


def app_from_env() -> FastAPI:
    s = get_settings()
    return create_app(s.hunter_agent_name, s.agent_token)
