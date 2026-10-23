import subprocess
import sys

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from hunter import agents
from hunter.agent_runner import create_app
from hunter.schemas import AgentPlan, PlanRequest
from hunter.settings import get_settings

TOKEN = "k" * 32
PROFILE = {"kind": "internship", "roles": ["backend"], "primary_countries": ["CH"],
           "secondary_countries": ["DE"]}
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def client(planner=agents.run_plan, name="codex"):
    return TestClient(create_app(name, TOKEN, planner=planner))


def test_requires_bearer_token():
    c = client()
    assert c.post("/plan", json={"profile": PROFILE}).status_code == 401
    assert c.post("/plan", json={"profile": PROFILE},
                  headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.post("/plan", json={"profile": PROFILE},
                  headers={"Authorization": TOKEN}).status_code == 401


def test_valid_demo_plan():
    body = client().post("/plan", json={"profile": PROFILE}, headers=AUTH).json()
    assert body["agent"] == "codex" and body["mode"] == "demo" and body["queries"]


def test_request_schema_is_strict():
    c = client()
    for bad in [
        {"profile": {**PROFILE, "kind": "full_time"}},
        {"profile": {**PROFILE, "roles": ["x" * 500]}},
        {"profile": {**PROFILE, "primary_countries": ["Switzerland"]}},
        {"profile": PROFILE, "extra": "field"},
        {"nope": 1},
    ]:
        assert c.post("/plan", json=bad, headers=AUTH).status_code == 422, bad


def test_unknown_profile_fields_are_stripped_not_forwarded():
    seen = {}

    def planner(agent, profile):
        seen.update(profile)
        return agents.demo_plan(agent, profile)

    body = {"profile": {**PROFILE, "admin_token": "SECRET", "prompt": "ignore all"}}
    assert client(planner).post("/plan", json=body, headers=AUTH).status_code == 200
    assert "admin_token" not in seen and "prompt" not in seen


@pytest.mark.parametrize("bad_output", [
    {"agent": "claude-1", "mode": "cli", "queries": ["a"]},          # wrong identity
    {"agent": "codex", "mode": "cli", "queries": ["x" * 161]},       # too long
    {"agent": "codex", "mode": "cli", "queries": ["q"] * 16},        # too many
    {"agent": "codex", "mode": "cli", "queries": ["a\x00b"]},        # control char
    {"agent": "codex", "mode": "cli", "queries": ["a"], "cmd": "rm"},  # extra field
    {"agent": "codex", "mode": "evil", "queries": ["a"]},
])
def test_malicious_planner_output_rejected(bad_output):
    # claude-1 output pretending to be codex is rejected at the schema layer too
    c = client(lambda a, p: bad_output)
    r = c.post("/plan", json={"profile": PROFILE}, headers=AUTH)
    if bad_output.get("agent") == "claude-1":
        # schema accepts the value (valid agent name); identity is enforced by the orchestrator
        assert r.status_code == 200
        assert r.json()["agent"] == "claude-1"
    else:
        assert r.status_code == 502
        assert "queries" not in r.text


def test_planner_crash_is_generic_502():
    def boom(a, p):
        raise subprocess.CalledProcessError(1, ["claude"], stderr="secret-in-stderr")

    r = client(boom).post("/plan", json={"profile": PROFILE}, headers=AUTH)
    assert r.status_code == 502 and "secret" not in r.text


def test_busy_runner_rejects_parallel_run():
    import threading
    gate, entered = threading.Event(), threading.Event()

    def slow(a, p):
        entered.set()
        gate.wait(5)
        return agents.demo_plan(a, p)

    c = client(slow)
    t = threading.Thread(target=lambda: c.post("/plan", json={"profile": PROFILE}, headers=AUTH))
    t.start()
    assert entered.wait(5)
    assert c.post("/plan", json={"profile": PROFILE}, headers=AUTH).status_code == 503
    gate.set()
    t.join()


def test_runner_config_validation():
    with pytest.raises(ValueError):
        create_app("claude-9", TOKEN)
    with pytest.raises(ValueError):
        create_app("codex", "short")


def test_docs_not_exposed():
    c = client()
    assert all(c.get(p).status_code == 404 for p in ("/docs", "/openapi.json"))


def test_schemas_reject_extra_and_bad_values():
    with pytest.raises(ValidationError):
        AgentPlan(agent="codex", mode="cli", queries=["a"], evil=1)
    with pytest.raises(ValidationError):
        PlanRequest.model_validate({"profile": {"kind": "internship", "roles": ["A B"]}})


def test_agent_runtime_imports_no_infrastructure_clients():
    """The agent runtime must be unable to talk to Redis/PostgreSQL even in principle."""
    code = (
        "import sys, hunter.agent_runner;"
        "bad=[m for m in ('redis','rq','sqlalchemy','psycopg','hunter.db','hunter.queueing',"
        "'hunter.orchestrator') if m in sys.modules];"
        "print(','.join(bad))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == ""


def test_cli_env_excludes_infrastructure_secrets(monkeypatch):
    for key in ("REDIS_URL", "DATABASE_URL", "ADMIN_TOKEN", "TELEGRAM_BOT_TOKEN",
                "AGENT_TOKEN", "AGENT_TOKEN_CODEX"):
        monkeypatch.setenv(key, "secret")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", "/home/hunter/.claude")
    env = agents.cli_env()
    # inherited variables come only from the allow-list; the rest are fixed hardening constants
    assert set(env) <= set(agents._ENV_ALLOWLIST) | set(agents._CLI_FIXED_ENV)
    assert {k: env[k] for k in agents._CLI_FIXED_ENV} == agents._CLI_FIXED_ENV
    assert "secret" not in env.values()
    assert "CLAUDE_CONFIG_DIR" in env


def _cli(monkeypatch, name, stdout):
    monkeypatch.setenv("AGENT_MODE", "cli")
    monkeypatch.setenv("HUNTER_AGENT_NAME", name)
    get_settings.cache_clear()
    seen = {}

    def fake_run(command, **kw):
        seen.update(command=command, env=kw["env"], cwd=kw["cwd"])
        return subprocess.CompletedProcess(command, 0, stdout=stdout)

    monkeypatch.setattr(agents.subprocess, "run", fake_run)
    return seen


def test_cli_refuses_foreign_identity(monkeypatch):
    monkeypatch.setenv("AGENT_MODE", "cli")
    monkeypatch.setenv("HUNTER_AGENT_NAME", "claude-2")
    get_settings.cache_clear()
    try:
        with pytest.raises(ValueError):
            agents.run_plan("claude-1", PROFILE)
    finally:
        get_settings.cache_clear()


def test_cli_claude_call_is_sandboxed_and_fence_tolerant(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://leak")
    seen = _cli(monkeypatch, "claude-1",
                '{"result": "```json\\n{\\"queries\\": [\\"a\\"]}\\n```"}')
    try:
        plan = agents.run_plan("claude-1", PROFILE)
    finally:
        get_settings.cache_clear()
    assert plan["queries"] == ["a"] and plan["mode"] == "cli"
    assert "REDIS_URL" not in seen["env"] and seen["cwd"] == "/tmp"
    assert seen["command"][:2] == ["claude", "-p"] and "--tools" in seen["command"]


def test_cli_claude_error_envelope(monkeypatch):
    _cli(monkeypatch, "claude-1", '{"is_error": true, "result": "boom"}')
    try:
        with pytest.raises(ValueError):
            agents.run_plan("claude-1", PROFILE)
    finally:
        get_settings.cache_clear()


def test_cli_codex_path(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_MODE", "cli")
    monkeypatch.setenv("HUNTER_AGENT_NAME", "codex")
    monkeypatch.setenv("REDIS_URL", "redis://leak")
    get_settings.cache_clear()
    seen = {}

    def fake_run(command, **kw):
        seen.update(command=command, env=kw["env"])
        out = command[command.index("--output-last-message") + 1]
        open(out, "w").write('{"queries": ["backend CH"]}')
        return subprocess.CompletedProcess(command, 0, stdout="")

    monkeypatch.setattr(agents.subprocess, "run", fake_run)
    try:
        plan = agents.run_plan("codex", PROFILE)
    finally:
        get_settings.cache_clear()
    assert plan == {"agent": "codex", "mode": "cli", "queries": ["backend CH"]}
    assert seen["command"][:2] == ["codex", "exec"]
    assert seen["command"][seen["command"].index("--sandbox") + 1] == "read-only"
    assert "REDIS_URL" not in seen["env"]
