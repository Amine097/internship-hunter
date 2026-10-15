import pathlib
import subprocess

import pytest
import yaml

from hunter import agents
from hunter.settings import Settings
from hunter.worker import validate_identity

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILE = {"kind": "internship", "roles": ["backend"], "primary_countries": ["CH"]}


def test_worker_identity_must_match_queue():
    validate_identity("claude-1", "claude-1")
    validate_identity("discovery", None)
    for queue, name in [("claude-1", "claude-2"), ("codex", None), ("discovery", "codex"),
                        ("bogus", None)]:
        with pytest.raises(ValueError):
            validate_identity(queue, name)


def test_cli_env_excludes_infrastructure_secrets(monkeypatch):
    for key in ("REDIS_URL", "DATABASE_URL", "ADMIN_TOKEN", "TELEGRAM_BOT_TOKEN"):
        monkeypatch.setenv(key, "secret")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", "/home/hunter/.claude")
    env = agents.cli_env()
    assert "CLAUDE_CONFIG_DIR" in env
    assert not {"REDIS_URL", "DATABASE_URL", "ADMIN_TOKEN", "TELEGRAM_BOT_TOKEN"} & set(env)


def test_cli_mode_refuses_foreign_identity(monkeypatch):
    monkeypatch.setenv("AGENT_MODE", "cli")
    monkeypatch.setenv("HUNTER_AGENT_NAME", "claude-2")
    from hunter.settings import get_settings
    get_settings.cache_clear()
    try:
        with pytest.raises(ValueError):
            agents.run_plan("claude-1", PROFILE)
    finally:
        get_settings.cache_clear()


def test_cli_claude_call_is_sandboxed(monkeypatch):
    monkeypatch.setenv("AGENT_MODE", "cli")
    monkeypatch.setenv("HUNTER_AGENT_NAME", "claude-1")
    monkeypatch.setenv("REDIS_URL", "redis://leak")
    from hunter.settings import get_settings
    get_settings.cache_clear()
    seen = {}

    def fake_run(command, **kw):
        seen.update(command=command, env=kw["env"], cwd=kw["cwd"])
        return subprocess.CompletedProcess(
            command, 0, stdout='{"result": "```json\\n{\\"queries\\": [\\"a\\"]}\\n```"}')

    monkeypatch.setattr(agents.subprocess, "run", fake_run)
    try:
        plan = agents.run_plan("claude-1", PROFILE)
    finally:
        get_settings.cache_clear()
    assert plan["queries"] == ["a"] and plan["mode"] == "cli"
    assert "REDIS_URL" not in seen["env"] and seen["cwd"] == "/tmp"
    assert seen["command"][:2] == ["claude", "-p"]


def test_invalid_agent_mode_rejected():
    with pytest.raises(ValueError):
        Settings(agent_mode="auto")


def test_no_setting_can_enable_submission():
    from hunter.policy import SUBMISSION_ENABLED
    assert SUBMISSION_ENABLED is False
    assert not any("submi" in f or "apply" in f for f in Settings.model_fields)


def _compose():
    return yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]


def test_compose_agents_have_no_database_and_own_volume():
    services = _compose()
    agent_names = ["agent-claude-1", "agent-claude-2", "agent-codex"]
    volumes = []
    for name in agent_names:
        svc = services[name]
        assert svc["networks"] == ["queue"], name
        assert not any(k in svc["environment"] for k in
                       ("DATABASE_URL", "ADMIN_TOKEN", "TELEGRAM_BOT_TOKEN", "POSTGRES_PASSWORD"))
        assert svc["environment"]["HUNTER_QUEUE"] == svc["environment"]["HUNTER_AGENT_NAME"]
        assert not any("docker.sock" in v for v in svc.get("volumes", []))
        volumes += svc["volumes"]
    assert len(set(volumes)) == 3


def test_compose_exposes_only_loopback_and_no_docker_socket():
    for name, svc in _compose().items():
        for port in svc.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), (name, port)
        assert not any("docker.sock" in str(v) for v in svc.get("volumes", []))
        assert not svc.get("privileged")
