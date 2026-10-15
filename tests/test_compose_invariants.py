import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPOSE = yaml.safe_load((ROOT / "compose.yaml").read_text())
SERVICES = COMPOSE["services"]
AGENTS = ["agent-claude-1", "agent-claude-2", "agent-codex"]
SECRET_KEYS = {"DATABASE_URL", "REDIS_URL", "ADMIN_TOKEN", "TELEGRAM_BOT_TOKEN",
               "POSTGRES_PASSWORD", "REDIS_PASSWORD"}


def test_agents_hold_no_infrastructure_credentials_and_no_infra_network():
    own_volumes = []
    for name in AGENTS:
        svc = SERVICES[name]
        env = svc["environment"]
        assert not SECRET_KEYS & set(env), name
        assert not any(k.startswith("AGENT_TOKEN_") for k in env), "only its own inbound token"
        assert env["HUNTER_AGENT_NAME"] == name.removeprefix("agent-")
        nets = set(svc["networks"])
        assert not nets & {"data", "queue", "edge", "egress"}, name
        assert len(nets) == 1 and next(iter(nets)).startswith("agent_"), name
        own_volumes += svc["volumes"]
        assert "ports" not in svc
    assert len(set(own_volumes)) == 3


def test_agent_networks_are_pairwise_separate():
    nets = [SERVICES[a]["networks"][0] for a in AGENTS]
    assert len(set(nets)) == 3
    for n in nets:
        talkers = [s for s, v in SERVICES.items() if n in v.get("networks", [])]
        assert len(talkers) == 2  # the agent itself + the orchestrator (discovery)
        assert "discovery" in talkers


def test_only_discovery_sees_agent_tokens():
    for name, svc in SERVICES.items():
        keys = {k for k in svc.get("environment", {}) if k.startswith("AGENT_TOKEN_")}
        if name != "discovery":
            assert not keys, name
    env = SERVICES["discovery"]["environment"]
    assert len([k for k in env if k.startswith("AGENT_TOKEN_")]) == 3


def test_hardening_applied_everywhere():
    for name, svc in SERVICES.items():
        assert "no-new-privileges:true" in svc["security_opt"], name
        assert svc.get("mem_limit"), name
        assert svc.get("pids_limit"), name
    for name in AGENTS + ["api", "discovery", "scheduler", "telegram", "migrate", "redis"]:
        assert SERVICES[name]["read_only"] is True, name
        assert SERVICES[name]["cap_drop"] == ["ALL"], name


def test_redis_runs_unprivileged_and_unreachable_from_agents():
    redis = SERVICES["redis"]
    assert redis["user"] not in ("0", "root", None)
    assert redis["networks"] == ["queue"]
    assert COMPOSE["networks"]["queue"].get("internal") is True
    assert COMPOSE["networks"]["data"].get("internal") is True


def test_published_ports_are_loopback_only_and_no_docker_socket():
    for name, svc in SERVICES.items():
        for port in svc.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), (name, port)
        assert not any("docker.sock" in str(v) for v in svc.get("volumes", []))
        assert not svc.get("privileged")


def test_images_are_tagged_by_release_not_mutable_local():
    for name in ("api", "discovery", *AGENTS):
        assert "${RELEASE_SHA" in SERVICES[name]["image"], name
        assert ":local" not in SERVICES[name]["image"]
