import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPOSE = yaml.safe_load((ROOT / "compose.yaml").read_text())
SERVICES = COMPOSE["services"]
AGENTS = ["agent-claude-1", "agent-claude-2", "agent-codex"]
SECRET_KEYS = {"DATABASE_URL", "ADMIN_TOKEN", "TELEGRAM_BOT_TOKEN", "POSTGRES_PASSWORD"}


PROXIES = {"agent-claude-1": "egress-claude-1", "agent-claude-2": "egress-claude-2",
           "agent-codex": "egress-codex"}


def test_agents_hold_no_infrastructure_credentials_and_only_an_internal_network():
    own_volumes = []
    for name in AGENTS:
        svc = SERVICES[name]
        env = svc["environment"]
        assert not SECRET_KEYS & set(env), name
        assert "REDIS_URL" not in env
        assert not any(k.startswith("AGENT_TOKEN_") for k in env), "only its own inbound token"
        assert env["HUNTER_AGENT_NAME"] == name.removeprefix("agent-")
        (net,) = svc["networks"]
        assert net.startswith("agent_") and COMPOSE["networks"][net].get("internal") is True
        assert env["HTTPS_PROXY"] == f"http://{PROXIES[name]}:3128"
        own_volumes += svc["volumes"]
        assert "ports" not in svc
    assert len(set(own_volumes)) == 3


def test_each_agent_network_holds_exactly_agent_proxy_and_orchestrator():
    for agent, proxy in PROXIES.items():
        net = SERVICES[agent]["networks"][0]
        talkers = sorted(s for s, v in SERVICES.items() if net in v.get("networks", []))
        assert talkers == sorted([agent, proxy, "discovery"])


def test_egress_proxies_are_the_only_agent_path_out_and_are_allowlisted():
    for agent, proxy in PROXIES.items():
        svc = SERVICES[proxy]
        assert "egress" in svc["networks"] and SERVICES[agent]["networks"][0] in svc["networks"]
        allow = svc["environment"]["EGRESS_ALLOW"]
        assert "*" not in allow and "${" in allow  # explicit hostnames with env override
    assert COMPOSE["networks"]["egress"].get("internal") is not True
    assert not any(n in SERVICES[a]["networks"] for a in AGENTS for n in ("egress", "edge", "data"))
    assert "anthropic" in SERVICES["egress-claude-1"]["environment"]["EGRESS_ALLOW"]
    assert "openai" in SERVICES["egress-codex"]["environment"]["EGRESS_ALLOW"]
    assert "openai" not in SERVICES["egress-claude-1"]["environment"]["EGRESS_ALLOW"]


def test_redis_and_rq_are_gone_from_the_architecture():
    assert "redis" not in SERVICES
    text = (ROOT / "compose.yaml").read_text().lower()
    assert "redis" not in text.replace("no redis", "")
    project = (ROOT / "pyproject.toml").read_text().lower()
    assert "redis" not in project and '"rq' not in project
    for f in (ROOT / "hunter").rglob("*.py"):
        src = f.read_text()
        assert "import redis" not in src and "from rq" not in src and "import rq" not in src, f


def test_postgres_is_unreachable_from_agents_and_proxies():
    for name in [*AGENTS, *PROXIES.values()]:
        assert "data" not in SERVICES[name]["networks"], name


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
    for name in AGENTS + list(PROXIES.values()) + ["api", "discovery", "scheduler", "telegram",
                                                   "migrate"]:
        assert SERVICES[name]["read_only"] is True, name
        assert SERVICES[name]["cap_drop"] == ["ALL"], name


def test_data_network_is_internal():
    assert COMPOSE["networks"]["data"].get("internal") is True


def test_published_ports_are_loopback_only_and_no_docker_socket():
    for name, svc in SERVICES.items():
        for port in svc.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), (name, port)
        assert not any("docker.sock" in str(v) for v in svc.get("volumes", []))
        assert not svc.get("privileged")


def test_images_are_tagged_by_release_not_mutable_local():
    for name in ("api", "discovery", *AGENTS, *PROXIES.values()):
        assert "${RELEASE_SHA" in SERVICES[name]["image"], name
        assert ":local" not in SERVICES[name]["image"]
