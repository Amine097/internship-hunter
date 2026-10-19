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
        out_nets = [n for n in svc["networks"] if not COMPOSE["networks"][n].get("internal")]
        assert len(out_nets) == 1 and out_nets[0].startswith("egress_"), proxy
        assert SERVICES[agent]["networks"][0] in svc["networks"]
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


RSM = yaml.safe_load((ROOT / "compose.rsm.yaml").read_text())["services"]


def test_broker_socket_is_confined_to_the_session_controller():
    assert set(RSM) == {"session-controller"}
    mounts = [v for v in RSM["session-controller"]["volumes"]]
    assert mounts == ["/var/lib/hunter-rsm-ipc:/run/hunter-rsm:ro"]
    # nothing in the base file may mount a host path at all
    for name, svc in SERVICES.items():
        for v in svc.get("volumes", []):
            assert not str(v).startswith("/"), (name, v)
            assert "hunter-rsm" not in str(v), (name, v)
    for name in [*AGENTS, *PROXIES.values(), "api", "discovery", "telegram", "scheduler",
                 "postgres", "migrate"]:
        assert "hunter-rsm" not in yaml.safe_dump(SERVICES[name]), name


def test_no_docker_socket_anywhere_including_the_override():
    text = (ROOT / "compose.yaml").read_text() + (ROOT / "compose.rsm.yaml").read_text()
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "docker.sock" not in code and "/var/run/docker" not in code


def test_session_controller_has_database_only_and_no_agent_or_egress_reach():
    svc = SERVICES["session-controller"]
    assert svc["networks"] == ["data"]
    assert "ports" not in svc
    assert not SECRET_KEYS - {"DATABASE_URL"} & set(svc["environment"])
    assert not any(k.startswith("AGENT_TOKEN") for k in svc["environment"])
    assert svc["read_only"] is True and svc["cap_drop"] == ["ALL"]
    assert svc["environment"]["RSM_ENABLED"] == "false"     # opt-in only via the override


def test_broker_is_disabled_unless_the_override_is_used():
    assert SERVICES["session-controller"]["environment"]["RSM_ENABLED"] == "false"
    assert RSM["session-controller"]["environment"]["RSM_ENABLED"] == "true"


OUTBOUND_NETS = [n for n, cfg in COMPOSE["networks"].items() if not (cfg or {}).get("internal")]


def test_the_set_of_networks_with_a_route_out_is_explicit():
    """Every one of these is a way to dial the host unless deploy/host-egress-guard.sh is active;
    adding one must be a conscious decision that also updates docs/deployment.md."""
    assert set(OUTBOUND_NETS) == {"edge", "egress", "egress_claude_1", "egress_claude_2",
                                  "egress_codex"}
    guard = (ROOT / "deploy" / "host-egress-guard.sh").read_text()
    assert 'BRIDGES=("br-+" "docker0")' in guard     # Docker's naming; covers all of the above


def test_only_known_services_have_a_route_out():
    """A new service on a non-internal network is a new way to dial the host: make it explicit."""
    out = {n: sorted(s for s, v in SERVICES.items() if set(v.get("networks", [])) & {n})
           for n in OUTBOUND_NETS}
    assert out == {"edge": ["api"], "egress": ["discovery", "telegram"],
                   "egress_claude_1": ["egress-claude-1"], "egress_claude_2": ["egress-claude-2"],
                   "egress_codex": ["egress-codex"]}
    for agent in AGENTS:
        assert not set(SERVICES[agent]["networks"]) & set(OUTBOUND_NETS), agent


def test_proxies_do_not_share_a_network_with_each_other_or_with_trusted_services():
    """A compromised proxy must not be able to use another proxy's allow-list or reach discovery
    (discovery legitimately shares each AGENT network with an agent and its proxy)."""
    own = {p: set(SERVICES[p]["networks"]) & set(OUTBOUND_NETS) for p in PROXIES.values()}
    for a in own:
        assert len(own[a]) == 1
        for other, svc in SERVICES.items():
            if other != a:
                assert not own[a] & set(svc.get("networks", [])), (a, other)
        assert not set(SERVICES[a]["networks"]) & {"data", "edge", "egress"}, a


def test_proxy_healthcheck_detects_a_reachable_host_and_the_target_list_is_passed_through():
    dockerfile = (ROOT / "docker" / "egress-proxy.Dockerfile").read_text()
    assert "egress-healthcheck.sh" in dockerfile
    for proxy in PROXIES.values():
        svc = SERVICES[proxy]
        assert svc["healthcheck"]["test"] == ["CMD-SHELL", "/usr/local/bin/egress-healthcheck.sh"]
        assert svc["environment"]["EGRESS_FORBIDDEN_TARGETS"] == "${EGRESS_FORBIDDEN_TARGETS:-}"
    for agent, proxy in PROXIES.items():     # agents wait for a healthy (i.e. isolated) proxy
        assert SERVICES[agent]["depends_on"][proxy] == {"condition": "service_healthy"}
