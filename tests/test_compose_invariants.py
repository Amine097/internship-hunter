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


def test_api_is_published_on_loopback_18000_and_nothing_publishes_host_port_8000():
    """The production host has a rootful Gluetun on <tailscale ip>:8000: the application's default
    host port must be different, and every tool must reach the API through that port."""
    assert SERVICES["api"]["ports"] == ["127.0.0.1:18000:8000"]      # container side stays 8000
    for name, svc in SERVICES.items():
        for port in svc.get("ports", []):
            host_side = str(port).split(":")[-2]
            assert host_side != "8000", (name, port)
    for rel in ("deploy/remote-deploy.sh", "deploy/smoke-test.sh", "README.md"):
        text = (ROOT / rel).read_text()
        assert "127.0.0.1:8000" not in text, rel
    assert "API_PORT=18000" in (ROOT / "deploy" / "remote-deploy.sh").read_text()
    assert "http://127.0.0.1:18000" in (ROOT / "deploy" / "smoke-test.sh").read_text()


def test_smoke_test_only_sends_the_admin_token_to_the_composes_own_api():
    smoke = (ROOT / "deploy" / "smoke-test.sh").read_text()
    guard_at = smoke.index("refusing to send ADMIN_TOKEN")
    first_token_use = smoke.index('-H "X-Admin-Token:')
    assert guard_at < first_token_use                    # identity is proven before any token use
    assert '"${COMPOSE[@]}" port api 8000' in smoke
    assert "^http://127\\.0\\.0\\.1:" in smoke and "localhost)" not in smoke   # literal IPv4 only


# ---- L-f / N-11: nothing in the compose files may bypass the guard's interface matching ----------
RSM_FILE = yaml.safe_load((ROOT / "compose.rsm.yaml").read_text())
ALL_COMPOSE = {"compose.yaml": COMPOSE, "compose.rsm.yaml": RSM_FILE}


def test_no_service_uses_host_or_foreign_network_modes():
    """network_mode: host/none/container:/service: would put a container outside the bridges the
    guard matches (br-*, docker0) - or in someone else's network namespace."""
    for fname, doc in ALL_COMPOSE.items():
        for name, svc in (doc.get("services") or {}).items():
            assert "network_mode" not in svc, (fname, name, svc.get("network_mode"))
            assert "pid" not in svc or svc["pid"] != "host", (fname, name)
            assert not svc.get("ipc") == "host", (fname, name)


def test_every_network_is_a_plain_docker_bridge_with_default_naming():
    """A custom bridge name (com.docker.network.bridge.name), a non-bridge driver, an external
    network or enabled IPv6 would route traffic around the guard's `-i br-+ / docker0` rules."""
    for fname, doc in ALL_COMPOSE.items():
        for net, cfg in (doc.get("networks") or {}).items():
            cfg = cfg or {}
            where = (fname, net)
            assert cfg.get("driver", "bridge") == "bridge", where
            assert not cfg.get("driver_opts"), where                  # incl. bridge.name
            assert not cfg.get("external"), where
            assert not cfg.get("enable_ipv6"), where
            assert not cfg.get("ipam", {}).get("driver"), where
            assert "name" not in cfg or cfg["name"].startswith("internship-hunter"), where
    text = (ROOT / "compose.yaml").read_text() + (ROOT / "compose.rsm.yaml").read_text()
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "com.docker.network.bridge.name" not in code
    assert "network_mode" not in code


def test_services_with_a_route_out_cannot_reconfigure_the_network():
    for name in ("api", "discovery", "telegram", *PROXIES.values()):
        svc = SERVICES[name]
        assert not set(svc.get("cap_add", [])) & {"NET_ADMIN", "NET_RAW", "SYS_ADMIN"}, name
        assert not svc.get("sysctls"), name
        assert svc.get("cap_drop") == ["ALL"], name
        assert not svc.get("devices"), name


# ---- DNS (docs/deployment.md, "DNS"; proven on a real rootless daemon: test_dns_rootless_lab.py)
def _has_route_out(svc):
    return any(not COMPOSE["networks"][n].get("internal", False) for n in svc.get("networks", []))


def test_every_service_with_a_route_out_names_its_resolver_and_no_other_service_does():
    """Docker's embedded resolver forwards from the DAEMON's namespace - outside the host guard -
    unless `dns:` is explicit. Only services with a route out may carry one (internal-only
    services get no external forwarding at all, and must not look like they are meant to)."""
    out = {n for n, s in SERVICES.items() if _has_route_out(s)}
    assert out == {"api", "discovery", "telegram", "egress-claude-1", "egress-claude-2",
                   "egress-codex"}
    with_dns = {n for n, s in SERVICES.items() if "dns" in s}
    assert with_dns == out
    for n in out:
        assert SERVICES[n]["dns"] == ["${HUNTER_DNS:-10.0.2.3}"], n    # one resolver, one variable


def test_the_default_resolver_is_the_slirp4netns_one_the_guard_conf_documents():
    deployment = (ROOT / "docs" / "deployment.md").read_text()
    assert "DNS=10.0.2.3" in deployment and "HUNTER_DNS" in deployment
    assert "HUNTER_DNS" in (ROOT / ".env.example").read_text()


def test_nothing_rewrites_the_search_path_or_resolver_options():
    for name, svc in SERVICES.items():
        assert not {"dns_search", "dns_opt", "extra_hosts", "domainname"} & set(svc), name


def test_the_services_the_docker_daemon_must_not_start_by_itself_have_no_restart_policy():
    """Services with a route out and agents are started only by deploy/runtime-containment.sh,
    after the host guard is verified; the data tier keeps Docker's restart policy."""
    nets = COMPOSE["networks"]
    for name, svc in COMPOSE["services"].items():
        routed = any(not (nets[n] or {}).get("internal") for n in svc.get("networks", []))
        if routed or name.startswith("agent-"):
            assert svc.get("restart") == "no", f"{name}: the daemon would start it after a reboot"
        elif name == "migrate":
            assert svc.get("restart") == "no"
        else:
            assert svc.get("restart") == "unless-stopped", name
