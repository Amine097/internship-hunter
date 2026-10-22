"""Can an agent (or a proxy) reach anything but what the topology gives it? Real rootless Docker.

Independent review of PR #14, item 7: "can agents bypass their dedicated proxy or access another
agent's proxy". The repository's REAL compose.yaml topology (networks, internal flags, service names)
runs on a throwaway rootless Docker 29.9.1 (tests/rootless_lab/lab.sh: own state dir, own socket under
/tmp/hl.XXXXXX, own project name) with every service replaced by Alpine and a LISTENER on every port
we probe, so "reachable" can only mean "the network let the packet through" - a refused connection
cannot be mistaken for isolation.

For every ordered pair (source container, target container on network N) the TCP connect must succeed
exactly when the source is attached to N. Everything else - the other agents, the other agents'
proxies, the data tier, the other proxies' egress networks, the bridge gateways - must be unreachable.
The api's published host port is remapped to an ephemeral one: this review must not collide with any
other lab on the machine.

Opt-in like the other labs: HUNTER_ROOTLESS_LAB=1 (+ HUNTER_ROOTLESS_LAB_REQUIRED=1 to turn a skip into a failure).
"""
import concurrent.futures
import itertools
import json
import os
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve()
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from test_dns_rootless_lab import ENABLED, LAB_COMPOSE, LAB_SH, REQUIRED, SECRETS, Lab  # noqa: E402

PORTS = (3128, 8100, 8000, 5432, 22)
LISTEN = ('for p in ' + " ".join(map(str, PORTS)) + '; do nc -ll -p "$$p" -e /bin/true >/dev/null 2>&1 & done; exec sleep 3000')
SERVICES = ["postgres", "migrate", "api", "discovery", "scheduler", "session-controller", "telegram",
            "agent-claude-1", "agent-claude-2", "agent-codex", "egress-claude-1", "egress-claude-2", "egress-codex"]

pytestmark = pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="rootless Docker needs an unprivileged user")


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    if not ENABLED:
        pytest.skip("set HUNTER_ROOTLESS_LAB=1 to run the rootless Docker lab")
    path = tmp_path_factory.mktemp("rev14lab")
    lab = Lab(path)
    lab.project = "rev14"
    override = path / "listeners.yaml"
    override.write_text("services:\n" + "".join(
        f"  {s}:\n    command: !override [sh, -c, '{LISTEN}']\n" + ('    ports: !override ["127.0.0.1::8000"]\n' if s == "api" else "")
        for s in SERVICES))
    if os.environ.get("REV14_MUTATE") == "1":      # self-test of the detector: wire an agent to another proxy's network
        override.write_text(override.read_text().replace("  agent-codex:\n", "  agent-codex:\n    networks: !override [agent_codex, egress_claude_1]\n", 1))
    lab.override = override
    try:
        lab.run([LAB_SH, "up"], timeout=420)
    except AssertionError as e:
        if REQUIRED:
            raise
        pytest.skip(f"the rootless lab did not start: {str(e)[:300]}")
    lab.env()
    lab.up(extra_files=[override])
    yield lab
    lab.down()
    lab.run([LAB_SH, "down"], check=False, timeout=120)


def inspect(lab):
    """container name -> {network: ip}."""
    out = lab.run(["docker", "ps", "--filter", f"label=com.docker.compose.project={lab.project}",
                   "--format", "{{.Names}}"]).stdout.split()
    info = {}
    for name in out:
        raw = lab.run(["docker", "inspect", name]).stdout
        nets = json.loads(raw)[0]["NetworkSettings"]["Networks"]
        info[name] = {n: v["IPAddress"] for n, v in nets.items() if v["IPAddress"]}
    return info


def sweep(lab, source, ips, port=3128):
    """The set of `ips` the container `source` can open a TCP connection to (one exec, 1 s per miss)."""
    script = "for ip in " + " ".join(ips) + f'; do nc -z -w 1 "$ip" {port} && echo "$ip"; done; true'
    r = lab.run(["docker", "exec", source, "sh", "-c", script], check=False, timeout=300)
    return set(r.stdout.split())


@pytest.fixture(scope="module")
def reach(lab):
    """source container -> reachable IPs, probed in parallel from every container to every IP."""
    info = inspect(lab)
    ips = sorted({ip for nets in info.values() for ip in nets.values()})
    with concurrent.futures.ThreadPoolExecutor(len(info)) as pool:
        futs = {s: pool.submit(sweep, lab, s, ips) for s in info}
        return info, {s: f.result() for s, f in futs.items()}


def test_listeners_answer_where_we_look_positive_control(lab, reach):
    info, got = reach
    assert len(info) >= 12, info.keys()
    p = lab.project
    own_ip = info[f"{p}-egress-codex-1"][f"{p}_agent_codex"]
    assert own_ip in got[f"{p}-agent-codex-1"], "the agent cannot reach its OWN proxy: the probe proves nothing"
    # every port we may later probe really has a listener
    for port in PORTS:
        assert sweep(lab, f"{p}-agent-codex-1", [own_ip], port) == {own_ip}, port


def test_reachability_matrix_equals_the_shared_networks_and_nothing_more(lab, reach):
    info, got = reach
    violations, controls = [], 0
    for s, t in itertools.permutations(info, 2):
        for net, ip in info[t].items():
            expect = net in info[s]
            seen = ip in got[s]
            controls += int(expect and seen)
            if seen != expect:
                violations.append((s, t, net, ip, "expected reachable" if expect else "UNEXPECTEDLY REACHABLE"))
    assert controls > 10, "too few positive controls: shared-network peers must answer"
    assert not violations, "\n".join(map(str, violations))


def test_agents_reach_exactly_their_own_proxy_and_discovery(lab, reach):
    info, got = reach
    p = lab.project
    for agent, peers in {"agent-codex": {"egress-codex", "discovery"}, "agent-claude-1": {"egress-claude-1", "discovery"},
                         "agent-claude-2": {"egress-claude-2", "discovery"}}.items():
        src = f"{p}-{agent}-1"
        reached = {t for t, nets in info.items() if t != src and got[src] & set(nets.values())}
        assert reached == {f"{p}-{x}-1" for x in peers}, f"{agent} reaches {sorted(reached)}"


def test_no_proxy_reaches_another_agent_or_another_proxy(lab, reach):
    info, got = reach
    p = lab.project
    for proxy, agent in {"egress-codex": "agent-codex", "egress-claude-1": "agent-claude-1",
                         "egress-claude-2": "agent-claude-2"}.items():
        src = f"{p}-{proxy}-1"
        reached = {t for t, nets in info.items() if t != src and got[src] & set(nets.values())}
        assert reached == {f"{p}-{agent}-1", f"{p}-discovery-1"}, f"{proxy} reaches {sorted(reached)}"


def test_the_data_tier_is_reachable_only_from_the_data_network(lab, reach):
    info, got = reach
    p = lab.project
    pg = set(info[f"{p}-postgres-1"].values())
    for s in info:
        if s == f"{p}-postgres-1":
            continue
        can = bool(got[s] & pg)
        assert can == (f"{p}_data" in info[s]), f"{s}: reaches postgres={can}"


def test_other_ports_are_no_different_for_an_agent(lab, reach):
    info, got = reach
    p = lab.project
    src = f"{p}-agent-codex-1"
    foreign = sorted(ip for t, nets in info.items() for n, ip in nets.items() if n not in info[src])
    for port in (8100, 8000, 5432, 22):
        assert sweep(lab, src, foreign, port) == set(), port
