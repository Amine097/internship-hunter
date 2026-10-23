"""A hostile agent sweeps the network: the REAL compose topology on a REAL rootless Docker.

Original finding M-1: the smoke test's reach() called a refused connection and an unresolvable name
"blocked", probed only agent-codex and only by service name. Here the probe is what an attacker
inside an agent container would do - no names, no assumptions:

  * every service gets a live listener on every probed port, so a path that exists is ALWAYS
    answered (nothing is "closed", so nothing hides behind ECONNREFUSED);
  * from each of the three agents, every IP of every container on every network, every bridge
    gateway, the slirp4netns addresses, the host's own address, a public address and the metadata
    endpoint are probed by IP;
  * CONNECTED and REFUSED both mean "a route exists" (a refusal is an answer from the far side);
    only a timeout / "unreachable" is isolation, and an output the classifier does not recognise is
    a failure, never a pass;
  * the only addresses an agent may reach are its own proxy and the orchestrator on the agent's
    OWN network, and it must actually reach them (the positive control that proves the probe and
    the listeners work, so the silence everywhere else means something).

The negative control gives agent-codex a second network with a route out and requires the sweep to
notice. Opt-in and needs iptables like tests/test_dns_rootless_lab.py (HUNTER_ROOTLESS_LAB=1,
HUNTER_ROOTLESS_LAB_REQUIRED=1 in CI): it reuses that module's lab, guard and fixtures.
"""

import json
import os
import re

import pytest
import test_dns_rootless_lab as base

# the lab, the guard and the stack are that module's fixtures, shared by assignment so that pytest
# finds them here under the same names
lab = base.lab
stack = base.stack
_host_address = base._host_address

pytestmark = pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0, reason="rootless Docker needs an unprivileged user"
)

AGENTS = {"agent-claude-1": "egress-claude-1", "agent-claude-2": "egress-claude-2"}
AGENTS["agent-codex"] = "egress-codex"
PORTS = (3128, 8100)
LISTEN_PORTS = (3128, 8100, 22, 5432, 8000)

# busybox nc: connected = rc 0; the far side said no = "refused"; nothing came back = timeout
PROBE = r"""
probe() {
  out=$(nc -w 2 "$1" "$2" </dev/null 2>&1); rc=$?
  printf 'R %s:%s rc=%s %s\n' "$1" "$2" "$rc" "$(printf '%s' "$out" | tr '\n' ' ')"
}
for t in "$@"; do probe "${t%:*}" "${t##*:}" & done
wait
"""


def classify(rc, text):
    text = text.lower()
    if rc == 0:
        return "CONNECTED"
    if "refused" in text:
        return "REFUSED"
    if any(s in text for s in ("unreachable", "no route", "timed out")):
        return "BLOCKED"
    if text.strip() == "":
        return "BLOCKED"  # nc -w expired in silence: only trustworthy next to the positive controls
    return "UNKNOWN"


class Topology:
    """Everything the project's containers and networks look like to an attacker who can scan."""

    def __init__(self, lab):
        self.lab = lab
        ids = lab.run(
            ["docker", "compose", "-p", lab.project]
            + [a for f in getattr(lab, "current_files", lab.files) for a in ("-f", str(f))]
            + ["ps", "-q", "-a"]
        ).stdout.split()
        raw = json.loads(lab.run(["docker", "inspect", *ids]).stdout)
        self.containers = {}  # service -> {network name: ip}
        for c in raw:
            svc = c["Config"]["Labels"]["com.docker.compose.service"]
            self.containers[svc] = {
                n: v["IPAddress"] for n, v in c["NetworkSettings"]["Networks"].items()
            }
        nets = lab.run(
            [
                "docker",
                "network",
                "ls",
                "--filter",
                f"label=com.docker.compose.project={lab.project}",
            ]
            + ["--format", "{{.Name}}"]
        ).stdout.split()
        self.gateways = {}
        for n in nets:
            info = json.loads(lab.run(["docker", "network", "inspect", n]).stdout)[0]
            for cfg in info["IPAM"]["Config"] or []:
                if cfg.get("Gateway"):
                    self.gateways[n] = cfg["Gateway"]

    def own_network(self, agent):
        """The agent's private network (compose names it <project>_<agent, underscored>)."""
        return f"{self.lab.project}_{agent.replace('-', '_')}"


def start_listeners(stack, services):
    # `-ll -e`: accept connections forever and concurrently. A listener that serves one connection
    # and restarts would starve a second concurrent probe of the same port into a timeout, which
    # the sweep reads as "blocked": a breach hidden by the instrument (see concurrency_control).
    script = "".join(
        f"nc -ll -p {p} -e /bin/true >/dev/null 2>&1 </dev/null & " for p in LISTEN_PORTS
    )
    for svc in services:
        stack.run(
            ["docker", "compose", "-p", stack.project]
            + [a for f in stack.current_files for a in ("-f", str(f))]
            + ["exec", "-d", "-T", svc, "sh", "-c", script]
        )


def targets_for(topo, agent):
    """(label, "ip:port") for everything an attacker in `agent` would try."""
    mine = set(topo.containers[agent].values())
    out = []
    for svc, nets in topo.containers.items():
        for net, ip in nets.items():
            if ip and ip not in mine:
                out += [(f"{svc}@{net}", f"{ip}:{p}") for p in PORTS]
    for net, gw in topo.gateways.items():
        out += [(f"gateway@{net}", f"{gw}:{p}") for p in (22, *PORTS)]
    host = _host_address()
    extras = [
        ("slirp-gateway", "10.0.2.2:22"),
        ("slirp-dns", "10.0.2.3:53"),
        ("slirp-dns-tcp-8100", "10.0.2.3:8100"),
        ("public-ip", "1.1.1.1:443"),
        ("metadata", "169.254.169.254:80"),
    ]
    if host:
        extras += [("host-ssh", f"{host}:22"), ("host-8000", f"{host}:8000")]
    return out + extras


def run_probes(stack, agent, targets):
    """Probe every "ip:port" in `targets` at once from inside `agent` -> [(target, class), ...]."""
    r = stack.run(
        ["docker", "compose", "-p", stack.project]
        + [a for f in stack.current_files for a in ("-f", str(f))]
        + ["exec", "-T", agent, "sh", "-c", PROBE, "sh", *targets],
        timeout=180,
    )
    out = []
    for line in r.stdout.splitlines():
        m = re.match(r"R (\S+) rc=(\d+) ?(.*)$", line.strip())
        if m:
            out.append((m.group(1), classify(int(m.group(2)), m.group(3))))
    return out


def concurrency_control(stack, agent, expected):
    """The same ALLOWED target probed several times at once must connect every time. If the
    listeners (or the probe) cannot serve concurrent connections, silence elsewhere is void."""
    targets = sorted(expected) * 4
    results = run_probes(stack, agent, targets)
    assert len(results) == len(targets), f"{agent}: a control probe returned nothing"
    bad = [r for r in results if r[1] != "CONNECTED"]
    assert not bad, f"{agent}: the instrument fails its own positive control: {bad}"


def sweep(stack, topo, agent):
    """-> {target: (label, classification)} as seen from inside `agent`."""
    targets = targets_for(topo, agent)
    labels = {t: lbl for lbl, t in targets}
    seen = {t: (labels[t], c) for t, c in run_probes(stack, agent, list(labels))}
    if os.environ.get("SWEEP_VERBOSE"):  # SWEEP_VERBOSE=1 pytest -s : the whole table
        for t in sorted(seen, key=lambda t: (seen[t][1], seen[t][0])):
            print(f"{agent:15} {seen[t][1]:10} {seen[t][0]:34} {t}")
    missing = set(labels) - set(seen)
    assert not missing, f"{agent}: probes that returned nothing (not a pass): {missing}"
    return seen


def expected_reachable(topo, agent):
    net = topo.own_network(agent)
    peers = [AGENTS[agent], "discovery"]
    return {f"{topo.containers[p][net]}:{port}" for p in peers for port in PORTS}


def judge(seen, expected):
    reachable = {t for t, (_, c) in seen.items() if c in ("CONNECTED", "REFUSED")}
    unknown = {t: seen[t] for t, (_, c) in seen.items() if c == "UNKNOWN"}
    return reachable, unknown


@pytest.fixture
def swept_stack(stack):
    stack.up()
    stack.guard("apply")
    topo = Topology(stack)
    start_listeners(stack, topo.containers)
    return stack, topo


@pytest.mark.parametrize("agent", sorted(AGENTS))
def test_an_agent_reaches_only_its_own_proxy_and_the_orchestrator(swept_stack, agent):
    stack, topo = swept_stack
    expected = expected_reachable(topo, agent)
    concurrency_control(stack, agent, expected)
    seen = sweep(stack, topo, agent)
    reachable, unknown = judge(seen, expected)
    assert not unknown, f"unclassifiable probe output counts as a failure: {unknown}"
    # positive control: the allowed destinations ANSWER (so a silent target is meaningful)
    for t in expected:
        assert seen[t][1] == "CONNECTED", f"{agent} cannot connect to its own {seen[t][0]} {t}"
    extra = {t: seen[t] for t in reachable - expected}
    assert not extra, f"{agent} has a route to: {extra}"
    # and the probes that matter most were really made, by address
    labels = {lbl for lbl, _ in seen.values()}
    assert {"public-ip", "metadata", "slirp-gateway", "slirp-dns"} <= labels
    assert any(lbl.startswith("gateway@") for lbl in labels)


def test_the_sweep_notices_an_agent_that_gained_a_route_out(stack, tmp_path):
    """Negative control: the same sweep, an agent wired to the egress network by a bad override,
    must report destinations the healthy topology never exposes."""
    override = tmp_path / "mis.yaml"
    override.write_text(
        "services:\n  agent-codex:\n    networks: !override [agent_codex, egress]\n"
    )
    stack.up(extra_files=[override])
    stack.guard("apply")
    topo = Topology(stack)
    start_listeners(stack, topo.containers)
    concurrency_control(stack, "agent-codex", expected_reachable(topo, "agent-codex"))
    seen = sweep(stack, topo, "agent-codex")
    reachable, _ = judge(seen, None)
    extra = reachable - expected_reachable(topo, "agent-codex")
    assert extra, "the sweep did not notice that agent-codex now has a second network"
    assert any("@lab_egress" in seen[t][0] for t in extra), extra
