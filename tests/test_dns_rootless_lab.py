"""DNS on the REAL rootless Docker layout, with real Compose networks and real DNS packets.

tests/rootless_lab/lab.sh starts a genuine rootless Docker 29.9.1 (rootlesskit --net=slirp4netns
--detach-netns, the production layout) as an unprivileged user; the project's real compose.yaml
runs on it with every image swapped for Alpine and every process for `sleep`
(tests/rootless_lab/compose.lab.yaml), so what is exercised is the NETWORK behaviour of the real
file: its networks, internal flags, `dns:` entries and service names. The real host-egress-guard.sh
is applied to the daemon's real namespace and the real deploy/check-dns.sh judges the result.

What it establishes (docs/deployment.md, "DNS"):
  * Docker's embedded resolver (127.0.0.11) forwards from the DAEMON'S namespace when the servers
    come from the daemon's resolv.conf (`ExtServers: [host(...)]`): those queries bypass the guard.
  * with an explicit `dns:` the queries leave the container, cross the guard and only the
    resolver the guard was told about gets through (a private LAN resolver does not).
  * internal-only services get no external forwarding and no direct path; service names resolve
    only between services that share a network.
  * daemon-level `dns` (daemon.json) hands EVERY container, agents included, an explicit upstream
    that compose never mentions: check-dns.sh sees it in the runtime resolv.conf and refuses it.
  * the raw-UDP probe has a positive control: it must get an answer from the approved resolver
    from a service with a route out, or its "no answer" from the agents proves nothing.

Opt-in (it downloads ~100 MB of pinned, checksummed tools once): HUNTER_ROOTLESS_LAB=1.
HUNTER_ROOTLESS_LAB_REQUIRED=1 (CI) turns "cannot run" into a failure. iptables must be on PATH
(or GUARD_IPTABLES_DIR, as in test_host_egress_guard_netns.py).
"""

import contextlib
import json
import os
import re
import shutil
import socket
import subprocess
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LABDIR = ROOT / "tests" / "rootless_lab"
LAB_SH = LABDIR / "lab.sh"
LAB_COMPOSE = LABDIR / "compose.lab.yaml"
GUARD = ROOT / "deploy" / "host-egress-guard.sh"
CHECK_DNS = ROOT / "deploy" / "check-dns.sh"
ENABLED = os.environ.get("HUNTER_ROOTLESS_LAB") == "1"
REQUIRED = os.environ.get("HUNTER_ROOTLESS_LAB_REQUIRED") == "1"
IPT_DIR = os.environ.get("GUARD_IPTABLES_DIR")
SLIRP_DNS = "10.0.2.3"
OUT = ["api", "discovery", "telegram", "egress-claude-1", "egress-claude-2", "egress-codex"]
IN = [
    "agent-claude-1",
    "agent-claude-2",
    "agent-codex",
    "postgres",
    "migrate",
    "scheduler",
    "session-controller",
]
SECRETS = {
    "POSTGRES_PASSWORD": "x",
    "ADMIN_TOKEN": "x",
    "AGENT_TOKEN_CLAUDE_1": "x",
    "AGENT_TOKEN_CLAUDE_2": "x",
    "AGENT_TOKEN_CODEX": "x",
}

pytestmark = pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0, reason="rootless Docker needs an unprivileged user"
)


class Lab:
    def __init__(self, path):
        self.path = Path(path)
        self.xdg = None
        self.project = "lab"
        self.files = [ROOT / "compose.yaml", LAB_COMPOSE]

    # ---- plumbing -------------------------------------------------------------------------
    def env(self, **extra):
        env = {k: v for k, v in os.environ.items() if k not in ("DOCKER_HOST", "HUNTER_DNS")}
        if IPT_DIR:
            env["PATH"] = IPT_DIR + os.pathsep + env["PATH"]
        env["HUNTER_LAB_DIR"] = str(self.path)
        if (self.path / "xdg-path").exists():
            self.xdg = (self.path / "xdg-path").read_text().strip()
            env.update(
                XDG_RUNTIME_DIR=self.xdg,
                DOCKER_HOST=f"unix://{self.xdg}/docker.sock",
                DOCKER_CONFIG=str(self.path / "cli"),
                PATH=f"{self.path / 'bin'}{os.pathsep}{env['PATH']}",
            )
        env.update(SECRETS)
        env.update(extra)
        return env

    def run(self, argv, timeout=300, check=True, **env):
        r = subprocess.run(
            [str(a) for a in argv],
            capture_output=True,
            text=True,
            env=self.env(**env),
            cwd=ROOT,
            timeout=timeout,
        )
        if check and r.returncode != 0:
            raise AssertionError(f"{argv} -> {r.returncode}\n{r.stdout}\n{r.stderr}")
        return r

    # ---- daemon -------------------------------------------------------------------------------
    def restart_daemon(self, dns="", resolv_conf=None):
        """A new daemon process in a new network namespace (so: no guard, no DNAT). `resolv_conf`
        is the daemon's own upstream list, set explicitly instead of inherited from the machine."""
        extra = {"HUNTER_LAB_RESOLV_CONF": str(resolv_conf)} if resolv_conf else {}
        self.run([LAB_SH, "restart", dns], timeout=180, **extra)

    # ---- the stack ------------------------------------------------------------------------------
    def compose(self, *args, files=None, check=True, **env):
        argv = ["docker", "compose", "-p", self.project]
        for f in files or self.files:
            argv += ["-f", f]
        return self.run(argv + list(args), check=check, **env)

    def up(self, extra_files=(), **env):
        files = [*self.files, *extra_files]
        self.compose("up", "-d", "--no-build", "--remove-orphans", files=files, **env)
        self.current_files, self.current_env = files, env

    def down(self):
        self.compose(
            "down",
            "-t",
            "1",
            "--remove-orphans",
            check=False,
            files=getattr(self, "current_files", self.files),
            **getattr(self, "current_env", {}),
        )

    def exec(self, service, *cmd, check=False):
        return self.run(
            ["docker", "compose", "-p", self.project, "exec", "-T", service, *cmd],
            check=check,
            timeout=60,
        )

    def nslookup(self, service, name, server=None):
        argv = ["nslookup", "-timeout=3", f"{name}."] + ([server] if server else [])
        r = self.exec(service, *argv)
        return r.returncode == 0 and re.search(r"^Address: [0-9a-fA-F]", r.stdout, re.M) is not None

    # ---- guard (the real script, against the daemon's real namespace) --------------------------
    def guard(self, command, dns=SLIRP_DNS, check=True):
        return self.run(
            ["bash", GUARD, command, "--dns", dns], check=check, HUNTER_GUARD_TEST_MODE="1"
        )

    def netns(self, *cmd, check=True):
        """Run a command inside the daemon's detached network namespace (read-only use here)."""
        pid = (Path(self.xdg) / "dockerd-rootless" / "child_pid").read_text().strip()
        netns = f"/proc/{pid}/root{self.xdg}/dockerd-rootless/netns"
        return self.run(
            [
                "nsenter",
                "--preserve-credentials",
                "-t",
                pid,
                "--user",
                "--mount",
                f"--net={netns}",
                "--",
                *cmd,
            ],
            check=check,
        )

    def assert_leaves_by_the_uplink(self, address):
        """`address` must be routed out of the daemon's uplink (tap0), not into a Docker bridge. A
        bridge whose subnet covers a host address swallows the packet: the symptom is a control
        query that is never answered, which would be mistaken for the guard working."""
        route = self.netns("ip", "route", "get", address).stdout
        assert " dev tap0 " in f" {route} ", f"{address} does not leave by the uplink: {route}"

    def guard_dns_hits(self, resolver=SLIRP_DNS):
        out = self.netns("iptables", "-L", "HUNTER-EGRESS-GUARD", "-n", "-v", "-x").stdout
        for ln in out.splitlines():
            if f" {resolver} " in ln and "dpt:53" in ln:
                return int(ln.split()[0])
        return 0

    def zero_counters(self):
        self.netns("iptables", "-Z")

    def check_dns(self, mode="enforce", **env):
        argv = ["bash", CHECK_DNS, "-p", self.project]
        for f in getattr(self, "current_files", self.files):
            argv += ["-f", f]
        return self.run(
            argv,
            check=False,
            timeout=240,
            SMOKE_HOST_ISOLATION=mode,
            **{**getattr(self, "current_env", {}), **env},
        )

    def container_resolv_conf(self):
        """The /etc/resolv.conf an ad hoc container on the default bridge actually receives."""
        return self.run(
            ["docker", "run", "--rm", "alpine-local:3.20", "cat", "/etc/resolv.conf"]
        ).stdout

    @contextlib.contextmanager
    def lan_resolver_at(self, resolver):
        """Route LAN_RESOLVER:53 to the live `resolver` with a DNAT in the daemon's CURRENT network
        namespace (the guard's filter chains run after it). A restarted daemon has a new namespace,
        so this goes after any restart."""
        rule = [
            "PREROUTING", "-d", LAN_RESOLVER, "-p", "udp", "--dport", "53",
            "-j", "DNAT", "--to-destination", f"{resolver.bind_ip}:{resolver.port}",
        ]  # fmt: skip
        self.netns("iptables", "-t", "nat", "-I", *rule)
        try:
            yield
        finally:
            self.netns("iptables", "-t", "nat", "-D", *rule, check=False)


NODNS = ROOT / "tests" / "rootless_lab" / "compose.nodns.yaml"
LAN_RESOLVER = "192.168.1.1"  # the address a home/office router would answer DNS on


def _dns_answer(query):
    """A minimal DNS response: one A record (192.0.2.53) for any A question, none otherwise."""
    qend = 12
    while query[qend] != 0:
        qend += query[qend] + 1
    qend += 5  # the root label, QTYPE and QCLASS
    question, qtype = query[12:qend], int.from_bytes(query[qend - 4 : qend - 2], "big")
    answers = qtype == 1
    head = query[:2] + b"\x81\x80\x00\x01" + (b"\x00\x01" if answers else b"\x00\x00")
    head += b"\x00\x00\x00\x00"
    rr = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x35" if answers else b""
    return head + question + rr


class LanResolver:
    """A REAL resolver on the host that counts every datagram that reaches it.

    The lab has no LAN, so "a private LAN resolver is refused" was only ever shown by a query that
    got no answer from an address (192.168.1.1) that probably does not exist on the runner: the
    same result with or without the guard. This gives the address a live resolver behind it: a DNAT
    in the daemon's namespace (which the guard's filter chains run after) sends 192.168.1.1:53 to a
    socket of this test on the host's own address, reached through the same slirp4netns uplink as
    any other host-side destination. The test can now (1) prove the resolver answers when no guard
    is applied (the positive control) and (2) prove with the SERVER'S OWN COUNTER that nothing
    reached it once the guard is applied."""

    def __init__(self, bind_ip):
        self.bind_ip = bind_ip
        self.received = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((bind_ip, 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                data, peer = self.sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                return
            self.received += 1
            try:
                self.sock.sendto(_dns_answer(data), peer)
            except (IndexError, OSError):
                pass

    def close(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()


def _host_address():
    """The host's own outbound IPv4 address (a connect() on UDP sends nothing)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


@pytest.fixture
def lan_host_resolver(lab):
    """A live resolver on the host (see LanResolver); not routed anywhere yet."""
    host = _host_address()
    if not host or host.startswith("127."):
        msg = f"no non-loopback host address for the LAN resolver stand-in ({host})"
        if REQUIRED:
            pytest.fail(msg)
        pytest.skip(msg)
    resolver = LanResolver(host)
    try:
        yield resolver
    finally:
        resolver.close()


@pytest.fixture
def lan_resolver(lab, lan_host_resolver):
    """A live resolver at LAN_RESOLVER:53 as seen from the containers of the CURRENT daemon."""
    with lab.lan_resolver_at(lan_host_resolver):
        yield lan_host_resolver


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    if not ENABLED:
        pytest.skip("set HUNTER_ROOTLESS_LAB=1 to run the rootless Docker lab")
    problems = [
        t
        for t in ("curl", "tar", "unshare", "nsenter", "iptables", "sha256sum")
        if not shutil.which(t, path=(IPT_DIR + os.pathsep if IPT_DIR else "") + os.environ["PATH"])
    ]
    if not problems:
        probe = subprocess.run(["unshare", "-Ur", "true"], capture_output=True)
        problems = [] if probe.returncode == 0 else ["unprivileged user namespaces"]
    if problems:
        if REQUIRED:
            pytest.fail(
                f"HUNTER_ROOTLESS_LAB_REQUIRED=1 but the lab cannot run: missing {problems}"
            )
        pytest.skip(f"cannot run the rootless lab: missing {problems}")
    path = tmp_path_factory.mktemp("lab")
    lab = Lab(path)
    try:
        lab.run([LAB_SH, "up"], timeout=420)
    except AssertionError as e:
        if REQUIRED:
            raise
        pytest.skip(f"the rootless lab did not start: {str(e)[:300]}")
    lab.env()
    yield lab
    lab.down()
    keep = os.environ.get("HUNTER_LAB_LOG_DIR")  # CI: the daemon's logs outlive the lab
    if keep:
        Path(keep).mkdir(parents=True, exist_ok=True)
        for name in ("dockerd.log", "runc.args"):
            if (path / name).exists():
                shutil.copy(path / name, Path(keep) / name)
        conf = path / "home" / ".config" / "docker" / "daemon.json"
        shutil.copy(conf, Path(keep) / "daemon.json")
    lab.run([LAB_SH, "down"], check=False, timeout=120)


@pytest.fixture
def stack(lab):
    """Bring the real topology up; the test decides the guard, the override and HUNTER_DNS."""
    lab.guard("remove", check=False)
    yield lab
    lab.down()
    lab.guard("remove", check=False)


# ---- the lab is the production layout --------------------------------------------------------
def test_the_lab_is_a_real_rootless_daemon_in_the_detached_namespace_layout(lab):
    info = lab.run(["docker", "info", "--format", "{{.ServerVersion}} {{.SecurityOptions}}"]).stdout
    assert info.startswith("29.9.1") and "rootless" in info
    r = lab.guard("plan")
    assert "detached layout" in r.stdout
    assert "net:[" in r.stdout


# ---- the finding: embedded DNS without an explicit resolver bypasses the guard ---------------
def test_embedded_dns_without_explicit_resolver_is_queried_from_the_daemon_and_bypasses_the_guard(
    stack,
):
    stack.up(extra_files=[NODNS])
    stack.guard("apply", dns="10.99.99.99")  # a guard that allows NO resolver the stack uses
    stack.zero_counters()
    for svc in OUT:
        assert "host(" in stack.exec(svc, "cat", "/etc/resolv.conf").stdout, svc
        assert stack.nslookup(svc, "example.com"), (
            f"{svc} resolves although the guard allows no resolver"
        )
    assert stack.guard_dns_hits() == 0  # the packets never crossed the guard
    r = stack.check_dns()
    assert r.returncode == 1 and "host(" in r.stderr and "breach" in r.stderr


def test_the_same_guard_blocks_dns_when_the_resolver_is_explicit(stack):
    stack.up()
    stack.guard("apply", dns="10.99.99.99")
    for svc in OUT:
        assert not stack.nslookup(svc, "example.com"), (
            f"{svc} resolved through a resolver the guard does not allow"
        )
    r = stack.check_dns()
    assert r.returncode == 1 and "cannot resolve" in r.stderr  # fail closed, loudly
    r = stack.check_dns(mode="report")  # CI-style: a warning, not a pass-through
    assert r.returncode == 0 and "WARN" in r.stderr


# ---- the solution: explicit resolver, policed by the guard -----------------------------------
def test_explicit_resolver_works_through_the_guard_and_check_dns_passes(stack):
    stack.up()
    stack.guard("apply")
    stack.guard("status")
    stack.zero_counters()
    for svc in OUT:
        assert "ExtServers: [10.0.2.3]" in stack.exec(svc, "cat", "/etc/resolv.conf").stdout, svc
        assert stack.nslookup(svc, "example.com"), svc
    assert stack.guard_dns_hits() > 0  # they crossed the guard's DNS exception
    # the positive control of the raw-UDP probe, with real packets: a service with a route out DOES
    # get a direct answer from the approved resolver, which gives the agents' silence its meaning
    for svc in OUT:
        assert stack.nslookup(svc, "example.com", server=SLIRP_DNS), svc
    r = stack.check_dns()
    assert r.returncode == 0, r.stdout + r.stderr
    assert "internal-only service(s) resolve nothing outside the project" in r.stdout


def test_a_private_lan_resolver_stays_unreachable_even_when_configured(stack, lan_resolver):
    """Never weaken the guard for LAN DNS: pointing the stack at one fails closed.

    F-4(a): "no answer" only means something if the same query IS answered when the guard is not
    there. The resolver is live (see LanResolver), so the test runs control -> guard -> control:
    answered, refused (and the resolver's own counter does not move), answered again."""
    lan = LAN_RESOLVER
    stack.up(HUNTER_DNS=lan)  # the `stack` fixture removed the guard: nothing stands in the way
    stack.assert_leaves_by_the_uplink(lan_resolver.bind_ip)
    # CONTROL, no guard: every service with a route out resolves through the LAN resolver, with the
    # configured and with a directly named server, and the resolver counted the packets
    for svc in OUT:
        assert f"ExtServers: [{lan}]" in stack.exec(svc, "cat", "/etc/resolv.conf").stdout, svc
        answered = stack.nslookup(svc, "control.example.com")
        assert answered, (
            f"{svc}: control query unanswered; the live resolver has seen "
            f"{lan_resolver.received} datagram(s)\n"
            + stack.netns("iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v").stdout
            + stack.exec(svc, "nslookup", "-timeout=3", "control.example.com.").stdout
        )
    assert stack.nslookup("egress-codex", "control-direct.example.com", server=lan)
    assert lan_resolver.received >= len(OUT) + 1, "the control did not reach the live resolver"

    stack.guard("apply")
    before = lan_resolver.received
    for svc in OUT:
        assert not stack.nslookup(svc, "guarded.example.com"), svc
    assert stack.check_dns(HUNTER_DNS=lan).returncode == 1
    # and querying that resolver directly is refused by the guard as well
    assert not stack.nslookup("egress-codex", "guarded-direct.example.com", server=lan)
    # refused, not merely unanswered: not one datagram arrived at the resolver
    assert lan_resolver.received == before, "the guard let queries through to the LAN resolver"

    stack.guard("remove")  # the guard, and only the guard, is what stopped them
    assert stack.nslookup("egress-codex", "after-removal.example.com")
    assert lan_resolver.received > before


def test_internal_only_services_have_no_dns_way_out_and_see_only_their_neighbours(stack):
    stack.up()
    stack.guard("apply")
    for svc in IN:
        resolv = stack.exec(svc, "cat", "/etc/resolv.conf").stdout
        assert "nameserver 127.0.0.11" in resolv and "nameserver 10." not in resolv, svc
        # measured: Docker lists the daemon's own resolver as host(...) for every container, never
        # forwards from an internal-only one; what must never appear here is an EXPLICIT upstream
        assert not re.search(r"ExtServers: \[(?!host\()", resolv), f"{svc}: {resolv}"
        assert not stack.nslookup(svc, "example.com"), f"{svc} resolved a public name"
        assert not stack.nslookup(svc, "example.com", server=SLIRP_DNS), (
            f"{svc} reached the resolver"
        )
        assert not stack.nslookup(svc, "example.com", server="1.1.1.1"), f"{svc} reached 1.1.1.1"
    # embedded DNS still resolves what is on the agent's own networks, and nothing else
    assert stack.nslookup("agent-claude-1", "egress-claude-1")
    assert stack.nslookup("agent-claude-1", "discovery")
    for hidden in (
        "egress-codex",
        "egress-claude-2",
        "agent-codex",
        "agent-claude-2",
        "postgres",
        "api",
    ):
        assert not stack.nslookup("agent-claude-1", hidden), hidden
    # the proxies see their agent and discovery, not each other
    assert stack.nslookup("egress-claude-1", "agent-claude-1")
    assert not stack.nslookup("egress-claude-1", "egress-codex")
    assert not stack.nslookup("egress-claude-1", "postgres")


# ---- the check catches regressions -----------------------------------------------------------
def test_check_dns_catches_a_resolver_configured_on_an_internal_only_service(stack, tmp_path):
    f = tmp_path / "mis.yaml"
    f.write_text("services:\n  agent-codex:\n    dns: [10.0.2.3]\n")
    stack.up(extra_files=[f])
    stack.guard("apply")
    r = stack.check_dns()
    assert r.returncode == 1 and "internal-only but has dns" in r.stderr, r.stdout + r.stderr


def test_check_dns_catches_an_internal_only_service_that_gained_a_route_out_at_runtime(stack):
    """compose says internal-only, the runtime disagrees (a `docker network connect`)."""
    stack.up()
    stack.guard("apply")
    stack.run(["docker", "network", "connect", "lab_egress", "lab-agent-codex-1"])
    r = stack.check_dns()
    assert (
        r.returncode == 1 and "agent-codex is internal-only but resolves example.com" in r.stderr
    ), r.stdout + r.stderr


def test_check_dns_refuses_a_topology_that_gave_an_agent_a_route_out(stack, tmp_path):
    f = tmp_path / "mis.yaml"
    f.write_text("services:\n  agent-codex:\n    networks: !override [agent_codex, egress]\n")
    stack.up(extra_files=[f])
    stack.guard("apply")
    r = stack.check_dns()
    assert r.returncode == 1 and "expected to be internal-only" in r.stderr, r.stdout + r.stderr


def test_check_dns_rejects_a_resolver_other_than_the_one_it_was_told_to_expect(stack):
    stack.up(HUNTER_DNS="1.1.1.1")  # public resolver: works, but is not the expected one
    stack.guard("apply")
    r = stack.check_dns(HUNTER_DNS=SLIRP_DNS)
    assert r.returncode == 1 and "Docker forwards its DNS to [1.1.1.1]" in r.stderr


# ---- daemon-level dns: do NOT configure it -----------------------------------------------------
def test_daemon_level_dns_gives_agents_an_explicit_upstream_and_check_dns_refuses_it(lab):
    """Claude 2's F-1, measured. daemon.json {"dns": [...]} changes every container's resolver
    state without a line of compose changing; the declaration-only check could not see it."""
    try:
        lab.restart_daemon(dns=SLIRP_DNS)
        lab.guard("apply")
        lab.up()
        lab.zero_counters()
        cfg = lab.compose("config", "--format", "json").stdout
        declared = json.loads(cfg)["services"]
        for svc in IN:
            assert not declared[svc].get("dns"), f"compose declares no dns for {svc}"
            # ... but the RUNTIME resolver state of the agents now names an explicit upstream
            resolv = lab.exec(svc, "cat", "/etc/resolv.conf").stdout
            assert "ExtServers: [10.0.2.3]" in resolv and "Overrides: [nameservers]" in resolv, (
                svc,
                resolv,
            )
        # what Docker 29.9.1 still does NOT do: forward from an internal-only container. No name
        # outside the project resolves, no packet reached the guard's DNS exception, no direct path.
        for svc in IN:
            assert not lab.nslookup(svc, "example.com"), svc
            assert not lab.nslookup(svc, "example.com", server=SLIRP_DNS), svc
        assert lab.guard_dns_hits() == 0
        assert lab.nslookup("agent-codex", "egress-codex")  # local discovery is untouched
        # the check reads the runtime state and refuses, in every mode
        for mode in ("enforce", "report"):
            r = lab.check_dns(mode=mode)
            assert r.returncode == 1, r.stdout + r.stderr
            for svc in IN:
                assert f"{svc} is internal-only but Docker gave it explicit upstream" in r.stderr
            assert "daemon-level dns (daemon.json)" in r.stderr
        # the second reason not to: every ad hoc container now holds the guard's DNS exception too
        r = lab.run(
            [
                "docker",
                "run",
                "--rm",
                "alpine-local:3.20",
                "nslookup",
                "-timeout=3",
                "example.com.",
            ],
            check=False,
        )
        assert r.returncode == 0 and "Address: " in r.stdout, r.stdout + r.stderr
        assert lab.guard_dns_hits() > 0
    finally:
        lab.down()
        lab.restart_daemon(dns="")


def test_without_daemon_level_dns_ad_hoc_containers_get_no_dns_and_per_container_dns_works(
    lab, lan_host_resolver
):
    """The documented state: nothing configured at daemon level; `--dns 10.0.2.3` per container.

    F-4(b): this used to test the private-upstream half only `if upstream_is_private()`, i.e. never
    on a runner whose upstream is 127.0.0.53 (all of GitHub's), and nobody noticed. The daemon's
    upstream is now SET by the test (`resolv-conf`: a private address with a live resolver behind
    it), so the same thing happens on every machine and there is no branch to skip: an ad hoc
    container inherits it and is refused by the guard, and answered without the guard."""
    run = ["docker", "run", "--rm", "alpine-local:3.20", "nslookup", "-timeout=3", "example.com."]
    explicit = [*run[:3], "--dns", SLIRP_DNS, *run[3:]]
    upstream = lab.path / "lan-upstream-resolv.conf"
    upstream.write_text(f"nameserver {LAN_RESOLVER}\n")
    try:
        lab.restart_daemon(resolv_conf=upstream)
        with lab.lan_resolver_at(lan_host_resolver):
            lab.assert_leaves_by_the_uplink(lan_host_resolver.bind_ip)
            # the premise, from the container's side: it inherited the LAN upstream
            inherited = lab.container_resolv_conf()
            assert f"nameserver {LAN_RESOLVER}" in inherited, inherited
            assert "Using OriginResolvConfPath from env" in (lab.path / "dockerd.log").read_text()
            # CONTROL, no guard: the inherited LAN upstream answers, so a refusal below is the guard
            r = lab.run(run, check=False)
            assert r.returncode == 0 and "Address: " in r.stdout, r.stdout + r.stderr
            assert lan_host_resolver.received >= 1, "the answer did not come from the LAN resolver"
            lab.guard("apply")
            before = lan_host_resolver.received
            r = lab.run(run, check=False)
            assert r.returncode != 0, "an ad hoc container reached the host's LAN resolver"
            assert lan_host_resolver.received == before, (
                "the guard let the query reach the resolver"
            )
            r = lab.run(explicit, check=False)
            assert r.returncode == 0 and "Address: " in r.stdout, r.stdout + r.stderr
    finally:
        lab.guard("remove", check=False)
        lab.restart_daemon()  # the next test starts from the machine's own daemon configuration


# ---- the raw-UDP probe has a positive control (Claude 2's F-2) ---------------------------------
def test_a_probe_that_cannot_receive_direct_answers_is_a_defect_not_a_pass(stack, tmp_path):
    """Every 'no direct answer' the agents produce is only evidence if the SAME probe gets an
    answer from the approved resolver where the network allows it. Sabotage the probe tool in every
    container (a nslookup that never answers when a server is named) and the agents' silence must
    not certify anything: DEFECT in every mode, distinct from the network blocking a query."""
    wrapper = tmp_path / "nslookup"
    wrapper.write_text(
        "#!/bin/sh\n"
        "for last; do :; done\n"
        'case "$last" in *[!0-9.]*) exec /bin/busybox nslookup "$@" ;; esac\n'
        "exit 1\n"
    )
    wrapper.chmod(0o755)
    override = tmp_path / "broken-probe.yaml"
    override.write_text(
        "services:\n"
        + "".join(
            f"  {svc}:\n    volumes: ['{wrapper}:/usr/local/bin/nslookup:ro']\n" for svc in OUT + IN
        )
    )
    stack.up(extra_files=[override])
    stack.guard("apply")
    assert stack.nslookup("egress-codex", "example.com")  # names still resolve ...
    # ... but the probe can no longer receive a direct answer
    assert not stack.nslookup("egress-codex", "example.com", server=SLIRP_DNS)
    for mode in ("enforce", "report"):
        r = stack.check_dns(mode=mode)
        assert r.returncode == 1 and "PROBE DEFECT" in r.stderr, (mode, r.stdout + r.stderr)
        assert "UNVERIFIED" in r.stderr
    # and the same stack with a working probe passes: the defect was the probe, not the network
    stack.down()
    stack.up()
    assert stack.check_dns().returncode == 0
