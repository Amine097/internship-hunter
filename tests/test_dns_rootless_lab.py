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

Opt-in (it downloads ~100 MB of pinned, checksummed tools once): HUNTER_ROOTLESS_LAB=1.
HUNTER_ROOTLESS_LAB_REQUIRED=1 (CI) turns "cannot run" into a failure. iptables must be on PATH
(or GUARD_IPTABLES_DIR, as in test_host_egress_guard_netns.py).
"""

import os
import re
import shutil
import subprocess
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
    def restart_daemon(self, dns=""):
        self.run([LAB_SH, "restart", dns], timeout=180)

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

    def upstream_is_private(self):
        """Is the daemon's own upstream resolver a non-global address (the guard rejects those)?"""
        out = self.netns("cat", "/etc/resolv.conf").stdout
        import ipaddress

        for ln in out.splitlines():
            if ln.startswith("nameserver"):
                ip = ipaddress.ip_address(ln.split()[1])
                if (
                    ip.version == 4
                    and not ip.is_loopback
                    and (ip.is_private or ip in ipaddress.ip_network("100.64.0.0/10"))
                ):
                    return True
        return False


NODNS = ROOT / "tests" / "rootless_lab" / "compose.nodns.yaml"


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
    keep = os.environ.get("HUNTER_LAB_LOG_DIR")        # CI: the daemon's logs outlive the lab
    if keep:
        Path(keep).mkdir(parents=True, exist_ok=True)
        for name in ("dockerd.log", "runc.args"):
            if (path / name).exists():
                shutil.copy(path / name, Path(keep) / name)
        shutil.copy(path / "home" / ".config" / "docker" / "daemon.json", Path(keep) / "daemon.json")
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
    r = stack.check_dns()
    assert r.returncode == 0, r.stdout + r.stderr
    assert "internal-only service(s) resolve nothing outside the project" in r.stdout


def test_a_private_lan_resolver_stays_unreachable_even_when_configured(stack):
    """Never weaken the guard for LAN DNS: pointing the stack at one fails closed."""
    lan = "192.168.1.1"
    stack.up(HUNTER_DNS=lan)
    stack.guard("apply")
    for svc in OUT:
        assert f"ExtServers: [{lan}]" in stack.exec(svc, "cat", "/etc/resolv.conf").stdout, svc
        assert not stack.nslookup(svc, "example.com"), svc
    assert stack.check_dns(HUNTER_DNS=lan).returncode == 1
    # and querying that resolver directly is refused by the guard as well
    assert not stack.nslookup("egress-codex", "example.com", server=lan)


def test_internal_only_services_have_no_dns_way_out_and_see_only_their_neighbours(stack):
    stack.up()
    stack.guard("apply")
    for svc in IN:
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


# ---- daemon-level dns: ad hoc containers -----------------------------------------------------
def test_daemon_level_dns_makes_ad_hoc_containers_resolve_through_the_guard(lab):
    run = ["docker", "run", "--rm", "alpine-local:3.20", "nslookup", "-timeout=3", "example.com."]
    try:
        lab.restart_daemon(dns=SLIRP_DNS)
        lab.guard("apply")
        r = lab.run(run, check=False)
        assert r.returncode == 0 and "Address: " in r.stdout, r.stdout + r.stderr
        assert lab.guard_dns_hits() > 0
        if lab.upstream_is_private():
            lab.restart_daemon(dns="")  # the host's resolver, a private address
            lab.guard("apply")
            r = lab.run(run, check=False)
            assert r.returncode != 0, "an ad hoc container reached the host's LAN resolver"
    finally:
        lab.restart_daemon(dns="")
