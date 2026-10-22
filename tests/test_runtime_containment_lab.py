"""Runtime containment on a REAL rootless Docker (rootlesskit --detach-netns + slirp4netns).

The same lab as test_dns_rootless_lab.py (tests/rootless_lab/lab.sh: a genuine rootless Docker
29.9.1 as an unprivileged user) runs the repository's real compose.yaml topology (images swapped
for Alpine, processes for `sleep`; the real restart policies); the REAL deploy/host-egress-guard.sh
guards the daemon's real namespace, the REAL deploy/check-dns.sh judges DNS, and the REAL
deploy/runtime-containment.sh is the watchdog. Only check-host-isolation.sh is a stub here (it needs
the production host's addresses; its own tests are elsewhere): `--verify-targets` is the knob that
stands for "Tailscale is up".

What this establishes with real Docker, real iptables and real endpoints:
  * the daemon does NOT start the supervised services after a restart (`restart: "no"`), so the
    restart race is closed by construction; the watchdog starts them once the guard is re-applied;
  * a rule deleted from, or the whole of, the guard in the daemon's namespace is repaired with the
    set stopped first;
  * `docker network connect` of an agent to another network, a foreign container on an agent
    network, and daemon-level `dns` are caught, the unauthorised endpoint is removed, evidence is
    kept, and a reset restores the stack;
  * an ad hoc container on the default bridge or on an unrelated network is left alone;
  * Tailscale late: the set is not started while the protected addresses are not live.

Opt-in like the DNS lab (HUNTER_ROOTLESS_LAB=1; HUNTER_ROOTLESS_LAB_REQUIRED=1 turns a skip
into a failure).
"""

import fcntl
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from test_dns_rootless_lab import (
    ENABLED,
    IPT_DIR,
    LAB_COMPOSE,
    LAB_SH,
    REQUIRED,
    ROOT,
    SLIRP_DNS,
    Lab,
)

CONTAINMENT = ROOT / "deploy" / "runtime-containment.sh"
GUARD = ROOT / "deploy" / "host-egress-guard.sh"
CHECK_DNS = ROOT / "deploy" / "check-dns.sh"
SUPERVISED = [
    "api",
    "discovery",
    "telegram",
    "egress-claude-1",
    "egress-claude-2",
    "egress-codex",
    "agent-claude-1",
    "agent-claude-2",
    "agent-codex",
]
SHA = "b" * 40
NETS_FMT = "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}"
ISOLATION_STUB = """#!/usr/bin/env bash
echo "isolation $*" >> "$STUB_DIR/isolation.log"
if [[ "${1:-}" == --verify-targets ]]; then
  [[ -e "$STUB_DIR/targets_down" ]] && { echo "FAIL target is not live (stub)"; exit 1; }
fi
exit 0
"""

pytestmark = pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0, reason="rootless Docker needs an unprivileged user"
)


class Rig(Lab):
    """The DNS lab's helpers plus a containment installation (BASE) around the real scripts."""

    def setup_base(self, tmp: Path):
        self.base = tmp / "base"
        self.stub = tmp / "stub"
        for d in (self.base / "deploy", self.base / "state", self.stub):
            d.mkdir(parents=True, exist_ok=True)
        for src, mode in ((GUARD, 0o755), (CHECK_DNS, 0o755)):
            dst = self.base / "deploy" / src.name
            shutil.copy(src, dst)
            dst.chmod(mode)
        iso = self.base / "deploy" / "check-host-isolation.sh"
        iso.write_text(ISOLATION_STUB)
        iso.chmod(0o755)
        (self.base / "deploy").chmod(0o755)
        (self.base / "deploy" / "host-egress-guard.conf").write_text(f"DNS={SLIRP_DNS}\n")
        (self.base / "deploy" / "host-isolation.conf").write_text("ROOTFUL_TARGETS=172.17.0.2:9\n")
        for c in ("host-egress-guard.conf", "host-isolation.conf"):
            (self.base / "deploy" / c).chmod(0o644)
        self.lock = self.base / "state" / "deploy.lock"
        self.state_dir = self.base / "state" / "containment"

    def wenv(self, **extra):
        return {
            "HUNTER_CONTAINMENT_TEST_MODE": "1",
            "HUNTER_BASE": str(self.base),
            "HUNTER_GUARD_TEST_MODE": "1",
            "STUB_DIR": str(self.stub),
            "HUNTER_CONTAINMENT_START_TIMEOUT": "60",
            "HUNTER_CONTAINMENT_DOCKER_TIMEOUT": "60",
            **extra,
        }

    def wd(self, *argv, **extra):
        return self.run(
            ["bash", CONTAINMENT, *argv], check=False, timeout=400, **self.wenv(**extra)
        )

    def commit(self):
        files = [ROOT / "compose.yaml", LAB_COMPOSE]
        args = ["-p", self.project]
        for f in files:
            args += ["-f", str(f)]
        with open(self.lock, "w") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            return self.wd(
                "commit", "--sha", SHA, "--release-dir", str(ROOT),
                "--forbidden", "100.107.22.84:22", "--protected-ips", "100.107.22.84",
                "--rootful", "172.17.0.2:9", "--", *args,
            )  # fmt: skip

    def once(self, **extra):
        return self.wd("once", **extra)

    def running(self):
        out = self.run(
            ["docker", "ps", "--format", '{{.Label "com.docker.compose.service"}}'], check=False
        ).stdout
        return sorted(x for x in out.split() if x)

    def supervised_running(self):
        return [s for s in self.running() if s in SUPERVISED]

    def latched(self):
        return (self.state_dir / "latch").exists()

    def latch_reason(self):
        return json.loads((self.state_dir / "latch").read_text())["reason"]

    def state(self):
        return (self.state_dir / "state").read_text().strip()

    def log(self):
        p = self.state_dir / "events.log"
        return p.read_text() if p.exists() else ""

    def networks_of(self, container):
        out = self.run(
            ["docker", "inspect", "-f", NETS_FMT, container],
            check=False,
        ).stdout  # fmt: skip
        return sorted(out.split())

    def guard_rule_count(self):
        out = self.netns("iptables", "-S", "HUNTER-EGRESS-GUARD", check=False).stdout
        return len([ln for ln in out.splitlines() if ln.startswith("-A")])


@pytest.fixture(scope="module")
def clab(tmp_path_factory):
    if not ENABLED:
        pytest.skip("set HUNTER_ROOTLESS_LAB=1 to run the rootless Docker lab")
    problems = [
        t
        for t in ("curl", "tar", "unshare", "nsenter", "iptables", "sha256sum", "flock", "timeout")
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
    path = tmp_path_factory.mktemp("clab")
    lab = Rig(path)
    lab.project = "clab"
    try:
        lab.run([LAB_SH, "up"], timeout=420)
    except AssertionError as e:
        if REQUIRED:
            raise
        pytest.skip(f"the rootless lab did not start: {str(e)[:300]}")
    lab.env()
    lab.setup_base(path)
    yield lab
    lab.down()
    keep = os.environ.get("HUNTER_LAB_LOG_DIR")
    if keep:
        Path(keep).mkdir(parents=True, exist_ok=True)
        for name in ("dockerd.log",):
            if (path / name).exists():
                shutil.copy(path / name, Path(keep) / f"containment-{name}")
    lab.run([LAB_SH, "down"], check=False, timeout=120)


@pytest.fixture
def rig(clab):
    """A committed, guarded, healthy stack; torn down (and un-latched) afterwards."""
    shutil.rmtree(clab.state_dir, ignore_errors=True)
    for f in clab.stub.iterdir():
        f.unlink()
    clab.guard("remove", check=False)
    clab.up()
    clab.guard("apply")
    c = clab.commit()
    assert c.returncode == 0, c.stdout + c.stderr
    yield clab
    clab.down()
    clab.guard("remove", check=False)
    for extra in ("foreign",):
        clab.run(["docker", "rm", "-f", extra], check=False)


def test_the_supervised_set_is_exactly_the_services_with_a_route_out_and_the_agents(rig):
    contract = json.loads((rig.state_dir / "contract.json").read_text())
    assert sorted(k for k, v in contract["services"].items() if v["supervised"]) == sorted(
        SUPERVISED
    )
    assert contract["project"] == "clab" and contract["dns"] == SLIRP_DNS
    assert (rig.state_dir / "desired").read_text().strip() == "running"


def test_a_healthy_real_stack_is_left_alone(rig):
    before = rig.supervised_running()
    r = rig.once()
    assert r.returncode == 0, r.stdout + r.stderr
    assert rig.supervised_running() == before and sorted(before) == sorted(SUPERVISED)
    assert not rig.latched() and rig.state().startswith("ok")


def test_ad_hoc_containers_elsewhere_are_not_our_business(rig):
    rig.run(["docker", "network", "create", "unrelated-net"])
    try:
        rig.run(
            ["docker", "run", "-d", "--name", "adhoc-default", "alpine-local:3.20", "sleep", "300"]
        )
        rig.run(["docker", "run", "-d", "--name", "adhoc-own", "--network", "unrelated-net",
                 "alpine-local:3.20", "sleep", "300"])  # fmt: skip
        r = rig.once()
        assert r.returncode == 0, r.stdout + r.stderr
        assert sorted(rig.supervised_running()) == sorted(SUPERVISED) and not rig.latched()
        names = rig.run(["docker", "ps", "--format", "{{.Names}}"]).stdout.split()
        assert "adhoc-default" in names and "adhoc-own" in names
    finally:
        rig.run(["docker", "rm", "-f", "adhoc-default", "adhoc-own"], check=False)
        rig.run(["docker", "network", "rm", "unrelated-net"], check=False)


def test_after_a_daemon_restart_only_the_watchdog_starts_the_set_and_after_the_guard(rig):
    """The restart race, with a real daemon: a new network namespace, no guard, restart policies."""
    try:
        rig.restart_daemon()
        # (rootless Docker only restores containers once it is up; give it a moment to try)
        for _ in range(10):
            rig.run(["docker", "info"], check=False)
        assert rig.supervised_running() == [], "the daemon itself started a supervised service"
        assert rig.guard("status", check=False).returncode != 0
        r = rig.once()
        assert r.returncode in (0, 1), r.stdout + r.stderr
        assert sorted(rig.supervised_running()) == sorted(SUPERVISED), rig.log()
        assert rig.guard("status").returncode == 0
        log = rig.log()
        assert "GUARD-REPAIRED" in log and "STARTED" in log
        assert log.index("GUARD-REPAIRED") < log.index("START ")
        assert rig.latched() is False
    finally:
        rig.guard("remove", check=False)


def test_a_rule_deleted_from_the_guard_stops_the_set_and_is_repaired(rig):
    n = rig.guard_rule_count()
    assert n > 5
    rig.netns("iptables", "-D", "HUNTER-EGRESS-GUARD", "1")  # the ESTABLISHED/RELATED accept
    assert rig.guard_rule_count() == n - 1
    r = rig.once()
    assert r.returncode == 1, r.stdout + r.stderr
    assert rig.guard_rule_count() == n and rig.guard("status").returncode == 0
    assert sorted(rig.supervised_running()) == sorted(SUPERVISED) and not rig.latched()
    log = rig.log()
    assert "QUARANTINE" in log and "GUARD-REPAIRED" in log
    assert log.index("QUARANTINE") < log.index("GUARD-REPAIRED")


def test_the_guard_removed_entirely_is_put_back_before_anything_runs_again(rig):
    rig.guard("remove")
    r = rig.once()
    assert r.returncode == 1, r.stdout + r.stderr
    assert rig.guard("status").returncode == 0
    assert sorted(rig.supervised_running()) == sorted(SUPERVISED)


def test_a_guard_that_cannot_be_repaired_leaves_the_set_stopped_not_latched(rig):
    rig.guard("remove")
    conf = rig.base / "deploy" / "host-egress-guard.conf"
    # a guard conf the script refuses: apply fails, nothing may run
    conf.write_text("NONSENSE=1\n")
    try:
        for _ in range(2):
            rig.once()
        assert rig.supervised_running() == [] and not rig.latched()
        assert rig.state().startswith("waiting")
    finally:
        conf.write_text(f"DNS={SLIRP_DNS}\n")
    rig.once()
    assert sorted(rig.supervised_running()) == sorted(SUPERVISED)


def test_an_agent_hot_attached_to_another_network_is_caught_disconnected_and_latched(rig):
    agent = f"{rig.project}-agent-codex-1"
    before = rig.networks_of(agent)
    rig.run(["docker", "network", "connect", f"{rig.project}_egress", agent])  # the hot attachment
    assert f"{rig.project}_egress" in rig.networks_of(agent)
    r = rig.once()
    assert r.returncode == 1, r.stdout + r.stderr
    assert rig.supervised_running() == []  # all of them, not only the agent
    assert rig.networks_of(agent) == before  # the unauthorised endpoint is gone
    assert rig.latched() and "ATTACH-UNEXPECTED" in rig.latch_reason()
    assert "postgres" in rig.running()  # the data tier is not supervised
    # evidence is kept: the container exists, stopped, not removed
    assert agent in rig.run(["docker", "ps", "-a", "--format", "{{.Names}}"]).stdout.split()
    # a latched stack does not come back on its own, however many cycles pass
    for _ in range(2):
        rig.once()
    assert rig.supervised_running() == []


def test_reset_restores_the_stack_after_an_investigated_incident(rig):
    agent = f"{rig.project}-agent-codex-1"
    rig.run(["docker", "network", "connect", f"{rig.project}_egress", agent])
    rig.once()
    assert rig.latched()
    assert rig.wd("reset").returncode == 0  # the endpoint was already removed
    assert not rig.latched()
    r = rig.once()
    assert r.returncode == 0, r.stdout + r.stderr
    assert sorted(rig.supervised_running()) == sorted(SUPERVISED)


def test_a_foreign_container_on_an_agent_network_is_disconnected_not_killed(rig):
    rig.run(["docker", "run", "-d", "--name", "foreign", "--network", f"{rig.project}_agent_codex",
             "alpine-local:3.20", "sleep", "300"])  # fmt: skip
    r = rig.once()
    assert r.returncode == 1, r.stdout + r.stderr
    assert rig.latched() and "ATTACH-FOREIGN" in rig.latch_reason()
    assert rig.supervised_running() == []
    assert "foreign" in rig.run(["docker", "ps", "--format", "{{.Names}}"]).stdout.split()
    assert f"{rig.project}_agent_codex" not in rig.networks_of("foreign")
    refused = rig.wd("reset")
    assert refused.returncode == 0, refused.stderr  # nothing foreign is attached any more


def test_daemon_level_dns_after_a_restart_never_lets_the_set_run(rig):
    """F-1 at runtime: daemon.json {"dns": [...]} + restart: only the runtime shows it."""
    try:
        rig.restart_daemon(dns=SLIRP_DNS)
        r = rig.once()
        assert r.returncode == 1, r.stdout + r.stderr
        assert rig.latched(), rig.log()
        assert rig.latch_reason().startswith(("POST-START", "DNS-RT"))
        assert rig.supervised_running() == []
    finally:
        rig.down()
        rig.restart_daemon(dns="")
        rig.guard("remove", check=False)


def test_tailscale_late_nothing_is_started_until_the_protected_addresses_are_live(rig):
    rig.run(["docker", "compose", "-p", rig.project, "stop", "-t", "1", *SUPERVISED], timeout=120)
    (rig.stub / "targets_down").write_text("")
    for _ in range(2):
        rig.once()
    assert rig.supervised_running() == [] and "TARGETS" in rig.state()
    assert not rig.latched()
    (rig.stub / "targets_down").unlink()
    rig.once()
    assert sorted(rig.supervised_running()) == sorted(SUPERVISED)


def test_the_watchdog_stopping_stops_the_set_and_the_next_instance_brings_it_back(rig):
    q = rig.wd("quarantine", "--reason", "watchdog-stopped", "--no-latch")
    assert q.returncode == 0, q.stdout + q.stderr
    assert rig.supervised_running() == [] and not rig.latched()
    assert "postgres" in rig.running()
    rig.once()
    assert sorted(rig.supervised_running()) == sorted(SUPERVISED)


def test_the_files_are_private(rig):
    assert stat.S_IMODE(rig.state_dir.stat().st_mode) == 0o700
