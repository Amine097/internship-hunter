"""The runtime-containment WATCHDOG, as a long-running process, on a REAL rootless Docker.

tests/test_runtime_containment_lab.py drives the watchdog with `once` (single cycles); the
event-driven `watch` loop - `docker events`, `ip monitor`, the fifo, the interval backstop - is only
unit-tested against a stub daemon, and the lab compose disables every healthcheck. These tests run
the real `watch` against the real daemon and ask what an operator would ask:

  * LATENCY   a hot `docker network connect` of an agent is acted on by the EVENT, not by the
              poll (the interval is set far beyond the test): how long does the agent stay
              attached before the endpoint is removed and the set stopped?
  * QUIET     a healthy stack with ordinary healthchecks does not make the watchdog spin. Every
              cycle runs `host-egress-guard.sh status` (which renders scratch chains in the
              daemon's namespace) and a compose render; the production proxies and agents each
              run a healthcheck every 10 s and Docker reports each run as container events.
  * CONTRACT  a container that merely CLAIMS to be an agent (project and service labels, the
              right network) but carries capabilities and a host bind mount the release never
              gave it is not a project service.

Skipped unless PR #13 (deploy/runtime-containment.sh) is in the tree. Opt-in like the lab
(HUNTER_ROOTLESS_LAB=1). Open findings are strict xfails, red today and breaking the build when fixed.
"""

import os
import signal
import subprocess
import time

import pytest

base = pytest.importorskip("test_runtime_containment_lab")
# the lab and the committed, guarded, healthy stack are that module's fixtures
clab = base.clab
rig = base.rig

pytestmark = pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0, reason="rootless Docker needs an unprivileged user"
)


def _wait(predicate, timeout, step=0.1):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if predicate():
            return time.monotonic() - t0
        time.sleep(step)
    return None


class Watcher:
    """`runtime-containment.sh watch` as systemd would run it (minus the unit)."""

    def __init__(self, rig, interval):
        self.rig = rig
        self.log = open(rig.state_dir.parent / "watch.out", "w")
        env = {**rig.env(), **rig.wenv()}
        self.proc = subprocess.Popen(
            ["bash", str(base.CONTAINMENT), "watch", "--interval", str(interval)],
            env=env,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    def stop(self):
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(self.proc.pid, signal.SIGKILL)
        self.log.close()

    def beats(self, seconds):
        """How many cycles ran in `seconds` (every cycle rewrites the heartbeat file)."""
        seen, hb = set(), self.rig.state_dir / "heartbeat"
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                st = hb.stat()
                seen.add((st.st_ino, st.st_mtime_ns))
            except OSError:
                pass
            time.sleep(0.05)
        return len(seen)


@pytest.fixture
def watcher(rig):
    # a poll interval far beyond every test: whatever happens next, an EVENT caused it
    w = Watcher(rig, interval=300)
    ok = _wait(
        lambda: rig.state().startswith("ok") if (rig.state_dir / "state").exists() else False, 120
    )
    if ok is None:
        w.stop()
        pytest.fail("the watchdog never reached 'ok' on a healthy stack:\n" + rig.log()[-1500:])
    yield w
    w.stop()


def test_LATENCY_an_event_wakes_the_cycle_and_the_hostile_endpoint_goes(rig, watcher):
    """Positive control: the poll is 300 s, so only the docker event can have caused the reaction."""
    agent = "clab-agent-codex-1"
    assert "clab_egress" not in rig.networks_of(agent)
    t0 = time.monotonic()
    rig.run(["docker", "network", "connect", "clab_egress", agent])
    detached = _wait(lambda: "clab_egress" not in rig.networks_of(agent), 90, step=0.05)
    assert detached is not None, (
        "the unauthorised endpoint was never removed (poll=300 s: events dead?)"
    )
    assert _wait(rig.latched, 60, step=0.05) is not None
    assert "ATTACH-UNEXPECTED" in rig.latch_reason()
    print(f"\nLATENCY event -> endpoint removed: {time.monotonic() - t0:.1f}s")


@pytest.mark.xfail(
    strict=True,
    reason="quarantine() stops the whole set (docker stop, up to 5 s grace each) BEFORE it "
    "disconnects the unauthorised endpoint: the hostile route outlives the shutdown",
)
def test_ORDER_the_hostile_endpoint_is_removed_before_the_set_is_stopped(rig, watcher):
    """Cutting the route is instant (`network disconnect -f`); stopping is not. A hot-attached agent
    must lose its extra network before anything else happens to it."""
    agent = "clab-agent-codex-1"
    rig.run(["docker", "network", "connect", "clab_egress", agent])
    t_detach = t_stop = None
    t0 = time.monotonic()
    while time.monotonic() - t0 < 90 and (t_detach is None or t_stop is None):
        now = time.monotonic() - t0
        if t_detach is None and "clab_egress" not in rig.networks_of(agent):
            t_detach = now
        if t_stop is None and len(rig.supervised_running()) < len(base.SUPERVISED):
            t_stop = now
    print(f"\nORDER endpoint removed at {t_detach}, first supervised container gone at {t_stop}")
    assert t_detach is not None and t_stop is not None
    assert t_detach <= t_stop, (
        f"the agent kept its extra network {t_detach - t_stop:.1f}s AFTER the first container "
        "of the set had stopped"
    )


@pytest.mark.xfail(
    strict=True,
    reason="every healthcheck run is a container event (exec_create/exec_start/exec_die) and the "
    "watcher wakes on ALL container events: the watchdog never idles",
)
def test_QUIET_healthchecks_do_not_spin_the_watchdog(rig, watcher):
    """9 ordinary containers with a 10 s healthcheck, like the supervised set in production."""
    names = [f"hc-{i}" for i in range(9)]
    try:
        for n in names:
            rig.run(
                ["docker", "run", "-d", "--name", n, "--health-cmd", "true",
                 "--health-interval", "10s", "alpine-local:3.20", "sleep", "600"]
            )  # fmt: skip
        time.sleep(15)  # let the start-up events and the first checks settle
        cycles = watcher.beats(60)
        print(f"\nQUIET cycles in 60 s on a healthy stack (poll interval 300 s): {cycles}")
        # the poll is 300 s here and nothing lifecycle-related happens: ~1 cycle (the start-up one)
        assert cycles <= 2, (
            f"{cycles} cycles in 60 s: each one runs guard status + a compose render"
        )
    finally:
        rig.run(["docker", "rm", "-f", *names], check=False)


@pytest.mark.xfail(
    strict=True,
    reason="the assessor compares networks and four flags, not capabilities, mounts or devices",
)
def test_CONTRACT_an_imposter_with_agent_labels_but_more_privilege_is_not_accepted(rig):
    """The operator (or a script) starts a container that claims to be agent-codex: same labels, same
    network, plus NET_ADMIN, no seccomp and the host's root mounted. Nothing the release declares."""
    try:
        rig.run(
            ["docker", "run", "-d", "--name", "imposter",
             "--label", "com.docker.compose.project=clab",
             "--label", "com.docker.compose.service=agent-codex",
             "--network", "clab_agent_codex", "--cap-add", "NET_ADMIN",
             "--security-opt", "seccomp=unconfined", "-v", "/:/host:ro",
             "alpine-local:3.20", "sleep", "600"]
        )  # fmt: skip
        r = rig.once()
        imposter_running = "imposter" in rig.run(["docker", "ps", "--format", "{{.Names}}"]).stdout
        assert rig.latched() or not imposter_running, (
            "the watchdog certified a container with CAP_NET_ADMIN and a host bind mount: "
            + r.stdout[-300:]
            + r.stderr[-300:]
        )
    finally:
        rig.run(["docker", "rm", "-f", "imposter"], check=False)
