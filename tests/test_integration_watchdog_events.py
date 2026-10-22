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
  * LOCK      a deploy that arrives while the watchdog is mid-cycle is refused ("another deploy is
              running", exit 4): the watchdog holds the deploy lock for whole cycles.
  * ADDR      a new host address (a rootful Docker bridge) stops the WHOLE set before the guard is
              re-applied, and three of them latch the stack.
  * CONTRACT  a container that merely CLAIMS to be an agent (project and service labels, the
              right network) but carries capabilities and a host bind mount the release never
              gave it is not a project service.

Skipped unless PR #13 (deploy/runtime-containment.sh) is in the tree. Opt-in like the lab
(HUNTER_ROOTLESS_LAB=1). Open findings are strict xfails: red today, breaking the build when fixed.
"""

import fcntl
import os
import random
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

    def __init__(self, rig, interval, path_prefix=None):
        self.rig = rig
        self.log = open(rig.state_dir.parent / "watch.out", "w")
        env = {**rig.env(), **rig.wenv()}
        if path_prefix:
            env["PATH"] = f"{path_prefix}{os.pathsep}{env['PATH']}"
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
    """Positive control: the poll is 300 s, so only the docker event can have caused it."""
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
    """A container that claims to be agent-codex (same labels, same network) plus NET_ADMIN, no
    seccomp and the host's root mounted: nothing the release declares."""
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


@pytest.mark.xfail(
    strict=True,
    reason="remote-deploy.sh takes deploy.lock with `flock -n` and dies 'another deploy is "
    "running' (exit 4); the watchdog holds the SAME lock, exclusively, for all of every cycle",
)
def test_LOCK_the_watchdog_does_not_make_a_deploy_fail_with_another_deploy_is_running(rig):
    """What a deploy does first (deploy/remote-deploy.sh: `exec 9>deploy.lock; flock -n 9 || die
    ... 4`), attempted every ~0.1 s for 60 s against the watchdog as the unit runs it (`--interval
    10`) on a stack whose containers run 10 s healthchecks. No deploy is running, so no attempt may
    fail."""
    names = [f"hc-{i}" for i in range(9)]
    w = None
    try:
        for n in names:
            rig.run(
                ["docker", "run", "-d", "--name", n, "--health-cmd", "true",
                 "--health-interval", "10s", "alpine-local:3.20", "sleep", "600"]
            )  # fmt: skip
        w = Watcher(rig, interval=10)
        assert _wait(lambda: (rig.state_dir / "state").exists(), 120) is not None
        time.sleep(15)
        attempts = refused = 0
        end = time.monotonic() + 60
        while time.monotonic() < end:
            fd = os.open(rig.lock, os.O_RDWR | os.O_CREAT)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fd, fcntl.LOCK_UN)
            except BlockingIOError:
                refused += 1
            finally:
                os.close(fd)
            attempts += 1
            time.sleep(random.uniform(0.05, 0.15))
        print(f"\nLOCK deploy-lock attempts refused while NO deploy runs: {refused}/{attempts}")
        assert refused == 0, (
            f"{refused} of {attempts} lock attempts found the lock taken by the watchdog: a deploy "
            "started at one of those instants dies with 'another deploy is running'"
        )
    finally:
        if w is not None:
            w.stop()
        rig.run(["docker", "rm", "-f", *names], check=False)


def _state(rig):
    try:
        return rig.state()
    except OSError:
        return ""


def _host_address_shim(tmp_path):
    """`ip` that, while <dir>/flag exists, reports ONE more global IPv4 address on the host (what
    `docker network create` on the host's ROOTFUL daemon does: a new br-* gateway). Everything else
    passes through. Only the watchdog's (and so the guard's) PATH sees it. Returns (dir, flag)."""
    d = tmp_path / "ipshim"
    d.mkdir()
    flag = d / "flag"
    real = subprocess.run(["bash", "-c", "command -v ip"], capture_output=True, text=True).stdout
    (d / "ip").write_text(
        "#!/bin/sh\n"
        f'out=$({real.strip()} "$@"); rc=$?\n'
        '[ -n "$out" ] && printf \'%s\\n\' "$out"\n'
        f'if [ -e {flag} ] && [ "$*" = "-4 -o addr show scope global" ]; then\n'
        "  echo '99: br-qa4    inet 198.51.100.77/24 brd 198.51.100.255 scope global br-qa4'\n"
        "fi\n"
        "exit $rc\n"
    )
    (d / "ip").chmod(0o755)
    return d, flag


@pytest.mark.xfail(
    strict=True,
    reason="a host address that the guard does not know yet (here: a rootful Docker bridge) makes "
    "the watchdog STOP THE WHOLE SET, then repair the guard; the repair alone takes seconds",
)
def test_ADDR_a_new_host_address_is_absorbed_without_stopping_the_set(rig, tmp_path):
    d, flag = _host_address_shim(tmp_path)
    w = Watcher(rig, interval=5, path_prefix=str(d))
    try:
        assert _wait(lambda: _state(rig).startswith("ok"), 180) is not None, rig.log()[-1500:]
        full = len(rig.supervised_running())
        assert full >= 6, rig.running()
        flag.write_text("")  # the host gains an address the applied policy does not mention
        lowest, t0, back = full, time.monotonic(), None
        while time.monotonic() - t0 < 150:
            n = len(rig.supervised_running())
            lowest = min(lowest, n)
            if lowest < full and n == full:
                back = time.monotonic() - t0
                break
            time.sleep(0.3)
        print(f"\nADDR supervised running: {full} -> lowest {lowest}; whole again after {back}")
        assert lowest == full, (
            f"the set dropped to {lowest}/{full} containers because a host address appeared "
            "(guard drift repairable in seconds); events:\n" + rig.log()[-900:]
        )
    finally:
        w.stop()


@pytest.mark.xfail(
    strict=True,
    reason="each repairable guard drift is a quarantine, and three in 15 minutes LATCH the stack "
    "until a human runs `reset`: three bridge changes on a shared rootful Docker is enough",
)
def test_ADDR_three_host_address_changes_do_not_latch_the_stack(rig, tmp_path):
    d, flag = _host_address_shim(tmp_path)
    w = Watcher(rig, interval=5, path_prefix=str(d))
    try:
        assert _wait(lambda: _state(rig).startswith("ok"), 180) is not None, rig.log()[-1500:]
        for i in range(3):
            flag.write_text("") if i % 2 == 0 else flag.unlink()
            _wait(lambda: rig.latched() or _state(rig).startswith("quarantined"), 40)
            if rig.latched():
                break
            _wait(lambda: _state(rig).startswith("ok"), 150)
        print(f"\nADDR after 3 address changes: latched={rig.latched()} state={rig.state()}")
        assert not rig.latched(), "three host address changes latched the stack: " + (
            rig.latch_reason() if rig.latched() else ""
        )
    finally:
        w.stop()
