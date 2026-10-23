"""The runtime-containment WATCHDOG, as a long-running process, on a REAL rootless Docker.

tests/test_runtime_containment_lab.py drives the watchdog mostly with `once` (single cycles). These
tests run the real `watch` against the real daemon and ask what an operator would ask, one claim per
fix that PR #13 made to the findings of the first QA review:

  LATENCY  a hot `docker network connect` of an agent is acted on by the EVENT, not by the poll
           (the interval is far beyond the test).
  ORDER    the hostile endpoint is removed before the supervised set is stopped.
  QUIET    healthchecks (container exec events) do not make the watchdog cycle, while real
           lifecycle events still do - a quiet watchdog that is deaf would be worse than a busy one.
  LOCK     the watchdog never takes deploy.lock (not even while it acts), takes its own action lock
           only while it changes something, and never makes a deploy fail with "another deploy is
           running" while nothing is wrong.
  ADDR     a new host address (a rootful Docker bridge) is absorbed into the guard's policy without
           stopping the set, repeatedly, without latching the stack.
  CONTRACT a container that merely CLAIMS to be an agent (labels, network) but carries privileges
           the release never gave it is not a project service: the watchdog latches and stops it
           (the spec check; the full matrix is tests/test_runtime_containment_spec_lab.py).

Every fix has three kinds of evidence, none of which is "CI is green":
  * the behaviour itself, measured with an instrument that is independent of the one #13's own
    tests use;
  * a CONTROL for that instrument: the same measurement is shown to see what it claims to see
    (a real stop is counted, a held lock is seen, real lifecycle events wake a cycle, the address
    really reaches the policy), so a pass cannot be a blind instrument;
  * a MUTANT of the current script (the old behaviour re-introduced into a copy: stop-first,
    unfiltered events, the deploy lock as the action lock) that the same measurement must catch.

Skipped unless PR #13 (deploy/runtime-containment.sh) is in the tree. Opt-in like the lab
(HUNTER_ROOTLESS_LAB=1).
"""

import fcntl
import os
import random
import re
import signal
import subprocess
import threading
import time

import pytest

base = pytest.importorskip("test_runtime_containment_lab")
# the lab and the committed, guarded, healthy stack are that module's fixtures
clab = base.clab
rig = base.rig

pytestmark = pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0, reason="rootless Docker needs an unprivileged user"
)

AGENT = "clab-agent-codex-1"
EXTRA_NET = "clab_egress"
SHIM_ADDRESS = "198.51.100.77"


def _wait(predicate, timeout, step=0.1):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if predicate():
            return time.monotonic() - t0
        time.sleep(step)
    return None


def _state(rig):
    try:
        return rig.state()
    except OSError:
        return ""


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


def _start(rig, interval, path_prefix=None):
    w = Watcher(rig, interval, path_prefix)
    ok = _wait(lambda: _state(rig).startswith("ok"), 150)
    if ok is None:
        w.stop()
        pytest.fail("the watchdog never reached 'ok' on a healthy stack:\n" + rig.log()[-1500:])
    return w


@pytest.fixture
def watcher(rig):
    # a poll interval far beyond every test: whatever happens next, an EVENT caused it
    w = _start(rig, 300)
    yield w
    w.stop()


# ---- mutants: the OLD behaviour re-introduced into a copy of the CURRENT script -----------------
def _mutate(src, *edits):
    out = src
    for pattern, repl in edits:
        new, n = re.subn(pattern, repl, out, count=1, flags=re.M)
        assert n == 1, f"the script no longer contains {pattern!r}: update this mutant"
        out = new
    assert out != src
    return out


def _quarantine_body(src):
    i = src.index("\nquarantine() {")
    return i, src.index("\n}\n", i) + 3


def stop_first(src):
    """quarantine(): the set is stopped first and the hostile endpoint is removed afterwards."""
    i, j = _quarantine_body(src)
    body = _mutate(
        src[i:j],
        (r"^\s*do_actions \|\| cut=1[^\n]*$", "  : # mutant: no early cut"),
        (r"^\s*\[\[ \$\{#ACTIONS\[@\]\} -gt 0 \]\] && ACTIONS=\(\)[^\n]*$", "  :"),
        (r"(stop_ids \"\$\{SUP_IDS\[@\]\}\"; fi)", r"\1; do_actions || cut=1"),
    )
    return src[:i] + body + src[j:]


def unfiltered_events(src):
    """`docker events` without --filter event=...: every healthcheck exec_create/exec_die wakes."""
    out = re.sub(r"--filter event=\w+ ?", "", src)
    assert out.count("--filter event=") == 0 < src.count("--filter event=")
    return out


def deploy_lock_is_the_action_lock(src):
    return _mutate(
        src,
        (
            r'^ACTION_LOCK="\$BASE/state/containment\.action\.lock"',
            'ACTION_LOCK="$BASE/state/deploy.lock"',
        ),
    )


@pytest.fixture
def use_mutant(monkeypatch, tmp_path):
    def apply(mutation):
        dst = tmp_path / "mutant" / "runtime-containment.sh"
        dst.parent.mkdir(exist_ok=True)
        dst.write_text(mutation(base.CONTAINMENT.read_text()))
        dst.chmod(0o755)
        monkeypatch.setattr(base, "CONTAINMENT", dst)

    return apply


# ---- LATENCY ------------------------------------------------------------------------------------
def test_LATENCY_an_event_wakes_the_cycle_and_the_hostile_endpoint_goes(rig, watcher):
    """Positive control: the poll is 300 s, so only the docker event can have caused it."""
    assert EXTRA_NET not in rig.networks_of(AGENT)
    t0 = time.monotonic()
    rig.run(["docker", "network", "connect", EXTRA_NET, AGENT])
    detached = _wait(lambda: EXTRA_NET not in rig.networks_of(AGENT), 90, step=0.05)
    assert detached is not None, (
        "the unauthorised endpoint was never removed (poll=300 s: events dead?)"
    )
    assert _wait(rig.latched, 60, step=0.05) is not None
    assert "ATTACH-UNEXPECTED" in rig.latch_reason()
    print(f"\nLATENCY event -> endpoint removed: {time.monotonic() - t0:.1f}s")


# ---- ORDER --------------------------------------------------------------------------------------
def _order_trace(rig):
    """Hot-attach the agent and record when the endpoint disappears, when the first supervised
    container stops and whether the latch was on disk at the moment of the cut."""
    rig.run(["docker", "network", "connect", EXTRA_NET, AGENT])
    t_cut = t_stop = latched_at_cut = None
    t0 = time.monotonic()
    while time.monotonic() - t0 < 90 and (t_cut is None or t_stop is None):
        now = time.monotonic() - t0
        if t_cut is None and EXTRA_NET not in rig.networks_of(AGENT):
            t_cut, latched_at_cut = now, rig.latched()
        if t_stop is None and len(rig.supervised_running()) < len(base.SUPERVISED):
            t_stop = now
    print(f"\nORDER endpoint removed at {t_cut}, first supervised container gone at {t_stop}")
    return t_cut, t_stop, latched_at_cut


def test_ORDER_the_hostile_endpoint_is_removed_before_the_set_is_stopped(rig, watcher):
    t_cut, t_stop, latched_at_cut = _order_trace(rig)
    assert t_cut is not None and t_stop is not None
    assert t_cut <= t_stop, f"the agent kept its extra network {t_cut - t_stop:.1f}s after a stop"
    assert latched_at_cut, "the endpoint was cut before the intent (the latch) was on disk"


def test_ORDER_control_the_instrument_sees_a_stop_and_an_attached_network(rig):
    """No watchdog runs: nothing removes the endpoint, and a plain `docker stop` is counted."""
    rig.run(["docker", "network", "connect", EXTRA_NET, AGENT])
    assert EXTRA_NET in rig.networks_of(AGENT)
    full = len(rig.supervised_running())
    assert full == len(base.SUPERVISED)
    rig.run(["docker", "stop", "-t", "1", "clab-api-1"])
    assert len(rig.supervised_running()) == full - 1
    rig.run(["docker", "network", "disconnect", "-f", EXTRA_NET, AGENT])
    assert EXTRA_NET not in rig.networks_of(AGENT)


def test_ORDER_negative_control_a_stop_first_script_is_caught(rig, use_mutant):
    """The old order, re-introduced into a copy of today's script, must fail the measurement above:
    the endpoint outlives the first stopped container."""
    use_mutant(stop_first)
    w = _start(rig, 300)
    try:
        t_cut, t_stop, _ = _order_trace(rig)
    finally:
        w.stop()
    assert t_cut is not None and t_stop is not None
    assert t_cut > t_stop, f"the mutant was not caught: cut at {t_cut}, first stop at {t_stop}"


# ---- QUIET --------------------------------------------------------------------------------------
def _healthchecking_containers(rig, n=9):
    names = [f"hc-{i}" for i in range(n)]
    for name in names:
        rig.run(
            ["docker", "run", "-d", "--name", name, "--health-cmd", "true",
             "--health-interval", "10s", "alpine-local:3.20", "sleep", "600"]
        )  # fmt: skip
    return names


def test_QUIET_healthchecks_do_not_spin_the_watchdog(rig, watcher):
    """9 ordinary containers with a 10 s healthcheck, like the supervised set in production."""
    names = _healthchecking_containers(rig)
    try:
        time.sleep(15)  # let the start-up events and the first checks settle
        cycles = watcher.beats(60)
        print(f"\nQUIET cycles in 60 s on a healthy stack (poll interval 300 s): {cycles}")
        assert cycles <= 2, (
            f"{cycles} cycles in 60 s: each one runs guard status + a compose render"
        )
    finally:
        rig.run(["docker", "rm", "-f", *names], check=False)


def test_QUIET_control_real_lifecycle_events_still_wake_the_watchdog(rig, watcher):
    """A watchdog that filters out too much is deaf. Ad hoc containers are not its business, but
    their create/start/die/destroy events must still make it look (a cheap read-only cycle), and
    the same counter that reads 'quiet' above must read 'busy' here."""
    watcher.beats(8)  # drain whatever the start-up caused
    seen = {}

    def churn():
        for i in range(3):
            n = f"churn-{i}"
            rig.run(["docker", "run", "-d", "--name", n, "alpine-local:3.20", "sleep", "30"])
            time.sleep(4)
            rig.run(["docker", "rm", "-f", n])
            time.sleep(4)

    t = threading.Thread(target=churn)
    t.start()
    seen["cycles"] = watcher.beats(26)
    t.join()
    print(f"\nQUIET control: {seen['cycles']} cycles for 6 lifecycle events")
    assert seen["cycles"] >= 3, "container lifecycle events did not wake the watchdog"


def test_QUIET_negative_control_an_unfiltered_event_stream_is_caught(rig, use_mutant):
    use_mutant(unfiltered_events)
    w = _start(rig, 300)
    names = _healthchecking_containers(rig)
    try:
        time.sleep(15)
        cycles = w.beats(45)
    finally:
        w.stop()
        rig.run(["docker", "rm", "-f", *names], check=False)
    print(f"\nQUIET mutant (no event filter): {cycles} cycles in 45 s")
    assert cycles > 2, f"the mutant was not caught: only {cycles} cycles"


# ---- CONTRACT -----------------------------------------------------------------------------------
def test_CONTRACT_an_imposter_with_agent_labels_but_more_privilege_is_not_accepted(rig):
    """A container that claims to be agent-codex (same labels, same network) plus NET_ADMIN, no
    seccomp and the host's root mounted: nothing the release declares. It must be caught (the
    security latch is set) AND the unauthorised container that was running must be stopped."""
    try:
        rig.run(
            ["docker", "run", "-d", "--name", "imposter",
             "--label", "com.docker.compose.project=clab",
             "--label", "com.docker.compose.service=agent-codex",
             "--network", "clab_agent_codex", "--cap-add", "NET_ADMIN",
             "--security-opt", "seccomp=unconfined", "-v", "/:/host:ro",
             "alpine-local:3.20", "sleep", "600"]
        )  # fmt: skip
        assert "imposter" in rig.run(["docker", "ps", "--format", "{{.Names}}"]).stdout.split(), (
            "the impostor never ran: the test would prove nothing"
        )
        r = rig.once()
        output = r.stdout[-300:] + r.stderr[-300:]
        assert rig.latched(), (
            "the watchdog certified a container with CAP_NET_ADMIN and a bind mount: " + output
        )
        assert "SPEC" in rig.latch_reason(), rig.latch_reason()
        still_running = rig.run(["docker", "ps", "--format", "{{.Names}}"]).stdout.split()
        assert "imposter" not in still_running, "the latch is set but the impostor keeps running"
    finally:
        rig.run(["docker", "rm", "-f", "imposter"], check=False)


# ---- LOCK ---------------------------------------------------------------------------------------
def _try_flock(path):
    """What a deploy does first (remote-deploy.sh: `exec 9>deploy.lock; flock -n 9 || die`)."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return True
    except BlockingIOError:
        return False
    finally:
        os.close(fd)


def _open_by_others(path):
    """Pids (not this process) that hold `path` open, from /proc/<pid>/fd. The watchdog takes its
    lock with `exec {fd}<file; flock -n $fd` and closes the descriptor to drop it, so this is when
    it holds the lock. /proc/locks cannot be used: a lock taken by the short-lived flock(1) binary
    is not listed once that process has exited."""
    target, me, out = os.path.realpath(path), os.getpid(), []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        if int(pid) == me:
            continue
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                try:
                    if os.readlink(f"/proc/{pid}/fd/{fd}") == target:
                        out.append(int(pid))
                except OSError:
                    pass
        except OSError:
            pass
    return out


def test_LOCK_control_the_observers_see_a_lock_held_the_way_the_watchdog_holds_it(rig):
    """Held by `exec 9<file; flock -n 9` in bash, exactly as runtime-containment.sh does it: both
    observers must report it, and both must report it free afterwards, or 'never' means nothing."""
    path = rig.base / "state" / "observer-control.lock"
    path.parent.mkdir(exist_ok=True)
    path.touch()
    assert _try_flock(path) is True and _open_by_others(path) == []
    holder = subprocess.Popen(["bash", "-c", 'exec 9<"$0"; flock -n 9 && exec sleep 30', str(path)])
    try:
        assert _wait(lambda: _try_flock(path) is False, 10) is not None, "a held lock looked free"
        assert holder.pid in _open_by_others(path)
    finally:
        holder.kill()
        holder.wait()
    assert _try_flock(path) is True and _open_by_others(path) == []


def test_LOCK_a_deploy_is_never_refused_while_nothing_is_wrong(rig):
    """`watch --interval 10` beside nine healthchecking containers; a deploy attempt every ~0.1 s
    for 60 s. No deploy runs and nothing is wrong, so neither lock may ever be found taken."""
    names = _healthchecking_containers(rig)
    w = None
    try:
        w = _start(rig, 10)
        time.sleep(15)
        attempts = refused_deploy = refused_action = 0
        end = time.monotonic() + 60
        while time.monotonic() < end:
            refused_deploy += not _try_flock(rig.lock)
            refused_action += not _try_flock(rig.action_lock)
            attempts += 1
            time.sleep(random.uniform(0.05, 0.15))
        print(f"\nLOCK refused: deploy {refused_deploy}/{attempts}, action {refused_action}")
        assert refused_deploy == 0, (
            f"{refused_deploy}/{attempts} deploy attempts found the lock taken"
        )
        assert refused_action == 0, f"{refused_action}/{attempts} found the action lock taken"
    finally:
        if w is not None:
            w.stop()
        rig.run(["docker", "rm", "-f", *names], check=False)


def _locks_during_an_incident(rig):
    """Hot-attach the agent and watch both lock files until the set is down. A lock counts as HELD
    when another process has had its file open for 0.3 s and a non-blocking flock then fails: the
    probe waits that long so it cannot collide with the watchdog's own instantaneous `flock -n`
    (which would make it yield) - a probe can only fail while someone really holds the lock."""
    rig.run(["docker", "network", "connect", EXTRA_NET, AGENT])
    held = {"deploy": 0, "action": 0}
    since = {"deploy": None, "action": None}
    paths = {"deploy": rig.lock, "action": rig.action_lock}
    samples = 0
    t0 = time.monotonic()
    while time.monotonic() - t0 < 90:
        now = time.monotonic()
        for name, path in paths.items():
            if not _open_by_others(path):
                since[name] = None
                continue
            since[name] = since[name] or now
            if now - since[name] >= 0.3 and not _try_flock(path):
                held[name] += 1
        samples += 1
        if rig.latched() and not rig.supervised_running():
            break
        time.sleep(0.02)
    return held["deploy"], held["action"], samples


def test_LOCK_the_watchdog_holds_its_own_lock_while_it_acts_and_never_the_deploy_lock(rig, watcher):
    deploy_held, action_held, samples = _locks_during_an_incident(rig)
    print(f"\nLOCK during the incident: deploy held {deploy_held}/{samples}, action {action_held}")
    assert action_held >= 1, "the watchdog changed the stack without holding the action lock"
    assert deploy_held == 0, f"the watchdog held deploy.lock in {deploy_held}/{samples} samples"


def test_LOCK_negative_control_a_watchdog_that_takes_the_deploy_lock_is_caught(rig, use_mutant):
    use_mutant(deploy_lock_is_the_action_lock)
    w = _start(rig, 300)
    try:
        deploy_held, _, samples = _locks_during_an_incident(rig)
    finally:
        w.stop()
    assert deploy_held >= 1, f"the mutant was not caught (0/{samples} samples)"


# ---- ADDR ---------------------------------------------------------------------------------------
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
        f"  echo '99: br-qa4    inet {SHIM_ADDRESS}/24 brd 198.51.100.255 scope global br-qa4'\n"
        "fi\n"
        "exit $rc\n"
    )
    (d / "ip").chmod(0o755)
    return d, flag


def _in_policy(rig):
    return f"-d {SHIM_ADDRESS}/32" in rig.netns("iptables", "-S", "HUNTER-EGRESS-GUARD").stdout


def _lowest_running(rig, full, seconds, until=None):
    lowest, t0 = full, time.monotonic()
    while time.monotonic() - t0 < seconds:
        lowest = min(lowest, len(rig.supervised_running()))
        if until and until():
            break
        time.sleep(0.2)
    return lowest


def test_ADDR_control_the_instrument_sees_a_container_go_down(rig):
    full = len(rig.supervised_running())
    assert full == len(base.SUPERVISED)
    rig.run(["docker", "stop", "-t", "1", "clab-api-1"])
    assert _lowest_running(rig, full, 1) == full - 1
    assert _in_policy(rig) is False  # and the policy does not mention the shim address yet


def test_ADDR_a_new_host_address_is_absorbed_without_stopping_the_set(rig, tmp_path):
    d, flag = _host_address_shim(tmp_path)
    w = _start(rig, 5, str(d))
    try:
        full = len(rig.supervised_running())
        assert full == len(base.SUPERVISED), rig.running()
        assert not _in_policy(rig)
        flag.write_text("")  # the host gains an address the applied policy does not mention
        # it must really reach the guard (a 'fix' that ignores the change also keeps the set up)
        lowest = _lowest_running(rig, full, 60, until=lambda: _in_policy(rig))
        assert _in_policy(rig), (
            "the new host address never reached the guard policy:\n" + rig.log()[-900:]
        )
        lowest = min(lowest, _lowest_running(rig, full, 10))
        print(f"\nADDR supervised running: {full} -> lowest {lowest}")
        assert lowest == full, (
            f"the set dropped to {lowest}/{full} containers because a host address appeared "
            "(guard drift repairable in seconds); events:\n" + rig.log()[-900:]
        )
        assert not rig.latched()
    finally:
        w.stop()


def test_ADDR_rapid_address_changes_do_not_latch_the_stack(rig, tmp_path):
    """Four changes (appear, vanish, appear, vanish) a few seconds apart - faster than a human, the
    shape of a build that creates and removes networks on a shared rootful Docker."""
    d, flag = _host_address_shim(tmp_path)
    w = _start(rig, 5, str(d))
    try:
        full = len(rig.supervised_running())
        lowest = full
        for i in range(4):
            if i % 2 == 0:
                flag.write_text("")
            else:
                flag.unlink()
            time.sleep(random.uniform(2, 4))
            lowest = min(lowest, len(rig.supervised_running()))
        flag.write_text("")  # finish on 'present' so the converged policy is observable
        converged = _wait(lambda: _in_policy(rig), 60)
        lowest = min(lowest, _lowest_running(rig, full, 10))
        print(f"\nADDR after 4 rapid changes: latched={rig.latched()} lowest={lowest}/{full}")
        assert converged is not None, (
            "the policy never converged on the final address:\n" + rig.log()[-900:]
        )
        assert not rig.latched(), "rapid host address changes latched the stack: " + (
            rig.latch_reason() if rig.latched() else ""
        )
        assert lowest == full, f"the set dropped to {lowest}/{full} during the address changes"
    finally:
        w.stop()
