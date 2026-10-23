"""Runtime containment (PR #13) under injected failure, on a REAL rootless Docker.

Independent of the PR's own lab tests: the failure is injected at an exact Docker call by a PATH
shim (the watchdog resolves `docker` through PATH in test mode), not by polling and killing it.

  CRASH   the watchdog's whole process session is SIGKILLed at the first `network disconnect`
          (before the cut) or at the first `stop` (after the cut): the next instance must finish.
  CUT     `network disconnect` fails every time: an endpoint that cannot be removed from a container
          that is ours kills that container; from a foreign one it is logged, the set stays stopped
          and the latch cannot be reset while it is there.
  TAMPER  deleting the guard's jump is structural (stop first, then repair); deleting a per-address
          REJECT is address drift (absorbed, nothing stops).
  LOCK    a deploy holding the action lock pauses the watchdog (no action, no deadlock); a watchdog
          that is continuously "waiting" does not starve a deploy's `flock -w`.

Opt-in with the lab (HUNTER_ROOTLESS_LAB=1); needs PR #13 in the tree.
"""

import fcntl
import os
import re
import shutil
import subprocess
import time

import pytest

base = pytest.importorskip("test_runtime_containment_lab")
clab = base.clab
rig = base.rig

pytestmark = pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0, reason="rootless Docker needs an unprivileged user"
)

SHIM = """#!/bin/sh
# SHIM_MODE: crash-disconnect | crash-stop | fail-disconnect; all else goes to the real docker
case "$SHIM_MODE:$*" in
  crash-disconnect:*"network disconnect"*|crash-stop:*" stop "*|crash-stop:"stop "*)
    sid=$(ps -o sid= -p $$ | tr -d ' ')
    kill -9 $(ps -o pid= -s "$sid") 2>/dev/null ;;
  fail-disconnect:*"network disconnect"*) echo "shim: disconnect refused" >&2; exit 1 ;;
esac
exec "$REAL_DOCKER" "$@"
"""


def wait_for(pred, timeout, step=0.1):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if pred():
            return time.monotonic() - t0
        time.sleep(step)
    return None


@pytest.fixture
def shim(rig, tmp_path):
    d = tmp_path / "shim"
    d.mkdir()
    (d / "docker").write_text(SHIM)
    (d / "docker").chmod(0o755)
    real = shutil.which("docker", path=rig.env()["PATH"])
    assert real
    return d, real


def once_with_shim(rig, shim, mode):
    """`once` in its own session (so the shim can kill all of it), with docker shimmed."""
    d, real = shim
    env = {**rig.env(), **rig.wenv(), "SHIM_MODE": mode, "REAL_DOCKER": real}
    env["PATH"] = f"{d}{os.pathsep}{env['PATH']}"
    p = subprocess.Popen(
        ["bash", str(base.CONTAINMENT), "once"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        start_new_session=True,
    )  # fmt: skip
    out, _ = p.communicate(timeout=300)
    return p.returncode, out


def hot_attach(rig, agent="agent-codex-1"):
    name = f"{rig.project}-{agent}"
    extra = f"{rig.project}_egress"
    rig.run(["docker", "network", "connect", extra, name])
    assert extra in rig.networks_of(name)
    return name, extra


@pytest.mark.parametrize("point", ["disconnect", "stop"])
def test_CRASH_a_watchdog_killed_at_each_step_of_a_quarantine_is_finished_by_the_next(
    rig, shim, point
):
    name, extra = hot_attach(rig)
    rc, out = once_with_shim(rig, shim, f"crash-{point}")
    assert rc == -9, f"the shim did not kill the watchdog (rc={rc}): {out[-400:]}"
    assert rig.latched(), "the intent must be on disk BEFORE anything is cut or stopped"
    if point == "disconnect":
        # died before the cut: the hostile endpoint is still there and nothing was stopped yet
        assert extra in rig.networks_of(name)
        assert len(rig.supervised_running()) == len(base.SUPERVISED)
    else:
        assert extra not in rig.networks_of(name)  # cut already done
    # a fresh instance, no shim: the latch alone must drive it to the end state
    r = rig.once()
    assert extra not in rig.networks_of(name), r.stdout + r.stderr
    assert wait_for(lambda: rig.supervised_running() == [], 90) is not None
    assert rig.latched() and "ATTACH-UNEXPECTED" in rig.latch_reason()


def test_CUT_an_endpoint_that_cannot_be_removed_from_our_container_kills_it(rig, shim):
    name, extra = hot_attach(rig)
    rc, out = once_with_shim(rig, shim, "fail-disconnect")
    log = rig.log()
    assert "DISCONNECT-FAILED" in log and "KILLED" in log, log[-800:]
    assert name not in rig.run(["docker", "ps", "--format", "{{.Names}}"]).stdout.split()
    assert rig.supervised_running() == [] and rig.latched()


def test_CUT_a_foreign_container_that_cannot_be_disconnected_is_not_killed_set_stays_stopped(
    rig, shim
):
    net = f"{rig.project}_agent_codex"
    rig.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            "foreign",
            "--network",
            net,
            "alpine-local:3.20",
            "sleep",
            "600",
        ]
    )
    rc, out = once_with_shim(rig, shim, "fail-disconnect")
    log = rig.log()
    assert "ATTACH-FOREIGN" in rig.latch_reason()
    assert "could NOT be removed" in log, log[-800:]
    assert "foreign" in rig.run(["docker", "ps", "--format", "{{.Names}}"]).stdout.split(), (
        "not ours: not killed"
    )
    assert rig.supervised_running() == [] and rig.latched()
    # and the latch cannot be cleared while the foreign endpoint is still there
    r = rig.wd("reset")
    assert r.returncode != 0 and rig.latched(), r.stdout + r.stderr


def guard_rules(rig):
    return rig.netns("iptables", "-S", "HUNTER-EGRESS-GUARD").stdout.splitlines()


def test_TAMPER_deleting_the_guard_jump_is_structural_stop_first_then_repair(rig):
    jump = [
        ln
        for ln in rig.netns("iptables", "-S", "DOCKER-USER").stdout.splitlines()
        if "HUNTER-EGRESS-GUARD" in ln
    ]
    assert jump, rig.netns("iptables", "-S", "DOCKER-USER").stdout
    rig.netns("iptables", *jump[0].replace("-A", "-D", 1).split())
    assert rig.guard("status", check=False).returncode == 1, "a missing jump is never address drift"
    r = rig.once()
    log = rig.log()
    assert "QUARANTINE" in log and "GUARD-REPAIRED" in log, r.stdout + r.stderr + log
    assert "GUARD-ADDRESS-ABSORBED" not in log
    assert log.index("QUARANTINE") < log.index("GUARD-REPAIRED")
    assert rig.guard("status").returncode == 0 and not rig.latched()


def test_TAMPER_deleting_a_per_address_reject_is_drift_absorbed_without_a_stop(rig):
    rej = [ln for ln in guard_rules(rig) if re.search(r"-d \S+/32 -j REJECT", ln)]
    assert rej, guard_rules(rig)
    rig.netns("iptables", *rej[0].replace("-A", "-D", 1).split())
    assert rig.guard("status", check=False).returncode == 3, "address-only drift is exit 3"
    r = rig.once()
    log = rig.log()
    assert "GUARD-ADDRESS-ABSORBED" in log and "QUARANTINE" not in log, r.stdout + log
    assert rig.guard("status").returncode == 0
    assert len(rig.supervised_running()) == len(base.SUPERVISED) and not rig.latched()


def test_TAMPER_an_extra_accept_in_the_guard_chain_is_structural(rig):
    rig.netns("iptables", "-I", "HUNTER-EGRESS-GUARD", "1", "-j", "ACCEPT")
    assert rig.guard("status", check=False).returncode == 1, "an ACCEPT is never address drift"
    rig.once()
    log = rig.log()
    assert "QUARANTINE" in log and "GUARD-ADDRESS-ABSORBED" not in log


def hold_lock(path):
    fh = open(path, "a+")  # noqa: SIM115 - held by the test, closed by the caller
    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fh


def test_LOCK_a_deploy_holding_the_action_lock_pauses_the_watchdog_and_nothing_deadlocks(rig):
    action = rig.base / "state" / "containment.action.lock"
    action.parent.mkdir(parents=True, exist_ok=True)
    name, extra = hot_attach(rig)
    fh = hold_lock(action)  # what remote-deploy.sh does for a whole deploy
    try:
        t0 = time.monotonic()
        r = rig.once()
        assert time.monotonic() - t0 < 60, "a held action lock must not block the watchdog"
        assert rig.state().startswith("paused"), rig.state()
        assert extra in rig.networks_of(name), "nothing is changed under a deploy's feet"
        assert not rig.latched(), r.stdout + r.stderr
    finally:
        fh.close()
    rig.once()  # the deploy is over: the watchdog acts
    assert extra not in rig.networks_of(name) and rig.latched()


def test_LOCK_the_deploy_lock_itself_is_never_taken_by_the_watchdog(rig):
    deploy = rig.base / "state" / "deploy.lock"
    deploy.parent.mkdir(parents=True, exist_ok=True)
    name, extra = hot_attach(rig)
    fh = hold_lock(deploy)
    try:
        rig.once()
        assert extra not in rig.networks_of(name), "the watchdog does not wait for deploy.lock"
    finally:
        fh.close()


def test_LOCK_a_continuously_waiting_watchdog_does_not_starve_a_deploy(rig):
    """The set stopped and a protected address 'not live': every cycle has a problem to report and
    takes the action lock to look. A deploy waiting with `flock -w` must still get it quickly."""
    rig.run(
        ["docker", "stop", "-t", "1", *[f"{rig.project}-{s}-1" for s in base.SUPERVISED]],
        check=False,
    )
    (rig.stub / "targets_down").write_text("")
    w = subprocess.Popen(
        ["bash", str(base.CONTAINMENT), "watch", "--interval", "1"],
        env={**rig.env(), **rig.wenv()}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )  # fmt: skip
    action = rig.base / "state" / "containment.action.lock"
    try:
        assert wait_for(
            lambda: (rig.state_dir / "state").exists() and rig.state().startswith("waiting"), 120
        )
        waits = []
        for _ in range(12):
            t0 = time.monotonic()
            fh = open(action, "a+")  # noqa: SIM115
            fcntl.flock(fh, fcntl.LOCK_EX)  # blocking, like `flock -w` in the deploy
            waits.append(time.monotonic() - t0)
            fh.close()
            time.sleep(0.4)
        print(
            f"\nLOCK deploy waits behind a waiting watchdog: max {max(waits):.2f}s, "
            f"mean {sum(waits) / len(waits):.2f}s"
        )
        assert max(waits) < 30, waits
    finally:
        os.killpg(w.pid, 15)
        w.wait(timeout=30)


@pytest.mark.parametrize("victim", ["egress-codex", "agent-codex", "telegram"])
def test_RECOVERY_a_supervised_container_that_dies_comes_back_without_a_quarantine(rig, victim):
    """restart: "no" means the daemon will not restart it; the watchdog must, once, with its backoff
    (3 s here), without calling a crash an incident. The proxies are the services #14 replaced."""
    name = f"{rig.project}-{victim}-1"
    w = subprocess.Popen(
        ["bash", str(base.CONTAINMENT), "watch", "--interval", "3"],
        env={**rig.env(), **rig.wenv(HUNTER_CONTAINMENT_RESTART_BACKOFF="3")},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
    )  # fmt: skip
    try:
        assert wait_for(
            lambda: (rig.state_dir / "state").exists() and rig.state().startswith("ok"), 120
        )
        rig.run(["docker", "kill", name])
        assert name not in rig.run(["docker", "ps", "--format", "{{.Names}}"]).stdout.split()
        t = wait_for(
            lambda: name in rig.run(["docker", "ps", "--format", "{{.Names}}"]).stdout.split(), 90
        )
        assert t is not None, rig.log()[-800:]
        assert wait_for(lambda: len(rig.supervised_running()) == len(base.SUPERVISED), 60)
        print(f"\nRECOVERY {victim} back after {t:.1f}s")
        assert not rig.latched() and "QUARANTINE" not in rig.log() and "LATCHED" not in rig.log()
    finally:
        os.killpg(w.pid, 15)
        w.wait(timeout=30)
