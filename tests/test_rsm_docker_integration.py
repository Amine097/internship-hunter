"""REAL Docker, DISPOSABLE containers only (names hv-rsm-test-<run>-*, label
hunter-rsm-test=1). Never touches any other container: the policy lists only those names.

Runs when RSM_INTEGRATION=1 (CI, and locally with a docker CLI). The helper process is the
real `python -m hunter.rsm serve`, killed with SIGKILL mid-session."""
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid

import pytest

from hunter.rsm.broker import Broker
from hunter.rsm.dockerctl import CliDocker
from hunter.rsm.policy import parse_policy
from hunter.rsm.store import Store

pytestmark = pytest.mark.skipif(
    os.environ.get("RSM_INTEGRATION") != "1" or shutil.which("docker") is None,
    reason="RSM_INTEGRATION=1 and a docker CLI are required")

IMAGE = "alpine:3.20"
RUN = uuid.uuid4().hex[:8]
P = f"hv-rsm-test-{RUN}"


def sh(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check)


def running(name):
    r = sh("inspect", "-f", "{{.State.Running}}", name, check=False)
    return r.stdout.strip() == "true"


def policy_name(name):
    return f"{P}-{name}"


@pytest.fixture(scope="module", autouse=True)
def _image():
    sh("pull", "-q", IMAGE)


@pytest.fixture
def world(tmp_path):
    names = {k: policy_name(k) for k in ("vpn", "client", "worker", "protected", "stopped")}
    sh("run", "-d", "--name", names["vpn"], "--label", "hunter-rsm-test=1",
       "--restart", "always", IMAGE, "sleep", "3600")
    sh("run", "-d", "--name", names["client"], "--label", "hunter-rsm-test=1",
       "--restart", "unless-stopped", f"--network=container:{names['vpn']}",
       IMAGE, "sleep", "3600")
    sh("run", "-d", "--name", names["worker"], "--label", "hunter-rsm-test=1",
       "--restart", "no", IMAGE, "sleep", "3600")
    sh("run", "-d", "--name", names["protected"], "--label", "hunter-rsm-test=1",
       IMAGE, "sleep", "3600")
    sh("create", "--name", names["stopped"], "--label", "hunter-rsm-test=1", IMAGE,
       "sleep", "3600")
    doc = {
        "version": 1, "max_session_seconds": 600, "stale_contact_seconds": 2,
        "prepared_timeout_seconds": 60, "min_available_mib": 1,
        "protected": [names["protected"]],
        "containers": {
            names["worker"]: {"stop_timeout": 5},
            names["client"]: {"stop_timeout": 5, "depends_on": [names["vpn"]]},
            names["vpn"]: {"stop_timeout": 5},
            names["stopped"]: {"stop_timeout": 5},
        },
    }
    pol = tmp_path / "policy.json"
    pol.write_text(json.dumps(doc))
    yield names, pol, tmp_path
    for n in names.values():
        sh("rm", "-f", n, check=False)


def policy_of(pol_path):
    return parse_policy(json.loads(pol_path.read_text()))


def restart_policies(names):
    return {k: sh("inspect", "-f", "{{.HostConfig.RestartPolicy.Name}}", n).stdout.strip()
            for k, n in names.items()}


def call(sock, obj):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(120)
        s.connect(sock)
        s.sendall(json.dumps(obj).encode() + b"\n")
        return json.loads(s.makefile().readline())


def rsm_cli(*args, pol, state):
    return subprocess.run(
        [sys.executable, "-m", "hunter.rsm", *args, "--policy", str(pol),
         "--state-dir", str(state), "--docker-bin", shutil.which("docker"),
         "--insecure-policy-permissions"],
        capture_output=True, text=True, timeout=120)


def test_real_stop_restore_order_policies_and_untouched_bystanders(world):
    names, pol, tmp = world
    before = restart_policies(names)
    b = Broker(policy_of(pol), CliDocker(shutil.which("docker")), Store(tmp / "state"),
               probe_runner=lambda p: (False, ""))
    sid = f"it-{RUN}-0001"
    r = b.prepare(sid)
    assert r["ok"], r
    assert set(r["to_stop"]) == {names["vpn"], names["client"], names["worker"]}
    assert r["to_stop"].index(names["client"]) < r["to_stop"].index(names["vpn"])
    r = b.stop_approved(sid)
    assert r["ok"], r
    assert not running(names["vpn"]) and not running(names["client"])
    assert running(names["protected"])                    # never touched
    assert not running(names["stopped"])                  # was never running
    r = b.restore(sid)
    assert r["ok"], r
    assert running(names["vpn"]) and running(names["client"]) and running(names["worker"])
    assert running(names["protected"]) and not running(names["stopped"])
    assert restart_policies(names) == before              # restart policies preserved
    started = [e["container"] for e in b.store.audit_events() if e["event"] == "start"]
    assert started.index(names["vpn"]) < started.index(names["client"])


def test_unlisted_dependent_on_the_vpn_namespace_blocks_the_session(world):
    names, pol, tmp = world
    extra = f"{P}-unlisted"
    sh("run", "-d", "--name", extra, "--label", "hunter-rsm-test=1",
       f"--network=container:{names['vpn']}", IMAGE, "sleep", "3600")
    try:
        b = Broker(policy_of(pol), CliDocker(shutil.which("docker")), Store(tmp / "state"),
                   probe_runner=lambda p: (False, ""))
        r = b.prepare(f"it-{RUN}-0002")
        assert not r["ok"] and r["code"] == "blocked_dependency"
        assert running(names["vpn"]) and running(names["client"])
    finally:
        sh("rm", "-f", extra, check=False)


def test_killing_the_real_helper_process_mid_session_is_recovered_by_the_watchdog(world):
    names, pol, tmp = world
    state, sock = tmp / "state", str(tmp / "rsm.sock")
    server = subprocess.Popen(
        [sys.executable, "-m", "hunter.rsm", "serve", "--policy", str(pol),
         "--state-dir", str(state), "--socket", sock, "--docker-bin", shutil.which("docker"),
         "--insecure-policy-permissions"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(100):
            if os.path.exists(sock):
                break
            time.sleep(0.1)
        sid = f"it-{RUN}-0003"
        assert call(sock, {"op": "prepare", "session_id": sid})["ok"]
        assert call(sock, {"op": "stop_approved", "session_id": sid})["ok"]
        assert not running(names["vpn"])
    finally:
        server.send_signal(signal.SIGKILL)                  # the helper dies hard
        server.wait(timeout=10)
    assert not running(names["client"])                     # still down: nobody restored yet

    time.sleep(3)                                           # controller silent > 2 s
    r = rsm_cli("watchdog", pol=pol, state=state)           # independent systemd-timer unit
    out = json.loads(r.stdout)
    assert r.returncode == 0 and out["code"] == "restored" and out["reason"] == \
        "controller_silent", r.stdout + r.stderr
    assert running(names["vpn"]) and running(names["client"]) and running(names["worker"])
    assert running(names["protected"])
    status = rsm_cli("status", pol=pol, state=state)
    assert json.loads(status.stdout)["active"] is False


def test_boot_recovery_command_restores_after_a_simulated_reboot(world):
    """Simulated reboot: a `restart=unless-stopped` container we stopped stays down
    (exactly what Docker does), then the boot unit restores the snapshot."""
    names, pol, tmp = world
    state = tmp / "state"
    b = Broker(policy_of(pol), CliDocker(shutil.which("docker")), Store(state),
               probe_runner=lambda p: (False, ""))
    sid = f"it-{RUN}-0004"
    assert b.prepare(sid)["ok"] and b.stop_approved(sid)["ok"]
    assert not running(names["client"])
    r = rsm_cli("recover", pol=pol, state=state)
    out = json.loads(r.stdout)
    assert out["code"] == "restored" and out["reason"] == "boot_recovery", r.stdout + r.stderr
    assert running(names["client"]) and running(names["vpn"])


def test_policy_names_that_do_not_exist_are_ignored_not_created(world):
    names, pol, tmp = world
    doc = json.loads(pol.read_text())
    doc["containers"][f"{P}-ghost"] = {"stop_timeout": 5}
    pol.write_text(json.dumps(doc))
    b = Broker(policy_of(pol), CliDocker(shutil.which("docker")), Store(tmp / "state"),
               probe_runner=lambda p: (False, ""))
    r = b.prepare(f"it-{RUN}-0005")
    assert r["ok"] and f"{P}-ghost" not in r["to_stop"]
    assert sh("inspect", f"{P}-ghost", check=False).returncode != 0
    assert b.restore(f"it-{RUN}-0005")["ok"]
