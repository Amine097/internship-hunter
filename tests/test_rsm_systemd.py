"""The PRODUCTION units under a REAL systemd (the per-user manager), not just their text.

What this proves: socket activation hands the broker its listening descriptor; the broker
runs under the production sandbox (empty capability set, seccomp filter, no_new_privs) and
needs no chown/chmod; a SIGKILLed broker is restarted while the socket stays put; clients
connected through a restart are not lost.

What it cannot prove (needs the system manager + root + another user; see
deploy/rsm/pilot): SocketUser/SocketGroup ownership, EACCES for an unauthorised user, the
docker supplementary group, and rootless-Docker namespace mapping. The per-user manager
rejects those directives, so exactly those (and nothing else) are removed below.
"""
import ast
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import threading
import time
import uuid
from pathlib import Path

import pytest

from hunter.rsm_client import RsmClient

ROOT = Path(__file__).resolve().parents[1]
UNITS = ROOT / "deploy" / "rsm"
RUNTIME = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))


def _user_manager_ok() -> bool:
    if shutil.which("systemctl") is None or not RUNTIME.exists():
        return False
    r = subprocess.run(["systemctl", "--user", "is-system-running"], capture_output=True,
                       text=True, env={**os.environ, "XDG_RUNTIME_DIR": str(RUNTIME)})
    return r.stdout.strip() in ("running", "degraded")


pytestmark = pytest.mark.skipif(not _user_manager_ok(),
                                reason="needs a systemd --user manager")

# Directives the per-user manager cannot honour. The test removes ONLY these.
REMOVED_DIRECTIVES = {
    "SocketUser", "SocketGroup",                       # system manager only
    "User", "Group", "SupplementaryGroups",            # system manager only
    "StateDirectory", "StateDirectoryMode",            # replaced by a test directory
    "After", "Requires", "RequiresMountsFor",          # docker.service/mounts: system units
    "ListenStream", "ReadWritePaths", "ReadOnlyPaths", "ExecStart", "Environment",  # re-pointed
    "ProtectHome",                                      # repo lives under /home: read-only
    "WantedBy",
}


def uctl(*args, check=True):
    env = {**os.environ, "XDG_RUNTIME_DIR": str(RUNTIME)}
    return subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True,
                          env=env, check=check)


def directives(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z]+)=(.*)$", line.strip())
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def transform(text: str, repl: dict[str, str], renames: dict[str, str]) -> str:
    out = []
    skipping = False
    for line in text.splitlines():
        if skipping:                       # continuation lines of a removed directive
            skipping = line.rstrip().endswith("\\")
            continue
        m = re.match(r"^([A-Za-z]+)=", line.strip())
        key = m.group(1) if m else None
        if key in repl:
            out.append(f"{key}={repl[key]}")
            skipping = line.rstrip().endswith("\\")
            continue
        if key in REMOVED_DIRECTIVES:
            skipping = line.rstrip().endswith("\\")
            continue
        for a, b in renames.items():
            line = line.replace(a, b)
        out.append(line)
    return "\n".join(out) + "\n"


FAKE_DOCKER = """#!/bin/sh
# no daemon in this test: every container is 'missing', nothing is running
case "$1" in
  inspect) echo "Error: No such container: $4" >&2; exit 1;;
esac
exit 0
"""


@pytest.fixture
def broker_units(tmp_path):
    tag = f"hv-rsm-{uuid.uuid4().hex[:8]}"
    runtime_dir = RUNTIME / tag
    runtime_dir.mkdir(mode=0o750)
    # NOT under /tmp: the production unit has PrivateTmp=yes, which hides the host /tmp
    work = RUNTIME / f"{tag}-work"
    work.mkdir(mode=0o750)
    state = work / "state"
    state.mkdir()
    policy = work / "policy.json"
    policy.write_text('{"version": 1, "containers": {"hv-rsm-test-none": {}}}')
    fake = work / "docker"
    fake.write_text(FAKE_DOCKER)
    fake.chmod(0o755)
    sock = runtime_dir / "rsm.sock"

    prod_socket = (UNITS / "hunter-rsm.socket").read_text()
    prod_service = (UNITS / "hunter-rsm.service").read_text()
    renames = {"hunter-rsm.socket": f"{tag}.socket", "hunter-rsm.service": f"{tag}.service"}
    sock_unit = transform(prod_socket, {"ListenStream": str(sock)}, renames)
    svc_unit = transform(prod_service, {}, renames)
    svc_unit = svc_unit.replace("[Service]\n", (
        "[Service]\n"
        f"ExecStart=/usr/bin/python3 -m hunter.rsm serve --systemd --policy {policy} "
        f"--state-dir {state} --docker-bin {fake} --insecure-policy-permissions "
        f"--allowed-uid {os.getuid()}\n"
        f"Environment=PYTHONPATH={ROOT} PYTHONDONTWRITEBYTECODE=1\n"
        f"ReadWritePaths={state}\nProtectHome=read-only\n"), 1)
    svc_unit = svc_unit.replace("[Unit]\n", f"[Unit]\nRequires={tag}.socket\nAfter={tag}.socket\n",
                                1)
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    (unit_dir / f"{tag}.socket").write_text(sock_unit)
    (unit_dir / f"{tag}.service").write_text(svc_unit)
    uctl("daemon-reload")
    yield {"tag": tag, "sock": sock, "state": state, "socket_unit": sock_unit,
           "service_unit": svc_unit, "prod_socket": prod_socket, "prod_service": prod_service,
           "dir": runtime_dir}
    uctl("stop", f"{tag}.socket", f"{tag}.service", check=False)
    for suffix in ("socket", "service"):
        (unit_dir / f"{tag}.{suffix}").unlink(missing_ok=True)
    uctl("daemon-reload", check=False)
    shutil.rmtree(runtime_dir, ignore_errors=True)
    shutil.rmtree(work, ignore_errors=True)


def main_pid(tag):
    out = uctl("show", "-p", "MainPID", "--value", f"{tag}.service").stdout.strip()
    return int(out or 0)


def status_of(sock, timeout=20):
    return RsmClient(str(sock), timeout=timeout).status()


# ---- the production units are only minimally changed for this test ------------------------------

def test_only_whitelisted_directives_differ_from_production(broker_units):
    for prod, test in ((broker_units["prod_socket"], broker_units["socket_unit"]),
                       (broker_units["prod_service"], broker_units["service_unit"])):
        prod_set = {(k, v) for k, v in directives(prod) if k not in REMOVED_DIRECTIVES}
        test_set = {(k, v) for k, v in directives(test)
                    if k not in REMOVED_DIRECTIVES and not k.startswith("Exec")}
        norm = lambda v: re.sub(r"hunter-rsm|hv-rsm-[0-9a-f]{8}", "X", v)  # noqa: E731
        renamed = {(k, norm(v)) for k, v in prod_set}
        got = {(k, norm(v)) for k, v in test_set}
        assert renamed - got == set(), f"production directive dropped: {renamed - got}"
    # the sandbox itself is entirely preserved
    kept = {k for k, _ in directives(broker_units["service_unit"])}
    for must in ("NoNewPrivileges", "ProtectSystem", "PrivateTmp", "CapabilityBoundingSet",
                 "SystemCallFilter", "RestrictAddressFamilies", "SystemCallErrorNumber",
                 "RestrictNamespaces", "LockPersonality"):
        assert must in kept, must


def test_systemd_accepts_the_units(broker_units):
    tag = broker_units["tag"]
    r = subprocess.run(["systemd-analyze", "--user", "verify", f"{tag}.socket",
                        f"{tag}.service"], capture_output=True, text=True,
                       env={**os.environ, "XDG_RUNTIME_DIR": str(RUNTIME)},
                       cwd=Path.home() / ".config" / "systemd" / "user")
    bad = [ln for ln in r.stderr.splitlines()
           if re.search(r"Unknown (key|section|assignment)|Failed to parse|Invalid", ln)]
    assert bad == [], r.stderr


# ---- HIGH-1: socket activation under the production sandbox -------------------------------------

def test_socket_activation_starts_the_broker_on_first_connect(broker_units):
    tag, sock = broker_units["tag"], broker_units["sock"]
    uctl("start", f"{tag}.socket")
    assert uctl("is-active", f"{tag}.socket").stdout.strip() == "active"
    assert uctl("is-active", f"{tag}.service", check=False).stdout.strip() == "inactive"
    assert sock.exists() and stat.S_ISSOCK(sock.stat().st_mode)
    assert stat.S_IMODE(sock.stat().st_mode) == 0o660          # SocketMode, set by systemd
    assert sock.stat().st_uid == os.getuid()
    resp = status_of(sock)
    assert resp["ok"] is True and resp["code"] == "status"
    assert uctl("is-active", f"{tag}.service").stdout.strip() == "active"   # started on demand


def test_broker_inherits_fd3_and_runs_inside_the_sandbox(broker_units):
    tag, sock = broker_units["tag"], broker_units["sock"]
    uctl("start", f"{tag}.socket")
    status_of(sock)
    pid = main_pid(tag)
    assert pid > 0
    status = dict(ln.split(":\t", 1) for ln in Path(f"/proc/{pid}/status").read_text()
                  .splitlines() if ":\t" in ln)
    assert status["NoNewPrivs"].strip() == "1"
    assert int(status["CapEff"], 16) == 0 and int(status["CapBnd"], 16) == 0
    assert status["Seccomp"].strip() == "2"                    # filter mode: the unit's filter
    fds = {int(p.name): os.readlink(p) for p in Path(f"/proc/{pid}/fd").iterdir()}
    assert fds[3].startswith("socket:")                        # the inherited descriptor
    assert str(sock) not in " ".join(v for v in fds.values() if not v.startswith("socket:"))


def test_broker_needs_no_chown_and_the_sandbox_forbids_it(tmp_path):
    """Guards both halves: the production filter really blocks chown, and our code never
    calls it (so the broker cannot be re-broken by a future in-process chown)."""
    # same property set as the unit (ProtectSystem/PrivateTmp give the user manager the
    # user namespace it needs to drop the capability bounding set)
    props = ["-p", "NoNewPrivileges=yes", "-p", "ProtectSystem=strict", "-p", "PrivateTmp=yes",
             "-p", "CapabilityBoundingSet=",
             "-p", "AmbientCapabilities=", "-p", "SystemCallFilter=@system-service",
             "-p", "SystemCallFilter=~@privileged @resources @mount @swap @reboot @raw-io",
             "-p", "SystemCallErrorNumber=EPERM"]
    r = subprocess.run(
        ["systemd-run", "--user", "--wait", "--collect", "-q", "--pipe", *props,
         "/usr/bin/python3", "-c",
         "import os,sys\ntry:\n os.chown('/proc/self', -1, os.getgid())\nexcept PermissionError:"
         "\n print('EPERM')"],
        capture_output=True, text=True, env={**os.environ, "XDG_RUNTIME_DIR": str(RUNTIME)})
    assert "EPERM" in r.stdout, r.stdout + r.stderr
    banned = {"chown", "lchown", "fchown", "chmod", "fchmod"}
    for f in (ROOT / "hunter" / "rsm").glob("*.py"):
        for node in ast.walk(ast.parse(f.read_text())):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in banned and getattr(node.func.value, "id", "") == "os":
                pytest.fail(f"{f.name}:{node.lineno} calls os.{node.func.attr}")


def test_the_real_docker_cli_runs_under_the_production_filter():
    """The helper shells out to the docker CLI (a Go binary); a too-strict syscall filter would
    kill it (SIGSYS) at startup. Client-only: no daemon needed."""
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("no docker CLI installed")
    props = ["-p", "NoNewPrivileges=yes", "-p", "ProtectSystem=strict", "-p", "PrivateTmp=yes",
             "-p", "CapabilityBoundingSet=", "-p", "AmbientCapabilities=",
             "-p", "SystemCallArchitectures=native",
             "-p", "SystemCallFilter=@system-service",
             "-p", "SystemCallFilter=~@privileged @resources @mount @swap @reboot @raw-io",
             "-p", "SystemCallErrorNumber=EPERM", "-p", "RestrictAddressFamilies=AF_UNIX "
             "AF_INET AF_INET6"]
    r = subprocess.run(["systemd-run", "--user", "--wait", "--collect", "-q", "--pipe", *props,
                        docker, "--version"], capture_output=True, text=True,
                       env={**os.environ, "XDG_RUNTIME_DIR": str(RUNTIME)})
    assert "Docker version" in r.stdout, r.stdout + r.stderr


def test_serve_systemd_outside_systemd_fails_clearly(tmp_path):
    from hunter.rsm.broker import Broker
    from hunter.rsm.policy import parse_policy
    from hunter.rsm.server import RsmServer
    from hunter.rsm.store import Store
    b = Broker(parse_policy({"version": 1, "containers": {"x": {}}}), None,
               Store(tmp_path / "s"))
    for env in ({}, {"LISTEN_PID": "1", "LISTEN_FDS": "1"}, {"LISTEN_PID": str(os.getpid()),
                                                             "LISTEN_FDS": "0"}):
        for k in ("LISTEN_PID", "LISTEN_FDS"):
            os.environ.pop(k, None)
        os.environ.update(env)
        with pytest.raises(RuntimeError, match="not socket-activated"):
            RsmServer.from_systemd(b)
        for k in ("LISTEN_PID", "LISTEN_FDS"):
            os.environ.pop(k, None)


# ---- HIGH-2: stable lifecycle -------------------------------------------------------------------

def test_killed_broker_is_restarted_and_the_socket_never_changes(broker_units):
    tag, sock = broker_units["tag"], broker_units["sock"]
    uctl("start", f"{tag}.socket")
    status_of(sock)
    inode, pid = sock.stat().st_ino, main_pid(tag)
    os.kill(pid, signal.SIGKILL)                               # the broker crashes
    resp = status_of(sock, timeout=30)                         # queued, then served by the new one
    assert resp["ok"] is True
    new_pid = main_pid(tag)
    assert new_pid not in (0, pid)
    assert sock.stat().st_ino == inode                         # same socket inode throughout
    assert int(uctl("show", "-p", "NRestarts", "--value", f"{tag}.service").stdout) >= 1


def test_clients_survive_a_broker_restart_in_the_middle_of_their_calls(broker_units):
    tag, sock = broker_units["tag"], broker_units["sock"]
    uctl("start", f"{tag}.socket")
    status_of(sock)
    failures, calls, stop = [], [0], threading.Event()

    def controller():                                           # the long-running controller
        client = RsmClient(str(sock), timeout=30)
        while not stop.is_set():
            try:
                client.status()
                calls[0] += 1
            except Exception as exc:
                failures.append(repr(exc))
            time.sleep(0.05)

    t = threading.Thread(target=controller)
    t.start()
    for _ in range(3):
        time.sleep(0.5)
        uctl("restart", f"{tag}.service")                      # operator restarts the broker
        time.sleep(0.5)
    stop.set()
    t.join(timeout=60)
    assert failures == [], failures
    assert calls[0] > 10


def test_broker_started_after_the_client_is_waited_for_not_refused(broker_units):
    """Mirrors 'rootless daemon (and its controller) started BEFORE the broker': the socket
    exists first (it is activated at boot) so a connect queues instead of failing."""
    tag, sock = broker_units["tag"], broker_units["sock"]
    uctl("start", f"{tag}.socket")
    assert uctl("is-active", f"{tag}.service", check=False).stdout.strip() == "inactive"
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(20)
    s.connect(str(sock))                                       # accepted by the kernel queue
    s.sendall(b'{"op": "status"}\n')
    assert b'"ok": true' in s.makefile("rb").readline()        # broker spawned, answered
    s.close()


def test_socket_unit_restart_keeps_the_directory_stable(broker_units):
    tag, sock = broker_units["tag"], broker_units["sock"]
    uctl("start", f"{tag}.socket")
    status_of(sock)
    d_inode = sock.parent.stat().st_ino
    uctl("restart", f"{tag}.socket")                           # inode of the SOCKET may change
    assert sock.parent.stat().st_ino == d_inode                # the bind-mounted DIRECTORY does not
    assert status_of(sock)["ok"] is True
    assert stat.S_IMODE(sock.parent.stat().st_mode) & 0o007 == 0   # not world accessible
    assert stat.S_IMODE(sock.stat().st_mode) & 0o002 == 0          # not world writable


# ---- the WATCHDOG unit, run by real systemd under the production sandbox ------------------------

FAKE_DOCKER_WITH_STATE = """#!/bin/sh
D="$(dirname "$0")"
case "$1" in
  inspect)
    running=false; [ -f "$D/state/started" ] && running=true
    echo "[{\\"Id\\":\\"abc123\\",\\"Name\\":\\"/$4\\",\\"State\\":{\\"Running\\":$running},"\
"\\"HostConfig\\":{\\"RestartPolicy\\":{\\"Name\\":\\"no\\"},\\"NetworkMode\\":\\"default\\"},"\
"\\"Config\\":{\\"Labels\\":{}}}]";;
  start) touch "$D/state/started";;
  ps) ;;
esac
exit 0
"""

SESSION = {"version": 1, "history": [], "session": {
    "id": "pilot-aaaaaaaa", "phase": "stopped", "created_at": 0, "deadline": 4e9,
    "last_contact": 0, "snapshot": [{"name": "hv-rsm-test-none", "id": "abc123",
                                      "restart_policy": "no"}],
    "stop_order": ["hv-rsm-test-none"], "stopped": ["hv-rsm-test-none"], "skipped": [],
    "failures": {}}}


def run_watchdog_unit(tag_suffix, state_text, command="watchdog"):
    import json
    tag = f"hv-rsm-{uuid.uuid4().hex[:8]}-{tag_suffix}"
    work = RUNTIME / f"{tag}-work"
    work.mkdir(mode=0o750)
    state = work / "state"
    state.mkdir()
    (state / "session.json").write_text(state_text if isinstance(state_text, str)
                                         else json.dumps(state_text))
    (work / "policy.json").write_text('{"version": 1, "containers": {"hv-rsm-test-none": {}}}')
    fake = work / "docker"
    fake.write_text(FAKE_DOCKER_WITH_STATE)
    fake.chmod(0o755)
    prod = (UNITS / f"hunter-rsm-{'recover' if command == 'recover' else 'watchdog'}.service"
            ).read_text()
    text = transform(prod, {}, {}).replace("[Service]\n", (
        "[Service]\n"
        f"ExecStart=/usr/bin/python3 -m hunter.rsm {command} --policy {work}/policy.json "
        f"--state-dir {state} --docker-bin {fake} --insecure-policy-permissions\n"
        f"Environment=PYTHONPATH={ROOT} PYTHONDONTWRITEBYTECODE=1\n"
        f"ReadWritePaths={state}\nProtectHome=read-only\n"), 1)
    unit = Path.home() / ".config" / "systemd" / "user" / f"{tag}.service"
    unit.write_text(text)
    uctl("daemon-reload")
    try:
        r = uctl("start", f"{tag}.service", check=False)
        show = dict(ln.split("=", 1) for ln in uctl(
            "show", "-p", "Result", "-p", "ExecMainStatus", f"{tag}.service"
        ).stdout.splitlines() if "=" in ln)
        return {"result": show["Result"], "status": int(show["ExecMainStatus"]),
                "started": (state / "started").exists(),
                "state": (state / "session.json").read_text(),
                "audit": (state / "audit.log").read_text() if (state / "audit.log").exists()
                else "", "stderr": r.stderr}
    finally:
        uctl("stop", f"{tag}.service", check=False)
        unit.unlink(missing_ok=True)
        uctl("daemon-reload", check=False)
        shutil.rmtree(work, ignore_errors=True)


def test_watchdog_unit_restores_a_silent_session_under_the_sandbox():
    out = run_watchdog_unit("restore", SESSION)
    assert out["result"] == "success" and out["status"] == 0, out["stderr"]
    assert out["started"] is True                                  # the container was started
    assert '"session": null' in out["state"]
    assert "watchdog_restore" in out["audit"] and "controller_silent" in out["audit"]


def test_boot_recovery_unit_restores_regardless_of_deadline_under_the_sandbox():
    out = run_watchdog_unit("boot", SESSION, command="recover")
    assert out["result"] == "success" and out["started"] is True
    assert "boot_recovery" in out["audit"]


def test_watchdog_unit_fails_loudly_on_corrupt_state_and_acts_on_nothing():
    out = run_watchdog_unit("corrupt", "{truncated")
    assert out["result"] == "exit-code" and out["status"] == 3      # visible in systemd
    assert out["started"] is False
    assert out["state"] == "{truncated"                              # untouched, not "idle"
    assert "state_corrupt" in out["audit"]
