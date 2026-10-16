"""The PRODUCTION units under the REAL system manager, as root, on a DISPOSABLE host.

Runs only in the `rsm-systemd` CI job (ephemeral GitHub-hosted runner, sudo). It installs the
units, code, policy and socket directory at their production paths, the way
docs/resource-sessions.md does, with disposable users, and removes everything afterwards (the
fixture teardown and the job's `if: always()` step, `python tests/test_rsm_systemd.py --cleanup`).
The unit files are installed byte-for-byte (placeholders substituted). The ONE test-only
change is a drop-in that bind-mounts a fake `docker` over /usr/bin/docker inside the units'
own mount namespace, so no real container is ever inspected, stopped or started.

What this proves: socket activation hands the broker its listening descriptor; systemd owns the
socket (SocketUser/SocketGroup/SocketMode) and its stable directory; the authorised uid is
served, a member of the socket group with another uid is refused by SO_PEERCRED, and any other
user gets EACCES; the broker runs under the production sandbox (empty capability bounding set,
seccomp filter, no_new_privs) with the docker supplementary group and needs no chown/chmod; a
SIGKILLed broker is restarted while the socket stays put; clients connected through a restart
are not lost; the watchdog and boot-recovery units restore under the same sandbox.

What it cannot prove: rootless-Docker namespace mapping (deploy/rsm/pilot, rsm-pilot.yaml).
"""
import ast
import grp
import json
import os
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
UNITS = ROOT / "deploy" / "rsm"
SYSTEMD_DIR = Path("/etc/systemd/system")
UNIT_FILES = ("hunter-rsm.socket", "hunter-rsm.service", "hunter-rsm-watchdog.service",
              "hunter-rsm-watchdog.timer", "hunter-rsm-recover.service")
SERVICES = ("hunter-rsm.service", "hunter-rsm-watchdog.service", "hunter-rsm-recover.service")
SOCK = Path("/var/lib/hunter-rsm-ipc/rsm.sock")
STATE = Path("/var/lib/hunter-rsm")
TEST_DIR = Path("/opt/hv-rsm-test")              # fake docker + a copy of the client
MARKER = TEST_DIR / "installed-by-test_rsm_systemd"
FAKE_STATE = STATE / ".hv-fake-docker"
HELPER, CLIENT, MEMBER, OTHER = "hunter-rsm", "hv-rsm-client", "hv-rsm-member", "hv-rsm-other"
USERS = (OTHER, MEMBER, CLIENT, HELPER)           # deletion order (MEMBER is in CLIENT's group)
INSTALLED = [*(SYSTEMD_DIR / u for u in UNIT_FILES),
             *(SYSTEMD_DIR / f"{s}.d" for s in SERVICES),
             Path("/etc/tmpfiles.d/hunter-rsm.conf"), Path("/opt/hunter-rsm"),
             Path("/etc/hunter-rsm"), STATE, SOCK.parent, TEST_DIR]
POLICY = '{"version": 1, "containers": {"hv-rsm-test-none": {}}}\n'
DROPIN = """# CI only (tests/test_rsm_systemd.py): a fake docker inside THIS unit's mount namespace.
[Service]
BindReadOnlyPaths=/opt/hv-rsm-test/docker:/usr/bin/docker
"""
FAKE_DOCKER = """#!/bin/sh
# hv-rsm-test fake docker: no daemon is ever contacted. One container, hv-rsm-test-none.
F=/var/lib/hunter-rsm/.hv-fake-docker
echo "$*" >> "$F/calls"
case "$1" in
  inspect)
    running=false; [ -f "$F/started" ] && running=true
    echo "[{\\"Id\\":\\"abc123\\",\\"Name\\":\\"/$4\\",\\"State\\":{\\"Running\\":$running},"\\
"\\"HostConfig\\":{\\"RestartPolicy\\":{\\"Name\\":\\"no\\"},\\"NetworkMode\\":\\"default\\"},"\\
"\\"Config\\":{\\"Labels\\":{}}}]";;
  start) touch "$F/started";;
  ps) ;;
esac
exit 0
"""

ENABLED = os.environ.get("RSM_SYSTEMD") == "1"
pytestmark = pytest.mark.skipif(
    not ENABLED, reason="root + system manager on a disposable host: the rsm-systemd CI job")


def run(*cmd, check=True, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, check=check, **kw)


def ctl(*args, check=True):
    return run("systemctl", *args, check=check)


def show(unit, *props) -> dict:
    out = ctl("show", unit, *(f"-p{p}" for p in props)).stdout
    return dict(ln.split("=", 1) for ln in out.splitlines() if "=" in ln)


def disposable_host_problem() -> str | None:
    if os.environ.get("RSM_SYSTEMD_DISPOSABLE_HOST") == "1":
        return None
    if os.environ.get("GITHUB_ACTIONS") == "true" \
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted":
        return None
    return ("refusing: this installs at the PRODUCTION paths; run only on an ephemeral "
            "GitHub-hosted runner (or set RSM_SYSTEMD_DISPOSABLE_HOST=1 in a throwaway VM)")


def substitute(name: str) -> str:
    text = (UNITS / name).read_text()
    text = text.replace("__HUNTER_CLIENT_GROUP__", CLIENT)       # CLIENT's primary group
    return text.replace("__HUNTER_ROOTLESS_UID__", str(pwd.getpwnam(CLIENT).pw_uid))


def install() -> None:
    problem = disposable_host_problem()
    if problem:
        pytest.fail(problem)
    if os.geteuid() != 0:
        pytest.fail("must run as root (sudo) against the system manager")
    state = run("systemctl", "is-system-running", check=False).stdout.strip()
    if state not in ("running", "degraded"):
        pytest.fail(f"system manager not usable: {state!r}")
    present = [str(p) for p in INSTALLED if p.exists()]
    present += [u for u in USERS if _exists(pwd.getpwnam, u)]
    if present:
        pytest.fail(f"refusing: an RSM installation (or a leftover) exists: {present}")
    if not Path("/usr/bin/docker").is_file() or not _exists(grp.getgrnam, "docker"):
        pytest.fail("needs the docker CLI at /usr/bin/docker and a 'docker' group")
    TEST_DIR.mkdir(mode=0o755)
    MARKER.write_text("created by tests/test_rsm_systemd.py; removed by --cleanup\n")

    # users (docs step 2; the helper is NOT added to docker: SupplementaryGroups= grants it)
    run("adduser", "--system", "--group", "--no-create-home", "--shell", "/usr/sbin/nologin",
        HELPER)
    run("useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", "--user-group", CLIENT)
    run("useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", "--user-group",
        "--groups", CLIENT, MEMBER)
    run("useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", "--user-group", OTHER)

    # code: root-owned, stdlib only (as install-pilot.sh)
    src = Path("/opt/hunter-rsm/src/hunter")
    src.mkdir(parents=True)
    shutil.copy(ROOT / "hunter" / "__init__.py", src / "__init__.py")
    shutil.copytree(ROOT / "hunter" / "rsm", src / "rsm",
                    ignore=shutil.ignore_patterns("__pycache__"))
    client = TEST_DIR / "src" / "hunter"
    client.mkdir(parents=True)
    shutil.copy(ROOT / "hunter" / "__init__.py", client / "__init__.py")
    shutil.copy(ROOT / "hunter" / "rsm_client.py", client / "rsm_client.py")
    for base in (Path("/opt/hunter-rsm"), TEST_DIR):
        for p in (base, *base.rglob("*")):
            os.chown(p, 0, 0)
            p.chmod(0o755 if p.is_dir() else 0o644)
    fake = TEST_DIR / "docker"
    fake.write_text(FAKE_DOCKER)
    fake.chmod(0o755)

    # policy: root-owned, not group/world writable (the REAL permission check runs)
    Path("/etc/hunter-rsm").mkdir(mode=0o755)
    Path("/etc/hunter-rsm/policy.json").write_text(POLICY)
    Path("/etc/hunter-rsm/policy.json").chmod(0o644)

    # socket directory (tmpfiles.d) and units, exactly as shipped
    tmpfiles = Path("/etc/tmpfiles.d/hunter-rsm.conf")
    tmpfiles.write_text((UNITS / "tmpfiles-hunter-rsm.conf").read_text()
                        .replace("__HUNTER_CLIENT_GROUP__", CLIENT))
    run("systemd-tmpfiles", "--create", str(tmpfiles))
    for name in UNIT_FILES:
        text = substitute(name)
        assert "__HUNTER_" not in text, name
        (SYSTEMD_DIR / name).write_text(text)
    for svc in SERVICES:
        (SYSTEMD_DIR / f"{svc}.d").mkdir()
        (SYSTEMD_DIR / f"{svc}.d" / "hv-rsm-test.conf").write_text(DROPIN)
    ctl("daemon-reload")                     # nothing is enabled: the timer never fires


def _exists(lookup, name) -> bool:
    try:
        lookup(name)
        return True
    except KeyError:
        return False


def cleanup() -> list[str]:
    """Removes what install() created - only if its marker proves install() created it."""
    if MARKER.exists():
        ctl("stop", "hunter-rsm-watchdog.timer", "hunter-rsm.socket", *SERVICES, check=False)
        ctl("reset-failed", "hunter-rsm*", check=False)
        for p in INSTALLED:
            if p.is_dir() and not p.is_symlink():
                shutil.rmtree(p, ignore_errors=True)
            else:
                p.unlink(missing_ok=True)
        for user in USERS:
            if _exists(pwd.getpwnam, user):
                run("userdel", user, check=False)
            if _exists(grp.getgrnam, user):
                run("groupdel", user, check=False)
        ctl("daemon-reload", check=False)
    left = [str(p) for p in INSTALLED if p.exists()]
    left += [u for u in USERS if _exists(pwd.getpwnam, u) or _exists(grp.getgrnam, u)]
    return left


@pytest.fixture(scope="module")
def host():
    try:
        install()
        yield
    finally:
        left = cleanup()
        assert left == [], f"left behind: {left}"


@pytest.fixture
def fresh(host):
    """Every test starts with stopped units and an empty broker state directory."""
    def reset():
        ctl("stop", "hunter-rsm.socket", *SERVICES, check=False)
        ctl("reset-failed", "hunter-rsm*", check=False)
        shutil.rmtree(STATE, ignore_errors=True)
        uid, gid = pwd.getpwnam(HELPER).pw_uid, grp.getgrnam(HELPER).gr_gid
        for d in (STATE, FAKE_STATE):
            d.mkdir(mode=0o750)
            os.chown(d, uid, gid)
    reset()
    yield
    reset()


# ---- talking to the broker AS a given user (the uid is what SO_PEERCRED sees) -----------------

RAW_CALL = r"""
import json, socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(float(sys.argv[3]))
try:
    s.connect(sys.argv[1])
    s.sendall(sys.argv[2].encode() + b"\n")
    print(s.makefile("rb").readline().decode().strip())
except OSError as exc:
    print(json.dumps({"exception": type(exc).__name__, "errno": exc.errno}))
"""
CLIENT_STATUS = r"""
import json, sys
sys.path.insert(0, "/opt/hv-rsm-test/src")
from hunter.rsm_client import RsmClient
print(json.dumps(RsmClient(sys.argv[1], timeout=float(sys.argv[2])).status()))
"""
CONTROLLER_LOOP = r"""
import json, sys, threading, time
sys.path.insert(0, "/opt/hv-rsm-test/src")
from hunter.rsm_client import RsmClient
stop = threading.Event()
threading.Thread(target=lambda: (sys.stdin.read(), stop.set()), daemon=True).start()
client, calls, failures = RsmClient(sys.argv[1], timeout=30), 0, []
while not stop.is_set():
    try:
        client.status()
        calls += 1
    except Exception as exc:
        failures.append(repr(exc))
    time.sleep(0.05)
print(json.dumps({"calls": calls, "failures": failures}))
"""


def as_user(user: str) -> dict:
    pw = pwd.getpwnam(user)
    return {"user": pw.pw_uid, "group": pw.pw_gid,
            "extra_groups": os.getgrouplist(user, pw.pw_gid), "cwd": "/",
            "env": {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}}


def call(user: str, payload: str = '{"op": "status"}', timeout: float = 30) -> dict:
    r = subprocess.run(["/usr/bin/python3", "-c", RAW_CALL, str(SOCK), payload, str(timeout)],
                       capture_output=True, text=True, timeout=timeout + 30, **as_user(user))
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def status_of(user: str = CLIENT, timeout: float = 20) -> dict:
    r = subprocess.run(["/usr/bin/python3", "-c", CLIENT_STATUS, str(SOCK), str(timeout)],
                       capture_output=True, text=True, timeout=timeout * 4 + 30, **as_user(user))
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def main_pid(unit="hunter-rsm.service") -> int:
    return int(show(unit, "MainPID").get("MainPID") or 0)


def proc_status(pid: int) -> dict:
    return dict(ln.split(":\t", 1) for ln in Path(f"/proc/{pid}/status").read_text()
                .splitlines() if ":\t" in ln)


def directives(text: str) -> list[tuple[str, str]]:
    out = []
    for line in re.sub(r"\\\n\s*", " ", text).splitlines():
        m = re.match(r"^([A-Za-z]+)=(.*)$", line.strip())
        if m:
            out.append((m.group(1), m.group(2)))
    return out


# Every [Service] directive of the production broker unit applies to a transient unit, except
# how the process is started and restarted.
NOT_TRANSIENT = {"Type", "ExecStart", "Restart", "RestartSec"}


def production_sandbox_props() -> list[str]:
    service = (UNITS / "hunter-rsm.service").read_text().split("[Service]", 1)[1]
    service = service.split("\n[", 1)[0]
    props = [f"{k}={v}" for k, v in directives(service) if k not in NOT_TRANSIENT]
    keys = {p.split("=", 1)[0] for p in props}
    for must in ("User", "SupplementaryGroups", "NoNewPrivileges", "CapabilityBoundingSet",
                 "SystemCallFilter", "SystemCallErrorNumber", "RestrictNamespaces"):
        assert must in keys, must
    return [arg for p in props for arg in ("-p", p)]


def transient(*cmd) -> subprocess.CompletedProcess:
    return run("systemd-run", "--wait", "--collect", "-q", "--pipe", *production_sandbox_props(),
               *cmd, check=False, timeout=120)


# ---- the installed units ARE the production units ----------------------------------------------

def test_installed_units_are_production_plus_only_the_fake_docker_dropin(fresh):
    for name in UNIT_FILES:
        assert (SYSTEMD_DIR / name).read_text() == substitute(name), name
    dropins = sorted(p for p in SYSTEMD_DIR.glob("hunter-rsm*.d/*"))
    assert [p.name for p in dropins] == ["hv-rsm-test.conf"] * len(SERVICES)
    assert all(p.read_text() == DROPIN for p in dropins)
    # what systemd actually LOADED for each service: the production sandbox, nothing relaxed
    for unit in SERVICES:
        got = show(unit, "User", "SupplementaryGroups", "NoNewPrivileges", "ProtectSystem",
                   "ProtectHome", "PrivateTmp", "PrivateDevices", "CapabilityBoundingSet",
                   "AmbientCapabilities", "SystemCallFilter", "SystemCallErrorNumber",
                   "SystemCallArchitectures", "RestrictNamespaces", "RestrictAddressFamilies",
                   "LockPersonality", "RestrictSUIDSGID", "UMask", "BindReadOnlyPaths",
                   "DropInPaths")
        assert got["User"] == HELPER and got["SupplementaryGroups"] == "docker", unit
        assert got["NoNewPrivileges"] == "yes" and got["ProtectSystem"] == "strict", unit
        assert got["ProtectHome"] == "yes" and got["PrivateTmp"] == "yes", unit
        assert got["PrivateDevices"] == "yes" and got["LockPersonality"] == "yes", unit
        assert got["CapabilityBoundingSet"] == "" and got["AmbientCapabilities"] == "", unit
        assert got["SystemCallArchitectures"] == "native", unit
        allowed = set(got["SystemCallFilter"].split())          # loaded as an allow-list
        assert {"read", "write", "connect"} <= allowed, unit
        assert not allowed & {"chown", "fchown", "fchownat", "lchown", "mount", "umount2",
                              "reboot", "swapon", "setrlimit", "ioperm"}, unit
        assert got["SystemCallErrorNumber"] in ("1", "EPERM"), unit
        assert got["RestrictNamespaces"] == "yes" and got["RestrictSUIDSGID"] == "yes", unit
        assert set(got["RestrictAddressFamilies"].split()) == {"AF_UNIX", "AF_INET",
                                                               "AF_INET6"}, unit
        assert got["UMask"] == "0027", unit
        assert got["BindReadOnlyPaths"] in ("/opt/hv-rsm-test/docker:/usr/bin/docker",
                                            "/opt/hv-rsm-test/docker:/usr/bin/docker:rbind"), unit
        assert got["DropInPaths"] == f"/etc/systemd/system/{unit}.d/hv-rsm-test.conf", unit
    sock = show("hunter-rsm.socket", "SocketUser", "SocketGroup", "SocketMode",
                "DirectoryMode", "RemoveOnStop", "Accept", "Listen")
    assert (sock["SocketUser"], sock["SocketGroup"], sock["SocketMode"]) == \
        (HELPER, CLIENT, "0660")
    assert sock["RemoveOnStop"] == "no" and sock["Accept"] == "no"
    assert sock["Listen"] == f"{SOCK} (Stream)"
    # the sandbox itself is entirely present in the PRODUCTION file
    kept = {k for k, _ in directives((UNITS / "hunter-rsm.service").read_text())}
    for must in ("NoNewPrivileges", "ProtectSystem", "PrivateTmp", "CapabilityBoundingSet",
                 "SystemCallFilter", "RestrictAddressFamilies", "SystemCallErrorNumber",
                 "RestrictNamespaces", "LockPersonality"):
        assert must in kept, must


def test_systemd_accepts_the_units(fresh):
    r = run("systemd-analyze", "verify", *(str(SYSTEMD_DIR / u) for u in UNIT_FILES),
            check=False)
    bad = [ln for ln in r.stderr.splitlines()
           if re.search(r"Unknown (key|section|assignment)|Failed to parse|Invalid", ln)]
    assert bad == [], r.stderr


# ---- HIGH-1: socket activation, ownership and authorisation ------------------------------------

def test_socket_activation_starts_the_broker_on_first_connect(fresh):
    ctl("start", "hunter-rsm.socket")
    assert ctl("is-active", "hunter-rsm.socket").stdout.strip() == "active"
    assert ctl("is-active", "hunter-rsm.service", check=False).stdout.strip() == "inactive"
    st = SOCK.stat()
    assert stat.S_ISSOCK(st.st_mode)
    assert stat.S_IMODE(st.st_mode) == 0o660                   # SocketMode, set by systemd
    assert st.st_uid == pwd.getpwnam(HELPER).pw_uid            # SocketUser
    assert st.st_gid == grp.getgrnam(CLIENT).gr_gid            # SocketGroup
    d = SOCK.parent.stat()                                     # tmpfiles.d, root-owned
    assert (d.st_uid, d.st_gid, stat.S_IMODE(d.st_mode)) == (0, grp.getgrnam(CLIENT).gr_gid,
                                                             0o750)
    resp = status_of(CLIENT)
    assert resp["ok"] is True and resp["code"] == "status"
    assert ctl("is-active", "hunter-rsm.service").stdout.strip() == "active"   # on demand


def test_only_the_authorised_uid_is_served(fresh):
    ctl("start", "hunter-rsm.socket")
    assert call(CLIENT)["ok"] is True
    # same group as the socket, other uid: passes the file permissions, refused by SO_PEERCRED
    assert grp.getgrnam(CLIENT).gr_gid in os.getgrouplist(MEMBER, pwd.getpwnam(MEMBER).pw_gid)
    assert call(MEMBER) == {"ok": False, "code": "forbidden"}
    # no group access: the kernel refuses before the broker sees anything
    assert call(OTHER) == {"exception": "PermissionError", "errno": 13}
    # root bypasses the file permissions, but uid 0 is not on the allow-list either
    assert call("root") == {"ok": False, "code": "forbidden"}
    audit = [json.loads(ln) for ln in (STATE / "audit.log").read_text().splitlines() if ln]
    rejected = sorted(e["uid"] for e in audit if e.get("event") == "peer_rejected")
    assert rejected == sorted([0, pwd.getpwnam(MEMBER).pw_uid])
    # the authorised user holds no docker privilege of its own
    assert grp.getgrnam("docker").gr_gid not in os.getgrouplist(CLIENT,
                                                                 pwd.getpwnam(CLIENT).pw_gid)


def test_broker_inherits_fd3_and_runs_inside_the_sandbox(fresh):
    ctl("start", "hunter-rsm.socket")
    status_of(CLIENT)
    pid = main_pid()
    assert pid > 0
    status = proc_status(pid)
    assert status["NoNewPrivs"].strip() == "1"
    assert int(status["CapEff"], 16) == 0 and int(status["CapBnd"], 16) == 0
    assert int(status["CapPrm"], 16) == 0 and int(status["CapAmb"], 16) == 0
    assert status["Seccomp"].strip() == "2"                    # filter mode: the unit's filter
    assert status["Uid"].split()[0] == str(pwd.getpwnam(HELPER).pw_uid)
    assert str(grp.getgrnam("docker").gr_gid) in status["Groups"].split()
    fds = {int(p.name): os.readlink(p) for p in Path(f"/proc/{pid}/fd").iterdir()}
    assert fds[3].startswith("socket:")                        # the inherited descriptor
    assert str(SOCK) not in " ".join(v for v in fds.values() if not v.startswith("socket:"))
    # the fake docker is what /usr/bin/docker is INSIDE the broker's mount namespace
    assert Path(f"/proc/{pid}/root/usr/bin/docker").read_text() == FAKE_DOCKER


def test_broker_needs_no_chown_and_the_sandbox_forbids_it(fresh):
    """Guards both halves: the production filter really blocks chown, and our code never
    calls it (so the broker cannot be re-broken by a future in-process chown)."""
    # a no-op chown of a file the process OWNS is always permitted by the kernel, so only the
    # seccomp filter can refuse it (procfs would refuse any chown and prove nothing)
    r = transient("/usr/bin/python3", "-c",
                  "import os, tempfile\nfd, p = tempfile.mkstemp()\n"
                  "try:\n os.chown(p, os.getuid(), os.getgid())\n print('CHOWN-ALLOWED')\n"
                  "except PermissionError:\n print('EPERM')\n"
                  "print([l for l in open('/proc/self/status') if l.startswith('CapBnd')])")
    assert "EPERM" in r.stdout and "CHOWN-ALLOWED" not in r.stdout, r.stdout + r.stderr
    assert "0000000000000000" in r.stdout, r.stdout             # empty bounding set
    banned = {"chown", "lchown", "fchown", "chmod", "fchmod"}
    for f in (ROOT / "hunter" / "rsm").glob("*.py"):
        for node in ast.walk(ast.parse(f.read_text())):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in banned and getattr(node.func.value, "id", "") == "os":
                pytest.fail(f"{f.name}:{node.lineno} calls os.{node.func.attr}")


def test_the_real_docker_cli_runs_under_the_production_filter(fresh):
    """The helper shells out to the docker CLI (a Go binary); a too-strict syscall filter would
    kill it (SIGSYS) at startup. Client-only: no daemon is contacted."""
    r = transient("/usr/bin/docker", "--version")
    assert r.returncode == 0 and "Docker version" in r.stdout, r.stdout + r.stderr


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

def test_killed_broker_is_restarted_and_the_socket_never_changes(fresh):
    ctl("start", "hunter-rsm.socket")
    status_of(CLIENT)
    inode, pid = SOCK.stat().st_ino, main_pid()
    os.kill(pid, signal.SIGKILL)                               # the broker crashes
    resp = status_of(CLIENT, timeout=30)                       # queued, then served by the new one
    assert resp["ok"] is True
    new_pid = main_pid()
    assert new_pid not in (0, pid)
    assert SOCK.stat().st_ino == inode                         # same socket inode throughout
    assert int(show("hunter-rsm.service", "NRestarts")["NRestarts"]) >= 1


def test_clients_survive_a_broker_restart_in_the_middle_of_their_calls(fresh):
    ctl("start", "hunter-rsm.socket")
    status_of(CLIENT)
    controller = subprocess.Popen(                             # the long-running controller
        ["/usr/bin/python3", "-c", CONTROLLER_LOOP, str(SOCK)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **as_user(CLIENT))
    try:
        for _ in range(3):
            time.sleep(0.5)
            ctl("restart", "hunter-rsm.service")               # operator restarts the broker
            time.sleep(0.5)
        out, err = controller.communicate(input="", timeout=60)
    finally:
        controller.kill()
    result = json.loads(out)
    assert result["failures"] == [], result["failures"]
    assert result["calls"] > 10, (result, err)


def test_broker_started_after_the_client_is_waited_for_not_refused(fresh):
    """Mirrors 'rootless daemon (and its controller) started BEFORE the broker': the socket
    exists first (it is activated at boot) so a connect queues instead of failing."""
    ctl("start", "hunter-rsm.socket")
    assert ctl("is-active", "hunter-rsm.service", check=False).stdout.strip() == "inactive"
    assert call(CLIENT, timeout=20)["ok"] is True              # broker spawned, answered


def test_socket_unit_restart_keeps_the_directory_stable(fresh):
    ctl("start", "hunter-rsm.socket")
    status_of(CLIENT)
    d_inode = SOCK.parent.stat().st_ino
    ctl("restart", "hunter-rsm.socket")                        # inode of the SOCKET may change
    assert SOCK.parent.stat().st_ino == d_inode                # the bind-mounted DIRECTORY does not
    assert status_of(CLIENT)["ok"] is True
    assert stat.S_IMODE(SOCK.parent.stat().st_mode) & 0o007 == 0   # not world accessible
    assert stat.S_IMODE(SOCK.stat().st_mode) & 0o002 == 0          # not world writable


# ---- the WATCHDOG and RECOVERY units, run by the system manager under the production sandbox --

SESSION = {"version": 1, "history": [], "session": {
    "id": "pilot-aaaaaaaa", "phase": "stopped", "created_at": 0, "deadline": 4e9,
    "last_contact": 0, "snapshot": [{"name": "hv-rsm-test-none", "id": "abc123",
                                      "restart_policy": "no"}],
    "stop_order": ["hv-rsm-test-none"], "stopped": ["hv-rsm-test-none"], "skipped": [],
    "failures": {}}}


def run_unit(unit: str, state_text) -> dict:
    path = STATE / "session.json"
    path.write_text(state_text if isinstance(state_text, str) else json.dumps(state_text))
    os.chown(path, pwd.getpwnam(HELPER).pw_uid, grp.getgrnam(HELPER).gr_gid)
    path.chmod(0o640)
    r = ctl("start", unit, check=False)
    got = show(unit, "Result", "ExecMainStatus")
    audit = STATE / "audit.log"
    return {"result": got["Result"], "status": int(got["ExecMainStatus"]),
            "started": (FAKE_STATE / "started").exists(), "state": path.read_text(),
            "audit": audit.read_text() if audit.exists() else "", "stderr": r.stderr}


def test_watchdog_unit_restores_a_silent_session_under_the_sandbox(fresh):
    out = run_unit("hunter-rsm-watchdog.service", SESSION)
    assert out["result"] == "success" and out["status"] == 0, out["stderr"]
    assert out["started"] is True                                  # the container was started
    assert '"session": null' in out["state"]
    assert "watchdog_restore" in out["audit"] and "controller_silent" in out["audit"]


def test_boot_recovery_unit_restores_regardless_of_deadline_under_the_sandbox(fresh):
    out = run_unit("hunter-rsm-recover.service", SESSION)
    assert out["result"] == "success" and out["started"] is True, out["stderr"]
    assert "boot_recovery" in out["audit"]


def test_watchdog_unit_fails_loudly_on_corrupt_state_and_acts_on_nothing(fresh):
    out = run_unit("hunter-rsm-watchdog.service", "{truncated")
    assert out["result"] == "exit-code" and out["status"] == 3      # visible in systemd
    assert out["started"] is False
    assert out["state"] == "{truncated"                              # untouched, not "idle"
    assert "state_corrupt" in out["audit"]


if __name__ == "__main__":
    # CI `if: always()` step: remove whatever a crashed run left, then prove nothing remains.
    if sys.argv[1:] != ["--cleanup"]:
        sys.exit("usage: python tests/test_rsm_systemd.py --cleanup")
    if disposable_host_problem() and MARKER.exists():
        sys.exit(disposable_host_problem())
    remaining = cleanup()
    print(f"left behind: {remaining}" if remaining else "clean: nothing left behind")
    sys.exit(1 if remaining else 0)
