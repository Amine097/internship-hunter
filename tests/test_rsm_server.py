import ast
import json
import os
import socket
import stat
import sys
import threading
from pathlib import Path

import pytest
from fake_docker import FakeDocker
from test_rsm_broker import SID, Clock, policy_doc, world

from hunter.rsm import OPERATIONS
from hunter.rsm.broker import Broker
from hunter.rsm.dockerctl import CliDocker, DockerError
from hunter.rsm.policy import parse_policy
from hunter.rsm.server import MAX_REQUEST_BYTES, RsmServer, handle_request
from hunter.rsm.store import Store

PKG = Path(__file__).resolve().parents[1] / "hunter" / "rsm"


@pytest.fixture
def broker(tmp_path):
    d = world()
    b = Broker(parse_policy(policy_doc()), d, Store(tmp_path / "s", clock=Clock()),
               clock=Clock(), mem_available=lambda: 9000, probe_runner=lambda p: (False, "idle"))
    return b, d


def req(broker, obj):
    raw = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    return handle_request(broker, raw)


# ---- the protocol cannot express anything dangerous --------------------------------------------

def test_exactly_five_operations_exist():
    assert OPERATIONS == ("prepare", "stop_approved", "restore", "status", "emergency_restore")


@pytest.mark.parametrize("payload", [
    {"op": "exec", "session_id": SID},
    {"op": "stop", "session_id": SID},
    {"op": "docker", "args": ["rm", "-f", "x"]},
    {"op": "prepare", "session_id": SID, "container": "adguard"},
    {"op": "stop_approved", "session_id": SID, "containers": ["adguard"]},
    {"op": "restore", "session_id": SID, "command": "id"},
    {"op": "status", "name": "jellyfin"},
    {"op": "prepare", "session_id": SID, "timeout": 0},
    {"op": "emergency_restore", "session_id": SID},
    {"op": ["prepare"], "session_id": SID},
    {"op": "prepare", "session_id": "$(reboot)"},
    {"op": "prepare", "session_id": "a" * 500},
    ["prepare"], "prepare", 7, None,
])
def test_nothing_but_the_five_ops_with_a_session_id_is_accepted(broker, payload):
    b, docker = broker
    resp = req(b, payload)
    assert resp["ok"] is False
    assert docker.calls == []                       # not a single Docker call was made


def test_malformed_and_oversized_requests(broker):
    b, docker = broker
    assert req(b, b"{not json")["code"] == "bad_request"
    assert req(b, b"\xff\xfe")["code"] == "bad_request"
    assert req(b, b"x" * (MAX_REQUEST_BYTES + 1))["code"] == "bad_request"
    assert docker.calls == []


def test_valid_requests_round_trip(broker):
    b, docker = broker
    assert req(b, {"op": "prepare", "session_id": SID})["code"] == "prepared"
    assert req(b, {"op": "status", "session_id": SID})["active"] is True
    assert req(b, {"op": "stop_approved", "session_id": SID})["code"] == "stopped"
    assert req(b, {"op": "restore", "session_id": SID})["code"] == "restored"
    assert req(b, {"op": "emergency_restore"})["code"] == "nothing_to_restore"


def test_internal_errors_do_not_leak_details(broker, monkeypatch):
    b, docker = broker

    def boom(*a):
        raise RuntimeError("secret path /etc/hunter-rsm/jf.key")

    monkeypatch.setattr(b, "prepare", boom)
    resp = req(b, {"op": "prepare", "session_id": SID})
    assert resp == {"ok": False, "code": "internal_error"}
    assert any(e["event"] == "operation_error" for e in b.store.audit_events())


# ---- real unix socket ---------------------------------------------------------------

def _call(path, obj):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(5)
        s.connect(path)
        s.sendall(json.dumps(obj).encode() + b"\n")
        return json.loads(s.makefile().readline())


@pytest.fixture
def served(tmp_path, broker):
    b, docker = broker
    path = str(tmp_path / "rsm.sock")
    servers = []

    def start(allowed_uids=()):
        srv = RsmServer(path, b, group=None, allowed_uids=allowed_uids)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return path

    yield start, b, docker
    for s in servers:
        s.shutdown()
        s.server_close()


def test_socket_serves_the_protocol_and_has_restrictive_mode(served):
    start, b, docker = served
    path = start()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o660          # no world access
    assert _call(path, {"op": "prepare", "session_id": SID})["code"] == "prepared"
    assert _call(path, {"op": "stop_approved", "session_id": SID})["ok"]
    assert _call(path, {"op": "restore", "session_id": SID})["code"] == "restored"


def test_socket_rejects_a_peer_whose_uid_is_not_allowlisted(served):
    start, b, docker = served
    path = start(allowed_uids=(os.getuid() + 12345,))
    assert _call(path, {"op": "prepare", "session_id": SID}) == {"ok": False,
                                                                 "code": "forbidden"}
    assert docker.calls == []
    assert any(e["event"] == "peer_rejected" for e in b.store.audit_events())
    path = None


def test_socket_accepts_the_allowlisted_uid(served):
    start, b, docker = served
    path = start(allowed_uids=(os.getuid(),))
    assert _call(path, {"op": "status"})["ok"]


# ---- privilege boundary of the helper itself --------------------------------------

def test_package_depends_only_on_the_standard_library():
    allowed = set(sys.stdlib_module_names) | {"hunter"}
    for f in PKG.glob("*.py"):
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                mods = [node.module.split(".")[0]]
            for m in mods:
                assert m in allowed, f"{f.name} imports non-stdlib {m}"
                if m == "hunter":
                    imported = node.module if isinstance(node, ast.ImportFrom) else ""
                    assert imported.startswith("hunter.rsm"), f"{f.name} imports app code"


def test_no_shell_and_only_four_docker_subcommands():
    src = (PKG / "dockerctl.py").read_text()
    assert "shell=True" not in src and "os.system" not in src and "os.popen" not in src
    for f in PKG.glob("*.py"):
        text = f.read_text()
        assert "shell=True" not in text and "eval(" not in text and "exec(" not in text.replace(
            "exec(\"", "")
    used = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "_run" and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant):
                used.add(first.value)
    assert used == {"inspect", "stop", "start", "ps"}      # no run/exec/rm/kill/update/cp/...


def test_cli_docker_builds_fixed_argv_and_rejects_hostile_names(tmp_path):
    log = tmp_path / "argv.log"
    fake = tmp_path / "docker"
    fake.write_text(f"#!/bin/sh\necho \"$@\" >> {log}\n"
                    "case \"$1\" in inspect) echo '[]';; esac\nexit 0\n")
    fake.chmod(0o755)
    d = CliDocker(str(fake))
    for bad in ["a b", "x;reboot", "$(id)", "../x", "-f", "--privileged", "", "a" * 70, "x\ny"]:
        with pytest.raises(DockerError):
            d.stop(bad, 10)
        with pytest.raises(DockerError):
            d.start(bad)
        with pytest.raises(DockerError):
            d.inspect(bad)
    assert not log.exists()                               # nothing was ever executed
    d.stop("jellyfin", 30)
    d.start("jellyfin")
    assert log.read_text().splitlines() == ["stop --time 30 jellyfin", "start jellyfin"]


def test_cli_docker_runs_with_a_scrubbed_environment(tmp_path, monkeypatch):
    out = tmp_path / "env.txt"
    fake = tmp_path / "docker"
    fake.write_text(f"#!/bin/sh\nenv > {out}\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "leak")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    CliDocker(str(fake)).start("radarr")
    env = out.read_text()
    assert "TELEGRAM_BOT_TOKEN" not in env and "LD_PRELOAD" not in env


def test_broker_never_acts_on_a_name_outside_the_policy(broker):
    b, docker = broker
    docker.add("not-in-policy-but-running")
    b.prepare(SID)
    b.stop_approved(SID)
    b.restore(SID)
    assert "not-in-policy-but-running" not in docker.touched()
    assert docker.touched() <= set(b.policy.containers)


def test_a_snapshot_edited_to_name_a_protected_container_is_still_not_touched(broker):
    """Defence in depth: even a tampered state file cannot make restore start/stop names
    that are not in the (root-owned) policy."""
    b, docker = broker
    b.prepare(SID)
    state = b.store.load()
    state["session"]["snapshot"].append({"name": "adguard", "id": "x", "restart_policy": "no"})
    state["session"]["stop_order"].append("adguard")
    b.store.save(state)
    docker.c["adguard"]["running"] = False
    b.stop_approved(SID) if False else None
    res = b.restore(SID)
    assert res["code"] == "restore_failed" and "adguard" in res["failures"]
    assert "adguard" not in docker.touched()
    assert docker.c["adguard"]["running"] is False         # not started either


def test_systemd_units_are_sandboxed():
    unit_dir = Path(__file__).resolve().parents[1] / "deploy" / "rsm"
    for unit in ("hunter-rsm.service", "hunter-rsm-watchdog.service",
                 "hunter-rsm-recover.service"):
        text = (unit_dir / unit).read_text()
        for must in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes",
                     "PrivateTmp=yes", "ReadWritePaths=/var/lib/hunter-rsm",
                     "CapabilityBoundingSet=", "RestrictAddressFamilies=",
                     "SystemCallFilter="):
            assert must in text, f"{unit} missing {must}"
        assert "User=hunter-rsm" in text
    assert FakeDocker  # keep import referenced
