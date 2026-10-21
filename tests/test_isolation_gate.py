"""R7: the start-time gates. After a Docker daemon restart the restart policy can start containers
before the host guard is re-applied; each container with a route out must then EXIT instead of
running application code. Unit tests here; the packet-level proof is in
tests/test_host_egress_guard_netns.py (stage `gate`)."""
import os
import socket
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "docker" / "isolation-gate.sh"
CHECK = ROOT / "docker" / "egress-forbidden-check.sh"
PROXY = ROOT / "docker" / "egress-proxy.sh"
COMPOSE = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]
pytestmark = pytest.mark.skipif(os.name != "posix", reason="shell scripts")

NC = textwrap.dedent("""\
    #!/bin/sh
    # models Alpine busybox `nc` (-vv -z -w N host port | -l -p PORT); damage via STUB_NC_*
    case " $* " in *" -l "*) sleep 0.2; exit 0 ;; esac
    v=0
    while [ "${1#-}" != "$1" ]; do
      case "$1" in -w) shift ;; -v|-vv) v=1 ;; esac
      shift
    done
    t="$1:$2"
    [ -z "${STUB_NC_BROKEN:-}" ] || exit 1                          # silent, always fails
    if [ -n "${STUB_NC_NO_VV:-}" ] && [ "$v" = 1 ]; then
      echo "nc: invalid option -- 'v'"; echo "Usage: nc [OPTIONS] HOST PORT"; exit 1
    fi
    case "$t" in
      127.0.0.1:3128) echo "$1 ($t) open"; exit 0 ;;
      127.0.0.1:1)
        [ -z "${STUB_NC_SILENT_REFUSAL:-}" ] || exit 1
        [ -z "${STUB_NC_LOCALISED:-}" ] || { echo "nc: $t: Connexion refusee"; exit 1; }
        echo "nc: 127.0.0.1 ($t): Connection refused"; exit 1 ;;
    esac
    for r in ${STUB_REACHABLE:-}; do [ "$r" = "$t" ] && { echo "$1 ($t) open"; exit 0; }; done
    for r in ${STUB_REFUSED:-}; do
      [ "$r" = "$t" ] && { echo "nc: $1 ($t): Connection refused"; exit 1; }
    done
    for r in ${STUB_ODD:-}; do [ "$r" = "$t" ] && { echo "nc: banner grabbed"; exit 1; }; done
    for r in ${STUB_SILENT:-}; do [ "$r" = "$t" ] && exit 1; done
    for r in ${STUB_TIMEOUT:-}; do
      [ "$r" = "$t" ] && { echo "nc: $1 ($t): Operation timed out"; exit 1; }
    done
    echo "nc: $1 ($t): Host is unreachable"; exit 1
""")
SITECUSTOMIZE = textwrap.dedent("""\
    import errno, os, socket
    _real = socket.create_connection
    def _create(addr, timeout=None, *a, **k):
        host, port = addr
        if host.startswith("127."):
            return _real(addr, timeout, *a, **k)
        key = f"{host}:{port}"
        if key in os.environ.get("STUB_REACHABLE", "").split():
            return socket.socket()
        if key in os.environ.get("STUB_REFUSED", "").split():
            raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")
        if key in os.environ.get("STUB_WEIRD", "").split():
            raise OSError(errno.EIO, "weird")
        if key in os.environ.get("STUB_SLOW", "").split():
            raise TimeoutError()
        raise OSError(errno.EHOSTUNREACH, "No route to host")
    socket.create_connection = _create
""")


@pytest.fixture
def stub(tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "py").mkdir()
    nc = tmp_path / "bin" / "nc"
    nc.write_text(NC)
    nc.chmod(nc.stat().st_mode | stat.S_IEXEC)
    for name in ("tinyproxy",):
        f = tmp_path / "bin" / name
        f.write_text('#!/bin/sh\necho "tinyproxy started" >> "$STUB_DIR/started"\n')
        f.chmod(0o755)
    (tmp_path / "py" / "sitecustomize.py").write_text(SITECUSTOMIZE)
    return tmp_path


def env_for(stub, **extra):
    env = {"PATH": f"{stub}/bin:{os.environ['PATH']}", "PYTHONPATH": str(stub / "py"),
           "STUB_DIR": str(stub), "HOME": str(stub)}
    env.update(extra)
    return env


def gate(stub, targets, **extra):
    marker = stub / "ran"
    marker.unlink(missing_ok=True)
    env = env_for(stub, **extra)
    if targets is not None:
        env["EGRESS_FORBIDDEN_TARGETS"] = targets
    r = subprocess.run(["sh", str(GATE), "sh", "-c", f"echo ran > {marker}"], capture_output=True,
                       text=True, env=env, timeout=30)
    return r, marker.exists()


# ---- app-image gate (api, discovery, telegram) ------------------------------------------------
def test_gate_without_targets_just_runs_the_service(stub):
    for targets in (None, ""):
        r, ran = gate(stub, targets)
        assert r.returncode == 0 and ran


def test_gate_lets_the_service_start_when_the_host_does_not_answer(stub):
    r, ran = gate(stub, "100.107.22.84:22,100.107.22.84:8000")
    assert r.returncode == 0 and ran, r.stderr


def test_gate_stops_the_service_when_a_forbidden_target_connects(stub):
    r, ran = gate(stub, "100.107.22.84:22,100.107.22.84:8000", STUB_REACHABLE="100.107.22.84:8000")
    assert r.returncode == 1 and not ran
    assert "100.107.22.84:8000 is reachable" in r.stderr and "refusing to start" in r.stderr


def test_gate_stops_the_service_when_the_host_answers_refused(stub):
    r, ran = gate(stub, "100.107.22.84:2375", STUB_REFUSED="100.107.22.84:2375")
    assert r.returncode == 1 and not ran and "connection refused" in r.stderr


def test_gate_treats_timeouts_as_isolation_and_unknown_errors_as_failure(stub):
    r, ran = gate(stub, "100.107.22.84:22", STUB_SLOW="100.107.22.84:22")
    assert r.returncode == 0 and ran
    r, ran = gate(stub, "100.107.22.84:22", STUB_WEIRD="100.107.22.84:22")
    assert r.returncode == 1 and not ran and "unclassifiable" in r.stderr


@pytest.mark.parametrize("bad", ["100.107.22.84", "x:22", "100.107.22.84:22;id", "host.example:22",
                                 "100.107.22.84:"])
def test_gate_rejects_malformed_targets(stub, bad):
    r, ran = gate(stub, bad)
    assert r.returncode == 1 and not ran and "malformed target" in r.stderr


def test_gate_without_python_refuses_to_start(stub):
    env = {"PATH": "/nonexistent", "EGRESS_FORBIDDEN_TARGETS": "100.107.22.84:22"}
    r = subprocess.run(["/bin/sh", str(GATE), "/bin/echo", "should-not-run"], capture_output=True,
                       text=True, env=env, timeout=30)
    assert r.returncode == 1 and "should-not-run" not in r.stdout
    assert "python not found" in r.stderr


def test_gate_really_stops_on_a_live_listener_and_on_a_refusing_port(stub):
    """No stubs: a real listener is 'reachable'; after it closes the port REFUSES - an answer."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    env = {"PATH": os.environ["PATH"], "EGRESS_FORBIDDEN_TARGETS": f"127.0.0.1:{port}"}
    try:
        r = subprocess.run(["sh", str(GATE), "echo", "service-started"], capture_output=True,
                           text=True, env=env, timeout=30)
        assert r.returncode == 1 and "service-started" not in r.stdout
    finally:
        srv.close()
    r = subprocess.run(["sh", str(GATE), "echo", "service-started"], capture_output=True,
                       text=True, env=env, timeout=30)
    assert r.returncode == 1 and "service-started" not in r.stdout
    assert "connection refused" in r.stderr


# ---- proxy start gate --------------------------------------------------------------------------
def start_proxy(stub, **extra):
    env = env_for(stub, EGRESS_ALLOW="api.openai.com", **extra)
    (stub / "started").unlink(missing_ok=True)
    return subprocess.run(["sh", str(PROXY)], capture_output=True, text=True, env=env, timeout=30)


def test_proxy_starts_when_the_host_does_not_answer(stub):
    r = start_proxy(stub, EGRESS_FORBIDDEN_TARGETS="100.107.22.84:22")
    assert r.returncode == 0 and (stub / "started").exists(), r.stderr


@pytest.mark.parametrize("kind", ["STUB_REACHABLE", "STUB_REFUSED"])
def test_proxy_refuses_to_start_when_the_host_answers(stub, kind):
    r = start_proxy(stub, EGRESS_FORBIDDEN_TARGETS="100.107.22.84:22,100.107.22.84:8000",
                    **{kind: "100.107.22.84:8000"})
    assert r.returncode == 1 and not (stub / "started").exists()
    assert "refusing to start" in r.stderr and "100.107.22.84:8000" in r.stderr


def test_proxy_without_targets_starts_as_before(stub):
    assert start_proxy(stub).returncode == 0 and (stub / "started").exists()


# ---- wiring ------------------------------------------------------------------------------------
@pytest.mark.parametrize("svc", ["api", "discovery", "telegram"])
def test_every_app_service_with_a_route_out_starts_through_the_gate(svc):
    cfg = COMPOSE[svc]
    assert cfg["entrypoint"] == ["/usr/local/bin/isolation-gate.sh"]
    assert cfg["environment"]["EGRESS_FORBIDDEN_TARGETS"] == "${EGRESS_FORBIDDEN_TARGETS:-}"
    assert "command" in cfg           # the gate execs "$@": the original command is its argument


def test_images_ship_the_gate_scripts_executable():
    app = (ROOT / "docker" / "app.Dockerfile").read_text()
    assert "isolation-gate.sh" in app and "chmod 0755 /usr/local/bin/isolation-gate.sh" in app
    proxy = (ROOT / "docker" / "egress-proxy.Dockerfile").read_text()
    for f in ("egress-proxy.sh", "egress-healthcheck.sh", "egress-forbidden-check.sh"):
        assert f in proxy
    for f in ("isolation-gate.sh", "egress-proxy.sh", "egress-healthcheck.sh",
              "egress-forbidden-check.sh"):
        assert os.access(ROOT / "docker" / f, os.X_OK), f


def test_services_without_a_route_out_do_not_carry_the_gate():
    for svc in ("postgres", "migrate", "scheduler", "session-controller", "agent-codex"):
        assert "entrypoint" not in COMPOSE[svc], svc


# ---- F-2: the proxy start check and healthcheck FAIL CLOSED -----------------------------------
HEALTH = ROOT / "docker" / "egress-healthcheck.sh"
T = "100.107.22.84:22,100.107.22.84:8000"


def run_check(stub, targets=T, path=None, **extra):
    env = env_for(stub, **extra)
    if path is not None:
        env["PATH"] = path
    env["EGRESS_FORBIDDEN_TARGETS"] = targets
    return subprocess.run(["/bin/sh", str(CHECK)], capture_output=True, text=True, env=env,
                          timeout=30)


def run_health(stub, targets=T, path=None, **extra):
    env = env_for(stub, **extra)
    if path is not None:
        env["PATH"] = path
    env["EGRESS_FORBIDDEN_TARGETS"] = targets
    return subprocess.run(["/bin/sh", str(HEALTH)], capture_output=True, text=True, env=env,
                          timeout=30)


def test_check_passes_only_on_recognised_isolation_errors(stub):
    assert run_check(stub).returncode == 0                       # "Host is unreachable"
    assert run_check(stub, STUB_TIMEOUT="100.107.22.84:22").returncode == 0
    assert run_health(stub).returncode == 0


@pytest.mark.parametrize("damage,msg", [
    ({"STUB_REACHABLE": "100.107.22.84:8000"}, "is reachable"),
    ({"STUB_REFUSED": "100.107.22.84:22"}, "connection refused"),
    ({"STUB_ODD": "100.107.22.84:22"}, "unrecognised result"),        # unexpected stderr
    ({"STUB_SILENT": "100.107.22.84:22"}, "unrecognised result"),     # NO text at all: not fine
])
def test_check_and_healthcheck_reject_everything_but_isolation(stub, damage, msg):
    for runner in (run_check, run_health):
        r = runner(stub, **damage)
        assert r.returncode == 1 and msg in r.stderr, (runner.__name__, r.stderr)


def test_missing_nc_fails_closed_for_start_check_healthcheck_and_proxy(stub):
    empty = stub / "empty"
    empty.mkdir()
    r = run_check(stub, path=str(empty))
    assert r.returncode == 1 and "nc is missing" in r.stderr
    assert run_health(stub, path=str(empty)).returncode == 1
    env = env_for(stub, EGRESS_ALLOW="api.openai.com", EGRESS_FORBIDDEN_TARGETS=T)
    env["PATH"] = str(empty)
    (stub / "started").unlink(missing_ok=True)
    r = subprocess.run(["/bin/sh", str(PROXY)], capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 1 and not (stub / "started").exists()


def test_broken_nc_that_always_fails_cannot_prove_isolation(stub):
    """The reproduced fail-open: nc fails everything, so every target 'looks blocked'."""
    for runner in (run_check, run_health):
        r = runner(stub, STUB_NC_BROKEN="1")
        assert r.returncode == 1, runner.__name__
    r = start_proxy(stub, EGRESS_FORBIDDEN_TARGETS=T, STUB_NC_BROKEN="1")
    assert r.returncode == 1 and not (stub / "started").exists()
    assert "self-test" in run_check(stub, STUB_NC_BROKEN="1").stderr


def test_nc_that_does_not_support_the_options_fails_closed(stub):
    r = run_check(stub, STUB_NC_NO_VV="1")
    assert r.returncode == 1 and "self-test" in r.stderr
    assert run_health(stub, STUB_NC_NO_VV="1").returncode == 1
    r = start_proxy(stub, EGRESS_FORBIDDEN_TARGETS=T, STUB_NC_NO_VV="1")
    assert r.returncode == 1 and not (stub / "started").exists()


def test_nc_that_is_silent_on_a_refusal_fails_the_self_test(stub):
    """busybox `nc -z` without -vv: a refusal and a block look identical - refuse to guess."""
    r = run_check(stub, STUB_NC_SILENT_REFUSAL="1")
    assert r.returncode == 1 and "does not report 'Connection refused'" in r.stderr


def test_localised_messages_are_not_recognised_so_the_script_pins_the_c_locale(stub):
    text = CHECK.read_text()
    assert "LC_ALL=C" in text and "export LC_ALL" in text
    r = run_check(stub, STUB_NC_LOCALISED="1")                   # a French nc under another locale
    assert r.returncode == 1


def test_malformed_targets_fail_the_check(stub):
    for bad in ("100.107.22.84", "x:22", "100.107.22.84:22;id", "100.107.22.84:", "a:b:1"):
        assert run_check(stub, targets=bad).returncode == 1, bad


def test_empty_list_still_means_development_and_passes_without_nc(stub):
    empty = stub / "empty2"
    empty.mkdir()
    env = env_for(stub)
    env["PATH"] = str(empty)
    env.pop("EGRESS_FORBIDDEN_TARGETS", None)
    r = subprocess.run(["/bin/sh", str(CHECK)], capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0
