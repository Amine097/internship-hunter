"""Behavioural tests of deploy/check-host-isolation.sh (the part of the smoke test that proves
containers with a route out cannot dial the Docker host) and docker/egress-healthcheck.sh.

`docker compose exec` is replaced by a stub that runs the real in-container probe scripts locally
against a modelled firewall. The modelled network answers like the real one did when observed
(Alpine busybox `nc -vv -z`: "Connection refused" / "Host is unreachable"; python: errnos):
  STUB_REACHABLE   destinations that connect         `host:port` | `svc@host:port` | `*` | `svc@*`
  STUB_REFUSED     destinations that answer "refused" (same syntax)
  anything else    is blocked ("Host is unreachable" / EHOSTUNREACH)
The host-side canary listener is real. Probe tools can be made broken or missing on purpose.
"""
import json
import os
import shutil
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "deploy" / "check-host-isolation.sh"
HEALTH = ROOT / "docker" / "egress-healthcheck.sh"
pytestmark = pytest.mark.skipif(os.name != "posix", reason="shell scripts")

OUTBOUND = ["api", "discovery", "egress-claude-1", "egress-claude-2", "egress-codex", "telegram"]

DOCKER = textwrap.dedent("""\
    #!/usr/bin/env bash
    [[ "$1" == compose ]] || exit 99
    shift
    while [[ "$1" != exec && "$1" != config ]]; do shift; done
    if [[ "$1" == config ]]; then
      [[ -n "${STUB_CONFIG_FAIL:-}" ]] && exit 1
      cat "$STUB_DIR/config.json"; exit 0
    fi
    shift; [[ "$1" == -T ]] && shift
    svc="$1"; shift
    echo "exec $svc $1" >> "$STUB_DIR/log"
    if [[ " ${STUB_EXEC_FAIL:-} " == *" $svc "* ]]; then
      echo "service $svc is not running" >&2; exit 1
    fi
    if [[ " ${STUB_NO_PYTHON:-} " == *" $svc "* && "$1" == python ]]; then
      echo "exec: python: not found" >&2; exit 127
    fi
    script="$(sed -e "s#/proc/net/route#$STUB_DIR/route#g" \\
                  -e "s#/proc/net/ipv6_route#$STUB_DIR/ipv6_route#g")"
    export STUB_SVC="$svc" PYTHONPATH="$STUB_DIR/py"
    case "$1" in
      python) shift; echo "$3" >> "$STUB_DIR/targets"
              out="$(printf '%s\\n' "$script" | PATH="$STUB_DIR/bin:$PATH" python3 "$@")" ;;
      sh)     shift; echo "$4" >> "$STUB_DIR/targets"
              path="$STUB_DIR/bin:$PATH"
              [[ " ${STUB_NO_NC:-} " == *" $svc "* ]] && path="$STUB_DIR/nonc"
              out="$(printf '%s\\n' "$script" | PATH="$path" sh "$@")" ;;
      *) exit 98 ;;
    esac
    # --- deliberate damage to the probe's output, per service --------------------------------
    for pair in ${STUB_DROP_RESULT:-}; do          # svc=host:port : the probe "skips" a target
      [[ "${pair%%=*}" == "$svc" ]] && out="$(grep -v "^RESULT ${pair#*=} " <<<"$out")"
    done
    for s in ${STUB_DUP_RESULT:-}; do
      [[ "$s" == "$svc" ]] && out="$out"$'\\n'"$(grep -m1 '^RESULT ' <<<"$out")"
    done
    for s in ${STUB_TRUNCATE:-}; do [[ "$s" == "$svc" ]] && out="$(grep -v '^DONE' <<<"$out")"; done
    for s in ${STUB_GARBAGE:-}; do
      [[ "$s" == "$svc" ]] && out="$out"$'\\n'"Segmentation fault"
    done
    for s in ${STUB_NOISE:-}; do [[ "$s" == "$svc" ]] && out="$(grep -v '^RESULT' <<<"$out")"; done
    printf '%s\\n' "$out"
""")

# modelled busybox `nc -vv -z -w N host port`
NC = textwrap.dedent("""\
    #!/bin/sh
    while [ "${1#-}" != "$1" ]; do [ "$1" = -w ] && shift; shift; done
    t="$1:$2"
    for s in ${STUB_NC_BROKEN:-}; do [ "$s" = "$STUB_SVC" ] && exit 1; done   # silent, always fails
    match() {
      for r in $1; do
        case "$r" in "$t"|"*"|"$STUB_SVC@$t"|"$STUB_SVC@*") return 0 ;; esac
      done
      return 1
    }
    case "$t" in
      127.0.0.1:3128) [ -z "${STUB_NO_LISTENER:-}" ] && { echo "$1 ($t) open"; exit 0; } ;;
      127.0.0.1:1) for s in ${STUB_NC_NO_REFUSAL_TEXT:-}; do [ "$s" = "$STUB_SVC" ] && exit 1; done
                   echo "nc: $1 ($t): Connection refused"; exit 1 ;;
    esac
    match "${STUB_REACHABLE:-}" && { echo "$1 ($t) open"; exit 0; }
    match "${STUB_REFUSED:-}" && { echo "nc: $1 ($t): Connection refused"; exit 1; }
    for s in ${STUB_NC_UNKNOWN_ERROR:-}; do
      [ "$s" = "$STUB_SVC" ] && { echo "nc: weird failure"; exit 1; }
    done
    echo "nc: $1 ($t): Host is unreachable"; exit 1
""")

IP = textwrap.dedent("""\
    #!/bin/sh
    if [ -n "${STUB_SVC:-}" ]; then      # inside a container
      case "$*" in route*)
        [ -n "${STUB_NO_GATEWAY:-}" ] || echo "default via 172.19.0.1 dev eth0" ;; esac
      exit 0
    fi
    case "$*" in                         # on the host
      *route*) for g in ${STUB_HOST_GATEWAYS:-}; do
                 echo "default via $g dev eth0 proto dhcp"; done ;;
      *addr*) for a in ${STUB_HOST_ADDRS:-}; do
                echo "2: eth0    inet $a/24 brd 0.0.0.0 scope global eth0"; done
              for a in ${STUB_ROOTFUL_ADDRS:-}; do
                echo "7: docker0    inet $a/16 brd 0.0.0.0 scope global docker0"; done ;;
    esac
""")

SITECUSTOMIZE = textwrap.dedent("""\
    import errno, os, socket
    _real = socket.create_connection
    _own = set()                  # loopback ports THIS process listened on: the probe's controls
    _listen = socket.socket.listen
    def _record_listen(self, n=0):
        if os.environ.get("STUB_PY_BREAK_CONTROLS") == os.environ.get("STUB_SVC"):
            raise OSError("no listen")
        _own.add(self.getsockname()[1])
        return _listen(self, n)
    socket.socket.listen = _record_listen
    def _match(spec, host, port, svc):
        return any(r in (f"{host}:{port}", "*", f"{svc}@{host}:{port}", f"{svc}@*")
                   for r in spec.split())
    def _create(addr, timeout=None, *a, **k):
        host, port = addr
        if host == "127.0.0.1" and int(port) in _own:
            return _real(addr, timeout, *a, **k)      # controls use the real stack
        svc = os.environ.get("STUB_SVC", "")
        if _match(os.environ.get("STUB_REACHABLE", ""), host, port, svc):
            return socket.socket()
        if _match(os.environ.get("STUB_REFUSED", ""), host, port, svc):
            raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")
        if svc in os.environ.get("STUB_PY_UNKNOWN_ERROR", "").split():
            raise OSError(errno.EIO, "weird")
        raise OSError(errno.EHOSTUNREACH, "No route to host")
    socket.create_connection = _create
""")


def config_json(services=OUTBOUND, extra=()):
    svcs = {s: {"networks": {"egress": None}} for s in [*services, *extra]}
    svcs.update({"postgres": {"networks": {"data": None}},
                 "agent-codex": {"networks": {"agent_codex": None}}})
    return json.dumps({"services": svcs, "networks": {
        "data": {"internal": True}, "agent_codex": {"internal": True}, "egress": {}}})


@pytest.fixture
def stub(tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "py").mkdir()
    (tmp_path / "nonc").mkdir()
    for name, body in (("docker", DOCKER), ("nc", NC), ("ip", IP)):
        f = tmp_path / "bin" / name
        f.write_text(body)
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    # a PATH without nc for the "missing nc" test: only the tools the probe itself needs
    for tool in ("sh", "awk", "sort", "printf", "mktemp", "cat", "rm", "echo", "sed", "tr", "grep"):
        real = shutil.which(tool)
        if real:
            (tmp_path / "nonc" / tool).symlink_to(real)
    (tmp_path / "nonc" / "ip").symlink_to(tmp_path / "bin" / "ip")
    (tmp_path / "py" / "sitecustomize.py").write_text(SITECUSTOMIZE)
    (tmp_path / "config.json").write_text(config_json())
    (tmp_path / "route").write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "eth0\t00000000\t010013AC\t0003\t0\t0\t0\t00000000\n")
    (tmp_path / "ipv6_route").write_text("")
    return tmp_path


def run(stub, mode="enforce", reachable="", ips="127.0.0.1", addrs="", extra=None, args=()):
    env = {
        "PATH": f"{stub}/bin:{os.environ['PATH']}", "STUB_DIR": str(stub),
        "SMOKE_HOST_ISOLATION": mode, "SMOKE_PROTECTED_IPS": ips,
        "SMOKE_AUTODETECT_HOST_IPS": "1" if addrs else "0",
        "STUB_REACHABLE": reachable, "STUB_HOST_ADDRS": addrs, "HOME": str(stub),
    }
    env.update(extra or {})
    return subprocess.run(["bash", str(CHECK), *args], capture_output=True, text=True, env=env,
                          timeout=90)


def test_nothing_reachable_passes_and_probes_every_outbound_service(stub):
    r = run(stub)
    assert r.returncode == 0, r.stdout + r.stderr
    log = (stub / "log").read_text()
    for svc in OUTBOUND:
        assert f"exec {svc} " in log, svc
    assert "canaries: 1" in r.stdout and "controls verified" in r.stdout


def test_outbound_services_are_computed_from_compose_not_hardcoded(stub):
    (stub / "config.json").write_text(config_json(extra=["newcomer"]))
    r = run(stub, reachable="newcomer@127.0.0.1:22")
    assert "exec newcomer " in (stub / "log").read_text()
    assert r.returncode == 1 and "newcomer reaches 127.0.0.1:22" in r.stderr


def test_a_required_outbound_service_disappearing_is_not_silently_ignored(stub):
    (stub / "config.json").write_text(config_json(services=[s for s in OUTBOUND if s != "api"]))
    r = run(stub)
    assert r.returncode == 1 and "service 'api' is expected to have a route out" in r.stderr


def test_compose_config_failure_fails_closed(stub):
    r = run(stub, extra={"STUB_CONFIG_FAIL": "1"})
    assert r.returncode == 1 and "cannot determine which services have a route out" in r.stderr


@pytest.mark.parametrize("svc", OUTBOUND)
@pytest.mark.parametrize("port", [22, 8000])
def test_every_outbound_service_is_checked_against_tailnet_style_ports(stub, svc, port):
    r = run(stub, reachable=f"{svc}@127.0.0.1:{port}")
    assert r.returncode == 1
    assert f"{svc} reaches 127.0.0.1:{port} (connection OPEN)" in r.stderr
    for other in OUTBOUND:
        if other != svc:
            assert f"{other} reaches" not in r.stderr


# ---- R2: ECONNREFUSED is an answer, not isolation --------------------------------------------
@pytest.mark.parametrize("svc", OUTBOUND)
def test_connection_refused_on_a_protected_destination_is_a_breach(stub, svc):
    """A closed port that answers RST proves the packet reached the host. 2375 is closed there."""
    r = run(stub, extra={"STUB_REFUSED": f"{svc}@127.0.0.1:2375"})
    assert r.returncode == 1
    assert f"{svc} reaches 127.0.0.1:2375 (connection REFUSED" in r.stderr


def test_timeout_unreachable_and_prohibited_are_the_only_passes(stub):
    assert run(stub).returncode == 0       # modelled default: "Host is unreachable"/EHOSTUNREACH


# ---- R2: broken or missing tools never look like isolation -----------------------------------
def test_missing_nc_fails(stub):
    r = run(stub, extra={"STUB_NO_NC": "egress-codex"})
    assert r.returncode == 1 and "egress-codex: probe tool nc is missing" in r.stderr


def test_broken_nc_that_fails_everything_is_not_mistaken_for_isolation(stub):
    """The dangerous direction: a tool that always says 'no' would 'prove' isolation."""
    r = run(stub, extra={"STUB_NC_BROKEN": "egress-claude-1"})
    assert r.returncode == 1
    assert "egress-claude-1: positive control failed" in r.stderr
    assert "cannot connect to a listener inside the container" in r.stderr


def test_nc_without_a_listener_to_control_against_fails(stub):
    r = run(stub, extra={"STUB_NO_LISTENER": "1"})
    assert r.returncode == 1 and "positive control failed" in r.stderr


def test_nc_that_cannot_tell_refused_from_blocked_fails(stub):
    """busybox `nc -z` WITHOUT -vv is silent on a refusal: refused cannot be told from blocked."""
    r = run(stub, extra={"STUB_NC_NO_REFUSAL_TEXT": "egress-codex"})
    assert r.returncode == 1 and "cannot recognise a connection refusal" in r.stderr


def test_unclassifiable_failure_text_is_unverified_not_blocked(stub):
    r = run(stub, extra={"STUB_NC_UNKNOWN_ERROR": "egress-codex"})
    assert r.returncode == 1 and "unclassifiable result" in r.stderr


def test_missing_python_fails(stub):
    r = run(stub, extra={"STUB_NO_PYTHON": "telegram"})
    assert r.returncode == 1 and "telegram: docker exec produced no output" in r.stderr


def test_python_that_cannot_open_a_listener_fails_its_controls(stub):
    r = run(stub, extra={"STUB_PY_BREAK_CONTROLS": "discovery"})
    assert r.returncode == 1 and "discovery" in r.stderr


def test_python_unclassifiable_errno_is_unverified(stub):
    r = run(stub, extra={"STUB_PY_UNKNOWN_ERROR": "api"})
    assert r.returncode == 1 and "api: unclassifiable result" in r.stderr


def test_failed_docker_exec_fails_closed(stub):
    r = run(stub, extra={"STUB_EXEC_FAIL": "egress-claude-2"})
    assert r.returncode == 1 and "egress-claude-2: docker exec produced no output" in r.stderr
    assert "UNVERIFIED" in r.stderr


def test_truncated_probe_output_is_not_a_pass(stub):
    r = run(stub, extra={"STUB_TRUNCATE": "discovery"})
    assert r.returncode == 1 and "discovery: probe reported DONE" in r.stderr


def test_a_skipped_target_is_not_a_pass(stub):
    r = run(stub, extra={"STUB_DROP_RESULT": "egress-codex=127.0.0.1:5432"})
    assert r.returncode == 1 and "egress-codex: probe skipped 1 target(s)" in r.stderr


def test_duplicated_result_is_not_a_pass(stub):
    r = run(stub, extra={"STUB_DUP_RESULT": "api"})
    assert r.returncode == 1 and "api: duplicate result" in r.stderr


def test_unknown_output_lines_are_failures_not_noise(stub):
    r = run(stub, extra={"STUB_GARBAGE": "telegram"})
    assert r.returncode == 1 and "telegram: malformed probe output" in r.stderr


def test_probe_that_prints_no_results_at_all_fails(stub):
    r = run(stub, extra={"STUB_NOISE": "egress-claude-1"})
    assert r.returncode == 1 and "egress-claude-1: probe skipped" in r.stderr


def test_missing_gateway_is_not_a_pass(stub):
    r = run(stub, extra={"STUB_NO_GATEWAY": "1"})
    assert r.returncode == 1 and "no default gateway found" in r.stderr


def test_gateway_is_probed_on_each_container(stub):
    r = run(stub, reachable="egress-claude-2@172.19.0.1:22")
    assert r.returncode == 1 and "egress-claude-2 reaches 172.19.0.1:22" in r.stderr
    r = run(stub, extra={"STUB_REFUSED": "api@172.19.0.1:5432"})
    assert r.returncode == 1 and "api reaches 172.19.0.1:5432 (connection REFUSED" in r.stderr


def test_ipv6_default_route_in_a_container_is_flagged(stub):
    (stub / "ipv6_route").write_text(
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
        "fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n")
    r = run(stub)
    assert r.returncode == 1 and "IPv6 default route" in r.stderr


# ---- the host-side positive control and what gets protected ----------------------------------
def test_canary_catches_arbitrary_ports_not_only_known_services(stub):
    r = run(stub, reachable="egress-codex@*")
    assert r.returncode == 1
    canary = [ln for ln in r.stderr.splitlines() if "egress-codex reaches 127.0.0.1:" in ln]
    assert any(not ln.split(" (")[0].endswith((":22", ":8000", ":2375", ":2376", ":5432"))
               for ln in canary)


def test_default_ports_cover_ssh_docker_api_postgres_and_8000(stub):
    for port in (22, 2375, 2376, 5432, 8000):
        r = run(stub, reachable=f"egress-codex@127.0.0.1:{port}")
        assert r.returncode == 1 and f"127.0.0.1:{port}" in r.stderr, port


def test_real_host_addresses_are_detected_and_probed(stub):
    r = run(stub, ips="", addrs="127.0.0.1", reachable="egress-codex@127.0.0.1:22")
    assert r.returncode == 1 and "egress-codex reaches 127.0.0.1:22" in r.stderr


def test_rootful_docker_bridge_addresses_of_the_host_are_protected(stub):
    """docker0/br-* gateways are the host's addresses: rootful containers' ports listen there."""
    ips = run(stub, ips="", args=["--list-ips"],
              extra={"STUB_ROOTFUL_ADDRS": "172.17.0.1", "SMOKE_AUTODETECT_HOST_IPS": "1"})
    assert "172.17.0.1" in ips.stdout.split()


def test_host_default_gateway_is_protected_and_probed(stub):
    r = run(stub, ips="127.0.0.1", extra={"STUB_HOST_GATEWAYS": "203.0.113.1",
                                          "STUB_REACHABLE": "egress-codex@203.0.113.1:22"})
    assert r.returncode == 1 and "egress-codex reaches 203.0.113.1:22" in r.stderr


def test_operator_supplied_rootful_targets_are_probed_and_validated(stub):
    r = run(stub, extra={"SMOKE_ROOTFUL_TARGETS": "172.18.0.5:8080,172.18.0.6:9000",
                         "STUB_REACHABLE": "discovery@172.18.0.5:8080"})
    assert r.returncode == 1 and "discovery reaches 172.18.0.5:8080 (connection OPEN)" in r.stderr
    assert "172.18.0.6:9000" in (stub / "targets").read_text()
    for bad in ("172.18.0.5", "evil.example:80", "172.18.0.5:80;id", "999.1.1.1:80"):
        assert run(stub, extra={"SMOKE_ROOTFUL_TARGETS": bad}).returncode == 1, bad


def test_metadata_endpoint_is_probed_and_tailnet_dns_only_with_a_tailnet(stub):
    r = run(stub, reachable="egress-codex@169.254.169.254:80")
    assert r.returncode == 1 and "egress-codex reaches 169.254.169.254:80" in r.stderr
    (stub / "targets").unlink()
    run(stub)
    assert "100.100.100.100" not in (stub / "targets").read_text()
    (stub / "targets").unlink()
    run(stub, mode="report", ips="100.107.22.84")
    assert "100.100.100.100:53" in (stub / "targets").read_text()


def test_only_listed_addresses_are_ever_probed_no_scanning(stub):
    run(stub, ips="127.0.0.1", extra={"SMOKE_ROOTFUL_TARGETS": "172.18.0.5:8080",
                                      "STUB_HOST_GATEWAYS": "203.0.113.1"})
    probed = set()
    for line in (stub / "targets").read_text().split():
        probed.add(line.rsplit(":", 1)[0])
    assert probed <= {"127.0.0.1", "172.18.0.5", "169.254.169.254", "203.0.113.1"}


# ---- modes and configuration ----------------------------------------------------------------
def test_report_mode_warns_but_does_not_fail(stub):
    r = run(stub, mode="report", reachable="egress-codex@127.0.0.1:22")
    assert r.returncode == 0
    assert "WARN" in r.stderr and "egress-codex reaches 127.0.0.1:22" in r.stderr


def test_enforce_is_the_default_mode():
    assert 'MODE="${SMOKE_HOST_ISOLATION:-enforce}"' in CHECK.read_text()


def test_enforce_without_any_target_address_refuses_to_certify(stub):
    r = run(stub, ips="")
    assert r.returncode == 1 and "no host address to protect" in r.stderr
    assert run(stub, mode="report", ips="").returncode == 0


def test_configured_address_that_is_not_local_cannot_be_canaried(stub):
    r = run(stub, ips="100.107.22.84")
    assert r.returncode == 1 and "cannot open a canary on 100.107.22.84" in r.stderr


def test_production_marker_requires_a_tailnet_address(stub):
    r = run(stub, extra={"SMOKE_EXPECT_ROOTLESS": "1"})
    assert r.returncode == 1 and "no Tailscale (100.64.0.0/10) address" in r.stderr
    optout = {"SMOKE_EXPECT_ROOTLESS": "1", "SMOKE_REQUIRE_TAILNET": "0"}
    assert run(stub, extra=optout).returncode == 0


@pytest.mark.parametrize("env", [{"SMOKE_PROTECTED_IPS": "not-an-ip"},
                                 {"SMOKE_PROTECTED_IPS": "300.1.1.1"},
                                 {"SMOKE_PROTECTED_PORTS": "22;rm"},
                                 {"SMOKE_HOST_ISOLATION": "maybe"}])
def test_invalid_configuration_is_rejected(stub, env):
    r = run(stub, extra=env)
    assert r.returncode == 1 and "FAIL" in r.stderr


def test_list_ips_prints_the_union_of_explicit_and_detected_addresses(stub):
    r = run(stub, ips="100.107.22.84,192.168.1.5", addrs="203.0.113.9 192.168.1.5",
            args=["--list-ips"])
    assert r.returncode == 0
    assert r.stdout.split() == ["100.107.22.84", "192.168.1.5", "203.0.113.9"]


def test_canary_listener_does_not_outlive_the_check(stub):
    r = run(stub, extra={"TMPDIR": str(stub)})          # canary file name carries the unique dir
    assert r.returncode == 0
    left = subprocess.run(["pgrep", "-f", f"python3 - {stub}/tmp"], capture_output=True, text=True)
    assert left.stdout.strip() == "", "canary listener leaked"
    assert not list(stub.glob("tmp.*"))


# ---- the proxy's own healthcheck (detection of a missing guard) --------------------------------
def health(stub, targets=None, reachable="", refused="", listening=True):
    env = {"PATH": f"{stub}/bin:{os.environ['PATH']}", "STUB_REACHABLE": reachable,
           "STUB_REFUSED": refused, "STUB_SVC": "p", "STUB_DIR": str(stub)}
    if not listening:
        env["STUB_NO_LISTENER"] = "1"
    if targets is not None:
        env["EGRESS_FORBIDDEN_TARGETS"] = targets
    return subprocess.run(["sh", str(HEALTH)], capture_output=True, text=True, env=env, timeout=30)


def test_healthcheck_without_targets_only_checks_the_listener(stub):
    assert health(stub).returncode == 0
    assert health(stub, listening=False).returncode == 1


def test_healthcheck_is_unhealthy_when_a_forbidden_target_answers(stub):
    t = "100.107.22.84:22,100.107.22.84:8000"
    assert health(stub, t).returncode == 0
    for reach in ("100.107.22.84:22", "100.107.22.84:8000"):
        r = health(stub, t, reachable=reach)
        assert r.returncode == 1 and f"{reach} is reachable" in r.stderr
        r = health(stub, t, refused=reach)               # a refusal is an answer too
        assert r.returncode == 1 and "connection refused" in r.stderr


@pytest.mark.parametrize("bad", ["100.107.22.84", "100.107.22.84:", "a:b:1", "x;reboot:22", ":22",
                                 "100.107.22.84:22x", "host.example:22"])
def test_healthcheck_rejects_malformed_targets(stub, bad):
    assert health(stub, bad).returncode == 1
