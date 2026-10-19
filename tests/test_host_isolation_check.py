"""Behavioural tests of deploy/check-host-isolation.sh (the part of the smoke test that proves
containers with a route out cannot dial the Docker host) and docker/egress-healthcheck.sh.

`docker compose exec` is replaced by a stub that runs the real in-container probe scripts locally
against a modelled firewall: STUB_REACHABLE lists the destinations a container "can" reach, as
`host:port` (everyone), `svc@host:port` or `svc@*`. The host-side canary listener is real.
"""
import os
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "deploy" / "check-host-isolation.sh"
HEALTH = ROOT / "docker" / "egress-healthcheck.sh"
pytestmark = pytest.mark.skipif(os.name != "posix", reason="shell scripts")

DOCKER = textwrap.dedent("""\
    #!/usr/bin/env bash
    [[ "$1" == compose ]] || exit 99
    shift
    while [[ "$1" != exec ]]; do shift; done
    shift; [[ "$1" == -T ]] && shift
    svc="$1"; shift
    echo "exec $svc $1" >> "$STUB_DIR/log"
    if [[ " ${STUB_EXEC_FAIL:-} " == *" $svc "* ]]; then
      echo "service $svc is not running" >&2; exit 1
    fi
    script="$(sed -e "s#/proc/net/route#$STUB_DIR/route#g" \\
                  -e "s#/proc/net/ipv6_route#$STUB_DIR/ipv6_route#g")"
    export STUB_SVC="$svc" PATH="$STUB_DIR/bin:$PATH" PYTHONPATH="$STUB_DIR/py"
    case "$1" in
      python) shift; out="$(printf '%s\\n' "$script" | python3 "$@")" ;;
      sh)     shift; out="$(printf '%s\\n' "$script" | sh "$@")" ;;
      *) exit 98 ;;
    esac
    [[ " ${STUB_TRUNCATE:-} " == *" $svc "* ]] && out="$(grep -v '^PROBED' <<<"$out")"
    printf '%s\\n' "$out"
""")

# `nc -z [-w N] host port` succeeds iff the destination is in the modelled firewall's allow set
NC = textwrap.dedent("""\
    #!/bin/sh
    while [ "$1" = -z ] || [ "$1" = -w ]; do [ "$1" = -w ] && shift; shift; done
    t="$1:$2"
    for r in ${STUB_REACHABLE:-}; do
      case "$r" in "$t"|"*"|"$STUB_SVC@$t"|"$STUB_SVC@*") exit 0 ;; esac
    done
    exit 1
""")

IP = textwrap.dedent("""\
    #!/bin/sh
    case "$*" in
      route*) echo "default via 172.19.0.1 dev eth0"; echo "172.19.0.0/16 dev eth0" ;;
      *addr*) for a in ${STUB_HOST_ADDRS:-}; do
                echo "2: eth0    inet $a/24 brd 0.0.0.0 scope global eth0"; done ;;
    esac
""")

SITECUSTOMIZE = textwrap.dedent("""\
    import os, socket
    def _create(addr, timeout=None, *a, **k):
        host, port = addr
        svc = os.environ.get("STUB_SVC", "")
        for r in os.environ.get("STUB_REACHABLE", "").split():
            if r in (f"{host}:{port}", "*", f"{svc}@{host}:{port}", f"{svc}@*"):
                return socket.socket()
        raise ConnectionRefusedError()
    socket.create_connection = _create
""")


@pytest.fixture
def stub(tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "py").mkdir()
    for name, body in (("docker", DOCKER), ("nc", NC), ("ip", IP)):
        f = tmp_path / "bin" / name
        f.write_text(body)
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    (tmp_path / "py" / "sitecustomize.py").write_text(SITECUSTOMIZE)
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
                          timeout=60)


def test_nothing_reachable_passes_and_probes_every_outbound_service(stub):
    r = run(stub, ips="127.0.0.1")
    assert r.returncode == 0, r.stdout + r.stderr
    log = (stub / "log").read_text()
    for svc in ("egress-claude-1", "egress-claude-2", "egress-codex", "discovery", "telegram",
                "api"):
        assert f"exec {svc} " in log, svc
    assert "canaries: 1" in r.stdout


@pytest.mark.parametrize("svc", ["egress-claude-1", "egress-claude-2", "egress-codex"])
@pytest.mark.parametrize("port", [22, 8000])
def test_every_proxy_is_checked_against_tailnet_ip_ports_22_and_8000(stub, svc, port):
    r = run(stub, reachable=f"{svc}@127.0.0.1:{port}")
    assert r.returncode == 1
    assert f"{svc} reaches 127.0.0.1:{port}" in r.stderr
    for other in ("egress-claude-1", "egress-claude-2", "egress-codex"):
        if other != svc:
            assert f"{other} reaches" not in r.stderr


def test_real_tailnet_ip_is_probed_when_it_is_a_host_address(stub):
    """Detection finds the host's own addresses (here via `ip addr`); explicit IPs are added."""
    r = run(stub, ips="", addrs="127.0.0.1", reachable="egress-codex@127.0.0.1:22")
    assert r.returncode == 1 and "egress-codex reaches 127.0.0.1:22" in r.stderr


def test_default_ports_cover_ssh_docker_api_postgres_and_8000(stub):
    for port in (22, 2375, 2376, 5432, 8000):
        r = run(stub, reachable=f"egress-codex@127.0.0.1:{port}")
        assert r.returncode == 1 and f"127.0.0.1:{port}" in r.stderr, port


def test_gateway_is_probed_on_each_proxy(stub):
    r = run(stub, reachable="egress-claude-2@172.19.0.1:22")
    assert r.returncode == 1 and "egress-claude-2 reaches 172.19.0.1:22" in r.stderr


def test_canary_catches_arbitrary_ports_not_only_known_services(stub):
    """A closed well-known port proves nothing; an open canary on a random port does."""
    r = run(stub, reachable="egress-codex@*")
    assert r.returncode == 1
    canary = [ln for ln in r.stderr.splitlines() if "egress-codex reaches 127.0.0.1:" in ln]
    assert any(not ln.endswith((":22", ":8000", ":2375", ":2376", ":5432")) for ln in canary)


def test_trusted_services_with_a_route_out_are_checked_too(stub):
    for svc in ("discovery", "telegram", "api"):
        r = run(stub, reachable=f"{svc}@127.0.0.1:22")
        assert r.returncode == 1 and f"{svc} reaches 127.0.0.1:22" in r.stderr, svc


def test_report_mode_warns_but_does_not_fail(stub):
    r = run(stub, mode="report", reachable="egress-codex@127.0.0.1:22")
    assert r.returncode == 0
    assert "WARN" in r.stderr and "egress-codex reaches 127.0.0.1:22" in r.stderr


def test_enforce_is_the_default_mode(stub):
    env_mode = CHECK.read_text()
    assert 'MODE="${SMOKE_HOST_ISOLATION:-enforce}"' in env_mode


def test_probe_that_cannot_run_fails_closed(stub):
    r = run(stub, extra={"STUB_EXEC_FAIL": "egress-claude-2"})
    assert r.returncode == 1 and "egress-claude-2: probe did not complete" in r.stderr
    assert "UNVERIFIED" in r.stderr


def test_truncated_probe_output_is_not_a_pass(stub):
    r = run(stub, extra={"STUB_TRUNCATE": "discovery"})
    assert r.returncode == 1 and "discovery: probe did not complete" in r.stderr


def test_missing_gateway_is_not_a_pass(stub):
    (stub / "route").write_text("Iface\tDestination\tGateway\tFlags\n")
    r = run(stub)
    assert r.returncode == 1 and "no default gateway found" in r.stderr


def test_ipv6_default_route_in_a_container_is_flagged(stub):
    (stub / "ipv6_route").write_text(
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
        "fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n")
    r = run(stub)
    assert r.returncode == 1 and "IPv6 default route" in r.stderr


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
    # an explicit opt-out is possible, but it has to be spelled out
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
def health(stub, targets=None, reachable="", listening=True):
    env = {"PATH": f"{stub}/bin:{os.environ['PATH']}", "STUB_REACHABLE": reachable,
           "STUB_SVC": "p", "STUB_DIR": str(stub)}
    if listening:
        env["STUB_REACHABLE"] += " 127.0.0.1:3128"
    if targets is not None:
        env["EGRESS_FORBIDDEN_TARGETS"] = targets
    return subprocess.run(["sh", str(HEALTH)], capture_output=True, text=True, env=env, timeout=30)


def test_healthcheck_without_targets_only_checks_the_listener(stub):
    assert health(stub).returncode == 0
    assert health(stub, listening=False).returncode == 1


def test_healthcheck_is_unhealthy_when_a_forbidden_target_is_reachable(stub):
    t = "100.107.22.84:22,100.107.22.84:8000"
    assert health(stub, t).returncode == 0
    for reach in ("100.107.22.84:22", "100.107.22.84:8000"):
        r = health(stub, t, reachable=reach)
        assert r.returncode == 1 and f"{reach} is reachable" in r.stderr


@pytest.mark.parametrize("bad", ["100.107.22.84", "100.107.22.84:", "a:b:1", "x;reboot:22", ":22",
                                 "100.107.22.84:22x"])
def test_healthcheck_rejects_malformed_targets(stub, bad):
    assert health(stub, bad).returncode == 1
