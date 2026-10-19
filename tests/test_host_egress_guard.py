"""Static and plan-mode tests of deploy/host-egress-guard.sh (no namespace, no iptables).
The packet-level behaviour is proven in tests/test_host_egress_guard_netns.py."""
import os
import re
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

GUARD = Path(__file__).resolve().parents[1] / "deploy" / "host-egress-guard.sh"
pytestmark = pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0,
                                reason="shell script; the guard refuses to run as root")


@pytest.fixture
def env(tmp_path):
    """A fake /proc with a rootless daemon in ANOTHER network namespace, and a fake `ip`."""
    proc = tmp_path / "proc"
    (proc / "4242" / "ns").mkdir(parents=True)
    (proc / "4242" / "root" / "etc").mkdir(parents=True)
    (proc / "4242" / "ns" / "net").symlink_to("net:[4026532227]")
    (proc / "self" / "ns").mkdir(parents=True)
    (proc / "self" / "ns" / "net").symlink_to("net:[4026531840]")
    (proc / "4242" / "root" / "etc" / "resolv.conf").write_text(
        "nameserver 127.0.0.53\nnameserver 10.0.2.3\nnameserver fd00::1\n")
    state = tmp_path / "xdg" / "dockerd-rootless"
    state.mkdir(parents=True)
    (state / "child_pid").write_text("4242\n")
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    ip = bin_ / "ip"
    ip.write_text(textwrap.dedent("""\
        #!/bin/sh
        echo "2: eth0    inet 203.0.113.9/24 brd 203.0.113.255 scope global eth0"
        echo "5: tailscale0    inet 100.107.22.84/32 scope global tailscale0"
    """))
    ip.chmod(ip.stat().st_mode | stat.S_IEXEC)
    return {"PATH": f"{bin_}:{os.environ['PATH']}", "HUNTER_GUARD_PROC": str(proc),
            "XDG_RUNTIME_DIR": str(tmp_path / "xdg"), "HOME": str(tmp_path)}


def guard(env, *args):
    return subprocess.run(["bash", str(GUARD), *args], capture_output=True, text=True, env=env,
                          timeout=30)


def test_plan_rejects_tailnet_non_global_space_and_the_hosts_own_addresses(env):
    r = guard(env, "plan")
    assert r.returncode == 0, r.stderr
    for cidr in ("100.64.0.0/10", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                 "169.254.0.0/16", "224.0.0.0/4"):
        assert f"-A HUNTER-EGRESS-GUARD -d {cidr} -j REJECT" in r.stdout, cidr
    assert "-d 203.0.113.9/32 -j REJECT" in r.stdout            # host public/LAN address
    assert "-d 100.107.22.84/32 -j REJECT" in r.stdout          # the real Tailscale IP, by address
    assert "-A HUNTER-EGRESS-GUARD-IN" in r.stdout and "-j REJECT" in r.stdout


def test_plan_exempts_bridge_local_traffic_and_covers_every_docker_bridge(env):
    r = guard(env, "plan")
    for b in ("br-+", "docker0"):
        assert f"-A HUNTER-EGRESS-GUARD -o {b} -j RETURN" in r.stdout
    # bridge-local RETURNs come before the first reject, or peers on one network would be cut
    assert r.stdout.index("-o br-+ -j RETURN") < r.stdout.index("-j REJECT")


def test_plan_never_accepts_anything_it_only_returns_or_rejects(env):
    r = guard(env, "plan")
    rules = [ln for ln in r.stdout.splitlines() if ln.startswith("-A ")]
    assert rules and not [ln for ln in rules if "-j ACCEPT" in ln]
    # default for unmatched (public) destinations is RETURN to Docker's own rules, last in chain
    chain = [ln for ln in rules if ln.startswith("-A HUNTER-EGRESS-GUARD ")]
    assert chain[-1].endswith("-j RETURN")


def test_dns_exception_is_port_53_to_the_namespaces_resolver_only(env):
    r = guard(env, "plan")
    assert "-d 10.0.2.3/32 -p udp --dport 53 -j RETURN" in r.stdout
    assert "-d 10.0.2.3/32 -p tcp --dport 53 -j RETURN" in r.stdout
    assert "127.0.0.53" not in r.stdout and "fd00" not in r.stdout     # loopback/v6 never excepted
    # the exception precedes the rejects it would otherwise hit (10.0.0.0/8)
    assert r.stdout.index("-p udp --dport 53 -j RETURN") < r.stdout.index("-d 10.0.0.0/8 -j REJECT")


def test_explicit_dns_and_protect_arguments(env):
    r = guard(env, "plan", "--dns", "192.168.1.1,192.168.1.2", "--protect", "198.51.100.77/32")
    assert "-d 192.168.1.2/32 -p udp --dport 53 -j RETURN" in r.stdout
    assert "-d 198.51.100.77/32 -j REJECT" in r.stdout and "10.0.2.3" not in r.stdout


def test_no_resolver_is_an_error_not_a_silently_broken_proxy(env, tmp_path):
    resolv = tmp_path / "proc" / "4242" / "root" / "etc" / "resolv.conf"
    resolv.write_text("nameserver 127.0.0.53\n")
    r = guard(env, "plan")
    assert r.returncode == 1 and "no usable DNS resolver" in r.stderr


def test_refuses_the_host_network_namespace(env, tmp_path):
    ns = tmp_path / "proc" / "4242" / "ns" / "net"
    ns.unlink()
    ns.symlink_to("net:[4026531840]")                       # same as /proc/self/ns/net
    r = guard(env, "plan")
    assert r.returncode == 1 and "HOST network namespace" in r.stderr


def test_refuses_without_a_rootless_daemon_or_with_a_stale_pid(env, tmp_path):
    (tmp_path / "xdg" / "dockerd-rootless" / "child_pid").unlink()
    assert "no rootless Docker daemon" in guard(env, "status").stderr
    (tmp_path / "xdg" / "dockerd-rootless" / "child_pid").write_text("999999\n")
    assert "is gone" in guard(env, "status").stderr


@pytest.mark.parametrize("args", [(), ("bogus",), ("plan", "--dns"), ("plan", "--what"),
                                  ("plan", "--protect", "10.0.0.0/33"), ("plan", "--protect", "x"),
                                  ("apply", "--wait", "soon"), ("plan", "--dns", "1.1.1.1;reboot")])
def test_bad_usage_is_rejected(env, args):
    assert guard(env, *args).returncode == 1


def test_script_only_edits_the_daemon_namespace_and_never_runs_as_root():
    text = GUARD.read_text()
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert 'die "refusing to run as root' in code and '"$(id -u)" != 0' in code
    # every firewall command goes through the nsenter wrapper (ipt/ipt6/${NS[@]})
    for ln in code.splitlines():
        s = ln.strip()
        assert not re.match(r"^(sudo|iptables\S*|ip6tables\S*|nft|ufw|firewall-cmd)\b", s), s
    for forbidden in ("ufw", "tailscale", "systemctl", "docker ", "nft ", "sshd", "gluetun"):
        assert forbidden not in code, forbidden
