"""Static and plan-mode tests of deploy/host-egress-guard.sh (no namespace, no iptables).
The packet-level behaviour is proven in tests/test_host_egress_guard_netns.py."""
import os
import re
import socket
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
    """A fake /proc with a rootless daemon in ANOTHER network+user namespace, a fake `ip`, and a
    fake rootless socket. Only usable because HUNTER_GUARD_TEST_MODE=1 is set explicitly."""
    proc = tmp_path / "proc"
    (proc / "4242" / "ns").mkdir(parents=True)
    (proc / "4242" / "root" / "etc").mkdir(parents=True)
    (proc / "4242" / "ns" / "net").symlink_to("net:[4026532227]")
    (proc / "4242" / "ns" / "user").symlink_to("user:[4026532226]")
    (proc / "4242" / "cmdline").write_bytes(b"dockerd\0--host=unix:///x\0")
    # /proc/<pid>/stat: field 22 (start time) is the 20th token after the "(comm) "
    (proc / "4242" / "stat").write_text("4242 (dockerd) S " + " ".join(["0"] * 18) + " 777 0 0\n")
    (proc / "4242" / "uid_map").write_text(f"         0       {os.getuid()}          1\n")
    (proc / "self" / "ns").mkdir(parents=True)
    (proc / "self" / "ns" / "net").symlink_to("net:[4026531840]")
    (proc / "self" / "ns" / "user").symlink_to("user:[4026531837]")
    (proc / "4242" / "root" / "etc" / "resolv.conf").write_text(
        "nameserver 127.0.0.53\nnameserver 10.0.2.3\nnameserver fd00::1\n")
    state = tmp_path / "xdg" / "dockerd-rootless"
    state.mkdir(parents=True)
    (state / "child_pid").write_text("4242\n")
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(tmp_path / "xdg" / "docker.sock"))
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    ip = bin_ / "ip"
    ip.write_text(textwrap.dedent("""\
        #!/bin/sh
        case "$*" in
          *route*) echo "default via 203.0.113.1 dev eth0 proto dhcp" ;;
          *addr*)
            echo "2: eth0    inet 203.0.113.9/24 brd 203.0.113.255 scope global eth0"
            echo "5: tailscale0    inet 100.107.22.84/32 scope global tailscale0"
            echo "7: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0"
            echo "9: br-0123456789ab    inet 172.20.0.1/16 scope global br-0123456789ab" ;;
        esac
    """))
    ip.chmod(ip.stat().st_mode | stat.S_IEXEC)
    yield {"PATH": f"{bin_}:{os.environ['PATH']}", "HUNTER_GUARD_PROC": str(proc),
           "HUNTER_GUARD_TEST_MODE": "1", "XDG_RUNTIME_DIR": str(tmp_path / "xdg"),
           "HOME": str(tmp_path)}
    sock.close()


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
    assert "-d 203.0.113.1/32 -j REJECT" in r.stdout            # the host's default gateway
    # rootful Docker bridges' gateway addresses: rootful containers' published ports listen there
    assert "-d 172.17.0.1/32 -j REJECT" in r.stdout and "-d 172.20.0.1/32 -j REJECT" in r.stdout
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
    assert 'die "refusing to run as root' in code and '"$MYUID" != 0' in code
    # every firewall command goes through the nsenter wrapper (ipt/ipt6/${NS[@]})
    for ln in code.splitlines():
        s = ln.strip()
        assert not re.match(r"^(sudo|iptables\S*|ip6tables\S*|nft|ufw|firewall-cmd)\b", s), s
    for forbidden in ("ufw", "tailscale", "systemctl", "docker ", "nft ", "sshd", "gluetun"):
        assert forbidden not in code, forbidden


# ---- R5: the target must be proven to be this user's rootless daemon -------------------------
def test_proc_override_is_refused_outside_explicit_test_mode(env):
    env = {k: v for k, v in env.items() if k != "HUNTER_GUARD_TEST_MODE"}
    r = guard(env, "plan")
    assert r.returncode == 1 and "only honoured with HUNTER_GUARD_TEST_MODE=1" in r.stderr


def test_test_mode_is_announced_loudly(env):
    assert "WARNING test mode" in guard(env, "plan").stderr


def test_refuses_a_process_that_is_not_a_docker_daemon(env, tmp_path):
    (tmp_path / "proc" / "4242" / "cmdline").write_bytes(b"sleep\x00600\x00")
    r = guard(env, "plan")
    assert r.returncode == 1 and "not a Docker daemon" in r.stderr


def test_refuses_a_process_not_in_a_user_namespace_mapped_to_this_uid(env, tmp_path):
    (tmp_path / "proc" / "4242" / "uid_map").write_text("         0          0 4294967295\n")
    r = guard(env, "plan")
    assert r.returncode == 1 and "not rootless Docker" in r.stderr


def test_refuses_a_process_sharing_our_user_namespace(env, tmp_path):
    link = tmp_path / "proc" / "4242" / "ns" / "user"
    link.unlink()
    link.symlink_to("user:[4026531837]")
    r = guard(env, "plan")
    assert r.returncode == 1 and "shares this user namespace" in r.stderr


def test_refuses_without_the_rootless_socket(env, tmp_path):
    (tmp_path / "xdg" / "docker.sock").unlink()
    assert "no rootless Docker socket" in guard(env, "plan").stderr


def test_refuses_a_pidfile_owned_by_someone_else(env, tmp_path):
    # stat is the same user in a test, so check the guard compares against the current uid
    assert '"$(stat -c %u "$PIDFILE")" == "$MYUID"' in GUARD.read_text()


def test_conf_file_supplies_dns_and_protect_and_must_be_trusted(env, tmp_path):
    d = tmp_path / "g"
    d.mkdir()
    script = d / "host-egress-guard.sh"
    script.write_text(GUARD.read_text())
    conf = d / "host-egress-guard.conf"
    conf.write_text("# comment\nDNS=192.168.7.7\nPROTECT=198.51.100.9/32\n")
    conf.chmod(0o644)
    r = subprocess.run(["bash", str(script), "plan"], capture_output=True, text=True, env=env)
    assert r.returncode == 0 and "-d 192.168.7.7/32 -p udp --dport 53" in r.stdout
    assert "-d 198.51.100.9/32 -j REJECT" in r.stdout
    conf.chmod(0o666)                                           # world-writable: not trusted
    r = subprocess.run(["bash", str(script), "plan"], capture_output=True, text=True, env=env)
    assert r.returncode == 1 and "not group/world-writable" in r.stderr
    conf.chmod(0o644)
    conf.write_text("EVIL=1\n")
    r = subprocess.run(["bash", str(script), "plan"], capture_output=True, text=True, env=env)
    assert r.returncode == 1 and "unknown line" in r.stderr


def test_plan_covers_ipv6_forward_and_input(env):
    r = guard(env, "plan")
    assert "-A HUNTER-EGRESS-GUARD6 -j REJECT --reject-with icmp6-adm-prohibited" in r.stdout
    assert "-A HUNTER-EGRESS-GUARD6-IN -p ipv6-icmp -j RETURN" in r.stdout
    assert "-A HUNTER-EGRESS-GUARD6-IN -j REJECT --reject-with icmp6-adm-prohibited" in r.stdout
    assert "ip6tables -I INPUT 1" in r.stdout and "ip6tables -I FORWARD 1" in r.stdout


# ---- the daemon's network namespace: rootlesskit --detach-netns ------------------------------
HOST_NET = "net:[4026531840]"


def _detached(env, tmp_path, own_net=HOST_NET, child_net=HOST_NET):
    """The production layout: the rootlesskit child is in the HOST network namespace and the
    daemon's namespace is a file under the child's root. The tests cannot make an nsfs file, so
    the fake one is a plain file and the (test-mode-only) filesystem-type override says what to
    expect; tests/test_host_egress_guard_detached_netns.py does it with real namespaces."""
    root = tmp_path / "proc" / "4242" / "root"
    f = root / str(tmp_path / "xdg").lstrip("/") / "dockerd-rootless" / "netns"
    f.parent.mkdir(parents=True)
    f.write_text("")
    fstype = subprocess.run(["stat", "-f", "-c", "%T", str(f)], capture_output=True,
                            text=True).stdout.strip()
    ino = str(f.stat().st_ino)
    link = tmp_path / "proc" / "4242" / "ns" / "net"
    link.unlink()
    link.symlink_to(child_net.replace("INODE", ino))
    me = tmp_path / "proc" / "self" / "ns" / "net"
    me.unlink()
    me.symlink_to(own_net.replace("INODE", ino))
    return f, {**env, "HUNTER_GUARD_TEST_NSFS_TYPE": fstype}


def test_detached_namespace_is_the_target_not_the_childs_host_namespace(env, tmp_path):
    f, env = _detached(env, tmp_path)
    r = guard(env, "plan")
    assert r.returncode == 0, r.stderr
    assert f"net:[{f.stat().st_ino}]" in r.stdout and "detached layout" in r.stdout
    assert HOST_NET in r.stdout                        # named as "this process / the host"


def test_detached_namespace_equal_to_the_host_is_refused(env, tmp_path):
    f, env = _detached(env, tmp_path, own_net="net:[INODE]", child_net="net:[INODE]")
    r = guard(env, "plan")
    assert r.returncode == 1 and "is the HOST network namespace" in r.stderr


def test_a_child_in_the_host_namespace_without_a_detached_one_is_refused(env, tmp_path):
    link = tmp_path / "proc" / "4242" / "ns" / "net"
    link.unlink()
    link.symlink_to(HOST_NET)
    r = guard(env, "plan")
    assert r.returncode == 1 and "no detached daemon namespace" in r.stderr
    assert "cannot be identified" in r.stderr


def test_a_plain_file_is_not_a_namespace(env, tmp_path):
    f, env = _detached(env, tmp_path)
    env = {k: v for k, v in env.items() if k != "HUNTER_GUARD_TEST_NSFS_TYPE"}
    r = guard(env, "plan")
    assert r.returncode == 1 and "not a namespace file" in r.stderr


def test_a_symlink_instead_of_the_bind_mounted_file_is_refused(env, tmp_path):
    f, env = _detached(env, tmp_path)
    target = tmp_path / "elsewhere"
    target.write_text("")
    f.unlink()
    f.symlink_to(target)
    r = guard(env, "plan")
    assert r.returncode == 1 and "symbolic link" in r.stderr


def test_a_child_in_a_third_namespace_is_ambiguous(env, tmp_path):
    f, env = _detached(env, tmp_path, child_net="net:[4026539999]")
    r = guard(env, "plan")
    assert r.returncode == 1 and "ambiguous layout" in r.stderr


def test_the_filesystem_type_override_is_refused_outside_test_mode(env, tmp_path):
    f, env = _detached(env, tmp_path)
    env = {k: v for k, v in env.items() if k != "HUNTER_GUARD_TEST_MODE"}
    env.pop("HUNTER_GUARD_PROC")
    r = guard(env, "plan")
    assert r.returncode == 1 and "HUNTER_GUARD_TEST_NSFS_TYPE is only honoured" in r.stderr


def test_an_unreadable_start_time_is_refused(env, tmp_path):
    (tmp_path / "proc" / "4242" / "stat").unlink()
    r = guard(env, "plan")
    assert r.returncode == 1 and "start time" in r.stderr


def test_every_firewall_command_goes_through_the_verified_namespace_gate():
    code = "\n".join(ln for ln in GUARD.read_text().splitlines() if not ln.lstrip().startswith("#"))
    assert code.count("NS_PREFIX=(nsenter") == 1             # one entry point, defined once
    others = [ln for ln in code.splitlines()
              if "nsenter" in ln and not ln.startswith("NS_PREFIX=(nsenter") and "PATH=" not in ln]
    assert not others
    assert "exit 97" in code and "/proc/self/ns/net" in code and "/proc/self/ns/user" in code
    assert "--net=$NETNS_FILE" in code and "--preserve-credentials" in code
    assert "-U -n" not in code                      # the pre-detach form that fails in production
    # no path that quietly picks the child's namespace when the detached one is missing or unusable
    assert code.count("TARGET_NET=") == 2
