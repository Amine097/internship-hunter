"""The REAL deploy/host-egress-guard.sh against REAL iptables and REAL packets, inside throwaway
user+network namespaces (tests/netns_guard_sandbox.sh). It reproduces the production finding -
a container on a non-internal bridge can dial the host's Tailscale IP through the daemon's
uplink - and proves the guard closes it while public traffic and DNS keep working.

Needs unprivileged user namespaces and iptables (set GUARD_IPTABLES_DIR to a directory holding
iptables/iptables-restore/ip6tables wrappers if they are not on PATH). It skips where those are
missing, unless GUARD_NETNS_REQUIRED=1 (CI), where a skip would hide a broken guard.
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

SANDBOX = Path(__file__).resolve().parent / "netns_guard_sandbox.sh"
IPT_DIR = os.environ.get("GUARD_IPTABLES_DIR")
REQUIRED = os.environ.get("GUARD_NETNS_REQUIRED") == "1"


def _env():
    env = dict(os.environ)
    if IPT_DIR:
        env["PATH"] = IPT_DIR + os.pathsep + env["PATH"]
    return env


def _unavailable():
    env = _env()
    if os.geteuid() == 0:
        return "the guard refuses to run as root"
    for tool in ("unshare", "nsenter", "ip", "python3"):
        if not shutil.which(tool, path=env["PATH"]):
            return f"{tool} not found"
    if not shutil.which("iptables", path=env["PATH"]):
        return "iptables not found"
    probe = subprocess.run(["unshare", "-Urn", "true"], capture_output=True, env=env)
    if probe.returncode != 0:
        return "unprivileged user namespaces are not available"
    return None


@pytest.fixture(scope="module")
def stages():
    why = _unavailable()
    if why:
        if REQUIRED:
            pytest.fail(f"GUARD_NETNS_REQUIRED=1 but the sandbox cannot run: {why}")
        pytest.skip(why)
    run = subprocess.run(["bash", str(SANDBOX)], capture_output=True, text=True, env=_env(),
                         timeout=120)
    assert run.returncode == 0, run.stdout + run.stderr
    out, stage = {}, None
    for line in run.stdout.splitlines():
        if line.startswith("STAGE "):
            stage = line.split()[1]
            out[stage] = {}
        elif stage and len(line.split()) == 2 and line.split()[1] in ("REACHABLE", "blocked"):
            out[stage][line.split()[0]] = line.split()[1]
        else:
            out.setdefault("_", []).append(line)
    return out


PROTECTED = ["tailnet_ssh", "tailnet_gluetun", "host_public_ip", "slirp_gateway", "bridge_gateway"]


def test_the_finding_reproduces_without_the_guard(stages):
    """Observed in production: the default-bridge container reaches 100.x:22 and :8000."""
    before = stages["before"]
    for label in ("tailnet_ssh", "tailnet_gluetun", "host_public_ip", "slirp_gateway"):
        assert before[label] == "REACHABLE", label


def test_guard_blocks_every_protected_destination(stages):
    g = stages["guarded"]
    for label in PROTECTED:
        assert g[label] == "blocked", label


def test_guard_keeps_the_internet_and_dns_working(stages):
    g = stages["guarded"]
    assert g["internet"] == "REACHABLE"          # CONNECT to a provider is a public destination
    assert g["dns_udp"] == "REACHABLE" and g["dns_tcp"] == "REACHABLE"
    assert g["daemon_to_container"] == "REACHABLE"   # docker-proxy style traffic still flows
    # agent <-> proxy <-> orchestrator traffic never leaves a bridge; with br_netfilter it still
    # crosses FORWARD, where a blanket 172.16/12 reject would cut it
    assert g["peer_same_bridge"] == "REACHABLE"


def test_guard_covers_the_default_bridge_and_adhoc_containers_too(stages):
    assert stages["before"]["default_bridge_tailnet_ssh"] == "REACHABLE"
    assert stages["guarded"]["default_bridge_tailnet_ssh"] == "blocked"
    assert stages["guarded"]["default_bridge_internet"] == "REACHABLE"


def test_guard_is_idempotent_and_status_reports_it(stages):
    assert "status active" in stages["_"]
    reapply = [ln for ln in stages["_"] if ln.startswith("rules_after_reapply")][0].split()
    assert reapply[-1] == "2"                    # one jump per bridge pattern, no duplicates
    assert int(reapply[1]) < 40                  # the chain was rebuilt, not appended to


def test_remove_restores_dockers_own_rules_exactly(stages):
    assert "status inactive" in stages["_"]
    assert stages["removed"] == stages["before"]
    assert "leftover_rules 0" in stages["_"]
