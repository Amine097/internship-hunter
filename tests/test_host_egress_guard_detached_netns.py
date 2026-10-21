"""deploy/host-egress-guard.sh against the rootlesskit --detach-netns layout, with REAL user, mount
and network namespaces (tests/netns_guard_lifecycle_sandbox.sh): the production host's rootlesskit
child sits in the HOST network namespace and the daemon's namespace is only reachable through a
file inside the child's mount namespace. Covers the layout itself, every refusal (absent, not a
namespace, the host's, ambiguous, Docker's chains missing), daemon restarts (stale pid file, a
namespace swapped or a process killed under a running apply, a real restart) and the namespace
gate that every firewall command passes through. Packet-level behaviour in this layout is in
tests/test_host_egress_guard_netns.py (its sandbox uses the same layout).

Needs unprivileged user namespaces and iptables (GUARD_IPTABLES_DIR as in the packet tests). Skips
where those are missing, unless GUARD_NETNS_REQUIRED=1 (CI).
"""
import os
import signal
import subprocess
from pathlib import Path

import pytest
from test_host_egress_guard_netns import REQUIRED, _env, _unavailable

SANDBOX = Path(__file__).resolve().parent / "netns_guard_lifecycle_sandbox.sh"

EXPECTED = """
detached_apply_and_status detached_layout_is_what_production_has
detached_rules_are_in_the_daemon_namespace detached_status_names_the_namespace
detached_every_nsenter_names_the_detached_file detached_remove_restores
detached_reapply_after_remove absent_detached_namespace_is_refused
absent_detached_namespace_status_fails plain_file_instead_of_a_namespace_is_refused
symlink_to_the_host_namespace_is_refused symlink_remove_is_refused
ambiguous_layout_is_refused child_is_in_host_netns_in_all_detached_cases
missing_docker_chains_apply missing_docker_chains_status
missing_docker_chains_remove_is_harmless no_mutating_command_was_ever_sent
restart_namespace_swap_is_detected restart_swap_never_touches_the_new_namespace
restart_process_death_is_detected stale_pidfile_is_refused stale_pidfile_apply_is_refused
restarted_daemon_is_unguarded_until_reapplied restarted_daemon_apply_and_status
restarted_daemon_rules_in_new_namespace second_restart_does_not_inherit_the_old_guard
second_restart_reapply gate_runs_with_the_verified_identity
gate_refuses_a_wrong_network_namespace gate_refuses_a_wrong_user_namespace
gate_refuses_the_host_namespace_identity child_layout_apply_and_status
child_layout_status_says_so child_layout_remove
""".split()


@pytest.fixture(scope="module")
def results():
    why = _unavailable()
    if why:
        if REQUIRED:
            pytest.fail(f"GUARD_NETNS_REQUIRED=1 but the sandbox cannot run: {why}")
        pytest.skip(why)
    proc = subprocess.Popen(["bash", str(SANDBOX)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env=_env(), start_new_session=True)
    try:
        stdout, stderr = proc.communicate(timeout=300)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        stdout, stderr = proc.communicate()
        pytest.fail("lifecycle sandbox timed out\n" + stdout[-3000:] + "\n" + stderr[-3000:])
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    assert proc.returncode == 0, stdout + stderr
    assert stdout.rstrip().endswith("DONE"), stdout + stderr         # the script ran to its end
    out = {}
    detail = None
    for line in stdout.splitlines():
        if line.startswith("RESULT "):
            _, name, verdict, *rest = line.split(" ", 3)
            out[name] = [verdict, rest[0] if rest else ""]
            detail = name
        elif detail:
            out[detail][1] += "\n" + line          # a failure detail can span lines
    return out


@pytest.mark.parametrize("name", EXPECTED)
def test_lifecycle_case(results, name):
    assert name in results, f"{name} did not run"
    assert results[name][0] == "PASS", results[name][1]


def test_no_unexpected_cases_are_silently_unchecked(results):
    assert set(results) == set(EXPECTED), set(results) ^ set(EXPECTED)
