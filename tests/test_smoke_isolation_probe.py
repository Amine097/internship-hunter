"""M-1: deploy/smoke-test.sh must CLASSIFY every agent-isolation probe, and only a result that
proves the packet did not get through (unreachable, timeout) may count as isolation. A refusal is
an answer from the target, a failed name lookup proves nothing about the network, and a broken
probe tool must
fail the check instead of looking like a block.

The real probe program is extracted from the script and run here against a socket layer whose
outcome per target is chosen by the test (the same technique as tests/test_isolation_gate.py).
"""
import errno
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SMOKE = (ROOT / "deploy" / "smoke-test.sh").read_text()
PROBE = re.search(r'^probe\(\) \{.*?<<\'PY\'.*?\n(.*?)\nPY\n', SMOKE, re.S | re.M).group(1)
ISOLATION = SMOKE[SMOKE.index("# 3. agent isolation"):SMOKE.index("# 4. egress policy")]

STUB = """
import errno, os, socket
_real = socket.create_connection
def _create(addr, timeout=None, *a, **k):
    host, port = addr[0], int(addr[1])
    if host == "127.0.0.1":
        return _real(addr, timeout, *a, **k)          # the probe's own controls stay real
    outcome = dict(x.split("=", 1) for x in os.environ["STUB_OUTCOMES"].split())[f"{host}:{port}"]
    if outcome == "open":
        return socket.socket()
    if outcome == "refused":
        raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")
    if outcome == "reset":
        raise ConnectionResetError(errno.ECONNRESET, "reset")
    if outcome == "timeout":
        raise TimeoutError()
    if outcome == "gaierror":
        raise socket.gaierror(socket.EAI_NONAME, "no such name")
    raise OSError(getattr(errno, outcome), outcome)
socket.create_connection = _create
"""


def run_probe(tmp_path, outcomes: dict, broken_controls=False):
    (tmp_path / "py").mkdir(exist_ok=True)
    stub = STUB
    if broken_controls:                          # a probe tool that cannot tell anything apart
        stub = stub.replace('return _real(addr, timeout, *a, **k)',
                            'raise OSError(errno.EHOSTUNREACH, "everything looks blocked")')
    (tmp_path / "py" / "sitecustomize.py").write_text(stub)
    env = {**os.environ, "PYTHONPATH": str(tmp_path / "py"),
           "STUB_OUTCOMES": " ".join(f"{k}={v}" for k, v in outcomes.items())}
    r = subprocess.run([sys.executable, "-", *outcomes], input=PROBE, capture_output=True,
                       text=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    lines = r.stdout.splitlines()
    results = {ln.split()[1]: ln.split()[2] for ln in lines if ln.startswith("RESULT ")}
    controls = {ln.split()[1]: ln.split()[2] for ln in lines if ln.startswith("CONTROL ")}
    return results, controls


@pytest.mark.parametrize("outcome,cls", [
    ("open", "open"),
    ("refused", "refused"),               # an answer from the target: the path EXISTS
    ("reset", "refused"),
    ("EHOSTUNREACH", "unreachable"),
    ("ENETUNREACH", "unreachable"),
    ("EACCES", "unreachable"),
    ("EPERM", "unreachable"),
    ("timeout", "timeout"),
    ("gaierror", "error"),                # a name lookup is never isolation evidence
    ("EIO", "error"),
    ("EINVAL", "error"),
])
def test_every_outcome_is_classified_exactly(tmp_path, outcome, cls):
    results, controls = run_probe(tmp_path, {"10.9.0.5:5432": outcome})
    assert results == {"10.9.0.5:5432": cls}
    assert controls == {"open": "open", "refused": "refused"}


def test_a_probe_tool_that_sees_everything_as_blocked_fails_its_controls(tmp_path):
    results, controls = run_probe(tmp_path, {"10.9.0.5:5432": "EHOSTUNREACH"}, broken_controls=True)
    assert controls != {"open": "open", "refused": "refused"}


def test_only_unreachable_or_timeout_count_as_isolation_in_the_assessment():
    # the shell accepts exactly these two words for "separate" and Internet targets ...
    assert '[[ "$r" == unreachable || "$r" == timeout ]] || fail' in ISOLATION
    # ... and the shared-network positive control needs a real answer
    assert '[[ "$r" == open || "$r" == refused ]] || fail' in ISOLATION
    # the old classifier (every OSError = "blocked") is gone
    assert 'print("blocked")' not in SMOKE and "except OSError:\n    print" not in SMOKE


def test_the_probe_controls_are_required_before_any_result_counts():
    assert '"CONTROL" && $2 == "open"' in ISOLATION and '"CONTROL" && $2 == "refused"' in ISOLATION
    assert "isolation UNVERIFIED" in ISOLATION


def test_targets_are_ip_addresses_from_docker_not_names():
    assert "docker inspect" in ISOLATION and ".IPAddress" in ISOLATION
    probe_calls = re.findall(r'probe "\$agent" (.*)\)', ISOLATION)
    assert probe_calls and "postgres:" not in probe_calls[0] and "api:" not in probe_calls[0]


def test_all_three_agents_are_probed_including_their_own_proxy_by_address():
    assert "for agent in agent-claude-1 agent-claude-2 agent-codex; do" in ISOLATION
    assert "cannot reach its own proxy by address" in ISOLATION


def test_host_addresses_are_classified_too_and_errors_are_never_a_pass():
    assert "unreachable|timeout) ;;" in ISOLATION
    assert "open|refused) host_leaks+=" in ISOLATION
    assert "*) fail" in ISOLATION.split("open|refused) host_leaks+=")[1].split("esac")[0]


def test_the_sni_swap_evidence_is_from_this_run_only():
    external = SMOKE[SMOKE.index('if [[ "$EXTERNAL" == 1 ]]; then'):]
    assert '--since "$since"' in external and 'grep -F "$swap"' in external
    assert "$RANDOM" in external


def test_no_caller_of_the_removed_unclassified_probe_remains():
    """`reach()` (every OSError = blocked) is gone, and nothing still calls it."""
    assert "reach() {" not in SMOKE
    assert not re.search(r"\$\(reach ", SMOKE)


def test_errno_values_used_by_the_classifier_exist():
    for name in ("EHOSTUNREACH", "ENETUNREACH", "EACCES", "EPERM"):
        assert hasattr(errno, name)
