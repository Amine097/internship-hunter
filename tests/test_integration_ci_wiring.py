"""The CI steps that run QA's adversarial tests cannot go green by not running them.

Same technique as tests/test_workflows.py: the step's own shell script is run with a fake `python`,
so a failing pytest, a skipping pytest and a passing one are shown to fail, fail and pass the step.
No job was added: the steps live in existing mandatory jobs (the ten-job membership check is in
tests/test_workflows.py).
"""

from pathlib import Path

import pytest
import yaml
from test_workflows import fake_python, run_step

CI = yaml.safe_load((Path(__file__).resolve().parents[1] / ".github/workflows/ci.yaml").read_text())

WIRED = [
    # (job, step name fragment, test files that step must run, required environment)
    (
        "host-guard-netns",
        "Adversarial integration tests",
        [
            "tests/test_integration_smoke_detectors.py",
            "tests/test_integration_proxy_authorization.py",
            "tests/test_integration_proxy_differential_fuzz.py",
            "tests/test_integration_proxy_resources.py",
        ],
        {"HUNTER_QA_REQUIRED": "1", "PROXY_AUTHZ_REQUIRED": "1"},
    ),
    (
        "egress-topology-lab",
        "Hostile-agent sweep",
        ["tests/test_integration_agent_sweep.py"],
        {"HUNTER_ROOTLESS_LAB": "1", "HUNTER_ROOTLESS_LAB_REQUIRED": "1"},
    ),
    (
        "rootless-dns-lab",
        "Watchdog events, order, locks, drift and failure injection",
        [
            "tests/test_integration_watchdog_events.py",
            "tests/test_integration_containment_failure_injection.py",
        ],
        {"HUNTER_ROOTLESS_LAB": "1", "HUNTER_ROOTLESS_LAB_REQUIRED": "1"},
    ),
]


def _step(job, fragment):
    return next(s for s in CI["jobs"][job]["steps"] if fragment in s.get("name", ""))


@pytest.mark.parametrize("job,fragment,files,env", WIRED, ids=[w[1] for w in WIRED])
def test_the_step_runs_its_files_as_required_with_pipefail(job, fragment, files, env):
    step = _step(job, fragment)
    assert step["shell"] == "bash" and "set -euo pipefail" in step["run"]
    for f in files:
        assert f in step["run"], f"{f} is not run by '{fragment}'"
    for k, v in env.items():
        assert step["env"][k] == v
    assert "sudo" not in step["run"]


@pytest.mark.parametrize("job,fragment,files,env", WIRED, ids=[w[1] for w in WIRED])
def test_a_failing_or_skipping_pytest_fails_the_step(tmp_path, job, fragment, files, env):
    step = _step(job, fragment)
    bad = tmp_path / "failing"
    bad.mkdir()
    assert run_step(step, bad, {"python": fake_python("1 failed, 9 passed in 3s", 1)}).returncode
    skip = tmp_path / "skipping"
    skip.mkdir()
    r = run_step(step, skip, {"python": fake_python("9 passed, 1 skipped in 3s", 0)})
    assert r.returncode != 0 and "skipped tests" in r.stdout
    deselected = tmp_path / "deselected"
    deselected.mkdir()
    r = run_step(step, deselected, {"python": fake_python("9 passed, 1 deselected", 0)})
    assert r.returncode != 0 and "skipped tests" in r.stdout
    ok = tmp_path / "ok"
    ok.mkdir()
    assert run_step(step, ok, {"python": fake_python("10 passed in 3s", 0)}).returncode == 0


def test_every_mandatory_job_is_still_present():
    assert len(CI["jobs"]) >= 10
    assert {
        "lint-test", "rsm-systemd", "host-guard-netns", "rootless-dns-lab", "egress-topology-lab",
        "cli-egress-probe", "shellcheck", "dependency-audit", "secret-scan", "docker",
    } <= set(CI["jobs"])  # fmt: skip
