"""The cli-egress-probe CI job is a mandatory security check: it runs the real CLIs or fails, a
failing or skipping pytest fails it, and it needs no privileges (the real step scripts are run
under the shell GitHub uses, as in test_workflows.py)."""
from pathlib import Path

import yaml
from test_workflows import fake_python, run_step

WF = Path(__file__).resolve().parents[1] / ".github" / "workflows"
JOB = yaml.safe_load((WF / "ci.yaml").read_text())["jobs"]["cli-egress-probe"]
PREREQ = next(s for s in JOB["steps"] if "must be available" in s.get("name", ""))
PROBE = next(s for s in JOB["steps"] if "What the pinned CLIs send" in s.get("name", ""))
INSTALL = next(s for s in JOB["steps"] if "pinned CLIs" in s.get("name", "") and s is not PROBE)


def test_the_job_is_unprivileged_and_runs_the_probe_as_required():
    assert "sudo" not in yaml.safe_dump(JOB) and JOB["runs-on"] == "ubuntu-22.04"
    assert "continue-on-error" not in yaml.safe_dump(JOB)
    assert PROBE["env"] == {"HUNTER_CLI_PROBE": "1", "HUNTER_CLI_PROBE_REQUIRED": "1"}
    for step in (PREREQ, INSTALL, PROBE):
        assert step["shell"] == "bash" and "set -euo pipefail" in step["run"]
        assert "if" not in step                       # never conditional
    assert "tests/test_cli_egress_probe.py" in PROBE["run"]
    assert "tests/cli_probe/install.sh" in INSTALL["run"]


def test_a_failing_or_skipping_probe_fails_the_step(tmp_path):
    r = run_step(PROBE, tmp_path, {"python": fake_python("1 failed, 19 passed in 90s", 1)})
    assert r.returncode != 0
    skip = tmp_path / "skip"
    skip.mkdir()
    r = run_step(PROBE, skip, {"python": fake_python("19 passed, 1 skipped in 90s", 0)})
    assert r.returncode != 0 and "skipped" in r.stdout
    ok = tmp_path / "ok"
    ok.mkdir()
    assert run_step(PROBE, ok, {"python": fake_python("20 passed in 90s", 0)}).returncode == 0


def test_missing_namespaces_fail_instead_of_reporting_success(tmp_path):
    tools = {t: "exit 0\n" for t in ("ip", "curl", "sha256sum", "shellcheck")}
    r = run_step(PREREQ, tmp_path, {**tools, "unshare": "exit 1\n"})
    assert r.returncode == 1 and "::error" in r.stdout and "CI blocker" in r.stdout
    ok = tmp_path / "ok"
    ok.mkdir()
    assert run_step(PREREQ, ok, {**tools, "unshare": "exit 0\n"}).returncode == 0


TOPO = yaml.safe_load((WF / "ci.yaml").read_text())["jobs"]["egress-topology-lab"]
TOPO_STEP = next(s for s in TOPO["steps"] if "every container pair" in s.get("name", ""))


def test_the_topology_lab_is_a_required_job_without_privileges_or_a_skip_path(tmp_path):
    assert "sudo" not in yaml.safe_dump(TOPO) and TOPO["runs-on"] == "ubuntu-22.04"
    assert TOPO_STEP["env"] == {"HUNTER_ROOTLESS_LAB": "1", "HUNTER_ROOTLESS_LAB_REQUIRED": "1"}
    assert "tests/test_egress_topology_lab.py" in TOPO_STEP["run"]
    r = run_step(TOPO_STEP, tmp_path, {"python": fake_python("5 passed, 1 skipped in 9s", 0)})
    assert r.returncode != 0 and "skipped" in r.stdout
    ok = tmp_path / "ok"
    ok.mkdir()
    assert run_step(TOPO_STEP, ok, {"python": fake_python("6 passed in 200s", 0)}).returncode == 0


def test_the_probe_installs_exactly_the_versions_the_agent_image_pins():
    install = (Path(__file__).parent / "cli_probe" / "install.sh").read_text()
    assert "docker/agent.Dockerfile" in install and "CLAUDE_CODE_VERSION" in install
    assert "CODEX_VERSION" in install and "sha256sum -c" in install
    assert 'got_cc" == "$CC"' in install                # the installed version is verified
