"""Static policy checks for the GitHub workflows (what secrets reach which job)."""
import re
from pathlib import Path

import yaml

WF = Path(__file__).resolve().parents[1] / ".github" / "workflows"
DEPLOY = yaml.safe_load((WF / "deploy.yaml").read_text())
SHA_PIN = re.compile(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}( |$)")


def jobs_referencing(secret: str, doc=DEPLOY):
    return {name for name, job in doc["jobs"].items() if secret in yaml.safe_dump(job)}


def test_signing_key_is_only_reachable_from_the_sign_job():
    assert jobs_referencing("RELEASE_SIGNING_KEY") == {"sign"}
    for other in ("ci.yaml",):
        assert "RELEASE_SIGNING_KEY" not in (WF / other).read_text()


def test_sign_job_is_restricted_to_main_and_its_own_environment():
    sign = DEPLOY["jobs"]["sign"]
    assert sign["environment"] == "release-signing"
    assert "refs/heads/main" in sign["if"]
    assert "verify" in sign["needs"] and "build" in sign["needs"]
    uses = [s.get("uses", "") for s in sign["steps"]]
    assert not any("docker" in u for u in uses)
    runs = "\n".join(s.get("run", "") for s in sign["steps"])
    assert "docker " not in runs and "tar -x" not in runs  # never executes/extracts artifacts
    checkout = next(s for s in sign["steps"] if "checkout" in s.get("uses", ""))
    assert checkout["with"]["ref"] == "${{ github.sha }}"  # trusted code, not the release ref


def test_build_and_verify_jobs_hold_no_secrets_and_no_environment():
    for name in ("verify", "build"):
        job = DEPLOY["jobs"][name]
        dumped = yaml.safe_dump(job)
        assert "secrets." not in dumped, name
        assert "environment" not in job, name


def test_deploy_secrets_are_confined_to_the_deploy_job():
    for secret in ("TS_OAUTH_SECRET", "DEPLOY_SSH_KEY", "DEPLOY_KNOWN_HOSTS"):
        assert jobs_referencing(secret) == {"deploy"}, secret
    assert DEPLOY["jobs"]["deploy"]["environment"] == "production"


def test_rsm_pilot_workflow_is_manual_secretless_and_does_not_relax_apparmor():
    text = (WF / "rsm-pilot.yaml").read_text()
    doc = yaml.safe_load(text)
    triggers = doc[True] if True in doc else doc["on"]
    assert set(triggers) == {"workflow_dispatch"}
    assert "secrets." not in text
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "apparmor_restrict_unprivileged_userns=0" not in code.replace(" ", "")
    assert "sysctl -w" not in code and "aa-teardown" not in code and "aa-disable" not in code
    assert "/usr/bin/rootlesskit" in code                      # a per-binary profile only
    assert "usermod -aG docker" not in code and "docker hunter-deploy" not in code
    assert doc["permissions"] == {"contents": "read"}


def test_rsm_systemd_job_is_the_only_privileged_ci_job_and_holds_nothing():
    text = (WF / "ci.yaml").read_text()
    ci = yaml.safe_load(text)
    job = ci["jobs"]["rsm-systemd"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["permissions"] == {"contents": "read"}
    assert "environment" not in job and "secrets." not in yaml.safe_dump(job)
    # never for fork PRs: privileged execution only for this repository's own branches
    assert "github.event.pull_request.head.repo.full_name == github.repository" in job["if"]
    checkout = next(s for s in job["steps"] if "checkout" in s.get("uses", ""))
    assert checkout["with"]["persist-credentials"] is False
    runs = "\n".join(s.get("run", "") for s in job["steps"])
    assert "RSM_SYSTEMD=1" in runs and "tests/test_rsm_systemd.py" in runs
    assert "skipped|deselected" in runs                         # a skip fails the job
    cleanup = [s for s in job["steps"] if "--cleanup" in s.get("run", "")]
    assert len(cleanup) == 1 and cleanup[0]["if"] == "always()"
    # sudo nowhere else; lint-test stays unprivileged and does not opt in
    for name, other in ci["jobs"].items():
        if name != "rsm-systemd":
            assert "sudo" not in yaml.safe_dump(other), name
    assert "RSM_SYSTEMD" not in yaml.safe_dump(ci["jobs"]["lint-test"])
    # the runner's AppArmor / user-namespace restrictions are not relaxed
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "apparmor_restrict_unprivileged_userns" not in code
    assert "sysctl" not in code and "aa-teardown" not in code and "aa-disable" not in code
    assert "/etc/apparmor.d" not in code and "apparmor_parser" not in code


def test_deploy_is_manual_only_and_disabled_by_default():
    triggers = DEPLOY[True] if True in DEPLOY else DEPLOY["on"]
    assert set(triggers) == {"workflow_dispatch"}
    assert "vars.DEPLOY_ENABLED == 'true'" in DEPLOY["jobs"]["verify"]["if"]
    for name in ("build", "sign", "deploy"):
        assert "verify" in str(DEPLOY["jobs"][name]["needs"])


def test_ci_does_not_run_on_untrusted_secrets_and_cancels_only_prs():
    ci = yaml.safe_load((WF / "ci.yaml").read_text())
    assert "secrets." not in (WF / "ci.yaml").read_text()
    assert "pull_request'" in ci["concurrency"]["cancel-in-progress"]
    assert ci["permissions"] == {"contents": "read"}


def test_all_actions_are_pinned_to_commit_shas():
    for wf in WF.glob("*.yaml"):
        doc = yaml.safe_load(wf.read_text())
        for job in doc["jobs"].values():
            for step in job.get("steps", []):
                if "uses" in step:
                    assert SHA_PIN.match(step["uses"]), (wf.name, step["uses"])


def test_actions_read_permission_only_where_needed():
    perms = {n: j.get("permissions", {}) for n, j in DEPLOY["jobs"].items()}
    assert perms["verify"].get("actions") == "read"
    assert all("actions" not in p for n, p in perms.items() if n != "verify")


def test_deploy_scripts_are_executable_in_git():
    import subprocess
    out = subprocess.run(["git", "ls-files", "-s", "deploy"], capture_output=True, text=True,
                         cwd=WF.parents[1], check=True).stdout.split("\n")
    scripts = [ln for ln in out if ln.endswith((".sh", ".py"))]
    assert scripts
    assert all(ln.startswith("100755") for ln in scripts), scripts


def test_ci_smoke_reports_but_deploy_gate_enforces_host_isolation():
    ci = (WF / "ci.yaml").read_text()
    assert "SMOKE_HOST_ISOLATION: report" in ci            # explicit, never implicit
    smoke = (WF.parents[1] / "deploy" / "smoke-test.sh").read_text()
    assert 'SMOKE_HOST_ISOLATION:-enforce' in smoke        # strict unless told otherwise
    assert "SMOKE_HOST_ISOLATION" not in (WF / "deploy.yaml").read_text()
    doc = (WF.parents[1] / "docs" / "deployment.md").read_text()
    assert "enforce" in doc and "SMOKE_EXPECT_ROOTLESS=1" in doc
