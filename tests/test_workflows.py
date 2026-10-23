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
    check = (WF.parents[1] / "deploy" / "check-host-isolation.sh").read_text()
    assert 'SMOKE_HOST_ISOLATION:-enforce' in check        # strict unless told otherwise
    assert 'check-host-isolation.sh" "$@"' in smoke        # and the smoke test cannot skip it
    assert "SMOKE_HOST_ISOLATION" not in (WF / "deploy.yaml").read_text()
    doc = (WF.parents[1] / "docs" / "deployment.md").read_text()
    assert "enforce" in doc and "SMOKE_EXPECT_ROOTLESS=1" in doc


def github_shell(step):
    """The command GitHub runs for a `run:` step: an unset `shell:` is `bash -e {0}` (NO pipefail),
    `shell: bash` is `bash --noprofile --norc -eo pipefail {0}`."""
    if step.get("shell") == "bash":
        return ["bash", "--noprofile", "--norc", "-eo", "pipefail"]
    return ["bash", "-e"]


def run_step(step, tmp_path, stubs, env=None):
    import subprocess
    script = tmp_path / "step.sh"
    script.write_text(step["run"])
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    for name, body in stubs.items():
        f = bindir / name
        f.write_text("#!/bin/bash\n" + body)
        f.chmod(0o755)
    e = {"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(tmp_path),
         "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"), **(env or {})}
    return subprocess.run([*github_shell(step), str(script)], cwd=tmp_path, env=e,
                          capture_output=True, text=True, timeout=60)


NETNS_JOB = yaml.safe_load((WF / "ci.yaml").read_text())["jobs"]["host-guard-netns"]
PACKET_STEP = next(s for s in NETNS_JOB["steps"] if "Packet-level guard tests" in s.get("name", ""))
PROBE_STEP = next(s for s in NETNS_JOB["steps"] if "must be available" in s.get("name", ""))


def fake_python(output, rc):
    return f"cat <<'EOF'\n{output}\nEOF\nexit {rc}\n"


def test_f1_the_old_construct_really_hid_a_failing_pytest():
    """Reproduction of the finding: `pytest | tee` under GitHub's default `bash -e` stays green."""
    import subprocess
    old = "false | tee netns.log\n! grep -qE '[0-9]+ (skipped|deselected)' netns.log\n"
    r = subprocess.run(["bash", "-e", "-c", old], capture_output=True)
    assert r.returncode == 0                                      # <- the bug: green job
    r = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", old],
                       capture_output=True)
    assert r.returncode != 0                                      # pipefail is what fixes it


def test_f1_a_failing_pytest_fails_the_packet_step(tmp_path):
    r = run_step(PACKET_STEP, tmp_path, {"python": fake_python("1 failed, 16 passed in 3s", 1)},
                 env={"GUARD_NETNS_REQUIRED": "1"})
    assert r.returncode != 0, r.stdout + r.stderr


def test_f1_a_skipping_pytest_fails_the_packet_step(tmp_path):
    r = run_step(PACKET_STEP, tmp_path, {"python": fake_python("16 passed, 1 skipped in 3s", 0)})
    assert r.returncode != 0 and "skipped tests" in r.stdout


def test_f1_a_passing_pytest_passes_the_packet_step(tmp_path):
    r = run_step(PACKET_STEP, tmp_path, {"python": fake_python("17 passed in 3s", 0)})
    assert r.returncode == 0, r.stdout + r.stderr


def test_f1_unavailable_namespaces_fail_the_required_job_instead_of_reporting_success(tmp_path):
    stubs = {"unshare": "exit 1\n", "iptables": "exit 0\n", "ip6tables": "exit 0\n",
             "nsenter": "exit 0\n"}
    r = run_step(PROBE_STEP, tmp_path, stubs)
    assert r.returncode == 1
    assert "::error" in r.stdout and "CI blocker" in r.stdout
    summary = (tmp_path / "summary.md").read_text()
    assert "BLOCKED" in summary and "ubuntu-22.04" in summary
    ok_dir = tmp_path / "ok"
    ok_dir.mkdir()
    assert run_step(PROBE_STEP, ok_dir, {**stubs, "unshare": "exit 0\n"}).returncode == 0
    missing = {k: v for k, v in stubs.items() if k != "ip6tables"}
    missing["unshare"] = "exit 0\n"
    miss_dir = tmp_path / "miss"
    miss_dir.mkdir()
    assert run_step(PROBE_STEP, miss_dir, missing).returncode == 1


def test_f1_every_piped_step_of_the_security_jobs_runs_with_pipefail():
    import re
    ci = yaml.safe_load((WF / "ci.yaml").read_text())
    for job_name in ("host-guard-netns", "rsm-systemd"):
        for step in ci["jobs"][job_name]["steps"]:
            run = step.get("run", "")
            if re.search(r"\|\s*tee\b|\|\s*grep\b", run):
                assert step.get("shell") == "bash", (job_name, step.get("name"))
                assert "set -euo pipefail" in run, (job_name, step.get("name"))


def test_ci_real_images_exercise_the_probe_tools_and_defects_stay_fatal_in_report_mode():
    ci = yaml.safe_load((WF / "ci.yaml").read_text())
    steps = ci["jobs"]["docker"]["steps"]
    step = next(s for s in steps if "Probe tools run in the real images" in s.get("name", ""))
    assert step["env"]["SMOKE_HOST_ISOLATION"] == "report" and step["shell"] == "bash"
    assert "probe controls verified in" in step["run"] and "set -euo pipefail" in step["run"]
    # ... and report mode does not soften defects (tests/test_host_isolation_check.py)
    check = (WF.parents[1] / "deploy" / "check-host-isolation.sh").read_text()
    assert "defects are fatal in every mode" in check


def test_ci_packet_level_guard_job_is_a_required_failing_job_not_a_skip():
    text = (WF / "ci.yaml").read_text()
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    # the project rule: never relax the AppArmor userns restriction, and no sudo outside rsm-systemd
    assert "sysctl -w" not in code and "apparmor_restrict_unprivileged_userns=0" not in code
    assert "sudo" not in yaml.safe_dump(NETNS_JOB) and NETNS_JOB["runs-on"] == "ubuntu-22.04"
    assert PACKET_STEP["env"]["GUARD_NETNS_REQUIRED"] == "1"
    names = [s.get("name", "") for s in NETNS_JOB["steps"]]
    assert not any("EXPLICIT SKIP" in n for n in names)           # no success-on-skip path any more
    assert "continue-on-error" not in yaml.safe_dump(NETNS_JOB)
    assert "if" not in PACKET_STEP and "if" not in PROBE_STEP     # always runs, never conditional
    pin = NETNS_JOB["steps"][0]["uses"].split("@")[1].split(" ")[0]
    assert pin == "11bd71901bbe5b1630ceea73d27597364c9af683"


# ---- the rootless DNS lab job and the DNS check in the docker job ---------------------------
LAB_JOB = yaml.safe_load((WF / "ci.yaml").read_text())["jobs"]["rootless-dns-lab"]
LAB_STEP = next(s for s in LAB_JOB["steps"] if "Real rootless Docker" in s.get("name", ""))
LAB_PROBE = next(s for s in LAB_JOB["steps"] if "must be available" in s.get("name", ""))


def test_dns_lab_is_a_required_failing_job_without_privileges_and_without_a_skip_path():
    assert "sudo" not in yaml.safe_dump(LAB_JOB) and LAB_JOB["runs-on"] == "ubuntu-22.04"
    assert LAB_STEP["env"]["HUNTER_ROOTLESS_LAB"] == "1"
    assert LAB_STEP["env"]["HUNTER_ROOTLESS_LAB_REQUIRED"] == "1"
    for step in (LAB_STEP, LAB_PROBE):
        assert step["shell"] == "bash" and "set -euo pipefail" in step["run"]
    assert "tests/test_dns_rootless_lab.py" in LAB_STEP["run"]
    assert "tests/test_runtime_containment_lab.py" in LAB_STEP["run"]   # containment, real daemon
    assert LAB_JOB["env"]["CI_REQUIRE_SERVICES"] == ""


def test_dns_lab_a_failing_or_skipping_pytest_fails_the_step(tmp_path):
    r = run_step(LAB_STEP, tmp_path, {"python": fake_python("1 failed, 10 passed in 3s", 1)},
                 env={"HUNTER_ROOTLESS_LAB": "1"})
    assert r.returncode != 0
    skip_dir = tmp_path / "skip"
    skip_dir.mkdir()
    r = run_step(LAB_STEP, skip_dir, {"python": fake_python("10 passed, 1 skipped in 3s", 0)})
    assert r.returncode != 0 and "skipped tests" in r.stdout
    ok_dir = tmp_path / "ok"
    ok_dir.mkdir()
    assert run_step(LAB_STEP, ok_dir, {"python": fake_python("11 passed in 3s", 0)}).returncode == 0


def test_dns_lab_unavailable_prerequisites_fail_instead_of_reporting_success(tmp_path):
    tools = {t: "exit 0\n" for t in ("iptables", "ip6tables", "nsenter", "curl", "tar",
                                      "sha256sum")}
    r = run_step(LAB_PROBE, tmp_path, {**tools, "unshare": "exit 1\n"})
    assert r.returncode == 1 and "::error" in r.stdout and "CI blocker" in r.stdout
    ok_dir = tmp_path / "ok"
    ok_dir.mkdir()
    assert run_step(LAB_PROBE, ok_dir, {**tools, "unshare": "exit 0\n"}).returncode == 0


def test_docker_job_gives_compose_a_resolver_that_exists_on_a_rootful_runner_and_checks_dns():
    ci = yaml.safe_load((WF / "ci.yaml").read_text())
    job = ci["jobs"]["docker"]
    assert job["env"]["HUNTER_DNS"] == "1.1.1.1"
    step = next(s for s in job["steps"] if "DNS check runs in the real images" in s.get("name", ""))
    assert step["env"]["SMOKE_HOST_ISOLATION"] == "report" and step["shell"] == "bash"
    assert "set -euo pipefail" in step["run"] and "deploy/check-dns.sh" in step["run"]
    smoke = (WF.parents[1] / "deploy" / "smoke-test.sh").read_text()
    assert 'check-dns.sh" "$@"' in smoke                  # the smoke test cannot skip it
    assert "/mnt/check-dns.sh" in (WF / "ci.yaml").read_text()          # and shellcheck sees it


def test_all_original_ci_jobs_are_still_there():
    jobs = set(yaml.safe_load((WF / "ci.yaml").read_text())["jobs"])
    assert {"lint-test", "rsm-systemd", "host-guard-netns", "shellcheck", "dependency-audit",
            "secret-scan", "docker"} <= jobs


# Every mandatory security job. A superset is fine: other changes add jobs (the CLI egress probe,
# ...) and
# a test that counts jobs turns CI red for whichever change merges second.
REQUIRED_JOBS = frozenset({
    "lint-test", "secret-scan", "rootless-dns-lab", "dependency-audit", "rsm-systemd", "shellcheck",
    "docker", "host-guard-netns",
})


def missing_or_optional(jobs: dict) -> set:
    """Required jobs that are absent, or that may fail without failing the workflow."""
    bad = set(REQUIRED_JOBS - set(jobs))
    bad |= {j for j in REQUIRED_JOBS & set(jobs)
            if (jobs[j] or {}).get("continue-on-error") not in (None, False)}
    return bad


def test_runtime_containment_script_is_linted_and_no_required_ci_job_was_dropped():
    ci = (WF / "ci.yaml").read_text()
    assert "/mnt/runtime-containment.sh" in ci                       # shellcheck sees it
    jobs = yaml.safe_load(ci)["jobs"]
    assert not missing_or_optional(jobs), missing_or_optional(jobs)
    assert "continue-on-error" not in yaml.safe_dump(jobs["rootless-dns-lab"])


def test_the_job_check_accepts_more_jobs_and_rejects_a_dropped_or_optional_required_one():
    base = {j: {"runs-on": "ubuntu-latest"} for j in REQUIRED_JOBS}
    assert missing_or_optional(base) == set()
    assert missing_or_optional({**base, "cli-egress-probe": {}, "something-new": {}}) == set()
    assert missing_or_optional({k: v for k, v in base.items() if k != "docker"}) == {"docker"}
    optional = {**base, "shellcheck": {"continue-on-error": True}}
    assert missing_or_optional(optional) == {"shellcheck"}
