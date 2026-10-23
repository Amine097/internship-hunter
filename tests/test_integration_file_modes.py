"""Scripts that are run as programs must be executable in git.

Found while reviewing PR #14: an edit made through a tool that rewrites files turned
deploy/smoke-test.sh from 100755 into 100644. CI runs it as `deploy/smoke-test.sh` (ci.yaml), the
deploy scripts call each other by path, so the stack's own smoke test would die with "Permission
denied" - after the images were built, in the one job that proves the isolation. Nothing else in the
suite looks at modes. The rule: a tracked file under deploy/ or docker/ whose first line is a
shebang is meant to be executed.
"""

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _tracked_with_modes():
    r = subprocess.run(
        ["git", "ls-files", "-s", "-z"], cwd=ROOT, capture_output=True, text=True, check=False
    )
    if r.returncode != 0:
        pytest.skip("not a git checkout")
    for entry in filter(None, r.stdout.split("\0")):
        meta, _, path = entry.partition("\t")
        yield meta.split()[0], path


def test_every_tracked_file_with_a_shebang_is_executable():
    """deploy/ and docker/ hold the programs that are run by path (tests/ helpers are launched
    through an explicit interpreter, so their mode is irrelevant and not checked)."""
    wrong = []
    for mode, path in _tracked_with_modes():
        if mode == "120000" or not path.startswith(("deploy/", "docker/")):
            continue
        f = ROOT / path
        try:
            with open(f, "rb") as fh:
                first = fh.read(2)
        except OSError:
            continue
        if first == b"#!" and mode != "100755":
            wrong.append(f"{path} is {mode}")
    assert not wrong, "run as programs but not executable in git: " + "; ".join(wrong)


def test_the_files_ci_and_the_deploy_scripts_call_by_path_are_executable():
    """Named explicitly: losing any of these breaks a job, whatever the shebang rule says."""
    modes = dict((p, m) for m, p in _tracked_with_modes())
    for rel in (
        "deploy/smoke-test.sh",
        "deploy/remote-deploy.sh",
        "deploy/check-dns.sh",
        "deploy/check-host-isolation.sh",
        "deploy/host-egress-guard.sh",
        "docker/egress-proxy.sh",
        "docker/egress-healthcheck.sh",
        "docker/egress-forbidden-check.sh",
    ):
        assert modes.get(rel) == "100755", f"{rel}: {modes.get(rel)}"
