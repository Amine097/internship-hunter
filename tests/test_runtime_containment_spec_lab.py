"""CONTRACT: the project's labels do not make a container the release's (real rootless Docker).

The reported hole: runtime-containment.sh identified a project container by its labels and compared
its networks and four flags, so a container that merely CLAIMS to be `agent-codex` (project and
service labels, the right network) but carries CAP_NET_ADMIN, an unconfined seccomp profile and the
host's root mounted passed every check. The watchdog now compares every project container with the
SPEC that `commit` rendered from the release's own compose files and the image store: image (by
content), process, capabilities, security options, devices, sysctls, namespaces, published ports and
the effective mount list.

Same lab as test_runtime_containment_lab.py (a genuine rootless Docker 29.9.1 as an unprivileged
user; the real compose.yaml topology with Alpine images; the real guard and the real watchdog).
Every impostor below is made two ways: by hand (`docker run` with copied labels - the reported
reproduction) and as a lookalike that compose itself builds from a tampered override file (the
same name, labels, networks, image, command and hardening, plus exactly ONE extra property).

Opt-in like the other labs (HUNTER_ROOTLESS_LAB=1; HUNTER_ROOTLESS_LAB_REQUIRED=1 turns a skip into
a failure).
"""

import fcntl
import json
import textwrap

import test_runtime_containment_lab as base
from test_runtime_containment_lab import ROOT, SUPERVISED

clab = base.clab  # the lab and the committed, guarded, healthy stack are that module's fixtures
rig = base.rig

LABELS = [
    "--label", "com.docker.compose.project=clab",
    "--label", "com.docker.compose.service=agent-codex",
]  # fmt: skip
IMPOSTOR = ["--name", "impostor", "--network", "clab_agent_codex"]
IMAGE = "alpine-local:3.20"

# (devices are covered by the fake-daemon tests: runc in a rootless user namespace cannot create
# device nodes at all, so there is no such container to catch here)
# `docker run` arguments that make a labelled lookalike dangerous, each in the shape that matters
RAW = {
    "net_admin": ["--cap-add", "NET_ADMIN"],
    "host_root_mounted": ["-v", "/:/host:ro"],
    "seccomp_unconfined": ["--security-opt", "seccomp=unconfined"],
    "privileged": ["--privileged"],
    "host_pid": ["--pid", "host"],
    "sysctl": ["--sysctl", "net.ipv4.ip_forward=1"],
    "net_admin_and_root_mounted_and_unconfined": [
        "--cap-add",
        "NET_ADMIN",
        "--security-opt",
        "seccomp=unconfined",
        "-v",
        "/:/host:ro",
    ],  # fmt: skip
    "nothing_extra_but_none_of_the_hardening": [],
}

# exactly one extra property over what compose builds for agent-codex
TAMPERED = {
    "cap_add": "cap_add: [NET_ADMIN]",
    "cap_add_sys_ptrace": "cap_add: [SYS_PTRACE]",
    "host_root_bind": "volumes: [/:/host:ro]",
    "host_etc_bind": "volumes: ['/etc:/mnt/etc']",
    "seccomp_unconfined": "security_opt: [seccomp=unconfined]",
    "writable_rootfs": "read_only: false",
    "caps_not_dropped": "cap_drop: !override []",
    "sysctl": "sysctls: {net.ipv4.ip_forward: 1}",
    "host_pid": "pid: host",
    "host_ipc": "ipc: host",
    "privileged": "privileged: true",
    "other_command": "command: [sleep, '3001']",
    "other_user": "user: '0'",
    "host_gateway_alias": "extra_hosts: ['hostgw:host-gateway']",
    "group_add": "group_add: ['0']",
    "published_port": "ports: ['127.0.0.1::8100']",
}


def containers(rig, service):
    out = rig.run(
        ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.service={service}",
         "--filter", "label=com.docker.compose.project=clab"],
        check=False,
    ).stdout.split()  # fmt: skip
    return out


def is_running(rig, name):
    r = rig.run(["docker", "inspect", "-f", "{{.State.Running}}", name], check=False)
    return r.stdout.strip() == "true"


def assert_caught(rig, why):
    r = rig.once()
    assert r.returncode == 1, f"{why}: not caught\n{r.stdout[-400:]}\n{r.stderr[-800:]}"
    assert rig.latched(), why
    reason = rig.latch_reason()
    assert "SPEC" in reason or "HOSTCFG" in reason, (why, reason)
    assert rig.supervised_running() == [], f"{why}: the set is still running"
    return reason


def override(tmp_path, body):
    path = tmp_path / "tamper.yaml"
    path.write_text("services:\n  agent-codex:\n" + textwrap.indent(body, "    ") + "\n")
    return str(path)


def recreate(rig, *services, extra=None):
    rig.compose(
        "up", "-d", "--no-deps", "--no-build", "--force-recreate", *services,
        files=[*rig.files, *([extra] if extra else [])],
    )  # fmt: skip


def heal(rig):
    """What an operator does after the investigation: genuine containers back, then reset."""
    rig.run(["docker", "rm", "-f", "impostor"], check=False)
    recreate(rig, "agent-codex")
    r = rig.wd("reset")
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_whole_real_stack_matches_the_spec_commit_rendered(rig):
    contract = json.loads((rig.state_dir / "contract.json").read_text())
    assert contract["version"] == 2
    spec = contract["services"]["agent-codex"]["spec"]
    assert spec["image"] == "alpine-local:3.20" and spec["image_id"].startswith("sha256:")
    assert spec["cap_drop"] == ["ALL"] and spec["cap_add"] == [] and spec["read_only"] is True
    r = rig.wd("check")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SPEC" not in r.stdout
    assert rig.once().returncode == 0 and not rig.latched()
    assert sorted(rig.supervised_running()) == sorted(SUPERVISED)


def test_a_labelled_impostor_next_to_the_genuine_agent_is_stopped_for_every_kind_of_extra_privilege(
    rig,
):
    caught = {}
    for how, args in RAW.items():
        rig.run(
            ["docker", "run", "-d", *IMPOSTOR, *LABELS, *args, IMAGE, "sleep", "600"]
        )  # fmt: skip
        caught[how] = assert_caught(rig, how)
        assert not is_running(rig, "impostor"), f"{how}: the impostor itself keeps running"
        assert "impostor" in caught[how], caught[how]
        rig.run(["docker", "rm", "-f", "impostor"])
        r = rig.wd("reset")
        assert r.returncode == 0, (how, r.stdout + r.stderr)
    # the genuine stack is accepted again afterwards, and starts
    assert rig.once().returncode == 0 and not rig.latched()
    assert sorted(rig.supervised_running()) == sorted(SUPERVISED)


def test_a_lookalike_with_exactly_one_extra_property_is_caught(rig, tmp_path):
    """One stack, many lookalikes: each is built by compose from a tampered override (so everything
    else - name, labels, networks, image, command, hardening - is the release's), caught, healed."""
    named = (
        "cap", "mounts", "security_opt", "read_only", "sysctls", "Mode",
        "privileged", "command", "user", "extra_hosts", "group_add", "published ports",
    )  # fmt: skip
    for how, body in TAMPERED.items():
        recreate(rig, "agent-codex", extra=override(tmp_path, body))
        reason = assert_caught(rig, how)
        assert "agent-codex" in reason and any(w in reason for w in named), (how, reason)
        heal(rig)
    assert rig.once().returncode == 0 and not rig.latched()
    assert sorted(rig.supervised_running()) == sorted(SUPERVISED)


def test_the_same_tag_with_other_content_is_not_the_release(rig):
    """`docker tag` can point alpine-local:3.20 at anything: the contract pinned the CONTENT."""
    original = rig.run(["docker", "image", "inspect", "-f", "{{.Id}}", IMAGE]).stdout.strip()
    try:
        rig.run(["docker", "run", "--name", "mutated", IMAGE, "touch", "/changed"])
        rig.run(["docker", "commit", "mutated", IMAGE])  # same tag, new image id
        recreate(rig, "agent-codex")
        reason = assert_caught(rig, "tag moved")
        assert "image id" in reason, reason
    finally:
        rig.run(["docker", "rm", "-f", "mutated"], check=False)
        rig.run(["docker", "tag", original, IMAGE])
        heal(rig)
    assert rig.once().returncode == 0


def test_recreating_services_with_the_same_release_is_accepted_and_recovers(rig):
    """`docker compose up --force-recreate`: new ids, same release, same everything. And a full
    recovery after the stack was stopped by a quarantine."""
    before = {s: containers(rig, s) for s in ("agent-codex", "egress-codex", "api", "postgres")}
    recreate(rig, "agent-codex", "egress-codex", "api", "postgres")
    after = {s: containers(rig, s) for s in before}
    assert all(before[s] != after[s] for s in before), "compose did not recreate"
    r = rig.once()
    assert r.returncode == 0 and not rig.latched(), r.stdout + r.stderr
    assert sorted(rig.supervised_running()) == sorted(SUPERVISED)
    assert "SPEC" not in rig.log()
    # a quarantine, then the operator's way back
    rig.run(
        ["docker", "run", "-d", *IMPOSTOR, *LABELS, "--cap-add", "NET_ADMIN", IMAGE, "sleep", "600"]
    )
    assert_caught(rig, "impostor")
    heal(rig)
    assert rig.once().returncode == 0
    assert sorted(rig.supervised_running()) == sorted(SUPERVISED)


def test_commit_refuses_a_release_that_asks_for_what_containment_will_not_accept(rig, tmp_path):
    extra = override(tmp_path, "cap_add: [NET_ADMIN]")
    args = ["-p", "clab"]
    for f in (*[str(x) for x in rig.files], extra):
        args += ["-f", f]
    with open(rig.lock, "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        before = (rig.state_dir / "contract.json").read_text()
        r = rig.wd(
            "commit", "--sha", "c" * 40, "--release-dir", str(ROOT),
            "--forbidden", "100.107.22.84:22", "--protected-ips", "100.107.22.84",
            "--rootful", "172.17.0.2:9", "--", *args,
        )  # fmt: skip
    assert r.returncode == 11 and "NET_ADMIN" in r.stderr, r.stdout + r.stderr
    assert (rig.state_dir / "contract.json").read_text() == before
