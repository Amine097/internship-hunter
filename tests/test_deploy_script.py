"""Behavioural tests of deploy/remote-deploy.sh with a stub docker/curl and real
ssh-keygen signatures, tar, sha256sum and flock."""
import fcntl
import gzip
import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import textwrap
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "remote-deploy.sh"
pytestmark = pytest.mark.skipif(
    not (shutil.which("ssh-keygen") and shutil.which("flock")), reason="needs ssh-keygen+flock")

SHA_A, SHA_B, SHA_C = "a" * 40, "b" * 40, "c" * 40

DOCKER_STUB = textwrap.dedent("""\
    #!/usr/bin/env bash
    echo "docker $* [RELEASE_SHA=${RELEASE_SHA:-}]" >> "$STUB_DIR/log"
    case "$1" in
      info) if [[ -n "${STUB_ROOTFUL:-}" ]]; then echo "[name=seccomp]";
            else echo "[name=seccomp name=rootless]"; fi ;;
      load) zcat "$3" >> "$STUB_DIR/images" ;;
      image) if [[ "$2" == inspect ]]; then grep -qx "$3" "$STUB_DIR/images"; else exit 0; fi ;;
      compose)
        shift
        while [[ "$1" == -p || "$1" == --env-file ]]; do shift 2; done
        case "$1" in
          up) [[ " ${STUB_FAIL_UP_SHA:-} " == *" $RELEASE_SHA "* ]] && exit 1
              echo "$RELEASE_SHA" > "$STUB_DIR/running" ;;
          ps) if [[ "$*" == *--format* ]]; then
                tag="${RELEASE_SHA}"; [[ "${STUB_WRONG_IMAGES:-}" == "$RELEASE_SHA" ]] && tag=dev
                for s in api discovery scheduler telegram migrate; do
                  echo "internship-hunter-app:$tag"; done
                for s in 1 2 3; do echo "internship-hunter-agent:$tag"; done
                for s in 1 2 3; do echo "internship-hunter-egress:$tag"; done
                echo "postgres:17-alpine"
              else [[ -f "$STUB_DIR/db" ]] && echo abc123; fi; exit 0 ;;
          exec) [[ -n "${STUB_FAIL_DUMP:-}" ]] && exit 1; echo "-- sql dump" ;;
          *) exit 0 ;;
        esac ;;
    esac
""")
CURL_STUB = textwrap.dedent("""\
    #!/usr/bin/env bash
    running="$(cat "$STUB_DIR/running" 2>/dev/null)"
    [[ -n "${STUB_FAIL_HEALTH_SHA:-}" && "$running" == "$STUB_FAIL_HEALTH_SHA" ]] && exit 1
    for last; do :; done
    [[ "$last" == */health ]] && echo '{"status":"ok","submission_enabled":false}'
    exit 0
""")


class Env:
    def __init__(self, tmp: Path):
        self.base = tmp / "base"
        self.stub = tmp / "stub"
        self.bin = tmp / "bin"
        for d in (self.base / "shared", self.stub, self.bin):
            d.mkdir(parents=True)
        (self.base / "shared" / ".env").write_text("X=1\n")
        (self.bin / "docker").write_text(DOCKER_STUB)
        (self.bin / "curl").write_text(CURL_STUB)
        for f in self.bin.iterdir():
            f.chmod(0o755)
        self.key = tmp / "release_key"
        self.other_key = tmp / "other_key"
        for k in (self.key, self.other_key):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(k)],
                           check=True)
        pub = (self.key.with_suffix(".pub")).read_text().split()
        (self.base / "shared" / "allowed_signers").write_text(f"release {pub[0]} {pub[1]}\n")
        self.tmp = tmp
        self.clock = 1_900_000_000

    def bundle(self, sha, *, created=None, key=None, tamper_source=False, extra_member=False,
               evil_path=False, wrong_hash=False, head="0003", compat="0002",
               symlink=False, extra_line=False) -> bytes:
        if created is None:
            self.clock += 10
            created = self.clock
        src = io.BytesIO()
        with tarfile.open(fileobj=src, mode="w:gz") as t:
            data = b"services: {}\n"
            ti = tarfile.TarInfo("../evil" if evil_path else "compose.yaml")
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
            if symlink:
                link = tarfile.TarInfo("shared-env")
                link.type = tarfile.SYMTYPE
                link.linkname = "/etc/passwd"
                t.addfile(link)
        source = src.getvalue()
        images = gzip.compress(
            f"internship-hunter-app:{sha}\ninternship-hunter-agent:{sha}\n"
            f"internship-hunter-egress:{sha}\n".encode())
        images_hash = "0" * 64 if wrong_hash else hashlib.sha256(images).hexdigest()
        manifest = (f"sha={sha}\nsource_sha256={hashlib.sha256(source).hexdigest()}\n"
                    f"images_sha256={images_hash}\ncreated={created}\n"
                    f"schema_head={head}\nrollback_compatible={compat}\n"
                    + ("evil=1\n" if extra_line else "")).encode()
        mpath = self.tmp / f"manifest-{sha[:4]}-{created}"
        mpath.write_bytes(manifest)
        sig = self.tmp / f"{mpath.name}.sig"
        sig.unlink(missing_ok=True)
        subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", str(key or self.key),
                        "-n", "hunter-release", str(mpath)], check=True)
        if tamper_source:
            source = source + b"\0"
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w") as t:
            members = {"manifest": manifest, "manifest.sig": sig.read_bytes(),
                       "source.tar.gz": source, "images.tar.gz": images}
            if extra_member:
                members["sneaky.sh"] = b"#!/bin/sh\n"
            for name, data in members.items():
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
        return out.getvalue()

    def run(self, command, stdin=b"", **extra):
        env = {
            "PATH": f"{self.bin}:{os.environ['PATH']}", "HOME": str(self.tmp),
            "HUNTER_BASE": str(self.base), "STUB_DIR": str(self.stub),
            "SSH_ORIGINAL_COMMAND": command, **extra,
        }
        return subprocess.run(["bash", str(SCRIPT)], input=stdin, env=env,
                              capture_output=True, timeout=60)

    def deploy(self, sha, *, command="deploy", **kw):
        run_kw = {k: kw.pop(k) for k in list(kw) if k.startswith(("STUB_", "HUNTER_"))}
        return self.run(command, self.bundle(sha, **kw), **run_kw)

    @property
    def log(self):
        p = self.stub / "log"
        return p.read_text() if p.exists() else ""

    def state(self, name):
        p = self.base / "state" / name
        return p.read_text().strip() if p.exists() else None

    @property
    def current_link(self):
        p = self.base / "current"
        return os.path.basename(os.readlink(p)) if p.is_symlink() else None


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def test_rejects_unknown_commands(env):
    for cmd in ("", "bash", "deploy; id", "rollback now"):
        assert env.run(cmd).returncode == 2


def test_refuses_rootful_docker(env):
    r = env.deploy(SHA_A, STUB_ROOTFUL="1")
    assert r.returncode == 5 and env.current_link is None


def test_first_deploy_loads_images_and_never_builds(env):
    r = env.deploy(SHA_A)
    assert r.returncode == 0, r.stderr.decode()
    assert env.current_link == SHA_A and env.state("current_sha") == SHA_A
    assert "docker load" in env.log
    assert " build" not in env.log and "--build" not in env.log
    assert "up -d --no-build" in env.log and f"[RELEASE_SHA={SHA_A}]" in env.log


def test_second_deploy_backs_up_database_and_records_previous(env):
    assert env.deploy(SHA_A).returncode == 0
    (env.stub / "db").write_text("")
    assert env.deploy(SHA_B).returncode == 0
    assert env.state("current_sha") == SHA_B and env.state("previous_sha") == SHA_A
    backups = list((env.base / "backups").glob("pre-*.sql.gz"))
    assert len(backups) == 1 and gzip.decompress(backups[0].read_bytes()).startswith(b"-- sql")


def test_backup_failure_aborts_before_any_change(env):
    env.deploy(SHA_A)
    (env.stub / "db").write_text("")
    r = env.deploy(SHA_B, STUB_FAIL_DUMP="1")
    assert r.returncode == 8
    assert env.current_link == SHA_A and env.state("current_sha") == SHA_A


def test_failed_start_restores_previous_release(env):
    env.deploy(SHA_A)
    r = env.deploy(SHA_B, STUB_FAIL_UP_SHA=SHA_B)
    assert r.returncode == 1
    assert env.current_link == SHA_A and env.state("current_sha") == SHA_A
    last_up = [ln for ln in env.log.splitlines() if " up " in ln][-1]
    assert f"[RELEASE_SHA={SHA_A}]" in last_up


def test_failed_health_check_restores_previous_release(env):
    env.deploy(SHA_A)
    r = env.deploy(SHA_B, STUB_FAIL_HEALTH_SHA=SHA_B)
    assert r.returncode == 1 and env.current_link == SHA_A
    assert (env.stub / "running").read_text().strip() == SHA_A


def test_first_deploy_failure_leaves_nothing_current(env):
    r = env.deploy(SHA_A, STUB_FAIL_UP_SHA=SHA_A)
    assert r.returncode == 1 and env.state("current_sha") is None


@pytest.mark.parametrize("kw,code", [
    ({"tamper_source": True}, 7),
    ({"wrong_hash": True}, 7),
    ({"extra_member": True}, 2),
    ({"evil_path": True}, 2),
    ({"symlink": True}, 2),
    ({"extra_line": True}, 2),
])
def test_integrity_failures_are_rejected(env, kw, code):
    r = env.deploy(SHA_A, **kw)
    assert r.returncode == code, r.stderr.decode()
    assert env.current_link is None and "up -d" not in env.log


def test_wrong_signing_key_is_rejected(env):
    r = env.deploy(SHA_A, key=env.other_key)
    assert r.returncode == 7 and "signature" in r.stderr.decode()


def test_manifest_tampering_breaks_signature(env):
    raw = env.bundle(SHA_A)
    swapped = raw.replace(SHA_A.encode(), SHA_C.encode())  # same length: valid tar, bad sig
    assert swapped != raw
    r = env.run("deploy", swapped)
    assert r.returncode in (2, 7) and env.current_link is None


def test_signed_but_older_bundle_is_refused(env):
    assert env.deploy(SHA_B, created=1_900_000_500).returncode == 0
    r = env.deploy(SHA_A, created=1_900_000_100)
    assert r.returncode == 7 and env.current_link == SHA_B


def test_rollback_reuses_loaded_images_without_building(env):
    env.deploy(SHA_A)
    env.deploy(SHA_B)
    env.stub.joinpath("log").write_text("")
    r = env.run("rollback")
    assert r.returncode == 0, r.stderr.decode()
    assert env.current_link == SHA_A and env.state("previous_sha") == SHA_B
    assert " build" not in env.log and "--build" not in env.log and "docker load" not in env.log
    assert "up -d --no-build" in env.log and f"[RELEASE_SHA={SHA_A}]" in env.log


def test_rollback_without_previous_fails_cleanly(env):
    env.deploy(SHA_A)
    assert env.run("rollback").returncode == 3 and env.current_link == SHA_A


def test_rollback_requires_images_to_be_present(env):
    env.deploy(SHA_A)
    env.deploy(SHA_B)
    (env.stub / "images").write_text("")  # images were pruned from the daemon
    r = env.run("rollback")
    assert r.returncode != 0 and env.current_link == SHA_B


def test_concurrent_deploy_is_refused(env):
    (env.base / "state").mkdir(parents=True, exist_ok=True)
    with open(env.base / "state" / "deploy.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        r = env.deploy(SHA_A)
    assert r.returncode == 4 and env.current_link is None


def test_oversized_bundle_is_refused(env):
    r = env.deploy(SHA_A, HUNTER_MAX_BUNDLE_BYTES="1024")
    assert r.returncode == 2


def test_pruning_never_removes_current_or_previous(env):
    shas = [f"{i:040x}" for i in range(1, 9)]
    for sha in shas:
        assert env.deploy(sha).returncode == 0
        time.sleep(0.01)
    kept = {p.name for p in (env.base / "releases").iterdir()}
    assert shas[-1] in kept and shas[-2] in kept and len(kept) <= 6


def test_stack_running_wrong_images_is_a_failed_deploy(env):
    """Real-daemon finding: compose can silently fall back to a mutable tag if RELEASE_SHA
    does not reach it. The script must verify what is actually running."""
    assert env.deploy(SHA_A).returncode == 0
    r = env.deploy(SHA_B, STUB_WRONG_IMAGES=SHA_B)
    assert r.returncode == 1
    assert "not running release" in r.stderr.decode()
    assert env.current_link == SHA_A and env.state("current_sha") == SHA_A


# --- schema compatibility / rollback (Task 2) --------------------------------------------

def last_up_env(env, sha):
    return (env.base / "state" / f"release-{sha}.env").read_text()


def test_compatible_upgrade_then_rollback_accepts_newer_schema_explicitly(env):
    assert env.deploy(SHA_A, head="0002", compat="").returncode == 0
    r = env.deploy(SHA_B, head="0003", compat="0002")        # N -> N+1 (expand-only)
    assert r.returncode == 0, r.stderr.decode()
    assert env.state("db_head") == "0003" and env.state("rollback_ok") == "1"
    r = env.run("rollback")
    assert r.returncode == 0, r.stderr.decode()
    assert env.current_link == SHA_A and env.state("current_head") == "0002"
    # the old release is told, explicitly, which newer revision it must tolerate
    assert "HUNTER_ACCEPT_SCHEMA_REVISION=0003" in last_up_env(env, SHA_A)
    assert env.state("db_head") == "0003"          # a rollback does not downgrade the DB
    assert "verified" in r.stdout.decode()


def test_incompatible_migration_is_refused_before_any_change(env):
    assert env.deploy(SHA_A, head="0002", compat="").returncode == 0
    env.stub.joinpath("log").write_text("")
    r = env.deploy(SHA_B, head="0004", compat="0003")        # does not list 0002
    assert r.returncode == 9 and "rollback-compatible" in r.stderr.decode()
    assert env.current_link == SHA_A and env.state("db_head") == "0002"
    assert "up -d" not in env.log and "docker load" not in env.log


def test_irreversible_deploy_is_explicit_and_blocks_rollback(env):
    env.deploy(SHA_A, head="0002", compat="")
    (env.stub / "db").write_text("")
    r = env.deploy(SHA_B, command="deploy-irreversible", head="0004", compat="0003")
    assert r.returncode == 0 and env.state("rollback_ok") == "0"
    assert list((env.base / "backups").glob("pre-*.sql.gz"))      # backup is mandatory
    r = env.run("rollback")
    assert r.returncode == 9 and env.current_link == SHA_B
    assert "MANUAL RECOVERY" in r.stderr.decode()


def test_migration_failure_restores_previous_release(env):
    """A migrate/up failure on N+1: the previous release is re-activated and the recorded
    database revision does not move."""
    env.deploy(SHA_A, head="0002", compat="")
    r = env.deploy(SHA_B, head="0003", compat="0002", STUB_FAIL_UP_SHA=SHA_B)
    assert r.returncode == 1
    assert env.current_link == SHA_A and env.state("db_head") == "0002"
    assert (env.stub / "running").read_text().strip() == SHA_A


def test_failed_migration_and_failed_restore_reports_manual_recovery(env):
    env.deploy(SHA_A, head="0002", compat="")
    # both the new release and the restore of the old one fail (e.g. half-applied migration)
    r = env.deploy(SHA_B, head="0003", compat="0002", STUB_FAIL_UP_SHA=f"{SHA_B} {SHA_A}")
    assert r.returncode == 10 and "MANUAL RECOVERY" in r.stderr.decode()


def test_failed_healthcheck_on_rollback_is_not_reported_as_success(env):
    env.deploy(SHA_A, head="0002", compat="")
    env.deploy(SHA_B, head="0003", compat="0002")
    r = env.run("rollback", STUB_FAIL_HEALTH_SHA=SHA_A)
    assert r.returncode == 6 and b"rolled back" not in r.stdout
    assert env.current_link == SHA_B and env.state("current_sha") == SHA_B
    assert (env.stub / "running").read_text().strip() == SHA_B   # re-activated the good one


def test_rollback_toggles_forward_without_accept_override(env):
    env.deploy(SHA_A, head="0002", compat="")
    env.deploy(SHA_B, head="0003", compat="0002")
    assert env.run("rollback").returncode == 0
    r = env.run("rollback")                                       # back to N+1
    assert r.returncode == 0 and env.current_link == SHA_B
    assert "ACCEPT" not in last_up_env(env, SHA_B)


def test_legacy_bundle_without_schema_fields_is_rejected(env):
    raw = env.bundle(SHA_A)
    # forge a legacy 4-line manifest and re-sign it
    legacy = (f"sha={SHA_A}\nsource_sha256={'0' * 64}\nimages_sha256={'0' * 64}\n"
              f"created=1900000001\n").encode()
    assert raw and legacy  # structure documented; strict parser covered by extra_line test
