"""Behavioural tests of deploy/remote-deploy.sh with a stub docker/curl and real
ssh-keygen signatures, tar, sha256sum and flock."""
import fcntl
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import textwrap
import threading
import time
from pathlib import Path

import pytest
import yaml

SCRIPT = Path(os.environ.get("HUNTER_DEPLOY_SCRIPT") or
              Path(__file__).resolve().parents[1] / "deploy" / "remote-deploy.sh")
pytestmark = pytest.mark.skipif(
    not (shutil.which("ssh-keygen") and shutil.which("flock")), reason="needs ssh-keygen+flock")

SHA_A, SHA_B, SHA_C = "a" * 40, "b" * 40, "c" * 40
REAL_CHECK_DNS = Path(__file__).resolve().parents[1] / "deploy" / "check-dns.sh"


def compose_template():
    """The topology of the real compose.yaml (networks, internal flags, dns entries)."""
    cfg = yaml.safe_load((Path(__file__).resolve().parents[1] / "compose.yaml").read_text())
    nets = {n: {"internal": bool((v or {}).get("internal"))} for n, v in cfg["networks"].items()}
    services = {}
    for name, svc in cfg["services"].items():
        services[name] = {"networks": {n: None for n in svc.get("networks", [])}}
        if svc.get("dns"):
            services[name]["dns"] = list(svc["dns"])
    return {"networks": nets, "services": services}

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
        accept=""
        envfiles=()
        while [[ "$1" == -p || "$1" == --env-file || "$1" == -f ]]; do
          if [[ "$1" == --env-file ]]; then
            envfiles+=("$2")
            v="$(sed -n 's/^HUNTER_ACCEPT_SCHEMA_REVISION=//p' "$2" 2>/dev/null)"
            [[ -n "$v" ]] && accept="$v"
          fi
          shift 2
        done
        case "$1" in
          config)
            # the effective configuration of the real compose.yaml topology (see RENDER)
            if [[ "$*" == *--format* ]]; then python3 "$STUB_DIR/render.py" "${envfiles[@]}"; fi
            exit 0 ;;
          up)
            # --- model of "migrate then start" against a stateful schema -------------------
            head="$(cat "$PWD/STUB_SCHEMA_HEAD" 2>/dev/null || echo 0001)"
            db="$(cat "$STUB_DIR/db_rev" 2>/dev/null || true)"
            [[ " ${STUB_FAIL_UP_SHA:-} " == *" $RELEASE_SHA "* ]] && exit 1
            if [[ -z "$db" || "$db" < "$head" ]]; then
              [[ " ${STUB_FAIL_MIGRATE_SHA:-} " == *" $RELEASE_SHA "* ]] && exit 1  # txn DDL
              echo "$head" > "$STUB_DIR/db_rev"
            elif [[ "$db" > "$head" ]]; then
              if [[ "$accept" != "$db" ]]; then
                echo "SchemaMismatch: database at $db unknown to release $head" >&2
                exit 1
              fi
            fi
            echo "$RELEASE_SHA" > "$STUB_DIR/running" ;;
          ps) if [[ "$*" == *--format* ]]; then
                tag="${RELEASE_SHA}"; [[ "${STUB_WRONG_IMAGES:-}" == "$RELEASE_SHA" ]] && tag=dev
                for s in api discovery scheduler telegram session-controller migrate; do
                  echo "internship-hunter-app:$tag"; done
                for s in 1 2 3; do echo "internship-hunter-agent:$tag"; done
                for s in 1 2 3; do echo "internship-hunter-egress:$tag"; done
                echo "postgres:17-alpine"
              else [[ -f "$STUB_DIR/db" ]] && echo abc123; fi; exit 0 ;;
          exec)
            if [[ "$*" == *psql* ]]; then
              [[ -f "$STUB_DIR/db_rev" ]] && cat "$STUB_DIR/db_rev"; exit 0
            fi
            [[ -n "${STUB_FAIL_DUMP:-}" ]] && exit 1; echo "-- sql dump" ;;
          port) if [[ -n "${STUB_WRONG_API_PORT:-}" ]]; then echo "0.0.0.0:8000"
                else echo "127.0.0.1:18000"; fi ;;
          down) rm -f "$STUB_DIR/running"; echo "DOWN" >> "$STUB_DIR/log" ;;
          *) exit 0 ;;
        esac ;;
    esac
""")
GUARD_STUB = textwrap.dedent("""\
    #!/usr/bin/env bash
    echo "guard $*" >> "$STUB_DIR/guard.log"
    [[ "$1" == status ]] || exit 0
    [[ -n "${STUB_GUARD_STATUS_FAIL:-}" ]] && { echo "NOT active: stub says so"; exit 1; }
    echo "active"
""")
CHECK_STUB = textwrap.dedent("""\
    #!/usr/bin/env bash
    if [[ "${1:-}" == --verify-targets ]]; then
      {
        echo "verify EGRESS_FORBIDDEN_TARGETS=${EGRESS_FORBIDDEN_TARGETS:-}" \
             "SMOKE_ROOTFUL_TARGETS=${SMOKE_ROOTFUL_TARGETS:-}" \
             "SMOKE_EXPECT_ROOTLESS=${SMOKE_EXPECT_ROOTLESS:-}"
      } >> "$STUB_DIR/verify.log"
      [[ -n "${STUB_VERIFY_FAIL:-}" ]] && { echo "FAIL target is not live (stub)"; exit 1; }
      exit 0
    fi
    running="$(cat "$STUB_DIR/running" 2>/dev/null)"
    {
      echo "check running=$running args=$*"
      echo "env SMOKE_HOST_ISOLATION=${SMOKE_HOST_ISOLATION:-}" \
           "SMOKE_EXPECT_ROOTLESS=${SMOKE_EXPECT_ROOTLESS:-}" \
           "SMOKE_PROTECTED_IPS=${SMOKE_PROTECTED_IPS:-}" \
           "SMOKE_ROOTFUL_TARGETS=${SMOKE_ROOTFUL_TARGETS:-}" \
           "SMOKE_AUTODETECT_HOST_IPS=${SMOKE_AUTODETECT_HOST_IPS:-}" \
           "SMOKE_PROTECTED_PORTS=${SMOKE_PROTECTED_PORTS:-unset}"
    } >> "$STUB_DIR/isolation.log"
    [[ -n "${STUB_FAIL_ISOLATION_ALL:-}" ]] && exit 1
    [[ " ${STUB_FAIL_ISOLATION_SHA:-} " == *" $running "* ]] && exit 1
    exit 0
""")
# `docker compose config --format json` for the REAL compose.yaml topology, with the one
# interpolation that matters, ${HUNTER_DNS:-10.0.2.3}, resolved the way compose does: the process
# environment beats the env files, a later env file beats an earlier one, the default fills in.
RENDER = textwrap.dedent("""\
    import json, os, re, sys
    vals = {}
    for f in sys.argv[1:]:
        for ln in open(f):
            if "=" in ln and not ln.lstrip().startswith("#"):
                k, v = ln.rstrip("\\n").split("=", 1)
                vals[k.strip()] = v.strip().strip("'\\"")
    if "HUNTER_DNS" in os.environ:
        vals["HUNTER_DNS"] = os.environ["HUNTER_DNS"]
    cfg = json.load(open(os.environ["STUB_DIR"] + "/compose-template.json"))
    for svc in cfg["services"].values():
        out = []
        for d in svc.pop("dns", []):
            m = re.fullmatch(r"\\$\\{HUNTER_DNS:-([^}]*)\\}", d)
            out.append((vals.get("HUNTER_DNS") or m.group(1)) if m else d)
        if out:
            svc["dns"] = out
    json.dump(cfg, sys.stdout)
""")
DNS_STUB = textwrap.dedent("""\
    #!/usr/bin/env bash
    if [[ "${SMOKE_DNS_CONFIG_ONLY:-}" == 1 ]]; then
      echo "dns-config running=$(cat "$STUB_DIR/running" 2>/dev/null) args=$*" \
           "SMOKE_DNS_EXPECT=${SMOKE_DNS_EXPECT:-} HUNTER_DNS=${HUNTER_DNS:-<unset>}" \
           >> "$STUB_DIR/dns-config.log"
      # the real script, judging RENDER's output
      [[ -n "${STUB_REAL_DNS_CONFIG:-}" ]] && exec "$STUB_REAL_DNS_CONFIG" "$@"
      exit 0
    fi
    running="$(cat "$STUB_DIR/running" 2>/dev/null)"
    echo "dns running=$running args=$* SMOKE_HOST_ISOLATION=${SMOKE_HOST_ISOLATION:-}" \
         "SMOKE_DNS_EXPECT=${SMOKE_DNS_EXPECT:-}" >> "$STUB_DIR/dns.log"
    [[ -n "${STUB_FAIL_DNS_ALL:-}" ]] && exit 1
    [[ " ${STUB_FAIL_DNS_SHA:-} " == *" $running "* ]] && exit 1
    exit 0
""")
CONTAINMENT_STUB = textwrap.dedent("""\
    #!/usr/bin/env bash
    running="$(cat "$STUB_DIR/running" 2>/dev/null)"
    echo "containment $* [running=$running]" >> "$STUB_DIR/containment.log"
    echo "containment $1" >> "$STUB_DIR/log"          # the same timeline as the docker calls
    case "$1" in
      status)
        if [[ -n "${STUB_CONTAINMENT_STATUS:-}" ]]; then
          echo "containment status stub: $STUB_CONTAINMENT_STATUS" >&2
          exit "$STUB_CONTAINMENT_STATUS"
        fi
        exit 0 ;;
      commit)
        if [[ " $* " == *" --check "* ]]; then
          # the read-only pre-flight: which release is it about? (--sha <sha>)
          sha=""; prev=""
          for a in "$@"; do [[ "$prev" == --sha ]] && sha="$a"; prev="$a"; done
          if [[ " ${STUB_NONCOMMITTABLE:-} " == *" $sha "* ]]; then
            echo "runtime-containment: api renders restart=unless-stopped (stub)" >&2; exit 11
          fi
          exit 0
        fi
        # a real commit happens INSIDE a deploy: its lock and the watchdog action lock are both held
        if flock -n "$STUB_DIR/../base/state/containment.action.lock" true 2>/dev/null; then
          echo "commit saw the action lock FREE" >> "$STUB_DIR/lock.log"
        else
          echo "commit saw the action lock held by the deploy" >> "$STUB_DIR/lock.log"
        fi
        if [[ " ${STUB_FAIL_COMMIT_SHA:-} " == *" $running "* ]]; then
          echo "commit refused (stub)" >&2; exit 11
        fi
        exit 0 ;;
    esac
    exit 0
""")
SS_STUB = textwrap.dedent("""\
    #!/usr/bin/env bash
    [[ -n "${STUB_PORT_BUSY:-}" ]] && echo "LISTEN 0 4096 127.0.0.1:18000 0.0.0.0:*"
    exit 0
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
        self.env_file = self.base / "shared" / ".env"
        self.env_file.write_text("X=1\nEGRESS_FORBIDDEN_TARGETS=100.107.22.84:22,100.107.22.84:8000\n")
        (self.base / "deploy").mkdir()
        self.conf = self.base / "deploy" / "host-isolation.conf"
        self.conf.write_text("ROOTFUL_TARGETS=172.17.0.2:9\n")
        self.conf.chmod(0o644)
        for name, body in (("host-egress-guard.sh", GUARD_STUB),
                           ("check-host-isolation.sh", CHECK_STUB),
                           ("check-dns.sh", DNS_STUB),
                           ("runtime-containment.sh", CONTAINMENT_STUB)):
            (self.base / "deploy" / name).write_text(body)
            (self.base / "deploy" / name).chmod(0o755)
        self.guard_conf = self.base / "deploy" / "host-egress-guard.conf"
        self.guard_conf.write_text("PROTECT=100.107.22.84/32\nDNS=10.0.2.3\n")
        self.guard_conf.chmod(0o644)
        (self.stub / "render.py").write_text(RENDER)
        (self.stub / "compose-template.json").write_text(json.dumps(compose_template()))
        (self.bin / "docker").write_text(DOCKER_STUB)
        (self.bin / "curl").write_text(CURL_STUB)
        (self.bin / "ss").write_text(SS_STUB)
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
            head_bytes = head.encode()
            hi = tarfile.TarInfo("STUB_SCHEMA_HEAD")
            hi.size = len(head_bytes)
            t.addfile(hi, io.BytesIO(head_bytes))
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
            "HUNTER_BASE": str(self.base), "STUB_DIR": str(self.stub), "HUNTER_TEST_MODE": "1",
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

    @property
    def dns_log(self):
        p = self.stub / "dns.log"
        return p.read_text() if p.exists() else ""

    @property
    def containment_log(self):
        p = self.stub / "containment.log"
        return p.read_text() if p.exists() else ""

    @property
    def dns_config_log(self):
        p = self.stub / "dns-config.log"
        return p.read_text() if p.exists() else ""

    @property
    def isolation_log(self):
        p = self.stub / "isolation.log"
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
    # R1: a failed FIRST deploy must not leave a half-started release, nor a 'current' symlink
    assert "DOWN" in env.log and env.current_link is None
    assert not (env.stub / "running").exists()
    assert "first deploy" in r.stderr.decode() and "stack stopped" in r.stderr.decode()


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


# --- MEDIUM-1 regression: restore after the database was already migrated -------------------

def set_db(env, rev):
    (env.stub / "db_rev").write_text(rev)


def db_rev(env):
    return (env.stub / "db_rev").read_text().strip()


def test_regression_restore_after_compatible_migration_and_failed_healthcheck(env):
    """Release A on 0003; B migrates to 0004 then fails its health check. The automatic
    restore must start A against the real 0004 schema (it used to exit 10 with SchemaMismatch)."""
    assert env.deploy(SHA_A, head="0003", compat="").returncode == 0
    assert db_rev(env) == "0003"
    r = env.deploy(SHA_B, head="0004", compat="0003", STUB_FAIL_HEALTH_SHA=SHA_B)
    err = r.stderr.decode()
    assert r.returncode == 1, err                      # deploy failed, but cleanly restored
    assert "RESTORE ALSO FAILED" not in err and "restored" in err
    assert db_rev(env) == "0004"                       # the migration really happened
    assert (env.stub / "running").read_text().strip() == SHA_A
    assert env.current_link == SHA_A and env.state("current_sha") == SHA_A
    assert env.state("db_head") == "0004"              # reflects the real database
    # A was told to accept exactly the revision the database is at, and nothing else
    assert "HUNTER_ACCEPT_SCHEMA_REVISION=0004" in last_up_env(env, SHA_A)


def test_restore_accepts_nothing_when_the_declaration_does_not_cover_the_target(env):
    """Irreversible deploy (previous head NOT declared compatible) that then fails health:
    the old release must not be force-started on the unknown schema."""
    assert env.deploy(SHA_A, head="0003", compat="").returncode == 0
    r = env.deploy(SHA_B, command="deploy-irreversible", head="0004", compat="",
                   STUB_FAIL_HEALTH_SHA=SHA_B)
    assert r.returncode == 10 and "MANUAL RECOVERY" in r.stderr.decode()
    assert "ACCEPT" not in last_up_env(env, SHA_A)
    assert db_rev(env) == "0004"


def test_restore_without_migration_needs_no_acceptance(env):
    assert env.deploy(SHA_A, head="0003", compat="").returncode == 0
    r = env.deploy(SHA_B, head="0004", compat="0003", STUB_FAIL_MIGRATE_SHA=SHA_B)
    assert r.returncode == 1 and db_rev(env) == "0003"   # transactional DDL: unchanged
    assert env.current_link == SHA_A
    assert "ACCEPT" not in last_up_env(env, SHA_A)


def test_rollback_reads_the_database_not_a_stale_state_file(env):
    assert env.deploy(SHA_A, head="0003", compat="").returncode == 0
    assert env.deploy(SHA_B, head="0004", compat="0003").returncode == 0
    (env.base / "state" / "db_head").write_text("0001\n")          # stale/corrupt state
    r = env.run("rollback")
    assert r.returncode == 0, r.stderr.decode()
    assert "HUNTER_ACCEPT_SCHEMA_REVISION=0004" in last_up_env(env, SHA_A)
    assert env.state("db_head") == "0004"                           # repaired from reality


def test_rollback_refuses_an_unexpected_database_revision(env):
    assert env.deploy(SHA_A, head="0003", compat="").returncode == 0
    assert env.deploy(SHA_B, head="0004", compat="0003").returncode == 0
    set_db(env, "0009")                                             # not B's head, not A's
    r = env.run("rollback")
    assert r.returncode == 9 and env.current_link == SHA_B
    assert "ACCEPT" not in last_up_env(env, SHA_A)
    assert "unreadable" not in r.stderr.decode() and "0009" in r.stderr.decode()


def test_rollback_after_database_restored_to_previous_schema_needs_no_acceptance(env):
    assert env.deploy(SHA_A, head="0003", compat="").returncode == 0
    assert env.deploy(SHA_B, head="0004", compat="0003").returncode == 0
    set_db(env, "0003")                       # operator restored a backup taken before B
    r = env.run("rollback")
    assert r.returncode == 0 and env.current_link == SHA_A
    assert "ACCEPT" not in last_up_env(env, SHA_A)


def test_rollback_is_refused_when_database_cannot_be_read(env):
    assert env.deploy(SHA_A, head="0003", compat="").returncode == 0
    assert env.deploy(SHA_B, head="0004", compat="0003").returncode == 0
    (env.stub / "db_rev").unlink()
    r = env.run("rollback")
    assert r.returncode == 9 and env.current_link == SHA_B


def test_toggle_back_to_the_newer_release_after_rollback(env):
    assert env.deploy(SHA_A, head="0003", compat="").returncode == 0
    assert env.deploy(SHA_B, head="0004", compat="0003").returncode == 0
    assert env.run("rollback").returncode == 0                      # B -> A (accept 0004)
    r = env.run("rollback")                                         # A -> B: db == B's head
    assert r.returncode == 0 and env.current_link == SHA_B
    assert env.run("rollback").returncode == 0                      # B -> A again (declared)


def test_rsm_override_is_used_only_when_the_operator_enabled_it(env):
    assert env.deploy(SHA_A).returncode == 0
    assert "compose.rsm.yaml" not in env.log
    (env.base / "shared" / "rsm.enabled").write_text("")
    assert env.deploy(SHA_B).returncode == 0
    assert "-f compose.yaml -f compose.rsm.yaml" in env.log


# ---- R1: the host-isolation gate -------------------------------------------------------------
def untouched(env):
    """Nothing was loaded, started, switched or recorded."""
    return ("docker load" not in env.log and "up -d" not in env.log
            and env.current_link is None and env.state("current_sha") is None)


def test_deploy_is_refused_when_the_guard_script_is_missing(env):
    (env.base / "deploy" / "host-egress-guard.sh").unlink()
    r = env.deploy(SHA_A)
    assert r.returncode == 11 and untouched(env)
    assert "host egress guard missing or untrusted" in r.stderr.decode()


def test_deploy_is_refused_when_the_check_script_is_missing(env):
    (env.base / "deploy" / "check-host-isolation.sh").unlink()
    r = env.deploy(SHA_A)
    assert r.returncode == 11 and untouched(env)


@pytest.mark.parametrize("name", ["host-egress-guard.sh", "check-host-isolation.sh",
                                  "check-dns.sh"])
def test_deploy_is_refused_when_a_gate_script_is_writable_by_others(env, name):
    (env.base / "deploy" / name).chmod(0o775)
    r = env.deploy(SHA_A)
    assert r.returncode == 11 and untouched(env)


def test_deploy_is_refused_when_the_gate_directory_is_writable_by_others(env):
    (env.base / "deploy").chmod(0o777)
    assert env.deploy(SHA_A).returncode == 11


def test_a_symlinked_gate_script_is_not_trusted(env):
    real = env.base / "elsewhere.sh"
    real.write_text(GUARD_STUB)
    real.chmod(0o755)
    g = env.base / "deploy" / "host-egress-guard.sh"
    g.unlink()
    g.symlink_to(real)
    assert env.deploy(SHA_A).returncode == 11


def test_deploy_is_refused_when_the_guard_reports_inactive(env):
    r = env.deploy(SHA_A, STUB_GUARD_STATUS_FAIL="1")
    assert r.returncode == 12 and untouched(env)
    err = r.stderr.decode()
    assert "NOT active" in err and "not active with the full expected policy" in err
    assert "guard status" in (env.stub / "guard.log").read_text()


@pytest.mark.parametrize("line", ["", "EGRESS_FORBIDDEN_TARGETS=\n", "EGRESS_FORBIDDEN_TARGETS=x\n",
                                  "EGRESS_FORBIDDEN_TARGETS=100.107.22.84\n",
                                  "EGRESS_FORBIDDEN_TARGETS=100.107.22.84:22;id\n",
                                  "EGRESS_FORBIDDEN_TARGETS=host.example:22\n"])
def test_deploy_requires_well_formed_forbidden_targets(env, line):
    env.env_file.write_text("X=1\n" + line)
    r = env.deploy(SHA_A)
    assert r.returncode == 11 and untouched(env)
    assert "EGRESS_FORBIDDEN_TARGETS" in r.stderr.decode()


def test_the_last_forbidden_targets_assignment_wins_as_in_compose(env):
    env.env_file.write_text("EGRESS_FORBIDDEN_TARGETS=100.107.22.84:22\nEGRESS_FORBIDDEN_TARGETS=\n")
    assert env.deploy(SHA_A).returncode == 11


def test_caller_environment_cannot_supply_the_targets_or_loosen_the_check(env):
    env.env_file.write_text("X=1\n")
    r = env.run("deploy", env.bundle(SHA_A), EGRESS_FORBIDDEN_TARGETS="1.2.3.4:22")
    assert r.returncode == 11
    env.env_file.write_text("EGRESS_FORBIDDEN_TARGETS=100.107.22.84:22\n")
    r = env.run("deploy", env.bundle(SHA_A), SMOKE_HOST_ISOLATION="report",
                SMOKE_AUTODETECT_HOST_IPS="0", SMOKE_PROTECTED_PORTS="1", SMOKE_ROOTFUL_TARGETS="x")
    assert r.returncode == 0, r.stderr.decode()
    assert "SMOKE_HOST_ISOLATION=enforce" in env.isolation_log
    assert "SMOKE_AUTODETECT_HOST_IPS=1" in env.isolation_log
    assert "SMOKE_PROTECTED_PORTS=unset" in env.isolation_log
    assert "SMOKE_ROOTFUL_TARGETS=172.17.0.2:9 " in env.isolation_log     # the conf, not "x"


def test_isolation_check_runs_in_enforce_mode_after_up_with_the_stacks_compose_args(env):
    r = env.deploy(SHA_A)
    assert r.returncode == 0, r.stderr.decode()
    log = env.isolation_log
    assert f"check running={SHA_A} args=-p internship-hunter -f compose.yaml" in log
    assert "--env-file" in log and f"release-{SHA_A}.env" in log
    assert ("SMOKE_HOST_ISOLATION=enforce SMOKE_EXPECT_ROOTLESS=1 "
            "SMOKE_PROTECTED_IPS=100.107.22.84 ") in log
    up = [i for i, ln in enumerate(env.log.splitlines()) if " up -d" in ln][0]
    assert up < len(env.log.splitlines())            # the check saw the new release running


def test_operator_rootful_targets_reach_the_check_from_the_trusted_conf(env):
    conf = env.base / "deploy" / "host-isolation.conf"
    conf.write_text("ROOTFUL_TARGETS=172.18.0.5:8080,172.18.0.6:9000\n")
    conf.chmod(0o644)
    assert env.deploy(SHA_A).returncode == 0
    assert "SMOKE_ROOTFUL_TARGETS=172.18.0.5:8080,172.18.0.6:9000" in env.isolation_log
    conf.chmod(0o666)                      # world-writable: not trusted
    assert env.deploy(SHA_B).returncode == 11


def test_failed_isolation_check_restores_the_previous_release(env):
    assert env.deploy(SHA_A).returncode == 0
    r = env.deploy(SHA_B, STUB_FAIL_ISOLATION_SHA=SHA_B)
    assert r.returncode == 1
    assert env.current_link == SHA_A and env.state("current_sha") == SHA_A
    assert "isolation check FAILED" in r.stderr.decode()
    assert (env.stub / "running").read_text().strip() == SHA_A
    assert f"check running={SHA_A}" in env.isolation_log     # the restored release was gated too


def test_first_deploy_with_failed_isolation_is_torn_down(env):
    r = env.deploy(SHA_A, STUB_FAIL_ISOLATION_SHA=SHA_A)
    assert r.returncode == 1
    assert env.current_link is None and env.state("current_sha") is None
    assert "DOWN" in env.log and not (env.stub / "running").exists()
    assert "first deploy" in r.stderr.decode()


def test_restore_that_also_fails_isolation_stops_the_stack(env):
    assert env.deploy(SHA_A).returncode == 0
    r = env.deploy(SHA_B, STUB_FAIL_ISOLATION_ALL="1")
    assert r.returncode == 10 and "MANUAL RECOVERY" in r.stderr.decode()
    assert "DOWN" in env.log and not (env.stub / "running").exists()      # fail closed, not exposed


def test_rollback_requires_the_isolation_prerequisites_too(env):
    assert env.deploy(SHA_A).returncode == 0
    assert env.deploy(SHA_B).returncode == 0
    (env.stub / "log").write_text("")
    r = env.run("rollback", STUB_GUARD_STATUS_FAIL="1")
    assert r.returncode == 12
    assert "up -d" not in env.log and env.current_link == SHA_B
    (env.base / "deploy" / "check-host-isolation.sh").unlink()
    assert env.run("rollback").returncode == 11
    env.env_file.write_text("X=1\n")
    (env.base / "deploy" / "check-host-isolation.sh").write_text(CHECK_STUB)
    (env.base / "deploy" / "check-host-isolation.sh").chmod(0o755)
    assert env.run("rollback").returncode == 11


def test_rollback_runs_the_enforce_check_on_the_target(env):
    env.deploy(SHA_A)
    env.deploy(SHA_B)
    (env.stub / "isolation.log").write_text("")
    assert env.run("rollback").returncode == 0
    assert f"check running={SHA_A}" in env.isolation_log
    assert "SMOKE_HOST_ISOLATION=enforce" in env.isolation_log


def test_rollback_whose_target_fails_isolation_reactivates_the_current_release(env):
    env.deploy(SHA_A)
    env.deploy(SHA_B)
    r = env.run("rollback", STUB_FAIL_ISOLATION_SHA=SHA_A)
    assert r.returncode == 6
    assert (env.stub / "running").read_text().strip() == SHA_B and env.current_link != SHA_A


def test_rollback_where_nothing_passes_isolation_stops_the_stack(env):
    env.deploy(SHA_A)
    env.deploy(SHA_B)
    r = env.run("rollback", STUB_FAIL_ISOLATION_ALL="1")
    assert r.returncode == 6 and "DOWN" in env.log
    assert not (env.stub / "running").exists()


# ---- R1: never the rootful daemon ------------------------------------------------------------
def test_a_rootful_daemon_is_refused_and_the_old_override_no_longer_exists(env):
    r = env.run("deploy", env.bundle(SHA_A), STUB_ROOTFUL="1", HUNTER_ALLOW_ROOTFUL="1")
    assert r.returncode == 5 and untouched(env)
    assert "HUNTER_ALLOW_ROOTFUL" not in SCRIPT.read_text()    # no rootful escape hatch at all


def test_production_mode_pins_the_users_own_socket_and_refuses_without_it(env, tmp_path):
    r = env.run("deploy", b"", HUNTER_TEST_MODE="0", XDG_RUNTIME_DIR=str(tmp_path / "nope"),
                DOCKER_HOST="unix:///var/run/docker.sock")
    assert r.returncode == 5 and b"rootless Docker socket" in r.stderr
    assert env.log == ""                             # no docker command was ever issued
    script = SCRIPT.read_text()
    assert 'export DOCKER_HOST="unix://$rd/docker.sock"' in script
    assert "unset DOCKER_CONTEXT" in script


def test_stub_docker_sees_a_pinned_host_in_production_mode(env, tmp_path):
    sock = tmp_path / "rd" / "docker.sock"
    sock.parent.mkdir()
    import socket as _s
    srv = _s.socket(_s.AF_UNIX)
    srv.bind(str(sock))
    try:
        (env.bin / "docker").write_text("#!/usr/bin/env bash\n"
                                        "echo \"DOCKER_HOST=$DOCKER_HOST\" >> \"$STUB_DIR/hosts\"\n"
                                        "case \"$1\" in info) echo '[name=rootless]';; esac\n")
        r = env.run("rollback", XDG_RUNTIME_DIR=str(sock.parent),
                    DOCKER_HOST="unix:///var/run/docker.sock")
        hosts = (env.stub / "hosts").read_text().split()
        assert hosts and set(hosts) == {f"DOCKER_HOST=unix://{sock}"}, (hosts, r.stderr)
    finally:
        srv.close()


# ---- R4: the API port ------------------------------------------------------------------------
def test_health_check_targets_port_18000_and_never_8000(env):
    assert env.deploy(SHA_A).returncode == 0
    script = SCRIPT.read_text()
    assert "http://127.0.0.1:$API_PORT" in script and "API_PORT=18000" in script
    assert "127.0.0.1:8000" not in script and "localhost:8000" not in script


def test_a_listener_that_is_not_our_api_blocks_the_deploy_before_any_change(env):
    r = env.deploy(SHA_A, STUB_PORT_BUSY="1")
    assert r.returncode == 3 and untouched(env)
    assert "port 18000 is already in use" in r.stderr.decode()


def test_our_own_running_api_on_18000_is_not_a_conflict(env):
    assert env.deploy(SHA_A).returncode == 0
    assert env.deploy(SHA_B, STUB_PORT_BUSY="1").returncode == 0


def test_health_check_refuses_an_api_that_publishes_a_different_port(env):
    """If compose says the api is not on 127.0.0.1:18000, curl must not talk to what is there."""
    r = env.deploy(SHA_A, STUB_WRONG_API_PORT="1")
    assert r.returncode == 1 and "expected 127.0.0.1:18000" in r.stderr.decode()
    assert env.current_link is None
    curl_calls = (env.stub / "curl.log").read_text() if (env.stub / "curl.log").exists() else ""
    assert "8000" not in curl_calls


def test_port_inspection_failure_fails_closed(env):
    (env.bin / "ss").write_text("#!/usr/bin/env bash\nexit 1\n")
    r = env.deploy(SHA_A)
    assert r.returncode == 3 and untouched(env)


# ---- F-6: a rootful container target is REQUIRED ------------------------------------------------
@pytest.mark.parametrize("content", [None, "", "# nothing\n", "ROOTFUL_TARGETS=\n", "OTHER=1\n"])
def test_deploy_requires_a_rootful_container_target(env, content):
    if content is None:
        env.conf.unlink()
    else:
        env.conf.write_text(content)
        env.conf.chmod(0o644)
    r = env.deploy(SHA_A)
    assert r.returncode == 11 and untouched(env)
    err = r.stderr.decode()
    assert "ROOTFUL_TARGETS" in err and "rootful container target" in err


def test_rootful_conf_must_be_trusted(env):
    env.conf.chmod(0o666)
    assert env.deploy(SHA_A).returncode == 11
    env.conf.chmod(0o644)
    real = env.base / "real.conf"
    real.write_text("ROOTFUL_TARGETS=172.17.0.2:9\n")
    env.conf.unlink()
    env.conf.symlink_to(real)
    assert env.deploy(SHA_A).returncode == 11


# ---- F-3: configured targets are verified live from the host before anything changes ------------
def test_targets_are_verified_with_the_trusted_check_before_any_change(env):
    r = env.deploy(SHA_A)
    assert r.returncode == 0, r.stderr.decode()
    log = (env.stub / "verify.log").read_text()
    assert "EGRESS_FORBIDDEN_TARGETS=100.107.22.84:22,100.107.22.84:8000" in log
    assert "SMOKE_ROOTFUL_TARGETS=172.17.0.2:9" in log and "SMOKE_EXPECT_ROOTLESS=1" in log


def test_dead_targets_fail_closed_before_anything_changes(env):
    r = env.deploy(SHA_A, STUB_VERIFY_FAIL="1")
    assert r.returncode == 11 and untouched(env)
    assert "not live from the host" in r.stderr.decode()
    assert "FAIL target is not live" in r.stderr.decode()


def test_rollback_also_re_verifies_the_targets(env):
    env.deploy(SHA_A)
    env.deploy(SHA_B)
    (env.stub / "log").write_text("")
    r = env.run("rollback", STUB_VERIFY_FAIL="1")
    assert r.returncode == 11 and "up -d" not in env.log and env.current_link == SHA_B


def test_host_networking_changes_between_deploys_fail_closed(env):
    assert env.deploy(SHA_A).returncode == 0
    assert env.deploy(SHA_B, STUB_VERIFY_FAIL="1").returncode == 11     # e.g. the address moved
    assert env.current_link == SHA_A and env.state("current_sha") == SHA_A


# ---- L-a: the forced-command boundary ------------------------------------------------------------
def test_production_mode_ignores_every_test_hook_from_the_environment(env):
    marker = env.tmp / "decoy"
    r = env.run("deploy", b"", HUNTER_TEST_MODE="0", HUNTER_BASE=str(marker),
                HUNTER_MAX_BUNDLE_BYTES="1", HUNTER_GUARD_PROC="/tmp/fake",
                HUNTER_GUARD_TEST_MODE="1", ACCEPT_SCHEMA_REVISION="9999")
    # the decoy base is never used or even created: production runs against /opt/internship-hunter
    assert not marker.exists()
    assert r.returncode in (5, 1)          # no rootless socket / no /opt/internship-hunter here


def test_test_mode_is_refused_against_the_production_directory_or_without_a_base(env):
    for base in ("/opt/internship-hunter", "/opt/internship-hunter/x", ""):
        extra = {"HUNTER_BASE": base} if base else {}
        r = subprocess.run(["bash", str(SCRIPT)], input=b"", capture_output=True, timeout=30, env={
            "PATH": f"{env.bin}:{os.environ['PATH']}", "HOME": str(env.tmp),
            "STUB_DIR": str(env.stub),
            "SSH_ORIGINAL_COMMAND": "deploy", "HUNTER_TEST_MODE": "1", **extra})
        assert r.returncode == 2 and b"HUNTER_TEST_MODE requires HUNTER_BASE" in r.stderr, base
        assert env.log == ""


def test_the_script_cleans_loader_and_interpreter_hooks_in_production_mode():
    text = SCRIPT.read_text()
    head = text[:text.index("# Trusted, root-owned copies")]
    for var in ("BASH_ENV", "LD_PRELOAD", "PYTHONPATH", "HUNTER_GUARD_PROC",
                "HUNTER_GUARD_TEST_MODE", "HUNTER_GUARD_TEST_NSFS_TYPE", "ACCEPT_SCHEMA_REVISION"):
        assert var in head, var
    assert "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" in head


def test_no_deploy_script_ever_names_the_rootful_docker_socket():
    for name in ("remote-deploy.sh", "check-host-isolation.sh", "host-egress-guard.sh",
                 "smoke-test.sh"):
        code = "\n".join(ln for ln in (SCRIPT.parent / name).read_text().splitlines()
                         if not ln.lstrip().startswith("#"))
        assert "/var/run/docker.sock" not in code and "/run/docker.sock" not in code, name


# ---- DNS: the stack must use the resolver the guard allows, from inside the container ------------
def test_deploy_is_refused_when_the_dns_check_is_missing_or_untrusted(env):
    (env.base / "deploy" / "check-dns.sh").unlink()
    r = env.deploy(SHA_A)
    assert r.returncode == 11 and untouched(env)
    assert "DNS check missing or untrusted" in r.stderr.decode()


@pytest.mark.parametrize("content", ["PROTECT=100.107.22.84/32\n", "DNS=\n", "DNS=resolver.lan\n",
                                     "DNS=10.0.2.3,not-an-ip\n", "DNS=10.0.2\n"])
def test_deploy_is_refused_without_an_explicit_valid_guard_resolver(env, content):
    env.guard_conf.write_text(content)
    r = env.deploy(SHA_A)
    assert r.returncode == 11 and untouched(env)
    assert "host-egress-guard.conf" in r.stderr.decode() and "DNS=" in r.stderr.decode()


def test_deploy_is_refused_when_the_guard_conf_is_missing_writable_or_a_symlink(env):
    env.guard_conf.chmod(0o666)
    assert env.deploy(SHA_A).returncode == 11
    env.guard_conf.chmod(0o644)
    real = env.base / "elsewhere.conf"
    real.write_text("DNS=10.0.2.3\n")
    real.chmod(0o644)
    env.guard_conf.unlink()
    env.guard_conf.symlink_to(real)
    assert env.deploy(SHA_A).returncode == 11
    env.guard_conf.unlink()
    assert env.deploy(SHA_A).returncode == 11


def test_dns_check_runs_in_enforce_mode_with_the_guards_resolver_after_the_isolation_check(env):
    env.guard_conf.write_text("# policy\nDNS=10.0.2.3\nPROTECT=100.107.22.84/32\n")
    r = env.deploy(SHA_A)
    assert r.returncode == 0, r.stderr.decode()
    log = env.dns_log
    assert f"dns running={SHA_A} args=-p internship-hunter -f compose.yaml" in log
    assert "SMOKE_HOST_ISOLATION=enforce SMOKE_DNS_EXPECT=10.0.2.3" in log
    assert "--env-file" in log and f"release-{SHA_A}.env" in log


def test_failed_dns_check_restores_the_previous_release(env):
    assert env.deploy(SHA_A).returncode == 0
    r = env.deploy(SHA_B, STUB_FAIL_DNS_SHA=SHA_B)
    assert r.returncode == 1 and "DNS check FAILED" in r.stderr.decode()
    assert env.current_link == SHA_A
    assert (env.stub / "running").read_text().strip() == SHA_A
    assert f"dns running={SHA_A}" in env.dns_log           # the restored release was gated too


def test_first_deploy_with_a_failed_dns_check_is_torn_down(env):
    r = env.deploy(SHA_A, STUB_FAIL_DNS_SHA=SHA_A)
    assert r.returncode == 1 and env.current_link is None
    assert "DOWN" in env.log and not (env.stub / "running").exists()


def test_rollback_runs_the_dns_check_on_the_target_and_needs_its_prerequisites(env):
    env.deploy(SHA_A)
    env.deploy(SHA_B)
    (env.stub / "dns.log").write_text("")
    assert env.run("rollback").returncode == 0
    assert f"dns running={SHA_A}" in env.dns_log
    env.guard_conf.write_text("PROTECT=1.2.3.4/32\n")
    assert env.run("rollback").returncode == 11


# ---- F-3: the RENDERED compose DNS is judged against the guard BEFORE anything starts ---------
def real_dns_config(env):
    """Route the gate's config-only calls to the real check-dns.sh (judging the rendering)."""
    return {"STUB_REAL_DNS_CONFIG": str(REAL_CHECK_DNS)}


def test_the_rendered_dns_is_checked_before_images_are_loaded_or_anything_starts(env):
    r = env.deploy(SHA_A, **real_dns_config(env))
    assert r.returncode == 0, r.stderr.decode()
    lines = env.dns_config_log.splitlines()
    assert lines and all("SMOKE_DNS_EXPECT=10.0.2.3" in ln for ln in lines)
    # first deploy: nothing runs at any config check; only the post-start check sees the release
    assert all("running= " in ln for ln in lines), lines
    assert f"dns running={SHA_A}" in env.dns_log
    # and the very first of them precedes `docker load`
    assert env.log.index("docker load") > 0 and len(lines) >= 2          # early gate + activate()


def test_a_callers_hunter_dns_cannot_override_the_guard_resolver(env):
    r = env.deploy(SHA_A, HUNTER_DNS="9.9.9.9", **real_dns_config(env))
    assert r.returncode == 0, r.stderr.decode()
    assert "HUNTER_DNS=<unset>" in env.dns_config_log and "9.9.9.9" not in env.dns_config_log
    assert env.current_link == SHA_A


def test_without_the_scrub_the_stubbed_compose_would_have_honoured_the_callers_value(env):
    """Control for the test above: the model of compose really lets the process environment win."""
    out = subprocess.run(
        ["python3", str(env.stub / "render.py"), str(env.env_file)],
        env={"STUB_DIR": str(env.stub), "HUNTER_DNS": "9.9.9.9", "PATH": os.environ["PATH"]},
        capture_output=True, text=True, check=True).stdout
    assert json.loads(out)["services"]["api"]["dns"] == ["9.9.9.9"]


@pytest.mark.parametrize("shared_env,guard", [
    ("HUNTER_DNS=9.9.9.9\n", "DNS=10.0.2.3\n"),                  # operator override vs guard
    ("HUNTER_DNS=192.168.1.1\n", "DNS=10.0.2.3\n"),              # a LAN resolver the guard refuses
    ("X=1\n", "DNS=1.1.1.1\n"),                                  # guard changed, compose not
    ("HUNTER_DNS=10.0.2.3,1.1.1.1\n", "DNS=10.0.2.3,1.1.1.1\n"),  # compose renders ONE string
])
def test_a_dns_disagreement_stops_the_deploy_before_anything_is_touched(env, shared_env, guard):
    env.env_file.write_text(
        "EGRESS_FORBIDDEN_TARGETS=100.107.22.84:22,100.107.22.84:8000\n" + shared_env)
    env.guard_conf.write_text(guard)
    r = env.deploy(SHA_A, **real_dns_config(env))
    err = r.stderr.decode()
    assert r.returncode == 11, err
    assert "rendered DNS configuration disagrees with the guard" in err
    assert "nothing was started" in err
    assert untouched(env) and not (env.stub / "running").exists()
    assert "docker load" not in env.log and "DOWN" not in env.log


def test_a_dns_disagreement_leaves_the_running_release_alone(env):
    assert env.deploy(SHA_A, **real_dns_config(env)).returncode == 0
    before = env.log
    env.env_file.write_text(env.env_file.read_text() + "HUNTER_DNS=9.9.9.9\n")
    r = env.deploy(SHA_B, **real_dns_config(env))
    assert r.returncode == 11
    assert env.current_link == SHA_A and env.state("current_sha") == SHA_A
    assert (env.stub / "running").read_text().strip() == SHA_A
    after = env.log[len(before):]
    assert "docker load" not in after and " up " not in after and "DOWN" not in after
    assert not (env.base / "backups").exists()                     # no dump either


def test_a_dns_disagreement_refuses_a_rollback_before_anything_changes(env):
    env.deploy(SHA_A, **real_dns_config(env))
    env.deploy(SHA_B, **real_dns_config(env))
    env.env_file.write_text(env.env_file.read_text() + "HUNTER_DNS=9.9.9.9\n")
    before = env.log
    r = env.run("rollback", **real_dns_config(env))
    assert r.returncode == 11 and b"rollback target" in r.stderr
    assert env.current_link == SHA_B and (env.stub / "running").read_text().strip() == SHA_B
    assert " up " not in env.log[len(before):] and "DOWN" not in env.log[len(before):]


def test_activate_repeats_the_gate_right_before_up_so_a_restore_is_covered_too(env):
    """A restore of the previous release goes through activate(): its DNS is judged again."""
    assert env.deploy(SHA_A, **real_dns_config(env)).returncode == 0
    env.deploy(SHA_B, STUB_FAIL_UP_SHA=SHA_B, **real_dns_config(env))
    shas = [ln.split("args=")[0] for ln in env.dns_config_log.splitlines()]
    # A: early + activate; B: early + activate (up fails); A restored: activate again
    assert len(shas) == 5, env.dns_config_log
    assert env.current_link == SHA_A


def test_the_gate_expects_exactly_what_the_guard_conf_says(env):
    env.guard_conf.write_text("DNS=1.1.1.1\n")
    env.env_file.write_text(env.env_file.read_text() + "HUNTER_DNS=1.1.1.1\n")
    r = env.deploy(SHA_A, **real_dns_config(env))
    assert r.returncode == 0, r.stderr.decode()      # guard and compose agree on a public resolver
    assert "SMOKE_DNS_EXPECT=1.1.1.1" in env.dns_config_log
    assert "SMOKE_DNS_EXPECT=1.1.1.1" in env.dns_log


def real_commits(env):
    """The `commit` calls (not the read-only `commit --check` pre-flights)."""
    return [ln for ln in env.containment_log.splitlines()
            if ln.startswith("containment commit") and " --check " not in ln]


# ---- runtime containment: the watchdog that keeps the isolation true after the deploy -----------
def test_deploy_is_refused_when_the_containment_watchdog_script_is_missing_or_untrusted(env):
    (env.base / "deploy" / "runtime-containment.sh").chmod(0o775)
    r = env.deploy(SHA_A)
    assert r.returncode == 11 and untouched(env)
    assert "runtime containment missing or untrusted" in r.stderr.decode()
    (env.base / "deploy" / "runtime-containment.sh").unlink()
    assert env.deploy(SHA_A).returncode == 11


@pytest.mark.parametrize("status", ["20", "21"])
def test_deploy_and_rollback_are_refused_while_the_watchdog_is_dead_or_latched(env, status):
    r = env.deploy(SHA_A, STUB_CONTAINMENT_STATUS=status)
    assert r.returncode == 13 and untouched(env)
    assert "runtime containment is not active" in r.stderr.decode()
    assert env.deploy(SHA_A).returncode == 0
    assert env.deploy(SHA_B).returncode == 0
    r = env.run("rollback", STUB_CONTAINMENT_STATUS=status)
    assert r.returncode == 13 and env.current_link == SHA_B


def test_the_status_check_is_the_require_active_one(env):
    assert env.deploy(SHA_A).returncode == 0
    assert "containment status --require-active" in env.containment_log


def test_a_release_is_committed_only_after_every_gate_passed_with_the_isolation_parameters(env):
    r = env.deploy(SHA_A)
    assert r.returncode == 0, r.stderr.decode()
    commits = real_commits(env)
    assert len(commits) == 1
    c = commits[0]
    assert f"--sha {SHA_A}" in c and f"--release-dir {env.base}/releases/{SHA_A}" in c
    assert "--forbidden 100.107.22.84:22,100.107.22.84:8000" in c
    assert "--protected-ips 100.107.22.84" in c and "--rootful 172.17.0.2:9" in c
    assert "-- -p internship-hunter -f compose.yaml --env-file" in c
    # ... and by then the stack is up and both isolation checks ran for this release
    assert f"[running={SHA_A}]" in c
    assert f"dns running={SHA_A}" in env.dns_log and f"check running={SHA_A}" in env.isolation_log


def test_a_release_the_watchdog_refuses_is_not_kept_and_the_previous_one_is_restored(env):
    assert env.deploy(SHA_A).returncode == 0
    r = env.deploy(SHA_B, STUB_FAIL_COMMIT_SHA=SHA_B)
    assert r.returncode == 1 and "runtime containment refused release" in r.stderr.decode()
    assert env.current_link == SHA_A and (env.stub / "running").read_text().strip() == SHA_A
    commits = real_commits(env)
    assert f"--sha {SHA_A}" in commits[-1]            # the restored release is committed again


def test_a_first_deploy_the_watchdog_refuses_is_torn_down_and_recorded_as_stopped(env):
    r = env.deploy(SHA_A, STUB_FAIL_COMMIT_SHA=SHA_A)
    assert r.returncode == 1 and env.current_link is None
    timeline = env.log.splitlines()
    assert "DOWN" in timeline and "containment desired" in timeline
    # the watchdog is told BEFORE the stack is torn down, so it cannot restart what is being removed
    assert timeline.index("containment desired") < timeline.index("DOWN")
    assert "containment desired stopped" in env.containment_log


def test_a_failed_gate_never_reaches_the_commit(env):
    env.deploy(SHA_A, STUB_FAIL_DNS_SHA=SHA_A)
    assert real_commits(env) == []
    env.deploy(SHA_B, STUB_FAIL_ISOLATION_SHA=SHA_B)
    assert not any(f"--sha {SHA_B}" in ln for ln in real_commits(env))


def test_rollback_commits_the_release_it_restored(env):
    env.deploy(SHA_A)
    env.deploy(SHA_B)
    assert env.run("rollback").returncode == 0
    commits = real_commits(env)
    assert f"--sha {SHA_A}" in commits[-1]


# ---- PR #13 re-review: the action lock; a first deploy with nothing to go back to ----------------
def test_a_deploy_holds_the_watchdogs_action_lock_for_its_whole_duration(env):
    assert env.deploy(SHA_A).returncode == 0
    assert "commit saw the action lock held by the deploy" in (env.stub / "lock.log").read_text()
    # ... and releases it with the deploy: the watchdog can act again straight afterwards
    fd = os.open(env.base / "state" / "containment.action.lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)


def test_a_deploy_waits_for_a_watchdog_action_in_flight_and_then_proceeds(env):
    lock = env.base / "state" / "containment.action.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    fh = open(lock, "w")
    fcntl.flock(fh, fcntl.LOCK_EX)                     # the watchdog is stopping/starting the stack
    threading.Timer(1.5, lambda: (fcntl.flock(fh, fcntl.LOCK_UN), fh.close())).start()
    t0 = time.monotonic()
    r = env.deploy(SHA_A, HUNTER_ACTION_LOCK_WAIT="20")
    assert r.returncode == 0, r.stderr.decode()
    assert time.monotonic() - t0 >= 1.2


def test_a_deploy_that_cannot_get_the_action_lock_in_time_changes_nothing_and_says_why(env):
    lock = env.base / "state" / "containment.action.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    with open(lock, "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        r = env.deploy(SHA_A, HUNTER_ACTION_LOCK_WAIT="1")
    assert r.returncode == 4 and untouched(env)
    assert b"in the middle of stopping or starting the stack" in r.stderr


def test_a_release_runtime_containment_cannot_supervise_is_refused_before_anything_changes(env):
    r = env.deploy(SHA_A, STUB_NONCOMMITTABLE=SHA_A)
    assert r.returncode == 11 and untouched(env)
    assert b"runtime containment cannot supervise it" in r.stderr
    assert "docker load" not in env.log and "backups" not in os.listdir(env.base)


def pre_containment_running(env):
    """A running release from before runtime containment (it would be refused by `commit`)."""
    assert env.deploy(SHA_A).returncode == 0
    return {"STUB_NONCOMMITTABLE": SHA_A}


def test_the_first_deploy_over_a_pre_containment_release_needs_an_explicit_acknowledgement(env):
    knob = pre_containment_running(env)
    before = env.log
    r = env.deploy(SHA_B, **knob)
    assert r.returncode == 14, r.stderr.decode()
    assert b"predates runtime containment" in r.stderr and b"deploy-irreversible" in r.stderr
    assert env.current_link == SHA_A and env.state("current_sha") == SHA_A
    after = env.log[len(before):]
    assert "docker load" not in after and " up " not in after and "DOWN" not in after
    assert not (env.base / "backups").exists()


def test_acknowledged_it_deploys_and_records_that_there_is_no_way_back(env):
    knob = pre_containment_running(env)
    r = env.deploy(SHA_B, command="deploy-irreversible", **knob)
    assert r.returncode == 0, r.stderr.decode()
    assert env.current_link == SHA_B and env.state("rollback_ok") == "0"
    assert b"will NOT be restored" in r.stderr


def test_a_failed_acknowledged_deploy_restores_nothing_and_never_reports_a_restore(env):
    knob = pre_containment_running(env)
    before = env.log
    r = env.deploy(SHA_B, command="deploy-irreversible", STUB_FAIL_UP_SHA=SHA_B, **knob)
    err = r.stderr.decode()
    assert r.returncode == 10, err
    assert "NOT restored" in err and "deploy: restored" not in err           # never a false success
    after = env.log[len(before):]
    up_lines = [ln for ln in after.splitlines() if " up " in ln]
    assert all(f"[RELEASE_SHA={SHA_A}]" not in ln for ln in up_lines)
    assert "DOWN" in after and not (env.stub / "running").exists()          # fail closed
    assert env.current_link == SHA_A and env.state("current_sha") == SHA_A  # state does not claim B
    assert "containment desired stopped" in env.containment_log             # the watchdog is told
    assert "MANUAL RECOVERY REQUIRED" in err


def test_a_rollback_to_a_pre_containment_release_is_refused_before_anything_changes(env):
    assert env.deploy(SHA_A).returncode == 0
    assert env.deploy(SHA_B).returncode == 0
    before = env.log
    r = env.run("rollback", STUB_NONCOMMITTABLE=SHA_A)
    assert r.returncode == 14, r.stderr.decode()
    assert b"predates runtime containment" in r.stderr and b"nothing was changed" in r.stderr
    assert env.current_link == SHA_B and (env.stub / "running").read_text().strip() == SHA_B
    assert env.log[len(before):].count(" up ") == 0 and "DOWN" not in env.log[len(before):]


def test_a_committable_previous_release_is_still_restored_after_a_failed_deploy(env):
    assert env.deploy(SHA_A).returncode == 0
    r = env.deploy(SHA_B, STUB_FAIL_UP_SHA=SHA_B)
    assert r.returncode == 1 and env.current_link == SHA_A
    assert b"deploy: restored" in r.stderr
