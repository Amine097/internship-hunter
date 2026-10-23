"""Adversarial tests of deploy/runtime-containment.sh against a STATEFUL fake Docker.

The fake daemon (a Python script on PATH) keeps containers, networks and their attachments in a
JSON file, honours `ps / inspect / network ls|inspect|disconnect / stop / kill / compose
config|start` the way the script uses them, and logs every call in order together with the guard
stub's calls (`events.log`), so a test can assert ORDER: nothing is started before the guard is
verified, the set is stopped before a repair, a proxy is healthy before an agent starts. Topology,
restart policies and service names come from the repository's REAL compose.yaml. The packet- and
daemon-level truth is established against a real rootless Docker in
test_runtime_containment_lab.py.

Fault injection: flag files in the stub directory (guard_broken, guard_unrepairable,
targets_down, post_start_fails, docker_down, docker_hang, disconnect_fails, start_fails) and
the STUB_RESTART / STUB_CONFIG_FAIL environment variables; see Rig.
"""

import fcntl
import json
import os
import shutil
import signal
import stat
import subprocess
import textwrap
import time
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "runtime-containment.sh"
REAL_CHECK_DNS = ROOT / "deploy" / "check-dns.sh"
pytestmark = pytest.mark.skipif(
    not (shutil.which("flock") and shutil.which("timeout")), reason="needs flock+timeout"
)

SHA = "a" * 40
COMPOSE = yaml.safe_load((ROOT / "compose.yaml").read_text())
OUT = ["api", "discovery", "telegram", "egress-claude-1", "egress-claude-2", "egress-codex"]
AGENTS = ["agent-claude-1", "agent-claude-2", "agent-codex"]
SUPERVISED = OUT + AGENTS
DATA = ["postgres", "scheduler", "session-controller"]


PROJECT = "internship-hunter"
# what the images declare themselves (docker image inspect): the defaults a service without
# command/entrypoint/user in compose.yaml runs with
IMAGE_BASES = {
    "postgres:17-alpine": {
        "Entrypoint": ["docker-entrypoint.sh"],
        "Cmd": ["postgres"],
        "User": "",
        "Volumes": {"/var/lib/postgresql/data": {}},
    },
    "internship-hunter-app": {"Entrypoint": None, "Cmd": ["python"], "User": "hunter"},
    "internship-hunter-agent": {"Entrypoint": None, "Cmd": ["python"], "User": "hunter"},
    "internship-hunter-egress": {
        "Entrypoint": ["/usr/local/bin/egress-entry.sh"],
        "Cmd": ["python", "/app/egress_proxy.py"],
        "User": "proxy",
    },
}


def image_defaults(ref):
    return IMAGE_BASES[ref.split(":")[0] if ref.startswith("internship") else ref]


def render(name, svc, sha=SHA):
    """One service as `docker compose config --format json` renders it (the subset that matters)."""
    r = {
        "image": svc["image"].replace("${RELEASE_SHA:-dev}", sha),
        "restart": svc.get("restart", "unless-stopped"),
        "networks": {n: None for n in svc.get("networks", [])},
        "cap_drop": list(svc.get("cap_drop", [])),
        "security_opt": list(svc.get("security_opt", [])),
        "read_only": bool(svc.get("read_only")),
        "tmpfs": list(svc.get("tmpfs", [])),
        "command": svc.get("command"),
        "entrypoint": svc.get("entrypoint"),
        "volumes": [],
        "ports": [],
    }
    if svc.get("cap_add"):
        r["cap_add"] = list(svc["cap_add"])
    for v in svc.get("volumes", []):
        src, dst = v.split(":")
        r["volumes"].append({"type": "volume", "source": src, "target": dst, "volume": {}})
    for port in svc.get("ports", []):
        ip, pub, tgt = port.split(":")
        r["ports"].append(
            {
                "mode": "ingress",
                "host_ip": ip,
                "target": int(tgt),
                "published": pub,
                "protocol": "tcp",
            }
        )
    if svc.get("dns"):
        r["dns"] = list(svc["dns"])
    return r


def template(sha=SHA):
    nets = {
        n: {"internal": bool((v or {}).get("internal")), "name": f"{PROJECT}_{n}"}
        for n, v in COMPOSE["networks"].items()
    }
    volumes = {v: {"name": f"{PROJECT}_{v}"} for v in COMPOSE["volumes"]}
    services = {name: render(name, svc, sha) for name, svc in COMPOSE["services"].items()}
    return {"networks": nets, "services": services, "volumes": volumes}


def image_id(ref):
    return "sha256:" + (ref.encode().hex() * 4)[:64]


def release_images(sha):
    refs = {render(n, v, sha)["image"] for n, v in COMPOSE["services"].items()}
    return {ref: {"Id": image_id(ref), "Config": image_defaults(ref)} for ref in refs}


def genuine(name, sha=SHA):
    """The (Config, HostConfig, Mounts, Image) `docker inspect` reports for a container that
    compose created for service `name` of the release: what the assessor must accept."""
    r = render(name, COMPOSE["services"][name], sha)
    img = image_defaults(r["image"])
    ports = {
        f"{p['target']}/tcp": [{"HostIp": p["host_ip"], "HostPort": p["published"]}]
        for p in r["ports"]
    }
    first = sorted(r["networks"])[0] if r["networks"] else "default"
    hc = {
        "NetworkMode": f"{PROJECT}_{first}",
        "Privileged": False,
        "CapAdd": r.get("cap_add"),
        "CapDrop": r["cap_drop"],
        "SecurityOpt": r["security_opt"] or None,
        "ReadonlyRootfs": r["read_only"],
        "PidMode": "",
        "IpcMode": "private",
        "UTSMode": "",
        "UsernsMode": "",
        "CgroupnsMode": "private",
        "CgroupParent": "",
        "Devices": [],
        "DeviceCgroupRules": None,
        "DeviceRequests": None,
        "Sysctls": None,
        "Runtime": "runc",
        "VolumesFrom": None,
        "Links": None,
        "ExtraHosts": None,
        "GroupAdd": None,
        "PublishAllPorts": False,
        "PortBindings": ports or {},
        "Tmpfs": {t: "" for t in r["tmpfs"]} or None,
    }
    mounts = [
        {
            "Type": "volume",
            "Name": f"{PROJECT}_{v['source']}",
            "Source": f"/var/lib/docker/volumes/{PROJECT}_{v['source']}/_data",
            "Destination": v["target"],
            "RW": True,
        }
        for v in r["volumes"]
    ] + [{"Type": "tmpfs", "Source": "", "Destination": t, "RW": True} for t in r["tmpfs"]]
    config = {
        "Image": r["image"],
        "Entrypoint": r["entrypoint"] or img["Entrypoint"],
        "Cmd": r["command"] or img["Cmd"],
        "User": img["User"],
    }
    return config, hc, mounts, image_id(r["image"])


DOCKER = textwrap.dedent("""\
    #!/usr/bin/env python3
    import json, os, re, sys, time
    D = os.environ["STUB_DIR"]
    ST = D + "/docker.json"
    args = sys.argv[1:]
    open(D + "/docker.log", "a").write(" ".join(args) + "\\n")
    open(D + "/events.log", "a").write("docker " + " ".join(args) + "\\n")
    if os.path.exists(D + "/docker_down"):
        sys.exit(1)
    if os.path.exists(D + "/docker_hang") and args[0] in ("ps", "info"):
        time.sleep(120)
    if args[0] in ("ps", "inspect") and os.environ.get("STUB_DOCKER_DELAY"):
        # a slow daemon: cycles that take a while
        time.sleep(float(os.environ["STUB_DOCKER_DELAY"]))
    def load(): return json.load(open(ST))
    def save(s): json.dump(s, open(ST, "w"))
    def labels(c):
        if not c["project"]:
            return {}
        return {"com.docker.compose.project": c["project"],
                "com.docker.compose.service": c["service"]}
    def container_json(s, cid):
        c = s["containers"][cid]
        nets = {}
        for nid in c["nets"]:
            nets[s["networks"][nid]["name"]] = {"NetworkID": nid}
        return {"Id": cid, "Name": "/" + c["name"],
                "Config": {**c.get("config", {}), "Labels": labels(c)},
                "Image": c.get("image_id", ""),
                "State": {"Running": c["running"],
                          "Health": {"Status": c["health"]} if c["health"] != "none" else None},
                "NetworkSettings": {"Networks": nets}, "HostConfig": c["host_config"],
                "Mounts": [m if isinstance(m, dict) else {"Source": m} for m in c["mounts"]],
                "ResolvConfPath": c["resolv"]}
    def network_json(s, nid):
        n = s["networks"][nid]
        lab = {}
        if n["project"]:
            lab = {"com.docker.compose.project": n["project"],
                   "com.docker.compose.network": n["logical"]}
        return {"Id": nid, "Name": n["name"], "Internal": n["internal"], "Driver": "bridge",
                "Labels": lab}
    def flt(argv):
        out = []
        i = 0
        while i < len(argv):
            if argv[i] == "--filter":
                out.append(argv[i + 1]); i += 2
            else:
                i += 1
        return out
    verb = args[0]
    if verb == "info":
        if "DefaultRuntime" in " ".join(args):
            print(os.environ.get("STUB_DEFAULT_RUNTIME", "runc")); sys.exit(0)
        print("[name=seccomp name=rootless]"); sys.exit(0)
    if verb == "events":
        while True:
            if os.path.exists(D + "/events.trigger"):
                os.remove(D + "/events.trigger"); print("network connect", flush=True)
            time.sleep(0.1)
    s = load()
    # "a deploy replaced the containers meanwhile"
    if verb == "ps" and os.environ.get("STUB_HEAL_AT_PS_CALL"):
        n = int(open(D + "/ps.count").read()) + 1 if os.path.exists(D + "/ps.count") else 1
        open(D + "/ps.count", "w").write(str(n))
        if n == int(os.environ["STUB_HEAL_AT_PS_CALL"]):
            s["containers"]["c-agent-codex"]["nets"] = ["net-agent_codex"]
            save(s)
    if verb == "ps" and os.path.exists(D + "/ghost"):
        # a container that vanishes between `ps` and `inspect` (compose recreating it)
        print("c-ghost")
    if verb == "ps":
        want = [f.split("=", 1)[1] for f in flt(args) if f.startswith("label=")]
        everything = any(a in ("-a", "-aq") for a in args)
        for cid, c in s["containers"].items():
            if not c["running"] and not everything:
                continue
            l = [f"{k}={v}" for k, v in labels(c).items()]
            if all(w in l for w in want):
                print(cid)
        sys.exit(0)
    if verb == "inspect":
        if args[1] == "-f":
            c = s["containers"][args[3]]
            print(c["health"]); sys.exit(0)
        print(json.dumps([container_json(s, c) for c in args[1:]])); sys.exit(0)
    if verb == "image" and args[1] == "inspect":
        img = s.get("images", {}).get(args[2])
        if img is None:
            sys.exit(1)
        print(json.dumps([img])); sys.exit(0)
    if verb == "network":
        if args[1] == "ls":
            print("\\n".join(s["networks"])); sys.exit(0)
        if args[1] == "inspect":
            print(json.dumps([network_json(s, n) for n in args[2:]])); sys.exit(0)
        if args[1] == "disconnect":
            net, cid = args[-2], args[-1]
            latch = os.environ.get("STUB_LATCH_PATH", "")
            open(D + "/events.log", "a").write(
                "note disconnect latch_present=%s\\n" % (bool(latch) and os.path.exists(latch)))
            if os.path.exists(D + "/disconnect_fails"):
                sys.exit(1)
            if net in s["containers"][cid]["nets"]:
                s["containers"][cid]["nets"].remove(net)
            save(s); sys.exit(0)
    if verb in ("stop", "kill"):
        # the test kills the script now
        if verb == "stop" and os.path.exists(D + "/crash_on_stop"):
            open(D + "/crash_marker", "w").write("stopping")
            time.sleep(60)
        if verb == "stop" and os.path.exists(D + "/slow_stop"):
            time.sleep(float(open(D + "/slow_stop").read() or 2))
        ids = [a for a in args[1:] if not a.startswith("-") and not a.isdigit()]
        for cid in ids:
            s["containers"][cid]["running"] = False
        save(s); sys.exit(0)
    if verb == "compose":
        i = 1
        while args[i] in ("-p", "-f", "--env-file"):
            i += 2
        sub = args[i]
        if sub == "config":
            if os.environ.get("STUB_CONFIG_FAIL"):
                sys.exit(1)
            t = json.load(open(D + "/compose-template.json"))
            dns = os.environ.get("HUNTER_DNS") or "10.0.2.3"
            for name, svc in t["services"].items():
                if "dns" in svc:
                    svc["dns"] = [re.sub(r"\\$\\{HUNTER_DNS:-[^}]*\\}", dns, d) for d in svc["dns"]]
                for pair in os.environ.get("STUB_RESTART", "").split():
                    n, pol = pair.split("=")
                    if n == name:
                        svc["restart"] = pol
            print(json.dumps(t)); sys.exit(0)
        if sub == "start":
            if os.path.exists(D + "/start_fails"):
                sys.exit(1)
            for svc in args[i + 1:]:
                for cid, c in s["containers"].items():
                    if c["service"] == svc and c["project"]:
                        c["running"] = True
                        c["health"] = "none" if c["health"] == "none" else "healthy"
            save(s); sys.exit(0)
    sys.exit(99)
""")

GUARD = textwrap.dedent("""\
    #!/usr/bin/env bash
    echo "guard $*" >> "$STUB_DIR/events.log"
    case "$1" in
      status) if [[ -e "$STUB_DIR/guard_broken" ]]; then echo "NOT active: stub says so"; exit 1; fi
              if [[ -e "$STUB_DIR/guard_stale" ]]; then
                echo "NOT active (stale host addresses only; re-run apply): stub"; exit 3
              fi
              echo active ;;
      apply)  [[ -e "$STUB_DIR/guard_unrepairable" ]] && exit 1
              rm -f "$STUB_DIR/guard_broken" "$STUB_DIR/guard_stale"
              # "the host moved again right after the apply": the next N applies are overtaken
              if [[ -s "$STUB_DIR/guard_restale" ]]; then
                n="$(cat "$STUB_DIR/guard_restale")"; echo $((n - 1)) > "$STUB_DIR/guard_restale"
                [[ "$n" -gt 0 ]] && : > "$STUB_DIR/guard_stale"
              fi
              echo applied ;;
    esac
""")
ISOLATION = textwrap.dedent("""\
    #!/usr/bin/env bash
    echo "isolation $* targets=${EGRESS_FORBIDDEN_TARGETS:-}" \\
         "protected=${SMOKE_PROTECTED_IPS:-}" >> "$STUB_DIR/events.log"
    if [[ "${1:-}" == --verify-targets ]]; then
      if [[ -e "$STUB_DIR/targets_down" ]]; then
        echo "FAIL target is not live (Tailscale)"; exit 1
      fi
      exit 0
    fi
    [[ -e "$STUB_DIR/post_start_fails" ]] && { echo "FAIL isolation breach (stub)"; exit 1; }
    exit 0
""")
DNS = textwrap.dedent("""\
    #!/usr/bin/env bash
    if [[ "${SMOKE_DNS_CONFIG_ONLY:-}" == 1 ]]; then exec "$REAL_CHECK_DNS" "$@"; fi
    echo "dns-check $* expect=${SMOKE_DNS_EXPECT:-}" >> "$STUB_DIR/events.log"
    [[ -e "$STUB_DIR/post_start_fails" ]] && { echo "FAIL dns (stub)"; exit 1; }
    exit 0
""")
IP = textwrap.dedent("""\
    #!/usr/bin/env bash
    if [[ "$1" == monitor || "$2" == monitor ]]; then
      while :; do
        if [[ -e "$STUB_DIR/ip.trigger" ]]; then
          rm -f "$STUB_DIR/ip.trigger"; echo "10.0.0.1 dev tailscale0"
        fi
        sleep 0.1
      done
    fi
    echo "default via 192.168.1.1 dev eth0"
""")


class Rig:
    """A deployed, healthy stack, committed under containment, with knobs to break it."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.base = tmp / "base"
        self.stub = tmp / "stub"
        self.bin = tmp / "bin"
        for d in (
            self.base / "deploy",
            self.base / "state",
            self.base / "shared",
            self.base / "releases" / SHA,
            self.stub,
            self.bin,
            self.stub / "resolv",
        ):
            d.mkdir(parents=True, exist_ok=True)
        (self.base / "shared" / ".env").write_text("X=1\n")
        self.lock = self.base / "state" / "deploy.lock"
        self.action_lock = self.base / "state" / "containment.action.lock"
        self.state_dir = self.base / "state" / "containment"
        for name, body in (
            ("host-egress-guard.sh", GUARD),
            ("check-host-isolation.sh", ISOLATION),
            ("check-dns.sh", DNS),
        ):
            p = self.base / "deploy" / name
            p.write_text(body)
            p.chmod(0o755)
        (self.base / "deploy").chmod(0o755)
        (self.base / "deploy" / "host-egress-guard.conf").write_text(
            "PROTECT=100.107.22.84/32\nDNS=10.0.2.3\n"
        )
        (self.base / "deploy" / "host-isolation.conf").write_text("ROOTFUL_TARGETS=172.17.0.2:9\n")
        for c in ("host-egress-guard.conf", "host-isolation.conf"):
            (self.base / "deploy" / c).chmod(0o644)
        (self.bin / "docker").write_text(DOCKER)
        (self.bin / "ip").write_text(IP)
        for f in self.bin.iterdir():
            f.chmod(0o755)
        (self.stub / "compose-template.json").write_text(json.dumps(template_with_no_restart()))
        self.write_docker_state(self.healthy_state())
        self.args = [
            "-p",
            "internship-hunter",
            "-f",
            "compose.yaml",
            "--env-file",
            str(self.base / "shared" / ".env"),
        ]

    # ---- the fake daemon ----------------------------------------------------------------
    def healthy_state(self):
        nets, containers = {}, {}
        for n, v in COMPOSE["networks"].items():
            nets[f"net-{n}"] = {
                "name": f"internship-hunter_{n}",
                "logical": n,
                "project": "internship-hunter",
                "internal": bool((v or {}).get("internal")),
            }
        for name, svc in COMPOSE["services"].items():
            if name == "migrate":
                running = False
            else:
                running = True
            out = any(
                not (COMPOSE["networks"][n] or {}).get("internal") for n in svc.get("networks", [])
            )
            resolv = self.stub / "resolv" / name
            resolv.write_text(
                "# Generated by Docker Engine.\nnameserver 127.0.0.11\nsearch lan\n\n"
                "# Based on host file: '/etc/resolv.conf' (internal resolver)\n"
                + ("# ExtServers: [10.0.2.3]\n" if out else "# ExtServers: [host(192.168.1.1)]\n")
                + "# Overrides: []\n"
            )
            config, hc, mounts, img_id = genuine(name)
            containers[f"c-{name}"] = {
                "name": f"internship-hunter-{name}-1",
                "project": "internship-hunter",
                "service": name,
                "running": running,
                "health": "healthy" if name.startswith(("egress", "agent", "api")) else "none",
                "nets": [f"net-{n}" for n in svc.get("networks", [])],
                "config": config,
                "image_id": img_id,
                "host_config": hc,
                "mounts": mounts,
                "resolv": str(resolv),
            }
        # an unrelated ad hoc container on Docker's default bridge (must never be touched)
        nets["net-bridge"] = {"name": "bridge", "logical": "", "project": "", "internal": False}
        adhoc = self.stub / "resolv" / "adhoc"
        adhoc.write_text("nameserver 192.168.1.1\n")
        containers["c-adhoc"] = {
            "name": "adhoc",
            "project": "",
            "service": "",
            "running": True,
            "health": "none",
            "nets": ["net-bridge"],
            "host_config": {"NetworkMode": "default"},
            "mounts": [],
            "resolv": str(adhoc),
        }
        images = release_images(SHA)
        return {"containers": containers, "networks": nets, "images": images}

    def write_docker_state(self, s):
        (self.stub / "docker.json").write_text(json.dumps(s))

    def docker_state(self):
        return json.loads((self.stub / "docker.json").read_text())

    def mutate(self, fn):
        s = self.docker_state()
        fn(s)
        self.write_docker_state(s)

    def running(self):
        return sorted(
            c["service"] or c["name"]
            for c in self.docker_state()["containers"].values()
            if c["running"]
        )

    def is_running(self, service):
        return any(
            c["running"] and c["service"] == service
            for c in self.docker_state()["containers"].values()
        )

    def attach(self, service, logical):
        self.mutate(lambda s: s["containers"][f"c-{service}"]["nets"].append(f"net-{logical}"))

    def stop_service(self, service):
        self.mutate(lambda s: s["containers"][f"c-{service}"].update(running=False))

    def set_resolv(self, service, text):
        Path(self.docker_state()["containers"][f"c-{service}"]["resolv"]).write_text(text)

    def flag(self, name, on=True):
        p = self.stub / name
        if on:
            p.write_text("")
        else:
            p.unlink(missing_ok=True)

    # ---- the script -----------------------------------------------------------------------
    def env(self, **extra):
        e = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "HUNTER_BASE": str(self.base),
            "HUNTER_CONTAINMENT_TEST_MODE": "1",
            "STUB_DIR": str(self.stub),
            "REAL_CHECK_DNS": str(REAL_CHECK_DNS),
            "HUNTER_CONTAINMENT_DOCKER_TIMEOUT": "5",
            "HUNTER_CONTAINMENT_START_TIMEOUT": "5",
            "XDG_RUNTIME_DIR": str(self.tmp / "xdg"),
            "STUB_LATCH_PATH": str(self.state_dir / "latch"),
        }
        e.update(extra)
        return e

    def run(self, *argv, timeout=60, **extra):
        return subprocess.run(
            ["bash", str(SCRIPT), *argv],
            capture_output=True,
            text=True,
            env=self.env(**extra),
            timeout=timeout,
        )

    def deploy_locks(self):
        """What remote-deploy.sh holds for the whole of a deploy: deploy.lock (one deploy at a
        time) AND the
        watchdog's action lock. Returns a context manager; the truncating open stamps the lock's
        mtime."""
        self.lock.parent.mkdir(parents=True, exist_ok=True)
        rig = self

        class Held:
            def __enter__(self):
                self.a = open(rig.lock, "w")
                fcntl.flock(self.a, fcntl.LOCK_EX)
                self.b = open(rig.action_lock, "w")
                fcntl.flock(self.b, fcntl.LOCK_EX)
                return self

            def __exit__(self, *exc):
                self.b.close()
                self.a.close()

        return Held()

    def under_deploy_lock(self, *argv, **extra):
        """Run a command the way remote-deploy.sh does: while it holds both of its locks."""
        with self.deploy_locks():
            return self.run(*argv, **extra)

    def commit(self, **extra):
        return self.under_deploy_lock(
            "commit",
            "--sha",
            SHA,
            "--release-dir",
            str(self.base / "releases" / SHA),
            "--forbidden",
            "100.107.22.84:22,100.107.22.84:8000",
            "--protected-ips",
            "100.107.22.84",
            "--rootful",
            "172.17.0.2:9",
            "--",
            *self.args,
            **extra,
        )

    def once(self, **extra):
        return self.run("once", **extra)

    # ---- observations -------------------------------------------------------------------------
    @property
    def events(self):
        p = self.stub / "events.log"
        return p.read_text().splitlines() if p.exists() else []

    def clear_events(self):
        (self.stub / "events.log").write_text("")
        (self.stub / "docker.log").write_text("")

    def mutating_calls(self):
        return [
            e
            for e in self.events
            if e.startswith("docker ")
            and any(v in e.split()[1:3] for v in ("stop", "kill", "start"))
            or " disconnect" in e
        ]

    @property
    def state(self):
        p = self.state_dir / "state"
        return p.read_text().strip() if p.exists() else None

    @property
    def latched(self):
        return (self.state_dir / "latch").exists()

    def latch_reason(self):
        return json.loads((self.state_dir / "latch").read_text())["reason"]

    @property
    def log(self):
        p = self.state_dir / "events.log"
        return p.read_text() if p.exists() else ""


def template_with_no_restart():
    """The real compose.yaml topology, as `docker compose config` renders it."""
    return template()


@pytest.fixture
def rig(tmp_path):
    r = Rig(tmp_path)
    c = r.commit()
    assert c.returncode == 0, c.stderr
    r.clear_events()
    return r


def stopped_all_supervised(r):
    return not any(r.is_running(s) for s in SUPERVISED)


# =============================== the contract (commit) ===============================
def test_the_real_compose_file_gives_exactly_the_supervised_set_no_restart_policy():
    t = template()
    for name, svc in t["services"].items():
        if name in SUPERVISED:
            assert svc["restart"] == "no", f"{name} must not be restarted by the Docker daemon"
        elif name != "migrate":
            assert svc["restart"] == "unless-stopped", name


def test_commit_is_only_valid_inside_a_deploy(tmp_path):
    r = Rig(tmp_path)
    r.lock.write_text("")  # a deploy lock nobody holds
    out = r.run(
        "commit", "--sha", SHA, "--release-dir", str(r.base / "releases" / SHA), "--", *r.args
    )
    assert out.returncode == 2 and "only valid inside a deploy" in out.stderr
    assert not (r.state_dir / "contract.json").exists()
    assert r.run("desired", "running").returncode == 2


def test_commit_records_the_contract_and_marks_the_stack_wanted(tmp_path):
    r = Rig(tmp_path)
    c = r.commit()
    assert c.returncode == 0, c.stderr
    contract = json.loads((r.state_dir / "contract.json").read_text())
    assert contract["dns"] == "10.0.2.3" and contract["release_sha"] == SHA
    assert sorted(k for k, v in contract["services"].items() if v["supervised"]) == sorted(
        SUPERVISED
    )
    assert contract["services"]["agent-codex"]["networks"] == ["agent_codex"]
    assert contract["networks"]["agent_codex"]["internal"] is True
    assert (r.state_dir / "desired").read_text().strip() == "running"
    assert contract["compose_args"][:2] == ["-p", "internship-hunter"]


@pytest.mark.parametrize("svc", ["api", "egress-codex", "agent-claude-1", "discovery"])
def test_commit_refuses_a_supervised_service_the_daemon_would_restart_by_itself(tmp_path, svc):
    r = Rig(tmp_path)
    c = r.commit(STUB_RESTART=f"{svc}=unless-stopped")
    assert c.returncode != 0 and f"{svc} renders restart=unless-stopped" in c.stderr
    assert not (r.state_dir / "contract.json").exists()


def test_commit_refuses_without_a_trusted_dns_in_the_guard_conf(tmp_path):
    r = Rig(tmp_path)
    (r.base / "deploy" / "host-egress-guard.conf").write_text("PROTECT=1.2.3.4/32\n")
    assert r.commit().returncode == 11


# =============================== steady state, false positives ===============================
def test_a_healthy_stack_is_left_completely_alone(rig):
    r = rig.once()
    assert r.returncode == 0, r.stderr
    assert rig.state == "ok 9/9 supervised services running"
    assert rig.mutating_calls() == [] and not rig.latched
    assert int((rig.state_dir / "heartbeat").read_text()) > 0


def test_false_positives_are_not_violations(rig):
    # the one-shot migrate service is not running; an unrelated ad hoc container sits on the default
    # bridge; another one runs on a user network of its own; a replica of a service; a service
    # that lost
    # a network it needs (availability, not a security matter); a stopped foreign container
    def noise(s):
        s["networks"]["net-other"] = {
            "name": "my-own-net",
            "logical": "",
            "project": "",
            "internal": False,
        }
        s["containers"]["c-other"] = dict(
            s["containers"]["c-adhoc"], name="other", nets=["net-other"]
        )
        s["containers"]["c-api2"] = dict(s["containers"]["c-api"], name="internship-hunter-api-2")
        s["containers"]["c-stopped"] = dict(
            s["containers"]["c-adhoc"], name="stopped", running=False, nets=["net-other"]
        )
        s["containers"]["c-telegram"]["nets"].remove("net-egress")

    rig.mutate(noise)
    r = rig.once()
    assert r.returncode == 0, r.stderr + rig.log
    assert rig.mutating_calls() == [] and not rig.latched and rig.state.startswith("ok")


def test_a_changed_host_resolver_is_a_warning_not_a_stop(rig):
    (rig.state_dir / "contract.json").write_text(
        json.dumps(
            {
                **json.loads((rig.state_dir / "contract.json").read_text()),
                "resolver_baseline": "9.9.9.9",
            }
        )
    )
    child = rig.tmp / "xdg" / "dockerd-rootless"
    child.mkdir(parents=True)
    (child / "child_pid").write_text("1")
    r = rig.once()
    assert r.returncode == 0 and rig.mutating_calls() == [] and not rig.latched
    assert rig.state.startswith("ok")


def test_nothing_that_is_not_ours_is_ever_stopped(rig):
    rig.attach("agent-codex", "egress_claude_1")
    rig.mutate(lambda s: s["containers"]["c-adhoc"]["nets"].append("net-agent_codex"))
    rig.once()
    assert rig.docker_state()["containers"]["c-adhoc"]["running"] is True
    assert not any(" stop " in f" {e} " and "c-adhoc" in e for e in rig.events)
    # the foreign endpoint on our agent network is removed, the container itself is left running
    assert "net-agent_codex" not in rig.docker_state()["containers"]["c-adhoc"]["nets"]


# =============================== latching: possible compromise ===============================
def test_a_hot_network_attachment_stops_the_set_removes_the_endpoint_and_latches(rig):
    rig.attach(
        "agent-codex", "egress_claude_1"
    )  # an agent that can now reach another proxy's network
    r = rig.once()
    assert r.returncode == 1
    assert stopped_all_supervised(rig), rig.running()
    assert "net-egress_claude_1" not in rig.docker_state()["containers"]["c-agent-codex"]["nets"]
    assert rig.latched and "ATTACH-UNEXPECTED" in rig.latch_reason()
    assert rig.is_running("postgres") and rig.is_running(
        "scheduler"
    )  # the data tier is not supervised
    assert rig.docker_state()["containers"]["c-adhoc"]["running"] is True


def test_a_latched_stack_stays_down_even_if_everything_looks_fine_again(rig):
    rig.attach("agent-codex", "egress_claude_1")
    rig.once()
    rig.clear_events()
    for _ in range(3):
        r = rig.once()
        assert r.returncode == 1 and rig.state.startswith("latched")
    assert stopped_all_supervised(rig) and not any("start" in e.split()[:4] for e in rig.events)
    # somebody starts a service by hand: the next cycle stops it again
    rig.mutate(lambda s: s["containers"]["c-api"].update(running=True))
    rig.once()
    assert not rig.is_running("api") and "the latch is set" in rig.log


@pytest.mark.parametrize(
    "svc,net",
    [
        ("agent-claude-1", "egress"),
        ("agent-codex", "data"),
        ("discovery", "egress_codex"),
        ("api", "agent_codex"),
        ("egress-claude-1", "agent_codex"),
    ],
)
def test_any_unexpected_attachment_of_a_project_container_is_caught(rig, svc, net):
    rig.attach(svc, net)
    assert rig.once().returncode == 1
    assert rig.latched and stopped_all_supervised(rig)
    assert f"net-{net}" not in rig.docker_state()["containers"][f"c-{svc}"]["nets"]


def test_a_foreign_container_on_an_agent_network_is_disconnected_and_latches(rig):
    rig.mutate(lambda s: s["containers"]["c-adhoc"]["nets"].append("net-agent_claude_1"))
    assert rig.once().returncode == 1
    assert rig.latched and "ATTACH-FOREIGN" in rig.latch_reason() and stopped_all_supervised(rig)
    assert rig.docker_state()["containers"]["c-adhoc"]["nets"] == ["net-bridge"]


def test_a_project_container_on_a_foreign_network_is_caught(rig):
    rig.mutate(lambda s: s["containers"]["c-agent-codex"]["nets"].append("net-bridge"))
    assert rig.once().returncode == 1 and rig.latched and stopped_all_supervised(rig)


@pytest.mark.parametrize("net", ["agent_claude_1", "agent_claude_2", "agent_codex", "data"])
def test_an_internal_network_that_is_no_longer_internal_latches(rig, net):
    rig.mutate(lambda s: s["networks"][f"net-{net}"].update(internal=False))
    assert rig.once().returncode == 1
    assert rig.latched and "NET-FLAG" in rig.latch_reason() and stopped_all_supervised(rig)


@pytest.mark.parametrize(
    "hc,mounts,why",
    [
        ({"NetworkMode": "host"}, [], "network mode host"),
        ({"NetworkMode": "container:c-api"}, [], "network mode container"),
        ({"NetworkMode": "default", "Privileged": True}, [], "privileged"),
        ({"NetworkMode": "default", "PidMode": "host"}, [], "host pid"),
        ({"NetworkMode": "default"}, ["/run/user/1001/docker.sock"], "docker socket"),
    ],
)
def test_a_container_started_around_the_networks_latches(rig, hc, mounts, why):
    rig.mutate(lambda s: s["containers"]["c-egress-codex"].update(host_config=hc, mounts=mounts))
    assert rig.once().returncode == 1
    assert rig.latched and "HOSTCFG" in rig.latch_reason(), why
    assert stopped_all_supervised(rig)


def test_a_stopped_container_carrying_an_unexpected_endpoint_is_caught_before_it_is_started(rig):
    """`docker network connect` works on a stopped container: the endpoint comes back with it."""
    rig.mutate(
        lambda s: [
            c.update(running=False) for c in s["containers"].values() if c["service"] in SUPERVISED
        ]
    )
    rig.attach("agent-codex", "egress_claude_1")
    r = rig.once()
    assert r.returncode == 1 and rig.latched and "ATTACH-UNEXPECTED" in rig.latch_reason()
    assert not any(" start " in e for e in rig.events if e.startswith("docker")), rig.events
    assert "net-egress_claude_1" not in rig.docker_state()["containers"]["c-agent-codex"]["nets"]


def test_a_container_claiming_the_project_without_a_service_of_the_release_latches(rig):
    rig.mutate(
        lambda s: s["containers"].update(
            {"c-rogue": dict(s["containers"]["c-api"], service="shell", name="rogue")}
        )
    )
    assert rig.once().returncode == 1
    assert rig.latched and "SVC-UNKNOWN" in rig.latch_reason()
    assert not rig.docker_state()["containers"]["c-rogue"]["running"]


# ---- runtime DNS (not compose): the daemon-level dns finding, in the loop ----
def test_a_service_with_a_route_out_that_slips_to_the_daemons_resolver_latches(rig):
    rig.set_resolv("egress-codex", "nameserver 127.0.0.11\n# ExtServers: [host(192.168.1.1)]\n")
    assert rig.once().returncode == 1
    assert (
        rig.latched and "DNS-RT" in rig.latch_reason() and "host(192.168.1.1)" in rig.latch_reason()
    )
    assert stopped_all_supervised(rig)


def test_an_agent_that_acquires_an_upstream_resolver_latches(rig):
    """daemon.json {"dns": [...]} + a restart: compose says nothing, the runtime has it."""
    rig.set_resolv(
        "agent-codex",
        "nameserver 127.0.0.11\n# ExtServers: [10.0.2.3]\n# Overrides: [nameservers]\n",
    )
    assert rig.once().returncode == 1
    assert rig.latched and "explicit upstream" in rig.latch_reason() and stopped_all_supervised(rig)


def test_a_postgres_with_an_explicit_upstream_is_caught_too(rig):
    rig.set_resolv("postgres", "nameserver 127.0.0.11\n# ExtServers: [1.1.1.1]\n")
    assert rig.once().returncode == 1 and rig.latched


def test_a_wrong_nameserver_line_latches(rig):
    rig.set_resolv("api", "nameserver 192.168.1.1\n# ExtServers: [10.0.2.3]\n")
    assert rig.once().returncode == 1 and rig.latched and "DNS-RT" in rig.latch_reason()


def test_a_resolv_conf_that_cannot_be_read_stops_the_set_but_heals_by_itself(rig):
    path = Path(rig.docker_state()["containers"]["c-telegram"]["resolv"])
    saved = path.read_text()
    path.unlink()
    r = rig.once()
    assert r.returncode == 1 and not rig.latched and stopped_all_supervised(rig)
    assert "UNVERIFIED" in rig.log
    path.write_text(saved)
    rig.once()
    assert all(rig.is_running(s) for s in SUPERVISED) and not rig.latched


# ============================ self-healing: a prerequisite is missing ============================
def test_guard_drift_stops_the_set_repairs_the_guard_and_restarts_in_that_order(rig):
    rig.flag("guard_broken")
    r = rig.once()
    assert r.returncode == 1, r.stderr
    ev = [
        e
        for e in rig.events
        if e.startswith(("guard", "docker stop", "docker compose")) or " start " in e
    ]
    stop = next(i for i, e in enumerate(ev) if e.startswith("docker stop"))
    apply_ = next(i for i, e in enumerate(ev) if e == "guard apply --wait 20")
    start = next(i for i, e in enumerate(ev) if " start " in e)
    assert stop < apply_ < start, ev
    assert all(rig.is_running(s) for s in SUPERVISED) and not rig.latched
    assert "GUARD-REPAIRED" in rig.log and "QUARANTINE" in rig.log


def test_an_unrepairable_guard_leaves_the_set_stopped_and_waiting_not_latched(rig):
    rig.flag("guard_broken")
    rig.flag("guard_unrepairable")
    for _ in range(3):
        rig.once()
    assert stopped_all_supervised(rig) and not rig.latched and rig.state.startswith("waiting")
    assert "GUARD-UNREPAIRABLE" in rig.log
    # the host is repaired by the operator (or the daemon's ExecStartPost): the set comes back alone
    rig.flag("guard_broken", False)
    rig.flag("guard_unrepairable", False)
    r = rig.once()
    assert r.returncode == 0 and all(rig.is_running(s) for s in SUPERVISED)


def test_the_set_is_never_started_before_the_guard_is_verified(rig):
    """The restart race: the daemon came back, nothing runs (restart: no), the guard is missing."""
    rig.mutate(
        lambda s: [
            c.update(running=False) for c in s["containers"].values() if c["service"] in SUPERVISED
        ]
    )
    rig.flag("guard_broken")
    rig.flag("guard_unrepairable")
    rig.once()
    assert not any(" start " in e for e in rig.events if e.startswith("docker")), rig.events
    rig.flag("guard_unrepairable", False)
    rig.once()
    ev = rig.events
    first_start = next(i for i, e in enumerate(ev) if e.startswith("docker") and " start " in e)
    applied = max(i for i, e in enumerate(ev) if e.startswith("guard apply") and i < first_start)
    verified = [i for i, e in enumerate(ev) if e == "guard status" and applied < i < first_start]
    assert verified, ev  # a successful `status` after the repair, before the first start
    assert all(rig.is_running(s) for s in SUPERVISED)


def test_a_cold_start_is_verified_with_the_enforce_mode_checks(rig):
    rig.mutate(
        lambda s: [
            c.update(running=False) for c in s["containers"].values() if c["service"] in SUPERVISED
        ]
    )
    rig.once()
    iso = [e for e in rig.events if e.startswith("isolation") and "--verify-targets" not in e]
    dns = [e for e in rig.events if e.startswith("dns-check")]
    assert iso and "protected=100.107.22.84" in iso[-1]
    assert dns and "expect=10.0.2.3" in dns[-1]
    assert "STARTED" in rig.log


def test_proxies_are_started_and_healthy_before_anything_that_uses_them(rig):
    rig.mutate(
        lambda s: [
            c.update(running=False) for c in s["containers"].values() if c["service"] in SUPERVISED
        ]
    )
    rig.once()
    starts = [e for e in rig.events if e.startswith("docker compose") and " start " in e]
    assert len(starts) == 2
    assert all(f"egress-{n}" in starts[0] for n in ("claude-1", "claude-2", "codex"))
    assert (
        "agent-codex" in starts[1]
        and "api" in starts[1]
        and "egress" not in starts[1].split("start")[1]
    )


def test_post_start_verification_failure_stops_the_set_again_and_latches(rig):
    rig.mutate(
        lambda s: [
            c.update(running=False) for c in s["containers"].values() if c["service"] in SUPERVISED
        ]
    )
    rig.flag("post_start_fails")
    r = rig.once()
    assert r.returncode == 1 and rig.latched and "POST-START" in rig.latch_reason()
    assert stopped_all_supervised(rig)


def test_tailscale_late_the_set_is_not_started_until_the_protected_addresses_are_live(rig):
    rig.mutate(
        lambda s: [
            c.update(running=False) for c in s["containers"].values() if c["service"] in SUPERVISED
        ]
    )
    rig.flag("targets_down")
    for _ in range(2):
        rig.once()
    assert (
        stopped_all_supervised(rig) and rig.state.startswith("waiting") and "TARGETS" in rig.state
    )
    assert not rig.latched
    rig.flag("targets_down", False)  # tailscaled is up, its address exists
    rig.once()
    assert all(rig.is_running(s) for s in SUPERVISED) and rig.state.startswith("ok")


def test_a_tailscale_restart_while_running_does_not_stop_the_stack(rig):
    """The address disappearing is not a loss of isolation (the guard still covers the range)."""
    rig.flag("targets_down")
    r = rig.once()
    assert r.returncode == 0 and rig.mutating_calls() == [] and rig.state.startswith("ok")


def test_a_guard_conf_changed_under_a_running_release_stops_the_set_and_waits(rig):
    (rig.base / "deploy" / "host-egress-guard.conf").write_text("DNS=1.1.1.1\n")
    r = rig.once()
    assert r.returncode == 1 and stopped_all_supervised(rig) and not rig.latched
    assert "DNS-CONF" in rig.state
    (rig.base / "deploy" / "host-egress-guard.conf").write_text("DNS=10.0.2.3\n")
    rig.once()
    assert all(rig.is_running(s) for s in SUPERVISED)


def test_a_helper_that_became_writable_is_not_trusted(rig):
    g = rig.base / "deploy" / "host-egress-guard.sh"
    g.chmod(0o775)
    r = rig.once()
    assert r.returncode == 1 and stopped_all_supervised(rig) and "TRUST" in rig.state
    g.chmod(0o755)
    rig.once()
    assert all(rig.is_running(s) for s in SUPERVISED)


def test_flapping_latches_instead_of_cycling_forever(rig):
    for i in range(3):
        rig.flag("guard_broken")
        rig.once()
        if rig.latched:
            break
    assert rig.latched and "FLAPPING" in rig.latch_reason()
    assert stopped_all_supervised(rig)


# ============================ desired state, deploy lock, supervision ============================
def test_containers_started_outside_a_deploy_are_stopped(rig):
    rig.under_deploy_lock("desired", "stopped")
    r = rig.once()
    assert r.returncode == 1 and rig.latched and "DESIRED" in rig.latch_reason()
    assert stopped_all_supervised(rig)


def test_a_stack_the_deploy_stopped_stays_stopped_without_alarm(rig):
    rig.under_deploy_lock("desired", "stopped")
    rig.mutate(
        lambda s: [
            c.update(running=False) for c in s["containers"].values() if c["service"] in SUPERVISED
        ]
    )
    r = rig.once()
    assert r.returncode == 0 and not rig.latched and rig.state.startswith("stopped")
    assert rig.mutating_calls() == []


def test_while_a_deploy_holds_the_lock_nothing_is_touched(rig):
    rig.attach("agent-codex", "egress_claude_1")  # a violation that WOULD latch
    with rig.deploy_locks():
        r = rig.once()
    assert r.returncode == 0 and rig.state.startswith("paused")
    assert rig.mutating_calls() == [] and not rig.latched
    assert int((rig.state_dir / "heartbeat").read_text()) > 0  # still alive
    assert rig.once().returncode == 1 and rig.latched  # the lock was released


def test_a_deploy_lock_held_for_too_long_is_a_hung_deploy_and_does_not_disable_containment(rig):
    rig.attach("agent-codex", "egress_claude_1")
    with rig.deploy_locks():
        old = time.time() - 7200
        os.utime(rig.action_lock, (old, old))
        r = rig.once(HUNTER_CONTAINMENT_MAX_DEPLOY_PAUSE="600")
    assert r.returncode == 1 and rig.latched and "DEPLOY-LOCK" in rig.log


def test_a_crashed_supervised_service_is_restarted_but_not_in_a_tight_loop(rig):
    rig.stop_service("discovery")
    assert rig.once().returncode == 0
    assert rig.is_running("discovery") and "START" in rig.log
    rig.stop_service("discovery")
    rig.clear_events()
    rig.once()
    assert not rig.is_running("discovery")  # inside the back-off window
    assert rig.once(HUNTER_CONTAINMENT_RESTART_BACKOFF="0").returncode == 0
    assert rig.is_running("discovery")


def test_a_crash_does_not_bypass_the_prerequisites(rig):
    rig.stop_service("discovery")
    rig.flag("guard_broken")
    rig.flag("guard_unrepairable")
    rig.once()
    assert stopped_all_supervised(
        rig
    )  # the guard is wrong: the rest of the set is stopped, not started


def test_docker_down_is_unverified_and_changes_nothing(rig):
    rig.flag("docker_down")
    r = rig.once()
    assert r.returncode == 0 or r.returncode == 2
    assert rig.state.startswith("unverified") and not rig.latched


def test_a_hanging_docker_is_cut_off_and_reported(rig):
    rig.flag("docker_hang")
    start = time.time()
    rig.once(HUNTER_CONTAINMENT_DOCKER_TIMEOUT="1")
    assert time.time() - start < 20
    assert rig.state.startswith("unverified")


def test_there_is_no_cycle_without_a_committed_release(tmp_path):
    r = Rig(tmp_path)
    out = r.once()
    assert out.returncode == 0 and r.state.startswith("idle")
    assert r.mutating_calls() == []


# =============================== commands ===============================
def test_status_reports_the_heartbeat_and_the_latch(rig):
    rig.once()
    ok = rig.run("status", "--require-active")
    assert ok.returncode == 0 and "state: ok" in ok.stdout
    (rig.state_dir / "heartbeat").write_text(str(int(time.time()) - 600))
    stale = rig.run("status", "--require-active")
    assert stale.returncode == 20 and "not running" in stale.stderr
    rig.once()
    rig.attach("agent-codex", "egress_claude_1")
    rig.once()
    latched = rig.run("status", "--require-active")
    assert latched.returncode == 21 and "LATCHED" in latched.stderr and "latch:" in latched.stdout


def test_quarantine_without_latch_is_the_dead_man_switch_and_recovers_on_the_next_cycle(rig):
    r = rig.run("quarantine", "--reason", "watchdog-stopped", "--no-latch")
    assert r.returncode == 0 and stopped_all_supervised(rig) and not rig.latched
    assert rig.is_running("postgres")
    rig.once()
    assert all(rig.is_running(s) for s in SUPERVISED)


def test_quarantine_with_latch_requires_a_reset(rig):
    assert rig.run("quarantine", "--reason", "operator says so").returncode == 0
    assert rig.latched and stopped_all_supervised(rig)
    rig.once()
    assert stopped_all_supervised(rig)


def test_reset_refuses_while_the_unauthorised_endpoint_is_still_there_then_restores(rig):
    rig.mutate(lambda s: s["containers"]["c-adhoc"]["nets"].append("net-agent_codex"))
    rig.flag("disconnect_fails")
    rig.once()
    assert rig.latched
    refused = rig.run("reset")
    assert refused.returncode == 1 and "ATTACH-FOREIGN" in refused.stderr and rig.latched
    rig.flag("disconnect_fails", False)
    done = rig.run("reset", "--disconnect-foreign")
    assert done.returncode == 0, done.stderr
    assert not rig.latched
    rig.once()
    assert all(rig.is_running(s) for s in SUPERVISED)


def test_reset_refuses_while_the_guard_is_not_in_place(rig):
    rig.attach("agent-codex", "egress_claude_1")
    rig.once()
    rig.flag("guard_broken")
    r = rig.run("reset", "--disconnect-foreign")
    assert r.returncode == 1 and "GUARD" in r.stderr and rig.latched


def test_check_is_read_only_and_names_every_finding(rig):
    rig.attach("agent-codex", "egress_claude_1")
    rig.set_resolv("api", "nameserver 127.0.0.11\n# ExtServers: [host(192.168.1.1)]\n")
    rig.clear_events()
    r = rig.run("check")
    assert r.returncode == 10
    assert "ATTACH-UNEXPECTED" in r.stdout and "DNS-RT" in r.stdout
    assert rig.mutating_calls() == [] and not rig.latched
    assert all(rig.is_running(s) for s in SUPERVISED)


def test_only_the_project_s_own_rootless_daemon_is_ever_addressed(rig):
    code = "\n".join(
        ln for ln in SCRIPT.read_text().splitlines() if not ln.lstrip().startswith("#")
    )
    assert "/var/run/docker.sock" not in code and "/run/docker.sock" not in code
    for verb in (
        "docker rm",
        "docker rmi",
        "docker system",
        "docker volume",
        "ufw",
        "tailscale ",
        "iptables ",
        "systemctl",
        "docker network rm",
        "docker run",
        "docker exec",
    ):
        assert verb not in code, verb


# =============================== the watch loop ===============================
def test_the_loop_reacts_to_a_docker_event_long_before_the_next_poll(rig):
    p = subprocess.Popen(
        ["bash", str(SCRIPT), "watch", "--interval", "30"],
        env=rig.env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.time() + 15
        while time.time() < deadline and not (rig.state_dir / "state").exists():
            time.sleep(0.1)
        assert rig.state.startswith("ok")
        rig.attach("agent-codex", "egress_claude_1")
        (rig.stub / "events.trigger").write_text("")  # `docker events` reports a connect
        deadline = time.time() + 15
        while time.time() < deadline and not (rig.latched and stopped_all_supervised(rig)):
            time.sleep(
                0.1
            )  # the latch is written FIRST (crash safety); the cut and the stop follow
        assert rig.latched and stopped_all_supervised(rig)
    finally:
        p.terminate()
        p.wait(timeout=10)


def test_a_host_address_event_triggers_a_cycle_too(rig):
    p = subprocess.Popen(
        ["bash", str(SCRIPT), "watch", "--interval", "30"],
        env=rig.env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.time() + 15
        while time.time() < deadline and not (rig.state_dir / "state").exists():
            time.sleep(0.1)
        rig.flag("guard_broken")  # a new address made `status` fail
        (rig.stub / "ip.trigger").write_text("")  # `ip monitor` reports it
        deadline = time.time() + 20
        while time.time() < deadline and "GUARD-REPAIRED" not in rig.log:
            time.sleep(0.1)
        assert "GUARD-REPAIRED" in rig.log
    finally:
        p.terminate()
        p.wait(timeout=10)


def test_a_second_watcher_refuses_to_run(rig):
    p = subprocess.Popen(
        ["bash", str(SCRIPT), "watch", "--interval", "30"],
        env=rig.env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.time() + 15
        while time.time() < deadline and not (rig.state_dir / "state").exists():
            time.sleep(0.1)
        r = rig.run("watch", "--interval", "30")
        assert r.returncode == 1 and "another instance" in r.stderr
    finally:
        p.terminate()
        p.wait(timeout=10)


def test_test_mode_cannot_be_aimed_at_the_production_directory(tmp_path):
    for base in ("/opt/internship-hunter", "/opt/internship-hunter/x", ""):
        r = subprocess.run(
            ["bash", str(SCRIPT), "check"],
            capture_output=True,
            text=True,
            env={
                "PATH": os.environ["PATH"],
                "HUNTER_CONTAINMENT_TEST_MODE": "1",
                "HUNTER_BASE": base,
            },
        )
        assert r.returncode == 2 and "requires HUNTER_BASE outside" in r.stderr


def test_the_script_is_executable_and_the_state_is_private(rig):
    rig.once()
    assert stat.S_IMODE(rig.state_dir.stat().st_mode) == 0o700


# ============================ the systemd user unit ============================
UNIT = ROOT / "deploy" / "systemd" / "hunter-containment.service"


def unit_directives():
    out = {}
    for ln in UNIT.read_text().splitlines():
        if ln.strip() and not ln.startswith(("#", "[")) and "=" in ln:
            k, v = ln.split("=", 1)
            out.setdefault(k.strip(), []).append(v.strip())
    return out


def test_the_unit_is_a_notify_service_with_a_watchdog_and_a_dead_man_switch():
    d = unit_directives()
    assert d["Type"] == ["notify"] and d["NotifyAccess"] == ["all"]
    assert d["Restart"] == ["always"] and int(d["WatchdogSec"][0]) >= 60
    assert d["ExecStart"] == [
        "/opt/internship-hunter/deploy/runtime-containment.sh watch --interval 10"
    ]
    # whatever ends the process stops the supervised set; a restart is not an incident
    assert d["ExecStopPost"] == [
        "/opt/internship-hunter/deploy/runtime-containment.sh quarantine "
        "--reason watchdog-stopped --no-latch"
    ]
    assert d["After"] == ["docker.service"] and "NoNewPrivileges" in d


def test_the_unit_runs_only_the_root_owned_copy_and_never_a_release_s_script():
    text = UNIT.read_text()
    for ln in text.splitlines():
        if ln.startswith(("ExecStart", "ExecStopPost")):
            assert "/opt/internship-hunter/deploy/" in ln and "/releases/" not in ln
    assert "docker.sock" not in text and "sudo" not in text


def test_the_script_reports_to_systemd_every_cycle_and_while_waiting_for_a_slow_start():
    text = SCRIPT.read_text()
    assert "WATCHDOG=1" in text and "--ready" in text
    # the long waits keep the heartbeat alive, otherwise WatchdogSec would kill a slow start
    wait = text[text.index("healthy_wait()") : text.index("start_services()")]
    assert "beat" in wait


# ============ PR #13 re-review: locks, address drift, quarantine order, commit --check ============
def try_flock(path, wait=0.0):
    """True if the lock was free (taken and released at once); with `wait`, if it became free in
    time."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT)
    try:
        end = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fd, fcntl.LOCK_UN)
                return True
            except BlockingIOError:
                if time.monotonic() >= end:
                    return False
                time.sleep(0.02)
    finally:
        os.close(fd)


def watching(rig, interval=1, **env):
    return subprocess.Popen(
        ["bash", str(SCRIPT), "watch", "--interval", str(interval)],
        env=rig.env(**env),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def stop_watching(p):
    p.terminate()
    p.wait(timeout=10)


# ---- 1. LOCK: a deploy must never be refused because the watchdog is checking ----
def test_LOCK_a_running_watchdog_never_makes_a_deploy_lock_attempt_fail(rig):
    """What remote-deploy.sh does first is `flock -n` on deploy.lock. With a slow daemon (every
    cycle takes
    ~1 s) and a 1 s interval the old watchdog held that lock for most of the time (87% refused in
    the QA lab)."""
    p = watching(rig, interval=1, STUB_DOCKER_DELAY="0.4")
    try:
        deadline = time.time() + 15
        while time.time() < deadline and not (rig.state_dir / "state").exists():
            time.sleep(0.1)
        attempts = refused_deploy = refused_action = 0
        end = time.monotonic() + 8
        while time.monotonic() < end:
            attempts += 1
            refused_deploy += not try_flock(rig.lock)
            refused_action += not try_flock(rig.action_lock)
            time.sleep(0.05)
    finally:
        stop_watching(p)
    assert attempts > 50
    assert refused_deploy == 0, f"{refused_deploy}/{attempts} deploy-lock attempts found it taken"
    assert refused_action == 0, (
        f"{refused_action}/{attempts} action-lock attempts: a healthy cycle must take no lock"
    )


def test_LOCK_the_watchdog_acts_under_the_action_lock_only_and_a_deploy_waits_for_it(rig):
    """While the watchdog is stopping the set it holds the ACTION lock (a deploy waits for it)
    and never the
    deploy lock (a second deploy is still told 'another deploy is running' by flock -n on ITS
    lock, not by us)."""
    rig.attach("agent-codex", "egress_claude_1")
    (rig.stub / "slow_stop").write_text("3")
    p = subprocess.Popen(
        ["bash", str(SCRIPT), "once"],
        env=rig.env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.time() + 15
        while time.time() < deadline and not any("docker stop" in e for e in rig.events):
            time.sleep(0.05)
        assert any("docker stop" in e for e in rig.events), "the watchdog never reached its stop"
        assert try_flock(rig.lock), "the watchdog holds the DEPLOY lock while it acts"
        assert not try_flock(rig.action_lock), "an action in flight must hold the action lock"
        t0 = time.monotonic()
        assert try_flock(rig.action_lock, wait=20), "the action lock was never released"
        print(f"\ndeploy waited {time.monotonic() - t0:.1f}s for the in-flight action")
    finally:
        p.wait(timeout=30)
    assert rig.latched and stopped_all_supervised(rig)


def test_LOCK_a_decision_is_remade_on_a_fresh_snapshot_after_the_lock_was_taken(rig):
    """The first observation sees a hot attachment; by the time the watchdog holds the lock a
    deploy has
    replaced the containers and the endpoint is gone. It must NOT latch on the stale observation."""
    rig.attach("agent-codex", "egress_claude_1")
    r = rig.once(
        STUB_HEAL_AT_PS_CALL="2"
    )  # the 2nd `docker ps` (after the lock) sees a clean stack
    assert r.returncode == 0, r.stderr
    assert not rig.latched and all(rig.is_running(s) for s in SUPERVISED)
    assert rig.mutating_calls() == []


def test_LOCK_a_busy_action_lock_makes_the_cycle_yield_without_touching_anything(rig):
    rig.attach("agent-codex", "egress_claude_1")
    with rig.deploy_locks():
        r = rig.once()
    assert r.returncode == 0 and rig.state.startswith("paused")
    assert rig.mutating_calls() == [] and not rig.latched


def test_LOCK_reset_waits_briefly_for_the_action_lock_and_then_says_why_it_failed(rig):
    rig.attach("agent-codex", "egress_claude_1")
    rig.once()
    assert rig.latched
    with open(rig.action_lock, "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        t0 = time.monotonic()
        r = rig.run("reset", timeout=60)
    assert r.returncode == 4 and "action lock is held" in r.stderr
    assert (
        "or the watchdog is stopping/starting" in r.stderr
    )  # no longer claims a deploy is the only reason
    assert time.monotonic() - t0 >= 25


# ---- 2. ADDR: a host-address change is absorbed, not an outage ----
def test_ADDR_a_stale_host_address_set_is_absorbed_without_stopping_anything(rig):
    rig.flag("guard_stale")
    r = rig.once()
    assert r.returncode == 0, r.stderr
    assert rig.mutating_calls() == [] and all(rig.is_running(s) for s in SUPERVISED)
    assert "GUARD-ADDRESS-ABSORBED" in rig.log and not rig.latched
    assert not (rig.state_dir / "flaps").exists()
    assert any(e == "guard apply --wait 20" for e in rig.events)
    assert rig.state.startswith("ok")


def test_ADDR_the_repair_is_verified_before_the_cycle_is_declared_healthy(rig):
    rig.flag("guard_stale")
    rig.once()
    ev = rig.events
    applied = max(i for i, e in enumerate(ev) if e.startswith("guard apply"))
    assert any(e == "guard status" for e in ev[applied + 1 :]), ev


def test_ADDR_ten_address_changes_never_latch_the_stack(rig):
    for _ in range(10):
        rig.flag("guard_stale")
        assert rig.once().returncode == 0
    assert not rig.latched and not (rig.state_dir / "flaps").exists()
    assert all(rig.is_running(s) for s in SUPERVISED)
    assert rig.log.count("GUARD-ADDRESS-ABSORBED") == 10


def test_ADDR_if_the_repair_does_not_hold_the_set_is_stopped_after_all(rig):
    rig.flag("guard_stale")
    rig.flag("guard_unrepairable")
    r = rig.once()
    assert r.returncode == 1 and stopped_all_supervised(rig)
    assert "GUARD-UNREPAIRABLE" in rig.log and "QUARANTINE" in rig.log
    assert not rig.latched  # one failed repair is a quarantine, not an incident
    rig.flag("guard_unrepairable", False)
    rig.once()
    assert all(rig.is_running(s) for s in SUPERVISED)


def test_ADDR_a_structural_guard_problem_is_still_stop_first(rig):
    """Tampered or missing rules (exit 1, not 3) keep the earlier behaviour: stop, repair,
    verify, restart."""
    rig.flag("guard_broken")
    rig.once()
    ev = [e for e in rig.events if e.startswith(("guard apply", "docker stop"))]
    assert ev.index(next(e for e in ev if e.startswith("docker stop"))) < ev.index(
        "guard apply --wait 20"
    )


def test_ADDR_address_drift_next_to_another_problem_is_not_waved_through(rig):
    rig.flag("guard_stale")
    rig.flag("targets_down")  # irrelevant while running, so only the drift remains...
    assert rig.once().returncode == 0
    (rig.base / "deploy" / "host-egress-guard.conf").write_text(
        "DNS=1.1.1.1\n"
    )  # ...but a DNS-CONF problem too
    rig.flag("guard_stale")
    r = rig.once()
    assert r.returncode == 1 and stopped_all_supervised(rig)


# ---- 3. ORDER: latch, cut the hostile route, then stop ----
def test_ORDER_the_hostile_endpoint_is_removed_before_anything_is_stopped(rig):
    rig.attach("agent-codex", "egress_claude_1")
    rig.once()
    ev = rig.events
    cut = next(i for i, e in enumerate(ev) if "network disconnect" in e)
    stop = next(i for i, e in enumerate(ev) if e.startswith("docker stop"))
    assert cut < stop, ev
    assert stopped_all_supervised(rig) and rig.latched


def test_ORDER_the_intent_is_on_disk_before_the_first_docker_mutation(rig):
    rig.attach("agent-codex", "egress_claude_1")
    rig.once()
    assert "note disconnect latch_present=True" in rig.events


def test_ORDER_the_same_holds_when_the_latch_is_already_set_and_someone_attaches_again(rig):
    rig.attach("agent-codex", "egress_claude_1")
    rig.once()
    rig.clear_events()
    rig.mutate(lambda s: s["containers"]["c-api"].update(running=True))
    rig.attach("api", "agent_codex")
    rig.once()
    ev = rig.events
    cut = next(i for i, e in enumerate(ev) if "network disconnect" in e)
    stop = next(i for i, e in enumerate(ev) if e.startswith("docker stop"))
    assert cut < stop, ev


def test_ORDER_an_endpoint_that_cannot_be_removed_gets_its_container_killed_and_the_set_still_stops(
    rig,
):
    rig.attach("agent-codex", "egress_claude_1")
    rig.flag("disconnect_fails")
    r = rig.once()
    assert r.returncode == 1 and rig.latched
    assert stopped_all_supervised(rig)
    assert "DISCONNECT-FAILED" in rig.log and "KILLED" in rig.log
    assert "could NOT be removed" in rig.log
    ev = rig.events
    kill = next(i for i, e in enumerate(ev) if e.startswith("docker kill"))
    stop = next(i for i, e in enumerate(ev) if e.startswith("docker stop"))
    assert kill < stop


def test_ORDER_a_foreign_endpoint_that_cannot_be_removed_does_not_get_its_container_killed(rig):
    rig.mutate(lambda s: s["containers"]["c-adhoc"]["nets"].append("net-agent_codex"))
    rig.flag("disconnect_fails")
    rig.once()
    assert rig.latched and stopped_all_supervised(rig)
    assert rig.docker_state()["containers"]["c-adhoc"]["running"] is True  # not ours: left alone
    assert "KILLED" not in rig.log


def test_ORDER_a_crash_between_the_cut_and_the_stop_does_not_fail_open(rig):
    """The process dies while `docker stop` is running. The extra endpoint is already gone, so
    the evidence that
    caused the latch has vanished: only the durable latch makes the next cycle finish the job."""
    rig.attach("agent-codex", "egress_claude_1")
    (rig.stub / "crash_on_stop").write_text("")
    p = subprocess.Popen(
        ["bash", str(SCRIPT), "once"],
        env=rig.env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    deadline = time.time() + 15
    while time.time() < deadline and not (rig.stub / "crash_marker").exists():
        time.sleep(0.05)
    assert (rig.stub / "crash_marker").exists()
    os.killpg(p.pid, signal.SIGKILL)  # the script and its docker stub die mid-stop
    p.wait(timeout=10)
    assert (
        "net-egress_claude_1" not in rig.docker_state()["containers"]["c-agent-codex"]["nets"]
    )  # evidence gone
    assert rig.latched  # ... but the intent survived
    assert not stopped_all_supervised(rig)  # (nothing was stopped yet)
    (rig.stub / "crash_on_stop").unlink()
    r = rig.once()
    assert r.returncode == 1 and stopped_all_supervised(rig) and rig.latched


# ---- 4. commit --check: could this release be put under containment? (read-only, no lock) ----
def test_commit_check_accepts_a_committable_release_and_writes_nothing(tmp_path):
    r = Rig(tmp_path)
    out = r.run(
        "commit",
        "--check",
        "--sha",
        SHA,
        "--release-dir",
        str(r.base / "releases" / SHA),
        "--",
        *r.args,
    )
    assert out.returncode == 0 and "can be put under runtime containment" in out.stdout, out.stderr
    assert not (r.state_dir / "contract.json").exists() and not (r.state_dir / "desired").exists()


@pytest.mark.parametrize("svc", ["api", "egress-codex", "agent-codex"])
def test_commit_check_refuses_a_release_that_predates_containment_without_changing_anything(
    tmp_path, svc
):
    r = Rig(tmp_path)
    out = r.run(
        "commit",
        "--check",
        "--sha",
        SHA,
        "--release-dir",
        str(r.base / "releases" / SHA),
        "--",
        *r.args,
        STUB_RESTART=f"{svc}=unless-stopped",
    )
    assert out.returncode == 11 and f"{svc} renders restart=unless-stopped" in out.stderr
    assert not (r.state_dir / "contract.json").exists()


def test_commit_check_needs_no_deploy_lock_and_does_not_disturb_a_committed_release(rig):
    before = (rig.state_dir / "contract.json").read_text()
    out = rig.run(
        "commit",
        "--check",
        "--sha",
        "b" * 40,
        "--release-dir",
        str(rig.base / "releases" / SHA),
        "--",
        *rig.args,
        STUB_RESTART="api=unless-stopped",
    )
    assert out.returncode == 11
    assert (rig.state_dir / "contract.json").read_text() == before


# ---- QUIET: only lifecycle events wake the loop (a healthcheck run is not news) ----
def test_QUIET_the_event_stream_is_filtered_to_lifecycle_events():
    text = SCRIPT.read_text()
    line = text[text.index("docker events") : text.index("--format", text.index("docker events"))]
    for ev in ("create", "start", "die", "destroy", "connect", "disconnect"):
        assert f"--filter event={ev}" in line, ev
    assert "exec_" not in line and "health_status" not in line


def test_ADDR_the_host_moving_again_right_after_the_apply_is_not_a_failed_repair(rig):
    rig.flag("guard_stale")
    (rig.stub / "guard_restale").write_text("2")  # the next two applies are overtaken
    r = rig.once()
    assert r.returncode == 0, r.stderr
    assert rig.mutating_calls() == [] and all(rig.is_running(s) for s in SUPERVISED)
    assert "GUARD-ADDRESS-ABSORBED" in rig.log and "GUARD-VERIFY-FAILED" not in rig.log
    assert [e for e in rig.events if e.startswith("guard apply")].__len__() == 3


def test_ADDR_a_host_that_never_stops_changing_ends_in_a_quarantine_not_a_loop(rig):
    rig.flag("guard_stale")
    (rig.stub / "guard_restale").write_text("99")
    r = rig.once()
    assert r.returncode == 1 and stopped_all_supervised(rig)
    assert "kept changing" in rig.log
    assert len([e for e in rig.events if e.startswith("guard apply")]) <= 12  # bounded


# ======================================================================================
# CONTRACT: a container that merely carries the project and service labels is not the
# release's container
# ======================================================================================
# Labels are free text (`docker run --label com.docker.compose.service=agent-codex`). What
# identifies a container of the release is everything the release's compose files say about
# it: the image (by content), the process, the capabilities, the security options, the
# mounts, the namespaces, the published ports.


def container(rig, svc):
    return rig.docker_state()["containers"][f"c-{svc}"]


def tweak(rig, svc, fn):
    def go(s):
        fn(s["containers"][f"c-{svc}"])

    rig.mutate(go)


def add_cap(*caps):
    return lambda c: c["host_config"].update(
        CapAdd=list(c["host_config"].get("CapAdd") or []) + list(caps)
    )


def hc(**kw):
    return lambda c: c["host_config"].update(kw)


def cfg(**kw):
    return lambda c: c["config"].update(kw)


def add_mount(**m):
    return lambda c: c["mounts"].append({"Type": "bind", "RW": True, **m})


IMPOSTERS = {
    "net_admin": add_cap("NET_ADMIN"),
    "net_admin_spelled_CAP_": add_cap("CAP_NET_ADMIN"),
    "sys_admin": add_cap("SYS_ADMIN"),
    "net_raw": add_cap("NET_RAW"),
    "sys_ptrace": add_cap("SYS_PTRACE"),
    "caps_not_dropped": hc(CapDrop=None),
    "only_some_caps_dropped": hc(CapDrop=["NET_BIND_SERVICE"]),
    "privileged": hc(Privileged=True),
    "host_root_mounted_ro": add_mount(Source="/", Destination="/host", RW=False),
    "host_etc_mounted": add_mount(Source="/etc", Destination="/mnt/etc"),
    "home_mounted": add_mount(Source="/home/hunter-deploy", Destination="/h"),
    "another_agents_home": lambda c: c["mounts"].append(
        {
            "Type": "volume",
            "Name": "internship-hunter_claude1_home",
            "Source": "/v/claude1",
            "Destination": "/other",
            "RW": True,
        }
    ),
    "docker_socket": add_mount(
        Source="/run/user/1001/docker.sock", Destination="/var/run/docker.sock"
    ),
    "extra_tmpfs": lambda c: c["mounts"].append(
        {"Type": "tmpfs", "Destination": "/dev/shm/x", "RW": True}
    ),
    "seccomp_unconfined": hc(SecurityOpt=["no-new-privileges:true", "seccomp=unconfined"]),
    "apparmor_unconfined": hc(SecurityOpt=["no-new-privileges:true", "apparmor=unconfined"]),
    "no_new_privileges_dropped": hc(SecurityOpt=None),
    "rootfs_flipped": lambda c: c["host_config"].update(
        ReadonlyRootfs=not c["host_config"]["ReadonlyRootfs"]
    ),
    "device": hc(Devices=[{"PathOnHost": "/dev/net/tun", "PathInContainer": "/dev/net/tun"}]),
    "sysctl": hc(Sysctls={"net.ipv4.ip_forward": "1"}),
    "host_pid": hc(PidMode="host"),
    "host_ipc": hc(IpcMode="host"),
    "host_uts": hc(UTSMode="host"),
    "host_userns": hc(UsernsMode="host"),
    "host_cgroupns": hc(CgroupnsMode="host"),
    "cgroup_parent": hc(CgroupParent="/system.slice"),
    "other_runtime": hc(Runtime="nvidia"),
    "extra_group": hc(GroupAdd=["0"]),
    "host_gateway_alias": hc(ExtraHosts=["host.docker.internal:host-gateway"]),
    "published_port": hc(PortBindings={"22/tcp": [{"HostIp": "0.0.0.0", "HostPort": "2222"}]}),
    "publish_all": hc(PublishAllPorts=True),
    "volumes_from": hc(VolumesFrom=["c-postgres"]),
    "links": hc(Links=["c-postgres:db"]),
    "network_mode_bridge": hc(NetworkMode="bridge"),
    "other_image": cfg(Image="alpine-local:3.20"),
    "same_tag_other_content": lambda c: c.update(image_id="sha256:" + "f" * 64),
    "other_command": cfg(Cmd=["sh", "-c", "sleep 600"]),
    "other_entrypoint": cfg(Entrypoint=["/bin/sh"]),
    "root_user": cfg(User="root"),
}
# the agent of the reported reproduction, a proxy (route out), the API (published port) and two
# services that have no route out at all
VICTIMS = ["agent-codex", "egress-codex", "api", "postgres", "scheduler"]


@pytest.mark.parametrize("how", sorted(IMPOSTERS))
@pytest.mark.parametrize("svc", VICTIMS)
def test_CONTRACT_a_container_with_the_right_labels_and_network_but_other_privileges_latches(
    rig, svc, how
):
    tweak(rig, svc, IMPOSTERS[how])
    r = rig.once()
    assert r.returncode == 1, (how, r.stderr[-400:])
    assert rig.latched and "SPEC" in rig.latch_reason() or "HOSTCFG" in rig.latch_reason(), (
        rig.latch_reason()
    )
    assert stopped_all_supervised(rig)
    assert not container(rig, svc)["running"], "the impostor itself must be stopped"
    assert rig.state.startswith("latched")


def test_CONTRACT_the_reported_impostor_next_to_the_genuine_agent_is_stopped_and_latches(rig):
    """Labels of agent-codex, its network, plus NET_ADMIN, no seccomp, the host's root mounted."""

    def add(s):
        c = dict(container(rig, "agent-codex"), name="imposter")
        c["host_config"] = dict(
            c["host_config"], CapAdd=["NET_ADMIN"], SecurityOpt=["seccomp=unconfined"]
        )
        c["mounts"] = [{"Type": "bind", "Source": "/", "Destination": "/host", "RW": False}]
        c["config"] = dict(c["config"], Image="alpine-local:3.20")
        s["containers"]["c-imposter"] = c

    rig.mutate(add)
    r = rig.once()
    assert r.returncode == 1 and rig.latched and "SPEC" in rig.latch_reason()
    s = rig.docker_state()["containers"]
    assert not s["c-imposter"]["running"] and not s["c-agent-codex"]["running"]
    assert stopped_all_supervised(rig)


def test_CONTRACT_a_genuine_container_does_not_hide_an_impostor_of_an_unsupervised_service(rig):
    """Only supervised services are the watchdog's to start, but every project container must be
    the release's: a `scheduler` with a host bind mount is stopped with the set."""
    tweak(rig, "scheduler", add_mount(Source="/", Destination="/host"))
    assert rig.once().returncode == 1
    assert rig.latched and not container(rig, "scheduler")["running"]


def test_CONTRACT_a_stopped_impostor_is_caught_before_the_watchdog_can_start_it(rig):
    """`compose start <service>` starts WHICHEVER container carries the labels."""
    rig.mutate(
        lambda s: [
            c.update(running=False) for c in s["containers"].values() if c["service"] in SUPERVISED
        ]
    )
    tweak(rig, "agent-codex", add_cap("NET_ADMIN"))
    r = rig.once()
    assert r.returncode == 1 and rig.latched and "SPEC" in rig.latch_reason()
    assert not any(" start " in e for e in rig.events if e.startswith("docker")), rig.events


def test_CONTRACT_a_latched_impostor_stays_blocked_after_reset_until_it_is_removed(rig):
    tweak(rig, "agent-codex", add_cap("NET_ADMIN"))
    assert rig.once().returncode == 1 and rig.latched
    r = rig.run("reset")
    assert r.returncode != 0 or rig.once().returncode == 1
    assert not container(rig, "agent-codex")["running"]
    rig.mutate(
        lambda s: s["containers"]["c-agent-codex"].update(host_config=genuine("agent-codex")[1])
    )
    r = rig.run("reset")
    assert r.returncode == 0, r.stderr + rig.log
    assert rig.once().returncode == 0 and not rig.latched


def test_CONTRACT_the_finding_names_what_differs(rig):
    tweak(rig, "agent-codex", add_cap("NET_ADMIN"))
    tweak(rig, "agent-codex", add_mount(Source="/", Destination="/host"))
    rig.once()
    why = rig.latch_reason()
    assert "cap_add" in why and "NET_ADMIN" in why and "mounts differ" in why and "/host" in why


# ---- the genuine article is accepted, in every shape a legitimate deployment gives it ----


def test_CONTRACT_a_container_recreated_by_compose_with_a_new_id_is_accepted(rig):
    """`docker compose up --force-recreate`: new id, same release, same everything."""

    def recreate(s):
        c = s["containers"].pop("c-agent-codex")
        s["containers"]["c-new0123"] = dict(c, name=c["name"])

    rig.mutate(recreate)
    assert rig.once().returncode == 0 and not rig.latched
    assert rig.mutating_calls() == []


def test_CONTRACT_every_service_of_the_real_compose_file_is_accepted(rig):
    assert set(COMPOSE["services"]) == {
        s["service"] for s in rig.docker_state()["containers"].values() if s["project"]
    }
    r = rig.run("check")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SPEC" not in r.stdout


def test_CONTRACT_an_anonymous_volume_the_image_declares_is_accepted_any_other_is_not(rig):
    anon = {
        "Type": "volume",
        "Name": "a" * 64,
        "Source": "/v/a",
        "Destination": "/var/lib/postgresql/data",
        "RW": True,
    }
    rig.mutate(
        lambda s: s["containers"]["c-scheduler"]["mounts"].append(anon)
    )  # not declared by the scheduler's image
    assert rig.once().returncode == 1 and rig.latched
    tweak(rig, "scheduler", lambda c: c["mounts"].pop())
    assert rig.run("reset").returncode == 0
    # the postgres image declares VOLUME /var/lib/postgresql/data: an anonymous volume at another
    # destination is not its own
    tweak(
        rig,
        "postgres",
        lambda c: c["mounts"].append(dict(anon, Destination="/var/lib/postgresql/x")),
    )
    assert rig.once().returncode == 1
    tweak(rig, "postgres", lambda c: c["mounts"].pop())
    assert rig.run("reset").returncode == 0
    # an anonymous volume at a destination the IMAGE declares is Docker's own doing when the release
    # does not mount that path itself
    path = rig.state_dir / "contract.json"
    d = json.loads(path.read_text())
    d["services"]["postgres"]["spec"]["volumes"] = []
    path.write_text(json.dumps(d))
    tweak(
        rig,
        "postgres",
        lambda c: c.update(mounts=[m for m in c["mounts"] if m["Type"] == "tmpfs"] + [dict(anon)]),
    )
    assert rig.run("reset").returncode == 0
    assert rig.once().returncode == 0 and not rig.latched


def test_CONTRACT_a_deploy_in_progress_is_not_an_impostor_and_the_commit_accepts_the_new_release(
    rig,
):
    """Release B's containers do not match release A's contract. While the deploy holds the lock the
    watchdog touches nothing; once the deploy committed B they are the release."""
    sha_b = "b" * 40

    def to_b(s):
        s["images"].update(release_images(sha_b))
        for name in COMPOSE["services"]:
            c = s["containers"][f"c-{name}"]
            c["config"], c["host_config"], c["mounts"], c["image_id"] = genuine(name, sha_b)
        return s

    rig.mutate(to_b)
    (rig.stub / "compose-template.json").write_text(json.dumps(template(sha_b)))
    with rig.deploy_locks():
        r = rig.once()
        assert r.returncode == 0 and rig.mutating_calls() == [] and not rig.latched
    # outside a deploy, release A's contract rejects release B's containers (a deploy that
    # died before its commit) ...
    assert rig.once().returncode == 1 and rig.latched
    assert rig.run("reset").returncode == 1
    # ... after the deploy committed release B they are accepted
    r = rig.under_deploy_lock(
        "commit", "--sha", sha_b, "--release-dir", str(rig.base / "releases" / SHA),
        "--forbidden", "100.107.22.84:22", "--protected-ips", "100.107.22.84",
        "--rootful", "172.17.0.2:9", "--", *rig.args,
    )  # fmt: skip
    assert r.returncode == 0, r.stderr
    assert rig.run("reset").returncode == 0
    assert rig.once().returncode == 0 and not rig.latched


def test_CONTRACT_a_rollback_to_the_previous_release_is_accepted_by_its_own_contract(rig):
    sha_b = "b" * 40
    rig.mutate(lambda s: s["images"].update(release_images(sha_b)))
    (rig.stub / "compose-template.json").write_text(json.dumps(template(sha_b)))
    c = rig.under_deploy_lock(
        "commit", "--sha", sha_b, "--release-dir", str(rig.base / "releases" / SHA),
        "--forbidden", "100.107.22.84:22", "--protected-ips", "100.107.22.84",
        "--rootful", "172.17.0.2:9", "--", *rig.args,
    )  # fmt: skip
    assert c.returncode == 0
    # the stack still runs release A's containers: B's contract calls them impostors ...
    assert rig.once().returncode == 1 and rig.latched
    # ... and a rollback commits release A again
    (rig.stub / "compose-template.json").write_text(json.dumps(template(SHA)))
    assert rig.commit().returncode == 0
    assert rig.run("reset").returncode == 0
    assert rig.once().returncode == 0 and not rig.latched


def test_CONTRACT_a_tag_moved_after_the_commit_is_not_the_release(rig):
    """The contract pins the image CONTENT it saw at commit time."""
    rig.mutate(
        lambda s: s["images"][f"internship-hunter-agent:{SHA}"].update(Id="sha256:" + "e" * 64)
    )
    assert rig.once().returncode == 0, (
        "moving the tag alone changes nothing: the containers keep their image"
    )
    tweak(rig, "agent-codex", lambda c: c.update(image_id="sha256:" + "e" * 64))
    assert rig.once().returncode == 1 and "image id" in rig.latch_reason()


def test_CONTRACT_the_runtime_is_the_daemons_default_whatever_its_name(rig):
    assert rig.once(STUB_DEFAULT_RUNTIME="runcw").returncode == 1, (
        "a runc container on a runcw daemon is not the default"
    )
    assert rig.run("reset", STUB_DEFAULT_RUNTIME="runcw").returncode == 1
    for svc in COMPOSE["services"]:
        tweak(rig, svc, hc(Runtime="runcw"))
    assert rig.run("reset", STUB_DEFAULT_RUNTIME="runcw").returncode == 0
    assert rig.once(STUB_DEFAULT_RUNTIME="runcw").returncode == 0


def test_CONTRACT_a_leftover_container_of_another_release_is_caught_before_it_can_be_started(rig):
    """What a deploy killed halfway can leave behind: a stopped container of the old release
    carrying the service label."""

    def leftover(s):
        s["containers"]["c-old"] = dict(
            s["containers"]["c-egress-codex"], name="deadbeef_internship-hunter-egress-codex-1"
        )
        s["containers"]["c-old"].update(running=False, image_id="sha256:" + "1" * 64)

    rig.mutate(leftover)
    assert rig.once().returncode == 1 and rig.latched and "image id" in rig.latch_reason()


def test_CONTRACT_a_container_that_vanishes_during_the_snapshot_is_unverified_not_a_violation(rig):
    (rig.stub / "ghost").write_text("")
    r = rig.once()
    assert r.returncode == 2 and not rig.latched and rig.mutating_calls() == []
    (rig.stub / "ghost").unlink()
    assert rig.once().returncode == 0


def test_CONTRACT_a_contract_from_before_the_spec_existed_warns_and_does_not_stop_the_stack(rig):
    path = rig.state_dir / "contract.json"
    d = json.loads(path.read_text())
    d["version"] = 1
    for svc in d["services"].values():
        svc.pop("spec")
    path.write_text(json.dumps(d))
    tweak(rig, "agent-codex", add_cap("NET_ADMIN"))  # not detectable by a legacy contract ...
    r = rig.once()
    assert r.returncode == 0 and not rig.latched
    assert "SPEC-LEGACY" in rig.log  # ... but loudly said so, once per cycle
    assert rig.mutating_calls() == []


# ---- the contract is built from the release, and refuses a release that asks for too much ----


def committed(rig):
    return json.loads((rig.state_dir / "contract.json").read_text())


def test_CONTRACT_commit_pins_what_the_release_and_the_image_store_say(rig):
    d = committed(rig)
    sp = d["services"]["agent-codex"]["spec"]
    assert d["version"] == 2
    assert sp["image"] == f"internship-hunter-agent:{SHA}"
    assert sp["image_id"] == image_id(sp["image"])
    assert sp["cap_drop"] == ["ALL"] and sp["cap_add"] == [] and sp["read_only"] is True
    assert sp["security_opt"] == ["no-new-privileges:true"] and sp["tmpfs"] == ["/tmp"]
    assert sp["volumes"] == [
        {
            "type": "volume",
            "source": "internship-hunter_codex_home",
            "target": "/home/hunter",
            "ro": False,
        }
    ]
    assert sp["network_names"] == ["internship-hunter_agent_codex"]
    assert d["services"]["postgres"]["spec"]["cap_add"] == [
        "CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"
    ]  # fmt: skip
    assert d["services"]["api"]["spec"]["ports"] == ["127.0.0.1|18000|8000/tcp"]


@pytest.mark.parametrize(
    "field,value,fragment",
    [
        ("cap_add", ["NET_ADMIN"], "NET_ADMIN"),
        ("cap_add", ["CAP_SYS_ADMIN"], "SYS_ADMIN"),
        ("cap_add", ["ALL"], "ALL"),
        ("security_opt", ["seccomp=unconfined"], "unconfined"),
        ("security_opt", ["label:disable"], "unconfined"),
        ("devices", ["/dev/net/tun:/dev/net/tun"], "devices"),
        ("volumes_from", ["postgres"], "volumes_from"),
        ("links", ["postgres"], "volumes_from"),
        ("pid", "host", "host pid"),
        ("ipc", "host", "host ipc"),
        ("userns_mode", "host", "host userns_mode"),
        (
            "volumes",
            [{"type": "bind", "source": "/run/user/1/docker.sock", "target": "/s"}],
            "Docker socket",
        ),
        ("volumes", [{"type": "npipe", "source": "x", "target": "/s"}], "cannot verify"),
    ],
)
def test_CONTRACT_commit_refuses_a_release_that_asks_for_what_containment_will_not_accept(
    rig, field, value, fragment
):
    t = template()
    t["services"]["agent-codex"][field] = value
    (rig.stub / "compose-template.json").write_text(json.dumps(t))
    before = (rig.state_dir / "contract.json").read_text()
    r = rig.commit()
    assert r.returncode == 11 and fragment in r.stderr, r.stderr
    assert (rig.state_dir / "contract.json").read_text() == before


def test_CONTRACT_commit_refuses_an_image_the_store_does_not_have(rig):
    rig.mutate(lambda s: s["images"].pop(f"internship-hunter-agent:{SHA}"))
    r = rig.commit()
    assert r.returncode == 11 and "cannot be pinned" in r.stderr


def test_CONTRACT_commit_check_does_not_need_the_images(rig):
    """The pre-flight runs before the release's images are loaded."""
    rig.mutate(lambda s: s.update(images={}))
    r = rig.run(
        "commit", "--check", "--sha", "c" * 40, "--release-dir", str(rig.base / "releases" / SHA),
        "--", *rig.args,
    )  # fmt: skip
    assert r.returncode == 0, r.stderr
