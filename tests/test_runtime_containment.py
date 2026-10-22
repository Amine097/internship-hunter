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


def template():
    nets = {
        n: {"internal": bool((v or {}).get("internal"))} for n, v in COMPOSE["networks"].items()
    }
    services = {}
    for name, svc in COMPOSE["services"].items():
        services[name] = {
            "networks": {n: None for n in svc.get("networks", [])},
            "restart": svc.get("restart", "unless-stopped"),
        }
        if svc.get("dns"):
            services[name]["dns"] = list(svc["dns"])
    return {"networks": nets, "services": services}


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
        return {"Id": cid, "Name": "/" + c["name"], "Config": {"Labels": labels(c)},
                "State": {"Running": c["running"],
                          "Health": {"Status": c["health"]} if c["health"] != "none" else None},
                "NetworkSettings": {"Networks": nets}, "HostConfig": c["host_config"],
                "Mounts": [{"Source": m} for m in c["mounts"]], "ResolvConfPath": c["resolv"]}
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
        print("[name=seccomp name=rootless]"); sys.exit(0)
    if verb == "events":
        while True:
            if os.path.exists(D + "/events.trigger"):
                os.remove(D + "/events.trigger"); print("network connect", flush=True)
            time.sleep(0.1)
    s = load()
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
    if verb == "network":
        if args[1] == "ls":
            print("\\n".join(s["networks"])); sys.exit(0)
        if args[1] == "inspect":
            print(json.dumps([network_json(s, n) for n in args[2:]])); sys.exit(0)
        if args[1] == "disconnect":
            net, cid = args[-2], args[-1]
            if os.path.exists(D + "/disconnect_fails"):
                sys.exit(1)
            if net in s["containers"][cid]["nets"]:
                s["containers"][cid]["nets"].remove(net)
            save(s); sys.exit(0)
    if verb in ("stop", "kill"):
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
              echo active ;;
      apply)  [[ -e "$STUB_DIR/guard_unrepairable" ]] && exit 1
              rm -f "$STUB_DIR/guard_broken"; echo applied ;;
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
            containers[f"c-{name}"] = {
                "name": f"internship-hunter-{name}-1",
                "project": "internship-hunter",
                "service": name,
                "running": running,
                "health": "healthy" if name.startswith(("egress", "agent", "api")) else "none",
                "nets": [f"net-{n}" for n in svc.get("networks", [])],
                "host_config": {"NetworkMode": "default"},
                "mounts": [],
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
        return {"containers": containers, "networks": nets}

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

    def under_deploy_lock(self, *argv, **extra):
        """Run a command the way remote-deploy.sh does: while it holds deploy.lock."""
        self.lock.parent.mkdir(parents=True, exist_ok=True)
        with open(self.lock, "w") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
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
    with open(rig.lock, "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        r = rig.once()
    assert r.returncode == 0 and rig.state.startswith("paused")
    assert rig.mutating_calls() == [] and not rig.latched
    assert int((rig.state_dir / "heartbeat").read_text()) > 0  # still alive
    assert rig.once().returncode == 1 and rig.latched  # the lock was released


def test_a_deploy_lock_held_for_too_long_is_a_hung_deploy_and_does_not_disable_containment(rig):
    rig.attach("agent-codex", "egress_claude_1")
    with open(rig.lock, "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        old = time.time() - 7200
        os.utime(rig.lock, (old, old))
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
        while time.time() < deadline and not rig.latched:
            time.sleep(0.1)
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
