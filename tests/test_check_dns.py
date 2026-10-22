"""Behavioural tests of deploy/check-dns.sh against a MODELLED resolver.

`docker compose config` returns the topology of the real compose.yaml (HUNTER_DNS substituted);
`docker compose exec` runs the real in-container probe scripts locally, with name resolution,
direct DNS queries and /etc/resolv.conf answered by a model that can be damaged on purpose:
  STUB_ANNOTATION   svc=<text>      replaces the `# ExtServers: [...]` text of that service
  STUB_NAMESERVER   svc=<ip>        replaces the embedded resolver address in resolv.conf
  STUB_NO_ANNOTATION svc ...        resolv.conf without the annotation
  STUB_EXT_BROKEN   svc ...         services that cannot resolve public names (no guard exception)
  STUB_IN_RESOLVES  svc ...         internal-only services that DO resolve public names (a leak)
  STUB_DIRECT_OK    svc@ip ...      direct DNS query to ip is answered
  STUB_PROBE_DEAD   python|nslookup the raw-query probe of that flavour never receives any answer
  STUB_CTRL_BLOCKED svc ...         the network blocks that service's raw query to the resolver
  STUB_APPROVED     ip              the resolver the model answers (default 10.0.2.3)
  STUB_LEAK_PEER    svc=peer ...    the name resolves although no network is shared
  STUB_LOSE_PEER    svc=peer ...    the name does not resolve although a network is shared
  STUB_SELF_BROKEN  svc ...         not even the service's own name resolves
  STUB_NO_PYTHON / STUB_NO_NSLOOKUP / STUB_EXEC_FAIL / STUB_TRUNCATE / STUB_GARBAGE   tooling damage
The packet-level truth is established against a real rootless Docker in test_dns_rootless_lab.py.
"""

import json
import os
import re
import shutil
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "deploy" / "check-dns.sh"
pytestmark = pytest.mark.skipif(os.name != "posix", reason="shell scripts")

COMPOSE = yaml.safe_load((ROOT / "compose.yaml").read_text())
OUT = ["api", "discovery", "telegram", "egress-claude-1", "egress-claude-2", "egress-codex"]
IN = [
    "agent-claude-1",
    "agent-claude-2",
    "agent-codex",
    "postgres",
    "migrate",
    "scheduler",
    "session-controller",
]


def topology(mutate=None):
    nets = {
        n: {"internal": bool((v or {}).get("internal"))} for n, v in COMPOSE["networks"].items()
    }
    services = {}
    for name, svc in COMPOSE["services"].items():
        services[name] = {"networks": {n: None for n in svc.get("networks", [])}}
        if "dns" in svc:
            services[name]["dns"] = [
                d.replace("${HUNTER_DNS:-10.0.2.3}", "10.0.2.3") for d in svc["dns"]
            ]
    cfg = {"networks": nets, "services": services}
    if mutate:
        mutate(cfg)
    return cfg


DOCKER = textwrap.dedent("""\
    #!/usr/bin/env bash
    [[ "$1" == compose ]] || exit 99
    shift
    while [[ "$1" != exec && "$1" != config && "$1" != ps ]]; do shift; done
    if [[ "$1" == ps ]]; then
      python3 -c 'import json,os,sys
skip = os.environ.get("STUB_NOT_RUNNING", "").split()
for s in json.load(open(sys.argv[1]))["services"]:
    print(s) if s not in skip else None' "$STUB_DIR/config.json"
      exit 0
    fi
    if [[ "$1" == config ]]; then
      [[ -n "${STUB_CONFIG_FAIL:-}" ]] && exit 1
      cat "$STUB_DIR/config.json"; exit 0
    fi
    shift; [[ "$1" == -T ]] && shift
    svc="$1"; shift
    echo "exec $svc $1" >> "$STUB_DIR/log"
    if [[ " ${STUB_EXEC_FAIL:-} " == *" $svc "* ]]; then
      echo "service $svc is not running" >&2; exit 1
    fi
    export STUB_SVC="$svc" PYTHONPATH="$STUB_DIR/py" PATH="$STUB_DIR/bin:$PATH"
    has_python=1
    case "$svc" in egress-*) has_python=0 ;; esac
    [[ " ${STUB_NO_PYTHON:-} " == *" $svc "* ]] && has_python=0
    case "$1" in
      sh)
        if [[ "$2" == -c ]]; then                       # `command -v python`
          [[ "$has_python" == 1 ]] && exit 0 || exit 1
        fi
        shift; script="$(sed "s#/etc/resolv.conf#$STUB_DIR/resolv/$svc#g")"
        path="$STUB_DIR/bin:$PATH"
        [[ " ${STUB_NO_NSLOOKUP:-} " == *" $svc "* ]] && path="$STUB_DIR/nonslookup"
        out="$(printf '%s\\n' "$script" | PATH="$path" sh "$@")" ;;
      python)
        shift; script="$(sed "s#/etc/resolv.conf#$STUB_DIR/resolv/$svc#g")"
        out="$(printf '%s\\n' "$script" | python3 "$@")" ;;
      *) exit 98 ;;
    esac
    for s in ${STUB_TRUNCATE:-}; do [[ "$s" == "$svc" ]] && out="$(grep -v '^DONE' <<<"$out")"; done
    for s in ${STUB_GARBAGE:-}; do
      [[ "$s" == "$svc" ]] && out="$out"$'\\n'"Segmentation fault"
    done
    printf '%s\\n' "$out"
""")

# the model: one function, used by the python probe (getaddrinfo + UDP) and the fake nslookup
MODEL = textwrap.dedent("""\
    import json, os
    D = os.environ["STUB_DIR"]
    TOPO = json.load(open(D + "/config.json"))
    S = TOPO["services"]
    NETS = TOPO["networks"]
    def _words(name): return os.environ.get(name, "").split()
    def _pairs(name): return {tuple(p.split("=", 1)) for p in _words(name)}
    def is_out(svc):
        return any(not NETS[n].get("internal", False) for n in S[svc]["networks"])
    def resolves(svc, name):
        name = name.rstrip(".")
        if name in S:
            if name == svc:
                return svc not in _words("STUB_SELF_BROKEN")
            if (svc, name) in _pairs("STUB_LOSE_PEER"):
                return False
            if (svc, name) in _pairs("STUB_LEAK_PEER"):
                return True
            return bool(set(S[svc]["networks"]) & set(S[name]["networks"]))
        if is_out(svc):
            return svc not in _words("STUB_EXT_BROKEN")
        return svc in _words("STUB_IN_RESOLVES")
    def answered(svc, ip, tool):
        if f"{svc}@{ip}" in _words("STUB_DIRECT_OK"):
            return True
        if tool in _words("STUB_PROBE_DEAD"):          # a probe that can never receive an answer
            return False
        # the approved resolver answers the services whose network lets the query out
        return (
            is_out(svc)
            and ip == os.environ.get("STUB_APPROVED", "10.0.2.3")
            and svc not in _words("STUB_EXT_BROKEN")
            and svc not in _words("STUB_CTRL_BLOCKED")
        )
""")
SITECUSTOMIZE = textwrap.dedent("""\
    import os, socket
    from model import resolves, answered
    svc = os.environ.get("STUB_SVC", "")
    def _gai(host, *a, **k):
        if resolves(svc, host):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0))]
        raise socket.gaierror(socket.EAI_NONAME, "no such name")
    socket.getaddrinfo = _gai
    class _Udp:
        def __init__(self, *a, **k): self.q = None
        def settimeout(self, t): pass
        def sendto(self, data, addr): self.q = (data, addr[0])
        def recvfrom(self, n):
            data, ip = self.q
            if answered(svc, ip, "python"):
                return data[:2] + b"\\x81\\x80", (ip, 53)
            raise OSError("timed out")
        def close(self): pass
    _real = socket.socket
    socket.socket = lambda *a, **k: _Udp() if a[1:2] == (socket.SOCK_DGRAM,) else _real(*a, **k)
""")
NSLOOKUP = textwrap.dedent("""\
    #!/usr/bin/env python3
    import os, sys
    sys.path.insert(0, os.environ["STUB_DIR"] + "/py")
    from model import answered, resolves
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    name, server = args[0], (args[1] if len(args) > 1 else None)
    svc = os.environ["STUB_SVC"]
    ok = answered(svc, server, "nslookup") if server else resolves(svc, name)
    if ok:
        print("Server:\\t\\t127.0.0.11\\nAddress:\\t127.0.0.11:53\\n")
        print("Name:\\texample\\nAddress: 192.0.2.1")
        sys.exit(0)
    print("** server can't find %s: NXDOMAIN" % name)
    sys.exit(1)
""")


class Env:
    def __init__(self, tmp: Path, mutate=None):
        self.stub = tmp / "stub"
        self.bin = tmp / "bin"
        for d in (
            self.stub / "bin",
            self.stub / "py",
            self.stub / "resolv",
            self.stub / "nonslookup",
            self.bin,
        ):
            d.mkdir(parents=True)
        self.cfg = topology(mutate)
        (self.stub / "config.json").write_text(json.dumps(self.cfg))
        (self.stub / "py" / "model.py").write_text(MODEL)
        (self.stub / "py" / "sitecustomize.py").write_text(SITECUSTOMIZE)
        (self.stub / "bin" / "nslookup").write_text(NSLOOKUP)
        for tool in ("sh", "grep", "sed", "cat"):  # a PATH that has everything except nslookup
            (self.stub / "nonslookup" / tool).symlink_to(shutil.which(tool))
        (self.bin / "docker").write_text(DOCKER)
        ip = self.bin / "ip"
        ip.write_text('#!/bin/sh\necho "default via ${STUB_HOST_GATEWAY:-192.168.1.1} dev eth0"\n')
        for f in (*self.bin.iterdir(), self.stub / "bin" / "nslookup"):
            f.chmod(f.stat().st_mode | stat.S_IEXEC)
        for name, svc in self.cfg["services"].items():
            self.write_resolv(name)

    def write_resolv(self, name, extra=None):
        out = any(
            not self.cfg["networks"][n]["internal"] for n in self.cfg["services"][name]["networks"]
        )
        lines = [
            "# Generated by Docker Engine.",
            "nameserver 127.0.0.11",
            "search lan",
            "options ndots:0",
            "",
        ]
        lines.append("# Based on host file: '/etc/resolv.conf' (internal resolver)")
        lines.append("# ExtServers: [10.0.2.3]" if out else "# ExtServers: [host(192.168.1.1)]")
        lines.append("# Overrides: []")
        (self.stub / "resolv" / name).write_text("\n".join(lines) + "\n")

    def run(self, *args, **env):
        e = dict(os.environ)
        e.update({"PATH": f"{self.bin}:{os.environ['PATH']}", "STUB_DIR": str(self.stub)})
        for k in ("HUNTER_DNS", "SMOKE_DNS_EXPECT", "SMOKE_HOST_ISOLATION"):
            e.pop(k, None)
        e.update(env)
        for pair in e.get("STUB_ANNOTATION", "").split(";"):
            if pair:
                svc, text = pair.split("=", 1)
                p = self.stub / "resolv" / svc
                p.write_text(
                    re.sub(r"# ExtServers: \[.*\]", f"# ExtServers: [{text}]", p.read_text())
                )
        for pair in e.get("STUB_NAMESERVER", "").split():
            svc, ip = pair.split("=", 1)
            p = self.stub / "resolv" / svc
            p.write_text(p.read_text().replace("nameserver 127.0.0.11", f"nameserver {ip}"))
        for svc in e.get("STUB_NO_ANNOTATION", "").split():
            p = self.stub / "resolv" / svc
            p.write_text(re.sub(r"# ExtServers:.*\n", "", p.read_text()))
        return subprocess.run(
            ["bash", str(CHECK), "-p", "x", "-f", "compose.yaml", *args],
            capture_output=True,
            text=True,
            env=e,
            timeout=120,
        )


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def test_a_correctly_isolated_stack_passes(env):
    r = env.run()
    assert r.returncode == 0, r.stdout + r.stderr
    assert "6 service(s) with a route out use 10.0.2.3 from inside the container" in r.stdout
    assert "7 internal-only service(s) resolve nothing outside the project" in r.stdout


def test_every_service_is_probed_with_the_right_tool(env):
    assert env.run().returncode == 0
    execs = [ln.split()[1:] for ln in (env.stub / "log").read_text().splitlines()]
    probed = {svc for svc, what in execs if what in ("python", "sh")}
    assert probed == set(env.cfg["services"]) and len(execs) == 2 * len(env.cfg["services"])


@pytest.mark.parametrize("svc", OUT)
def test_a_service_whose_dns_goes_through_the_daemon_is_a_breach_even_if_it_resolves(env, svc):
    r = env.run(STUB_ANNOTATION=f"{svc}=host(192.168.1.1)")
    assert r.returncode == 1 and "breach" in r.stderr and "host(192.168.1.1)" in r.stderr
    assert (
        env.run(
            STUB_ANNOTATION=f"{svc}=host(192.168.1.1)", SMOKE_HOST_ISOLATION="report"
        ).returncode
        == 1
    )


def test_a_different_resolver_than_expected_is_a_breach(env):
    r = env.run(STUB_ANNOTATION="egress-codex=1.1.1.1")
    assert r.returncode == 1 and "expected [10.0.2.3]" in r.stderr
    assert env.run(SMOKE_DNS_EXPECT="1.1.1.1").returncode == 1  # expectation vs configured dns


def test_the_expected_resolver_comes_from_the_deploy_gate_or_hunter_dns(env):
    assert env.run(SMOKE_DNS_EXPECT="10.0.2.3", HUNTER_DNS="9.9.9.9").returncode == 0
    r = env.run(HUNTER_DNS="9.9.9.9")
    assert r.returncode == 1 and "configured dns is ['10.0.2.3']" in r.stderr


def test_a_route_out_without_an_explicit_resolver_is_a_breach():
    def drop(cfg):
        cfg["services"]["discovery"].pop("dns")

    import tempfile

    with tempfile.TemporaryDirectory() as d:
        e = Env(Path(d), drop)
        r = e.run()
        assert (
            r.returncode == 1
            and "discovery has a route out but its configured dns is EMPTY" in r.stderr
        )


def test_an_internal_only_service_with_a_resolver_is_a_breach():
    def add(cfg):
        cfg["services"]["agent-codex"]["dns"] = ["10.0.2.3"]

    import tempfile

    with tempfile.TemporaryDirectory() as d:
        r = Env(Path(d), add).run()
        assert r.returncode == 1 and "agent-codex is internal-only but has dns" in r.stderr


def test_broken_public_resolution_fails_in_enforce_and_warns_in_report(env):
    r = env.run(STUB_EXT_BROKEN="egress-codex discovery")
    assert r.returncode == 1 and "egress-codex cannot resolve example.com" in r.stderr
    r = env.run(STUB_EXT_BROKEN="egress-codex", SMOKE_HOST_ISOLATION="report")
    assert r.returncode == 0 and "WARN" in r.stderr and "NOT acceptable in production" in r.stderr


@pytest.mark.parametrize("svc", ["agent-claude-1", "agent-codex", "postgres", "scheduler"])
def test_an_internal_only_service_that_resolves_a_public_name_is_a_leak_in_every_mode(env, svc):
    for mode in ("enforce", "report"):
        r = env.run(STUB_IN_RESOLVES=svc, SMOKE_HOST_ISOLATION=mode)
        assert (
            r.returncode == 1 and f"{svc} is internal-only but resolves example.com" in r.stderr
        ), mode


def test_an_internal_only_service_that_gets_direct_dns_answers_is_a_leak(env):
    for ip in ("10.0.2.3", "1.1.1.1"):
        r = env.run(STUB_DIRECT_OK=f"agent-claude-2@{ip}", SMOKE_HOST_ISOLATION="report")
        assert r.returncode == 1 and f"gets DNS answers from {ip} directly" in r.stderr


def test_a_proxy_that_can_query_the_hosts_gateway_resolver_directly_is_reported(env):
    r = env.run(STUB_DIRECT_OK="egress-claude-1@192.168.1.1")
    assert r.returncode == 1 and "host gateway 192.168.1.1" in r.stderr
    r = env.run(STUB_DIRECT_OK="egress-claude-1@192.168.1.1", SMOKE_HOST_ISOLATION="report")
    assert r.returncode == 0 and "WARN" in r.stderr


def test_service_names_must_not_resolve_across_networks(env):
    r = env.run(STUB_LEAK_PEER="agent-claude-1=egress-codex")
    assert r.returncode == 1 and "agent-claude-1 resolves egress-codex" in r.stderr
    assert "shares no network" in r.stderr


def test_service_names_must_resolve_within_a_shared_network(env):
    r = env.run(STUB_LOSE_PEER="agent-claude-1=egress-claude-1")
    assert r.returncode == 1 and "cannot resolve egress-claude-1" in r.stderr


def test_a_broken_embedded_resolver_is_a_defect_not_a_pass(env):
    for mode in ("enforce", "report"):
        r = env.run(STUB_SELF_BROKEN="postgres", SMOKE_HOST_ISOLATION=mode)
        assert r.returncode == 1 and "own service name" in r.stderr, mode


def test_resolv_conf_must_point_at_the_embedded_resolver_only(env):
    r = env.run(STUB_NAMESERVER="telegram=192.168.1.1")
    assert r.returncode == 1 and "expected only Docker's embedded 127.0.0.11" in r.stderr


def test_a_resolv_conf_without_the_annotation_cannot_be_verified(env):
    r = env.run(STUB_NO_ANNOTATION="api")
    assert r.returncode == 1 and "no ExtServers annotation" in r.stderr


@pytest.mark.parametrize(
    "var,svc",
    [
        ("STUB_NO_NSLOOKUP", "egress-codex"),
        ("STUB_EXEC_FAIL", "telegram"),
        ("STUB_TRUNCATE", "discovery"),
        ("STUB_GARBAGE", "agent-codex"),
    ],
)
def test_broken_tooling_is_a_defect_in_every_mode(env, var, svc):
    for mode in ("enforce", "report"):
        r = env.run(SMOKE_HOST_ISOLATION=mode, **{var: svc})
        assert r.returncode == 1 and "defect" in r.stderr and svc in r.stderr, (var, mode, r.stderr)
        assert "UNVERIFIED" in r.stderr or "DONE" in r.stderr or "malformed" in r.stderr


def test_a_container_with_neither_python_nor_nslookup_cannot_be_verified(env):
    r = env.run(STUB_NO_PYTHON="api", STUB_NO_NSLOOKUP="api")
    assert r.returncode == 1 and "nslookup is missing in the container" in r.stderr


def test_the_image_without_python_falls_back_to_nslookup_and_is_still_fully_checked(env):
    assert env.run(STUB_NO_PYTHON="api").returncode == 0
    assert env.run(STUB_NO_PYTHON="api", STUB_EXT_BROKEN="api").returncode == 1


def test_the_one_shot_migrate_service_may_be_stopped_and_is_then_not_probed(env):
    r = env.run(STUB_NOT_RUNNING="migrate")
    assert r.returncode == 0, r.stderr
    assert "migrate" not in (env.stub / "log").read_text()
    assert "6 internal-only service(s) resolve nothing" in r.stdout


@pytest.mark.parametrize("svc", ["api", "agent-codex", "egress-claude-1", "postgres"])
def test_any_other_stopped_service_refuses_to_certify(env, svc):
    r = env.run(STUB_NOT_RUNNING=svc)
    assert r.returncode == 1 and f"service '{svc}' is not running" in r.stderr


def test_a_public_resolver_as_the_expected_one_is_not_probed_twice(env):
    """CI gives compose HUNTER_DNS=1.1.1.1 - the same address the leak probe uses."""

    def public(cfg):
        for n in OUT:
            cfg["services"][n]["dns"] = ["1.1.1.1"]

    import tempfile

    with tempfile.TemporaryDirectory() as d:
        e = Env(Path(d), public)
        for n in OUT:
            p = e.stub / "resolv" / n
            p.write_text(p.read_text().replace("[10.0.2.3]", "[1.1.1.1]"))
        r = e.run(SMOKE_DNS_EXPECT="1.1.1.1", STUB_APPROVED="1.1.1.1")
        assert r.returncode == 0, r.stdout + r.stderr


def test_a_changed_topology_is_refused_instead_of_silently_shrinking_the_check():
    def internalise(cfg):
        cfg["services"]["telegram"]["networks"] = {"data": None}

    import tempfile

    with tempfile.TemporaryDirectory() as d:
        r = Env(Path(d), internalise).run()
        assert r.returncode == 1 and "'telegram' is expected to have a route out" in r.stderr

    def outwards(cfg):
        cfg["services"]["agent-codex"]["networks"] = {"agent_codex": None, "egress": None}

    with tempfile.TemporaryDirectory() as d:
        r = Env(Path(d), outwards).run()
        assert r.returncode == 1 and "'agent-codex' is expected to be internal-only" in r.stderr


def test_an_unreadable_compose_configuration_fails(env):
    r = env.run(STUB_CONFIG_FAIL="1")
    assert r.returncode == 1 and "cannot read the compose configuration" in r.stderr


@pytest.mark.parametrize(
    "var,val",
    [
        ("SMOKE_DNS_EXPECT", "resolver.lan"),
        ("SMOKE_DNS_EXPECT", "10.0.2.3;id"),
        ("SMOKE_DNS_NAME", "a b"),
        ("SMOKE_HOST_ISOLATION", "maybe"),
    ],
)
def test_bad_settings_are_refused(env, var, val):
    assert env.run(**{var: val}).returncode == 1


# ---- F-1: internal-only services are judged on the RUNTIME resolver state -----------------------
@pytest.mark.parametrize("svc", ["agent-claude-1", "agent-codex", "postgres", "scheduler"])
def test_an_internal_only_service_with_an_explicit_upstream_is_a_breach_in_every_mode(env, svc):
    """What a daemon-level `dns` (daemon.json) does: compose says nothing, the runtime has it."""
    for mode in ("enforce", "report"):
        r = env.run(STUB_ANNOTATION=f"{svc}=10.0.2.3", SMOKE_HOST_ISOLATION=mode)
        assert r.returncode == 1, mode
        assert (
            f"{svc} is internal-only but Docker gave it explicit upstream resolver(s)" in r.stderr
        )
        assert "daemon-level dns (daemon.json)" in r.stderr


def test_every_internal_only_service_is_named_when_the_daemon_level_dns_is_set(env):
    annotations = ";".join(f"{s}=10.0.2.3" for s in IN)
    r = env.run(STUB_ANNOTATION=annotations)
    assert r.returncode == 1
    for s in IN:
        assert f"{s} is internal-only but Docker gave it explicit upstream" in r.stderr, s


@pytest.mark.parametrize(
    "annotation", ["host(192.168.1.1) 10.0.2.3", "1.1.1.1", "10.0.2.3 host(10.0.0.1)"]
)
def test_any_explicit_entry_next_to_the_daemons_own_resolver_is_still_refused(env, annotation):
    r = env.run(STUB_ANNOTATION=f"agent-codex={annotation}")
    assert (
        r.returncode == 1 and "agent-codex is internal-only but Docker gave it explicit" in r.stderr
    )


def test_the_daemons_own_resolver_and_no_annotation_are_what_an_internal_only_service_may_carry(
    env,
):
    """host(...) is listed for every container and never used by an internal-only one (measured)."""
    assert (
        env.run(STUB_ANNOTATION="agent-codex=host(192.168.1.1) host(10.255.255.254)").returncode
        == 0
    )
    assert env.run(STUB_NO_ANNOTATION="agent-codex postgres").returncode == 0


def test_an_internal_only_service_whose_nameserver_is_not_the_embedded_resolver_is_a_breach(env):
    r = env.run(STUB_NAMESERVER="agent-claude-2=10.0.2.3")
    assert (
        r.returncode == 1 and "agent-claude-2: resolv.conf nameservers are ['10.0.2.3']" in r.stderr
    )


def test_local_service_discovery_is_still_required_while_the_upstream_is_judged(env):
    """The refusal is about the upstream; discovery between neighbours must keep working."""
    r = env.run(STUB_ANNOTATION="agent-codex=10.0.2.3", STUB_LOSE_PEER="agent-codex=egress-codex")
    assert "agent-codex cannot resolve egress-codex" in r.stderr
    assert "explicit upstream" in r.stderr


# ---- F-2: the raw-UDP probe has a positive control -------------------------------------------
@pytest.mark.parametrize(
    "tool,victims",
    [
        ("python", "api discovery telegram"),
        ("nslookup", "egress-claude-1 egress-claude-2 egress-codex"),
    ],
)
def test_a_probe_that_can_never_receive_an_answer_is_a_defect_in_every_mode(env, tool, victims):
    """Before, the agents' silence passed whatever the probe did; now it certifies nothing."""
    for mode in ("enforce", "report"):
        r = env.run(STUB_PROBE_DEAD=tool, SMOKE_HOST_ISOLATION=mode)
        assert r.returncode == 1, (mode, r.stderr)
        assert f"PROBE DEFECT - the raw {tool} DNS query to 10.0.2.3 got no answer" in r.stderr
        assert "UNVERIFIED" in r.stderr
        for v in victims.split():
            assert f"{v}: PROBE DEFECT" in r.stderr


def test_a_dead_probe_is_not_reported_as_the_network_blocking_something(env):
    r = env.run(STUB_PROBE_DEAD="python")
    assert "cannot resolve" not in r.stderr and "BROKEN" not in r.stderr


def test_a_blocked_query_is_told_apart_from_a_broken_probe(env):
    """No guard exception: names do not resolve AND the raw query is blocked. That is the network,
    not a probe defect: enforce fails (as before), report warns, agents' checks are unverified."""
    blocked = "egress-claude-1 egress-claude-2 egress-codex"
    r = env.run(STUB_EXT_BROKEN=blocked)
    assert r.returncode == 1 and "PROBE DEFECT" not in r.stderr
    r = env.run(STUB_EXT_BROKEN=blocked, SMOKE_HOST_ISOLATION="report")
    assert r.returncode == 0 and "PROBE DEFECT" not in r.stderr and "WARN" in r.stderr
    assert (
        "no nslookup probe got an answer" not in r.stderr
    )  # python agents still have a python control


def test_the_flavour_without_any_control_leaves_the_agents_checks_unverified_and_says_so(env):
    everything = "api discovery telegram egress-claude-1 egress-claude-2 egress-codex"
    r = env.run(STUB_EXT_BROKEN=everything, SMOKE_HOST_ISOLATION="report")
    assert r.returncode == 0  # report mode: a warning ...
    assert "cannot be told from a broken probe" in r.stderr  # ... that names the consequence
    assert "agent-codex" in r.stderr and "are UNVERIFIED" in r.stderr
    assert env.run(STUB_EXT_BROKEN=everything).returncode == 1  # enforce: fatal


def test_no_service_with_a_route_out_to_serve_as_control_for_a_flavour_is_a_defect(env):
    """The agents run python; if no service with a route out does, that probe has no control."""
    r = env.run(STUB_NO_PYTHON="api discovery telegram", SMOKE_HOST_ISOLATION="report")
    assert r.returncode == 1
    assert "no service with a route out ran the python probe" in r.stderr
    assert "agent-claude-1" in r.stderr and "UNVERIFIED" in r.stderr


def test_one_service_whose_raw_query_fails_while_it_resolves_is_a_probe_defect(env):
    r = env.run(STUB_CTRL_BLOCKED="api")
    assert r.returncode == 1 and "api: PROBE DEFECT" in r.stderr


def test_the_negative_checks_still_bite_when_the_control_succeeds(env):
    """The control must not blunt leak detection: a real answer for an agent is still a breach."""
    r = env.run(STUB_DIRECT_OK="agent-codex@10.0.2.3")
    assert (
        r.returncode == 1
        and "agent-codex is internal-only but gets DNS answers from 10.0.2.3" in r.stderr
    )


def test_the_approved_resolver_is_not_mistaken_for_a_leaking_gateway(env):
    assert env.run(STUB_HOST_GATEWAY="10.0.2.3").returncode == 0


def test_the_positive_control_queries_every_service_with_a_route_out(env):
    assert env.run().returncode == 0
    probed = {
        ln.split()[1]
        for ln in (env.stub / "log").read_text().splitlines()
        if ln.split()[2] in ("python", "sh")
    }
    assert set(OUT) <= probed


# ---- F-3 (the config-only mode the deploy gate runs BEFORE `compose up`) ---------------------
def test_config_only_mode_judges_the_rendered_dns_without_touching_any_container(env):
    r = env.run(
        SMOKE_DNS_CONFIG_ONLY="1",
        SMOKE_DNS_EXPECT="10.0.2.3",
        STUB_NOT_RUNNING=" ".join(env.cfg["services"]),
    )
    assert r.returncode == 0, r.stderr
    assert "13 services render dns exactly as the guard allows" in r.stdout
    assert not (env.stub / "log").exists()  # not a single `docker compose exec`


@pytest.mark.parametrize("expect", ["1.1.1.1", "10.0.2.3,1.1.1.1", "192.168.1.1"])
def test_config_only_mode_refuses_a_resolver_the_guard_does_not_allow(env, expect):
    r = env.run(SMOKE_DNS_CONFIG_ONLY="1", SMOKE_DNS_EXPECT=expect)
    assert r.returncode == 1 and "nothing was started" in r.stderr
    assert "api has a route out but its rendered dns is ['10.0.2.3']" in r.stderr
    assert not (env.stub / "log").exists()


def test_config_only_mode_refuses_a_missing_or_surplus_dns_entry(env):
    def drop(cfg):
        cfg["services"]["egress-codex"].pop("dns")
        cfg["services"]["postgres"]["dns"] = ["10.0.2.3"]

    import tempfile

    with tempfile.TemporaryDirectory() as d:
        r = Env(Path(d), drop).run(SMOKE_DNS_CONFIG_ONLY="1", SMOKE_DNS_EXPECT="10.0.2.3")
        assert r.returncode == 1
        assert "egress-codex has a route out but its rendered dns is EMPTY" in r.stderr
        assert "postgres is internal-only but its rendered dns is ['10.0.2.3']" in r.stderr


def test_config_only_mode_still_refuses_a_changed_topology(env):
    def internalise(cfg):
        cfg["services"]["telegram"]["networks"] = {"data": None}

    import tempfile

    with tempfile.TemporaryDirectory() as d:
        r = Env(Path(d), internalise).run(SMOKE_DNS_CONFIG_ONLY="1", SMOKE_DNS_EXPECT="10.0.2.3")
        assert r.returncode == 1 and "'telegram' is expected to have a route out" in r.stderr


def test_config_only_mode_is_a_strict_switch(env):
    assert env.run(SMOKE_DNS_CONFIG_ONLY="yes").returncode == 1
    assert env.run(SMOKE_DNS_CONFIG_ONLY="1", STUB_CONFIG_FAIL="1").returncode == 1


def test_the_script_has_no_way_to_change_the_stack():
    code = "\n".join(ln for ln in CHECK.read_text().splitlines() if not ln.lstrip().startswith("#"))
    for verb in (
        "compose up",
        "compose down",
        "compose restart",
        "docker run",
        "docker network",
        "iptables",
        "nsenter",
        "/var/run/docker.sock",
    ):
        assert verb not in code, verb
