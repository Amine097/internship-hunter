"""Functional regression tests for the original findings M-1 and M-2, against the REAL
deploy/smoke-test.sh (PR #14 fixed both; these tests are what keeps them fixed).

M-1  "reach() mistakes DNS scoping and closed ports for isolation" (section 3). A refused
     connection means a route EXISTS; a name that does not resolve proves DNS scoping, not the
     absence of a route; only agent-codex was probed, and by name. #14 replaced reach() with a
     classifying probe() and a decision loop over all three agents. Two layers here:

       1. the REAL probe program, cut out of the script, runs against the REAL kernel: a listening
          port, a closed port, a full accept queue (a SYN that is never answered), a name that does
          not resolve, and - inside a network namespace - ENETUNREACH, EHOSTUNREACH and EACCES.
       2. the REAL section-3 decision loop, cut out of the script, runs over a fake topology whose
          probe results the test chooses: a clean topology passes, and every leak shape (open,
          refused, unresolvable, an unseen shared path, broken controls, a missing own proxy) fails
          for EACH of the three agents.

     The negative controls are mutants of the real text (a classifier that calls a refusal
     "unreachable", a loop that probes one agent, an assessment that accepts a refusal, one that
     skips the controls): every one of them must be caught by the same tables, otherwise the tables
     prove nothing.
M-2  "The egress-denial suite fails open" (section 4): only a 403 with the proxy's own policy reason
     is a refusal; a dead proxy, a 5xx or a bare 403 is not. Checked through real sockets.

The functions are cut out of the script, so there is no second copy of the logic to drift.
SMOKE_UNDER_TEST=<path> points the tests at another copy of the script.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

SMOKE = Path(
    os.environ.get("SMOKE_UNDER_TEST")
    or Path(__file__).resolve().parents[1] / "deploy" / "smoke-test.sh"
)
SMOKE_TEXT = SMOKE.read_text()
BASH = shutil.which("bash")
# the CI job that provides unprivileged namespaces sets this: there a missing tool is a FAILURE
REQUIRED = os.environ.get("HUNTER_QA_REQUIRED") == "1"

pytestmark = pytest.mark.skipif(
    BASH is None or not hasattr(socket, "AF_UNIX"), reason="needs bash on a POSIX host"
)


def _function(name, text=None):
    """The text of `name() { ... }` from smoke-test.sh (ends at the first line that is just `}`)."""
    lines = (text or SMOKE_TEXT).splitlines()
    start = next((i for i, ln in enumerate(lines) if re.match(rf"{name}\(\)\s*\{{", ln)), None)
    if start is None:
        pytest.fail(
            f"{name}() is not in {SMOKE.name} any more: these tests extract it by name. If it "
            "was renamed on purpose, update tests/test_integration_smoke_detectors.py with it."
        )
    if re.search(r"\}\s*(#.*)?$", lines[start]):  # a one-liner, possibly with a trailing comment
        return lines[start]
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
    return "\n".join(lines[start : end + 1])


def _need(ok, why):
    """A tool the test needs is missing: skip, unless the job exists to run it (REQUIRED)."""
    if not ok:
        (pytest.fail if REQUIRED else pytest.skip)(why)


# =============================================================================================
# M-1 layer 1: the real probe program against the real kernel
# =============================================================================================
_m = re.search(r"^probe\(\) \{.*?<<'PY'.*?\n(.*?)\nPY\n", SMOKE_TEXT, re.S | re.M)
PROBE = _m.group(1) if _m else ""
REFUSED_CLAUSE = (
    '    except (ConnectionRefusedError, ConnectionResetError):\n        return "refused"'
)
GAI_CLAUSE = '    except socket.gaierror:\n        return "error"'


def _mutant_probe(refused_as="unreachable", gaierror_as="unreachable"):
    """The real probe with its classifier broken the way the original reach() was: a refusal and a
    failed name lookup both look like isolation."""
    assert REFUSED_CLAUSE in PROBE and GAI_CLAUSE in PROBE, "the probe's classifier changed shape"
    return PROBE.replace(
        REFUSED_CLAUSE, REFUSED_CLAUSE.replace('"refused"', f'"{refused_as}"')
    ).replace(GAI_CLAUSE, GAI_CLAUSE.replace('"error"', f'"{gaierror_as}"'))


def _parse(out):
    res = {ln.split()[1]: ln.split()[2] for ln in out.splitlines() if ln.startswith("RESULT ")}
    ctl = {ln.split()[1]: ln.split()[2] for ln in out.splitlines() if ln.startswith("CONTROL ")}
    return res, ctl


def run_probe(program, targets, netns_setup=None, timeout=60):
    """(results, controls) of the probe program for `targets`. With `netns_setup` (shell), the
    program runs in a fresh unprivileged network namespace after that setup (lo is brought up)."""
    assert PROBE, "probe() with its python heredoc was not found in smoke-test.sh"
    if netns_setup is None:
        cmd = [sys.executable, "-", *targets]
    else:
        setup = "ip link set lo up" + (f" && {netns_setup}" if netns_setup else "")
        cmd = [
            "unshare",
            "-Urn",
            "sh",
            "-c",
            f'{setup} && exec "$0" "$@"',
            sys.executable,
            "-",
            *targets,
        ]
    r = subprocess.run(cmd, input=program, capture_output=True, text=True, timeout=timeout)
    assert r.returncode == 0, r.stderr
    return _parse(r.stdout)


@pytest.fixture
def listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    yield s.getsockname()
    s.close()


@pytest.fixture
def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens now: connect() gets ECONNREFUSED
    return port


@pytest.fixture
def full_backlog():
    """A listening socket whose accept queue is full: further SYNs are dropped, never answered, so a
    connect() neither succeeds nor is refused - it times out (the shape of a firewall DROP)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(0)
    fillers = []
    for _ in range(4):
        c = socket.socket()
        c.setblocking(False)
        c.connect_ex(s.getsockname())
        fillers.append(c)
    yield s.getsockname()
    for c in fillers:
        c.close()
    s.close()


def _addr(a):
    return f"{a[0]}:{a[1]}"


def test_probe_classifies_open_refused_timeout_and_a_failed_lookup_on_a_real_kernel(
    listener, closed_port, full_backlog
):
    targets = {
        _addr(listener): "open",
        f"127.0.0.1:{closed_port}": "refused",  # a route exists, the port is closed: NOT isolation
        _addr(full_backlog): "timeout",  # a dropped SYN: isolation
        "no-such-host.invalid:80": "error",  # a name proves nothing about the network
    }
    results, controls = run_probe(PROBE, list(targets))
    assert controls == {"open": "open", "refused": "refused"}
    assert results == targets


def test_probe_classifies_the_three_kinds_of_no_route_as_unreachable():
    """ENETUNREACH (no route), EHOSTUNREACH (an `unreachable` route) and EACCES (`prohibit`) are the
    kernel's own statements that the packet did not leave. Run in a private network namespace."""
    _need(shutil.which("unshare") and shutil.which("ip"), "needs unshare and ip")
    probe = subprocess.run(["unshare", "-Urn", "true"], capture_output=True)
    _need(probe.returncode == 0, "unprivileged user+network namespaces are not available")
    setup = "ip route add unreachable 10.254.0.0/16 && ip route add prohibit 10.253.0.0/16"
    targets = {
        "10.255.255.1:80": "unreachable",  # ENETUNREACH
        "10.254.0.1:80": "unreachable",  # EHOSTUNREACH
        "10.253.0.1:80": "unreachable",  # EACCES
    }
    results, controls = run_probe(PROBE, list(targets), netns_setup=setup)
    assert controls == {"open": "open", "refused": "refused"}
    assert results == targets


def test_a_probe_that_cannot_use_its_own_loopback_fails_its_controls():
    """Inside a namespace whose lo is DOWN every connect fails the way a block does. The probe's
    own controls (an open and a refused local port) are what tell that apart from isolation, and
    smoke-test.sh refuses to count any result when they are wrong."""
    _need(shutil.which("unshare"), "needs unshare")
    r = subprocess.run(
        ["unshare", "-Urn", sys.executable, "-", "10.255.255.1:80"],
        input=PROBE,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if r.returncode != 0 and "Operation not permitted" in r.stderr:
        _need(False, "unprivileged network namespaces are not available")
    results, controls = _parse(r.stdout)
    assert controls != {"open": "open", "refused": "refused"}, controls


def test_negative_control_a_classifier_that_calls_refusals_isolation_fails_the_same_table(
    listener, closed_port, full_backlog
):
    """The table above must be able to tell the original reach() mistake apart: with the refusal
    and the failed lookup reported as isolation it does not pass."""
    targets = {
        _addr(listener): "open",
        f"127.0.0.1:{closed_port}": "refused",
        _addr(full_backlog): "timeout",
        "no-such-host.invalid:80": "error",
    }
    results, _ = run_probe(_mutant_probe(), list(targets))
    assert results != targets
    assert results[f"127.0.0.1:{closed_port}"] == "unreachable"  # the mistake, reproduced
    assert results["no-such-host.invalid:80"] == "unreachable"
    assert results[_addr(listener)] == "open"  # and the part that was right stays right


# =============================================================================================
# M-1 layer 2: the real section-3 decision loop over a fake topology
# =============================================================================================
ISOLATION = SMOKE_TEXT[
    SMOKE_TEXT.index("# 3. agent isolation") : SMOKE_TEXT.index("# 4. egress policy")
]
AGENTS = ["agent-claude-1", "agent-claude-2", "agent-codex"]
_loop_start = ISOLATION.index("mapfile -t RUNNING_SVCS")
_loop_end = ISOLATION.index("\ndone\n", ISOLATION.index("for agent in ")) + len("\ndone\n")
LOOP = ISOLATION[_loop_start:_loop_end]

# service -> {network: ip}. Every agent shares a network with ITS proxy and with `hub`; everything
# else (the other agents, their proxies, postgres, api) is on a network it does not share.
TOPOLOGY = {
    "postgres": {"data": "10.0.1.2"},
    "api": {"data": "10.0.1.3", "front": "10.0.2.2"},
    "hub": {"a1": "10.1.0.9", "a2": "10.2.0.9", "a3": "10.3.0.9"},
    "agent-claude-1": {"a1": "10.1.0.2"},
    "egress-claude-1": {"a1": "10.1.0.3", "out1": "10.1.1.3"},
    "agent-claude-2": {"a2": "10.2.0.2"},
    "egress-claude-2": {"a2": "10.2.0.3", "out2": "10.2.1.3"},
    "agent-codex": {"a3": "10.3.0.2"},
    "egress-codex": {"a3": "10.3.0.3", "out3": "10.3.1.3"},
}
FAKE_PROBE = r"""
import json, sys
topo, scen = json.load(open(sys.argv[1])), json.loads(sys.argv[2])
agent, targets = sys.argv[3], sys.argv[4:]
mine = {n for n in topo[agent]}
shared = {ip for s, nets in topo.items() if s != agent for n, ip in nets.items() if n in mine}
c = scen.get("controls", {"open": "open", "refused": "refused"})
print("CONTROL open", c["open"]); print("CONTROL refused", c["refused"])
for t in targets:
    host = t.rpartition(":")[0]
    default = "open" if host in shared else "unreachable"
    print("RESULT", t, scen.get("override", {}).get(agent, {}).get(t, default))
"""


def _assess(tmp_path, scenario, loop=LOOP):
    """Run the (possibly mutated) section-3 loop; returns (exit code, stderr)."""
    (tmp_path / "topo.json").write_text(json.dumps(TOPOLOGY))
    (tmp_path / "fakeprobe.py").write_text(FAKE_PROBE)
    prelude = f"""
set -uo pipefail
fail() {{ echo "FAIL $*" >&2; exit 1; }}
ok() {{ echo "ok   $*"; }}
SERVICES=({" ".join(TOPOLOGY)})
fakecompose() {{ printf '%s\\n' "${{SERVICES[@]}}"; }}
COMPOSE=(fakecompose)
PROTECTED_IPS=(100.64.0.1)
cid() {{ echo "$1"; }}
net_ips() {{ python3 - "$1" <<'PY'
import json, sys
for n, ip in json.load(open("{tmp_path}/topo.json"))[sys.argv[1]].items(): print(n, ip)
PY
}}
probe() {{ python3 {tmp_path}/fakeprobe.py {tmp_path}/topo.json '{json.dumps(scenario)}' \\
  "$1" "${{@:2}}"; }}
{_function("result_of")}
{_function("probe_port")}
"""
    r = subprocess.run(
        [BASH, "-c", prelude + loop + '\necho "ASSESSMENT-COMPLETE"'],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return r


def _target(svc, net, port):
    return f"{TOPOLOGY[svc][net]}:{port}"


def _leaks():
    """(name, agent, scenario): one defect injected, which the assessment must refuse to certify."""
    out = []
    for i, a in enumerate(AGENTS, 1):
        other = AGENTS[i % 3]
        peer = _target(other, f"a{(i % 3) + 1}", 8100)  # a separate network's agent
        pg = _target("postgres", "data", 5432)
        proxy = _target(f"egress-{a.removeprefix('agent-')}", f"a{i}", 3128)
        hub = _target("hub", f"a{i}", 9)
        net = lambda **ov: {"override": {a: ov}}  # noqa: E731
        out += [
            (f"{a}:peer-open", a, net(**{peer: "open"})),
            (f"{a}:peer-refused", a, net(**{peer: "refused"})),
            (f"{a}:postgres-refused", a, net(**{pg: "refused"})),
            (f"{a}:internet-open", a, net(**{"1.1.1.1:443": "open"})),
            (f"{a}:internet-refused", a, net(**{"8.8.8.8:53": "refused"})),
            (f"{a}:metadata-error", a, net(**{"169.254.169.254:80": "error"})),
            (f"{a}:lookup-failure", a, net(**{pg: "error"})),
            (f"{a}:shared-path-unseen", a, net(**{hub: "unreachable"})),
            (f"{a}:own-proxy-unreachable", a, net(**{proxy: "unreachable"})),
            (f"{a}:host-error", a, net(**{"100.64.0.1:22": "error"})),
            (
                f"{a}:controls-broken",
                a,
                {"controls": {"open": "unreachable", "refused": "unreachable"}},
            ),
            (f"{a}:control-open-only", a, {"controls": {"open": "open", "refused": "unreachable"}}),
        ]
    return out


def test_a_clean_topology_is_certified_for_all_three_agents(tmp_path):
    """Positive control: nothing in the failure table below is a symptom of a broken harness."""
    r = _assess(tmp_path, {})
    assert r.returncode == 0 and "ASSESSMENT-COMPLETE" in r.stdout, r.stderr


def test_timeouts_count_as_isolation(tmp_path):
    peer = _target("agent-codex", "a3", 8100)
    r = _assess(tmp_path, {"override": {"agent-claude-1": {peer: "timeout"}}})
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("name,agent,scenario", _leaks(), ids=[x[0] for x in _leaks()])
def test_every_leak_shape_fails_the_assessment_for_each_agent(tmp_path, name, agent, scenario):
    r = _assess(tmp_path, scenario)
    assert r.returncode == 1 and "ASSESSMENT-COMPLETE" not in r.stdout, (
        f"{name}: the assessment certified isolation\n{r.stdout}\n{r.stderr}"
    )
    assert r.stderr.startswith("FAIL "), r.stderr


def test_a_leak_in_the_last_agent_is_found_not_only_in_the_first(tmp_path):
    """Original M-1: only agent-codex was probed. Here only agent-claude-2 (the middle one) leaks;
    the clean run above certifies the others, so the failure is specific to the one that leaks."""
    peer = _target("agent-codex", "a3", 8100)
    r = _assess(tmp_path, {"override": {"agent-claude-2": {peer: "open"}}})
    assert r.returncode == 1 and "agent-claude-2 reaches" in r.stderr, r.stderr


MUTANTS = {
    "accepts a refusal as isolation": (
        '[[ "$r" == unreachable || "$r" == timeout ]] || fail "$agent reaches',
        '[[ "$r" != open ]] || fail "$agent reaches',
    ),
    "probes only agent-codex": (
        "for agent in agent-claude-1 agent-claude-2 agent-codex; do",
        "for agent in agent-codex; do",
    ),
    "ignores the probe's own controls": (
        "|| fail \"$agent: the probe's own controls failed",
        "|| : \"$agent: the probe's own controls failed",
    ),
    "does not need the shared-network positive control": (
        '[[ "$r" == open || "$r" == refused ]] || fail "$agent cannot reach $t on a network',
        ': "$agent cannot reach $t on a network',
    ),
}


_REAL_VERDICT = {}  # scenario -> exit code of the REAL loop (computed once)


@pytest.mark.parametrize("mutant", sorted(MUTANTS))
def test_negative_control_the_tables_catch_a_broken_assessment(tmp_path, mutant):
    """Each mutant is the real loop with one safeguard removed. At least one case that the real loop
    rejects must be certified by the mutant, otherwise the table would not notice the regression."""
    old, new = MUTANTS[mutant]
    assert old in LOOP, f"the loop no longer contains the text this mutant edits: {old!r}"
    mutated = LOOP.replace(old, new)
    certified = []
    for name, _agent, scenario in _leaks():
        key = json.dumps(scenario, sort_keys=True)
        if key not in _REAL_VERDICT:
            _REAL_VERDICT[key] = _assess(tmp_path, scenario).returncode
        if _REAL_VERDICT[key] == 1 and _assess(tmp_path, scenario, loop=mutated).returncode == 0:
            certified.append(name)
    assert certified, f"nothing in the leak table distinguishes the mutant that {mutant}"


def test_the_loop_really_is_the_one_in_smoke_test_sh():
    """The extraction must contain what #14 claims: classified results and all three agents."""
    assert "for agent in agent-claude-1 agent-claude-2 agent-codex; do" in LOOP
    assert "isolation UNVERIFIED" in LOOP and "a refusal is an answer, not isolation" in LOOP
    assert "reach() {" not in SMOKE_TEXT, "reach() is back"
    assert not re.search(r"\$\(reach ", SMOKE_TEXT), "something still calls reach()"


# =============================================================================================
# M-2: only the proxy's own policy refusal is a refusal
# =============================================================================================
OLD_FORM_GONE = "denied() {" not in SMOKE_TEXT


def test_the_fail_open_denied_is_gone():
    assert OLD_FORM_GONE, "denied() (accepts anything but 200) is back in smoke-test.sh"


# exec_in <service> <cmd...> runs in a container in the script; here it runs locally
PRELUDE = 'exec_in() { shift; "$@"; }\npython() { python3 "$@"; }\n'


def _run(snippet, timeout=30):
    return subprocess.run(
        [BASH, "-c", PRELUDE + snippet], capture_output=True, text=True, timeout=timeout
    )


class FakeProxy:
    """Answers every request with the raw `response` on 127.0.0.1:3128 (smoke-test.sh's port)."""

    def __init__(self, response):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 3128))
        self.sock.listen(8)
        self.response = response
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            c.recv(1024)
            c.sendall(self.response)
            c.close()

    def close(self):
        # close() alone does not wake a thread blocked in accept(): the port would stay open and a
        # later "dead proxy" test would be talking to this one
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        self.thread.join(timeout=2)


def _with_proxy(response, snippet):
    """Run `snippet` (bash) while a fake proxy answers `response` (None = nothing listens)."""
    proxy = None
    if response is not None:
        try:
            proxy = FakeProxy(response)
        except OSError:
            _need(False, "127.0.0.1:3128 is busy")
    try:
        r = _run(snippet)
        assert r.returncode == 0, r.stderr
        return r.stdout.strip()
    finally:
        if proxy:
            proxy.close()


def refused(answer):
    return _run(f"{_function('refused')}\nrefused '{answer}'").returncode == 0


def _ask(response, request="CONNECT example.com:443"):
    """What ask() reports for a proxy replying `response`, and whether refused() accepts it."""
    snippet = (
        f"{_function('ask')}\n{_function('refused')}\n"
        f'a="$(ask any-agent 127.0.0.1 "{request}")"; echo "$a"; '
        'if refused "$a"; then echo REFUSED; fi'
    )
    out = _with_proxy(response, snippet).splitlines()
    return out[0], "REFUSED" in out[1:]


def _http(status, reason=None):
    extra = f"X-Egress-Reason: {reason}\r\n" if reason else ""
    return f"HTTP/1.1 {status}\r\n{extra}Content-Length: 0\r\n\r\n".encode()


@pytest.mark.parametrize("answer", ["403 host", "403 port", "403 method"])
def test_refused_accepts_the_proxys_policy_answers(answer):
    assert refused(answer)


@pytest.mark.parametrize(
    "answer",
    [
        "error ConnectionRefusedError",
        "error TimeoutError",
        "502 upstream-failed",
        "503 busy",
        "504 upstream-timeout",
        "400 malformed",
        "200 -",
        "403 -",  # a 403 from something that is not the proxy's policy
        "",
    ],
)
def test_M2_refused_rejects_everything_that_is_not_a_policy_refusal(answer):
    assert not refused(answer), f"refused({answer!r}) counts as a denial"


def test_the_dead_proxy_condition_is_real_nothing_answers_on_3128():
    with socket.socket() as s:
        assert s.connect_ex(("127.0.0.1", 3128)) != 0, "something is listening on 3128"


def test_M2_a_dead_proxy_is_not_a_refusal_end_to_end():
    """Nothing listens on 3128: through the script's own ask() and refused() this must not pass."""
    answer, accepted = _ask(None)
    assert not accepted, f"a dead proxy was certified as refusing ({answer!r})"


@pytest.mark.parametrize(
    "response, accepted",
    [
        (_http("403 Forbidden", "host"), True),  # control: the real thing is accepted
        (_http("403 Forbidden", "port"), True),
        (_http("403 Forbidden"), False),  # a 403 with no policy reason
        (_http("502 Bad Gateway", "upstream-failed"), False),
        (_http("503 Service Unavailable", "busy"), False),
        (_http("200 Connection established"), False),
    ],
)
def test_M2_ask_and_refused_through_a_real_socket(response, accepted):
    assert _ask(response)[1] is accepted


def test_M2_the_denial_checks_cover_all_three_proxies():
    """egress-claude-2 was never exercised (original finding)."""
    section = re.sub(r"#.*", "", SMOKE_TEXT.split("# 4. egress policy", 1)[1])
    for proxy in ("egress-claude-1", "egress-claude-2", "egress-codex"):
        assert proxy in section, f"{proxy} is not exercised by the denial checks"
