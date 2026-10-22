"""Detectors for the original findings M-1 and M-2, run against the REAL deploy/smoke-test.sh.

M-1  "reach() mistakes DNS scoping and closed ports for isolation" (smoke-test.sh, section 3)
     gaierror and ECONNREFUSED are both reported as "blocked". A refused connection means a route
     EXISTS (L3 reachable, only the port is closed); a name that does not resolve proves DNS
     scoping, not the absence of a route. Only agent-codex was probed, and by name.
     Required: probe by IP, ENETUNREACH/EHOSTUNREACH/timeout = blocked, ECONNREFUSED = FAIL, all
     three agents.
M-2  "The egress-denial suite fails open" (smoke-test.sh, section 4)
     denied() accepts anything that is not 200, including "error", so with SMOKE_EXTERNAL=0 (no
     positive control) the whole suite passes with a dead proxy. Required: exactly the proxy's
     policy refusal (403) counts, upstream failures (502/504) and "error" do not, all three proxies.

The functions are cut out of the script and run for real (exec_in is replaced by a local call), so
there is no second copy of the logic to drift. Tests that describe a finding that is still OPEN are
`xfail(strict=True)`: they FAIL today (that is the reproduction), and the day the fix lands they
XPASS and break the build, which forces the marker off in the same PR (the fix owner removes it).
Owners: M-1 -> runtime containment (isolation section of smoke-test.sh); M-2 -> CLI egress.
"""

import os
import re
import shutil
import socket
import subprocess
import threading
from pathlib import Path

import pytest

# SMOKE_UNDER_TEST=<path> points the detectors at another copy (a branch under review, a fix)
SMOKE = Path(
    os.environ.get("SMOKE_UNDER_TEST")
    or Path(__file__).resolve().parents[1] / "deploy" / "smoke-test.sh"
)
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(
    BASH is None or not hasattr(socket, "AF_UNIX"), reason="needs bash on a POSIX host"
)

M1 = "M-1: reach() counts ECONNREFUSED and DNS failures as 'blocked' (smoke-test.sh section 3)"
M2 = "M-2: denied() accepts anything but 200, 'error' included (smoke-test.sh section 4)"


def _function(name):
    """The text of `name() { ... }` from smoke-test.sh (ends at the first line that is just `}`)."""
    lines = SMOKE.read_text().splitlines()
    start = next((i for i, ln in enumerate(lines) if re.match(rf"{name}\(\)\s*\{{", ln)), None)
    if start is None:
        pytest.fail(
            f"{name}() is not in {SMOKE.name} any more: these detectors extract it by name. If it "
            "was renamed on purpose, update tests/test_integration_smoke_detectors.py with it."
        )
    if re.search(r"\}\s*(#.*)?$", lines[start]):  # a one-liner, possibly with a trailing comment
        return lines[start]
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
    return "\n".join(lines[start : end + 1])


# exec_in <service> <cmd...> runs in a container in the script; here it runs locally
PRELUDE = 'exec_in() { shift; "$@"; }\npython() { python3 "$@"; }\n'


def _run(snippet, timeout=30):
    return subprocess.run(
        [BASH, "-c", PRELUDE + snippet], capture_output=True, text=True, timeout=timeout
    )


def reach(target):
    r = _run(f"{_function('reach')}\nreach any-service {target}")
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


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


# ---- M-1 ----------------------------------------------------------------------------------------
def test_reach_positive_control_a_listening_port_is_reachable(listener):
    """Without this, every 'blocked' below could be a broken probe (the finding's own lesson)."""
    host, port = listener
    assert reach(f"{host}:{port}") == "REACHABLE"


@pytest.mark.xfail(strict=True, reason=M1)
def test_M1_a_refused_connection_is_not_reported_as_blocked(closed_port):
    """ECONNREFUSED = a packet got there and was answered: a ROUTE EXISTS. reach() says 'blocked'.
    Reproduce: any host that is L3-reachable with the port closed (discovery:8100 in the stack)."""
    assert reach(f"127.0.0.1:{closed_port}") != "blocked"


@pytest.mark.xfail(strict=True, reason=M1)
def test_M1_a_name_that_does_not_resolve_is_not_reported_as_blocked():
    """gaierror proves DNS scoping, not that there is no route (postgres, api, ... by name)."""
    assert reach("no-such-service.invalid:5432") != "blocked"


def test_reach_reports_blocked_for_an_address_with_no_route():
    """The other half of the classification must keep working after the fix: no route = blocked."""
    # 240.0.0.0/4 is reserved: ENETUNREACH or a timeout, never a connection or a refusal
    assert reach("240.0.0.1:80") == "blocked"


def _isolation_probes():
    """(service, target-list-text) pairs for the L3 isolation loop of section 3."""
    text = SMOKE.read_text()
    return re.findall(r'reach\s+(agent-[a-z0-9-]+)\s+"?\$?([^\s"]*)', text)


@pytest.mark.xfail(strict=True, reason=M1)
def test_M1_every_agent_is_probed_for_isolation_not_only_agent_codex():
    probed = {svc for svc, _ in _isolation_probes()}
    assert {"agent-claude-1", "agent-claude-2", "agent-codex"} <= probed, probed


@pytest.mark.xfail(strict=True, reason=M1)
def test_M1_isolation_targets_are_addresses_not_service_names():
    """A service name that does not resolve from the agent says nothing about the route. The loop
    that proves isolation must probe IPs (docker inspect), at least for the peers it names."""
    text = SMOKE.read_text()
    loop = re.search(
        r"for target in ([^;]*?);\s*do\s*\n\s*\[\[ \"\$\(reach agent-codex", text, re.S
    )
    assert loop, "the section 3 isolation loop was not found: update this detector"
    targets = loop.group(1).replace("\\\n", " ").split()
    names = [t for t in targets if not re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", t)]
    assert not names, f"probed by name, not address: {names}"


# ---- M-2 ----------------------------------------------------------------------------------------
# Two forms of the script exist: the original fail-open denied() (main) and the policy-403-only
# refused()/ask() (PR #14). The original's checks are strict xfails (the reproduction); the same
# properties on the new form are plain assertions, so the detectors are red-then-green by design.
def _has(name):
    return re.search(rf"^{name}\(\)\s*\{{", SMOKE.read_text(), re.M) is not None


OLD = _has("denied")
NEW = _has("refused") and _has("ask")
old_form = pytest.mark.skipif(not OLD, reason="denied() was replaced (M-2 fixed in this script)")
new_form = pytest.mark.skipif(not NEW, reason="this script has no refused()/ask() yet")
open_m2 = pytest.mark.xfail(OLD, strict=True, reason=M2)


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
            pytest.skip("127.0.0.1:3128 is busy")
    try:
        r = _run(snippet)
        assert r.returncode == 0, r.stderr
        return r.stdout.strip()
    finally:
        if proxy:
            proxy.close()


# -- the original form: denied() / connect() ------------------------------------------------
def denied(status):
    """True if smoke-test.sh's denied() would count `status` as a refusal."""
    return _run(f"{_function('denied')}\ndenied '{status}'").returncode == 0


def _connect(status):
    """What connect() prints for a proxy answering `status` (None = no proxy)."""
    response = None if status is None else f"HTTP/1.1 {status}\r\n\r\n".encode()
    snippet = f"{_function('connect')}\nconnect any-agent 127.0.0.1 example.com 443"
    return _with_proxy(response, snippet)


@old_form
def test_denied_positive_controls():
    assert denied("403"), "the policy refusal must count as a denial"
    assert not denied("200"), "an established tunnel is never a denial"


@old_form
@open_m2
@pytest.mark.parametrize("status", ["error", "", "000", "502", "504", "500", "407", "400"])
def test_M2_only_the_policy_refusal_counts_as_a_denial(status):
    """A dead, wedged or unreachable proxy yields 'error'/5xx, which is NOT evidence of a policy.
    Reproduce: stop egress-codex, run the suite with SMOKE_EXTERNAL=0: every check still passes."""
    assert not denied(status), f"denied({status!r}) counts as a denial"


@old_form
def test_connect_reports_what_the_proxy_said():
    assert _connect("403 Forbidden") == "403"
    assert _connect("200 Connection established") == "200"


@old_form
@open_m2
def test_M2_a_dead_proxy_is_not_a_passing_egress_denial():
    """End to end through the script's own connect() and denied(): nothing listens, the check must
    NOT count that as 'the proxy refused example.com'."""
    # (one assertion on purpose: a second, incidental one could fail for the wrong reason and make
    # the xfail hide the fix)
    assert not denied(_connect(None)), "denied() certifies a proxy that is not even running"


@old_form
@open_m2
def test_M2_a_bad_gateway_is_not_a_passing_egress_denial():
    assert not denied(_connect("502 Bad Gateway"))


# -- the policy-403 form: refused() / ask() -------------------------------------------------
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


@new_form
@pytest.mark.parametrize("answer", ["403 host", "403 port", "403 method"])
def test_refused_accepts_the_proxys_policy_answers(answer):
    assert refused(answer)


@new_form
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


@new_form
def test_M2_a_dead_proxy_is_not_a_refusal_end_to_end():
    """Nothing listens on 3128: through the script's own ask() and refused() this must not pass."""
    answer, accepted = _ask(None)
    assert not accepted, f"a dead proxy was certified as refusing ({answer!r})"


@new_form
def test_the_dead_proxy_condition_is_real_nothing_answers_on_3128():
    with socket.socket() as s:
        assert s.connect_ex(("127.0.0.1", 3128)) != 0, "something is listening on 3128"


@new_form
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


@open_m2
def test_M2_the_denial_checks_cover_all_three_proxies():
    """egress-claude-2 is never exercised (original finding)."""
    text = SMOKE.read_text()
    assert "egress-claude-2" in re.sub(r"#.*", "", text.split("# 4. egress policy", 1)[1])
