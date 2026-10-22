"""Adversarial proxy-authorization tests: what actually reaches the upstream.

tests/proxy_authorization_scenarios.py runs inside a throwaway user+network namespace (no root, no
packet leaves the machine): a proxy on 127.0.0.1:3128 whose only allow-listed host is `localhost`, a
fake upstream on 127.0.0.1:443 that records every byte, and an attack matrix. These tests assert on
what the UPSTREAM saw, not on what the proxy's status line claims.

Properties (each one a test, each one demonstrated to be both satisfiable and detectable):
  AUTHZ   a denied request opens NO connection to the upstream (hostname look-alikes, other
          ports, every spelling of an IP literal, userinfo tricks, request-line smuggling, plain
          HTTP forwarding) and is answered with a 4xx, so a dead proxy cannot pass for a denial.
  FRONT   after `CONNECT allowed:443`, a TLS ClientHello whose SNI is another host, that has no SNI,
          or that carries Encrypted Client Hello is NOT relayed (original finding M-5, domain
          fronting through a shared CDN). Not even a byte reaches the upstream.
  FAIL    an upstream that is down is not reported as a policy denial (403), and is never a 200.
  LIVE    the legitimate request still works before and after the attacks.

Which proxy is judged (PROXY_UNDER_TEST):
  tinyproxy          (default) the repo's docker/egress-proxy.sh, unchanged, with a real tinyproxy
                     (TINYPROXY_DIR or PATH). Its known failures are pinned as strict xfails: they
                     document what is open TODAY and break the build when a fix lands, which forces
                     the marker off in the same change.
  egress_proxy       docker/egress_proxy.py (the CLI egress proxy) with its resolver pointed at the
                     fake upstream; every other line of it runs unchanged. NO xfails.
  cmd:<shell command> any other proxy (the CLI egress proxy under review): listens on 3128 and
                     reads EGRESS_ALLOW=localhost. NO xfails: every property must hold.
The `reference` and `reference-no-sni` modes always run: the first proves the properties can be met,
the second (the same proxy with the SNI check removed) proves the FRONT tests detect its absence.
PROXY_AUTHZ_REQUIRED=1 (CI) turns "cannot run" into a failure.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
RUNNER = HERE / "proxy_authorization_scenarios.py"
REQUIRED = os.environ.get("PROXY_AUTHZ_REQUIRED") == "1"
# the proxy the repo ships decides the default: once docker/egress_proxy.py exists, tinyproxy is
# gone (docker/egress-proxy.sh would exec a binary that is no longer installed): nothing is xfail
UNDER_TEST = os.environ.get(
    "PROXY_UNDER_TEST",
    "egress_proxy" if (HERE.parent / "docker" / "egress_proxy.py").exists() else "tinyproxy",
)
M5 = "M-5: the proxy tunnels a ClientHello whose SNI/ECH is not the CONNECT host (domain fronting)"
HARDENING = "request-line parser leniency: an extra token after the HTTP version is ignored"

_cache = {}


def _skip(reason):
    if REQUIRED:
        pytest.fail(f"PROXY_AUTHZ_REQUIRED=1 but the scenarios cannot run: {reason}")
    pytest.skip(reason)


def scenarios(mode):
    if mode in _cache:
        return _cache[mode]
    if os.name != "posix" or os.geteuid() == 0:
        _skip("needs an unprivileged POSIX user")
    for tool in ("unshare", "ip"):
        if not shutil.which(tool):
            _skip(f"{tool} not found")
    if subprocess.run(["unshare", "-Urn", "true"], capture_output=True).returncode != 0:
        _skip("unprivileged user+network namespaces are not available")
    env = dict(os.environ)
    if mode == "egress_proxy":
        if not (HERE.parent / "docker" / "egress_proxy.py").exists():
            _skip("docker/egress_proxy.py is not in this tree")
        env["PROXY_ALLOWED_HOST"] = "allowed.test"  # the proxy requires a dotted name
    if mode == "tinyproxy":
        tp = os.environ.get("TINYPROXY_DIR")
        if tp:
            env["PATH"] = tp + os.pathsep + env["PATH"]
        if not shutil.which("tinyproxy", path=env["PATH"]):
            _skip("tinyproxy is not installed (TINYPROXY_DIR or PATH)")
    r = subprocess.run(
        ["unshare", "-Urn", "--kill-child", sys.executable, str(RUNNER), mode],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )
    line = next((ln for ln in r.stdout.splitlines() if ln.startswith("SCENARIOS ")), None)
    if line is None:
        pytest.fail(f"the scenario runner produced no result ({mode}):\n{r.stdout}\n{r.stderr}")
    _cache[mode] = {c["case"]: c for c in json.loads(line[len("SCENARIOS ") :])}
    return _cache[mode]


def _cases(prefix):
    return [c for c in CASE_IDS if c.startswith(prefix)]


# the case ids are fixed by the runner; a renamed or dropped case must fail loudly, not vanish
CASE_IDS = [
    "legit",
    *(
        "deny:" + n
        for n in (
            "other_host allowed_host_port_80 allowed_host_port_8443 allowed_host_port_22 "
            "ip_literal_loopback ip_decimal ip_hex ip_octal ip_short ipv6_mapped_loopback "
            "userinfo_allowed_name_real_ip userinfo_garbage_then_allowed suffix_lookalike "
            "prefix_lookalike crlf_in_authority extra_token_in_request_line "
            "absolute_uri_get_to_allowed origin_form_get post_to_allowed"
        ).split()
    ),
    "front:sni_mismatch",
    "front:sni_absent",
    "front:sni_mismatch_pipelined",
    "front:ech_extension",
    "front:fragmented_sni_first",
    "front:fragmented_pipelined",
    "upstream_down",
    "legit_after",
]


def violations(obs):
    """The property violations in one observed case ([] = the property holds)."""
    name, bad = obs["case"], []
    ups, status = obs["upstream"], obs["status"]
    if name.startswith("deny:"):
        if ups:
            bad.append(f"AUTHZ: {len(ups)} upstream connection(s) opened for a denied request")
        if status is None or not 400 <= status < 500:
            bad.append(f"AUTHZ: a denial must be answered with a 4xx, got {status}")
    elif name.startswith("front:"):
        if any(u["bytes"] for u in ups):
            seen = [(u["hello"] or {}).get("sni", "?") if u["hello"] else "raw" for u in ups]
            bad.append(f"FRONT: the tunnel carried {sum(u['bytes'] for u in ups)} byte(s) ({seen})")
    elif name == "upstream_down":
        if status in (None, 200, 403):
            bad.append(f"FAIL: a dead upstream was reported as {status}")
    else:  # legit, legit_after
        hello = ups[0]["hello"] if ups else None
        if status != 200 or not hello or hello["sni"] != obs["allowed"]:
            bad.append(f"LIVE: the legitimate request failed (status {status}, upstream {ups})")
    return bad


def _xfail_for_baseline(request, case):
    if UNDER_TEST != "tinyproxy":
        return
    if case.startswith("front:"):
        request.applymarker(pytest.mark.xfail(strict=True, reason=M5))
    if case == "deny:extra_token_in_request_line":
        request.applymarker(pytest.mark.xfail(strict=False, reason=HARDENING))


# ---- the proxy under test ------------------------------------------------------------------------
@pytest.mark.parametrize("case", CASE_IDS)
def test_proxy_under_test(request, case):
    _xfail_for_baseline(request, case)
    obs = scenarios(UNDER_TEST)
    assert case in obs, f"{case} was not run: {sorted(obs)}"
    assert not violations(obs[case]), violations(obs[case])


def test_no_case_is_silently_unchecked():
    obs = scenarios(UNDER_TEST)
    assert sorted(obs) == sorted(CASE_IDS)


# ---- the tests themselves: satisfiable, and able to detect the flaw -------------------------
@pytest.mark.parametrize("case", CASE_IDS)
def test_the_hardened_reference_satisfies_every_property(case):
    """If no proxy could pass, the matrix would prove nothing."""
    assert not violations(scenarios("reference")[case])


@pytest.mark.parametrize("case", _cases("front:"))
def test_a_proxy_without_the_sni_check_is_caught(case):
    """Negative control: the same proxy minus the SNI/ECH check must fail every FRONT case ..."""
    assert any(v.startswith("FRONT") for v in violations(scenarios("reference-no-sni")[case]))


@pytest.mark.parametrize("case", [c for c in CASE_IDS if not c.startswith("front:")])
def test_the_sni_mutant_still_passes_everything_else(case):
    """... and nothing else, so each failure above is attributable to the missing check."""
    assert not violations(scenarios("reference-no-sni")[case])
