"""The PINNED Claude Code and Codex CLIs, invoked exactly as hunter/agents.py invokes them, observed
in a namespace with nothing but loopback (tests/cli_probe). It answers, with evidence, the
questions the egress policy rests on:

  * does the CLI hand the HOSTNAME to the proxy (CONNECT host:443) or resolve names itself?
    -> no DNS query at all may be seen (the agents have no resolver for public names anyway)
  * is the TLS SNI the CONNECT host, and is Encrypted Client Hello absent?
    -> required by the proxy's TLS gate; a mismatch here would break the CLI, not just a test
  * which hosts does each login mode need, and is every one of them allow-listed by default?
  * do the CLIs still try the hosts the hardening turns off (github.com, analytics, telemetry)?

Needs the pinned CLIs and Node (HUNTER_CLI_BIN, see the cli-egress-probe CI job), unprivileged
user namespaces and `ip`. Opt-in: HUNTER_CLI_PROBE=1; HUNTER_CLI_PROBE_REQUIRED=1 (CI) turns
"cannot run" into a failure. Each scenario runs once, all in parallel (each lasts until the
agent's own 90 s timeout: the observation endpoint never lets a request succeed).
"""
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker"))
import egress_proxy as ep  # noqa: E402

RUN = ROOT / "tests" / "cli_probe" / "run_probe.sh"
ENABLED = os.environ.get("HUNTER_CLI_PROBE") == "1"
REQUIRED = os.environ.get("HUNTER_CLI_PROBE_REQUIRED") == "1"
BIN = os.environ.get("HUNTER_CLI_BIN", "")


def default_allowlist(service: str) -> set[str]:
    env = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"][service]["environment"]
    m = re.fullmatch(r"\$\{EGRESS_ALLOW_[A-Z]+:-([^}]*)\}", env["EGRESS_ALLOW"])
    assert m, env["EGRESS_ALLOW"]
    return set(m.group(1).split(","))


# scenario -> (the proxy that agent uses, hosts that MUST be seen: the positive control)
SCENARIOS = {
    "claude-oauth": ("egress-claude-1", {"api.anthropic.com"}),
    "claude-oauth-expired": ("egress-claude-1", {"platform.claude.com"}),
    "codex-apikey": ("egress-codex", {"api.openai.com"}),
    "codex-chatgpt": ("egress-codex", {"auth.openai.com", "chatgpt.com"}),
}
NEVER = {"github.com", "api.github.com", "ab.chatgpt.com", "statsig.anthropic.com",
         "console.anthropic.com", "claude.ai", "objects.githubusercontent.com"}


@pytest.fixture(scope="module")
def observed(tmp_path_factory):
    if not ENABLED:
        pytest.skip("set HUNTER_CLI_PROBE=1 (and HUNTER_CLI_BIN) to run the pinned CLIs")
    missing = [t for t in ("unshare", "ip", "timeout") if not shutil.which(t)]
    if not BIN or not all((Path(BIN) / b).exists() for b in ("node", "claude", "codex")):
        missing.append("HUNTER_CLI_BIN with node, claude, codex")
    if not missing and subprocess.run(["unshare", "-Urnm", "true"], capture_output=True).returncode:
        missing.append("unprivileged user+network+mount namespaces")
    if missing:
        if REQUIRED:
            pytest.fail(f"HUNTER_CLI_PROBE_REQUIRED=1 but the probe cannot run: {missing}")
        pytest.skip(f"cannot run the CLI probe: {missing}")
    d = tmp_path_factory.mktemp("cli-probe")

    def one(scenario):
        log = d / f"{scenario}.jsonl"
        r = subprocess.run(["bash", str(RUN), scenario, str(log)], capture_output=True, text=True,
                           timeout=240, env={**os.environ, "HUNTER_PY": sys.executable})
        assert r.returncode == 0, f"{scenario}: {r.stdout}\n{r.stderr}"
        return scenario, [json.loads(ln) for ln in log.read_text().splitlines() if ln.strip()]
    with concurrent.futures.ThreadPoolExecutor(len(SCENARIOS)) as pool:
        return dict(pool.map(one, SCENARIOS))


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_the_probe_really_observed_the_cli(observed, scenario):
    recs = observed[scenario]
    kinds = {r["kind"] for r in recs}
    assert {"ready", "exit"} <= kinds, recs[:5]
    hosts = {r["target"].rpartition(":")[0] for r in recs if r["kind"] == "request"}
    needed = SCENARIOS[scenario][1]
    assert needed <= hosts, f"{scenario}: expected {needed}, saw {hosts}"


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_the_cli_never_resolves_a_name_itself(observed, scenario):
    dns = [r for r in observed[scenario] if r["kind"] == "dns"]
    assert dns == [], f"{scenario} sent DNS queries itself: {dns[:5]}"


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_every_request_is_connect_to_a_hostname_on_443(observed, scenario):
    for r in observed[scenario]:
        if r["kind"] != "request":
            continue
        host, _, port = r["target"].rpartition(":")
        assert r["method"] == "CONNECT", r
        assert port == "443" and ep.valid_hostname(host), r


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_the_tls_sni_is_the_connect_host_and_there_is_no_ech(observed, scenario):
    hellos = [r for r in observed[scenario] if r["kind"] == "request" and "sni" in r]
    assert hellos, f"{scenario}: no ClientHello observed"
    for r in hellos:
        assert r["sni"] == r["target"].rpartition(":")[0], r
        assert r["ech"] is False, r
    assert not [r for r in observed[scenario] if "first_record_type" in r]


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_everything_the_cli_needs_is_allow_listed_and_nothing_else_is_tried(observed, scenario):
    proxy = SCENARIOS[scenario][0]
    hosts = {r["target"].rpartition(":")[0] for r in observed[scenario] if r["kind"] == "request"}
    assert hosts <= default_allowlist(proxy), f"{scenario} needs {hosts - default_allowlist(proxy)}"
    assert not hosts & NEVER, f"{scenario} still tries {hosts & NEVER}"
