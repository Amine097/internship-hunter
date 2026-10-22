"""Static invariants of the CLI egress policy: what the image pins, what the defaults allow, and
how hunter/agents.py hardens the CLIs. The behaviour behind each is tested elsewhere
(test_egress_proxy.py: the proxy; test_cli_egress_probe.py: the pinned CLIs)."""
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from hunter import agents

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = yaml.safe_load((ROOT / "compose.yaml").read_text())
DOCKERFILE = (ROOT / "docker" / "egress-proxy.Dockerfile").read_text()
PROXY_PY = ROOT / "docker" / "egress_proxy.py"


def default_allow(service):
    raw = COMPOSE["services"][service]["environment"]["EGRESS_ALLOW"]
    return set(re.fullmatch(r"\$\{EGRESS_ALLOW_[A-Z]+:-([^}]*)\}", raw).group(1).split(","))


# ---- the defaults are exactly what the pinned CLIs need (measured: tests/cli_probe) --------------
def test_the_anthropic_default_is_the_api_and_its_oauth_token_endpoint_only():
    for svc in ("egress-claude-1", "egress-claude-2"):
        assert default_allow(svc) == {"api.anthropic.com", "platform.claude.com"}


def test_the_openai_default_is_the_api_and_the_chatgpt_login_endpoints_only():
    assert default_allow("egress-codex") == {"api.openai.com", "auth.openai.com", "chatgpt.com"}


@pytest.mark.parametrize("host", ["claude.ai", "console.anthropic.com", "statsig.anthropic.com",
                                  "github.com", "api.github.com", "ab.chatgpt.com"])
def test_hosts_the_pinned_clis_do_not_need_are_not_allowed_by_default(host):
    for svc in ("egress-claude-1", "egress-claude-2", "egress-codex"):
        assert host not in default_allow(svc), (svc, host)


def test_the_documented_example_matches_compose():
    env = (ROOT / ".env.example").read_text()
    assert "# EGRESS_ALLOW_ANTHROPIC=api.anthropic.com,platform.claude.com\n" in env
    assert "# EGRESS_ALLOW_OPENAI=api.openai.com,auth.openai.com,chatgpt.com\n" in env


# ---- the image: pinned, no tinyproxy, the interpreter isolated -----------------------------------
def test_the_proxy_image_is_pinned_by_digest_and_exact_package_version():
    assert re.search(r"^FROM alpine:3\.20@sha256:[0-9a-f]{64}$", DOCKERFILE, re.M)
    assert re.search(r"apk add --no-cache python3=\d+\.\d+\.\d+-r\d+ ", DOCKERFILE)
    assert "tinyproxy" not in DOCKERFILE.split("\nFROM")[1]     # only mentioned in the comment


def test_the_proxy_image_keeps_check_dns_nslookup_control_by_having_no_bare_python():
    # deploy/check-dns.sh: `command -v python` picks the python probe; the proxies must stay on the
    # busybox flavour so internal-only services without Python keep their positive control
    assert "rm -f /usr/bin/python" in DOCKERFILE
    check_dns = (ROOT / "deploy" / "check-dns.sh").read_text()
    assert "command -v python" in check_dns


def test_the_proxy_runs_isolated_from_environment_and_site_packages():
    assert PROXY_PY.read_text().splitlines()[0] == "#!/usr/bin/python3 -IB"
    assert "COPY docker/egress_proxy.py /usr/local/bin/hunter-egress-proxy" in DOCKERFILE
    wrapper = (ROOT / "docker" / "egress-proxy.sh").read_text()
    assert wrapper.rstrip().endswith("exec hunter-egress-proxy")
    assert "egress-forbidden-check.sh" in wrapper            # the start gate is kept


def test_the_proxy_uses_only_the_standard_library():
    src = PROXY_PY.read_text()
    imports = set(re.findall(r"^(?:import|from) ([a-z_]+)", src, re.M))
    assert imports <= {"__future__", "asyncio", "ipaddress", "json", "os", "re", "signal",
                       "socket", "sys", "time"}, imports


def test_the_proxy_module_compiles_under_python_3_12_syntax():
    subprocess.run(["python3", "-m", "py_compile", str(PROXY_PY)], check=True)


# ---- the CLIs are told not to contact anything beyond their API ----------------------------------
def test_every_cli_invocation_carries_the_network_hardening(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("DATABASE_URL", "postgresql://secret")
    env = agents.cli_env()
    assert env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] == "1"
    assert env["DISABLE_AUTOUPDATER"] == "1"
    assert "DATABASE_URL" not in env                  # the allow-list still holds


def test_codex_is_run_with_updates_analytics_plugins_and_apps_off(monkeypatch, tmp_path):
    calls = []

    class Done:
        returncode = 0

    def fake_run(command, **kw):
        calls.append((command, kw["env"]))
        out = command[command.index("--output-last-message") + 1]
        Path(out).write_text('{"queries": ["x"]}')
        return Done()
    monkeypatch.setattr(agents.subprocess, "run", fake_run)
    monkeypatch.setattr(agents, "get_settings", lambda: type("S", (), {
        "agent_mode": "cli", "hunter_agent_name": "codex"})())
    agents.run_plan("codex", {"kind": "internship", "roles": ["x"]})
    command, env = calls[0]
    overrides = [command[i + 1] for i, a in enumerate(command) if a == "-c"]
    assert set(overrides) == set(agents.CODEX_CONFIG_OVERRIDES)
    for needed in ("features.plugins=false", "features.apps=false", "analytics.enabled=false",
                   "check_for_update_on_startup=false"):
        assert needed in overrides
    assert command[:2] == ["codex", "exec"] and env["DISABLE_AUTOUPDATER"] == "1"
