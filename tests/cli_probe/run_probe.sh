#!/usr/bin/env bash
# Run the REAL agent invocation (hunter.agents.run_plan: its argv, its environment allow-list, its
# CLI hardening) with the PINNED CLIs inside a throwaway user+network+mount namespace that holds
# nothing but loopback, and record what the CLI tries to reach (tests/cli_probe/probe_server.py).
# Dummy credentials only; there is no route anywhere, so nothing can leave this machine.
#
#   run_probe.sh <scenario> <log.jsonl>
#     claude-oauth          Claude Code with a (dummy) valid OAuth login        -> agent claude-1
#     claude-oauth-expired  the same with an expired access token (refresh path)
#     codex-apikey          Codex signed in with an API key                       -> agent codex
#     codex-chatgpt         Codex signed in with ChatGPT, expired token (refresh path)
# Environment: HUNTER_CLI_BIN (directory holding node, claude, codex; required)
#              HUNTER_PY (python with this repository's dependencies; default python3)
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SCEN="${1:?scenario}"; LOG="$(realpath -m "${2:?log file}")"
BIN="${HUNTER_CLI_BIN:?HUNTER_CLI_BIN must point at node + the pinned CLIs}"
PY="$(command -v "${HUNTER_PY:-python3}")"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
mkdir -p "$W/home/.claude" "$W/home/.codex"
printf 'nameserver 127.0.0.1\n' >"$W/resolv.conf"
: >"$LOG"

case "$SCEN" in
  claude-oauth|claude-oauth-expired)
    AGENT=claude-1; exp=4102444800000          # 2100-01-01, in ms
    [[ "$SCEN" == claude-oauth-expired ]] && exp=1000
    printf '{"claudeAiOauth":{"accessToken":"sk-ant-oat01-dummy","refreshToken":"sk-ant-ort01-dummy","expiresAt":%s,"scopes":["user:inference"],"subscriptionType":"pro"}}\n' "$exp" \
      >"$W/home/.claude/.credentials.json" ;;
  codex-apikey)
    AGENT=codex; printf '{"OPENAI_API_KEY":"sk-dummy"}\n' >"$W/home/.codex/auth.json" ;;
  codex-chatgpt)
    AGENT=codex
    python3 - "$W/home/.codex/auth.json" <<'PY'
import base64, json, sys
b64 = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
claims = {"exp": 1000, "email": "probe@example.invalid",
          "https://api.openai.com/auth": {"chatgpt_plan_type": "plus", "chatgpt_user_id": "user-probe",
                                          "chatgpt_account_id": "acct-probe"}}
jwt = b64({"alg": "none", "typ": "JWT"}) + "." + b64(claims) + ".sig"
json.dump({"auth_mode": "chatgpt", "OPENAI_API_KEY": None,
           "tokens": {"id_token": jwt, "access_token": jwt, "refresh_token": "rt-dummy",
                      "account_id": "acct-probe"},
           "last_refresh": "2000-01-01T00:00:00Z"}, open(sys.argv[1], "w"))
PY
    ;;
  *) echo "unknown scenario $SCEN" >&2; exit 2 ;;
esac

# shellcheck disable=SC2016  # expanded inside the namespace
unshare -Urnm --propagation private bash -c '
  set -e
  W="$1"; LOG="$2"; HERE="$3"; shift 3
  ip link set lo up
  mount --bind "$W/resolv.conf" /etc/resolv.conf
  python3 "$HERE/probe_server.py" "$LOG" & srv=$!
  for _ in $(seq 1 50); do grep -q "\"ready\"" "$LOG" 2>/dev/null && break; sleep 0.1; done
  cd "$W"
  rc=0
  "$@" >"$W/stdout" 2>"$W/stderr" || rc=$?
  printf "{\"kind\": \"exit\", \"rc\": %s}\n" "$rc" >>"$LOG"
  tail -c 600 "$W/stderr" | tr -d "\000" | python3 -c "import json,sys; print(json.dumps({\"kind\":\"stderr\",\"text\":sys.stdin.read()}))" >>"$LOG"
  kill "$srv" 2>/dev/null || true
' probe "$W" "$LOG" "$HERE" \
  timeout 150 env -i PATH="$BIN:/usr/bin:/bin" HOME="$W/home" LANG=C.UTF-8 TZ=UTC \
    PYTHONPATH="$ROOT" AGENT_MODE=cli HUNTER_AGENT_NAME="$AGENT" \
    CLAUDE_CONFIG_DIR="$W/home/.claude" CODEX_HOME="$W/home/.codex" \
    HTTPS_PROXY=http://127.0.0.1:3128 HTTP_PROXY=http://127.0.0.1:3128 NO_PROXY=localhost,127.0.0.1 \
    "$PY" -c 'import sys; from hunter.agents import run_plan
try:
    run_plan(sys.argv[1], {"kind": "internship", "roles": ["data"], "primary_countries": ["CH"]})
except Exception as e:
    print(type(e).__name__, str(e)[:300], file=sys.stderr); sys.exit(3)' "$AGENT"
