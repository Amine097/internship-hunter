#!/usr/bin/env bash
# End-to-end smoke, isolation and egress test against a RUNNING stack (demo mode, throwaway
# secrets). Usage: ADMIN_TOKEN=... deploy/smoke-test.sh [docker compose args, e.g. -p x]
# SMOKE_EXTERNAL=0 skips the checks that need real Internet access (allowed-host CONNECT).
# SMOKE_EXPECT_ROOTLESS=1 additionally asserts the Docker daemon is rootless (production host).
# SMOKE_HOST_ISOLATION=enforce (default) | report
#   The proxy->host-gateway probe depends on the HOST, not on this repository: on a rootful
#   Docker host any container can reach services the host listens on at the bridge gateway
#   (e.g. sshd on 0.0.0.0, as on GitHub-hosted runners). CI therefore runs "report" and prints
#   what is reachable; the production smoke test MUST run "enforce" (docs/deployment.md).
set -Eeuo pipefail
: "${ADMIN_TOKEN:?set ADMIN_TOKEN}"
API="${API_URL:-http://127.0.0.1:8000}"
EXTERNAL="${SMOKE_EXTERNAL:-1}"
COMPOSE=(docker compose "$@")
ok() { echo "ok   $*"; }
fail() { echo "FAIL $*" >&2; exit 1; }
api() { curl -fsS -H "X-Admin-Token: $ADMIN_TOKEN" "$@"; }
exec_in() { local svc="$1"; shift; "${COMPOSE[@]}" exec -T "$svc" "$@"; }

wait_scan() { # wait_scan <scan_id> -> final state
  for _ in $(seq 1 60); do
    state="$(api "$API/scans" | python3 -c "import sys,json; print(next((s['state'] for s in json.load(sys.stdin) if s['id']==$1), ''))")"
    case "$state" in finished|partial|failed|cancelled) echo "$state"; return ;; esac
    sleep 2
  done
  echo timeout
}

# 1. service level -------------------------------------------------------------------------
curl -fsS "$API/health" | grep -q '"submission_enabled":false' || fail "health / submission flag"
ok "health reports submission disabled"
curl -fsS "$API/ready" | grep -q ready || fail "ready"
ok "ready (PostgreSQL reachable, schema matches)"
[[ "$(curl -s -o /dev/null -w '%{http_code}' "$API/profiles")" == 401 ]] || fail "unauthenticated /profiles"
ok "admin routes reject a missing token"

id="$(api -X POST "$API/scan/1" | python3 -c 'import sys,json; print(json.load(sys.stdin)["scan_id"])')"
again="$(api -X POST "$API/scan/1" | python3 -c 'import sys,json; print(json.load(sys.stdin)["scan_id"])')"
[[ "$id" == "$again" ]] || [[ "$(wait_scan "$id")" != timeout ]] || fail "idempotent scheduling"
[[ "$(wait_scan "$id")" == finished ]] || fail "scan $id did not finish"
runs="$(api "$API/scans" | python3 -c "import sys,json; s=[x for x in json.load(sys.stdin) if x['id']==$id][0]; print(sum(a['state']=='finished' and a['output']['mode']=='demo' for a in s['agents']))")"
[[ "$runs" == 3 ]] || fail "expected 3 finished demo agent runs, got $runs"
ok "scan $id finished through the PostgreSQL queue with three isolated demo agents"

# 2. the queue is a table: nothing executable can be forged -----------------------------------
out="$(exec_in discovery python - <<'PY'
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from hunter.db import session_scope
for stmt in ("UPDATE tasks SET kind = 'subprocess.run'", "UPDATE tasks SET state = 'pwned'"):
    try:
        with session_scope() as db:
            db.execute(text(stmt))
        print("ACCEPTED", stmt)
    except IntegrityError:
        print("rejected")
PY
)"
[[ "$(echo "$out" | tr -d '\r' | sort -u)" == rejected ]] || fail "forged task rows were accepted: $out"
ok "database rejects forged task kinds/states (no function names, no payloads)"

# 3. agent isolation --------------------------------------------------------------------------
reach() { # reach <service> <host:port> -> REACHABLE|blocked
  exec_in "$1" python - <<PY | tr -d '\r'
import socket
h, p = "${2%%:*}", int("${2##*:}")
try:
    socket.create_connection((h, p), timeout=4)
    print("REACHABLE")
except OSError:
    print("blocked")
PY
}
for target in postgres:5432 agent-claude-1:8100 api:8000 discovery:8100 egress-claude-1:3128 \
              1.1.1.1:443 8.8.8.8:53 169.254.169.254:80; do
  [[ "$(reach agent-codex "$target")" == blocked ]] || fail "agent-codex can reach $target"
done
ok "agent cannot reach postgres / peers / api / orchestrator / other proxies / the Internet directly"
[[ "$(reach agent-codex egress-codex:3128)" == REACHABLE ]] || fail "agent cannot reach its own proxy"
ok "agent reaches only its own egress proxy"

env_dump="$(exec_in agent-codex env)"
for k in DATABASE_URL ADMIN_TOKEN TELEGRAM_BOT_TOKEN POSTGRES_PASSWORD REDIS_URL; do
  grep -q "^$k=" <<<"$env_dump" && fail "agent env contains $k"
done
ok "agent environment holds no infrastructure credentials"

for a in agent-claude-1 agent-claude-2 agent-codex; do
  [[ "$(reach discovery "$a:8100")" == REACHABLE ]] || fail "orchestrator cannot reach $a"
done
ok "orchestrator reaches every agent runner"

code="$(exec_in discovery python - <<'PY' | tr -d '\r'
import urllib.request, urllib.error
req = urllib.request.Request("http://agent-codex:8100/plan", data=b'{"profile":{"kind":"internship"}}',
                             headers={"Content-Type": "application/json"})
try:
    urllib.request.urlopen(req, timeout=5); print(200)
except urllib.error.HTTPError as e:
    print(e.code)
PY
)"
[[ "$code" == 401 ]] || fail "agent runner accepted an unauthenticated plan request ($code)"
ok "agent runner rejects unauthenticated calls"

# 4. egress policy ----------------------------------------------------------------------------
connect() { # connect <agent> <proxy> <host> <port> -> HTTP status of CONNECT, or "error"
  exec_in "$1" python - <<PY | tr -d '\r'
import socket
try:
    s = socket.create_connection(("$2", 3128), timeout=8)
    s.sendall(b"CONNECT $3:$4 HTTP/1.1\r\nHost: $3:$4\r\n\r\n")
    print(s.recv(256).split(b" ")[1].decode())
except Exception:
    print("error")
PY
}
denied() { [[ "$1" != 200 ]] && return 0 || return 1; }
for t in "example.com 443" "1.1.1.1 443" "169.254.169.254 443" "10.0.0.1 443" "host.docker.internal 443" \
         "100.64.0.1 443" "100.100.100.100 443" "192.168.0.1 443" "172.16.0.1 443" \
         "127.0.0.1 443" "localhost 443" \
         "api.anthropic.com 22" "api.anthropic.com.evil.example 443" "api.openai.com 443"; do
  read -r host port <<<"$t"
  denied "$(connect agent-claude-1 egress-claude-1 "$host" "$port")" || fail "claude-1 proxy allowed $host:$port"
done
denied "$(connect agent-codex egress-codex api.anthropic.com 443)" || fail "codex proxy allowed anthropic"
ok "proxy refuses other hosts, IP literals, tailnet/LAN/metadata/loopback addresses, other ports and look-alikes"

plain="$(exec_in agent-codex python - <<'PY' | tr -d '\r'
import socket
try:
    s = socket.create_connection(("egress-codex", 3128), timeout=8)
    s.sendall(b"GET http://api.openai.com/ HTTP/1.1\r\nHost: api.openai.com\r\nConnection: close\r\n\r\n")
    print(s.recv(64).split(b" ")[1].decode())
except Exception:
    print("error")
PY
)"
[[ "$plain" != 200 && "$plain" != 301 && "$plain" != 404 && "$plain" != 400 ]] \
  || fail "proxy forwarded a plain-HTTP request to an allowed host (status $plain)"
ok "proxy is CONNECT-only: plain HTTP forwarding to an allowed host is refused ($plain)"
if [[ "$EXTERNAL" == 1 ]]; then
  [[ "$(connect agent-claude-1 egress-claude-1 api.anthropic.com 443)" == 200 ]] \
    || fail "claude-1 cannot reach its provider"
  [[ "$(connect agent-codex egress-codex api.openai.com 443)" == 200 ]] \
    || fail "codex cannot reach its provider"
  ok "legitimate provider access still works (CONNECT api.anthropic.com / api.openai.com)"
fi

# 4b. host isolation (the checks that matter most on a rootless production host) ----------------
# (1) Docker control surface: no container holds the Docker socket or runs privileged
bad="$("${COMPOSE[@]}" ps -q | xargs -r docker inspect --format \
  '{{.Name}} priv={{.HostConfig.Privileged}} sock={{range .Mounts}}{{.Source}} {{end}}' \
  | grep -E 'priv=true|docker\.sock' || true)"
[[ -z "$bad" ]] || fail "container with Docker socket or privileged: $bad"
if [[ "${SMOKE_EXPECT_ROOTLESS:-0}" == 1 ]]; then
  docker info --format '{{.SecurityOptions}}' | grep -q rootless || fail "Docker daemon is not rootless"
  ok "Docker daemon is rootless"
fi
ok "no container mounts the Docker socket or runs privileged"
# (2) the only container with an outbound route cannot reach host-side services
HOST_ISOLATION="${SMOKE_HOST_ISOLATION:-enforce}"
[[ "$HOST_ISOLATION" == enforce || "$HOST_ISOLATION" == report ]] \
  || fail "SMOKE_HOST_ISOLATION must be enforce or report"
gw="$(exec_in egress-codex sh -c "ip route | awk '/default/ {print \$3; exit}'" | tr -d '\r')"
if [[ -n "$gw" ]]; then
  reachable=""
  for port in 22 2375 2376 5432 8000; do
    if exec_in egress-codex nc -z -w 3 "$gw" "$port" >/dev/null 2>&1; then
      reachable="$reachable $port"
    fi
  done
  if [[ -z "$reachable" ]]; then
    ok "egress proxy cannot reach its gateway/host ($gw) on ssh, docker API, postgres or API port"
  elif [[ "$HOST_ISOLATION" == enforce ]]; then
    fail "egress proxy container can reach host/gateway $gw on port(s):$reachable"
  else
    echo "WARN host-isolation (report mode): proxy container reaches $gw on port(s):$reachable" \
         "- host services are exposed to containers on this Docker host; NOT acceptable in" \
         "production (needs rootless Docker + sshd bound to the tailnet interface)"
  fi
fi
# (3) no listening port other than the published loopback API on the host side
published="$("${COMPOSE[@]}" ps --format '{{.Publishers}}' | grep -v '^\[\]$' | grep -v '^$' || true)"
if grep -E '0\.0\.0\.0|::' <<<"$published" | grep -vq '^$'; then
  fail "a service is published on all interfaces: $published"
fi
ok "only loopback-published ports"

# 5. the worker survives and keeps serving -------------------------------------------------
id="$(api -X POST "$API/scan/2" | python3 -c 'import sys,json; print(json.load(sys.stdin)["scan_id"])')"
[[ "$(wait_scan "$id")" == finished ]] || fail "second profile scan did not finish"
ok "second scan finished"
echo "SMOKE TEST PASSED"
