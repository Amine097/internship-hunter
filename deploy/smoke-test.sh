#!/usr/bin/env bash
# End-to-end smoke + isolation test against a RUNNING stack (demo mode, throwaway secrets).
# Usage: ADMIN_TOKEN=... deploy/smoke-test.sh [docker compose args, e.g. -p hunterverify --env-file f]
set -Eeuo pipefail
: "${ADMIN_TOKEN:?set ADMIN_TOKEN}"
API="${API_URL:-http://127.0.0.1:8000}"
COMPOSE=(docker compose "$@")
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ok() { echo "ok   $*"; }
fail() { echo "FAIL $*" >&2; exit 1; }
api() { curl -fsS -H "X-Admin-Token: $ADMIN_TOKEN" "$@"; }
exec_in() { local svc="$1"; shift; "${COMPOSE[@]}" exec -T "$svc" "$@"; }

wait_scan() { # wait_scan <scan_id>
  for _ in $(seq 1 60); do
    state="$(api "$API/scans" | python3 -c "import sys,json; print(next((s['state'] for s in json.load(sys.stdin) if s['id']==$1), ''))")"
    [[ "$state" == finished || "$state" == partial || "$state" == failed ]] && { echo "$state"; return; }
    sleep 2
  done
  echo timeout
}

curl -fsS "$API/health" | grep -q '"submission_enabled":false' || fail "health / submission flag"
ok "health reports submission disabled"
curl -fsS "$API/ready" | grep -q ready || fail "ready"
ok "ready (postgres + redis reachable)"
[[ "$(curl -s -o /dev/null -w '%{http_code}' "$API/profiles")" == 401 ]] || fail "unauthenticated /profiles"
ok "admin routes reject missing token"

id="$(api -X POST "$API/scan/1" | python3 -c 'import sys,json; print(json.load(sys.stdin)["scan_id"])')"
[[ "$(wait_scan "$id")" == finished ]] || fail "scan $id did not finish"
runs="$(api "$API/scans" | python3 -c "import sys,json; s=[x for x in json.load(sys.stdin) if x['id']==$id][0]; print(sum(a['state']=='finished' and a['output']['mode']=='demo' for a in s['agents']))")"
[[ "$runs" == 3 ]] || fail "expected 3 finished demo agent runs, got $runs"
ok "scan $id finished with three isolated demo agents"

[[ "$(exec_in redis id -u | tr -d '\r')" != 0 ]] || fail "redis runs as root"
ok "redis runs unprivileged"

for target in redis:6379 postgres:5432 agent-claude-1:8100 api:8000; do
  out="$(exec_in agent-codex python - <<PY
import socket
h, p = "${target%%:*}", int("${target##*:}")
try:
    socket.create_connection((h, p), timeout=3)
    print("REACHABLE")
except OSError:
    print("blocked")
PY
)"
  [[ "$(echo "$out" | tr -d '\r')" == blocked ]] || fail "agent-codex can reach $target"
done
ok "agent container cannot reach redis / postgres / another agent / api"

env_dump="$(exec_in agent-codex env)"
for k in REDIS_URL DATABASE_URL ADMIN_TOKEN TELEGRAM_BOT_TOKEN POSTGRES_PASSWORD REDIS_PASSWORD; do
  grep -q "^$k=" <<<"$env_dump" && fail "agent env contains $k"
done
ok "agent environment holds no infrastructure credentials"

for a in agent-claude-1 agent-claude-2 agent-codex; do
  exec_in discovery python - <<PY || fail "orchestrator cannot reach $a"
import socket
socket.create_connection(("$a", 8100), timeout=3)
PY
done
ok "orchestrator reaches every agent runner"

code="$(exec_in discovery python - <<'PY'
import urllib.request, urllib.error
req = urllib.request.Request("http://agent-codex:8100/plan", data=b'{"profile":{"kind":"internship"}}',
                             headers={"Content-Type": "application/json"})
try:
    urllib.request.urlopen(req, timeout=5); print(200)
except urllib.error.HTTPError as e:
    print(e.code)
PY
)"
[[ "$(echo "$code" | tr -d '\r')" == 401 ]] || fail "agent runner accepted an unauthenticated plan request ($code)"
ok "agent runner rejects unauthenticated calls"

before="$(exec_in discovery python -c "import os,redis; print(redis.Redis.from_url(os.environ['REDIS_URL']).zcard('rq:failed:discovery'))" | tr -d '\r')"
exec_in discovery python - < "$HERE/smoke/attack.py" >/dev/null
sleep 8
exec_in discovery sh -c 'test ! -e /tmp/PWNED-PICKLE && test ! -e /tmp/PWNED-NAME' || fail "ATTACK SUCCEEDED: sentinel exists"
after="$(exec_in discovery python -c "import os,redis; print(redis.Redis.from_url(os.environ['REDIS_URL']).zcard('rq:failed:discovery'))" | tr -d '\r')"
[[ $((after - before)) -ge 1 ]] || fail "forged jobs were not recorded as failed"
ok "pickled and forged-name jobs injected into live Redis were rejected"

id="$(api -X POST "$API/scan/2" | python3 -c 'import sys,json; print(json.load(sys.stdin)["scan_id"])')"
[[ "$(wait_scan "$id")" == finished ]] || fail "worker unusable after attack"
ok "worker still processes legitimate scans after the attack"
echo "SMOKE TEST PASSED"
