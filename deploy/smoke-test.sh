#!/usr/bin/env bash
# End-to-end smoke, isolation and egress test against a RUNNING stack (demo mode, throwaway
# secrets). Usage: ADMIN_TOKEN=... deploy/smoke-test.sh [docker compose args, e.g. -p x]
# SMOKE_EXTERNAL=0 skips the checks that need real Internet access (allowed-host CONNECT).
# SMOKE_EXPECT_ROOTLESS=1 additionally asserts the Docker daemon is rootless (production host).
# SMOKE_HOST_ISOLATION=enforce (default) | report
#   Whether containers with a route out can dial the HOST (its Tailscale IP, its other
#   addresses, the bridge gateway) depends on the HOST, not on this repository: rootless
#   Docker's user-space NAT, or sshd on 0.0.0.0 on a rootful runner, make them reachable. CI
#   therefore runs "report" and prints what is reachable; the production smoke test MUST run
#   "enforce" with SMOKE_PROTECTED_IPS=<tailscale ip> (docs/deployment.md, "Host isolation").
#   The checks live in deploy/check-host-isolation.sh (see its header for all knobs).
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${ADMIN_TOKEN:?set ADMIN_TOKEN}"
API="${API_URL:-http://127.0.0.1:18000}"
EXTERNAL="${SMOKE_EXTERNAL:-1}"
COMPOSE=(docker compose "$@")
# The admin token must only ever reach OUR api container. Never trust a port number alone
# (the production host runs a rootful Gluetun on <tailscale ip>:8000): the URL must be loopback,
# and compose itself must say that the api service publishes exactly that host:port.
[[ "$API" =~ ^http://127\.0\.0\.1:([0-9]{1,5})$ ]] \
  || { echo "FAIL API_URL must be http://127.0.0.1:<port> - the literal IPv4 loopback, not 'localhost' (the admin token is sent to it)" >&2; exit 1; }
api_published="$("${COMPOSE[@]}" port api 8000 2>/dev/null | tr -d '\r')"
[[ "$api_published" == "127.0.0.1:${BASH_REMATCH[1]}" ]] \
  || { echo "FAIL compose says the api publishes '${api_published:-nothing}', not $API: refusing to send ADMIN_TOKEN" >&2; exit 1; }
# host addresses that no container may reach (SMOKE_PROTECTED_IPS + this host's own addresses)
mapfile -t PROTECTED_IPS < <("$HERE/check-host-isolation.sh" --list-ips)
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

# Every scan needs the owner's approval. The smoke test plays the owner by calling the same
# function the Telegram callback calls, inside the controller container.
session_state() { exec_in session-controller python - "$1" <<'PY' | tr -d '\r'
import sys
from hunter.db import session_scope
from hunter.models import ResourceSession
with session_scope() as db:
    print(db.get(ResourceSession, sys.argv[1]).state)
PY
}
decide() { # decide <session_id> <accept|decline>
  exec_in session-controller python - "$1" "$2" <<'PY' | tr -d '\r'
import sys
from hunter import sessions
from hunter.db import session_scope
from hunter.models import ResourceSession
sid, what = sys.argv[1], sys.argv[2]
with session_scope() as db:
    nonce = db.get(ResourceSession, sid).nonce
print(sessions.decide(sid, nonce, what == "accept").outcome)
PY
}
wait_session() { # wait_session <session_id> <state...>
  local sid="$1"; shift
  for _ in $(seq 1 90); do
    cur="$(session_state "$sid")"
    for want in "$@"; do [[ "$cur" == "$want" ]] && { echo "$cur"; return; }; done
    sleep 2
  done
  echo "timeout($cur)"
}
scan_count() { api "$API/scans" | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))'; }

sid="$(api -X POST "$API/scan/1" | python3 -c 'import sys,json; r=json.load(sys.stdin); assert r["state"]=="pending_approval"; print(r["session_id"])')"
sleep 6
[[ "$(session_state "$sid")" == pending && "$(scan_count)" == 0 ]] \
  || fail "a scan started (or the request vanished) without approval"
ok "POST /scan only requests approval: nothing started while pending"
[[ "$(decide "$sid" accept)" == accepted ]] || fail "accept was not applied"
[[ "$(decide "$sid" accept)" == already_handled ]] || fail "double accept was applied twice"
[[ "$(wait_session "$sid" completed failed blocked)" == completed ]] \
  || fail "session $sid did not complete (state $(session_state "$sid"))"
id="$(api "$API/scans" | python3 -c 'import sys,json; print(json.load(sys.stdin)[0]["id"])')"
[[ "$(wait_scan "$id")" == finished ]] || fail "scan $id did not finish"
runs="$(api "$API/scans" | python3 -c "import sys,json; s=[x for x in json.load(sys.stdin) if x['id']==$id][0]; print(sum(a['state']=='finished' and a['output']['mode']=='demo' for a in s['agents']))")"
[[ "$runs" == 3 ]] || fail "expected 3 finished demo agent runs, got $runs"
ok "approved session $sid ran scan $id with three isolated demo agents and completed"

dec="$(api -X POST "$API/scan/2" | python3 -c 'import sys,json; print(json.load(sys.stdin)["session_id"])')"
[[ "$(decide "$dec" decline)" == declined ]] || fail "decline was not applied"
sleep 4
[[ "$(session_state "$dec")" == declined ]] || fail "declined session changed state"
ok "declined request stays declined; no scan started"

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
# The host's own addresses follow SMOKE_HOST_ISOLATION like deploy/check-host-isolation.sh: on a
# rootful CI runner an internal network's gateway IS an address of the host (sshd listens on
# 0.0.0.0), so there it is reported; on the production host it must be unreachable (enforce).
host_leaks=()
for ip in "${PROTECTED_IPS[@]}"; do
  for port in 22 8000; do
    [[ "$(reach agent-codex "$ip:$port")" == blocked ]] || host_leaks+=("$ip:$port")
  done
done
if [[ ${#host_leaks[@]} -gt 0 ]]; then
  case "${SMOKE_HOST_ISOLATION:-enforce}" in
    report) echo "WARN agent-codex reaches host address(es) ${host_leaks[*]} (report mode: a rootful" \
                 "daemon exposes the bridge gateway; NOT acceptable in production)" >&2 ;;
    *) fail "agent-codex can reach host address(es): ${host_leaks[*]}" ;;
  esac
fi
if [[ ${#host_leaks[@]} -eq 0 ]]; then
  ok "agent cannot reach postgres / peers / api / orchestrator / other proxies / the host / the Internet directly"
else
  ok "agent cannot reach postgres / peers / api / orchestrator / other proxies / the Internet directly (host: see WARN)"
fi
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

ctl_mounts="$(docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' \
  "$("${COMPOSE[@]}" ps -q session-controller)")"
[[ "$ctl_mounts" != *hunter-rsm* ]] || fail "session-controller holds the broker socket in demo"
ok "demo stack: session-controller has no broker socket and RSM is disabled"

# 4. egress policy ----------------------------------------------------------------------------
# Every agent reaches the outside only through ITS proxy (docker/egress_proxy.py). A refusal counts
# only as the proxy's POLICY answer - exactly `403` with an X-Egress-Reason - never as "anything but
# 200": a dead, crashed or misrouted proxy (connection error, 502, 503) must FAIL this test.
PAIRS=("agent-claude-1 egress-claude-1 api.anthropic.com" "agent-claude-2 egress-claude-2 api.anthropic.com"
       "agent-codex egress-codex api.openai.com")
ask() { # ask <agent> <proxy> <request line> -> "<status> <X-Egress-Reason or ->", or "error <why>"
  exec_in "$1" python - "$2" "$3" <<'PY' | tr -d '\r'
import socket, sys
try:
    s = socket.create_connection((sys.argv[1], 3128), timeout=8)
    host = sys.argv[2].split(" ")[1].split("/")[2] if "://" in sys.argv[2] else sys.argv[2].split(" ")[1]
    s.sendall(f"{sys.argv[2]} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(1024)
        if not chunk:
            break
        head += chunk
    lines = head.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
    reason = next((ln.split(": ", 1)[1] for ln in lines[1:] if ln.lower().startswith("x-egress-reason: ")), "-")
    print(lines[0].split(" ")[1], reason)
except Exception as e:
    print("error", type(e).__name__)
PY
}
refused() { [[ "$1" =~ ^403\ (host|port|method)$ ]]; }   # the proxy said no, for a policy reason
# the proxies must refuse CONNECT to the real host addresses (hostname policy; the network-level
# proof that the host is unreachable is deploy/check-host-isolation.sh below)
targets=()
for ip in "${PROTECTED_IPS[@]}"; do targets+=("$ip:22" "$ip:8000" "$ip:443"); done
targets+=(example.com:443 1.1.1.1:443 169.254.169.254:443 10.0.0.1:443 host.docker.internal:443
          100.64.0.1:443 100.100.100.100:443 192.168.0.1:443 172.16.0.1:443 127.0.0.1:443
          localhost:443 "[::1]:443" api.anthropic.com:22 api.anthropic.com.evil.example:443
          api.openai.com:80 github.com:443 claude.ai:443 statsig.anthropic.com:443)
for pair in "${PAIRS[@]}"; do
  read -r agent proxy _ <<<"$pair"
  for t in "${targets[@]}"; do
    r="$(ask "$agent" "$proxy" "CONNECT $t")"
    refused "$r" || fail "$proxy did not refuse CONNECT $t with a policy 403 (got: $r)"
  done
done
for t in agent-claude-1:egress-claude-1:api.openai.com agent-claude-2:egress-claude-2:api.openai.com \
         agent-codex:egress-codex:api.anthropic.com; do
  IFS=: read -r agent proxy host <<<"$t"
  r="$(ask "$agent" "$proxy" "CONNECT $host:443")"
  refused "$r" || fail "$proxy did not refuse the other provider $host (got: $r)"
done
ok "all three proxies refuse other hosts, IP literals, tailnet/LAN/metadata/loopback addresses, other ports, look-alikes and the other provider (policy 403)"
for pair in "${PAIRS[@]}"; do
  read -r agent proxy host <<<"$pair"
  r="$(ask "$agent" "$proxy" "GET http://$host/")"
  [[ "$r" == "403 method" ]] || fail "$proxy did not refuse plain-HTTP forwarding with a policy 403 (got: $r)"
done
ok "all three proxies are CONNECT-only: plain HTTP forwarding is refused (403 method)"
# Positive control, also with SMOKE_EXTERNAL=0: the allow-listed provider host must NOT be a policy
# refusal - otherwise a deny-all proxy (a mistyped EGRESS_ALLOW) would pass every check above.
# 200 (tunnel opened) or 502/504 (allowed, but no network here) all mean the policy said yes.
for pair in "${PAIRS[@]}"; do
  read -r agent proxy host <<<"$pair"
  r="$(ask "$agent" "$proxy" "CONNECT $host:443")"
  [[ "$r" =~ ^(200|502|504)\  ]] || fail "$proxy does not allow its own provider $host (got: $r)"
done
ok "each proxy allows its own provider host (policy positive control)"
if [[ "$EXTERNAL" == 1 ]]; then
  # Real provider, real certificate, through the proxy's TLS gate: the right server name completes a
  # verified handshake; a swapped server name (a different site on a shared CDN) is cut by the proxy
  # before the provider sees it - and the proxy's own log says why.
  tls_via() { # tls_via <agent> <proxy> <connect host> <TLS server name> -> "tls-ok <version>" | "cut <why>" | "error <why>"
    exec_in "$1" python - "$2" "$3" "$4" <<'PY' | tr -d '\r'
import socket, ssl, sys
proxy, host, sni = sys.argv[1:4]
try:
    s = socket.create_connection((proxy, 3128), timeout=10)
    s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(1024)
        if not chunk:
            break
        head += chunk
    if head.split(b" ")[1:2] != [b"200"]:
        print("error connect", head[:40]); sys.exit()
    try:
        t = ssl.create_default_context().wrap_socket(s, server_hostname=sni)
        print("tls-ok", t.version())
    except (ssl.SSLEOFError, ConnectionResetError, ConnectionAbortedError) as e:
        print("cut", type(e).__name__)
except Exception as e:
    print("error", type(e).__name__, str(e)[:80])
PY
  }
  for pair in "${PAIRS[@]}"; do
    read -r agent proxy host <<<"$pair"
    r="$(tls_via "$agent" "$proxy" "$host" "$host")"
    [[ "$r" == "tls-ok TLSv1."* ]] || fail "$agent cannot complete a verified TLS handshake with $host through $proxy ($r)"
    r="$(tls_via "$agent" "$proxy" "$host" www.cloudflare.com)"
    [[ "$r" == cut* ]] || fail "$proxy let a TLS handshake for www.cloudflare.com through a CONNECT to $host ($r)"
    "${COMPOSE[@]}" logs --no-color "$proxy" 2>/dev/null | grep -q '"reason": "tls-sni-mismatch"' \
      || fail "$proxy did not log the cut SNI swap as tls-sni-mismatch"
  done
  ok "verified TLS to each provider works through its proxy; a swapped TLS server name is cut by every proxy (tls-sni-mismatch)"
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
# (2) no container with a route out (the three egress proxies, discovery, telegram, api) can
# dial the host: Tailscale IP, other host addresses, canaries, bridge gateway. This is the
# NETWORK boundary; the CONNECT checks above only test the proxy's hostname filter.
"$HERE/check-host-isolation.sh" "$@"
# (2b) DNS takes the guard-policed path and internal-only services resolve nothing outside
"$HERE/check-dns.sh" "$@"
# (3) no listening port other than the published loopback API on the host side
published="$("${COMPOSE[@]}" ps --format '{{.Publishers}}' | grep -v '^\[\]$' | grep -v '^$' || true)"
if grep -E '0\.0\.0\.0|::' <<<"$published" | grep -vq '^$'; then
  fail "a service is published on all interfaces: $published"
fi
ok "only loopback-published ports"

# 5. the worker survives and keeps serving -------------------------------------------------
sid2="$(api -X POST "$API/scan/2" | python3 -c 'import sys,json; print(json.load(sys.stdin)["session_id"])')"
[[ "$(decide "$sid2" accept)" == accepted ]] || fail "second accept"
[[ "$(wait_session "$sid2" completed failed blocked)" == completed ]] \
  || fail "second session did not complete"
ok "second approved session completed"
echo "SMOKE TEST PASSED"
