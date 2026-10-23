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
# Every probe result is CLASSIFIED, and only a result that proves the packet did not get through
# counts as isolation: `unreachable` (EHOSTUNREACH/ENETUNREACH/EACCES/EPERM) or `timeout`. A refusal
# (ECONNREFUSED/reset) is an ANSWER from the target: the path exists. A name that does not resolve
# proves nothing about the network, so every target is an IP ADDRESS read from Docker itself. Each
# probe run carries positive controls: the tool must see an open and a refused local port in that
# very container, and every address on a network the agent DOES share must be reached.
probe() { # probe <service> <ip:port>... -> CONTROL lines + "RESULT <ip:port> <open|refused|unreachable|timeout|error>"
  exec_in "$1" python - "${@:2}" <<'PY' | tr -d '\r'
import errno, socket, sys, threading
BLOCKED = {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EACCES, errno.EPERM}
def classify(host, port):
    try:
        socket.create_connection((host, int(port)), timeout=4).close()
        return "open"
    except (ConnectionRefusedError, ConnectionResetError):
        return "refused"
    except TimeoutError:
        return "timeout"
    except socket.gaierror:
        return "error"              # targets are IP literals: any name lookup is a probe defect
    except OSError as e:
        return "unreachable" if e.errno in BLOCKED else "error"
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); port = srv.getsockname()[1]
print("CONTROL open", classify("127.0.0.1", port))
srv.close()
print("CONTROL refused", classify("127.0.0.1", port))
res = {}
def run(t):
    host, _, p = t.rpartition(":")
    res[t] = classify(host, p)
threads = [threading.Thread(target=run, args=(t,)) for t in sys.argv[1:]]
for t in threads: t.start()
for t in threads: t.join()
for t in sys.argv[1:]:
    print("RESULT", t, res[t])
PY
}
result_of() { awk -v t="$2" '$1 == "RESULT" && $2 == t {print $3}' <<<"$1"; }
cid() { "${COMPOSE[@]}" ps -q "$1"; }
net_ips() { # net_ips <service> -> "<network> <ip>" per attached network
  docker inspect -f '{{range $n, $c := .NetworkSettings.Networks}}{{$n}} {{$c.IPAddress}}{{"\n"}}{{end}}' "$(cid "$1")"
}
probe_port() { case "$1" in postgres) echo 5432 ;; api) echo 8000 ;; agent-*) echo 8100 ;; egress-*) echo 3128 ;; *) echo 9 ;; esac; }
mapfile -t RUNNING_SVCS < <("${COMPOSE[@]}" ps --services --status running)
host_leaks=()
for agent in agent-claude-1 agent-claude-2 agent-codex; do
  mine=" $(net_ips "$agent" | awk '{print $1}' | tr '\n' ' ') "
  shared=(); separate=()
  for svc in "${RUNNING_SVCS[@]}"; do
    [[ "$svc" == "$agent" ]] && continue
    port="$(probe_port "$svc")"
    while read -r net ip; do
      [[ -n "$ip" ]] || continue
      if [[ "$mine" == *" $net "* ]]; then shared+=("$ip:$port"); else separate+=("$ip:$port"); fi
    done < <(net_ips "$svc")
  done
  internet=(1.1.1.1:443 8.8.8.8:53 169.254.169.254:80)
  hostt=(); for ip in "${PROTECTED_IPS[@]}"; do hostt+=("$ip:22" "$ip:8000"); done
  [[ ${#shared[@]} -ge 2 && ${#separate[@]} -ge 5 ]] \
    || fail "$agent: the topology the isolation probe expects is missing (shared=${shared[*]} separate=${separate[*]})"
  out="$(probe "$agent" "${shared[@]}" "${separate[@]}" "${internet[@]}" "${hostt[@]}")"
  [[ "$(awk '$1 == "CONTROL" && $2 == "open" {print $3}' <<<"$out")" == open \
     && "$(awk '$1 == "CONTROL" && $2 == "refused" {print $3}' <<<"$out")" == refused ]] \
    || fail "$agent: the probe's own controls failed - isolation UNVERIFIED ($out)"
  for t in "${shared[@]}"; do      # positive control: a path that must exist is seen as one
    r="$(result_of "$out" "$t")"
    [[ "$r" == open || "$r" == refused ]] || fail "$agent cannot reach $t on a network it shares ($r): the probe cannot see a path, isolation UNVERIFIED"
  done
  for t in "${separate[@]}" "${internet[@]}"; do
    r="$(result_of "$out" "$t")"
    [[ "$r" == unreachable || "$r" == timeout ]] || fail "$agent reaches $t ($r: a refusal is an answer, not isolation)"
  done
  for t in "${hostt[@]}"; do
    r="$(result_of "$out" "$t")"
    case "$r" in
      unreachable|timeout) ;;
      open|refused) host_leaks+=("$agent->$t") ;;
      *) fail "$agent: unclassifiable result for host address $t ($r) - isolation UNVERIFIED" ;;
    esac
  done
  own="$(net_ips "egress-${agent#agent-}" | awk -v m="$mine" 'index(m, " " $1 " ") {print $2; exit}')"
  [[ -n "$own" && "$(result_of "$out" "$own:3128")" == open ]] || fail "$agent cannot reach its own proxy by address"
done
# The host's own addresses follow SMOKE_HOST_ISOLATION like deploy/check-host-isolation.sh: on a
# rootful CI runner an internal network's gateway IS an address of the host (sshd listens on
# 0.0.0.0), so there it is reported; on the production host it must be unreachable (enforce).
if [[ ${#host_leaks[@]} -gt 0 ]]; then
  case "${SMOKE_HOST_ISOLATION:-enforce}" in
    report) echo "WARN agents reach host address(es) ${host_leaks[*]} (report mode: a rootful" \
                 "daemon exposes the bridge gateway; NOT acceptable in production)" >&2 ;;
    *) fail "agents reach host address(es): ${host_leaks[*]}" ;;
  esac
fi
ok "all three agents: every address on another network, the Internet$([[ ${#host_leaks[@]} -eq 0 ]] && echo ' and the host') unreachable (classified, by IP); every address on a shared network reached; probe controls verified"
ok "each agent reaches its own egress proxy by address"

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
  # The swapped name is unique to this run and the log is read only from this run's start, so the
  # evidence is THIS cut: an older line, or a cut for another reason, cannot satisfy the check.
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for pair in "${PAIRS[@]}"; do
    read -r agent proxy host <<<"$pair"
    r="$(tls_via "$agent" "$proxy" "$host" "$host")"
    [[ "$r" == "tls-ok TLSv1."* ]] || fail "$agent cannot complete a verified TLS handshake with $host through $proxy ($r)"
    swap="smoke-$(date +%s)-$RANDOM-$proxy.example.com"
    r="$(tls_via "$agent" "$proxy" "$host" "$swap")"
    [[ "$r" == cut* ]] || fail "$proxy let a TLS handshake for $swap through a CONNECT to $host ($r)"
    "${COMPOSE[@]}" logs --no-color --since "$since" "$proxy" 2>/dev/null \
      | grep -F "$swap" | grep -qF '"reason": "tls-sni-mismatch"' \
      || fail "$proxy did not log THIS run's cut SNI swap ($swap) as tls-sni-mismatch"
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
