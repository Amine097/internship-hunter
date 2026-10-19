#!/usr/bin/env bash
# Host-isolation check for a RUNNING stack: can any container that has a route out reach the
# Docker HOST itself (its Tailscale IP, its other addresses, its bridge gateway)?
#
# Usage: deploy/check-host-isolation.sh [docker compose args, e.g. -p x]
#        deploy/check-host-isolation.sh --list-ips     (print the addresses that are protected)
#
# Why this exists: the egress proxies filter by HOSTNAME (an application-level control on the
# CONNECT handler). That says nothing about what a proxy PROCESS can do with the network it is
# attached to. On rootless Docker the route out ends in a user-space NAT (slirp4netns/pasta)
# that dials from the host's own network namespace, so ANY address the host owns is reachable
# from a container on a non-internal network unless something at the network layer says no
# (deploy/host-egress-guard.sh). This script tests the network layer directly, with raw TCP
# connections, from every container that has a route out: the three egress proxies and the
# trusted services on edge/egress (discovery, telegram, api).
#
# Environment:
#   SMOKE_HOST_ISOLATION=enforce (default) | report
#       enforce: any reachable protected destination, or any check that could not be performed,
#                fails (exit 1). report: print WARN lines and exit 0 (CI on rootful runners).
#   SMOKE_PROTECTED_IPS="100.107.22.84 ..."   extra host addresses to protect (space/comma list)
#   SMOKE_AUTODETECT_HOST_IPS=1 (default)     also protect every global address of this host
#                                             (tailscale ip -4, ip -4 addr), minus docker bridges
#   SMOKE_PROTECTED_PORTS="22 8000 2375 2376 5432"   ports probed on every protected address
#                                             and on each container's gateway
#   SMOKE_REQUIRE_TAILNET=0|1                 enforce mode fails unless a 100.64.0.0/10 address
#                                             is among the protected ones (default: 1 when
#                                             SMOKE_EXPECT_ROOTLESS=1, i.e. on the production host)
#
# Besides the real services on those ports, a CANARY listener is opened on every protected
# address (ephemeral port, this script's lifetime). A closed port proves nothing; a canary that
# the host itself can reach but a container cannot is a real "blocked".
set -Eeuo pipefail

MODE="${SMOKE_HOST_ISOLATION:-enforce}"
PORTS="${SMOKE_PROTECTED_PORTS:-22 8000 2375 2376 5432}"
AUTODETECT="${SMOKE_AUTODETECT_HOST_IPS:-1}"
REQUIRE_TAILNET="${SMOKE_REQUIRE_TAILNET:-${SMOKE_EXPECT_ROOTLESS:-0}}"
# services with a route out. proxies are untrusted-adjacent (they parse hostile requests);
# the others are first-party but share the same kind of route, so the same network rule must hold.
PROXIES=(egress-claude-1 egress-claude-2 egress-codex)
TRUSTED_OUT=(discovery telegram api)

ok() { echo "ok   $*"; }
warn() { echo "WARN $*" >&2; }
fail() { echo "FAIL $*" >&2; exit 1; }

[[ "$MODE" == enforce || "$MODE" == report ]] || fail "SMOKE_HOST_ISOLATION must be enforce or report"
for p in $PORTS; do [[ "$p" =~ ^[0-9]{1,5}$ ]] || fail "invalid port in SMOKE_PROTECTED_PORTS: '$p'"; done

is_ipv4() {
  local ip="$1" o
  [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -ra o <<<"$ip"
  for n in "${o[@]}"; do (( 10#$n <= 255 )) || return 1; done
}
is_cgnat() { # 100.64.0.0/10 (Tailscale)
  local a b; IFS=. read -r a b _ _ <<<"$1"
  (( 10#$a == 100 && 10#$b >= 64 && 10#$b <= 127 ))
}

detect_host_ips() {
  if command -v tailscale >/dev/null 2>&1; then tailscale ip -4 2>/dev/null || true; fi
  # rootless Docker keeps its bridges in a private namespace, so the host's own interfaces are
  # exactly what `ip` shows here; the filter only matters on a rootful daemon (CI runners).
  ip -4 -o addr show scope global 2>/dev/null \
    | awk '$2 !~ /^(lo|docker0|br-|hg-|veth|virbr|cni|flannel|cali)/ {split($4, a, "/"); print a[1]}' || true
}

collect_ips() {
  local extra="${SMOKE_PROTECTED_IPS:-}"
  { # shellcheck disable=SC2086  # word splitting of a space/comma separated list is the point
    printf '%s\n' ${extra//,/ }
    [[ "$AUTODETECT" == 1 ]] && detect_host_ips || true
  } | awk 'NF' | sort -u
}

mapfile -t IPS < <(collect_ips)
for ip in "${IPS[@]}"; do is_ipv4 "$ip" || fail "not an IPv4 address: '$ip' (SMOKE_PROTECTED_IPS / detected)"; done

if [[ "${1:-}" == "--list-ips" ]]; then
  printf '%s\n' "${IPS[@]}"
  exit 0
fi

COMPOSE=(docker compose "$@")
exec_in() { local svc="$1"; shift; "${COMPOSE[@]}" exec -T "$svc" "$@"; }

# ---- preconditions: a check that cannot see anything must not pass -------------------------
if [[ ${#IPS[@]} -eq 0 ]]; then
  [[ "$MODE" == report ]] || fail "no host address to protect: set SMOKE_PROTECTED_IPS" \
    "(e.g. the Tailscale IP) - refusing to certify host isolation without a target"
  warn "no host address found; only the gateway is probed (report mode)"
fi
if [[ "$REQUIRE_TAILNET" == 1 && "$MODE" == enforce ]]; then
  have=0; for ip in "${IPS[@]}"; do is_cgnat "$ip" && have=1; done
  [[ "$have" == 1 ]] || fail "no Tailscale (100.64.0.0/10) address among the protected ones:" \
    "set SMOKE_PROTECTED_IPS=<tailscale ip> (found: ${IPS[*]:-none})"
fi

# ---- canary listeners on the protected addresses (host side) -------------------------------
CANARY_FILE="$(mktemp)"; CANARY_PID=""
# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() { [[ -z "$CANARY_PID" ]] || kill "$CANARY_PID" 2>/dev/null || true; rm -f "$CANARY_FILE"; }
trap cleanup EXIT
CANARIES=()
if [[ ${#IPS[@]} -gt 0 ]]; then
  python3 - "$CANARY_FILE" "${IPS[@]}" <<'PY' &
import os, selectors, socket, sys
out, ips = sys.argv[1], sys.argv[2:]
socks, lines = [], []
for ip in ips:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((ip, 0)); s.listen(16); socks.append(s)
        lines.append(f"{ip}:{s.getsockname()[1]}")
    except OSError:
        lines.append(f"{ip}:UNBOUND")
with open(out + ".tmp", "w") as f:
    f.write("\n".join(lines) + "\n")
os.replace(out + ".tmp", out)
sel = selectors.DefaultSelector()
for s in socks:
    sel.register(s, selectors.EVENT_READ)
while True:
    for key, _ in sel.select():
        try:
            key.fileobj.accept()[0].close()
        except OSError:
            pass
PY
  CANARY_PID=$!
  for _ in $(seq 1 50); do [[ -s "$CANARY_FILE" ]] && break; sleep 0.1; done
  [[ -s "$CANARY_FILE" ]] || fail "canary listener did not start"
  mapfile -t CANARIES <"$CANARY_FILE"
fi
TARGETS=()
for c in "${CANARIES[@]}"; do
  if [[ "$c" == *:UNBOUND ]]; then
    # a configured address that this host does not own cannot be probed: not a pass
    [[ "$MODE" == report ]] || fail "cannot open a canary on ${c%:UNBOUND}: not an address of this host"
    warn "cannot open a canary on ${c%:UNBOUND} (report mode)"
    continue
  fi
  # control: the canary MUST be reachable from the host itself, or "blocked" means nothing
  timeout 3 bash -c ": </dev/tcp/${c%:*}/${c##*:}" 2>/dev/null \
    || fail "canary control failed: this host cannot connect to its own listener $c"
  TARGETS+=("$c")
done
for ip in "${IPS[@]}"; do for p in $PORTS; do TARGETS+=("$ip:$p"); done; done
TARGET_LIST="${TARGETS[*]:-}"

# ---- in-container probes (all targets in parallel; they print only facts) --------------------
# sh flavour: the alpine egress image (busybox nc). python flavour: the app images.
# shellcheck disable=SC2016  # the probes are sent verbatim to the container's shell
SH_PROBE='
ports="$1"; targets="$2"; n=0
probe() { n=$((n + 1)); ( nc -z -w 3 "${1%:*}" "${1##*:}" >/dev/null 2>&1 && echo "REACHABLE $1" ) & }
gw="$(ip route 2>/dev/null | awk "/^default/ {print \$3; exit}")"
if [ -n "$gw" ]; then echo "GATEWAY $gw"; for p in $ports; do probe "$gw:$p"; done; else echo "GATEWAY none"; fi
for t in $targets; do probe "$t"; done
wait
v6=no
[ -r /proc/net/ipv6_route ] && v6="$(awk "\$1==\"00000000000000000000000000000000\" && \$2==\"00\" && \$10!=\"lo\" {f=1} END {print f ? \"yes\" : \"no\"}" /proc/net/ipv6_route)"
echo "V6DEFAULT $v6"
echo "PROBED $n"
'
# shellcheck disable=SC2016
PY_PROBE='
import socket, struct, sys, threading
ports, targets = sys.argv[1].split(), sys.argv[2].split()
gw = None
for line in open("/proc/net/route").read().splitlines()[1:]:
    f = line.split()
    if f[1] == "00000000" and int(f[3], 16) & 2:
        gw = socket.inet_ntoa(struct.pack("<L", int(f[2], 16))); break
print("GATEWAY", gw or "none")
if gw:
    targets = [f"{gw}:{p}" for p in ports] + targets
hits = []
def probe(t):
    h, p = t.rsplit(":", 1)
    try:
        socket.create_connection((h, int(p)), timeout=3).close(); hits.append(t)
    except OSError:
        pass
ts = [threading.Thread(target=probe, args=(t,)) for t in targets]
for t in ts: t.start()
for t in ts: t.join()
for t in hits: print("REACHABLE", t)
v6 = "no"
try:
    for line in open("/proc/net/ipv6_route"):
        f = line.split()
        if f[0] == "0" * 32 and f[1] == "00" and f[9] != "lo":
            v6 = "yes"
except OSError:
    pass
print("V6DEFAULT", v6)
print("PROBED", len(targets))
'

BREACH=()
assess() { # assess <service> <output>
  local svc="$1" out="$2" line probed="" gw=""
  while IFS= read -r line; do
    case "$line" in
      "REACHABLE "*) BREACH+=("$svc reaches ${line#REACHABLE }") ;;
      "GATEWAY "*) gw="${line#GATEWAY }" ;;
      "V6DEFAULT yes") BREACH+=("$svc has an IPv6 default route (the guard rules are IPv4)") ;;
      "PROBED "*) probed="${line#PROBED }" ;;
    esac
  done <<<"$out"
  [[ "$probed" =~ ^[0-9]+$ ]] && (( probed >= ${#TARGETS[@]} )) \
    || BREACH+=("$svc: probe did not complete (${probed:-no result}); host isolation UNVERIFIED")
  [[ -n "$gw" && "$gw" != none ]] \
    || BREACH+=("$svc: no default gateway found; the gateway was NOT tested")
}

for svc in "${PROXIES[@]}"; do
  out="$(printf '%s\n' "$SH_PROBE" | exec_in "$svc" sh -s -- "$PORTS" "$TARGET_LIST" 2>&1 | tr -d '\r')" || true
  assess "$svc" "$out"
done
for svc in "${TRUSTED_OUT[@]}"; do
  out="$(printf '%s\n' "$PY_PROBE" | exec_in "$svc" python - "$PORTS" "$TARGET_LIST" 2>&1 | tr -d '\r')" || true
  assess "$svc" "$out"
done

if [[ ${#BREACH[@]} -eq 0 ]]; then
  ok "no container with a route out reaches the host: ${#TARGETS[@]} destination(s) per container" \
     "(${IPS[*]:-no host address}; ports: $PORTS; canaries: ${#CANARIES[@]}; gateway) from" \
     "${PROXIES[*]} ${TRUSTED_OUT[*]}"
  exit 0
fi
if [[ "$MODE" == enforce ]]; then
  printf 'FAIL host isolation (enforce):\n' >&2
  printf '       - %s\n' "${BREACH[@]}" >&2
  echo "       Containers on a non-internal network can dial this host. Apply the host guard" \
       "(docs/deployment.md, \"Host isolation\") and re-run." >&2
  exit 1
fi
warn "host isolation (report mode) - NOT acceptable in production:"
printf 'WARN   - %s\n' "${BREACH[@]}" >&2
exit 0
