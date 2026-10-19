#!/usr/bin/env bash
# Host-isolation check for a RUNNING stack: can any container that has a route out reach the
# Docker HOST itself (its Tailscale IP, its other addresses, rootful containers, the bridge
# gateway, the LAN gateway, metadata/Tailscale infrastructure addresses)?
#
# Usage: deploy/check-host-isolation.sh [docker compose args, e.g. -p x -f compose.yaml]
#        deploy/check-host-isolation.sh --list-ips     (print the addresses that are protected)
#
# Why this exists: the egress proxies filter by HOSTNAME (an application-level control on the
# CONNECT handler). That says nothing about what a proxy PROCESS can do with the network it is
# attached to. On rootless Docker the route out ends in a user-space NAT (slirp4netns/pasta)
# that dials from the host's own network namespace, so ANY address the host owns is reachable
# from a container on a non-internal network unless something at the network layer says no
# (deploy/host-egress-guard.sh). This script tests the network layer directly, with raw TCP
# connections, from every container that has a route out (computed from `compose config`).
#
# What counts as "isolated": the connection attempt to a protected destination ends in a
# timeout, "host/network unreachable" or a permission error - i.e. nothing ANSWERED. An open
# port is a breach, and so is ECONNREFUSED: a refusal is an answer from the protected side, it
# proves the packet got there. (That is why closed ports such as 2375 are meaningful targets.)
#
# Fail-closed protocol. Every probe prints one line per target and a set of CONTROLS; the
# check passes only if all of this holds for every container, otherwise it is "UNVERIFIED":
#   TOOL <nc|python>          the probe tool exists and ran
#   CONTROL open ok          the tool connected to a listener inside that very container
#   CONTROL refused ok        the tool recognised a refusal on a closed local port (so a
#                             "refused" result on a protected target is not misread as blocked)
#   GATEWAY <ip>              the container's default gateway was found (and is probed)
#   RESULT <ip:port> <OPEN|REFUSED|BLOCKED|ERROR>   exactly once for every expected target
#   V6DEFAULT no, DONE <n>    no IPv6 route out; n equals the number of RESULT lines
# A missing nc/python, a failed `docker exec`, an unknown output line, a missing or duplicated
# RESULT, ERROR (unclassifiable) all fail. A canary listener on every protected address is a
# reachable positive control that does not depend on any real service listening.
#
#   deploy/check-host-isolation.sh --verify-targets   (host side only, no docker: are the configured
#        EGRESS_FORBIDDEN_TARGETS / SMOKE_ROOTFUL_TARGETS real? used by remote-deploy.sh)
#
# Environment:
#   SMOKE_HOST_ISOLATION=enforce (default) | report
#       enforce: any reachability breach, and any defect, fails (exit 1).
#       report:  ONLY actual network reachability violations (a container connected to / was
#                refused by a protected destination, or has an IPv6 route out) become WARN lines
#                with exit 0 (CI on rootful runners). A DEFECT is fatal in BOTH modes: a broken
#                positive control, UNVERIFIED, a tool error, missing/malformed/duplicate probe
#                output, a failed `docker exec`, incomplete service coverage, a canary that could
#                not be created. A check that cannot see must never look like a pass.
#   SMOKE_PROTECTED_IPS="100.107.22.84 ..."   extra host addresses to protect (space/comma list)
#   SMOKE_AUTODETECT_HOST_IPS=1 (default)     also protect every global address of this host on
#                                             EVERY interface (rootful docker0/br-* gateways
#                                             included), `tailscale ip -4`, and its default gateway
#   SMOKE_PROTECTED_PORTS="22 8000 2375 2376 5432"   probed on every protected address and on
#                                             each container's own gateway
#   SMOKE_ROOTFUL_TARGETS="172.17.0.2:8080,..."      explicit IP:port of rootful containers (or any
#                                             other service) that must be unreachable. Only what you
#                                             list is probed - nothing is scanned. Prefer a CLOSED
#                                             port on a rootful container's IP: no media application
#                                             receives a request, and a refusal still proves reach.
#   SMOKE_REQUIRE_ROOTFUL_TARGET=0|1          enforce mode fails unless at least one is given
#                                             (default: 1 when SMOKE_EXPECT_ROOTLESS=1)
#   SMOKE_REQUIRE_TAILNET=0|1                 enforce mode fails unless a 100.64.0.0/10 address
#                                             is among the protected ones (default: 1 when
#                                             SMOKE_EXPECT_ROOTLESS=1, i.e. on the production host)
# Also probed, as single well-known addresses (never ranges): the cloud metadata endpoint
# 169.254.169.254:80, Tailscale's MagicDNS 100.100.100.100:53/80 when a tailnet address exists,
# and the host's own default gateway on 22/80/443.
set -Eeuo pipefail

MODE="${SMOKE_HOST_ISOLATION:-enforce}"
PORTS="${SMOKE_PROTECTED_PORTS:-22 8000 2375 2376 5432}"
AUTODETECT="${SMOKE_AUTODETECT_HOST_IPS:-1}"
REQUIRE_TAILNET="${SMOKE_REQUIRE_TAILNET:-${SMOKE_EXPECT_ROOTLESS:-0}}"
REQUIRE_ROOTFUL="${SMOKE_REQUIRE_ROOTFUL_TARGET:-${SMOKE_EXPECT_ROOTLESS:-0}}"
# Services the stack is known to expose to a route out: if one of them disappears from the
# computed set, the topology changed and this check must be looked at, not silently shrink.
REQUIRED_OUT=(egress-claude-1 egress-claude-2 egress-codex discovery telegram api)

ok() { echo "ok   $*"; }
warn() { echo "WARN $*" >&2; }
fail() { echo "FAIL $*" >&2; exit 1; }

[[ "$MODE" == enforce || "$MODE" == report ]] || fail "SMOKE_HOST_ISOLATION must be enforce or report"
for p in $PORTS; do [[ "$p" =~ ^[0-9]{1,5}$ ]] || fail "invalid port in SMOKE_PROTECTED_PORTS: '$p'"; done

is_ipv4() {
  local ip="$1" o n
  [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -ra o <<<"$ip"
  for n in "${o[@]}"; do (( 10#$n <= 255 )) || return 1; done
}
is_target() { [[ "$1" =~ ^[0-9.]+:[0-9]{1,5}$ ]] && is_ipv4 "${1%:*}"; }
is_cgnat() { # 100.64.0.0/10 (Tailscale)
  local a b; IFS=. read -r a b _ _ <<<"$1"
  (( 10#$a == 100 && 10#$b >= 64 && 10#$b <= 127 ))
}

host_gateways() { ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "via") print $(i + 1)}' || true; }
detect_host_ips() {
  if command -v tailscale >/dev/null 2>&1; then tailscale ip -4 2>/dev/null || true; fi
  # Every global address on every interface except loopback. On a rootless host the rootful
  # Docker bridges (docker0, br-*) are the host's own addresses, and rootful containers'
  # published ports listen there: they are exactly what must stay unreachable.
  ip -4 -o addr show scope global 2>/dev/null | awk '$2 != "lo" {split($4, a, "/"); print a[1]}' || true
  host_gateways
}

collect_ips() {
  local extra="${SMOKE_PROTECTED_IPS:-}"
  { # shellcheck disable=SC2086  # word splitting of a space/comma separated list is the point
    printf '%s\n' ${extra//,/ }
    if [[ "$AUTODETECT" == 1 ]]; then detect_host_ips; fi
  } | awk 'NF' | sort -u
}

# Host-side liveness of a configured target: from THIS network namespace a safe TCP connect (no
# payload) must either connect or be REFUSED. A silent timeout / unreachable means the address is
# a typo, gone (container IP drift, interface change) or filtered - the protection it is meant to
# test would then silently test nothing.
host_connect() { # host_connect ip port -> OPEN | REFUSED | OTHER:<why>
  python3 - "$1" "$2" <<'PY'
import errno, socket, sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3).close()
    print("OPEN")
except (ConnectionRefusedError, ConnectionResetError):
    print("REFUSED")
except TimeoutError:
    print("OTHER:timed out")
except OSError as e:
    print(f"OTHER:{errno.errorcode.get(e.errno, e.errno)}")
PY
}
host_owns() { ip -4 -o addr show 2>/dev/null | awk '{split($4, a, "/"); print a[1]}' | grep -qx -- "$1"; }

verify_targets() {
  local t kind res bad=0 nfor=0 nroot=0 list
  for kind in forbidden rootful; do
    if [[ "$kind" == forbidden ]]; then list="${EGRESS_FORBIDDEN_TARGETS:-}"; else list="${SMOKE_ROOTFUL_TARGETS:-}"; fi
    for t in $(tr ',' ' ' <<<"$list"); do
      is_target "$t" || { echo "FAIL $kind target '$t' is not a literal ip:port" >&2; bad=1; continue; }
      if [[ "$kind" == forbidden ]]; then
        nfor=$((nfor + 1))
        host_owns "${t%:*}" \
          || { echo "FAIL forbidden target $t: ${t%:*} is not an address of this host (typo, or the address is gone)" >&2; bad=1; continue; }
      else
        nroot=$((nroot + 1))
      fi
      res="$(host_connect "${t%:*}" "${t##*:}")"
      case "$res" in
        OPEN|REFUSED) ok "$kind target $t is live from the host ($res)" ;;
        *) echo "FAIL $kind target $t is not live from the host (${res#OTHER:}): a typo, a dropped packet," \
                "or a container/interface that moved. Fix the configuration; protection against a" \
                "non-existent target is no protection." >&2; bad=1 ;;
      esac
    done
  done
  [[ "$nfor" -gt 0 ]] || { echo "FAIL EGRESS_FORBIDDEN_TARGETS is empty" >&2; bad=1; }
  if [[ "$nroot" -eq 0 && "$REQUIRE_ROOTFUL" == 1 ]]; then
    echo "FAIL no rootful container target configured: list at least one ip:port in" \
         "host-isolation.conf (ROOTFUL_TARGETS=), preferably a closed port on a rootful container's IP" >&2
    bad=1
  fi
  return "$bad"
}
if [[ "${1:-}" == "--verify-targets" ]]; then verify_targets; exit $?; fi

mapfile -t IPS < <(collect_ips)
for ip in "${IPS[@]}"; do is_ipv4 "$ip" || fail "not an IPv4 address: '$ip' (SMOKE_PROTECTED_IPS / detected)"; done

if [[ "${1:-}" == "--list-ips" ]]; then
  printf '%s\n' "${IPS[@]}"
  exit 0
fi

COMPOSE=(docker compose "$@")
exec_in() { local svc="$1"; shift; "${COMPOSE[@]}" exec -T "$svc" "$@"; }

# ---- preconditions: a check that cannot see anything must not pass -------------------------
if [[ ${#IPS[@]} -eq 0 ]]; then      # incomplete coverage is a defect, in report mode too
  fail "no host address to protect: set SMOKE_PROTECTED_IPS" \
    "(e.g. the Tailscale IP) - refusing to certify host isolation without a target"
fi
have_tailnet=0; for ip in "${IPS[@]}"; do is_cgnat "$ip" && have_tailnet=1; done
if [[ "$REQUIRE_TAILNET" == 1 && "$MODE" == enforce && "$have_tailnet" != 1 ]]; then
  fail "no Tailscale (100.64.0.0/10) address among the protected ones:" \
       "set SMOKE_PROTECTED_IPS=<tailscale ip> (found: ${IPS[*]:-none})"
fi
ROOTFUL=()
for t in $(tr ',' ' ' <<<"${SMOKE_ROOTFUL_TARGETS:-}"); do
  is_target "$t" || fail "invalid SMOKE_ROOTFUL_TARGETS entry (want ip:port): '$t'"
  ROOTFUL+=("$t")
done
if [[ "$REQUIRE_ROOTFUL" == 1 && "$MODE" == enforce && ${#ROOTFUL[@]} -eq 0 ]]; then
  fail "no rootful container target configured (SMOKE_ROOTFUL_TARGETS / host-isolation.conf):" \
       "the operator must name at least one ip:port of an existing rootful container"
fi

# ---- which services have a route out? (computed, never a hard-coded shortlist) ---------------
OUT_SERVICES=()
if ! mapfile -t OUT_SERVICES < <("${COMPOSE[@]}" config --format json 2>/dev/null | python3 -c '
import json, sys
cfg = json.load(sys.stdin)
nets = cfg.get("networks") or {}
for n, net in sorted(nets.items()):
    if (net or {}).get("enable_ipv6") and not (net or {}).get("internal", False):
        print("!IPV6 " + n)
for name, svc in sorted((cfg.get("services") or {}).items()):
    attached = list((svc.get("networks") or {"default": None}).keys())
    if any(not (nets.get(n) or {}).get("internal", False) for n in attached):
        print(name)
'); then OUT_SERVICES=(); fi
V6NETS="$(printf '%s\n' ${OUT_SERVICES[@]+"${OUT_SERVICES[@]}"} | sed -n 's/^!IPV6 //p' | tr '\n' ' ')"
if [[ -n "$V6NETS" ]]; then
  fail "IPv6 is enabled on outbound network(s) $V6NETS: the guard's IPv4 allow path was not" \
       "validated for IPv6; refusing to validate (docs/deployment.md, IPv6)"
fi
mapfile -t OUT_SERVICES < <(printf '%s\n' "${OUT_SERVICES[@]}" | awk 'NF && !/^!IPV6 /')
if [[ ${#OUT_SERVICES[@]} -eq 0 ]]; then
  fail "cannot determine which services have a route out (docker compose config failed)"
fi
for need in "${REQUIRED_OUT[@]}"; do
  printf '%s\n' "${OUT_SERVICES[@]}" | grep -qx -- "$need" \
    || fail "service '$need' is expected to have a route out but compose says otherwise:" \
            "the topology changed; review this check before trusting it (found: ${OUT_SERVICES[*]})"
done

# ---- canary listeners on the protected addresses (host side) -------------------------------
CANARY_FILE="$(mktemp)"; CANARY_PID=""
# shellcheck disable=SC2317,SC2329  # invoked by the EXIT trap
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
    # a configured address that this host does not own cannot be probed: a defect in every mode
    fail "cannot open a canary on ${c%:UNBOUND}: not an address of this host"
  fi
  # control: the canary MUST be reachable from the host itself, or "blocked" means nothing
  timeout 3 bash -c ": </dev/tcp/${c%:*}/${c##*:}" 2>/dev/null \
    || fail "canary control failed: this host cannot connect to its own listener $c"
  TARGETS+=("$c")
done
for ip in "${IPS[@]}"; do for p in $PORTS; do TARGETS+=("$ip:$p"); done; done
TARGETS+=("${ROOTFUL[@]}" 169.254.169.254:80)
[[ "$have_tailnet" == 1 ]] && TARGETS+=(100.100.100.100:53 100.100.100.100:80)
while read -r gw; do
  [[ -z "$gw" ]] || for p in 22 80 443; do TARGETS+=("$gw:$p"); done
done < <(host_gateways)
mapfile -t TARGETS < <(printf '%s\n' "${TARGETS[@]}" | awk 'NF' | sort -u)
TARGET_LIST="${TARGETS[*]:-}"

# ---- in-container probes (all targets in parallel; they print only facts) --------------------
# sh flavour: the alpine egress image (busybox `nc -vv -z`: its failure texts distinguish
# "Connection refused" / "Host is unreachable" / "Network unreachable" / "Operation timed out",
# observed with Alpine 3.20's busybox 1.36.1). python flavour: everything else.
# shellcheck disable=SC2016  # the probes are sent verbatim to the container's shell
SH_PROBE='
ports="$1"; targets="$2"; ctl="$3"
command -v nc >/dev/null 2>&1 || { echo "TOOLMISSING nc"; exit 0; }
echo "TOOL nc"
classify() {
  out="$(nc -vv -z -w 3 "$1" "$2" 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ]; then echo OPEN; return; fi
  case "$out" in
    *[Rr]efused*) echo REFUSED ;;
    *"timed out"*|*[Uu]nreachable*|*prohibited*|*"Permission denied"*|*"not permitted"*) echo BLOCKED ;;
    *) echo ERROR ;;
  esac
}
[ "$(classify 127.0.0.1 "$ctl")" = OPEN ] && echo "CONTROL open ok" || echo "CONTROL open FAIL"
[ "$(classify 127.0.0.1 1)" = REFUSED ] && echo "CONTROL refused ok" || echo "CONTROL refused FAIL"
gw="$(ip route 2>/dev/null | awk "/^default/ {print \$3; exit}")"
all="$targets"
if [ -n "$gw" ]; then echo "GATEWAY $gw"; for p in $ports; do all="$all $gw:$p"; done; else echo "GATEWAY none"; fi
d="$(mktemp -d)" || { echo "TOOLMISSING mktemp"; exit 0; }
n=0
for t in $(printf "%s\n" $all | sort -u); do
  n=$((n + 1))
  ( echo "RESULT $t $(classify "${t%:*}" "${t##*:}")" > "$d/$n" ) &
done
wait
cat "$d"/*
rm -rf "$d"
v6=no
[ -r /proc/net/ipv6_route ] && v6="$(awk "\$1==\"00000000000000000000000000000000\" && \$2==\"00\" && \$10!=\"lo\" {f=1} END {print f ? \"yes\" : \"no\"}" /proc/net/ipv6_route)"
echo "V6DEFAULT $v6"
echo "DONE $n"
'
# shellcheck disable=SC2016
PY_PROBE='
import errno, socket, struct, sys, threading
ports, targets = sys.argv[1].split(), sys.argv[2].split()
print("TOOL python")
BLOCKED = {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EPERM, errno.EACCES, errno.ETIMEDOUT,
           errno.ENETDOWN}
def classify(h, p):
    try:
        socket.create_connection((h, int(p)), timeout=3).close()
        return "OPEN"
    except (ConnectionRefusedError, ConnectionResetError):
        return "REFUSED"
    except TimeoutError:
        return "BLOCKED"
    except OSError as e:
        return "BLOCKED" if e.errno in BLOCKED else "ERROR"
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(4)
port = srv.getsockname()[1]
print("CONTROL open", "ok" if classify("127.0.0.1", port) == "OPEN" else "FAIL")
srv.close()
print("CONTROL refused", "ok" if classify("127.0.0.1", port) == "REFUSED" else "FAIL")
gw = None
for line in open("/proc/net/route").read().splitlines()[1:]:
    f = line.split()
    if f[1] == "00000000" and int(f[3], 16) & 2:
        gw = socket.inet_ntoa(struct.pack("<L", int(f[2], 16))); break
print("GATEWAY", gw or "none")
all_t = set(targets) | ({f"{gw}:{p}" for p in ports} if gw else set())
res = {}
def probe(t):
    res[t] = classify(*t.rsplit(":", 1))
ts = [threading.Thread(target=probe, args=(t,)) for t in sorted(all_t)]
for t in ts: t.start()
for t in ts: t.join()
for t in sorted(res): print("RESULT", t, res[t])
v6 = "no"
try:
    for line in open("/proc/net/ipv6_route"):
        f = line.split()
        if f[0] == "0" * 32 and f[1] == "00" and f[9] != "lo":
            v6 = "yes"
except OSError:
    pass
print("V6DEFAULT", v6)
print("DONE", len(res))
'

# The assessor turns a probe's stdout into breach lines (none = the container is isolated).
# It is deliberately strict: anything it does not recognise is a failure, not noise.
ASSESS='
import re, sys
svc, expected = sys.argv[1], set(sys.argv[2].split())
out, tool, controls, gw, v6, done, results = [], None, {}, None, None, None, {}
def reach(m): out.append("REACH " + m)
def defect(m): out.append("DEFECT " + m)
for ln in sys.stdin.read().splitlines():
    if not ln.strip(): continue
    m = re.fullmatch(r"TOOL (nc|python)", ln)
    if m: tool = m.group(1); continue
    m = re.fullmatch(r"TOOLMISSING (\S+)", ln)
    if m: defect(f"{svc}: probe tool {m.group(1)} is missing in the container; host isolation UNVERIFIED"); continue
    m = re.fullmatch(r"CONTROL (open|refused) (ok|FAIL)", ln)
    if m: controls[m.group(1)] = m.group(2); continue
    m = re.fullmatch(r"GATEWAY (\d+\.\d+\.\d+\.\d+|none)", ln)
    if m: gw = m.group(1); continue
    m = re.fullmatch(r"RESULT (\d+\.\d+\.\d+\.\d+:\d+) (OPEN|REFUSED|BLOCKED|ERROR)", ln)
    if m:
        if m.group(1) in results: defect(f"{svc}: duplicate result for {m.group(1)}")
        results[m.group(1)] = m.group(2); continue
    m = re.fullmatch(r"V6DEFAULT (yes|no)", ln)
    if m: v6 = m.group(1); continue
    m = re.fullmatch(r"DONE (\d+)", ln)
    if m: done = int(m.group(1)); continue
    defect(f"{svc}: malformed probe output {ln[:80]!r}; host isolation UNVERIFIED")
if tool is None:
    if not out: defect(f"{svc}: probe did not run (no output); host isolation UNVERIFIED")
else:
    for c, why in (("open", "cannot connect to a listener inside the container"),
                   ("refused", "cannot recognise a connection refusal")):
        if controls.get(c) != "ok":
            defect(f"{svc}: positive control failed - the probe tool {why}; host isolation UNVERIFIED")
    if gw in (None, "none"):
        defect(f"{svc}: no default gateway found; the gateway was NOT tested")
    if v6 is None: defect(f"{svc}: no IPv6 verdict")
    elif v6 == "yes": reach(f"{svc} has an IPv6 default route (the guard rules are IPv4-allow + IPv6-reject; not validated here)")
    missing = sorted(t for t in expected if t not in results)
    if missing: defect(f"{svc}: probe skipped {len(missing)} target(s), e.g. {missing[0]}; host isolation UNVERIFIED")
    if done != len(results): defect(f"{svc}: probe reported DONE {done} but printed {len(results)} results")
    for t, r in sorted(results.items()):
        if r == "OPEN": reach(f"{svc} reaches {t} (connection OPEN)")
        elif r == "REFUSED": reach(f"{svc} reaches {t} (connection REFUSED: the packet arrived and was answered)")
        elif r == "ERROR": defect(f"{svc}: unclassifiable result for {t}; host isolation UNVERIFIED")
for o in out: print(o)
'

REACHED=(); DEFECTS=()
probe_service() { # probe_service <service>
  local svc="$1" out err expected="$TARGET_LIST" gw p line
  err="$(mktemp)"
  if [[ "$svc" == egress-* ]]; then
    # tinyproxy (3128) is the in-container listener for the "open" control
    out="$(printf '%s\n' "$SH_PROBE" | exec_in "$svc" sh -s -- "$PORTS" "$TARGET_LIST" 3128 2>"$err" | tr -d '\r')" || true
  else
    out="$(printf '%s\n' "$PY_PROBE" | exec_in "$svc" python - "$PORTS" "$TARGET_LIST" 2>"$err" | tr -d '\r')" || true
  fi
  # the container's own gateway is only known inside it: expect its ports as well
  gw="$(sed -n 's/^GATEWAY \([0-9.]*\)$/\1/p' <<<"$out" | head -1)"
  if [[ -n "$gw" ]]; then for p in $PORTS; do expected="$expected $gw:$p"; done; fi
  while IFS= read -r line; do
    case "$line" in
      "REACH "*) REACHED+=("${line#REACH }") ;;
      "DEFECT "*) DEFECTS+=("${line#DEFECT }") ;;
      '') ;;
      *) DEFECTS+=("$svc: assessor produced an unexpected line: ${line:0:80}") ;;
    esac
  done < <(printf '%s\n' "$out" | python3 -c "$ASSESS" "$svc" "$expected" 2>&1 || echo "DEFECT $svc: the assessor itself failed")
  if [[ -z "$out" ]]; then
    DEFECTS+=("$svc: docker exec produced no output ($(head -c 160 "$err" | tr '\n' ' ')); host isolation UNVERIFIED")
  fi
  rm -f "$err"
}
for svc in "${OUT_SERVICES[@]}"; do probe_service "$svc"; done

# DEFECTS are fatal in every mode; only REACHED may be softened by report mode.
if [[ ${#DEFECTS[@]} -gt 0 ]]; then
  printf 'FAIL host isolation could not be verified (%s mode) - defects are fatal in every mode:\n' "$MODE" >&2
  printf '       - %s\n' "${DEFECTS[@]}" >&2
  [[ ${#REACHED[@]} -eq 0 ]] || { printf '       reachability violations seen as well:\n' >&2; printf '       - %s\n' "${REACHED[@]}" >&2; }
  exit 1
fi
ok "probe controls verified in ${#OUT_SERVICES[@]} service(s): ${OUT_SERVICES[*]} (probe tools exercised, results complete)"
if [[ ${#REACHED[@]} -eq 0 ]]; then
  ok "no container with a route out reaches the host: ${#TARGETS[@]} destination(s) + gateway per container" \
     "(${IPS[*]:-no host address}; ports: $PORTS; canaries: ${#CANARIES[@]}; rootful targets: ${#ROOTFUL[@]})"
  exit 0
fi
if [[ "$MODE" == enforce ]]; then
  printf 'FAIL host isolation (enforce):\n' >&2
  printf '       - %s\n' "${REACHED[@]}" >&2
  echo "       Containers on a non-internal network can dial this host. Apply the host guard" \
       "(docs/deployment.md, \"Host isolation\") and re-run." >&2
  exit 1
fi
warn "host isolation (report mode) - reachability violations, NOT acceptable in production:"
printf 'WARN   - %s\n' "${REACHED[@]}" >&2
exit 0
