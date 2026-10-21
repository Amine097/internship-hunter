#!/usr/bin/env bash
# DNS check for a RUNNING stack: does every container resolve exactly what it should, through
# the path the host guard polices, and nothing else?
#
# Usage: deploy/check-dns.sh [docker compose args, e.g. -p x -f compose.yaml]
#
# Why this exists (docs/deployment.md, "DNS"). On Docker's user-defined networks a container's
# resolver is Docker's embedded one (127.0.0.11). Where it forwards a name it cannot answer
# decides everything:
#   * servers taken from the daemon's own /etc/resolv.conf are queried by dockerd itself, from
#     ITS network namespace, annotated `ExtServers: [host(192.168.1.1)]` in the container's
#     resolv.conf. Those packets never cross the guard's FORWARD rules: the LAN resolver is
#     reachable and nothing says otherwise;
#   * servers set with `dns:` (compose / `--dns` / daemon.json) are queried from inside the
#     container, cross the daemon namespace's firewall, and the guard lets exactly the resolver
#     it was told about through (`DNS=` in host-egress-guard.conf).
#   * a container attached ONLY to `internal` networks gets no external forwarding at all.
# So: services with a route out must carry the explicit resolver (and Docker must have honoured
# it), services without one must not resolve anything outside the project, and service names
# resolve only between services that share a network.
#
# Checks, per service (the topology is computed from `compose config`, never hard-coded):
#   config   OUT services (any non-internal network) have `dns` == HUNTER_DNS; IN services have none
#   runtime  OUT: resolv.conf says `ExtServers: [<HUNTER_DNS>]`, never `host(...)`
#   control  every service resolves ITS OWN service name (the embedded resolver works)
#   names    a service name resolves iff the two services share a network (both directions)
#   OUT      resolves the public probe name (SMOKE_DNS_NAME)           [broken DNS]
#            cannot get an answer from the host's default gateway(s) on port 53   [guard hole]
#   IN       must NOT resolve the public probe name                    [DNS leak]
#            must get no answer from HUNTER_DNS or from 1.1.1.1 directly           [DNS leak]
#
# Fail-closed: a missing resolver tool, a failed `docker exec`, malformed/missing probe output or
# a failed own-name control are DEFECTS (fatal in every mode); so are isolation breaches (IN
# service resolving outside, a wrong ExtServers, a name resolving across networks). Only
# "OUT cannot resolve / can query the gateway" is softened by SMOKE_HOST_ISOLATION=report (CI on
# a rootful runner, where there is no guard and the network is whatever the runner offers).
#
# Environment:
#   SMOKE_HOST_ISOLATION=enforce (default) | report     as in check-host-isolation.sh
#   SMOKE_DNS_EXPECT=10.0.2.3[,ip]   the resolver(s) the services with a route out must use. The deploy
#                               gate passes DNS= from host-egress-guard.conf (what the guard allows);
#                               otherwise HUNTER_DNS, then 10.0.2.3 (compose.yaml's default)
#   SMOKE_DNS_NAME=example.com  public name for the positive/negative controls
set -Eeuo pipefail

MODE="${SMOKE_HOST_ISOLATION:-enforce}"
EXPECT_DNS="${SMOKE_DNS_EXPECT:-${HUNTER_DNS:-10.0.2.3}}"
EXT_NAME="${SMOKE_DNS_NAME:-example.com}"
PUBLIC_RESOLVER=1.1.1.1
REQUIRED_OUT=(egress-claude-1 egress-claude-2 egress-codex discovery telegram api)
REQUIRED_IN=(agent-claude-1 agent-claude-2 agent-codex postgres)

ok() { echo "ok   $*"; }
warn() { echo "WARN $*" >&2; }
fail() { echo "FAIL $*" >&2; exit 1; }

[[ "$MODE" == enforce || "$MODE" == report ]] || fail "SMOKE_HOST_ISOLATION must be enforce or report"
[[ "$EXT_NAME" =~ ^[A-Za-z0-9.-]+$ ]] || fail "invalid SMOKE_DNS_NAME: '$EXT_NAME'"
for d in ${EXPECT_DNS//,/ }; do
  [[ "$d" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail "invalid resolver in SMOKE_DNS_EXPECT / HUNTER_DNS: '$d' (IPv4 addresses only)"
done

COMPOSE=(docker compose "$@")
exec_in() { local svc="$1"; shift; "${COMPOSE[@]}" exec -T "$svc" "$@"; }
host_gateways() { ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "via") print $(i + 1)}' || true; }
GATEWAYS="$(host_gateways | sort -u | tr '\n' ' ')"

# ---- topology (computed from the effective compose configuration) ---------------------------------
TOPO="$("${COMPOSE[@]}" config --format json 2>/dev/null | python3 -c '
import json, sys
cfg = json.load(sys.stdin)
nets = cfg.get("networks") or {}
out = {"services": {}}
for name, svc in sorted((cfg.get("services") or {}).items()):
    attached = sorted((svc.get("networks") or {"default": None}).keys())
    out["services"][name] = {
        "networks": attached,
        "out": any(not (nets.get(n) or {}).get("internal", False) for n in attached),
        "dns": list(svc.get("dns") or []),
    }
json.dump(out, sys.stdout)
')" || TOPO=""
[[ -n "$TOPO" ]] || fail "cannot read the compose configuration (docker compose config failed)"
mapfile -t SERVICES < <(python3 -c 'import json,sys; print("\n".join(json.loads(sys.argv[1])["services"]))' "$TOPO")
role_of() { python3 -c 'import json,sys; print("OUT" if json.loads(sys.argv[1])["services"][sys.argv[2]]["out"] else "IN")' "$TOPO" "$1"; }
for need in "${REQUIRED_OUT[@]}"; do
  [[ "$(role_of "$need" 2>/dev/null || true)" == OUT ]] \
    || fail "service '$need' is expected to have a route out but compose says otherwise: the topology changed; review this check"
done
for need in "${REQUIRED_IN[@]}"; do
  [[ "$(role_of "$need" 2>/dev/null || true)" == IN ]] \
    || fail "service '$need' is expected to be internal-only but compose says otherwise: the topology changed; review this check"
done

# ---- probes (run inside each container; they print facts only) --------------------------------------
# python flavour (the app and agent images). getaddrinfo goes through /etc/resolv.conf, i.e. through
# the embedded resolver, exactly like the application; the direct query is a raw UDP DNS packet.
# shellcheck disable=SC2016  # sent verbatim to the container's interpreter
PY_PROBE='
import socket, struct, sys
selfname, ext, peers, direct = sys.argv[1], sys.argv[2], sys.argv[3].split(), sys.argv[4].split()
print("TOOL python")
for line in open("/etc/resolv.conf"):
    if line.startswith(("nameserver", "# ExtServers")):
        print("RESOLV", line.strip())
def resolves(name):
    try:
        socket.getaddrinfo(name + ".", None, socket.AF_INET)
        return "ok"
    except socket.gaierror:
        return "fail"
    except OSError:
        return "err"
def answered(ip, name):
    q = struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    try:
        s.sendto(q, (ip, 53)); data, _ = s.recvfrom(512)
        return "ok" if data[:2] == b"\x42\x42" else "fail"
    except OSError:
        return "fail"
    finally:
        s.close()
n = 0
print("SELF", resolves(selfname)); n += 1
print("EXT", resolves(ext)); n += 1
for p in peers:
    print("PEER", p, resolves(p)); n += 1
for ip in direct:
    print("DIRECT", ip, answered(ip, ext)); n += 1
print("DONE", n)
'
# sh flavour (the alpine egress image: busybox nslookup)
# shellcheck disable=SC2016
SH_PROBE='
selfname="$1"; ext="$2"; peers="$3"; direct="$4"
command -v nslookup >/dev/null 2>&1 || { echo "TOOLMISSING nslookup"; exit 0; }
echo "TOOL nslookup"
grep -E "^(nameserver|# ExtServers)" /etc/resolv.conf | sed "s/^/RESOLV /"
res() { nslookup -timeout=3 "$1." 2>&1 | grep -q "^Address: [0-9a-fA-F]" && echo ok || echo fail; }
ans() { nslookup -timeout=3 "$2." "$1" 2>&1 | grep -q "^Address: [0-9a-fA-F]" && echo ok || echo fail; }
n=0
echo "SELF $(res "$selfname")"; n=$((n + 1))
echo "EXT $(res "$ext")"; n=$((n + 1))
for p in $peers; do echo "PEER $p $(res "$p")"; n=$((n + 1)); done
for ip in $direct; do echo "DIRECT $ip $(ans "$ip" "$ext")"; n=$((n + 1)); done
echo "DONE $n"
'

# The assessor turns one probe's stdout into BREACH / BROKEN / DEFECT / WARN lines. Anything it
# does not recognise is a defect.
ASSESS="$(cat <<'PY'
import json, re, sys
svc, topo, mode, expect_dns, ext, gateways = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6].split()
S = topo["services"]
me = S[svc]
role = "OUT" if me["out"] else "IN"
out = []
def add(kind, msg): out.append(kind + " " + msg)
tool, resolv, selfr, extr, peers, direct, done = None, [], None, None, {}, {}, None
for ln in sys.stdin.read().splitlines():
    if not ln.strip(): continue
    m = re.fullmatch(r"TOOL (python|nslookup)", ln)
    if m: tool = m.group(1); continue
    m = re.fullmatch(r"TOOLMISSING (\S+)", ln)
    if m: add("DEFECT", f"{svc}: {m.group(1)} is missing in the container; DNS UNVERIFIED"); continue
    m = re.fullmatch(r"RESOLV (.*)", ln)
    if m: resolv.append(m.group(1)); continue
    m = re.fullmatch(r"SELF (ok|fail|err)", ln)
    if m: selfr = m.group(1); continue
    m = re.fullmatch(r"EXT (ok|fail|err)", ln)
    if m: extr = m.group(1); continue
    m = re.fullmatch(r"PEER (\S+) (ok|fail|err)", ln)
    if m:
        if m.group(1) in peers: add("DEFECT", f"{svc}: duplicate result for {m.group(1)}")
        peers[m.group(1)] = m.group(2); continue
    m = re.fullmatch(r"DIRECT (\S+) (ok|fail)", ln)
    if m: direct[m.group(1)] = m.group(2); continue
    m = re.fullmatch(r"DONE (\d+)", ln)
    if m: done = int(m.group(1)); continue
    add("DEFECT", f"{svc}: malformed probe output {ln[:80]!r}; DNS UNVERIFIED")
if tool is None:
    if not out: add("DEFECT", f"{svc}: probe did not run (no output); DNS UNVERIFIED")
else:
    want_peers = sorted(S)
    want_direct = ([expect_dns.split(",")[0], "1.1.1.1"] if role == "IN" else gateways)
    if selfr != "ok": add("DEFECT", f"{svc}: cannot resolve its own service name ({selfr}): the embedded resolver does not work; DNS UNVERIFIED")
    if extr is None: add("DEFECT", f"{svc}: no verdict for the public name")
    missing = [p for p in want_peers if p not in peers]
    if missing: add("DEFECT", f"{svc}: probe skipped {len(missing)} service name(s), e.g. {missing[0]}; DNS UNVERIFIED")
    missing = [d for d in want_direct if d not in direct]
    if missing: add("DEFECT", f"{svc}: probe skipped direct query to {missing[0]}; DNS UNVERIFIED")
    if done != 2 + len(peers) + len(direct): add("DEFECT", f"{svc}: probe reported DONE {done} for {2 + len(peers) + len(direct)} results")
    if any(v == "err" for v in [selfr, extr, *peers.values()]): add("DEFECT", f"{svc}: unclassifiable resolver error; DNS UNVERIFIED")
    # --- config + runtime: which resolver does Docker really use? ---
    exp_set = set(expect_dns.split(","))
    if role == "OUT":
        if set(me["dns"]) != exp_set:
            add("BREACH", f"{svc} has a route out but its configured dns is {me['dns'] or 'EMPTY'}, expected {sorted(exp_set)}: its queries would leave the guard-policed path")
        ann = [r for r in resolv if r.startswith("# ExtServers:")]
        ns = [r.split()[1] for r in resolv if r.startswith("nameserver")]
        if ns != ["127.0.0.11"]: add("BREACH", f"{svc}: resolv.conf nameservers are {ns}, expected only Docker's embedded 127.0.0.11")
        if len(ann) != 1: add("DEFECT", f"{svc}: resolv.conf has no ExtServers annotation: cannot tell which path its DNS takes; DNS UNVERIFIED")
        else:
            got = re.fullmatch(r"# ExtServers: \[(.*)\]", ann[0])
            servers = set(re.split(r"[ ,]+", got.group(1).strip())) if got else {"?"}
            if "host(" in ann[0] or servers != exp_set:
                add("BREACH", f"{svc}: Docker forwards its DNS to {ann[0][len('# ExtServers: '):]}, expected [{' '.join(sorted(exp_set))}] queried from the container (host(...) = from the daemon, outside the guard)")
    else:
        if me["dns"]: add("BREACH", f"{svc} is internal-only but has dns {me['dns']} configured")
    # --- names: a service name resolves iff a network is shared ---
    mine = set(me["networks"])
    for p, r in sorted(peers.items()):
        share = p == svc or bool(mine & set(S[p]["networks"]))
        if share and r != "ok": add("DEFECT", f"{svc} cannot resolve {p}, which shares a network with it (service discovery broken)")
        if not share and r == "ok": add("BREACH", f"{svc} resolves {p}, with which it shares no network (DNS leaks service names across networks)")
    # --- external names ---
    if role == "IN":
        if extr == "ok": add("BREACH", f"{svc} is internal-only but resolves {ext}: DNS is a way out")
        for d in want_direct:
            if direct.get(d) == "ok": add("BREACH", f"{svc} is internal-only but gets DNS answers from {d} directly")
    else:
        if extr == "fail": add("BROKEN", f"{svc} cannot resolve {ext} through {expect_dns}: the guard has no DNS exception for it, or the resolver is down")
        for d in gateways:
            if direct.get(d) == "ok": add("LEAK", f"{svc} gets DNS answers from the host gateway {d} directly: a LAN resolver is reachable outside the guard exception")
for o in out: print(o)
PY
)"

DEFECTS=(); BREACHES=(); BROKEN=(); LEAKS=()
tmp="$(mktemp -d)"
# shellcheck disable=SC2317,SC2329  # invoked by the EXIT trap
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

probe_service() { # probe_service <service>: writes $tmp/<service>.out and .err
  local svc="$1" role peers direct
  role="$(role_of "$svc")"
  peers="${SERVICES[*]}"
  if [[ "$role" == IN ]]; then direct="${EXPECT_DNS%%,*} $PUBLIC_RESOLVER"; else direct="$GATEWAYS"; fi
  # the python flavour where the image has python (app, agent), busybox nslookup otherwise (egress)
  if ! exec_in "$svc" sh -c 'command -v python >/dev/null 2>&1' </dev/null >/dev/null 2>&1; then
    printf '%s\n' "$SH_PROBE" | exec_in "$svc" sh -s -- "$svc" "$EXT_NAME" "$peers" "$direct" >"$tmp/$svc.out" 2>"$tmp/$svc.err" || true
  else
    printf '%s\n' "$PY_PROBE" | exec_in "$svc" python - "$svc" "$EXT_NAME" "$peers" "$direct" >"$tmp/$svc.out" 2>"$tmp/$svc.err" || true
  fi
}
for svc in "${SERVICES[@]}"; do probe_service "$svc" & done
wait

for svc in "${SERVICES[@]}"; do
  out="$(tr -d '\r' <"$tmp/$svc.out")"
  if [[ -z "$out" ]]; then
    DEFECTS+=("$svc: docker exec produced no output ($(head -c 160 "$tmp/$svc.err" | tr '\n' ' ')); DNS UNVERIFIED")
    continue
  fi
  while IFS= read -r line; do
    case "$line" in
      "BREACH "*) BREACHES+=("${line#BREACH }") ;;
      "BROKEN "*) BROKEN+=("${line#BROKEN }") ;;
      "LEAK "*)   LEAKS+=("${line#LEAK }") ;;
      "DEFECT "*) DEFECTS+=("${line#DEFECT }") ;;
      '') ;;
      *) DEFECTS+=("$svc: assessor produced an unexpected line: ${line:0:80}") ;;
    esac
  done < <(printf '%s\n' "$out" | python3 -c "$ASSESS" "$svc" "$TOPO" "$MODE" "$EXPECT_DNS" "$EXT_NAME" "$GATEWAYS" 2>&1 \
           || echo "DEFECT $svc: the assessor itself failed")
done

# DEFECTS and BREACHES are fatal in every mode; BROKEN/LEAK (the outside world, the guard) are
# softened by report mode only.
if [[ ${#DEFECTS[@]} -gt 0 || ${#BREACHES[@]} -gt 0 ]]; then
  printf 'FAIL DNS isolation could not be verified or is breached (%s mode) - fatal in every mode:\n' "$MODE" >&2
  [[ ${#DEFECTS[@]} -eq 0 ]] || printf '       defect: %s\n' "${DEFECTS[@]}" >&2
  [[ ${#BREACHES[@]} -eq 0 ]] || printf '       breach: %s\n' "${BREACHES[@]}" >&2
  [[ ${#BROKEN[@]} -eq 0 && ${#LEAKS[@]} -eq 0 ]] || printf '       also: %s\n' "${BROKEN[@]}" "${LEAKS[@]}" >&2
  exit 1
fi
OUT_N=0; for s in "${SERVICES[@]}"; do [[ "$(role_of "$s")" == OUT ]] && OUT_N=$((OUT_N + 1)); done
if [[ ${#BROKEN[@]} -eq 0 && ${#LEAKS[@]} -eq 0 ]]; then
  ok "DNS: $OUT_N service(s) with a route out use ${EXPECT_DNS} from inside the container and resolve $EXT_NAME;" \
     "$(( ${#SERVICES[@]} - OUT_N )) internal-only service(s) resolve nothing outside the project;" \
     "service names resolve only across shared networks (${#SERVICES[@]} services)"
  exit 0
fi
if [[ "$MODE" == enforce ]]; then
  printf 'FAIL DNS (enforce):\n' >&2
  printf '       - %s\n' "${BROKEN[@]}" "${LEAKS[@]}" >&2
  exit 1
fi
warn "DNS (report mode) - NOT acceptable in production:"
printf 'WARN   - %s\n' "${BROKEN[@]}" "${LEAKS[@]}" >&2
exit 0
