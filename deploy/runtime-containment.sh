#!/usr/bin/env bash
# Runtime containment for the ROOTLESS Docker stack: keeps the security prerequisites TRUE after
# the deploy gate has gone home, and stops the autonomous workloads when one of them is lost.
#
#   runtime-containment.sh watch [--interval S]   long-running (systemd user unit, Type=notify)
#   runtime-containment.sh once                   one cycle: check and, if needed, act
#   runtime-containment.sh check                  read-only: print findings, change nothing
#   runtime-containment.sh status [--require-active]   read-only summary (deploy gate, operators)
#   runtime-containment.sh quarantine --reason R [--no-latch]   stop the supervised set now
#   runtime-containment.sh reset [--disconnect-foreign]         operator: clear the latch, after checks
#   runtime-containment.sh commit --sha S --release-dir D [--forbidden L] [--protected-ips L]
#                         [--rootful L] -- <compose args>       remote-deploy.sh only, under its lock
#   runtime-containment.sh desired running|stopped              remote-deploy.sh only, under its lock
#
# WHY. The deploy gate proves isolation at deploy time. Nothing proved it afterwards: the guard
# could be removed or weakened, a container hot-attached to another network, the resolver changed,
# the host's Tailscale address could appear after the stack started (start gates only see targets
# that are reachable), and an agent would keep running through all of it (docs/deployment.md,
# "Runtime containment"). This script is the continuous version of that gate.
#
# THE SUPERVISED SET = every service with a route out (api, discovery, telegram, the three egress
# proxies) plus the agents. compose.yaml gives exactly these `restart: "no"`, so after a daemon
# restart or a reboot the DAEMON starts none of them; this script starts them, and only once the
# prerequisites hold (guard verified, protected host addresses live, rendered DNS == guard DNS=).
# The data tier (postgres, scheduler, session-controller) keeps Docker's restart policy: it has no
# route to the host.
#
# INVARIANTS (checked every cycle, and on host/Docker events), by consequence:
#   LATCHING (a possible compromise or a human error that can vanish by itself: the set is stopped
#   and stays stopped until `reset`):
#     ATTACH-UNEXPECTED  a project container is attached to a network its service does not declare
#     ATTACH-FOREIGN     a container that is not ours is attached to a project network
#     NET-FLAG           a project network that must be internal is not
#     HOSTCFG            host network/pid, privileged, or the Docker socket mounted in a project container
#     SVC-UNKNOWN        a container claims the project but no service of the release matches
#     DNS-RT             the RUNTIME resolver of a service differs from the contract (a service with a
#                        route out not on the approved resolver; an internal-only one with ANY upstream)
#     FLAPPING           three self-healed quarantines in 15 minutes
#     POST-START         the enforce-mode isolation/DNS checks failed after this script started the set
#     DESIRED            supervised containers run although no deploy committed them (manual `compose up`)
#   SELF-HEALING (a prerequisite is missing; the set is stopped, repaired if repairable, restarted):
#     GUARD              host-egress-guard.sh status != 0: removed, weakened, a new host address (Tailscale or
#                        a DHCP address that appeared after boot) the policy does not know yet
#     TARGETS            the protected host addresses are not live yet (Tailscale late at boot): never START
#                        the set on a host whose isolation targets cannot be probed
#     DNS-CONF           the rendered compose DNS differs from DNS= in the root-owned guard conf
#     TRUST              a root-owned helper is missing, a symlink, or writable by others
#     UNVERIFIED         Docker could not be inspected: nothing is certified
#   WARNING (logged, shown by `status`, nothing is stopped; a deploy re-baselines it):
#     RESOLVER           the daemon's upstream resolver list (the host's resolver) changed since the deploy
#
# FAIL CLOSED. Stopping is never conditional on being sure of the cause; starting always is.
# `docker stop` only: containers are never removed, so evidence survives. Endpoints that should not
# exist are disconnected, never the container killed outside the supervised set. Rootful Docker, UFW,
# Tailscale and every other container are never touched: this talks to the rootless socket of the
# user that owns it, and only to containers labelled with this compose project.
#
# DEAD MAN. The systemd unit (deploy/systemd/hunter-containment.service) is Type=notify with
# WatchdogSec, Restart=always and ExecStopPost=`quarantine --no-latch`: if this process dies, hangs
# or is stopped, the supervised set stops (and comes back when a new instance verifies everything).
# remote-deploy.sh refuses to deploy unless `status --require-active` says a fresh heartbeat exists.
#
# State (directory $BASE/state/containment, owned by the deploy user): contract.json (written by
# `commit` after a deploy passed every gate: topology, DNS, the isolation parameters), desired,
# latch, heartbeat, state, flaps, events.log. Exit codes: 0 ok, 10 critical finding, 11 not ready,
# 20 no/stale heartbeat, 21 latched, 22 paused/unverified, 2 usage.
set -Eeuo pipefail

PROD_BASE=/opt/internship-hunter
if [[ "${HUNTER_CONTAINMENT_TEST_MODE:-0}" == 1 ]]; then
  TEST_MODE=1
  BASE="${HUNTER_BASE:-}"
  if [[ -z "$BASE" || "$BASE" == "$PROD_BASE" || "$BASE" == "$PROD_BASE"/* ]]; then
    echo "runtime-containment: HUNTER_CONTAINMENT_TEST_MODE requires HUNTER_BASE outside $PROD_BASE" >&2; exit 2
  fi
else
  TEST_MODE=0
  BASE="$PROD_BASE"
  # nothing that makes a shell, the loader or Python load foreign code, nothing that redirects the
  # helpers this script trusts, and a fixed PATH
  unset BASH_ENV ENV LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT PYTHONPATH PYTHONHOME PYTHONSTARTUP \
        PYTHONUSERBASE PYTHONINSPECT HUNTER_BASE HUNTER_GUARD_PROC HUNTER_GUARD_TEST_MODE \
        HUNTER_GUARD_TEST_NSFS_TYPE HUNTER_DNS HUNTER_TEST_MODE DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG
  for v in $(compgen -e | grep -E '^(SMOKE_|COMPOSE_|EGRESS_)' || true); do unset "$v"; done
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  export PATH
fi

GUARD="$BASE/deploy/host-egress-guard.sh"
ISOLATION_CHECK="$BASE/deploy/check-host-isolation.sh"
DNS_CHECK="$BASE/deploy/check-dns.sh"
GUARD_CONF="$BASE/deploy/host-egress-guard.conf"
ISOLATION_CONF="$BASE/deploy/host-isolation.conf"
STATE="$BASE/state/containment"
DEPLOY_LOCK="$BASE/state/deploy.lock"
PROJECT=internship-hunter
INTERVAL=10
DOCKER_TIMEOUT="${HUNTER_CONTAINMENT_DOCKER_TIMEOUT:-25}"
HEARTBEAT_MAX_AGE="${HUNTER_CONTAINMENT_HEARTBEAT_MAX_AGE:-45}"   # status --require-active
MAX_DEPLOY_PAUSE="${HUNTER_CONTAINMENT_MAX_DEPLOY_PAUSE:-1800}"   # a deploy lock older than this is a hung deploy
FLAP_WINDOW=900; FLAP_MAX=3
RESTART_BACKOFF="${HUNTER_CONTAINMENT_RESTART_BACKOFF:-30}"
START_TIMEOUT="${HUNTER_CONTAINMENT_START_TIMEOUT:-120}"
MYUID="$(id -u)"

die() { echo "runtime-containment: $1" >&2; exit "${2:-1}"; }
now() { date +%s; }

# ---- Docker: the user's own rootless daemon, never the rootful one ----------------------------------
if [[ "$TEST_MODE" == 0 ]]; then
  [[ "$MYUID" != 0 ]] || die "refusing to run as root: run as the user that owns the rootless Docker daemon" 2
  RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$MYUID}"
  export DOCKER_HOST="unix://$RUNTIME_DIR/docker.sock"
fi
docker() { timeout "$DOCKER_TIMEOUT" docker "$@"; }

trusted_file() { # a regular, non-symlink file owned by root (the test user in test mode), not writable by others
  local want_uid=0 owner mode; [[ "$TEST_MODE" == 1 ]] && want_uid="$MYUID"
  [[ -f "$1" && ! -L "$1" ]] || return 1
  read -r owner mode < <(stat -c '%u %a' "$1") || return 1
  [[ "$owner" == "$want_uid" ]] && (( (8#$mode & 8#022) == 0 ))
}
trusted_exec() { trusted_file "$1" && [[ -x "$1" ]] && dir_trusted "$(dirname "$1")"; }
dir_trusted() {
  local want_uid=0 owner mode; [[ "$TEST_MODE" == 1 ]] && want_uid="$MYUID"
  [[ -d "$1" && ! -L "$1" ]] || return 1
  read -r owner mode < <(stat -c '%u %a' "$1") || return 1
  [[ "$owner" == "$want_uid" ]] && (( (8#$mode & 8#022) == 0 ))
}

# ---- state ---------------------------------------------------------------------------------------------
mkdir -p "$STATE"; chmod 700 "$STATE" 2>/dev/null || true
CONTRACT="$STATE/contract.json"
if [[ -f "$CONTRACT" ]]; then
  PROJECT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["project"])' "$CONTRACT" 2>/dev/null || echo internship-hunter)"
fi
atomic_write() { local f="$1" t; t="$(mktemp "$STATE/.tmp.XXXXXX")"; cat >"$t"; mv -f "$t" "$f"; }
read_file() { cat "$1" 2>/dev/null || true; }
log() { # log <LEVEL> <ID> <message>: events.log (bounded) and stderr (journald)
  local line; line="$(date -u +%Y-%m-%dT%H:%M:%SZ) $1 $2 $3"
  echo "runtime-containment: $1 $2 $3" >&2
  echo "$line" >>"$STATE/events.log" 2>/dev/null || true
  if [[ -f "$STATE/events.log" && "$(stat -c %s "$STATE/events.log" 2>/dev/null || echo 0)" -gt 1048576 ]]; then
    mv -f "$STATE/events.log" "$STATE/events.log.1" 2>/dev/null || true
  fi
}
notify() { # notify <sd_notify words...>: only under systemd (Type=notify), never an error
  if [[ -n "${NOTIFY_SOCKET:-}" ]] && command -v systemd-notify >/dev/null 2>&1; then systemd-notify "$@" 2>/dev/null || true; fi
}
set_state() { # set_state <name> [detail]
  printf '%s\n' "$1${2:+ $2}" | atomic_write "$STATE/state"
  notify "STATUS=$1${2:+: $2}"
}
beat() { now | atomic_write "$STATE/heartbeat"; notify WATCHDOG=1; }

guard_dns() { # DNS= of the root-owned guard conf (the one resolver the guard lets through)
  local v d
  trusted_file "$GUARD_CONF" || return 1
  v="$(sed -n 's/^DNS=//p' "$GUARD_CONF" | tail -1 | tr -d "\"' \r")"
  [[ -n "$v" ]] || return 1
  for d in ${v//,/ }; do [[ "$d" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1; done
  printf '%s' "$v"
}
rootful_targets() {
  local v
  trusted_file "$ISOLATION_CONF" || return 1
  v="$(sed -n 's/^ROOTFUL_TARGETS=//p' "$ISOLATION_CONF" | tail -1 | tr -d "\"' \r")"
  [[ -n "$v" ]] || return 1
  printf '%s' "$v"
}
daemon_resolvers() { # the upstream resolvers of the daemon itself (what a container without `dns:` would inherit)
  local pidf="${XDG_RUNTIME_DIR:-/run/user/$MYUID}/dockerd-rootless/child_pid" pid
  pid="$(cat "$pidf" 2>/dev/null)" || return 1
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  awk '$1 == "nameserver" {print $2}' "/proc/$pid/root/etc/resolv.conf" 2>/dev/null | sort | tr '\n' ' ' | sed 's/ $//'
}

# ---- the assessor: contract + Docker's own description of the containers and networks -------------------------
# Pure function of its inputs: prints one record per line, tab separated:
#   F <LEVEL> <LATCH 0|1> <ID> <message>     a finding (LEVEL CRIT|WARN)
#   A disconnect <network id> <container id> <what>
#   SUP <container id> <service>             supervised (or unknown project) containers that RUN
#   MISSING <service>                        supervised services of the contract that are not running
ASSESS="$(cat <<'PY'
import json, os, re, sys
contract = json.load(open(sys.argv[1]))
containers = json.load(open(sys.argv[2]))
networks = json.load(open(sys.argv[3]))
facts = json.loads(sys.argv[4])
P = contract["project"]
S = contract["services"]
LP, LS, LN = "com.docker.compose.project", "com.docker.compose.service", "com.docker.compose.network"
out = []
def find(level, latch, ident, msg): out.append("F\t%s\t%d\t%s\t%s" % (level, latch, ident, msg.replace("\t", " ").replace("\n", " ")))
def act(netid, cid, what): out.append("A\tdisconnect\t%s\t%s\t%s" % (netid, cid, what))
nets = {n["Id"]: n for n in networks}
def project_net(n): return n is not None and (n.get("Labels") or {}).get(LP) == P
# --- networks: the flags that make a network a boundary ---
for n in networks:
    if not project_net(n): continue
    logical = (n.get("Labels") or {}).get(LN)
    want = contract["networks"].get(logical)
    if want is None: continue
    if bool(n.get("Internal")) != bool(want["internal"]):
        find("CRIT", 1, "NET-FLAG", "network %s must be %s but is %s" % (n["Name"], "internal" if want["internal"] else "non-internal", "internal" if n.get("Internal") else "NOT internal"))
running = {}
for c in containers:
    labels = (c.get("Config") or {}).get("Labels") or {}
    name = c.get("Name", "?").lstrip("/")
    cid = c["Id"]
    attached = (c.get("NetworkSettings") or {}).get("Networks") or {}
    if labels.get(LP) != P:
        # not ours: it must not be on any of our networks
        for nname, ep in attached.items():
            n = nets.get(ep.get("NetworkID"))
            if project_net(n):
                find("CRIT", 1, "ATTACH-FOREIGN", "container %s (not part of the release) is attached to project network %s" % (name, n["Name"]))
                act(n["Id"], cid, "foreign container %s on %s" % (name, n["Name"]))
        continue
    svc_name = labels.get(LS, "?")
    svc = S.get(svc_name)
    up = bool((c.get("State") or {}).get("Running"))
    if svc is None:
        find("CRIT", 1, "SVC-UNKNOWN", "container %s claims service %r of project %s, which the deployed release does not define" % (name, svc_name, P))
        if up: out.append("SUP\t%s\t%s" % (cid, svc_name))
        continue
    if svc["supervised"] and up:
        running.setdefault(svc_name, []).append(cid)
        out.append("SUP\t%s\t%s" % (cid, svc_name))
    # --- attachments ---
    logical_now = set()
    for nname, ep in attached.items():
        n = nets.get(ep.get("NetworkID"))
        if not project_net(n):
            find("CRIT", 1, "ATTACH-UNEXPECTED", "%s (%s) is attached to %s, which is not a network of this release" % (name, svc_name, nname))
            act(ep.get("NetworkID", nname), cid, "%s on foreign network %s" % (name, nname))
            continue
        logical = (n.get("Labels") or {}).get(LN)
        logical_now.add(logical)
        if logical not in svc["networks"]:
            find("CRIT", 1, "ATTACH-UNEXPECTED", "%s (%s) is attached to %s, but the release declares only %s" % (name, svc_name, n["Name"], sorted(svc["networks"])))
            act(n["Id"], cid, "%s on %s" % (name, n["Name"]))
    # --- how it was started: no way around the networks ---
    hc = c.get("HostConfig") or {}
    mode = hc.get("NetworkMode") or ""
    bad = []
    if mode == "host" or mode.startswith("container:"): bad.append("network mode %s" % mode)
    if hc.get("Privileged"): bad.append("privileged")
    if hc.get("PidMode") == "host": bad.append("host pid namespace")
    for m in c.get("Mounts") or []:
        if re.search(r"docker\.sock$", m.get("Source", "") or ""): bad.append("the Docker socket mounted")
    if bad: find("CRIT", 1, "HOSTCFG", "%s (%s): %s" % (name, svc_name, ", ".join(bad)))
    # --- the runtime resolver state (not what compose declares); a stopped container's file is regenerated at start ---
    if not up:
        continue
    path = c.get("ResolvConfPath")
    try:
        lines = open(path).read().splitlines()
    except (OSError, TypeError):
        find("CRIT", 0, "DNS-RT", "%s (%s): UNVERIFIED, cannot read its resolv.conf (%s)" % (name, svc_name, path))
        continue
    ns = [l.split()[1] for l in lines if l.startswith("nameserver") and len(l.split()) > 1]
    ann = [l for l in lines if l.startswith("# ExtServers:")]
    tokens = []
    if len(ann) == 1:
        m = re.fullmatch(r"# ExtServers: \[(.*)\]", ann[0])
        tokens = re.findall(r"host\([^)]*\)|[^\s,]+", m.group(1)) if m else ["?"]
    explicit = [t for t in tokens if not (t.startswith("host(") and t.endswith(")"))]
    if ns != ["127.0.0.11"]:
        find("CRIT", 1, "DNS-RT", "%s (%s): resolv.conf nameservers are %s, expected only Docker's embedded 127.0.0.11" % (name, svc_name, ns))
    if svc["out"]:
        want = set(contract["dns"].split(","))
        if len(ann) != 1:
            find("CRIT", 0, "DNS-RT", "%s (%s): UNVERIFIED, its resolv.conf has %d ExtServers annotation(s)" % (name, svc_name, len(ann)))
        elif set(explicit) != want or len(explicit) != len(tokens):
            find("CRIT", 1, "DNS-RT", "%s (%s): Docker forwards its DNS to %s, the contract says [%s] queried from the container (host(...) = from the daemon, outside the guard)" % (name, svc_name, ann[0][len("# ExtServers: "):], " ".join(sorted(want))))
    elif explicit:
        find("CRIT", 1, "DNS-RT", "%s (%s) is internal-only but Docker gave it explicit upstream resolver(s) %s (daemon-level dns?): an agent carries no upstream" % (name, svc_name, explicit))
for svc_name, svc in sorted(S.items()):
    if svc["supervised"] and svc_name not in running:
        out.append("MISSING\t%s" % svc_name)
# --- DNS configuration drift ---
if facts.get("guard_dns") is not None and facts["guard_dns"] != contract["dns"]:
    find("CRIT", 0, "DNS-CONF", "DNS= in the guard conf is now %s but the deployed release was verified against %s" % (facts["guard_dns"], contract["dns"]))
if facts.get("resolvers") is not None and contract.get("resolver_baseline") is not None and facts["resolvers"] != contract["resolver_baseline"]:
    find("WARN", 0, "RESOLVER", "the daemon's upstream resolvers changed from [%s] to [%s] (host resolver change); every service uses an explicit resolver so nothing is stopped; redeploy to re-baseline" % (contract["resolver_baseline"], facts["resolvers"]))
print("\n".join(out))
PY
)"

# ---- Docker snapshot -----------------------------------------------------------------------------------------
TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

collect() { # collect: containers.json (ALL containers) and networks.json; false if Docker cannot be inspected
  local ids nets
  docker info --format '{{.SecurityOptions}}' >"$TMP/info" 2>/dev/null || return 1
  if [[ "$TEST_MODE" == 0 ]]; then
    grep -q rootless "$TMP/info" || { log CRIT UNVERIFIED "the Docker daemon is not rootless: refusing to act on it"; return 2; }
  fi
  ids="$(docker ps -aq --no-trunc 2>/dev/null)" || return 1     # stopped ones too: their endpoints come back when they start
  if [[ -n "$ids" ]]; then
    # shellcheck disable=SC2086  # ids are hex words
    docker inspect $ids >"$TMP/containers.json" 2>/dev/null || return 1
  else echo '[]' >"$TMP/containers.json"; fi
  nets="$(docker network ls -q --no-trunc 2>/dev/null)" || return 1
  if [[ -n "$nets" ]]; then
    # shellcheck disable=SC2086
    docker network inspect $nets >"$TMP/networks.json" 2>/dev/null || return 1
  else echo '[]' >"$TMP/networks.json"; fi
}

contract_get() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); v=d
for k in sys.argv[2].split("."): v=v[k]
print(v if not isinstance(v,(list,dict)) else json.dumps(v))' "$CONTRACT" "$1"; }

ACTED=0       # set when this cycle stopped something or latched
FINDINGS=()   # "LEVEL|LATCH|ID|message"
ACTIONS=()    # "netid|cid|what"
SUP_IDS=()    # running supervised (and unknown project) containers
MISSING=()    # supervised services that do not run
assess() { # assess: topology + runtime DNS from the Docker snapshot, into the arrays above
  local facts rec kind a b c d resolvers have_res=1
  FINDINGS=(); ACTIONS=(); SUP_IDS=(); MISSING=()
  resolvers="$(daemon_resolvers 2>/dev/null)" || have_res=0
  facts="$(GUARD_DNS_NOW="$(guard_dns 2>/dev/null || true)" RESOLVERS_NOW="$resolvers" HAVE_RES="$have_res" python3 -c '
import json, os
print(json.dumps({"guard_dns": os.environ["GUARD_DNS_NOW"] or None,
                  "resolvers": os.environ["RESOLVERS_NOW"] if os.environ["HAVE_RES"] == "1" else None}))')"
  rec="$(python3 -c "$ASSESS" "$CONTRACT" "$TMP/containers.json" "$TMP/networks.json" "$facts")" \
    || { FINDINGS+=("CRIT|0|UNVERIFIED|the assessor failed: nothing is certified"); return; }
  while IFS=$'\t' read -r kind a b c d; do
    case "$kind" in
      F) FINDINGS+=("$a|$b|$c|$d") ;;
      A) ACTIONS+=("$b|$c|$d") ;;
      SUP) SUP_IDS+=("$a") ;;
      MISSING) MISSING+=("$a") ;;
      '') ;;
      *) FINDINGS+=("CRIT|0|UNVERIFIED|assessor produced an unexpected record: ${kind:0:40}") ;;
    esac
  done <<<"$rec"
}

# ---- prerequisites (not about what runs, about what the host provides) ------------------------------------------
PREREQ=()     # "ID message"
contract_args() { python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["compose_args"]))' "$CONTRACT"; }
compose_cmd() { # compose_cmd <args...>: docker compose in the committed release, with its exact arguments
  local rel args
  rel="$(contract_get release_dir)"; mapfile -t args < <(contract_args)
  ( cd "$rel" && RELEASE_SHA="$(contract_get release_sha)" docker compose "${args[@]}" "$@" )
}
dns_config_ok() { # the rendered DNS must equal the guard's, judged by the root-owned check
  local rel args
  rel="$(contract_get release_dir)"; mapfile -t args < <(contract_args)
  ( cd "$rel" && RELEASE_SHA="$(contract_get release_sha)" SMOKE_DNS_CONFIG_ONLY=1 SMOKE_DNS_EXPECT="$1" "$DNS_CHECK" "${args[@]}" )
}
prereqs() { # prereqs <with_targets 0|1>: what the HOST must provide; PREREQ gets one entry per missing thing
  local with_targets="$1" out dnsexp f
  PREREQ=()
  for f in "$GUARD" "$ISOLATION_CHECK" "$DNS_CHECK"; do
    trusted_exec "$f" || PREREQ+=("TRUST $f is missing, not a regular executable, or writable by others")
  done
  trusted_file "$GUARD_CONF" || PREREQ+=("TRUST $GUARD_CONF is missing or untrusted")
  trusted_file "$ISOLATION_CONF" || PREREQ+=("TRUST $ISOLATION_CONF is missing or untrusted")
  [[ ${#PREREQ[@]} -eq 0 ]] || return 0
  if ! out="$("$GUARD" status 2>&1)"; then
    PREREQ+=("GUARD host-egress-guard.sh status: $(tr '\n' ' ' <<<"$out" | cut -c1-300)")
  fi
  dnsexp="$(guard_dns 2>/dev/null || true)"
  if [[ -z "$dnsexp" ]]; then
    PREREQ+=("DNS-CONF no valid DNS= in $GUARD_CONF")
  elif ! out="$(dns_config_ok "$dnsexp" 2>&1)"; then
    PREREQ+=("DNS-CONF rendered compose DNS disagrees with DNS=$dnsexp: $(tr '\n' ' ' <<<"$out" | cut -c1-300)")
  fi
  if [[ "$with_targets" == 1 ]]; then
    if ! out="$(EGRESS_FORBIDDEN_TARGETS="$(contract_get forbidden_targets)" SMOKE_ROOTFUL_TARGETS="$(rootful_targets 2>/dev/null || true)" \
                SMOKE_EXPECT_ROOTLESS=1 "$ISOLATION_CHECK" --verify-targets 2>&1)"; then
      PREREQ+=("TARGETS protected host addresses are not live yet (Tailscale late?): $(tr '\n' ' ' <<<"$out" | cut -c1-240)")
    fi
  fi
}

# ---- actions -----------------------------------------------------------------------------------------------------
stop_ids() { # stop_ids <ids...>
  [[ $# -gt 0 ]] || return 0
  docker stop -t 5 "$@" >/dev/null 2>&1 || { log CRIT STOP-FAILED "docker stop failed for ${#} container(s): killing"; docker kill "$@" >/dev/null 2>&1 || true; }
}
do_actions() { local a netid cid what
  for a in "${ACTIONS[@]}"; do
    IFS='|' read -r netid cid what <<<"$a"
    if docker network disconnect -f "$netid" "$cid" >/dev/null 2>&1; then log CRIT DISCONNECTED "$what"
    else log CRIT DISCONNECT-FAILED "$what"; fi
  done
}
latch_set() { # latch_set <reason>
  printf '{"time": %s, "reason": %s}\n' "$(now)" "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1")" | atomic_write "$STATE/latch"
}
flap_record() { # flap_record -> exits 0 normally, 1 when the flap limit is reached
  local t cutoff n=0
  t="$(now)"; cutoff=$((t - FLAP_WINDOW))
  { grep -E '^[0-9]+$' "$STATE/flaps" 2>/dev/null || true; echo "$t"; } | awk -v c="$cutoff" '$1 >= c' | atomic_write "$STATE/flaps"
  n="$(grep -c . "$STATE/flaps" || true)"
  (( n < FLAP_MAX ))
}
quarantine() { # quarantine <latch 0|1> <reason>: stop the supervised set now, remove unauthorised endpoints
  local latch="$1" reason="$2"
  ACTED=1
  if [[ ${#SUP_IDS[@]} -gt 0 ]]; then stop_ids "${SUP_IDS[@]}"; fi
  do_actions
  if [[ "$latch" == 1 ]]; then
    latch_set "$reason"; log CRIT LATCHED "$reason: ${#SUP_IDS[@]} container(s) stopped; stays stopped until 'runtime-containment.sh reset'"
    set_state latched "$reason"
  else
    if ! flap_record; then
      latch_set "FLAPPING: $FLAP_MAX quarantines in $((FLAP_WINDOW / 60)) minutes (last cause: $reason)"
      log CRIT LATCHED "FLAPPING: $reason"; set_state latched "flapping"
    else
      log CRIT QUARANTINE "$reason: ${#SUP_IDS[@]} container(s) stopped (will recover when the prerequisites hold)"
      set_state quarantined "$reason"
    fi
  fi
}
SUPERVISED_ALL=()
load_supervised() { mapfile -t SUPERVISED_ALL < <(python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["services"]
for k,v in sorted(d.items()):
    if v["supervised"]: print(k)' "$CONTRACT"); }

healthy_wait() { # healthy_wait <services...>: running (and healthy when a healthcheck exists), within START_TIMEOUT
  local deadline=$((SECONDS + START_TIMEOUT)) svc cid h all
  while (( SECONDS < deadline )); do
    beat                       # a slow start must not look like a dead watchdog
    all=1
    for svc in "$@"; do
      cid="$(docker ps -q --no-trunc --filter "label=com.docker.compose.project=$PROJECT" --filter "label=com.docker.compose.service=$svc" 2>/dev/null | head -1)"
      [[ -n "$cid" ]] || { all=0; break; }
      h="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || echo bad)"
      [[ "$h" == none || "$h" == healthy ]] || { all=0; break; }
    done
    [[ "$all" == 1 ]] && return 0
    sleep 1
  done
  return 1
}
start_services() { # start_services <services...>: in two phases (proxies first), only `start`, never create/pull/build
  local proxies=() rest=() s
  for s in "$@"; do
    if [[ "$s" == egress-* ]]; then proxies+=("$s"); else rest+=("$s"); fi
  done
  if [[ ${#proxies[@]} -gt 0 ]]; then
    compose_cmd start "${proxies[@]}" >/dev/null 2>&1 || { log CRIT START-FAILED "compose start ${proxies[*]} failed"; return 1; }
    healthy_wait "${proxies[@]}" || { log CRIT START-FAILED "proxies did not become healthy"; return 1; }
  fi
  if [[ ${#rest[@]} -gt 0 ]]; then
    compose_cmd start "${rest[@]}" >/dev/null 2>&1 || { log CRIT START-FAILED "compose start ${rest[*]} failed"; return 1; }
    healthy_wait "${rest[@]}" || { log CRIT START-FAILED "services did not become healthy"; return 1; }
  fi
}
verify_started() { # the deploy gate's enforce-mode checks, once, after THIS script started the set
  local ips rootful dnsexp
  beat
  ips="$(contract_get protected_ips)"; rootful="$(contract_get rootful_targets)"; dnsexp="$(contract_get dns)"
  local rel args out
  rel="$(contract_get release_dir)"; mapfile -t args < <(contract_args)
  if ! out="$( cd "$rel" && SMOKE_HOST_ISOLATION=enforce SMOKE_EXPECT_ROOTLESS=1 SMOKE_REQUIRE_TAILNET=1 SMOKE_AUTODETECT_HOST_IPS=1 \
               SMOKE_PROTECTED_IPS="$ips" SMOKE_ROOTFUL_TARGETS="$rootful" "$ISOLATION_CHECK" "${args[@]}" 2>&1 )"; then
    echo "$out" >&2; return 1
  fi
  if ! out="$( cd "$rel" && SMOKE_HOST_ISOLATION=enforce SMOKE_DNS_EXPECT="$dnsexp" "$DNS_CHECK" "${args[@]}" 2>&1 )"; then
    echo "$out" >&2; return 1
  fi
}

# ---- one cycle ----------------------------------------------------------------------------------------------------
DEPLOY_FD=""
take_deploy_lock() { # 0 = we hold it; 1 = a deploy holds it (paused); 2 = held too long (hung deploy: act anyway)
  [[ -e "$DEPLOY_LOCK" ]] || { mkdir -p "$(dirname "$DEPLOY_LOCK")"; : >>"$DEPLOY_LOCK"; }
  exec {DEPLOY_FD}<"$DEPLOY_LOCK"
  if flock -n "$DEPLOY_FD"; then return 0; fi
  exec {DEPLOY_FD}<&-; DEPLOY_FD=""
  local age=$(( $(now) - $(stat -c %Y "$DEPLOY_LOCK" 2>/dev/null || now) ))
  (( age > MAX_DEPLOY_PAUSE )) && return 2
  return 1
}
drop_deploy_lock() { [[ -z "$DEPLOY_FD" ]] || { exec {DEPLOY_FD}<&-; DEPLOY_FD=""; }; }

summarise() { printf '%s; ' "$@" | cut -c1-400; }

refresh() { # refresh <with_targets>: a new Docker snapshot and a new assessment; false if Docker cannot be inspected
  collect || return 1
  assess
  prereqs "$1"
}
problems_now() { # PROBLEMS = soft findings + missing prerequisites, as "ID message" lines
  local f level latch id msg r
  PROBLEMS=()
  for f in "${FINDINGS[@]}"; do
    IFS='|' read -r level latch id msg <<<"$f"
    [[ "$level" == CRIT && "$latch" == 0 ]] && PROBLEMS+=("$id $msg")
  done
  for r in "${PREREQ[@]}"; do PROBLEMS+=("$r"); done
}
note_waiting() { # log a change of the reason the set is not running, once
  local reason="$1"
  if [[ "$(read_file "$STATE/last_waiting")" != "$reason" ]]; then
    log CRIT WAITING "the supervised set is not running: $reason"
    printf '%s\n' "$reason" | atomic_write "$STATE/last_waiting"
  fi
  set_state waiting "$reason"
}

cycle_locked() { # runs with the deploy lock held (or a hung deploy's): returns 0 healthy/waiting, 1 acted on a violation, 2 unverified
  local desired latched f level latch id msg warns=() crit_latch=() r s cold due=() rc=0
  desired="$(read_file "$STATE/desired")"; latched=0; [[ -f "$STATE/latch" ]] && latched=1
  load_supervised
  collect || rc=$?
  if [[ "$rc" != 0 ]]; then
    log CRIT UNVERIFIED "Docker cannot be inspected (rc=$rc): no invariant can be certified"
    set_state unverified "docker unavailable"
    return 2
  fi
  assess
  prereqs "$([[ ${#SUP_IDS[@]} -eq 0 ]] && echo 1 || echo 0)"
  for f in "${FINDINGS[@]}"; do
    IFS='|' read -r level latch id msg <<<"$f"
    if [[ "$level" == WARN ]]; then warns+=("$id $msg")
    elif [[ "$latch" == 1 ]]; then crit_latch+=("$id $msg"); fi
  done
  if [[ ${#warns[@]} -gt 0 ]]; then
    for r in "${warns[@]}"; do
      if [[ "$(read_file "$STATE/last_warn")" != "$r" ]]; then log WARN "${r%% *}" "${r#* }"; printf '%s\n' "$r" | atomic_write "$STATE/last_warn"; fi
    done
  else rm -f "$STATE/last_warn"; fi
  # 1. a latch stays until an operator resets it, whatever else is true
  if [[ "$latched" == 1 ]]; then
    if [[ ${#SUP_IDS[@]} -gt 0 ]]; then ACTED=1; stop_ids "${SUP_IDS[@]}"; log CRIT LATCHED "the latch is set and supervised containers were running: stopped them again"; fi
    do_actions
    set_state latched "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["reason"])' "$STATE/latch" 2>/dev/null || echo unknown)"
    return 1
  fi
  # 2. integrity events: stop, remove the unauthorised endpoints, latch
  if [[ ${#crit_latch[@]} -gt 0 ]]; then
    quarantine 1 "$(summarise "${crit_latch[@]}")"
    return 1
  fi
  # 3. nothing may run that no deploy committed
  if [[ "$desired" != running ]]; then
    if [[ ${#SUP_IDS[@]} -gt 0 ]]; then
      quarantine 1 "DESIRED: supervised containers run but the last deploy did not leave the stack running (desired='${desired:-unset}')"
      return 1
    fi
    set_state stopped "desired state is '${desired:-unset}'"
    return 0
  fi
  # 4. a prerequisite or a soft finding is wrong: stop what runs, repair what can be repaired
  problems_now
  if [[ ${#PROBLEMS[@]} -gt 0 ]]; then
    local acted=0 only_guard=0
    [[ ${#PROBLEMS[@]} -eq 1 && "${PROBLEMS[0]}" == GUARD\ * ]] && only_guard=1
    if [[ ${#SUP_IDS[@]} -gt 0 ]]; then quarantine 0 "$(summarise "${PROBLEMS[@]}")"; acted=1; fi
    if [[ "$acted" == 1 && ( "$(read_file "$STATE/state")" == latched* ) ]]; then return 1; fi   # the flap limit just latched
    if [[ "$only_guard" == 1 ]]; then
      # only the guard is wrong: re-apply it (idempotent, the same call as the daemon's ExecStartPost)
      if "$GUARD" apply --wait 20 >/dev/null 2>&1 && "$GUARD" status >/dev/null 2>&1; then
        log INFO GUARD-REPAIRED "host-egress-guard.sh apply restored the policy"
      else
        log CRIT GUARD-UNREPAIRABLE "host-egress-guard.sh apply did not restore the policy; the supervised set stays stopped"
      fi
    fi
    refresh 1 || { set_state unverified "docker unavailable"; return 2; }
    problems_now
    if [[ ${#PROBLEMS[@]} -gt 0 ]]; then
      note_waiting "$(summarise "${PROBLEMS[@]}")"
      [[ "$acted" == 1 ]] && return 1 || return 0
    fi
  fi
  rm -f "$STATE/last_waiting"
  # 5. everything holds: make the set whole again
  if [[ ${#MISSING[@]} -gt 0 ]]; then
    cold=0; [[ ${#SUP_IDS[@]} -eq 0 ]] && cold=1
    for s in "${MISSING[@]}"; do
      if [[ "$cold" == 1 ]] || (( $(now) - $(cat "$STATE/restart.$s" 2>/dev/null || echo 0) >= RESTART_BACKOFF )); then due+=("$s"); fi
    done
    if [[ ${#due[@]} -gt 0 ]]; then
      for s in "${due[@]}"; do now >"$STATE/restart.$s"; done
      log INFO START "starting ${due[*]}$([[ "$cold" == 1 ]] && echo ' (cold start: every prerequisite verified first)')"
      if ! start_services "${due[@]}"; then
        set_state waiting "could not start ${due[*]}"; return 0
      fi
      if [[ "$cold" == 1 ]]; then
        if ! verify_started; then
          refresh 0 || true
          quarantine 1 "POST-START: the enforce-mode isolation/DNS checks failed after the set was started by the watchdog"
          return 1
        fi
        log INFO STARTED "the supervised set runs and passed the enforce-mode isolation and DNS checks"
      fi
      # ... and the runtime invariants (attachments, resolver state) are judged on what really runs now
      if refresh 0; then
        crit_latch=(); problems_now
        for f in "${FINDINGS[@]}"; do
          IFS='|' read -r level latch id msg <<<"$f"
          [[ "$level" == CRIT && "$latch" == 1 ]] && crit_latch+=("$id $msg")
        done
        if [[ ${#crit_latch[@]} -gt 0 ]]; then quarantine 1 "$(summarise "${crit_latch[@]}")"; return 1; fi
        if [[ ${#PROBLEMS[@]} -gt 0 ]]; then quarantine 0 "$(summarise "${PROBLEMS[@]}")"; note_waiting "$(summarise "${PROBLEMS[@]}")"; return 1; fi
      fi
    fi
  fi
  set_state ok "$(( ${#SUPERVISED_ALL[@]} - ${#MISSING[@]} ))/${#SUPERVISED_ALL[@]} supervised services running"
  return 0
}

cycle() { # one pass; 0 healthy/idle/waiting/paused, 1 acted on a violation (even if it healed), 2 unverified
  local lockrc=0 rc=0
  ACTED=0
  beat
  if [[ ! -f "$CONTRACT" ]]; then set_state idle "no release has been committed"; return 0; fi
  take_deploy_lock || lockrc=$?
  if [[ "$lockrc" == 1 ]]; then set_state paused "a deploy is running"; return 0; fi
  [[ "$lockrc" != 2 ]] || log WARN DEPLOY-LOCK "the deploy lock has been held for more than ${MAX_DEPLOY_PAUSE}s: treating the deploy as hung"
  cycle_locked || rc=$?
  drop_deploy_lock
  [[ "$rc" != 0 || "$ACTED" == 0 ]] || rc=1
  return "$rc"
}

# ---- commands --------------------------------------------------------------------------------------------------
hold_deploy_lock_required() { # commit/desired are for remote-deploy.sh, which holds the lock: if we can take it, nobody does
  [[ -e "$DEPLOY_LOCK" ]] || die "$1 is only valid while remote-deploy.sh holds $DEPLOY_LOCK (it does not exist)" 2
  exec {CHK_FD}<"$DEPLOY_LOCK"
  if flock -n "$CHK_FD"; then die "$1 is only valid inside a deploy (the deploy lock is free)" 2; fi
  exec {CHK_FD}<&-
}

cmd_commit() {
  local sha="" rel="" forbidden="" ips="" rootful="" args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --sha) sha="${2:?}"; shift 2 ;; --release-dir) rel="${2:?}"; shift 2 ;;
      --forbidden) forbidden="${2:-}"; shift 2 ;; --protected-ips) ips="${2:-}"; shift 2 ;;
      --rootful) rootful="${2:-}"; shift 2 ;; --) shift; args=("$@"); break ;; *) die "commit: unknown argument $1" 2 ;;
    esac
  done
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || die "commit: --sha must be a 40-hex commit" 2
  [[ -d "$rel" ]] || die "commit: --release-dir is not a directory" 2
  [[ ${#args[@]} -gt 0 ]] || die "commit: compose arguments are required after --" 2
  hold_deploy_lock_required commit
  local dnsv cfg i
  for ((i = 0; i < ${#args[@]}; i++)); do   # the compose project name (-p), as the labels carry it
    if [[ "${args[$i]}" == -p && -n "${args[$((i + 1))]:-}" ]]; then PROJECT="${args[$((i + 1))]}"; fi
  done
  dnsv="$(guard_dns)" || die "commit: $GUARD_CONF has no valid trusted DNS=" 11
  cfg="$( cd "$rel" && RELEASE_SHA="$sha" docker compose "${args[@]}" config --format json 2>/dev/null )" \
    || die "commit: docker compose config failed" 1
  python3 - "$PROJECT" "$sha" "$rel" "$dnsv" "$forbidden" "$ips" "$rootful" "$(daemon_resolvers 2>/dev/null || true)" "$(now)" "$cfg" "${args[@]}" >"$TMP/contract.json" <<'PY' || die "commit: the release cannot be put under containment (see the message above)" 11
import json, sys
project, sha, rel, dns, forbidden, ips, rootful, resolvers, ts, cfg = sys.argv[1:11]
args = sys.argv[11:]
cfg = json.loads(cfg)
nets = cfg.get("networks") or {}
services, bad = {}, []
for name, svc in sorted((cfg.get("services") or {}).items()):
    attached = sorted((svc.get("networks") or {"default": None}).keys())
    out = any(not (nets.get(n) or {}).get("internal", False) for n in attached)
    supervised = out or name.startswith("agent-")
    if supervised and (svc.get("restart") or "no") != "no":
        bad.append("%s renders restart=%s: the Docker daemon would start it after a reboot before the guard is verified (it must be \"no\"; this script starts it)" % (name, svc.get("restart")))
    if (svc.get("network_mode") or "") not in ("",):
        bad.append("%s sets network_mode=%s" % (name, svc["network_mode"]))
    if svc.get("privileged"): bad.append("%s is privileged" % name)
    services[name] = {"networks": attached, "out": out, "supervised": supervised, "dns": list(svc.get("dns") or [])}
if bad:
    print("\n".join("runtime-containment: " + b for b in bad), file=sys.stderr); sys.exit(1)
contract = {"version": 1, "project": project, "release_sha": sha, "release_dir": rel, "compose_args": args,
            "dns": dns, "forbidden_targets": forbidden, "protected_ips": ips, "rootful_targets": rootful,
            "resolver_baseline": resolvers if resolvers else None, "committed": int(ts),
            "networks": {n: {"internal": bool((v or {}).get("internal"))} for n, v in nets.items()},
            "services": services}
json.dump(contract, sys.stdout, indent=1)
PY
  atomic_write "$CONTRACT" <"$TMP/contract.json"
  echo running | atomic_write "$STATE/desired"
  rm -f "$STATE/flaps" "$STATE/last_warn"
  log INFO COMMIT "release $sha is under runtime containment: $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["services"]; print(sum(1 for v in d.values() if v["supervised"]))' "$CONTRACT") supervised services, DNS=$dnsv"
}

cmd_desired() {
  [[ "${1:-}" == running || "${1:-}" == stopped ]] || die "usage: desired running|stopped" 2
  hold_deploy_lock_required desired
  echo "$1" | atomic_write "$STATE/desired"
  log INFO DESIRED "$1"
}

cmd_status() {
  local require=0 hb age state latch="" rc=0
  [[ "${1:-}" == --require-active ]] && require=1
  hb="$(cat "$STATE/heartbeat" 2>/dev/null || echo 0)"; [[ "$hb" =~ ^[0-9]+$ ]] || hb=0
  age=$(( $(now) - hb ))
  state="$(read_file "$STATE/state")"; [[ -f "$STATE/latch" ]] && latch="$(cat "$STATE/latch")"
  echo "state: ${state:-unknown}"
  echo "heartbeat: ${age}s ago"
  echo "desired: $(read_file "$STATE/desired")"
  [[ -z "$latch" ]] || echo "latch: $latch"
  [[ -f "$STATE/last_warn" ]] && echo "warning: $(cat "$STATE/last_warn")"
  if [[ "$require" == 1 ]]; then
    if [[ -n "$latch" ]]; then echo "containment is LATCHED: run 'runtime-containment.sh reset' after investigating" >&2; return 21; fi
    if (( age > HEARTBEAT_MAX_AGE )); then echo "containment watchdog is not running (heartbeat ${age}s old, limit ${HEARTBEAT_MAX_AGE}s)" >&2; return 20; fi
  fi
  return "$rc"
}

cmd_check() {
  local rc=0 f level latch id msg r crit=0 wait=0
  [[ -f "$CONTRACT" ]] || { echo "idle: no release has been committed"; return 0; }
  load_supervised
  collect || rc=$?
  [[ "$rc" == 0 ]] || { echo "UNVERIFIED: Docker cannot be inspected"; return 22; }
  assess
  prereqs "$([[ ${#SUP_IDS[@]} -eq 0 ]] && echo 1 || echo 0)"
  for f in "${FINDINGS[@]}"; do
    IFS='|' read -r level latch id msg <<<"$f"
    printf '%s %s%s: %s\n' "$level" "$id" "$([[ "$latch" == 1 ]] && echo ' (latching)')" "$msg"
    [[ "$level" == CRIT ]] && crit=1
  done
  for r in "${PREREQ[@]}"; do echo "NOT-READY ${r%%|*}: $(cut -d'|' -f2 <<<"$r")"; wait=1; done
  [[ $crit == 1 ]] && return 10
  [[ $wait == 1 ]] && return 11
  echo "ok: ${#SUP_IDS[@]} supervised container(s) running, ${#MISSING[@]} not running"
  return 0
}

cmd_quarantine() {
  local reason="" latch=1
  while [[ $# -gt 0 ]]; do
    case "$1" in --reason) reason="${2:?}"; shift 2 ;; --no-latch) latch=0; shift ;; *) die "quarantine: unknown argument $1" 2 ;; esac
  done
  [[ -n "$reason" ]] || die "quarantine: --reason is required" 2
  [[ -f "$CONTRACT" ]] || { echo "nothing is under containment"; return 0; }
  load_supervised
  collect || { log CRIT UNVERIFIED "quarantine: Docker cannot be inspected"; return 22; }
  assess
  # the dead-man switch must not itself count towards the flap limit
  if [[ "$latch" == 0 ]]; then
    if [[ ${#SUP_IDS[@]} -gt 0 ]]; then stop_ids "${SUP_IDS[@]}"; fi
    log CRIT QUARANTINE "$reason: ${#SUP_IDS[@]} container(s) stopped"
    set_state quarantined "$reason"
  else
    quarantine 1 "$reason"
  fi
}

cmd_reset() {
  local disconnect=0 lockrc=0 rc=0 f level latch id msg bad=0 r
  [[ "${1:-}" == --disconnect-foreign ]] && disconnect=1
  [[ -f "$CONTRACT" ]] || die "reset: nothing is under containment" 2
  take_deploy_lock && lockrc=0 || lockrc=$?
  [[ "$lockrc" != 1 ]] || die "reset: a deploy is running" 4
  trap 'drop_deploy_lock; cleanup' EXIT
  load_supervised
  collect || die "reset: Docker cannot be inspected" 22
  assess
  if [[ "$disconnect" == 1 && ${#ACTIONS[@]} -gt 0 ]]; then do_actions; collect || die "reset: Docker cannot be inspected" 22; assess; fi
  # the stack must be verifiably clean WITH the supervised set stopped: stop it first if the operator left it running
  if [[ ${#SUP_IDS[@]} -gt 0 ]]; then stop_ids "${SUP_IDS[@]}"; collect || die "reset: Docker cannot be inspected" 22; assess; fi
  for f in "${FINDINGS[@]}"; do
    IFS='|' read -r level latch id msg <<<"$f"
    [[ "$level" == CRIT ]] || continue
    # runtime DNS of containers we just stopped is no longer running state; everything else must be clean
    echo "reset refused: $id $msg" >&2; bad=1
  done
  prereqs 1
  for r in "${PREREQ[@]}"; do echo "reset refused: ${r%%|*} $(cut -d'|' -f2 <<<"$r")" >&2; bad=1; done
  [[ "$bad" == 0 ]] || { [[ ${#ACTIONS[@]} -eq 0 ]] || echo "hint: --disconnect-foreign removes the unauthorised endpoints listed above" >&2; return 1; }
  rm -f "$STATE/latch" "$STATE/flaps"
  log INFO RESET "operator reset: latch cleared; the watchdog restarts the supervised set after verifying everything"
  set_state quarantined "reset; waiting for the next cycle"
}

# ---- watch: poll + wake on host/Docker events -----------------------------------------------------------------------
cmd_watch() {
  local fifo="$TMP/events" evpids=() p dead
  [[ "${1:-}" == --interval ]] && { INTERVAL="${2:?}"; shift 2; }
  [[ "$INTERVAL" =~ ^[0-9]+$ && "$INTERVAL" -ge 1 ]] || die "watch: --interval must be a positive number of seconds" 2
  exec 7>"$STATE/watch.lock"
  flock -n 7 || die "watch: another instance is running" 1
  mkfifo "$fifo"; exec 6<>"$fifo"
  start_wakers() {
    evpids=()
    # a Tailscale / DHCP / bridge address or route appearing, and Docker network or container events,
    # run a cycle at once; the interval is only the backstop
    if command -v ip >/dev/null 2>&1; then ( exec ip monitor address route 2>/dev/null ) >&6 & evpids+=("$!"); fi
    ( exec docker events --filter type=network --filter type=container --format '{{.Type}} {{.Action}}' 2>/dev/null ) >&6 & evpids+=("$!")
  }
  # shellcheck disable=SC2317,SC2329  # invoked by the trap
  stop_wakers() { for p in "${evpids[@]:-}"; do [[ -z "$p" ]] || kill "$p" 2>/dev/null || true; done; }
  trap 'stop_wakers; cleanup' EXIT
  notify --ready
  start_wakers
  log INFO WATCH "started (interval ${INTERVAL}s, pid $$)"
  while :; do
    cycle || true
    dead=0; for p in "${evpids[@]:-}"; do [[ -z "$p" ]] || kill -0 "$p" 2>/dev/null || dead=1; done
    [[ "$dead" == 0 ]] || { stop_wakers; start_wakers; }
    # wait for an event or the interval; drain a burst so one change is one cycle
    if read -r -t "$INTERVAL" -u 6 _; then
      while read -r -t 0.5 -u 6 _; do :; done
    fi
  done
}

cmd="${1:-}"; [[ $# -gt 0 ]] && shift
case "$cmd" in
  watch) cmd_watch "$@" ;;
  once) rc=0; cycle || rc=$?; exit "$rc" ;;
  check) cmd_check ;;
  status) cmd_status "$@" ;;
  quarantine) cmd_quarantine "$@" ;;
  reset) cmd_reset "$@" ;;
  commit) cmd_commit "$@" ;;
  desired) cmd_desired "$@" ;;
  *) die "usage: $0 watch|once|check|status|quarantine|reset|commit|desired" 2 ;;
esac
