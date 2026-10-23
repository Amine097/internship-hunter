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
#   runtime-containment.sh commit [--check] --sha S --release-dir D [--forbidden L] [--protected-ips L]
#                         [--rootful L] -- <compose args>       remote-deploy.sh only, under its locks; --check is
#                                                                a read-only pre-flight (could this release be committed?)
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
# ORDER of a quarantine: latch (the durable intent), cut the unauthorised endpoint, stop. Cutting is instant,
# stopping is not; and the latch first means a watchdog that dies half way cannot fail open. A guard whose only
# defect is the SET OF HOST ADDRESSES it names (`host-egress-guard.sh status` exit 3: a rootful Docker bridge came
# or went) is re-applied and verified FIRST - about a second, quicker than a stop - and the set is stopped only if
# that does not hold; an absorbed drift is not a flap.
# LOCKS: deploy.lock is remote-deploy.sh's alone; this script takes state/containment.action.lock, without
# waiting, only when a cycle has something to CHANGE, and observes again after taking it; remote-deploy.sh holds
# it for a whole deploy. A healthy cycle takes no lock.
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
        HUNTER_GUARD_TEST_NSFS_TYPE HUNTER_DNS HUNTER_TEST_MODE DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG \
        HUNTER_CONTAINMENT_DOCKER_TIMEOUT HUNTER_CONTAINMENT_HEARTBEAT_MAX_AGE HUNTER_CONTAINMENT_MAX_DEPLOY_PAUSE \
        HUNTER_CONTAINMENT_RESTART_BACKOFF HUNTER_CONTAINMENT_START_TIMEOUT
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
ACTION_LOCK="$BASE/state/containment.action.lock"
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
# Children never inherit the action lock descriptor: an orphaned or hung child would otherwise keep the lock
# (flock follows the open file description) for as long as it lives, long after this process died.
nolock() { if [[ -n "${ACT_FD:-}" && "$ACT_FD" != none ]]; then "$@" {ACT_FD}<&-; else "$@"; fi; }
docker() { nolock timeout "$DOCKER_TIMEOUT" docker "$@"; }

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
#   A disconnect <network id> <container id> <what> <owner project|foreign>
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
def act(netid, cid, what, owner): out.append("A\tdisconnect\t%s\t%s\t%s\t%s" % (netid, cid, what, owner))
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
                act(n["Id"], cid, "foreign container %s on %s" % (name, n["Name"]), "foreign")
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
            act(ep.get("NetworkID", nname), cid, "%s on foreign network %s" % (name, nname), "project")
            continue
        logical = (n.get("Labels") or {}).get(LN)
        logical_now.add(logical)
        if logical not in svc["networks"]:
            find("CRIT", 1, "ATTACH-UNEXPECTED", "%s (%s) is attached to %s, but the release declares only %s" % (name, svc_name, n["Name"], sorted(svc["networks"])))
            act(n["Id"], cid, "%s on %s" % (name, n["Name"]), "project")
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
  local facts rec kind a b c d e resolvers have_res=1
  FINDINGS=(); ACTIONS=(); SUP_IDS=(); MISSING=()
  resolvers="$(daemon_resolvers 2>/dev/null)" || have_res=0
  facts="$(GUARD_DNS_NOW="$(guard_dns 2>/dev/null || true)" RESOLVERS_NOW="$resolvers" HAVE_RES="$have_res" python3 -c '
import json, os
print(json.dumps({"guard_dns": os.environ["GUARD_DNS_NOW"] or None,
                  "resolvers": os.environ["RESOLVERS_NOW"] if os.environ["HAVE_RES"] == "1" else None}))')"
  rec="$(python3 -c "$ASSESS" "$CONTRACT" "$TMP/containers.json" "$TMP/networks.json" "$facts")" \
    || { FINDINGS+=("CRIT|0|UNVERIFIED|the assessor failed: nothing is certified"); return; }
  while IFS=$'\t' read -r kind a b c d e; do
    case "$kind" in
      F) FINDINGS+=("$a|$b|$c|$d") ;;
      A) ACTIONS+=("$b|$c|$d|$e") ;;
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
  ( cd "$rel" && RELEASE_SHA="$(contract_get release_sha)" SMOKE_DNS_CONFIG_ONLY=1 SMOKE_DNS_EXPECT="$1" nolock "$DNS_CHECK" "${args[@]}" )
}
prereqs() { # prereqs <with_targets 0|1>: what the HOST must provide; PREREQ gets one entry per missing thing
  local with_targets="$1" out dnsexp f grc
  PREREQ=()
  for f in "$GUARD" "$ISOLATION_CHECK" "$DNS_CHECK"; do
    trusted_exec "$f" || PREREQ+=("TRUST $f is missing, not a regular executable, or writable by others")
  done
  trusted_file "$GUARD_CONF" || PREREQ+=("TRUST $GUARD_CONF is missing or untrusted")
  trusted_file "$ISOLATION_CONF" || PREREQ+=("TRUST $ISOLATION_CONF is missing or untrusted")
  [[ ${#PREREQ[@]} -eq 0 ]] || return 0
  grc=0; out="$(nolock "$GUARD" status 2>&1)" || grc=$?
  if [[ "$grc" == 3 ]]; then
    # the policy is intact except for the set of host addresses it names (a rootful bridge came or went, an
    # interface got an address): repairable in a second by `apply`, no need to stop anything first
    PREREQ+=("GUARD-ADDR host-egress-guard.sh status: $(tr '\n' ' ' <<<"$out" | cut -c1-300)")
  elif [[ "$grc" != 0 ]]; then
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
                SMOKE_EXPECT_ROOTLESS=1 nolock "$ISOLATION_CHECK" --verify-targets 2>&1)"; then
      PREREQ+=("TARGETS protected host addresses are not live yet (Tailscale late?): $(tr '\n' ' ' <<<"$out" | cut -c1-240)")
    fi
  fi
}

# ---- actions -----------------------------------------------------------------------------------------------------
# ORDER (docs/deployment.md, "Runtime containment"): (1) record the intent durably, (2) cut the hostile route,
# (3) stop. Cutting a route is instant (`network disconnect -f`); stopping a container is not (SIGTERM, up to a
# 5 s grace): a stop-first order keeps the hostile endpoint alive for the whole shutdown. The intent is recorded
# first so that a crash anywhere below cannot fail open: the next cycle sees the latch and finishes the job even
# though the evidence (the extra endpoint) is already gone.
stop_ids() { # stop_ids <ids...>
  [[ $# -gt 0 ]] || return 0
  docker stop -t 5 "$@" >/dev/null 2>&1 || { log CRIT STOP-FAILED "docker stop failed for $# container(s): killing"; docker kill "$@" >/dev/null 2>&1 || true; }
}
do_actions() { # remove every unauthorised endpoint; a failure is retried once, then the container is killed if it is ours
  local a netid cid what owner failed=0
  for a in "${ACTIONS[@]}"; do
    IFS='|' read -r netid cid what owner <<<"$a"
    if docker network disconnect -f "$netid" "$cid" >/dev/null 2>&1 \
       || { sleep 0.5; docker network disconnect -f "$netid" "$cid" >/dev/null 2>&1; }; then
      log CRIT DISCONNECTED "$what"
    else
      failed=1
      log CRIT DISCONNECT-FAILED "$what"
      if [[ "$owner" == project ]]; then
        # the route cannot be removed and the container is ours: it must not keep running with it
        docker kill "$cid" >/dev/null 2>&1 && log CRIT KILLED "container with an unremovable unauthorised endpoint: $what"
      fi
    fi
  done
  return "$failed"
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
quarantine() { # quarantine <latch 0|1> <reason>: latch (if any), cut hostile endpoints, then stop the supervised set
  local latch="$1" reason="$2" cut=0
  ACTED=1
  if [[ "$latch" == 1 ]]; then latch_set "$reason"; fi           # 1. intent first: a crash below must not fail open
  do_actions || cut=1                                            # 2. the hostile routes go first
  [[ ${#ACTIONS[@]} -gt 0 ]] && ACTIONS=()                       #    (done: the latched branch must not redo them)
  if [[ ${#SUP_IDS[@]} -gt 0 ]]; then stop_ids "${SUP_IDS[@]}"; fi     # 3. then the set
  if [[ "$latch" == 1 ]]; then
    log CRIT LATCHED "$reason: ${#SUP_IDS[@]} container(s) stopped$([[ "$cut" == 1 ]] && echo ', an unauthorised endpoint could NOT be removed'); stays stopped until 'runtime-containment.sh reset'"
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
guard_apply_verified() { # re-apply the guard (idempotent; the daemon's own ExecStartPost call) and verify the FULL policy
  # The host can change its addresses again between the apply and the verification (a rootful Docker bridge
  # created and removed in quick succession): status exit 3 right after an apply is another address-only drift,
  # not a failed repair, so apply again (a few times); anything else is a failure.
  local out attempt rc
  for attempt in 1 2 3 4; do
    if ! out="$(nolock "$GUARD" apply --wait 20 2>&1)"; then
      log CRIT GUARD-APPLY-FAILED "host-egress-guard.sh apply: $(tr '\n' ' ' <<<"$out" | cut -c1-300)"; return 1
    fi
    rc=0; out="$(nolock "$GUARD" status 2>&1)" || rc=$?
    [[ "$rc" == 0 ]] && return 0
    [[ "$rc" == 3 ]] && continue
    log CRIT GUARD-VERIFY-FAILED "host-egress-guard.sh status after apply: $(tr '\n' ' ' <<<"$out" | cut -c1-300)"; return 1
  done
  log CRIT GUARD-VERIFY-FAILED "the host address set kept changing during $attempt apply attempts: $(tr '\n' ' ' <<<"$out" | cut -c1-200)"
  return 1
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
               SMOKE_PROTECTED_IPS="$ips" SMOKE_ROOTFUL_TARGETS="$rootful" nolock "$ISOLATION_CHECK" "${args[@]}" 2>&1 )"; then
    echo "$out" >&2; return 1
  fi
  if ! out="$( cd "$rel" && SMOKE_HOST_ISOLATION=enforce SMOKE_DNS_EXPECT="$dnsexp" nolock "$DNS_CHECK" "${args[@]}" 2>&1 )"; then
    echo "$out" >&2; return 1
  fi
}

# ---- one cycle ----------------------------------------------------------------------------------------------------
# LOCKING. Two locks, two jobs:
#   state/deploy.lock          held by remote-deploy.sh for the whole of a deploy (flock -n: one deploy at a time).
#                              The watchdog NEVER takes it, so a legitimate deploy cannot be refused because a
#                              check cycle happens to be running (it was: 87% of attempts in a measured run).
#   state/containment.action.lock   the right to CHANGE the stack (stop, disconnect, start, re-apply the guard,
#                              latch). The watchdog takes it only when a cycle has something to change, and only
#                              without waiting; remote-deploy.sh takes it (waiting) for the whole of a deploy. A
#                              watchdog action and a deploy therefore never overlap, and a healthy cycle - the
#                              overwhelmingly common one - takes no lock at all.
# A cycle first OBSERVES (read-only). When it decides to act it takes the action lock and observes AGAIN: what it
# decided on may be a deploy ago. If the lock is busy the cycle yields ("paused"); a lock older than
# MAX_DEPLOY_PAUSE is a hung deploy and does not disable containment.
ACT_FD=""
need_lock() { # 0: the action lock is ours and the snapshot is fresh; 99: just taken, observe again; 98: busy, yield
  [[ -n "$ACT_FD" ]] && return 0
  [[ -e "$ACTION_LOCK" ]] || { mkdir -p "$(dirname "$ACTION_LOCK")"; : >>"$ACTION_LOCK"; }
  exec {ACT_FD}<"$ACTION_LOCK"
  if flock -n "$ACT_FD"; then return 99; fi
  exec {ACT_FD}<&-; ACT_FD=""
  local age=$(( $(now) - $(stat -c %Y "$ACTION_LOCK" 2>/dev/null || now) ))
  if (( age > MAX_DEPLOY_PAUSE )); then
    log WARN DEPLOY-LOCK "the action lock has been held for more than ${MAX_DEPLOY_PAUSE}s: treating the deploy as hung and acting without it"
    ACT_FD=none
    return 99
  fi
  return 98
}
drop_lock() { [[ -z "$ACT_FD" || "$ACT_FD" == none ]] || exec {ACT_FD}<&-; ACT_FD=""; }

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

cycle_pass() { # one pass; 0 healthy/waiting, 1 acted on a violation, 2 unverified, 98 busy (yield), 99 observe again
  local desired latched f level latch id msg warns=() crit_latch=() r s cold due=() rc=0 addr_only
  desired="$(read_file "$STATE/desired")"; latched=0; [[ -f "$STATE/latch" ]] && latched=1
  load_supervised
  collect || rc=$?
  if [[ "$rc" != 0 ]]; then
    log CRIT UNVERIFIED "Docker cannot be inspected (rc=$rc): no invariant can be certified"
    set_state unverified "docker unavailable"
    return 2
  fi
  assess
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
  # Integrity first, BEFORE the (slower) prerequisite checks: a hostile endpoint is acted on at once.
  # 1. a latch stays until an operator resets it, whatever else is true
  if [[ "$latched" == 1 ]]; then
    if [[ ${#SUP_IDS[@]} -gt 0 || ${#ACTIONS[@]} -gt 0 ]]; then
      need_lock || return $?
      ACTED=1
      do_actions || true                                        # the route first,
      ACTIONS=()
      if [[ ${#SUP_IDS[@]} -gt 0 ]]; then stop_ids "${SUP_IDS[@]}"; fi     # then the set
      log CRIT LATCHED "the latch is set and supervised containers were running or an unauthorised endpoint was present: acted again"
    fi
    set_state latched "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["reason"])' "$STATE/latch" 2>/dev/null || echo unknown)"
    return 1
  fi
  # 2. integrity events: latch, cut the endpoint, stop, in that order
  if [[ ${#crit_latch[@]} -gt 0 ]]; then
    need_lock || return $?
    quarantine 1 "$(summarise "${crit_latch[@]}")"
    return 1
  fi
  # 3. nothing may run that no deploy committed
  if [[ "$desired" != running ]]; then
    if [[ ${#SUP_IDS[@]} -gt 0 ]]; then
      need_lock || return $?
      quarantine 1 "DESIRED: supervised containers run but the last deploy did not leave the stack running (desired='${desired:-unset}')"
      return 1
    fi
    set_state stopped "desired state is '${desired:-unset}'"
    return 0
  fi
  # 4. prerequisites (guard, DNS, protected addresses) and soft findings
  prereqs "$([[ ${#SUP_IDS[@]} -eq 0 ]] && echo 1 || echo 0)"
  problems_now
  if [[ ${#PROBLEMS[@]} -gt 0 ]]; then
    local acted=0 only_guard=0 repaired=0
    addr_only=0
    [[ ${#PROBLEMS[@]} -eq 1 && "${PROBLEMS[0]}" == GUARD-ADDR\ * ]] && addr_only=1
    [[ ${#PROBLEMS[@]} -eq 1 && "${PROBLEMS[0]}" == GUARD\ * ]] && only_guard=1
    # The only difference is the set of host addresses the guard names: a rootful Docker bridge or an interface
    # address came or went. `apply` fixes it in about a second - quicker than `docker stop`'s own grace period -
    # so stopping the set first would add an outage without closing the gap any sooner. Repair and verify
    # FIRST; stop only if the repair does not hold. A repaired drift is not a flap. The host may move again
    # while we look (a refresh takes seconds): a fresh address-only drift is repaired again, a few times.
    local round=0
    while [[ "$addr_only" == 1 ]]; do
      need_lock || return $?
      if (( round++ >= 3 )); then
        log CRIT GUARD-UNREPAIRABLE "the host address set keeps changing: stopping the supervised set"
        only_guard=1; break
      fi
      if guard_apply_verified; then
        log INFO GUARD-ADDRESS-ABSORBED "host address set changed; host-egress-guard.sh apply updated the policy ($(tr '\n' ' ' <<<"${PROBLEMS[0]#GUARD-ADDR }" | cut -c1-160))"
        repaired=1
        refresh "$([[ ${#SUP_IDS[@]} -eq 0 ]] && echo 1 || echo 0)" || { set_state unverified "docker unavailable"; return 2; }
        problems_now
        addr_only=0
        [[ ${#PROBLEMS[@]} -eq 1 && "${PROBLEMS[0]}" == GUARD-ADDR\ * ]] && addr_only=1
      else
        log CRIT GUARD-UNREPAIRABLE "host address drift could not be absorbed by host-egress-guard.sh apply: stopping the supervised set"
        only_guard=1; break
      fi
    done
    if [[ ${#PROBLEMS[@]} -gt 0 ]]; then
      # a structural guard problem, a missing prerequisite, a soft finding: stop what runs, repair what can be repaired
      need_lock || return $?
      if [[ ${#SUP_IDS[@]} -gt 0 ]]; then quarantine 0 "$(summarise "${PROBLEMS[@]}")"; acted=1; fi
      if [[ "$acted" == 1 && ( "$(read_file "$STATE/state")" == latched* ) ]]; then return 1; fi   # the flap limit just latched
      if [[ "$only_guard" == 1 && "$repaired" == 0 ]]; then
        if guard_apply_verified; then
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
  fi
  rm -f "$STATE/last_waiting"
  # 5. everything holds: make the set whole again
  if [[ ${#MISSING[@]} -gt 0 ]]; then
    cold=0; [[ ${#SUP_IDS[@]} -eq 0 ]] && cold=1
    for s in "${MISSING[@]}"; do
      if [[ "$cold" == 1 ]] || (( $(now) - $(cat "$STATE/restart.$s" 2>/dev/null || echo 0) >= RESTART_BACKOFF )); then due+=("$s"); fi
    done
    if [[ ${#due[@]} -gt 0 ]]; then
      need_lock || return $?
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

cycle() { # one cycle; 0 healthy/idle/waiting/paused, 1 acted on a violation (even if it healed), 2 unverified
  local rc=0 pass=0
  ACTED=0
  beat
  if [[ ! -f "$CONTRACT" ]]; then set_state idle "no release has been committed"; return 0; fi
  while :; do
    rc=0; cycle_pass || rc=$?
    if [[ "$rc" == 99 && "$pass" == 0 ]]; then pass=1; continue; fi     # the lock was just taken: decide on a FRESH snapshot
    break
  done
  if [[ "$rc" == 98 ]]; then set_state paused "a deploy (or an operator command) holds the action lock"; rc=0; fi
  [[ "$rc" != 99 ]] || rc=2                                          # cannot happen (the lock is held on the second pass)
  drop_lock
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
  local sha="" rel="" forbidden="" ips="" rootful="" check=0 args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --check) check=1; shift ;;      # read-only pre-flight: could this release be committed? (no lock, nothing written)
      --sha) sha="${2:?}"; shift 2 ;; --release-dir) rel="${2:?}"; shift 2 ;;
      --forbidden) forbidden="${2:-}"; shift 2 ;; --protected-ips) ips="${2:-}"; shift 2 ;;
      --rootful) rootful="${2:-}"; shift 2 ;; --) shift; args=("$@"); break ;; *) die "commit: unknown argument $1" 2 ;;
    esac
  done
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || die "commit: --sha must be a 40-hex commit" 2
  [[ -d "$rel" ]] || die "commit: --release-dir is not a directory" 2
  [[ ${#args[@]} -gt 0 ]] || die "commit: compose arguments are required after --" 2
  [[ "$check" == 1 ]] || hold_deploy_lock_required commit
  local dnsv cfg i
  for ((i = 0; i < ${#args[@]}; i++)); do   # the compose project name (-p), as the labels carry it
    if [[ "${args[$i]}" == -p && -n "${args[$((i + 1))]:-}" ]]; then PROJECT="${args[$((i + 1))]}"; fi
  done
  if [[ "$check" == 1 ]]; then dnsv="$(guard_dns 2>/dev/null || true)"
  else dnsv="$(guard_dns)" || die "commit: $GUARD_CONF has no valid trusted DNS=" 11; fi
  cfg="$( cd "$rel" && RELEASE_SHA="$sha" docker compose "${args[@]}" config --format json 2>/dev/null )" \
    || die "commit: docker compose config failed" 1
  python3 - "$PROJECT" "$sha" "$rel" "$dnsv" "$forbidden" "$ips" "$rootful" "$(daemon_resolvers 2>/dev/null || true)" "$(now)" "$cfg" "$check" "${args[@]}" >"$TMP/contract.json" <<'PY' || die "commit: the release cannot be put under containment (see the message above)" 11
import json, sys
project, sha, rel, dns, forbidden, ips, rootful, resolvers, ts, cfg, check = sys.argv[1:12]
args = sys.argv[12:]
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
if check == "1":
    sys.exit(0)                      # pre-flight only: the release is committable
contract = {"version": 1, "project": project, "release_sha": sha, "release_dir": rel, "compose_args": args,
            "dns": dns, "forbidden_targets": forbidden, "protected_ips": ips, "rootful_targets": rootful,
            "resolver_baseline": resolvers if resolvers else None, "committed": int(ts),
            "networks": {n: {"internal": bool((v or {}).get("internal"))} for n, v in nets.items()},
            "services": services}
json.dump(contract, sys.stdout, indent=1)
PY
  if [[ "$check" == 1 ]]; then echo "ok: release $sha can be put under runtime containment"; return 0; fi
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
    do_actions || true
    if [[ ${#SUP_IDS[@]} -gt 0 ]]; then stop_ids "${SUP_IDS[@]}"; fi
    log CRIT QUARANTINE "$reason: ${#SUP_IDS[@]} container(s) stopped"
    set_state quarantined "$reason"
  else
    quarantine 1 "$reason"
  fi
}

cmd_reset() {
  local disconnect=0 f level latch id msg bad=0 r
  [[ "${1:-}" == --disconnect-foreign ]] && disconnect=1
  [[ -f "$CONTRACT" ]] || die "reset: nothing is under containment" 2
  [[ -e "$ACTION_LOCK" ]] || { mkdir -p "$(dirname "$ACTION_LOCK")"; : >>"$ACTION_LOCK"; }
  exec {ACT_FD}<"$ACTION_LOCK"
  flock -w 30 "$ACT_FD" || die "reset: the action lock is held (a deploy is running, or the watchdog is stopping/starting the stack); retry in a minute" 4
  trap 'drop_lock; cleanup' EXIT
  load_supervised
  collect || die "reset: Docker cannot be inspected" 22
  assess
  if [[ "$disconnect" == 1 && ${#ACTIONS[@]} -gt 0 ]]; then do_actions || true; collect || die "reset: Docker cannot be inspected" 22; assess; fi
  # the stack must be verifiably clean WITH the supervised set stopped: stop it first if the operator left it running
  if [[ ${#SUP_IDS[@]} -gt 0 ]]; then stop_ids "${SUP_IDS[@]}"; collect || die "reset: Docker cannot be inspected" 22; assess; fi
  for f in "${FINDINGS[@]}"; do
    IFS='|' read -r level latch id msg <<<"$f"
    [[ "$level" == CRIT ]] || continue
    # runtime DNS of containers we just stopped is no longer running state; everything else must be clean
    echo "reset refused: $id $msg" >&2; bad=1
  done
  prereqs 1
  for r in "${PREREQ[@]}"; do echo "reset refused: $r" >&2; bad=1; done
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
    ( exec docker events --filter type=network --filter type=container \
        --filter event=create --filter event=start --filter event=die --filter event=destroy \
        --filter event=connect --filter event=disconnect --format '{{.Type}} {{.Action}}' 2>/dev/null ) >&6 & evpids+=("$!")
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
