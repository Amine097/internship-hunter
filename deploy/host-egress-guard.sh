#!/usr/bin/env bash
# Host-level egress guard for the ROOTLESS Docker daemon that runs Internship Hunter.
#
#   host-egress-guard.sh plan   [--dns IP[,IP]] [--protect CIDR[,CIDR]]   print, change nothing
#   host-egress-guard.sh apply  [--dns IP[,IP]] [--protect CIDR[,CIDR]] [--wait SECONDS]
#   host-egress-guard.sh status [--dns IP[,IP]] [--protect CIDR[,CIDR]]   exit 0 only if the FULL
#                                                    policy is installed and unmodified
#   host-egress-guard.sh remove                                            fully reversible
#
# THE PROBLEM. Containers on a non-internal network (the three egress proxies, discovery,
# telegram, api) leave through the rootless daemon's user-space NAT (slirp4netns / pasta). That
# NAT opens its sockets from the HOST's network namespace, so a container can dial any address
# the host owns - its Tailscale IP (sshd on :22), a rootful container's published port - and
# no host firewall (UFW/nftables FORWARD) ever sees a forwarded packet. Hostname filtering in the
# proxy (tinyproxy ACLs) is application level and is not a network boundary.
#
# WHAT THIS DOES. It enters ONLY the rootless daemon's own network namespace (the user owns it;
# it is not the host's) and adds three small chains there:
#   HUNTER-EGRESS-GUARD     in DOCKER-USER  (forwarded traffic), for packets entering from a
#                           Docker bridge (br-*, docker0: every compose network AND any ad-hoc
#                           `docker run`): established replies pass; traffic that stays on a
#                           Docker bridge is left to Docker's own isolation rules; DNS to the
#                           namespace's resolver passes; everything else addressed to non-global
#                           space (RFC1918, 100.64.0.0/10 = Tailscale, loopback, link-local, ...),
#                           to an address of THIS HOST (any interface, rootful bridges included)
#                           or to the host's default gateway is rejected. Public destinations
#                           are untouched, so CONNECT to the providers works.
#   HUNTER-EGRESS-GUARD-IN  in INPUT: containers may not open NEW connections to the daemon
#                           namespace itself (bridge gateway, docker-proxy listeners).
#   HUNTER-EGRESS-GUARD6    in the IPv6 FORWARD chain: NEW forwarded IPv6 is rejected, and
#   HUNTER-EGRESS-GUARD6-IN in the IPv6 INPUT chain: NEW IPv6 to the namespace itself (ICMPv6 kept).
#
# `status` does not just look for the jump rules: it renders the expected policy into scratch
# chains, lets the kernel canonicalise it, and compares chain contents, the position of the jump
# rules (they must be FIRST in DOCKER-USER, INPUT and the IPv6 FORWARD chain) and that Docker's
# own jump into DOCKER-USER is still first in FORWARD. Any missing, extra, reordered or edited
# rule, or an address of this host the policy does not know yet, makes it fail.
#
# WHAT IT NEVER TOUCHES: the host's iptables/nftables/UFW, sshd, Tailscale, Gluetun and the
# rootful daemon's containers (a different daemon in a different namespace). It refuses to run as
# root and refuses a target namespace equal to the host's, or one that is not this user's
# rootless Docker daemon. The rules vanish when the daemon restarts (new namespace): re-apply
# from an ExecStartPost drop-in (docs/deployment.md).
#
# Optional persistent parameters: host-egress-guard.conf NEXT TO THIS SCRIPT (root-owned, not
# group/world-writable), lines `DNS=ip[,ip]` and `PROTECT=cidr[,cidr]`; command-line options win.
set -Eeuo pipefail

TEST_MODE="${HUNTER_GUARD_TEST_MODE:-0}"
PROC=/proc
if [[ "$TEST_MODE" == 1 ]]; then
  PROC="${HUNTER_GUARD_PROC:-/proc}"
  echo "host-egress-guard: WARNING test mode: process table is '$PROC'" >&2
else
  [[ -z "${HUNTER_GUARD_PROC:-}" ]] \
    || { echo "host-egress-guard: HUNTER_GUARD_PROC is only honoured with HUNTER_GUARD_TEST_MODE=1" >&2; exit 1; }
  PATH=/usr/sbin:/usr/bin:/sbin:/bin     # never resolve iptables/nsenter through a caller's PATH
fi

BRIDGES=("br-+" "docker0")               # Docker's user-defined bridges and its default bridge
CHAIN="HUNTER-EGRESS-GUARD"
CHAIN_IN="HUNTER-EGRESS-GUARD-IN"
CHAIN6="HUNTER-EGRESS-GUARD6"
CHAIN6_IN="HUNTER-EGRESS-GUARD6-IN"
# Destinations that are never "the public Internet" (IANA special-purpose + multicast/reserved)
NON_GLOBAL=(0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12
            192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24
            203.0.113.0/24 224.0.0.0/4 240.0.0.0/4)
SUFFIX=""                                # "-X" while rendering the scratch copy used by `status`

die() { echo "host-egress-guard: $*" >&2; exit 1; }
note() { echo "host-egress-guard: $*"; }

cmd="${1:-}"; [[ $# -gt 0 ]] && shift
DNS_ARG=""; PROTECT_ARG=""; WAIT=60
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dns) DNS_ARG="${2:?--dns needs a value}"; shift 2 ;;
    --protect) PROTECT_ARG="${2:?--protect needs a value}"; shift 2 ;;
    --wait) WAIT="${2:?--wait needs a value}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ "$WAIT" =~ ^[0-9]+$ ]] || die "--wait must be a number of seconds"
case "$cmd" in plan|apply|status|remove) ;; *) die "usage: $0 plan|apply|status|remove [--dns IP,..] [--protect CIDR,..] [--wait S]" ;; esac

MYUID="$(id -u)"
[[ "$MYUID" != 0 ]] || die "refusing to run as root: run as the user that owns the rootless Docker daemon"

cidr_ok() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$ ]]; }

# ---- optional persistent parameters ---------------------------------------------------------
CONF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/host-egress-guard.conf"
if [[ -e "$CONF" ]]; then
  read -r cowner cmode < <(stat -c '%u %a' "$CONF")
  want_owner=0; [[ "$TEST_MODE" == 1 ]] && want_owner="$MYUID"
  if [[ "$cowner" != "$want_owner" ]] || (( (8#$cmode & 8#022) != 0 )); then
    die "$CONF must be owned by uid $want_owner and not group/world-writable"
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      ''|'#'*) ;;
      DNS=*) [[ -n "$DNS_ARG" ]] || DNS_ARG="${line#DNS=}" ;;
      PROTECT=*) [[ -n "$PROTECT_ARG" ]] || PROTECT_ARG="${line#PROTECT=}" ;;
      *) die "unknown line in $CONF: $line" ;;
    esac
  done <"$CONF"
fi

# ---- locate the rootless daemon's namespace, and prove it is THIS user's rootless daemon -------
RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$MYUID}"
STATE_DIR="$RUNTIME_DIR/dockerd-rootless"
PIDFILE="$STATE_DIR/child_pid"
[[ -r "$PIDFILE" ]] || die "no rootless Docker daemon found ($PIDFILE missing): is it running as this user?"
[[ "$(stat -c %u "$PIDFILE")" == "$MYUID" ]] || die "$PIDFILE is not owned by uid $MYUID"
PID="$(<"$PIDFILE")"
[[ "$PID" =~ ^[0-9]+$ ]] || die "malformed $PIDFILE"
[[ -d "$PROC/$PID" ]] || die "process $PID is gone (stale $PIDFILE)"
[[ "$(stat -c %u "$PROC/$PID")" == "$MYUID" ]] || die "process $PID is not owned by uid $MYUID"
tr '\0' ' ' <"$PROC/$PID/cmdline" 2>/dev/null | grep -Eq '(dockerd|rootlesskit)' \
  || die "process $PID is not a Docker daemon / rootlesskit process"
awk -v u="$MYUID" '$2 == u {f=1} END {exit !f}' "$PROC/$PID/uid_map" 2>/dev/null \
  || die "process $PID does not run in a user namespace mapped to uid $MYUID (not rootless Docker)"
[[ "$(readlink "$PROC/$PID/ns/user" 2>/dev/null)" != "$(readlink "$PROC/self/ns/user")" ]] \
  || die "process $PID shares this user namespace: not a rootless daemon"
target_ns="$(readlink "$PROC/$PID/ns/net" 2>/dev/null)" || die "process $PID has no network namespace"
own_ns="$(readlink "$PROC/self/ns/net")"
[[ "$target_ns" != "$own_ns" ]] \
  || die "process $PID is in the HOST network namespace: refusing (this tool must never edit the host's firewall)"
[[ -S "$RUNTIME_DIR/docker.sock" ]] || die "no rootless Docker socket at $RUNTIME_DIR/docker.sock"
NS=(nsenter --preserve-credentials -U -n -t "$PID" --)
ipt() { "${NS[@]}" iptables -w 5 "$@"; }
ipt6() { "${NS[@]}" ip6tables -w 5 "$@"; }

# ---- resolver(s) the containers' DNS queries are forwarded to (must stay reachable) ----------
detect_dns() {
  if [[ -n "$DNS_ARG" ]]; then tr ',' '\n' <<<"$DNS_ARG"; return; fi
  awk '$1 == "nameserver" {print $2}' "$PROC/$PID/root/etc/resolv.conf" 2>/dev/null || true
}
mapfile -t DNS < <(detect_dns | awk 'NF && $0 !~ /^127\./ && $0 !~ /:/')
for d in "${DNS[@]}"; do cidr_ok "$d" && [[ "$d" != */* ]] || die "invalid DNS address: $d"; done
[[ ${#DNS[@]} -gt 0 || "$cmd" == remove ]] \
  || die "no usable DNS resolver found in the daemon namespace: pass --dns <ip> (see docs/deployment.md)"

# ---- addresses of THIS host (the thing being protected), read from the host namespace --------
# Every global IPv4 address on every interface - rootful Docker bridges (docker0, br-*) included,
# because rootful containers' published ports listen there - and the default gateway(s).
host_addrs() {
  ip -4 -o addr show scope global 2>/dev/null | awk '{split($4, a, "/"); print a[1]"/32"}' || true
  ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "via") print $(i + 1)"/32"}' || true
}
mapfile -t EXTRA < <(tr ',' '\n' <<<"$PROTECT_ARG" | awk 'NF')
for c in "${EXTRA[@]}"; do cidr_ok "$c" || die "invalid --protect CIDR: $c"; done
mapfile -t HOSTS < <(host_addrs | sort -u)

render_v4() { # iptables-restore --noflush input; redefining a chain replaces it atomically
  local c="$CHAIN$SUFFIX" ci="$CHAIN_IN$SUFFIX" h n b d
  echo "*filter"
  echo ":$c - [0:0]"
  echo ":$ci - [0:0]"
  echo "-F $c"                        # explicit: do not rely on how the backend treats a redeclared chain
  echo "-F $ci"
  echo "-A $c -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
  # container-to-container: with br_netfilter, traffic that never leaves a bridge also traverses
  # FORWARD, and the peers' addresses are in 172.16/12. Docker's own rules police that traffic.
  for b in "${BRIDGES[@]}"; do echo "-A $c -o $b -j RETURN"; done
  for d in "${DNS[@]}"; do
    echo "-A $c -d $d/32 -p udp --dport 53 -j RETURN"
    echo "-A $c -d $d/32 -p tcp --dport 53 -j RETURN"
  done
  for h in "${HOSTS[@]}" "${EXTRA[@]}"; do
    [[ "$h" == */* ]] || h="$h/32"
    echo "-A $c -d $h -j REJECT --reject-with icmp-admin-prohibited"
  done
  for n in "${NON_GLOBAL[@]}"; do
    echo "-A $c -d $n -j REJECT --reject-with icmp-admin-prohibited"
  done
  echo "-A $c -j RETURN"
  echo "-A $ci -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
  echo "-A $ci -j REJECT --reject-with icmp-admin-prohibited"
  echo "COMMIT"
}
render_v6() {
  local c="$CHAIN6$SUFFIX" ci="$CHAIN6_IN$SUFFIX"
  echo "*filter"
  echo ":$c - [0:0]"
  echo ":$ci - [0:0]"
  echo "-F $c"
  echo "-F $ci"
  echo "-A $c -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
  echo "-A $c -j REJECT --reject-with icmp6-adm-prohibited"
  # to the daemon namespace itself (INPUT): neighbour discovery and friends must keep working,
  # everything else NEW is rejected. Containers are IPv4-only; this is for the day one is not.
  echo "-A $ci -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
  echo "-A $ci -p ipv6-icmp -j RETURN"
  echo "-A $ci -j REJECT --reject-with icmp6-adm-prohibited"
  echo "COMMIT"
}

do_plan() {
  cat <<EOF
# target: rootless daemon namespace of pid $PID ($target_ns); host namespace is $own_ns
# DNS exceptions (port 53 only): ${DNS[*]}
# host addresses protected: ${HOSTS[*]:-none found} ${EXTRA[*]:-}
# commands (run via: ${NS[*]}):
#   iptables-restore --noflush      <  the ruleset below
#   iptables -I DOCKER-USER 1 -i <${BRIDGES[*]}> -j $CHAIN
#   iptables -I INPUT 1       -i <${BRIDGES[*]}> -j $CHAIN_IN
#   ip6tables-restore --noflush     <  the IPv6 ruleset (required: apply/status fail without ip6tables)
#   ip6tables -I FORWARD 1    -i <${BRIDGES[*]}> -j $CHAIN6
#   ip6tables -I INPUT 1      -i <${BRIDGES[*]}> -j $CHAIN6_IN
EOF
  render_v4
  echo "# --- IPv6"
  render_v6
}

jumps_first() { # jumps_first <fn> <chain> <target>: our jumps are exactly the first rules of <chain>
  local fn="$1" from="$2" to="$3" want got b
  want="$(for b in "${BRIDGES[@]}"; do echo "-A $from -i $b -j $to"; done | sort)"
  got="$("$fn" -S "$from" 2>/dev/null | grep '^-A ' | head -n "${#BRIDGES[@]}" | sort || true)"
  [[ "$got" == "$want" ]]
}
ensure_jump() { # ensure_jump <iptables-fn> <chain> <target-chain>: idempotent, first position
  local fn="$1" from="$2" to="$3" b
  jumps_first "$fn" "$from" "$to" && return 0
  drop_jump "$fn" "$from" "$to"             # stale or displaced jumps are re-inserted at the top
  for b in "${BRIDGES[@]}"; do "$fn" -I "$from" 1 -i "$b" -j "$to"; done
}
drop_jump() {
  local fn="$1" from="$2" to="$3" b
  for b in "${BRIDGES[@]}"; do
    while "$fn" -C "$from" -i "$b" -j "$to" 2>/dev/null; do "$fn" -D "$from" -i "$b" -j "$to"; done
  done
}

lock() { exec 8>"$STATE_DIR/hunter-guard.lock"; flock -w 30 8 || die "another host-egress-guard run holds the lock"; }
need_ip6tables() {
  "${NS[@]}" ip6tables -S >/dev/null 2>&1 \
    || die "ip6tables is unavailable in the daemon namespace: refusing (IPv6 would be unguarded)"
}

# ---- full-policy verification ---------------------------------------------------------------
PROBLEMS=()
first_rules() { # first_rules <fn> <chain> <n>: the first n rules of a chain, one per line
  "$1" -S "$2" 2>/dev/null | grep '^-A ' | head -n "$3" || true
}
canon() { sed -E "s/^(-[NA] HUNTER-EGRESS-GUARD[A-Z0-9-]*)-X/\\1/"; }
cleanup_scratch() {
  local c
  for c in "$CHAIN-X" "$CHAIN_IN-X"; do ipt -F "$c" 2>/dev/null && ipt -X "$c" 2>/dev/null || true; done
  for c in "$CHAIN6-X" "$CHAIN6_IN-X"; do
    if ipt6 -S "$c" >/dev/null 2>&1; then ipt6 -F "$c" && ipt6 -X "$c" || true; fi
  done
}
check_jumps() { # check_jumps <fn> <chain> <target>: our jumps are the first rules, nothing before
  local fn="$1" from="$2" to="$3"
  jumps_first "$fn" "$from" "$to" \
    || PROBLEMS+=("$from does not start with the jumps into $to (found: $(first_rules "$fn" "$from" 3 | tr '\n' ';'))")
}
compare_chain() { # compare_chain <fn> <chain>: live chain == canonical expected chain
  local fn="$1" c="$2" live exp
  live="$("$fn" -S "$c" 2>/dev/null)" || { PROBLEMS+=("chain $c is missing"); return; }
  exp="$("$fn" -S "$c-X" 2>/dev/null | canon)" || { PROBLEMS+=("cannot render expected $c"); return; }
  if [[ "$live" != "$exp" ]]; then
    PROBLEMS+=("chain $c differs from the expected policy: $(diff <(echo "$exp") <(echo "$live") | grep '^[<>]' | head -4 | tr '\n' ';')")
  fi
}
verify_policy() {
  PROBLEMS=()
  need_ip6tables
  cleanup_scratch
  SUFFIX="-X" render_v4 | "${NS[@]}" iptables-restore -w 5 --noflush
  SUFFIX="-X" render_v6 | "${NS[@]}" ip6tables-restore -w 5 --noflush
  check_jumps ipt DOCKER-USER "$CHAIN"
  check_jumps ipt INPUT "$CHAIN_IN"
  check_jumps ipt6 FORWARD "$CHAIN6"
  check_jumps ipt6 INPUT "$CHAIN6_IN"
  if [[ "$(first_rules ipt FORWARD 1)" != "-A FORWARD -j DOCKER-USER" ]]; then
    PROBLEMS+=("FORWARD no longer starts with Docker's jump into DOCKER-USER: the guard can be bypassed")
  fi
  compare_chain ipt "$CHAIN"
  compare_chain ipt "$CHAIN_IN"
  compare_chain ipt6 "$CHAIN6"
  compare_chain ipt6 "$CHAIN6_IN"
  cleanup_scratch
  [[ ${#PROBLEMS[@]} -eq 0 ]] && return 0
  printf 'NOT active: %s\n' "${PROBLEMS[@]}"
  return 1
}

do_apply() {
  lock; need_ip6tables
  local deadline=$((SECONDS + WAIT))
  until ipt -S DOCKER-USER >/dev/null 2>&1; do
    (( SECONDS < deadline )) || die "chain DOCKER-USER does not exist in the daemon namespace (daemon not up, or nftables backend)"
    sleep 1
  done
  render_v4 | "${NS[@]}" iptables-restore -w 5 --noflush
  ensure_jump ipt DOCKER-USER "$CHAIN"
  ensure_jump ipt INPUT "$CHAIN_IN"
  render_v6 | "${NS[@]}" ip6tables-restore -w 5 --noflush
  ensure_jump ipt6 FORWARD "$CHAIN6"
  ensure_jump ipt6 INPUT "$CHAIN6_IN"
  note "applied: ${#HOSTS[@]} host address(es), ${#NON_GLOBAL[@]} non-global ranges, DNS ${DNS[*]}"
  verify_policy || die "policy was applied but does not verify: see messages above"
  note "existing connections are not cut; restart the stack and run deploy/smoke-test.sh to validate"
}

do_status() {
  lock
  if verify_policy; then
    echo "active (pid $PID; ${#HOSTS[@]} host address(es); DNS ${DNS[*]})"
  else
    return 1
  fi
}

do_remove() {
  lock
  drop_jump ipt DOCKER-USER "$CHAIN"
  drop_jump ipt INPUT "$CHAIN_IN"
  for c in "$CHAIN" "$CHAIN_IN"; do ipt -F "$c" 2>/dev/null && ipt -X "$c" 2>/dev/null || true; done
  cleanup_scratch
  if "${NS[@]}" ip6tables -S >/dev/null 2>&1; then
    drop_jump ipt6 FORWARD "$CHAIN6"
    drop_jump ipt6 INPUT "$CHAIN6_IN"
    for c in "$CHAIN6" "$CHAIN6_IN"; do
      if ipt6 -S "$c" >/dev/null 2>&1; then ipt6 -F "$c" && ipt6 -X "$c" || true; fi
    done
  fi
  note "removed: the daemon namespace is back to Docker's own rules"
}

case "$cmd" in
  plan) do_plan ;;
  apply) do_apply ;;
  status) do_status ;;
  remove) do_remove ;;
esac
