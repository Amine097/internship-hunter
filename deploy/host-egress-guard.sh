#!/usr/bin/env bash
# Host-level egress guard for the ROOTLESS Docker daemon that runs Internship Hunter.
#
#   host-egress-guard.sh plan   [--dns IP[,IP]] [--protect CIDR[,CIDR]]   print, change nothing
#   host-egress-guard.sh apply  [--dns IP[,IP]] [--protect CIDR[,CIDR]] [--wait SECONDS]
#   host-egress-guard.sh status                                            exit 0 only if active
#   host-egress-guard.sh remove                                            fully reversible
#
# THE PROBLEM. Containers on a non-internal network (the three egress proxies, discovery,
# telegram, api) leave through the rootless daemon's user-space NAT (slirp4netns / pasta). That
# NAT opens its sockets from the HOST's network namespace, so a container can dial any address
# the host owns - its Tailscale IP (sshd on :22), the Gluetun container's published port - and
# no host firewall (UFW/nftables FORWARD) ever sees a forwarded packet. Hostname filtering in the
# proxy (tinyproxy ACLs) is application level and is not a network boundary.
#
# WHAT THIS DOES. It enters ONLY the rootless daemon's own network namespace (the user owns it;
# it is not the host's) and adds two small chains there:
#   HUNTER-EGRESS-GUARD     in DOCKER-USER  (forwarded traffic), for packets entering from a
#                           Docker bridge (br-*, docker0: every compose network AND any ad-hoc
#                           `docker run`): established replies pass; traffic that stays on a
#                           Docker bridge is left to Docker's own isolation rules; DNS to the
#                           namespace's resolver passes; everything else addressed to non-global
#                           space (RFC1918, 100.64.0.0/10 = Tailscale, loopback, link-local, ...)
#                           or to an address of THIS HOST is rejected. Public destinations are
#                           untouched, so CONNECT to api.anthropic.com / api.openai.com works.
#   HUNTER-EGRESS-GUARD-IN  in INPUT: containers may not open NEW connections to the daemon
#                           namespace itself (bridge gateway, docker-proxy listeners).
# IPv6: containers are IPv4-only; NEW forwarded IPv6 from Docker bridges is rejected as well.
#
# WHAT IT NEVER TOUCHES: the host's iptables/nftables/UFW, sshd, Tailscale, Gluetun and the
# rootful daemon's containers (a different daemon in a different namespace). It refuses to run
# as root and refuses a target namespace equal to the host's. The rules vanish when the daemon
# restarts (new namespace): re-apply from an ExecStartPost drop-in (docs/deployment.md).
set -Eeuo pipefail

BRIDGES=("br-+" "docker0")               # Docker's user-defined bridges and its default bridge
CHAIN="HUNTER-EGRESS-GUARD"
CHAIN_IN="HUNTER-EGRESS-GUARD-IN"
CHAIN6="HUNTER-EGRESS-GUARD6"
PROC="${HUNTER_GUARD_PROC:-/proc}"        # seam for the tests; /proc in production
# Destinations that are never "the public Internet" (IANA special-purpose + multicast/reserved)
NON_GLOBAL=(0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12
            192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24
            203.0.113.0/24 224.0.0.0/4 240.0.0.0/4)

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

[[ "$(id -u)" != 0 ]] || die "refusing to run as root: run as the user that owns the rootless Docker daemon"

cidr_ok() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$ ]]; }

# ---- locate the rootless daemon's namespace ---------------------------------------------------
STATE_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/dockerd-rootless"
PIDFILE="$STATE_DIR/child_pid"
[[ -r "$PIDFILE" ]] || die "no rootless Docker daemon found ($PIDFILE missing): is it running as this user?"
PID="$(<"$PIDFILE")"
[[ "$PID" =~ ^[0-9]+$ ]] || die "malformed $PIDFILE"
target_ns="$(readlink "$PROC/$PID/ns/net" 2>/dev/null)" || die "process $PID is gone (stale $PIDFILE)"
own_ns="$(readlink "$PROC/self/ns/net")"
[[ "$target_ns" != "$own_ns" ]] \
  || die "process $PID is in the HOST network namespace: refusing (this tool must never edit the host's firewall)"
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
[[ ${#DNS[@]} -gt 0 || "$cmd" == status || "$cmd" == remove ]] \
  || die "no usable DNS resolver found in the daemon namespace: pass --dns <ip> (see docs/deployment.md)"

# ---- addresses of THIS host (the thing being protected), read from the host namespace --------
host_addrs() {
  ip -4 -o addr show scope global 2>/dev/null | awk '{split($4, a, "/"); print a[1]"/32"}' || true
}
mapfile -t EXTRA < <(tr ',' '\n' <<<"$PROTECT_ARG" | awk 'NF')
for c in "${EXTRA[@]}"; do cidr_ok "$c" || die "invalid --protect CIDR: $c"; done
mapfile -t HOSTS < <(host_addrs)

render_v4() { # iptables-restore --noflush input; redefining a chain replaces it atomically
  echo "*filter"
  echo ":$CHAIN - [0:0]"
  echo ":$CHAIN_IN - [0:0]"
  echo "-F $CHAIN"                    # explicit: do not rely on how the backend treats a redeclared chain
  echo "-F $CHAIN_IN"
  echo "-A $CHAIN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
  # container-to-container: with br_netfilter, traffic that never leaves a bridge also traverses
  # FORWARD, and the peers' addresses are in 172.16/12. Docker's own rules police that traffic.
  for b in "${BRIDGES[@]}"; do echo "-A $CHAIN -o $b -j RETURN"; done
  for d in "${DNS[@]}"; do
    echo "-A $CHAIN -d $d/32 -p udp --dport 53 -j RETURN"
    echo "-A $CHAIN -d $d/32 -p tcp --dport 53 -j RETURN"
  done
  for h in "${HOSTS[@]}" "${EXTRA[@]}"; do
    [[ "$h" == */* ]] || h="$h/32"
    echo "-A $CHAIN -d $h -j REJECT --reject-with icmp-admin-prohibited"
  done
  for n in "${NON_GLOBAL[@]}"; do
    echo "-A $CHAIN -d $n -j REJECT --reject-with icmp-admin-prohibited"
  done
  echo "-A $CHAIN -j RETURN"
  echo "-A $CHAIN_IN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
  echo "-A $CHAIN_IN -j REJECT --reject-with icmp-admin-prohibited"
  echo "COMMIT"
}
render_v6() {
  echo "*filter"
  echo ":$CHAIN6 - [0:0]"
  echo "-F $CHAIN6"
  echo "-A $CHAIN6 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
  echo "-A $CHAIN6 -j REJECT --reject-with icmp6-adm-prohibited"
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
#   ip6tables-restore --noflush     <  the IPv6 ruleset (skipped if ip6tables is unavailable)
#   ip6tables -I FORWARD 1    -i <${BRIDGES[*]}> -j $CHAIN6
EOF
  render_v4
  echo "# --- IPv6"
  render_v6
}

ensure_jump() { # ensure_jump <iptables-fn> <chain> <target-chain>  (idempotent, first position)
  local fn="$1" from="$2" to="$3" b
  for b in "${BRIDGES[@]}"; do
    "$fn" -C "$from" -i "$b" -j "$to" 2>/dev/null || "$fn" -I "$from" 1 -i "$b" -j "$to"
  done
}
drop_jump() {
  local fn="$1" from="$2" to="$3" b
  for b in "${BRIDGES[@]}"; do
    while "$fn" -C "$from" -i "$b" -j "$to" 2>/dev/null; do "$fn" -D "$from" -i "$b" -j "$to"; done
  done
}
have_jump() { local fn="$1" from="$2" to="$3" b; for b in "${BRIDGES[@]}"; do
  "$fn" -C "$from" -i "$b" -j "$to" 2>/dev/null || return 1; done; }

do_apply() {
  local deadline=$((SECONDS + WAIT))
  until ipt -S DOCKER-USER >/dev/null 2>&1; do
    (( SECONDS < deadline )) || die "chain DOCKER-USER does not exist in the daemon namespace (daemon not up, or nftables backend)"
    sleep 1
  done
  render_v4 | "${NS[@]}" iptables-restore -w 5 --noflush
  ensure_jump ipt DOCKER-USER "$CHAIN"
  ensure_jump ipt INPUT "$CHAIN_IN"
  if "${NS[@]}" ip6tables -S >/dev/null 2>&1; then
    render_v6 | "${NS[@]}" ip6tables-restore -w 5 --noflush
    ensure_jump ipt6 FORWARD "$CHAIN6"
  else
    note "WARNING: ip6tables unavailable in the daemon namespace; IPv6 is not guarded (containers are IPv4-only)"
  fi
  note "applied: ${#HOSTS[@]} host address(es), ${#NON_GLOBAL[@]} non-global ranges, DNS ${DNS[*]}"
  note "existing connections are not cut; restart the stack and run deploy/smoke-test.sh to validate"
}

do_status() {
  local ok=1
  have_jump ipt DOCKER-USER "$CHAIN" || { echo "missing: DOCKER-USER -> $CHAIN"; ok=0; }
  have_jump ipt INPUT "$CHAIN_IN" || { echo "missing: INPUT -> $CHAIN_IN"; ok=0; }
  ipt -S "$CHAIN" 2>/dev/null | grep -q -- '-d 100.64.0.0/10 .*-j REJECT' \
    || { echo "missing: $CHAIN does not reject 100.64.0.0/10 (Tailscale)"; ok=0; }
  if [[ "$ok" == 1 ]]; then echo "active (pid $PID)"; else echo "NOT active"; return 1; fi
}

do_remove() {
  drop_jump ipt DOCKER-USER "$CHAIN"
  drop_jump ipt INPUT "$CHAIN_IN"
  for c in "$CHAIN" "$CHAIN_IN"; do ipt -F "$c" 2>/dev/null && ipt -X "$c" 2>/dev/null || true; done
  if "${NS[@]}" ip6tables -S >/dev/null 2>&1; then
    drop_jump ipt6 FORWARD "$CHAIN6"
    ipt6 -F "$CHAIN6" 2>/dev/null && ipt6 -X "$CHAIN6" 2>/dev/null || true
  fi
  note "removed: the daemon namespace is back to Docker's own rules"
}

case "$cmd" in
  plan) do_plan ;;
  apply) do_apply ;;
  status) do_status ;;
  remove) do_remove ;;
esac
