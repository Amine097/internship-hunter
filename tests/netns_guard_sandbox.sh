#!/usr/bin/env bash
# Throwaway network-namespace sandbox that reproduces the rootless-Docker host-reachability
# problem and runs the REAL deploy/host-egress-guard.sh against it, with real iptables and real
# packets. Used by tests/test_host_egress_guard_netns.py. Needs unprivileged user namespaces and
# an iptables binary; touches nothing outside its own namespaces (no root, no host firewall).
#
#   R  user namespace owner       D  the "rootless daemon" netns: bridge br-a1b2c3d4e5f6 + uplink
#   C  a container on br-a1b2c3d4e5f6     U  the simulated HOST: owns the tailnet IP, a public IP, the
#                                    slirp gateway/DNS, and the "Internet" address 8.8.8.8
# Prints "STAGE <name>" then "<label> REACHABLE|blocked" lines.
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="${GUARD:-$HERE/../deploy/host-egress-guard.sh}"
WORK="$(mktemp -d)"
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

ns() { local pid="$1"; shift; nsenter --preserve-credentials -U -n -t "$pid" -- "$@"; }
unshare -Ur sleep 600 & R=$!; pids+=("$R"); sleep 0.3
mk() { nsenter --preserve-credentials -U -t "$R" -- unshare -n sleep 600 & pids+=("$!"); eval "$1=$!"; }
# the "daemon" must pass the guard's identity checks: a process whose cmdline says dockerd
nsenter --preserve-credentials -U -t "$R" -- unshare -n bash -c 'exec -a dockerd sleep 600' & D=$!; pids+=("$D")
mk C; mk C2; mk C3; mk U; sleep 0.5
for p in $D $C $C2 $C3 $U; do ns "$p" ip link set lo up; done

ns "$D" ip link add br-a1b2c3d4e5f6 type bridge
ns "$D" ip addr add 172.30.0.1/24 dev br-a1b2c3d4e5f6; ns "$D" ip link set br-a1b2c3d4e5f6 up
ns "$D" ip link add c1 type veth peer name c0
ns "$D" ip link set c0 netns "$C"; ns "$D" ip link set c1 master br-a1b2c3d4e5f6; ns "$D" ip link set c1 up
ns "$C" ip addr add 172.30.0.2/24 dev c0; ns "$C" ip link set c0 up; ns "$C" ip route add default via 172.30.0.1
# peer on the SAME bridge: with br_netfilter this traffic traverses FORWARD (the guard must not break it)
ns "$D" ip link add c3x type veth peer name c3y; ns "$D" ip link set c3y netns "$C3"; ns "$D" ip link set c3x master br-a1b2c3d4e5f6; ns "$D" ip link set c3x up
ns "$C3" ip addr add 172.30.0.3/24 dev c3y; ns "$C3" ip link set c3y up; ns "$C3" ip route add default via 172.30.0.1
# a container on docker0, the default bridge
ns "$D" ip link add docker0 type bridge; ns "$D" ip addr add 172.31.0.1/24 dev docker0; ns "$D" ip link set docker0 up
ns "$D" ip link add c2x type veth peer name c2y; ns "$D" ip link set c2y netns "$C2"; ns "$D" ip link set c2x master docker0; ns "$D" ip link set c2x up
ns "$C2" ip addr add 172.31.0.2/24 dev c2y; ns "$C2" ip link set c2y up; ns "$C2" ip route add default via 172.31.0.1
ns "$D" sysctl -qw net.bridge.bridge-nf-call-iptables=1 || true      # as on a host with br_netfilter loaded
ns "$D" ip link add up0 type veth peer name up1; ns "$D" ip link set up1 netns "$U"
ns "$D" ip addr add 10.0.2.100/24 dev up0; ns "$D" ip link set up0 up; ns "$D" ip route add default via 10.0.2.2
ns "$U" ip addr add 10.0.2.2/24 dev up1; ns "$U" ip link set up1 up
ns "$U" ip route add 172.30.0.0/24 via 10.0.2.100; ns "$U" ip route add 172.31.0.0/24 via 10.0.2.100
ns "$D" sysctl -qw net.ipv4.ip_forward=1; ns "$U" sysctl -qw net.ipv4.ip_forward=1
for a in 100.107.22.84 203.0.114.7 8.8.8.8 10.0.2.3; do ns "$U" ip addr add "$a/32" dev lo; done
# IPv6: the production design gives containers NO IPv6 route; this topology deliberately gives one
# (as if IPv6 were switched on) to prove the guard does not rely on that: fd7a::1 plays the host's
# Tailscale IPv6 address, 2001:db8:8::8 the IPv6 Internet.
ns "$D" sysctl -qw net.ipv6.conf.all.forwarding=1; ns "$U" sysctl -qw net.ipv6.conf.all.forwarding=1
ns "$D" ip -6 addr add fd30::1/64 dev br-a1b2c3d4e5f6 nodad
ns "$C" ip -6 addr add fd30::2/64 dev c0 nodad; ns "$C" ip -6 route add default via fd30::1 dev c0
ns "$D" ip -6 addr add fd00:2::100/64 dev up0 nodad; ns "$D" ip -6 route add default via fd00:2::2 dev up0
ns "$U" ip -6 addr add fd00:2::2/64 dev up1 nodad; ns "$U" ip -6 route add fd30::/64 via fd00:2::100
for a in fd7a::1 2001:db8:8::8; do ns "$U" ip -6 addr add "$a/128" dev lo nodad; done
sleep 1.5      # let the v6 addresses and routes settle
# what Docker creates before our hook runs
ns "$D" iptables -N DOCKER-USER; ns "$D" iptables -A DOCKER-USER -j RETURN
ns "$D" iptables -A FORWARD -j DOCKER-USER

# services: tailnet sshd + gluetun port, a public IP of the host, the slirp gateway, the Internet,
# the DNS resolver; plus a listener in D itself (docker-proxy / bridge gateway) and one in C
cat >"$WORK/listen.py" <<'PY'
import selectors, socket, sys
sel = selectors.DefaultSelector()
for spec in sys.argv[1:]:
    kind, ip, port = spec.split(":")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, int(port)))
    if kind == "tcp":
        s.listen(16)
    sel.register(s, selectors.EVENT_READ, kind)
while True:
    for key, _ in sel.select():
        if key.data == "tcp":
            key.fileobj.accept()[0].close()
        else:
            _, addr = key.fileobj.recvfrom(512); key.fileobj.sendto(b"pong", addr)
PY
ns "$U" python3 "$WORK/listen.py" tcp:100.107.22.84:22 tcp:100.107.22.84:8000 tcp:203.0.114.7:22 \
   tcp:10.0.2.2:22 tcp:8.8.8.8:443 tcp:10.0.2.3:53 udp:10.0.2.3:53 & pids+=("$!")
ns "$D" python3 "$WORK/listen.py" tcp:172.30.0.1:7000 & pids+=("$!")
cat >"$WORK/listen6.py" <<'PY'
import socket, sys, selectors
sel = selectors.DefaultSelector()
for spec in sys.argv[1:]:
    ip, port = spec.rsplit(",", 1)
    s = socket.socket(socket.AF_INET6)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, int(port))); s.listen(16); sel.register(s, selectors.EVENT_READ)
while True:
    for key, _ in sel.select():
        key.fileobj.accept()[0].close()
PY
ns "$U" python3 "$WORK/listen6.py" fd7a::1,22 2001:db8:8::8,443 & pids+=("$!")
ns "$D" python3 "$WORK/listen6.py" fd30::1,7001 & pids+=("$!")
ns "$C" python3 "$WORK/listen.py" tcp:172.30.0.2:9000 & pids+=("$!")
ns "$C3" python3 "$WORK/listen.py" tcp:172.30.0.3:9100 & pids+=("$!")
sleep 0.7

tcp_from() { # tcp_from <pid> <ip> <port>
  ns "$1" python3 -c '
import socket, sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2).close(); print("REACHABLE")
except OSError:
    print("blocked")' "$2" "$3"
}
dns_from_c() {
  ns "$C" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(b"q", ("10.0.2.3", 53))
try:
    s.recvfrom(16); print("REACHABLE")
except OSError:
    print("blocked")'
}
# does a container on docker0 get to run its service? (docker/isolation-gate.sh, python flavour)
gate_starts() {
  if ns "$C2" env EGRESS_FORBIDDEN_TARGETS=100.107.22.84:22,100.107.22.84:2375 \
       sh "$HERE/../docker/isolation-gate.sh" true >/dev/null 2>&1; then echo REACHABLE; else echo blocked; fi
}
matrix() {
  echo "STAGE $1"
  for t in tailnet_ssh:100.107.22.84:22 tailnet_gluetun:100.107.22.84:8000 host_public_ip:203.0.114.7:22 \
           slirp_gateway:10.0.2.2:22 bridge_gateway:172.30.0.1:7000 internet:8.8.8.8:443 \
           dns_tcp:10.0.2.3:53; do
    IFS=: read -r label ip port <<<"$t"
    echo "$label $(tcp_from "$C" "$ip" "$port")"
  done
  echo "dns_udp $(dns_from_c)"
  echo "daemon_to_container $(tcp_from "$D" 172.30.0.2 9000)"   # docker-proxy style: D dials C
  echo "peer_same_bridge $(tcp_from "$C" 172.30.0.3 9100)"        # agent <-> proxy style traffic
  echo "default_bridge_tailnet_ssh $(tcp_from "$C2" 100.107.22.84 22)"   # ad-hoc `docker run`
  echo "default_bridge_internet $(tcp_from "$C2" 8.8.8.8 443)"
  echo "service_starts_through_gate $(gate_starts)"
  echo "ipv6_host_tailnet $(tcp_from "$C" fd7a::1 22)"           # IPv6, if a container had a route
  echo "ipv6_internet $(tcp_from "$C" 2001:db8:8::8 443)"
  echo "ipv6_daemon_namespace $(tcp_from "$C" fd30::1 7001)"     # INPUT, not FORWARD
}

mkdir -p "$WORK/xdg/dockerd-rootless"; echo "$D" >"$WORK/xdg/dockerd-rootless/child_pid"
python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])' "$WORK/xdg/docker.sock"
export XDG_RUNTIME_DIR="$WORK/xdg"
export HUNTER_GUARD_TEST_MODE=1       # only so the guard finds the iptables wrappers on PATH
# persistent parameters live in a conf file next to the script, as in production: later calls
# (status, the systemd re-apply) then need no arguments and cannot disagree with the first apply
mkdir -p "$WORK/g"; cp "$GUARD" "$WORK/g/host-egress-guard.sh"; GUARD="$WORK/g/host-egress-guard.sh"
printf 'DNS=10.0.2.3\nPROTECT=203.0.114.7/32\n' >"$WORK/g/host-egress-guard.conf"; chmod 644 "$WORK/g/host-egress-guard.conf"
ARGS=()

matrix before
"$GUARD" apply >/dev/null
"$GUARD" status >/dev/null && echo "status active"
matrix guarded
"$GUARD" apply >/dev/null           # idempotent: no duplicated rules, still guarded
echo "rules_after_reapply $(ns "$D" iptables -S HUNTER-EGRESS-GUARD | wc -l) jumps $(ns "$D" iptables -S DOCKER-USER | grep -c HUNTER-EGRESS-GUARD)"

# ---- integrity: every tampering must make `status` fail; most are repaired by `apply` ----------
tamper() { # tamper <name> <repairable yes|no> <undo cmd or "-"> -- <iptables cmd...>
  local name="$1" repair="$2" undo="$3"; shift 4
  ns "$D" "$@" >/dev/null 2>&1 || { echo "tamper_$name SETUP-FAILED"; return; }
  if "$GUARD" status >/dev/null 2>&1; then echo "tamper_$name status_passed"; else echo "tamper_$name status_failed"; fi
  if [[ "$repair" == yes ]]; then
    "$GUARD" apply >/dev/null 2>&1 || true
    if "$GUARD" status >/dev/null 2>&1; then echo "repair_$name ok"; else echo "repair_$name FAILED"; fi
  else
    ns "$D" $undo >/dev/null 2>&1; if "$GUARD" status >/dev/null 2>&1; then echo "undo_$name ok"; else echo "undo_$name FAILED"; fi
  fi
}
G=HUNTER-EGRESS-GUARD
REJ=(-j REJECT --reject-with icmp-admin-prohibited)
tamper delete_cgnat_reject yes - -- iptables -D $G -d 100.64.0.0/10 "${REJ[@]}"
tamper accept_before_jumps yes - -- iptables -I DOCKER-USER 1 -j ACCEPT
tamper remove_docker0_jump yes - -- iptables -D DOCKER-USER -i docker0 -j $G
tamper flush_chain yes - -- iptables -F $G
tamper accept_inside_chain yes - -- iptables -I $G 1 -d 100.107.22.84/32 -j ACCEPT
tamper edit_input_chain yes - -- iptables -D $G-IN -j REJECT --reject-with icmp-admin-prohibited
tamper flush_ipv6_chain yes - -- ip6tables -F ${G}6
tamper flush_ipv6_input_chain yes - -- ip6tables -F ${G}6-IN
tamper remove_input_jump yes - -- iptables -D INPUT -i br-+ -j $G-IN
tamper docker_jump_displaced no "iptables -D FORWARD 1" -- iptables -I FORWARD 1 -j ACCEPT
echo "final_status $("$GUARD" status >/dev/null 2>&1 && echo ok || echo bad)"
"$GUARD" remove >/dev/null
"$GUARD" status >/dev/null 2>&1 || echo "status inactive"
matrix removed
echo "leftover_rules $(ns "$D" iptables -S | grep -c HUNTER || true)"
