#!/usr/bin/env bash
# Lifecycle and failure behaviour of the REAL deploy/host-egress-guard.sh against REAL (throwaway,
# unprivileged) user/mount/network namespaces, laid out the way rootlesskit lays them out:
#   --detach-netns   the rootlesskit child K is in the HOST network namespace and its own mount
#                    namespace; the daemon's network namespace D is bind-mounted at
#                    <state dir>/netns inside K's mount namespace only.
# Used by tests/test_host_egress_guard_detached_netns.py. Prints "RESULT <name> PASS|FAIL <detail>".
# Every refusal is also checked for "nothing was entered": a PATH shim logs each nsenter call.
set -Eeuo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="${GUARD:-$HERE/../deploy/host-egress-guard.sh}"
WORK="$(mktemp -d)"
pids=()
kill_tree() { local c; for c in $(pgrep -P "$1" 2>/dev/null || true); do kill_tree "$c"; done; kill "$1" 2>/dev/null || true; }
cleanup() { local p; for p in "${pids[@]}"; do kill_tree "$p"; done; rm -rf "$WORK"; }
trap cleanup EXIT

REAL_NSENTER="$(command -v nsenter)"
mkdir -p "$WORK/shim"
cat >"$WORK/shim/nsenter" <<EOF
#!/bin/sh
echo "\$*" | tr "\\n" " " >>"$WORK/nsenter.log"; echo >>"$WORK/nsenter.log"
exec "$REAL_NSENTER" "\$@"
EOF
chmod +x "$WORK/shim/nsenter"
: >"$WORK/nsenter.log"

ns() { local pid="$1"; shift; "$REAL_NSENTER" --preserve-credentials -U -n -t "$pid" -- "$@"; }   # setup only
kns() { local pid="$1"; shift; "$REAL_NSENTER" --preserve-credentials -U -m -t "$pid" -- "$@"; }
unshare -Ur sleep 900 & R=$!; pids+=("$R"); sleep 0.3
INR=("$REAL_NSENTER" --preserve-credentials -U -t "$R" --)     # always used directly: "$!" must be the real process

result() { echo "RESULT $1 $2 ${3:-}"; }
check() { # check <name> <condition-exit-status> [detail]
  if [[ "$2" == 0 ]]; then result "$1" PASS; else result "$1" FAIL "${3:-}"; fi
}

# mkdaemon <name> <docker-chains yes|no> <layout detached|nonetnsfile|regularfile|symlinktohost|third>
# sets D_<name> (namespace holder), K_<name> (rootlesskit child), X_<name> (XDG_RUNTIME_DIR)
mkdaemon() {
  local n="$1" chains="$2" layout="$3" d k x="$WORK/xdg-$1"
  "${INR[@]}" unshare -n sleep 900 & d=$!; pids+=("$d")
  case "$layout" in
    third) "${INR[@]}" unshare -m -n bash -c 'exec -a rootlesskit sleep 900' & k=$! ;;
    *)     "${INR[@]}" unshare -m bash -c 'exec -a rootlesskit sleep 900' & k=$! ;;
  esac
  pids+=("$k"); sleep 0.5
  ns "$d" ip link set lo up
  if [[ "$chains" == yes ]]; then
    ns "$d" iptables -N DOCKER-USER; ns "$d" iptables -A DOCKER-USER -j RETURN; ns "$d" iptables -A FORWARD -j DOCKER-USER
  fi
  mkdir -p "$x/dockerd-rootless"
  python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])' "$x/docker.sock"
  case "$layout" in
    detached|third) : >"$x/dockerd-rootless/netns"; kns "$k" mount --bind "/proc/$d/ns/net" "$x/dockerd-rootless/netns" ;;
    regularfile)    : >"$x/dockerd-rootless/netns" ;;
    symlinktohost)  ln -s "/proc/$$/ns/net" "$x/dockerd-rootless/netns" ;;
    nonetnsfile)    ;;
  esac
  echo "$k" >"$x/dockerd-rootless/child_pid"
  eval "D_$n=$d K_$n=$k X_$n=$x"
}
var() { local v="$1_$2"; echo "${!v}"; }

OUT=""; RC=0
g() { # g <daemon name> <guard args...>: captures stdout+stderr in OUT, exit status in RC
  local n="$1"; shift
  RC=0
  OUT="$(XDG_RUNTIME_DIR="$(var X "$n")" HUNTER_GUARD_TEST_MODE=1 PATH="$WORK/shim:$PATH" \
         bash "$GUARD" "$@" --dns 10.0.2.3 --protect 203.0.114.7/32 2>&1)" || RC=$?
}
hunter() { ns "$(var D "$1")" iptables -S 2>/dev/null | grep -c HUNTER || true; }
hunter6() { ns "$(var D "$1")" ip6tables -S 2>/dev/null | grep -c HUNTER || true; }
untouched() { [[ "$(hunter "$1")" == 0 && "$(hunter6 "$1")" == 0 ]]; }
nothing_entered() { [[ ! -s "$WORK/nsenter.log" ]]; }
reset_log() { : >"$WORK/nsenter.log"; }
refused() { # refused <name> <daemon> <message regex> <expect no nsenter yes|no>
  local ok=0
  [[ "$RC" != 0 ]] || ok=1
  grep -Eq "$3" <<<"$OUT" || ok=1
  untouched "$2" || ok=1
  [[ "$4" == no ]] || nothing_entered || ok=1
  check "$1" "$ok" "rc=$RC out=${OUT:0:300} log=$(head -c 300 "$WORK/nsenter.log")"
}

# ---- 1. the production layout works end to end -----------------------------------------------------
mkdaemon d1 yes detached
reset_log
g d1 apply; a=$RC; o="$OUT"
g d1 status; s=$RC
check detached_apply_and_status "$(( a + s ))" "apply rc=$a: ${o:0:300} status rc=$s: ${OUT:0:300}"
check detached_layout_is_what_production_has "$([[ "$(readlink "/proc/$K_d1/ns/net")" == "$(readlink /proc/self/ns/net)" && ! -s "$X_d1/dockerd-rootless/netns" ]] && echo 0 || echo 1)"
check detached_rules_are_in_the_daemon_namespace "$([[ "$(hunter d1)" -gt 0 ]] && echo 0 || echo 1)"
check detached_status_names_the_namespace "$(grep -q "net:\[$(stat -L -c %i "/proc/$K_d1/root$X_d1/dockerd-rootless/netns")\]" <<<"$OUT" && echo 0 || echo 1)" "$OUT"
check detached_every_nsenter_names_the_detached_file "$(grep -vq -- "--net=/proc/$K_d1/root$X_d1/dockerd-rootless/netns" "$WORK/nsenter.log" && echo 1 || echo 0)" "$(grep -v -- --net= "$WORK/nsenter.log" | head -3)"
g d1 remove; check detached_remove_restores "$([[ $RC == 0 ]] && untouched d1 && echo 0 || echo 1)" "$OUT"
g d1 apply; g d1 status; check detached_reapply_after_remove "$RC"

# ---- 2. refusals that happen BEFORE any namespace is entered -----------------------------------------
mkdaemon d2 yes nonetnsfile; reset_log; g d2 apply --wait 1
refused absent_detached_namespace_is_refused d2 "no detached daemon namespace" yes
g d2 status; check absent_detached_namespace_status_fails "$([[ $RC != 0 ]] && echo 0 || echo 1)" "$OUT"

mkdaemon d3 yes regularfile; reset_log; g d3 apply --wait 1
refused plain_file_instead_of_a_namespace_is_refused d3 "not a namespace file" yes

mkdaemon d4 yes symlinktohost; reset_log; g d4 apply --wait 1
refused symlink_to_the_host_namespace_is_refused d4 "symbolic link" yes
g d4 remove; check symlink_remove_is_refused "$([[ $RC != 0 ]] && nothing_entered && echo 0 || echo 1)" "$OUT"

mkdaemon d5 yes third; reset_log; g d5 apply --wait 1
refused ambiguous_layout_is_refused d5 "ambiguous layout" yes

# the old behaviour (enter the child's own network namespace) would have landed in the HOST here:
check child_is_in_host_netns_in_all_detached_cases "$([[ "$(readlink /proc/$K_d2/ns/net)" == "$(readlink /proc/self/ns/net)" ]] && echo 0 || echo 1)"

# ---- 3. Docker's chains missing: fail closed, nothing created -------------------------------------
mkdaemon d6 no detached; reset_log; g d6 apply --wait 2
refused missing_docker_chains_apply d6 "Docker's chains" no
g d6 status; check missing_docker_chains_status "$([[ $RC != 0 ]] && untouched d6 && grep -q "Docker's chains" <<<"$OUT" && echo 0 || echo 1)" "$OUT"
g d6 remove; check missing_docker_chains_remove_is_harmless "$([[ $RC == 0 ]] && untouched d6 && echo 0 || echo 1)" "$OUT"
check no_mutating_command_was_ever_sent "$(grep -Eq 'iptables-restore|ip6tables-restore| -I | -A | -N ' "$WORK/nsenter.log" && echo 1 || echo 0)"

# ---- 4. daemon restarts under a running apply ----------------------------------------------------
mkdaemon d7 no detached          # waits for chains that never come
mkdir -p "$WORK/b"; "${INR[@]}" unshare -n sleep 900 & Bpid=$!; pids+=("$Bpid"); sleep 0.5
ns "$Bpid" ip link set lo up; ns "$Bpid" iptables -N DOCKER-USER; ns "$Bpid" iptables -A DOCKER-USER -j RETURN; ns "$Bpid" iptables -A FORWARD -j DOCKER-USER
( g d7 apply --wait 30; echo "$RC" >"$WORK/d7.rc"; echo "$OUT" >"$WORK/d7.out" ) & w=$!
sleep 2.5
# "restart": the same state dir now exposes another namespace (one that even has Docker's chains)
kns "$K_d7" sh -c "umount '$X_d7/dockerd-rootless/netns' && mount --bind /proc/$Bpid/ns/net '$X_d7/dockerd-rootless/netns'"
wait "$w" || true
check restart_namespace_swap_is_detected "$([[ "$(<"$WORK/d7.rc")" != 0 ]] && grep -q "changed or vanished" "$WORK/d7.out" && untouched d7 && echo 0 || echo 1)" "$(<"$WORK/d7.out")"
check restart_swap_never_touches_the_new_namespace "$([[ "$(ns "$Bpid" iptables -S | grep -c HUNTER || true)" == 0 ]] && echo 0 || echo 1)"

mkdaemon d8 no detached
( g d8 apply --wait 30; echo "$RC" >"$WORK/d8.rc"; echo "$OUT" >"$WORK/d8.out" ) & w=$!
sleep 2.5; kill -9 "$K_d8" "$D_d8"; wait "$w" || true
check restart_process_death_is_detected "$([[ "$(<"$WORK/d8.rc")" != 0 ]] && grep -Eq "is gone|vanished|cannot enter" "$WORK/d8.out" && echo 0 || echo 1)" "$(<"$WORK/d8.out")"
g d8 status; check stale_pidfile_is_refused "$([[ $RC != 0 ]] && grep -q "is gone" <<<"$OUT" && echo 0 || echo 1)" "$OUT"
g d8 apply --wait 1; check stale_pidfile_apply_is_refused "$([[ $RC != 0 ]] && grep -q "is gone" <<<"$OUT" && echo 0 || echo 1)" "$OUT"

# ---- 5. a real restart: new process, new namespace, same state dir --------------------------------
restart_into() { # restart_into <name> : new rootlesskit child + new namespace behind the same state dir
  local n="$1" d k x
  x="$(var X "$n")"
  "${INR[@]}" unshare -n sleep 900 & d=$!; pids+=("$d")
  "${INR[@]}" unshare -m bash -c 'exec -a rootlesskit sleep 900' & k=$!; pids+=("$k"); sleep 0.5
  ns "$d" ip link set lo up
  ns "$d" iptables -N DOCKER-USER; ns "$d" iptables -A DOCKER-USER -j RETURN; ns "$d" iptables -A FORWARD -j DOCKER-USER
  kns "$k" mount --bind "/proc/$d/ns/net" "$x/dockerd-rootless/netns"
  echo "$k" >"$x/dockerd-rootless/child_pid"
  eval "D_$n=$d K_$n=$k"
}
: >"$X_d8/dockerd-rootless/netns" 2>/dev/null || true
restart_into d8
g d8 status; check restarted_daemon_is_unguarded_until_reapplied "$([[ $RC != 0 ]] && echo 0 || echo 1)" "$OUT"
g d8 apply; a=$RC; g d8 status
check restarted_daemon_apply_and_status "$(( a + RC ))" "$OUT"
check restarted_daemon_rules_in_new_namespace "$([[ "$(hunter d8)" -gt 0 ]] && echo 0 || echo 1)"
oldD=$D_d8; restart_into d8
g d8 status; check second_restart_does_not_inherit_the_old_guard "$([[ $RC != 0 ]] && untouched d8 && echo 0 || echo 1)" "$OUT"
g d8 apply; check second_restart_reapply "$RC" "$OUT"

# ---- 6. the namespace gate itself refuses a mismatching identity -------------------------------------
GATE="$(python3 - "$GUARD" <<'PY'
import re, sys
m = re.search(r"^NS_GATE='(.*?)'$", open(sys.argv[1]).read(), re.S | re.M)
print(m.group(1))
PY
)"
NETF="/proc/$K_d1/root$X_d1/dockerd-rootless/netns"
good_net="net:[$(stat -L -c %i "$NETF")]"; good_user="$(readlink "/proc/$K_d1/ns/user")"
gate() { "$REAL_NSENTER" --preserve-credentials -t "$K_d1" --user --mount "--net=$NETF" -- /bin/sh -c "$GATE" gate "$1" "$2" touch "$3" 2>/dev/null; }
rm -f "$WORK/m_ok" "$WORK/m_net" "$WORK/m_user" "$WORK/m_host"
gate "$good_net" "$good_user" "$WORK/m_ok" || true
RC=0; gate "net:[4026531840]" "$good_user" "$WORK/m_net" || RC=$?
check gate_runs_with_the_verified_identity "$([[ -e "$WORK/m_ok" ]] && echo 0 || echo 1)"
check gate_refuses_a_wrong_network_namespace "$([[ $RC == 97 && ! -e "$WORK/m_net" ]] && echo 0 || echo 1)" "rc=$RC"
RC=0; gate "$good_net" "user:[1]" "$WORK/m_user" || RC=$?
check gate_refuses_a_wrong_user_namespace "$([[ $RC == 97 && ! -e "$WORK/m_user" ]] && echo 0 || echo 1)" "rc=$RC"
RC=0; gate "$(readlink /proc/self/ns/net)" "$good_user" "$WORK/m_host" || RC=$?
check gate_refuses_the_host_namespace_identity "$([[ $RC == 97 && ! -e "$WORK/m_host" ]] && echo 0 || echo 1)" "rc=$RC"

# ---- 7. layout without --detach-netns (child in the daemon's namespace) ------------------------------
"${INR[@]}" unshare -m -n bash -c 'exec -a dockerd sleep 900' & D12=$!; pids+=("$D12"); sleep 0.5
ns "$D12" ip link set lo up; ns "$D12" iptables -N DOCKER-USER; ns "$D12" iptables -A DOCKER-USER -j RETURN; ns "$D12" iptables -A FORWARD -j DOCKER-USER
x12="$WORK/xdg-d12"; mkdir -p "$x12/dockerd-rootless"; echo "$D12" >"$x12/dockerd-rootless/child_pid"
python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])' "$x12/docker.sock"
D_d12=$D12; K_d12=$D12; X_d12=$x12
g d12 apply; a=$RC; g d12 status; s=$RC
check child_layout_apply_and_status "$(( a + s ))" "$OUT"
check child_layout_status_says_so "$(grep -q "child namespace" <<<"$OUT" && echo 0 || echo 1)" "$OUT"
g d12 remove; check child_layout_remove "$([[ $RC == 0 ]] && untouched d12 && echo 0 || echo 1)"
echo DONE
