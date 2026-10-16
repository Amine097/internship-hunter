#!/usr/bin/env bash
# Acceptance tests for the RSM pilot on a real Ubuntu 24.04 host (system systemd, rootful Docker
# for the disposable containers, and - when present - the rootless daemon of the client user).
# Run as root AFTER install-pilot.sh:   sudo deploy/rsm/pilot/pilot-test.sh --client-user hunter-deploy [--require-rootless]
#
# DISPOSABLE ONLY: every container this script creates or touches is named hv-pilot-*, and the
# installed policy cannot name anything else.
# shellcheck disable=SC2015  # `A && pass || fail`: pass() only echoes and always succeeds
set -Euo pipefail
CLIENT_USER=""; REQUIRE_ROOTLESS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --client-user) CLIENT_USER="${2:?}"; shift 2 ;;
    --require-rootless) REQUIRE_ROOTLESS=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ $EUID -eq 0 && -n "$CLIENT_USER" ]] || { echo "need root and --client-user" >&2; exit 2; }
SOCK=/var/lib/hunter-rsm-ipc/rsm.sock
CUID="$(id -u "$CLIENT_USER")"
PASSED=0; FAILED=0; SKIPPED=0
pass() { echo "PASS  $*"; PASSED=$((PASSED + 1)); }
fail() { echo "FAIL  $*" >&2; FAILED=$((FAILED + 1)); }
skip() { echo "SKIP  $*"; SKIPPED=$((SKIPPED + 1)); }
check() { local what="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi; }

call() { # call <user> <json> : one request over the socket as <user>
  sudo -u "$1" python3 -c 'import socket,sys
s=socket.socket(socket.AF_UNIX); s.settimeout(180); s.connect(sys.argv[1])
s.sendall(sys.argv[2].encode()+b"\n"); print(s.makefile().readline().strip())' "$SOCK" "$2" 2>&1
}
jget() { python3 -c 'import sys,json; print(json.loads(sys.stdin.read()).get(sys.argv[1], ""))' "$1"; }
RL() { sudo -u "$CLIENT_USER" env "XDG_RUNTIME_DIR=/run/user/$CUID" \
        "DOCKER_HOST=unix:///run/user/$CUID/docker.sock" docker "$@"; }
SESSION=0
sid() { SESSION=$((SESSION + 1)); printf 'pilot-%s-%04d' "$(date +%s)" "$SESSION"; }
running() { [[ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" == true ]]; }
reset_world() {
  docker ps -aq --filter "name=^hv-pilot-" | xargs -r docker rm -f >/dev/null
  docker pull -q alpine:3.20 >/dev/null
  docker run -d --name hv-pilot-vpn --restart unless-stopped alpine:3.20 sleep 3600 >/dev/null
  docker run -d --name hv-pilot-client --restart unless-stopped \
    --network container:hv-pilot-vpn alpine:3.20 sleep 3600 >/dev/null
  docker run -d --name hv-pilot-worker --restart no alpine:3.20 sleep 3600 >/dev/null
  docker run -d --name hv-pilot-slow --restart unless-stopped alpine:3.20 \
    sh -c 'trap "" TERM; while true; do sleep 1; done' >/dev/null     # ignores SIGTERM
  docker run -d --name hv-pilot-protected alpine:3.20 sleep 3600 >/dev/null
}
policy_without_dependency() {
  python3 - <<'PY'
import json
p = "/etc/hunter-rsm/policy.json"; d = json.load(open(p))
d["containers"]["hv-pilot-client"].pop("depends_on", None)
open(p, "w").write(json.dumps(d))
PY
}
policy_with_dependency() {
  python3 - <<'PY'
import json
p = "/etc/hunter-rsm/policy.json"; d = json.load(open(p))
d["containers"]["hv-pilot-client"]["depends_on"] = ["hv-pilot-vpn"]
open(p, "w").write(json.dumps(d))
PY
}

echo "=== HIGH-1: real systemd socket activation"
check "socket unit active"                      systemctl is-active hunter-rsm.socket
show="$(systemctl show hunter-rsm.socket -p SocketUser -p SocketGroup -p SocketMode)"
grep -q 'SocketUser=hunter-rsm' <<<"$show" && pass "SocketUser=hunter-rsm" || fail "SocketUser"
grep -q "SocketGroup=$(id -gn "$CLIENT_USER")" <<<"$show" && pass "SocketGroup = client primary group" || fail "SocketGroup"
grep -q 'SocketMode=0660' <<<"$show" && pass "SocketMode=0660" || fail "SocketMode"
[[ "$(stat -c '%U:%G:%a' $SOCK)" == "hunter-rsm:$(id -gn "$CLIENT_USER"):660" ]] \
  && pass "socket owner/group/mode as configured by systemd" || fail "socket stat: $(stat -c '%U:%G:%a' $SOCK)"
[[ "$(stat -c '%U:%G:%a' "$(dirname $SOCK)")" == "root:$(id -gn "$CLIENT_USER"):750" ]] \
  && pass "socket directory root-owned 0750, not world accessible" || fail "directory stat"
id -nG "$CLIENT_USER" | tr ' ' '\n' | grep -qx docker && fail "client user is in the docker group" \
  || pass "client user is NOT in the docker group"
out="$(call "$CLIENT_USER" '{"op": "status"}')"
[[ "$(jget ok <<<"$out")" == True ]] && pass "authorised client served (broker started on demand)" \
  || fail "authorised client: $out"
out="$(call nobody '{"op": "status"}')"
grep -Eq 'PermissionError|Permission denied|EACCES' <<<"$out" \
  && pass "unauthorised user gets EACCES" || fail "unauthorised user: $out"
pid="$(systemctl show -p MainPID --value hunter-rsm.service)"
grep -q '^NoNewPrivs:[[:space:]]*1' /proc/"$pid"/status && pass "broker: no_new_privs" || fail "no_new_privs"
grep -q '^CapEff:[[:space:]]*0000000000000000' /proc/"$pid"/status \
  && pass "broker: empty effective capability set" || fail "capabilities"
grep -q '^Seccomp:[[:space:]]*2' /proc/"$pid"/status && pass "broker: seccomp filter active" || fail "seccomp"
[[ "$(readlink /proc/"$pid"/fd/3)" == socket:* ]] && pass "broker inherited fd 3 from systemd" || fail "fd 3"
check "service healthy under the sandbox (docker CLI works)" \
  sudo -u hunter-rsm env PYTHONPATH=/opt/hunter-rsm/src python3 -m hunter.rsm plan

echo "=== HIGH-2: rootless namespace mapping and lifecycle"
if [[ -S /run/user/$CUID/docker.sock ]] && RL info >/dev/null 2>&1; then
  RL pull -q python:3.12-alpine >/dev/null
  RL rm -f hv-pilot-ctl >/dev/null 2>&1 || true
  RL run -d --name hv-pilot-ctl -v /var/lib/hunter-rsm-ipc:/run/hunter-rsm:ro \
    python:3.12-alpine sleep 3600 >/dev/null
  RL exec hv-pilot-ctl sh -c 'cat /proc/self/uid_map' | awk '{print "uid_map:", $0}'
  pycall='import socket,sys
s=socket.socket(socket.AF_UNIX); s.settimeout(30); s.connect("/run/hunter-rsm/rsm.sock")
s.sendall(b"{\"op\": \"status\"}\n"); print(s.makefile().readline().strip())'
  out="$(RL exec hv-pilot-ctl python3 -c "$pycall" 2>&1)"
  [[ "$(jget ok <<<"$out")" == True ]] && pass "rootless container root can use the socket (userns mapping)" \
    || fail "rootless container: $out"
  [[ "$(RL exec hv-pilot-ctl id -u)" == 0 ]] && pass "container uid 0 (maps to $CLIENT_USER, not host root)" || fail "uid"
  RL exec hv-pilot-ctl sh -c 'ls /var/run/docker.sock /run/docker.sock 2>&1' | grep -q "No such" \
    && pass "no Docker socket inside the container" || fail "docker socket visible in container"
  # broker restart while the controller keeps calling
  RL exec -d hv-pilot-ctl sh -c "while true; do python3 -c '$pycall' >/dev/null 2>>/tmp/fail || echo f >>/tmp/fail; sleep 0.2; done"
  for _ in 1 2 3; do sleep 1; systemctl restart hunter-rsm.service; sleep 1; done
  [[ ! -s <(RL exec hv-pilot-ctl cat /tmp/fail 2>/dev/null) ]] \
    && pass "controller unaffected by 3 broker restarts" || fail "controller saw failures"
  kill -9 "$(systemctl show -p MainPID --value hunter-rsm.service)"; sleep 4
  out="$(RL exec hv-pilot-ctl python3 -c "$pycall" 2>&1)"
  [[ "$(jget ok <<<"$out")" == True ]] && pass "service restarted after kill -9; same bind mount works" \
    || fail "after kill -9: $out"
  # rootless daemon (and container) started BEFORE the broker
  systemctl stop hunter-rsm.service hunter-rsm.socket
  RL restart hv-pilot-ctl >/dev/null
  systemctl start hunter-rsm.socket
  out="$(RL exec hv-pilot-ctl python3 -c "$pycall" 2>&1)"
  [[ "$(jget ok <<<"$out")" == True ]] && pass "container started before the broker still reaches it" \
    || fail "started-before-broker: $out"
  RL rm -f hv-pilot-ctl >/dev/null
else
  if [[ $REQUIRE_ROOTLESS -eq 1 ]]; then fail "rootless Docker for $CLIENT_USER is not running"
  else skip "rootless Docker not running for $CLIENT_USER (HIGH-2 namespace tests NOT executed)"; fi
fi

echo "=== sessions against DISPOSABLE rootful containers"
reset_world
S="$(sid)"
out="$(call "$CLIENT_USER" "{\"op\": \"prepare\", \"session_id\": \"$S\"}")"
[[ "$(jget ok <<<"$out")" == True ]] && pass "prepare" || fail "prepare: $out"
start=$(date +%s)
out="$(call "$CLIENT_USER" "{\"op\": \"stop_approved\", \"session_id\": \"$S\"}")"
took=$(( $(date +%s) - start ))
[[ "$(jget ok <<<"$out")" == True ]] && pass "stop_approved (${took}s)" || fail "stop: $out"
[[ $took -lt 60 ]] && pass "SIGTERM-ignoring container stopped within its bounded timeout" || fail "slow stop took ${took}s"
running hv-pilot-protected && pass "protected container untouched" || fail "protected container stopped"
c_end="$(docker inspect -f '{{.State.FinishedAt}}' hv-pilot-client)"
v_end="$(docker inspect -f '{{.State.FinishedAt}}' hv-pilot-vpn)"
[[ "$c_end" < "$v_end" || "$c_end" == "$v_end" ]] && pass "client (network user) stopped before its provider" || fail "stop order"
out="$(call "$CLIENT_USER" "{\"op\": \"restore\", \"session_id\": \"$S\"}")"
[[ "$(jget ok <<<"$out")" == True ]] && pass "restore" || fail "restore: $out"
for c in vpn client slow; do running "hv-pilot-$c" && pass "hv-pilot-$c running again" || fail "hv-pilot-$c not restored"; done
running hv-pilot-worker && pass "worker (restart=no, was running) restored" || fail "worker"
c_start="$(docker inspect -f '{{.State.StartedAt}}' hv-pilot-client)"
v_start="$(docker inspect -f '{{.State.StartedAt}}' hv-pilot-vpn)"
[[ "$v_start" < "$c_start" || "$v_start" == "$c_start" ]] && pass "provider started before client" || fail "start order"
[[ "$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' hv-pilot-client)" == unless-stopped ]] \
  && pass "restart policy preserved" || fail "restart policy changed"

echo "=== MEDIUM-2: real network namespace dependencies"
reset_world
policy_without_dependency; systemctl restart hunter-rsm.service
S="$(sid)"; out="$(call "$CLIENT_USER" "{\"op\": \"prepare\", \"session_id\": \"$S\"}")"
grep -q 'undeclared_dependency' <<<"$out" && pass "undeclared dependency refused" || fail "undeclared: $out"
running hv-pilot-client && running hv-pilot-vpn && pass "nothing stopped by the refused session" || fail "refusal stopped something"
policy_with_dependency; systemctl restart hunter-rsm.service
docker rm -f hv-pilot-vpn >/dev/null
docker run -d --name hv-pilot-vpn --restart unless-stopped alpine:3.20 sleep 3600 >/dev/null   # new id
S="$(sid)"; out="$(call "$CLIENT_USER" "{\"op\": \"prepare\", \"session_id\": \"$S\"}")"
grep -Eq 'stale_provider|ambiguous_provider' <<<"$out" && pass "provider recreated -> stale reference refused" \
  || fail "stale provider: $out"

echo "=== MEDIUM-3 / LOW-1: watchdog, corrupt state, administrator recovery"
reset_world
S="$(sid)"
call "$CLIENT_USER" "{\"op\": \"prepare\", \"session_id\": \"$S\"}" >/dev/null
call "$CLIENT_USER" "{\"op\": \"stop_approved\", \"session_id\": \"$S\"}" >/dev/null
kill -9 "$(systemctl show -p MainPID --value hunter-rsm.service)"
echo "waiting up to 240 s for the independent watchdog (stale 100 s + 30 s timer)..."
for _ in $(seq 1 48); do running hv-pilot-client && running hv-pilot-vpn && break; sleep 5; done
running hv-pilot-client && running hv-pilot-vpn && pass "watchdog restored containers after the broker died" \
  || fail "watchdog did not restore"
grep -q watchdog_restore /var/lib/hunter-rsm/audit.log && pass "watchdog action audited" || fail "audit"

reset_world
S="$(sid)"
call "$CLIENT_USER" "{\"op\": \"prepare\", \"session_id\": \"$S\"}" >/dev/null
call "$CLIENT_USER" "{\"op\": \"stop_approved\", \"session_id\": \"$S\"}" >/dev/null
cp /var/lib/hunter-rsm/session.json /root/hv-pilot-session.good
echo '{truncated' > /var/lib/hunter-rsm/session.json
out="$(call "$CLIENT_USER" '{"op": "status"}')"
[[ "$(jget code <<<"$out")" == state_corrupt ]] && pass "corrupt state reported, not treated as idle" || fail "corrupt: $out"
[[ "$(cat /var/lib/hunter-rsm/session.json)" == '{truncated' ]] && pass "corrupt file left in place" || fail "file was altered"
sudo -u hunter-rsm env PYTHONPATH=/opt/hunter-rsm/src python3 -m hunter.rsm admin show >/dev/null 2>&1
[[ $? -eq 5 ]] && pass "admin commands refuse non-root" || fail "admin ran as non-root"
PYTHONPATH=/opt/hunter-rsm/src python3 -m hunter.rsm admin recover-state --mode backup \
  --reason "pilot test: simulated truncation of session.json" >/dev/null 2>&1 \
  && pass "root recovered state from the backup" || fail "recover-state"
ls /var/lib/hunter-rsm/session.json.corrupt-* >/dev/null 2>&1 && pass "evidence preserved" || fail "no evidence file"
PYTHONPATH=/opt/hunter-rsm/src python3 -m hunter.rsm admin reconcile >/dev/null 2>&1
running hv-pilot-client && running hv-pilot-vpn && pass "admin reconcile restored the containers" || fail "reconcile"

docker ps -aq --filter "name=^hv-pilot-" | xargs -r docker rm -f >/dev/null
echo
echo "passed=$PASSED failed=$FAILED skipped=$SKIPPED"
[[ $FAILED -eq 0 ]]
