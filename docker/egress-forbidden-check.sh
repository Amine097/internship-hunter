#!/bin/sh
# Exit 0 only if (1) the probe tool is proven to work in THIS container and (2) NONE of
# EGRESS_FORBIDDEN_TARGETS (comma-separated ip:port) answered. Used by the egress proxy both at
# START (a proxy that can reach the host must not serve a single request, even in the seconds
# after a daemon restart before the host guard is re-applied) and by its healthcheck.
#
# FAIL-CLOSED. Only these outcomes are accepted as isolation: the connect attempt ended with
# "unreachable", "prohibited"/"permission denied", or "timed out". Connection success, a REFUSAL
# (it comes from the protected side: the packet got there), a missing or broken `nc`, an option
# the local nc does not understand, an empty or unrecognised message, a malformed target: all
# make this script exit 1. It never reasons "no error text => fine".
#
# Self-test first (a tool that always says "no" would otherwise prove isolation): `nc` must exist,
# must recognise a REFUSAL on a closed local port, and must see an OPEN local listener.
# Message texts (LC_ALL=C) are those of Alpine 3.20's busybox `nc -vv -z`: "Connection refused" /
# "Host is unreachable" / "Network unreachable" / "Operation timed out" (note that `nc -z` WITHOUT
# -vv is silent on a refusal). An unset or empty list passes (development, CI) - production
# deploys require it to be set (deploy/remote-deploy.sh).
set -eu
LC_ALL=C
export LC_ALL
targets="${EGRESS_FORBIDDEN_TARGETS:-}"
[ -n "$targets" ] || exit 0
fail() { echo "egress-forbidden-check: $*" >&2; exit 1; }

command -v nc >/dev/null 2>&1 || fail "nc is missing: cannot prove host isolation"

# --- self-test: refusal is recognised ---------------------------------------------------------
rc=0; out="$(nc -vv -z -w 1 127.0.0.1 1 2>&1)" || rc=$?
[ "$rc" -ne 0 ] || fail "self-test: nc connected to a closed local port"
case "$out" in *[Rr]efused*) ;; *) fail "self-test: nc does not report 'Connection refused' (got: $out)" ;; esac
# --- self-test: an open listener is seen as open (3128: the proxy's own port) -------------------
lp=""
if ! nc -z -w 1 127.0.0.1 3128 >/dev/null 2>&1; then      # not serving yet (start gate): make one
  nc -l -p 3128 >/dev/null 2>&1 &
  lp=$!
  sleep 0.3
fi
rc=0; nc -vv -z -w 1 127.0.0.1 3128 >/dev/null 2>&1 || rc=$?
[ -z "$lp" ] || { kill "$lp" 2>/dev/null || true; wait "$lp" 2>/dev/null || true; }
[ "$rc" -eq 0 ] || fail "self-test: nc cannot connect to a local listener on 3128"

# --- the targets ----------------------------------------------------------------------------------
old_ifs=$IFS; IFS=,
for t in $targets; do
  IFS=$old_ifs
  t="$(printf '%s' "$t" | tr -d ' ')"
  case "$t" in
    *[!0-9.:]*|''|*:|:*|*:*:*) fail "invalid EGRESS_FORBIDDEN_TARGETS entry: '$t'" ;;
  esac
  case "${t##*:}" in *[!0-9]*|'') fail "invalid port in '$t'" ;; esac
  rc=0; out="$(nc -vv -z -w 1 "${t%:*}" "${t##*:}" 2>&1)" || rc=$?
  [ "$rc" -ne 0 ] || fail "host isolation breach: $t is reachable from this proxy"
  case "$out" in
    *[Rr]efused*) fail "host isolation breach: $t answered (connection refused) from this proxy" ;;
    *[Uu]nreachable*|*"timed out"*|*"Permission denied"*|*"not permitted"*|*[Pp]rohibited*) ;;
    *) fail "unrecognised result for $t (not an isolation error): '$out'" ;;
  esac
  IFS=,
done
IFS=$old_ifs
exit 0
