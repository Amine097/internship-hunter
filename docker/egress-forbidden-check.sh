#!/bin/sh
# Exit 0 only if NONE of EGRESS_FORBIDDEN_TARGETS (comma-separated ip:port) answered. Used by the
# egress proxy both at START (a proxy that can reach the host must not serve a single request,
# even in the seconds after a daemon restart before the host guard is re-applied) and by its
# healthcheck. "Answered" = connected, or ECONNREFUSED: a refusal comes from the protected side,
# so the packet got there. Only timeouts / unreachable / prohibited pass.
# (busybox `nc -vv -z` reports "Connection refused" / "Host is unreachable" / "Operation timed
# out"; deploy/check-host-isolation.sh is calibrated against the same texts.)
# An unset or empty list passes (development, CI); production deploys require it to be set.
set -eu
targets="${EGRESS_FORBIDDEN_TARGETS:-}"
[ -n "$targets" ] || exit 0
old_ifs=$IFS; IFS=,
for t in $targets; do
  t="$(printf '%s' "$t" | tr -d ' ')"
  case "$t" in
    *[!0-9.:]*|''|*:|:*|*:*:*) echo "invalid EGRESS_FORBIDDEN_TARGETS entry: '$t'" >&2; exit 1 ;;
  esac
  case "${t##*:}" in *[!0-9]*|'') echo "invalid port in '$t'" >&2; exit 1 ;; esac
  rc=0
  out="$(nc -vv -z -w 1 "${t%:*}" "${t##*:}" 2>&1)" || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "host isolation breach: $t is reachable from this proxy" >&2
    exit 1
  fi
  case "$out" in
    *[Rr]efused*) echo "host isolation breach: $t answered (connection refused) from this proxy" >&2; exit 1 ;;
  esac
done
IFS=$old_ifs
exit 0
