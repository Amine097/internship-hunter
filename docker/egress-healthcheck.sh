#!/bin/sh
# Healthcheck of an egress proxy: it must be listening AND must NOT be able to open a TCP
# connection to any address in EGRESS_FORBIDDEN_TARGETS (comma-separated host:port, e.g. the
# Docker host's Tailscale IP on 22 and 8000). A reachable forbidden target means the host-level
# guard (deploy/host-egress-guard.sh) is missing: report "unhealthy" so the agents behind this
# proxy are not started and `compose up --wait` fails. This detects a missing guard; it does
# not replace it. An unset/empty list checks only the listener (development, CI).
set -eu
nc -z 127.0.0.1 3128 >/dev/null 2>&1 || exit 1
targets="${EGRESS_FORBIDDEN_TARGETS:-}"
[ -n "$targets" ] || exit 0
old_ifs=$IFS; IFS=,
for t in $targets; do
  t="$(printf '%s' "$t" | tr -d ' ')"
  case "$t" in
    *[!A-Za-z0-9.:-]*|''|*:|:*|*:*:*) echo "invalid EGRESS_FORBIDDEN_TARGETS entry: '$t'" >&2; exit 1 ;;
  esac
  case "${t##*:}" in *[!0-9]*|'') echo "invalid port in '$t'" >&2; exit 1 ;; esac
  # a reachable target is the failure; a refused/blocked/timed-out one is the pass
  if nc -z -w 1 "${t%:*}" "${t##*:}" >/dev/null 2>&1; then
    echo "host isolation breach: $t is reachable from this proxy" >&2
    exit 1
  fi
done
IFS=$old_ifs
exit 0
