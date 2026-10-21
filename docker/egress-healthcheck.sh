#!/bin/sh
# Healthcheck of an egress proxy: it must be listening AND must NOT be able to reach anything in
# EGRESS_FORBIDDEN_TARGETS (egress-forbidden-check.sh: connected or refused both count as
# reaching). A reachable forbidden target means the host-level guard (deploy/host-egress-guard.sh)
# is missing: report "unhealthy" so the agents behind this proxy are not started and
# `compose up --wait` fails. This detects a missing guard; it does not replace it.
set -eu
nc -z 127.0.0.1 3128 >/dev/null 2>&1 || exit 1
exec "$(dirname "$0")/egress-forbidden-check.sh"
