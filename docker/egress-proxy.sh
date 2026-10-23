#!/bin/sh
# Allow-listing CONNECT proxy for ONE agent. The policy lives in hunter-egress-proxy
# (docker/egress_proxy.py): only `CONNECT <listed-host>:443`, resolved by the proxy to global
# unicast IPv4 only, and a TLS handshake whose SNI is exactly that host; everything else (other
# hosts, IP literals, other ports, plain-HTTP forwarding, a different or missing SNI, Encrypted
# Client Hello) is refused or cut. This wrapper only keeps the start gate.
# EGRESS_ALLOW: comma-separated exact hostnames, e.g. "api.anthropic.com,platform.claude.com".
set -eu
: "${EGRESS_ALLOW:?EGRESS_ALLOW must list the permitted hostnames}"
# Fail closed at START: never serve while a forbidden host address answers. After a daemon
# restart the restart policy can start this container before the host guard is re-applied;
# exiting makes the policy retry until the guard is in place (docs/deployment.md, "Startup window").
"$(dirname "$0")/egress-forbidden-check.sh" || { echo "egress-proxy: refusing to start" >&2; exit 1; }
exec hunter-egress-proxy
