#!/bin/sh
# Allow-list forward proxy for ONE agent. Only CONNECT to :443 on listed hostnames succeeds;
# everything else (other hosts, IP literals, other ports, plain HTTP) is refused.
# EGRESS_ALLOW: comma-separated exact hostnames, e.g. "api.anthropic.com,claude.ai".
set -eu
: "${EGRESS_ALLOW:?EGRESS_ALLOW must list the permitted hostnames}"
conf=/tmp/tinyproxy.conf
allow=/tmp/allow.txt
: > "$allow"
old_ifs=$IFS; IFS=,
for host in $EGRESS_ALLOW; do
  host="$(printf '%s' "$host" | tr -d ' ')"
  case "$host" in
    ''|*[!A-Za-z0-9.-]*) echo "invalid hostname in EGRESS_ALLOW: '$host'" >&2; exit 1 ;;
  esac
  printf '^%s$\n' "$(printf '%s' "$host" | sed 's/\./\\./g')" >> "$allow"
done
IFS=$old_ifs
cat > "$conf" <<CONF
Port 3128
Listen 0.0.0.0
Timeout 600
MaxClients 16
LogLevel Notice
DisableViaHeader Yes
ConnectPort 443
FilterDefaultDeny Yes
Filter "$allow"
FilterType ere
FilterURLs Off
CONF
exec tinyproxy -d -c "$conf"
