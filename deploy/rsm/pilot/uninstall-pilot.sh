#!/usr/bin/env bash
# Removes everything install-pilot.sh created. Never touches any container but hv-pilot-*.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }
systemctl disable --now hunter-rsm-watchdog.timer hunter-rsm.socket hunter-rsm.service \
  hunter-rsm-recover.service 2>/dev/null || true
rm -f /etc/systemd/system/hunter-rsm* /etc/tmpfiles.d/hunter-rsm.conf
systemctl daemon-reload
docker ps -aq --filter "name=^hv-pilot-" | xargs -r docker rm -f
rm -rf /opt/hunter-rsm /etc/hunter-rsm
echo "state kept for inspection: /var/lib/hunter-rsm /var/lib/hunter-rsm-ipc (remove by hand)"
