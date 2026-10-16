#!/usr/bin/env bash
# Installs the Resource Session Manager for a DISPOSABLE-CONTAINER-ONLY PILOT on Ubuntu 24.04.
# Run as root from the repository root:  sudo deploy/rsm/pilot/install-pilot.sh --client-user hunter-deploy
#
# What it does NOT do: it never touches an existing container, never adds anyone to the docker
# group, never installs or configures rootless Docker (a prerequisite you do separately), and
# never relaxes AppArmor or any sysctl. The generated policy can only name hv-pilot-* containers.
set -Eeuo pipefail
CLIENT_USER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --client-user) CLIENT_USER="${2:?}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }
[[ -n "$CLIENT_USER" ]] || { echo "--client-user <rootless docker user> is required" >&2; exit 2; }
id "$CLIENT_USER" >/dev/null 2>&1 || { echo "no such user: $CLIENT_USER" >&2; exit 2; }
[[ -f deploy/rsm/hunter-rsm.socket && -d hunter/rsm ]] || { echo "run from the repo root" >&2; exit 2; }
. /etc/os-release
[[ "${VERSION_ID:-}" == "24.04" ]] || echo "WARNING: tested target is Ubuntu 24.04 (found ${VERSION_ID:-?})" >&2

if id -nG "$CLIENT_USER" | tr ' ' '\n' | grep -qx docker; then
  echo "REFUSING: $CLIENT_USER is in the rootful 'docker' group (root-equivalent)." >&2
  echo "Remove it:  gpasswd -d $CLIENT_USER docker   and rerun." >&2
  exit 3
fi
CLIENT_UID="$(id -u "$CLIENT_USER")"
CLIENT_GROUP="$(id -gn "$CLIENT_USER")"      # PRIMARY group: container root maps to it
[[ "$CLIENT_GROUP" != docker ]] || { echo "primary group must not be 'docker'" >&2; exit 3; }

echo "== helper user"
id hunter-rsm >/dev/null 2>&1 || adduser --system --group --no-create-home --shell /usr/sbin/nologin hunter-rsm
usermod -aG docker hunter-rsm

echo "== code (root-owned, stdlib only)"
install -d -m 0755 -o root -g root /opt/hunter-rsm/src/hunter
install -m 0644 -o root -g root hunter/__init__.py /opt/hunter-rsm/src/hunter/__init__.py
rm -rf /opt/hunter-rsm/src/hunter/rsm
cp -r hunter/rsm /opt/hunter-rsm/src/hunter/rsm
find /opt/hunter-rsm -name __pycache__ -prune -exec rm -rf {} +
chown -R root:root /opt/hunter-rsm
find /opt/hunter-rsm -type d -exec chmod 0755 {} +
find /opt/hunter-rsm -type f -exec chmod 0644 {} +

echo "== policy (pilot: hv-pilot-* only)"
install -d -m 0755 -o root -g root /etc/hunter-rsm
python3 - <<'PY'
import json
doc = {
  "version": 1, "max_session_seconds": 900, "stale_contact_seconds": 100,
  "prepared_timeout_seconds": 120, "min_available_mib": 1,
  "protected": ["hv-pilot-protected"],
  "containers": {
    "hv-pilot-worker": {"stop_timeout": 5},
    "hv-pilot-slow":   {"stop_timeout": 5},
    "hv-pilot-client": {"stop_timeout": 5, "depends_on": ["hv-pilot-vpn"]},
    "hv-pilot-vpn":    {"stop_timeout": 5},
  },
}
open("/etc/hunter-rsm/policy.json", "w").write(json.dumps(doc, indent=2) + "\n")
PY
chown root:root /etc/hunter-rsm/policy.json && chmod 0644 /etc/hunter-rsm/policy.json

echo "== socket directory (stable, administrator-owned, outside /run and /etc)"
sed "s/__HUNTER_CLIENT_GROUP__/$CLIENT_GROUP/" deploy/rsm/tmpfiles-hunter-rsm.conf \
  > /etc/tmpfiles.d/hunter-rsm.conf
systemd-tmpfiles --create /etc/tmpfiles.d/hunter-rsm.conf

echo "== units"
sed "s/__HUNTER_CLIENT_GROUP__/$CLIENT_GROUP/" deploy/rsm/hunter-rsm.socket \
  > /etc/systemd/system/hunter-rsm.socket
sed "s/__HUNTER_ROOTLESS_UID__/$CLIENT_UID/" deploy/rsm/hunter-rsm.service \
  > /etc/systemd/system/hunter-rsm.service
install -m 0644 deploy/rsm/hunter-rsm-watchdog.service deploy/rsm/hunter-rsm-watchdog.timer \
  deploy/rsm/hunter-rsm-recover.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now hunter-rsm.socket hunter-rsm-recover.service hunter-rsm-watchdog.timer
echo "installed. client user=$CLIENT_USER uid=$CLIENT_UID group=$CLIENT_GROUP"
ls -l /var/lib/hunter-rsm-ipc/
