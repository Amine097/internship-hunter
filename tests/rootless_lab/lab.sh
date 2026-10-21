#!/usr/bin/env bash
# A throwaway REAL rootless Docker 29.9.1 (rootlesskit --net=slirp4netns --detach-netns, the
# production layout) for tests/test_dns_rootless_lab.py. No root, no host firewall, nothing outside
# its own directories. It differs from the production host in ONE way that does not touch
# networking: it maps a single uid (no subuid/newuidmap), so images with files owned by other
# users cannot be unpacked; the lab therefore uses an Alpine rootfs repacked with root ownership.
#
#   lab.sh up      [dns]   start the daemon (optional daemon-level `dns`), write $LAB/env.sh
#   lab.sh restart [dns]   stop and start it again (new network namespace, no guard)
#   lab.sh down
#
# Environment: HUNTER_LAB_DIR (state; default: a new mktemp dir, printed), HUNTER_LAB_CACHE
# (downloads; default ~/.cache/hunter-rootless-lab). iptables must be on PATH (or see
# GUARD_IPTABLES_DIR in tests/test_host_egress_guard_netns.py).
set -Eeuo pipefail
CACHE="${HUNTER_LAB_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/hunter-rootless-lab}"
LAB="${HUNTER_LAB_DIR:-}"
cmd="${1:-}"; DAEMON_DNS="${2:-}"

DOCKER_VER=29.9.1
COMPOSE_VER=v2.40.3
ALPINE_VER=3.20.3
URL_DOCKER="https://download.docker.com/linux/static/stable/x86_64/docker-$DOCKER_VER.tgz"
SHA_DOCKER=c158ecc55adb3afb01bbd3539ed3b997d20c26dbdc418080506cc1bf5243ff57
URL_EXTRAS="https://download.docker.com/linux/static/stable/x86_64/docker-rootless-extras-$DOCKER_VER.tgz"
SHA_EXTRAS=c87668896a3fced2e715324e9fb6a0634aba3e5d8408a471f6bc23dc476662af
URL_COMPOSE="https://github.com/docker/compose/releases/download/$COMPOSE_VER/docker-compose-linux-x86_64"
SHA_COMPOSE=dba9d98e1ba5bfe11d88c99b9bd32fc4a0624a30fafe68eea34d61a3e42fd372
URL_SLIRP="https://github.com/rootless-containers/slirp4netns/releases/download/v1.3.3/slirp4netns-x86_64"
SHA_SLIRP=5618887b671a30a2f7548f2bdf7fba98a53981abc80cfd3183cd28b4dc8b2b97
URL_ALPINE="https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-$ALPINE_VER-x86_64.tar.gz"
SHA_ALPINE=d4e6fd67dcf75e40c451560ac7265166c2b72a0f38ddc9aae756a7de3d1efa0c

die() { echo "lab: $*" >&2; exit 1; }

fetch() { # fetch <url> <sha256> -> path in the cache (verified; a bad download is never used)
  local url="$1" sha="$2" f
  f="$CACHE/$(basename "$1")"
  mkdir -p "$CACHE"
  if [[ ! -f "$f" ]] || [[ "$(sha256sum "$f" | cut -d' ' -f1)" != "$sha" ]]; then
    curl -fsSL --retry 4 --retry-delay 3 -o "$f.part" "$url" || die "download failed: $url"
    mv "$f.part" "$f"
  fi
  [[ "$(sha256sum "$f" | cut -d' ' -f1)" == "$sha" ]] || die "checksum mismatch for $f (expected $sha)"
  echo "$f"
}

prepare() {
  [[ -n "$LAB" ]] || LAB="$(mktemp -d)"
  mkdir -p "$LAB/bin" "$LAB/data" "$LAB/home/.config/docker" "$LAB/cli/cli-plugins" "$LAB/img"
  XDG="$LAB/xdg-path"
  if [[ ! -s "$LAB/xdg-path" ]]; then mktemp -d /tmp/hl.XXXXXX >"$LAB/xdg-path"; fi
  XDG="$(<"$LAB/xdg-path")"; chmod 700 "$XDG"
  unshare -Ur true 2>/dev/null || die "unprivileged user namespaces are not available"
  command -v iptables >/dev/null || die "iptables is not on PATH"
  if [[ ! -x "$LAB/bin/dockerd" ]]; then
    local t
    t="$(fetch "$URL_DOCKER" "$SHA_DOCKER")"; tar xzf "$t" -C "$LAB" && cp -a "$LAB"/docker/. "$LAB/bin/"
    t="$(fetch "$URL_EXTRAS" "$SHA_EXTRAS")"; tar xzf "$t" -C "$LAB" && cp -a "$LAB"/docker-rootless-extras/. "$LAB/bin/"
    cp "$(fetch "$URL_SLIRP" "$SHA_SLIRP")" "$LAB/bin/slirp4netns"
    cp "$(fetch "$URL_COMPOSE" "$SHA_COMPOSE")" "$LAB/bin/docker-compose"
    chmod +x "$LAB/bin/"*
    ln -sf "$LAB/bin/docker-compose" "$LAB/cli/cli-plugins/docker-compose"
    # single-uid stand-ins for the setuid helpers (a process may map its own uid for a child)
    printf '#!/bin/sh\nexit 0\n' >"$LAB/bin/getsubids"
    cat >"$LAB/bin/newuidmap" <<'MAP'
#!/bin/sh
pid=$1; shift
echo "$1 $2 $3" > /proc/$pid/uid_map
MAP
    cat >"$LAB/bin/newgidmap" <<'MAP'
#!/bin/sh
pid=$1; shift
echo deny > /proc/$pid/setgroups
echo "$1 $2 $3" > /proc/$pid/gid_map
MAP
    # runc wrapper. (1) with one gid mapped the default devpts option gid=5 cannot be applied;
    # (2) a runner without a systemd user session cannot create the cgroup scope Docker asks for
    # (limits are not under test), so `--systemd-cgroup` is removed and the spec's cgroupsPath/resources
    # are dropped.
    cat >"$LAB/bin/runcw" <<RUNC
#!/bin/bash
prev=""
args=()
echo "\$*" >>"$LAB/runc.args"
for a in "\$@"; do
  [ "\$a" = "--systemd-cgroup" ] && continue
  args+=("\$a")
  if [ "\$prev" = "--bundle" ] && [ -f "\$a/config.json" ]; then
    python3 - "\$a/config.json" <<'PY'
import json, sys
p = sys.argv[1]
c = json.load(open(p))
for m in c.get("mounts", []):
    if m.get("destination") == "/dev/pts":
        m["options"] = [o for o in m.get("options", []) if o != "gid=5"]
lin = c.get("linux", {})
lin.pop("cgroupsPath", None)
lin.pop("resources", None)
json.dump(c, open(p, "w"))
PY
  fi
  prev="\$a"
done
exec "$LAB/bin/runc" "\${args[@]}"
RUNC
    chmod +x "$LAB/bin/getsubids" "$LAB/bin/newuidmap" "$LAB/bin/newgidmap" "$LAB/bin/runcw"
  fi
  if [[ ! -f "$LAB/img/rootfs.tar" ]]; then
    mkdir -p "$LAB/img/root"
    tar xzf "$(fetch "$URL_ALPINE" "$SHA_ALPINE")" -C "$LAB/img/root" --no-same-owner
    tar -C "$LAB/img/root" --owner=0 --group=0 --numeric-owner -cf "$LAB/img/rootfs.tar" .
  fi
}

write_env() {
  cat >"$LAB/env.sh" <<ENV
export HUNTER_LAB_DIR='$LAB'
export XDG_RUNTIME_DIR='$XDG'
export DOCKER_HOST='unix://$XDG/docker.sock'
export DOCKER_CONFIG='$LAB/cli'
export PATH='$LAB/bin':\$PATH
ENV
}

start() {
  local dns="$1" j=""
  [[ -z "$dns" ]] || j=", \"dns\": [\"$dns\"]"
  # cgroupfs: a CI runner has no systemd user session to hand cgroups to (limits are not under test)
  echo "{\"runtimes\": {\"runcw\": {\"path\": \"$LAB/bin/runcw\"}}, \"default-runtime\": \"runcw\", \"exec-opts\": [\"native.cgroupdriver=cgroupfs\"]$j}" \
    >"$LAB/home/.config/docker/daemon.json"
  (
    export XDG_RUNTIME_DIR="$XDG" HOME="$LAB/home" PATH="$LAB/bin:$PATH" DOCKERD_ROOTLESS_ROOTLESSKIT_NET=slirp4netns
    export DOCKERD_ROOTLESS_ROOTLESSKIT_FLAGS="--subid-source=dynamic"
    exec setsid "$LAB/bin/dockerd-rootless.sh" --group root --data-root "$LAB/data" --host "unix://$XDG/docker.sock" \
      >"$LAB/dockerd.log" 2>&1
  ) &
  for _ in $(seq 1 60); do
    DOCKER_HOST="unix://$XDG/docker.sock" "$LAB/bin/docker" info >/dev/null 2>&1 && break
    sleep 1
  done
  DOCKER_HOST="unix://$XDG/docker.sock" "$LAB/bin/docker" info >/dev/null 2>&1 \
    || { tail -20 "$LAB/dockerd.log" >&2; die "the rootless daemon did not start"; }
  DOCKER_HOST="unix://$XDG/docker.sock" "$LAB/bin/docker" info --format '{{.SecurityOptions}}' | grep -q rootless \
    || die "the daemon is not rootless"
  DOCKER_HOST="unix://$XDG/docker.sock" "$LAB/bin/docker" image inspect alpine-local:3.20 >/dev/null 2>&1 \
    || DOCKER_HOST="unix://$XDG/docker.sock" "$LAB/bin/docker" import "$LAB/img/rootfs.tar" alpine-local:3.20 >/dev/null
  write_env
}

stop() {
  local pidf="$XDG/docker.pid"
  if [[ -f "$pidf" ]]; then kill "$(<"$pidf")" 2>/dev/null || true; fi
  for _ in $(seq 1 30); do pgrep -f "rootlesskit --state-dir=$XDG" >/dev/null 2>&1 || break; sleep 1; done
  pkill -f "rootlesskit --state-dir=$XDG" 2>/dev/null || true
  sleep 1
}

case "$cmd" in
  up)      prepare; start "$DAEMON_DNS"; echo "$LAB" ;;
  restart) [[ -n "$LAB" ]] || die "HUNTER_LAB_DIR is required"; prepare; stop; rm -rf "${XDG:?}"/* 2>/dev/null || true; start "$DAEMON_DNS" ;;
  down)    [[ -n "$LAB" ]] || die "HUNTER_LAB_DIR is required"; XDG="$(<"$LAB/xdg-path")"; stop; rm -rf "${XDG:?}" "$LAB" ;;
  *)       die "usage: lab.sh up|restart|down [daemon-dns]" ;;
esac
