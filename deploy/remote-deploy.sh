#!/usr/bin/env bash
# Server-side deploy entrypoint, installed as the SSH *forced command* of the CI key:
#   restrict,command="/opt/internship-hunter/deploy/remote-deploy.sh" ssh-ed25519 AAAA... ci-deploy
# Receives a tar.gz of the repo on stdin; SSH_ORIGINAL_COMMAND is "deploy <sha>" or "rollback".
# Runs as an unprivileged `hunter-deploy` user, never as root, and never exposes a shell.
set -euo pipefail

BASE="${HUNTER_BASE:-/opt/internship-hunter}"
CMD="${SSH_ORIGINAL_COMMAND:-}"
read -r ACTION ARG EXTRA <<<"$CMD"
[[ -z "${EXTRA:-}" ]] || { echo "bad command" >&2; exit 2; }

compose() { (cd "$BASE/current" && docker compose --env-file "$BASE/shared/.env" "$@"); }

case "$ACTION" in
  deploy)
    [[ "${ARG:-}" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid sha" >&2; exit 2; }
    [[ -f "$BASE/shared/.env" ]] || { echo "missing $BASE/shared/.env" >&2; exit 3; }
    rel="$BASE/releases/$ARG"
    mkdir -p "$rel"
    tar -xzf - -C "$rel" --no-same-owner --no-same-permissions
    prev="$(readlink -f "$BASE/current" || true)"
    ln -sfn "$rel" "$BASE/current.new" && mv -Tf "$BASE/current.new" "$BASE/current"
    [[ -n "$prev" ]] && ln -sfn "$prev" "$BASE/previous"
    compose config -q
    compose up -d --build --remove-orphans --wait --wait-timeout 300
    curl -fsS --retry 10 --retry-delay 3 --retry-connrefused http://127.0.0.1:8000/ready
    curl -fsS http://127.0.0.1:8000/health | grep -q '"submission_enabled":false'
    ls -1dt "$BASE"/releases/* | tail -n +6 | xargs -r rm -rf
    echo "deployed $ARG"
    ;;
  rollback)
    [[ -L "$BASE/previous" ]] || { echo "no previous release" >&2; exit 3; }
    ln -sfn "$(readlink -f "$BASE/previous")" "$BASE/current.new" && mv -Tf "$BASE/current.new" "$BASE/current"
    compose up -d --build --remove-orphans --wait --wait-timeout 300
    echo "rolled back"
    ;;
  *)
    echo "unsupported command" >&2; exit 2 ;;
esac
