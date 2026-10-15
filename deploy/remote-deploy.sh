#!/usr/bin/env bash
# Server-side deploy entrypoint, installed as the SSH *forced command* of the CI key:
#   restrict,command="/opt/internship-hunter/deploy/remote-deploy.sh" ssh-ed25519 AAAA... ci-deploy
# SSH_ORIGINAL_COMMAND is exactly "deploy" (signed release bundle on stdin) or "rollback".
#
# Properties:
#  * the bundle must carry a manifest signed with the release-signing key (separate from the
#    SSH key) whose public half lives in $BASE/shared/allowed_signers; hashes of the source
#    archive and the pre-built images are checked against the signed manifest
#  * images are immutable, tagged by commit SHA, and loaded - never built - on this host
#  * one deploy at a time (flock); failed deploys restore the previous release automatically
#  * rollback re-uses already-loaded images: no build, no registry, no network
#  * refuses to run against a rootful Docker daemon unless HUNTER_ALLOW_ROOTFUL=1
set -Eeuo pipefail

BASE="${HUNTER_BASE:-/opt/internship-hunter}"
MAX_BUNDLE_BYTES="${HUNTER_MAX_BUNDLE_BYTES:-3221225472}"   # 3 GiB
KEEP_RELEASES=5
PROJECT=internship-hunter
SIGN_NAMESPACE=hunter-release

die() { echo "deploy: $1" >&2; exit "${2:-1}"; }
state() { echo "$BASE/state/$1"; }

compose() { # compose <sha> <args...>
  # RELEASE_SHA is passed as an env-file *and* env var so no env-forwarding quirk can make
  # compose fall back to a mutable tag (activate() additionally verifies what is running).
  local sha="$1" relenv; shift
  relenv="$BASE/state/release-$sha.env"
  printf 'RELEASE_SHA=%s\n' "$sha" > "$relenv"
  (cd "$BASE/releases/$sha" && RELEASE_SHA="$sha" \
     docker compose -p "$PROJECT" --env-file "$BASE/shared/.env" --env-file "$relenv" "$@")
}

health_check() {
  curl -fsS --retry 10 --retry-delay 3 --retry-connrefused http://127.0.0.1:8000/ready >/dev/null
  curl -fsS http://127.0.0.1:8000/health | grep -q '"submission_enabled":false'
}

activate() { # activate <sha>: start (never build) the release, then verify health
  # Explicit `|| return`: errexit is suppressed when this runs inside `if !`/`||`.
  local sha="$1"
  docker image inspect "internship-hunter-app:$sha" >/dev/null 2>&1 \
    || { echo "deploy: image internship-hunter-app:$sha is not loaded" >&2; return 3; }
  docker image inspect "internship-hunter-agent:$sha" >/dev/null 2>&1 \
    || { echo "deploy: image internship-hunter-agent:$sha is not loaded" >&2; return 3; }
  compose "$sha" config -q || return 1
  compose "$sha" up -d --no-build --remove-orphans --wait --wait-timeout 300 || return 1
  verify_running_images "$sha" || return 1
  health_check || return 1
}

verify_running_images() { # every first-party container must run exactly this release's images
  local sha="$1" images bad n
  images="$(compose "$sha" ps --format '{{.Image}}')" || return 1
  bad="$(grep '^internship-hunter-' <<<"$images" | grep -v ":$sha\$" || true)"
  n="$(grep -c "^internship-hunter-.*:$sha\$" <<<"$images" || true)"
  if [[ -n "$bad" || "$n" -lt 7 ]]; then
    echo "deploy: containers are not running release $sha (found: ${bad:-only $n matching})" >&2
    return 1
  fi
}

set_current() { ln -sfn "$BASE/releases/$1" "$BASE/current.new" && mv -Tf "$BASE/current.new" "$BASE/current"; }

require_rootless() {
  [[ "${HUNTER_ALLOW_ROOTFUL:-0}" == 1 ]] && return 0
  docker info --format '{{.SecurityOptions}}' | grep -q rootless \
    || die "refusing to deploy: Docker daemon is not rootless (see docs/deployment.md)" 5
}

do_rollback() {
  local current previous
  current="$(cat "$(state current_sha)" 2>/dev/null || true)"
  previous="$(cat "$(state previous_sha)" 2>/dev/null || true)"
  [[ "$previous" =~ ^[0-9a-f]{40}$ ]] || die "no previous release recorded" 3
  [[ -d "$BASE/releases/$previous" ]] || die "previous release directory missing" 3
  activate "$previous" || die "rollback target failed health check" 6
  set_current "$previous"
  echo "$previous" > "$(state current_sha)"
  [[ -n "$current" ]] && echo "$current" > "$(state previous_sha)"
  echo "rolled back to $previous (DB schema is NOT downgraded; see docs/backup-restore.md)"
}

do_deploy() {
  [[ -f "$BASE/shared/.env" ]] || die "missing $BASE/shared/.env" 3
  [[ -f "$BASE/shared/allowed_signers" ]] || die "missing $BASE/shared/allowed_signers" 3

  local stage; stage="$(mktemp -d "$BASE/staging/bundle.XXXXXX")"
  STAGE="$stage"

  head -c "$((MAX_BUNDLE_BYTES + 1))" > "$stage/bundle.tar"
  [[ "$(stat -c %s "$stage/bundle.tar")" -le "$MAX_BUNDLE_BYTES" ]] || die "bundle too large" 2
  local members; members="$(tar -tf "$stage/bundle.tar" | LC_ALL=C sort | tr '\n' ' ')"
  [[ "$members" == "images.tar.gz manifest manifest.sig source.tar.gz " ]] \
    || die "unexpected bundle members: $members" 2
  tar -xf "$stage/bundle.tar" -C "$stage" --no-same-owner --no-same-permissions

  # 1) signature over the manifest
  ssh-keygen -Y verify -f "$BASE/shared/allowed_signers" -I release -n "$SIGN_NAMESPACE" \
    -s "$stage/manifest.sig" < "$stage/manifest" >/dev/null 2>&1 \
    || die "manifest signature verification FAILED" 7

  # 2) strict manifest parsing
  local sha src_hash img_hash created
  sha="$(sed -n 's/^sha=\([0-9a-f]\{40\}\)$/\1/p' "$stage/manifest")"
  src_hash="$(sed -n 's/^source_sha256=\([0-9a-f]\{64\}\)$/\1/p' "$stage/manifest")"
  img_hash="$(sed -n 's/^images_sha256=\([0-9a-f]\{64\}\)$/\1/p' "$stage/manifest")"
  created="$(sed -n 's/^created=\([0-9]\{10\}\)$/\1/p' "$stage/manifest")"
  [[ -n "$sha" && -n "$src_hash" && -n "$img_hash" && -n "$created" ]] || die "bad manifest" 2
  [[ "$(wc -l < "$stage/manifest")" -eq 4 ]] || die "bad manifest (extra lines)" 2

  # 3) artifact integrity
  [[ "$(sha256sum "$stage/source.tar.gz" | cut -d' ' -f1)" == "$src_hash" ]] \
    || die "source archive hash mismatch" 7
  [[ "$(sha256sum "$stage/images.tar.gz" | cut -d' ' -f1)" == "$img_hash" ]] \
    || die "image archive hash mismatch" 7

  # 4) replay/downgrade protection: a validly signed but OLDER bundle is refused
  local last_created; last_created="$(cat "$(state current_created)" 2>/dev/null || echo 0)"
  [[ "$created" -ge "$last_created" ]] || die "bundle is older than the running release" 7

  # 5) unpack source safely
  if tar -tzf "$stage/source.tar.gz" | grep -Eq '^/|(^|/)\.\.(/|$)'; then
    die "source archive contains unsafe paths" 2
  fi
  local rel="$BASE/releases/$sha"
  rm -rf "$rel.partial"; mkdir -p "$rel.partial"
  tar -xzf "$stage/source.tar.gz" -C "$rel.partial" --no-same-owner --no-same-permissions
  rm -rf "$rel"; mv "$rel.partial" "$rel"

  # 6) immutable images: load, never build
  docker load -i "$stage/images.tar.gz" >/dev/null

  local previous; previous="$(cat "$(state current_sha)" 2>/dev/null || true)"

  # 7) database backup before anything is changed (skipped on the very first deploy)
  if [[ -n "$previous" ]] && compose "$previous" ps -q postgres 2>/dev/null | grep -q .; then
    mkdir -p "$BASE/backups"
    local dump stamp
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    dump="$BASE/backups/pre-$sha-$stamp.sql.gz"
    compose "$previous" exec -T postgres pg_dump -U hunter hunter | gzip > "$dump" \
      || die "pg_dump failed; aborting before any change" 8
    [[ -s "$dump" ]] || die "empty backup; aborting" 8
    # shellcheck disable=SC2012  # names are generated by this script (sha + timestamp)
    ls -1t "$BASE"/backups/pre-*.sql.gz | tail -n +11 | xargs -r rm -f
  fi

  # 8) switch; any failure restores the previous release
  if ! ( set_current "$sha" && activate "$sha" ); then
    echo "deploy: $sha failed; restoring ${previous:-<none>}" >&2
    if [[ -n "$previous" ]]; then
      set_current "$previous"
      activate "$previous" || echo "deploy: RESTORE ALSO FAILED - manual intervention" >&2
    fi
    exit 1
  fi
  [[ -n "$previous" && "$previous" != "$sha" ]] && echo "$previous" > "$(state previous_sha)"
  echo "$sha" > "$(state current_sha)"
  echo "$created" > "$(state current_created)"

  # 9) prune old releases, never current or previous
  local keep_prev; keep_prev="$(cat "$(state previous_sha)" 2>/dev/null || true)"
  # shellcheck disable=SC2012  # directory names are 40-hex commit SHAs
  ls -1dt "$BASE"/releases/*/ 2>/dev/null | tail -n +$((KEEP_RELEASES + 1)) | while read -r d; do
    name="$(basename "$d")"
    [[ "$name" == "$sha" || "$name" == "$keep_prev" ]] && continue
    rm -rf "$d"
    docker image rm "internship-hunter-app:$name" "internship-hunter-agent:$name" >/dev/null 2>&1 || true
  done
  echo "deployed $sha"
}

STAGE=""
trap '[[ -z "$STAGE" ]] || rm -rf "$STAGE"' EXIT

main() {
  mkdir -p "$BASE"/{releases,state,staging,shared}
  exec 9>"$BASE/state/deploy.lock"
  flock -n 9 || die "another deploy is running" 4
  case "${SSH_ORIGINAL_COMMAND:-}" in
    deploy)   require_rootless; do_deploy ;;
    rollback) require_rootless; do_rollback ;;
    *)        die "unsupported command" 2 ;;
  esac
}
main
