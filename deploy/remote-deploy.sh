#!/usr/bin/env bash
# Server-side deploy entrypoint, installed as the SSH *forced command* of the CI key:
#   restrict,command="/opt/internship-hunter/deploy/remote-deploy.sh" ssh-ed25519 AAAA... ci-deploy
# SSH_ORIGINAL_COMMAND is exactly one of:
#   deploy               signed release bundle on stdin; refused if rollback would be unsafe
#   deploy-irreversible  same, but the operator accepts that rollback to the running release
#                        will NOT be possible (contracting migration); backup is mandatory
#   rollback             re-activate the previous release from already-loaded images
#
# Properties:
#  * manifest signed with the release-signing key (separate from the SSH key); hashes of the
#    source archive and pre-built images are checked against the signed manifest
#  * only regular files/directories are accepted in the bundle and the source archive
#  * images are immutable, tagged by commit SHA, loaded - never built - on this host
#  * schema compatibility with the rollback target is checked BEFORE anything changes
#  * one deploy at a time (flock); failed deploys restore the previous release
#  * rollback is only reported successful after images, health and schema were verified
#  * talks only to the ROOTLESS daemon: DOCKER_HOST is pinned to the user's own socket (never the
#    rootful /var/run/docker.sock) and a daemon that is not rootless is refused (exit 5)
#  * refuses to deploy or roll back unless host isolation is in place (docs/deployment.md, "Host
#    isolation"): the root-owned host-egress-guard.sh reports its FULL policy active (exit 12),
#    EGRESS_FORBIDDEN_TARGETS is set (exit 11), and after `up --wait` the root-owned
#    check-host-isolation.sh passes in ENFORCE mode from every container with a route out, and the
#    root-owned check-dns.sh confirms DNS takes the guard-policed path (the resolver is the one
#    host-egress-guard.conf allows) and that internal-only services resolve nothing outside; before
#    anything is loaded or started the RENDERED compose dns must equal that conf's DNS= (the caller's
#    HUNTER_DNS is ignored); a failure is a failed activation (previous release restored; a first
#    deploy is torn down)
#  * runtime containment: refuses to deploy unless the root-owned runtime-containment.sh watchdog is
#    alive and not latched (exit 13); a release is committed to it only after every gate above passed
#    (it then supervises the services with a route out and the agents: docs/deployment.md, "Runtime
#    containment"), and a stack this script tears down is recorded as intentionally stopped
#  * exit codes: 2 bad input, 3 missing files/ports, 4 locked, 5 not rootless, 7 integrity,
#    8 backup, 9 schema, 10/6 restore failed (stack stopped), 11 isolation prerequisites, 12 guard,
#    13 runtime containment inactive or latched, 14 a release that predates runtime containment cannot be
#    restored under it (deploy-irreversible acknowledges it; a rollback to it is refused before anything changes)
set -Eeuo pipefail

# ---- the forced-command boundary --------------------------------------------------------------
# Whatever environment the caller arrives with, production runs ONLY against /opt/internship-hunter
# with the system's tools and none of the test hooks. The hooks (HUNTER_TEST_MODE, HUNTER_BASE,
# HUNTER_MAX_BUNDLE_BYTES; they exist for tests/test_deploy_script.py: stub docker, files owned by
# the test user) are honoured together or not at all, and never against the production directory.
PROD_BASE=/opt/internship-hunter
if [[ "${HUNTER_TEST_MODE:-0}" == 1 ]]; then
  TEST_MODE=1
  BASE="${HUNTER_BASE:-}"
  if [[ -z "$BASE" || "$BASE" == "$PROD_BASE" || "$BASE" == "$PROD_BASE"/* ]]; then
    echo "deploy: HUNTER_TEST_MODE requires HUNTER_BASE outside $PROD_BASE" >&2; exit 2
  fi
  MAX_BUNDLE_BYTES="${HUNTER_MAX_BUNDLE_BYTES:-3221225472}"
else
  TEST_MODE=0
  BASE="$PROD_BASE"
  MAX_BUNDLE_BYTES=3221225472   # 3 GiB
  unset HUNTER_TEST_MODE HUNTER_BASE HUNTER_MAX_BUNDLE_BYTES
  # nothing that makes a shell, the loader or Python load foreign code, and a fixed PATH
  unset BASH_ENV ENV LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT PYTHONPATH PYTHONHOME PYTHONSTARTUP \
        PYTHONUSERBASE PYTHONINSPECT
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  export PATH
fi
# guard / schema overrides are test hooks of other scripts: never inherited from the caller
unset HUNTER_GUARD_PROC HUNTER_GUARD_TEST_MODE HUNTER_GUARD_TEST_NSFS_TYPE HUNTER_ACCEPT_SCHEMA_REVISION ACCEPT_SCHEMA_REVISION
# Trusted, root-owned copies; they are NOT taken from the (signed, but newer) release bundle, so a
# bundle can never weaken the gate that is about to judge it.
GUARD="$BASE/deploy/host-egress-guard.sh"
ISOLATION_CHECK="$BASE/deploy/check-host-isolation.sh"
ISOLATION_CONF="$BASE/deploy/host-isolation.conf"      # REQUIRED: ROOTFUL_TARGETS=ip:port,...
DNS_CHECK="$BASE/deploy/check-dns.sh"
GUARD_CONF="$BASE/deploy/host-egress-guard.conf"       # REQUIRED here: DNS=<the one resolver the guard allows>
CONTAINMENT="$BASE/deploy/runtime-containment.sh"      # REQUIRED: keeps the isolation true AFTER this script is done
ACTION_LOCK_WAIT=180     # seconds a deploy waits for an in-flight watchdog action (a cold start can take minutes)
[[ "$TEST_MODE" == 1 ]] && ACTION_LOCK_WAIT="${HUNTER_ACTION_LOCK_WAIT:-$ACTION_LOCK_WAIT}"
API_PORT=18000          # host side; the container side stays 8000 (Gluetun lives on tailnet:8000)
KEEP_RELEASES=5
PROJECT=internship-hunter
SIGN_NAMESPACE=hunter-release

die() { echo "deploy: $1" >&2; exit "${2:-1}"; }
state() { echo "$BASE/state/$1"; }
read_state() { cat "$(state "$1")" 2>/dev/null || true; }

compose_args() { # compose_args <sha>: sets CARGS (project, files, env files) for that release
  # RELEASE_SHA goes through an env-file *and* env var so no env-forwarding quirk can make
  # compose fall back to a mutable tag (activate() additionally verifies what is running).
  local sha="$1" relenv
  relenv="$BASE/state/release-$sha.env"
  {
    printf 'RELEASE_SHA=%s\n' "$sha"
    [[ -n "${ACCEPT_SCHEMA_REVISION:-}" ]] \
      && printf 'HUNTER_ACCEPT_SCHEMA_REVISION=%s\n' "$ACCEPT_SCHEMA_REVISION"
  } > "$relenv"
  local files=(-f compose.yaml)
  # opt-in: connect the session controller to the host broker (docs/resource-sessions.md)
  [[ -f "$BASE/shared/rsm.enabled" ]] && files+=(-f compose.rsm.yaml)
  CARGS=(-p "$PROJECT" "${files[@]}" --env-file "$BASE/shared/.env" --env-file "$relenv")
}

compose() { # compose <sha> <args...>   (optional env: ACCEPT_SCHEMA_REVISION)
  local sha="$1"; shift
  compose_args "$sha"
  (cd "$BASE/releases/$sha" && RELEASE_SHA="$sha" docker compose "${CARGS[@]}" "$@")
}

actual_db_revision() { # actual_db_revision <sha>: what the database REALLY says (never state files)
  local rev
  rev="$(compose "$1" exec -T postgres psql -U hunter -d hunter -qAt \
          -c 'SELECT version_num FROM alembic_version' 2>/dev/null | tr -d '\r' | head -1)" || true
  [[ "$rev" =~ ^[0-9A-Za-z_]{1,32}$ ]] && printf '%s' "$rev"
  return 0
}

# accept_revision <db_now> <target_head> <leaving_head> <leaving_compat_csv>
# Prints the revision the TARGET release may be told to accept ("" = none needed).
# Returns 1 when the target must not be started against this database.
#   - db already at the target's own head       -> nothing to accept
#   - db at the head of the release we are leaving AND that release's SIGNED declaration
#     lists the target's head                   -> accept exactly that revision
#   - anything else (unknown / unexpected)      -> refuse; never accept arbitrary revisions
accept_revision() {
  local db_now="$1" target_head="$2" leaving_head="$3" leaving_compat="$4"
  if [[ -z "$db_now" ]]; then return 1; fi
  if [[ "$db_now" == "$target_head" ]]; then printf ''; return 0; fi
  if [[ "$db_now" == "$leaving_head" && -n "$target_head" \
        && ",$leaving_compat," == *",$target_head,"* ]]; then
    printf '%s' "$db_now"; return 0
  fi
  return 1
}

health_check() { # health_check <sha>: OUR api, on OUR published port - never whatever else listens
  local sha="$1" published
  published="$(compose "$sha" port api 8000 2>/dev/null | tr -d '\r')" || return 1
  if [[ "$published" != "127.0.0.1:$API_PORT" ]]; then
    echo "deploy: the api container publishes '${published:-nothing}', expected 127.0.0.1:$API_PORT" >&2
    return 1
  fi
  curl -fsS --retry 10 --retry-delay 3 --retry-connrefused "http://127.0.0.1:$API_PORT/ready" >/dev/null
  curl -fsS "http://127.0.0.1:$API_PORT/health" | grep -q '"submission_enabled":false'
}

# ---- host isolation gate ------------------------------------------------------------------------
trusted_file() { # trusted_file <path>: a regular, executable file we can trust to enforce policy
  local f="$1" want_uid=0 owner mode d
  [[ "$TEST_MODE" == 1 ]] && want_uid="$(id -u)"
  [[ -f "$f" && ! -L "$f" && -x "$f" ]] || return 1
  for d in "$f" "$(dirname "$f")"; do
    read -r owner mode < <(stat -c '%u %a' "$d")
    if [[ "$owner" != "$want_uid" ]] || (( (8#$mode & 8#022) != 0 )); then return 1; fi
  done
}

forbidden_targets() { # the effective EGRESS_FORBIDDEN_TARGETS (last assignment wins, as in compose)
  local v t
  v="$(sed -n 's/^EGRESS_FORBIDDEN_TARGETS=//p' "$BASE/shared/.env" | tail -1 | tr -d "\"' \r")"
  [[ -n "$v" ]] || return 1
  for t in ${v//,/ }; do
    [[ "$t" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]{1,5}$ ]] || return 1
  done
  printf '%s' "$v"
}

rootful_targets() { # REQUIRED, root-owned: ROOTFUL_TARGETS=ip:port,... (at least one existing rootful target)
  local v
  [[ -f "$ISOLATION_CONF" && ! -L "$ISOLATION_CONF" ]] || return 1
  trusted_file_data "$ISOLATION_CONF" || return 1
  v="$(sed -n 's/^ROOTFUL_TARGETS=//p' "$ISOLATION_CONF" | tail -1 | tr -d "\"' \r")"
  [[ -n "$v" ]] || return 1
  printf '%s' "$v"
}
guard_dns() { # the resolver(s) the guard lets through (DNS= in its trusted conf); the stack must use exactly these
  local v d
  [[ -f "$GUARD_CONF" && ! -L "$GUARD_CONF" ]] || return 1
  trusted_file_data "$GUARD_CONF" || return 1
  v="$(sed -n 's/^DNS=//p' "$GUARD_CONF" | tail -1 | tr -d "\"' \r")"
  [[ -n "$v" ]] || return 1
  for d in ${v//,/ }; do
    [[ "$d" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  done
  printf '%s' "$v"
}
trusted_file_data() { # like trusted_file but for non-executable data
  local owner mode want_uid=0; [[ "$TEST_MODE" == 1 ]] && want_uid="$(id -u)"
  read -r owner mode < <(stat -c '%u %a' "$1")
  [[ "$owner" == "$want_uid" ]] && (( (8#$mode & 8#022) == 0 )) && [[ ! -L "$1" ]]
}

require_isolation_prereqs() { # nothing is changed before these hold
  local out
  trusted_file "$GUARD" \
    || die "host egress guard missing or untrusted: $GUARD must exist, be executable, root-owned and not writable by others (docs/deployment.md, \"Host isolation\")" 11
  trusted_file "$ISOLATION_CHECK" \
    || die "isolation check missing or untrusted: $ISOLATION_CHECK must exist, be executable, root-owned and not writable by others" 11
  trusted_file "$DNS_CHECK" \
    || die "DNS check missing or untrusted: $DNS_CHECK must exist, be executable, root-owned and not writable by others" 11
  trusted_file "$CONTAINMENT" \
    || die "runtime containment missing or untrusted: $CONTAINMENT must exist, be executable, root-owned and not writable by others" 11
  guard_dns >/dev/null \
    || die "$GUARD_CONF must exist (root-owned, not writable by others) and set DNS=<ip>: the single resolver the guard lets containers use (slirp4netns: 10.0.2.3; docs/deployment.md, \"DNS\")" 11
  forbidden_targets >/dev/null \
    || die "EGRESS_FORBIDDEN_TARGETS must be set in $BASE/shared/.env to a comma-separated ip:port list (e.g. <tailscale ip>:22,<tailscale ip>:8000)" 11
  rootful_targets >/dev/null \
    || die "$ISOLATION_CONF must exist (root-owned, not writable by others) and set ROOTFUL_TARGETS=<ip:port>[,...]: name at least one EXISTING rootful container target (a closed port on its IP is ideal; docs/deployment.md)" 11
  # The targets must be REAL: forbidden ones are addresses of this host, every target answers (or
  # refuses) from the host's own namespace. A typo, a dropped packet or a moved container/bridge
  # would otherwise leave the protection testing nothing. Safe TCP connects only, no payload.
  if ! out="$(EGRESS_FORBIDDEN_TARGETS="$(forbidden_targets)" SMOKE_ROOTFUL_TARGETS="$(rootful_targets)" \
              SMOKE_EXPECT_ROOTLESS=1 "$ISOLATION_CHECK" --verify-targets 2>&1)"; then
    echo "$out" >&2
    die "configured isolation targets are not live from the host (typo, dropped packet, or the address moved): fix $BASE/shared/.env / $ISOLATION_CONF" 11
  fi
  if ! out="$("$GUARD" status 2>&1)"; then
    echo "$out" >&2
    die "host egress guard is not active with the full expected policy (run '$GUARD apply'; docs/deployment.md)" 12
  fi
  # the watchdog that keeps all of this true after the deploy: alive (fresh heartbeat) and not latched
  if ! out="$("$CONTAINMENT" status --require-active 2>&1)"; then
    echo "$out" >&2
    die "runtime containment is not active (watchdog not running, or latched after an incident): systemctl --user status hunter-containment; docs/deployment.md, \"Runtime containment\"" 13
  fi
}

dns_config_gate() { # dns_config_gate <sha>: the RENDERED compose dns must equal the guard's DNS=, BEFORE anything starts
  local sha="$1" want
  want="$(guard_dns)" || return 1
  compose_args "$sha"
  # HUNTER_DNS only ever comes from shared/.env (the caller's value was removed in main); whatever the
  # effective configuration says, it is compared with the root-owned guard conf, not trusted
  if ! ( cd "$BASE/releases/$sha" && RELEASE_SHA="$sha" SMOKE_DNS_CONFIG_ONLY=1 SMOKE_DNS_EXPECT="$want" \
         "$DNS_CHECK" "${CARGS[@]}" ); then
    echo "deploy: the rendered compose DNS of $sha disagrees with DNS=$want in $GUARD_CONF" \
         "(HUNTER_DNS in $BASE/shared/.env must be unset or equal to it); nothing was started" >&2
    return 1
  fi
}

isolation_gate() { # isolation_gate <sha>: ENFORCE mode, from every container with a route out
  local sha="$1" targets ips t rootful
  targets="$(forbidden_targets)" || return 1
  rootful="$(rootful_targets)" || return 1
  ips="$(for t in ${targets//,/ }; do echo "${t%:*}"; done | sort -u | tr '\n' ' ')"
  compose_args "$sha"
  if ! ( cd "$BASE/releases/$sha" && \
         SMOKE_HOST_ISOLATION=enforce SMOKE_EXPECT_ROOTLESS=1 SMOKE_REQUIRE_TAILNET=1 \
         SMOKE_AUTODETECT_HOST_IPS=1 SMOKE_PROTECTED_IPS="$ips" SMOKE_ROOTFUL_TARGETS="$rootful" \
         "$ISOLATION_CHECK" "${CARGS[@]}" ); then
    echo "deploy: host isolation check FAILED for $sha (enforce mode)" >&2
    return 1
  fi
  # DNS: the resolver of every service with a route out is the one the guard allows, queried from
  # inside the container (so the guard polices it); internal-only services resolve nothing outside
  if ! ( cd "$BASE/releases/$sha" && SMOKE_HOST_ISOLATION=enforce SMOKE_DNS_EXPECT="$(guard_dns)" \
         "$DNS_CHECK" "${CARGS[@]}" ); then
    echo "deploy: DNS check FAILED for $sha (enforce mode)" >&2
    return 1
  fi
}

port_preflight() { # read-only: 127.0.0.1:$API_PORT must be free, or held by OUR running api
  local listeners running
  listeners="$(ss -H -ltn "sport = :$API_PORT" 2>/dev/null)" \
    || die "cannot inspect listening ports (ss missing?); refusing to guess" 3
  [[ -n "$listeners" ]] || return 0
  running="$(read_state current_sha)"
  if [[ -n "$running" ]] \
     && [[ "$(compose "$running" port api 8000 2>/dev/null | tr -d '\r')" == "127.0.0.1:$API_PORT" ]]; then
    return 0
  fi
  die "host port $API_PORT is already in use by something that is not this application: $listeners" 3
}

stop_stack() { # fail closed: tear the project down (never volumes) rather than leave it exposed
  local sha="$1"
  echo "deploy: stopping the stack (docker compose down; volumes are kept)" >&2
  # first: the watchdog must not restart what is being torn down
  "$CONTAINMENT" desired stopped >/dev/null 2>&1 \
    || echo "deploy: WARNING could not record 'desired: stopped' for the containment watchdog" >&2
  compose "$sha" down --remove-orphans >/dev/null 2>&1 \
    || echo "deploy: WARNING 'compose down' failed; stop the project by hand: docker compose -p $PROJECT down" >&2
}

verify_running_images() { # every first-party container must run exactly this release's images
  local sha="$1" images bad n
  images="$(compose "$sha" ps --format '{{.Image}}')" || return 1
  bad="$(grep '^internship-hunter-' <<<"$images" | grep -v ":$sha\$" || true)"
  n="$(grep -c "^internship-hunter-.*:$sha\$" <<<"$images" || true)"
  if [[ -n "$bad" || "$n" -lt 11 ]]; then
    echo "deploy: containers are not running release $sha (found: ${bad:-only $n matching})" >&2
    return 1
  fi
}

containment_commit() { # containment_commit <sha>: put the verified release under runtime containment
  local sha="$1" targets ips t
  targets="$(forbidden_targets)" || return 1
  ips="$(for t in ${targets//,/ }; do echo "${t%:*}"; done | sort -u | tr '\n' ' ')"
  compose_args "$sha"
  "$CONTAINMENT" commit --sha "$sha" --release-dir "$BASE/releases/$sha" --forbidden "$targets" \
    --protected-ips "$ips" --rootful "$(rootful_targets)" -- "${CARGS[@]}"
}

containment_committable() { # containment_committable <sha>: could this release be put under runtime containment? (read-only)
  local sha="$1"
  [[ -d "$BASE/releases/$sha" ]] || return 1
  compose_args "$sha"
  "$CONTAINMENT" commit --check --sha "$sha" --release-dir "$BASE/releases/$sha" -- "${CARGS[@]}" >/dev/null 2>&1
}

activate() { # activate <sha>: start (never build) the release, then verify it
  # Explicit `|| return`: errexit is suppressed when this runs inside `if !`/`||`.
  local sha="$1"
  docker image inspect "internship-hunter-app:$sha" >/dev/null 2>&1 \
    || { echo "deploy: image internship-hunter-app:$sha is not loaded" >&2; return 3; }
  docker image inspect "internship-hunter-agent:$sha" >/dev/null 2>&1 \
    || { echo "deploy: image internship-hunter-agent:$sha is not loaded" >&2; return 3; }
  docker image inspect "internship-hunter-egress:$sha" >/dev/null 2>&1 \
    || { echo "deploy: image internship-hunter-egress:$sha is not loaded" >&2; return 3; }
  compose "$sha" config -q || return 1
  dns_config_gate "$sha" || return 1
  compose "$sha" up -d --no-build --remove-orphans --wait --wait-timeout 300 || return 1
  verify_running_images "$sha" || return 1
  health_check "$sha" || return 1
  isolation_gate "$sha" || return 1
  # last: the watchdog takes over only a release that passed everything above (its contract is written
  # under this script's lock; a refusal, e.g. a supervised service with a restart policy, fails the activation)
  containment_commit "$sha" || { echo "deploy: runtime containment refused release $sha" >&2; return 1; }
}

set_current() { ln -sfn "$BASE/releases/$1" "$BASE/current.new" && mv -Tf "$BASE/current.new" "$BASE/current"; }

require_rootless() {
  # Only ever the user's own rootless daemon: pin the socket, so an inherited DOCKER_HOST,
  # DOCKER_CONTEXT or a docker-group membership can never route a command to the rootful one.
  # (Tests have no daemon: with HUNTER_TEST_MODE the pin applies only when a socket exists.)
  local rd="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
  if [[ "$TEST_MODE" != 1 || -S "$rd/docker.sock" ]]; then
    [[ -S "$rd/docker.sock" ]] || die "rootless Docker socket $rd/docker.sock not found" 5
    export DOCKER_HOST="unix://$rd/docker.sock"
    unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
  fi
  docker info --format '{{.SecurityOptions}}' | grep -q rootless \
    || die "refusing to deploy: Docker daemon is not rootless (see docs/deployment.md)" 5
}

only_regular_entries() { # only_regular_entries <tar> <z|-> <allow_dirs 0|1>: no links/devices/fifos
  local flag="-tvf"; [[ "$2" == z ]] && flag="-tzvf"
  local bad
  if [[ "$3" == 1 ]]; then
    bad="$(tar "$flag" "$1" | cut -c1 | grep -v '^[-d]' || true)"
  else
    bad="$(tar "$flag" "$1" | cut -c1 | grep -v '^-' || true)"
  fi
  [[ -z "$bad" ]]
}

manual_recovery() {
  local backups
  # shellcheck disable=SC2012  # names are generated by this script (sha + timestamp)
  backups="$(ls -1t "$BASE"/backups/*.sql.gz 2>/dev/null | head -3 | tr '\n' ' ' || true)"
  cat >&2 <<MSG
deploy: MANUAL RECOVERY REQUIRED
  running release : $(read_state current_sha)
  database revision: $(read_state db_head)
  latest backups   : $backups
  procedure        : docs/backup-restore.md ("Restore")
MSG
}

do_rollback() {
  local current previous cur_head prev_head db_now accept leaving_compat
  require_isolation_prereqs
  current="$(read_state current_sha)"; previous="$(read_state previous_sha)"
  cur_head="$(read_state current_head)"; prev_head="$(read_state previous_head)"
  [[ "$previous" =~ ^[0-9a-f]{40}$ ]] || die "no previous release recorded" 3
  [[ -d "$BASE/releases/$previous" ]] || die "previous release directory missing" 3
  dns_config_gate "$previous" || die "rollback target $previous is refused: its rendered DNS configuration disagrees with the guard" 11
  containment_committable "$previous" \
    || die "rollback target $previous predates runtime containment (its services render a restart policy) and cannot be restored under it: nothing was changed, the running release $current stays. Deploy a fixed release instead (docs/deployment.md, \"First deploy with runtime containment\")" 14
  # the declaration that matters is the one SIGNED INTO the release we are leaving
  leaving_compat="$(read_state "compat-$current")"
  db_now="$(actual_db_revision "$current")"
  if ! accept="$(accept_revision "$db_now" "$prev_head" "$cur_head" "$leaving_compat")"; then
    echo "deploy: rollback refused: database is at '${db_now:-unreadable}'; $previous (head" \
         "'${prev_head:-unknown}') is not covered by the signed declaration of $current" \
         "(head '${cur_head:-unknown}', compatible with '${leaving_compat:-nothing}')." >&2
    manual_recovery
    exit 9
  fi
  export ACCEPT_SCHEMA_REVISION="$accept"
  if ! activate "$previous"; then
    echo "deploy: rollback target $previous failed verification; re-activating $current" >&2
    export ACCEPT_SCHEMA_REVISION=""
    if ! activate "$current"; then
      echo "deploy: could not re-activate $current either" >&2
      stop_stack "$current"          # neither release verified: fail closed, do not leave it up
    fi
    manual_recovery
    exit 6
  fi
  set_current "$previous"
  echo "$previous" > "$(state current_sha)"
  echo "$current" > "$(state previous_sha)"
  echo "$prev_head" > "$(state current_head)"
  echo "$cur_head" > "$(state previous_head)"
  echo "$db_now" > "$(state db_head)"
  echo "rolled back to $previous (verified: images, health, schema; DB revision ${db_now} ${accept:+accepted explicitly})"
}

do_deploy() { # do_deploy <normal|irreversible>
  local mode="$1"
  [[ -f "$BASE/shared/.env" ]] || die "missing $BASE/shared/.env" 3
  [[ -f "$BASE/shared/allowed_signers" ]] || die "missing $BASE/shared/allowed_signers" 3
  require_isolation_prereqs      # before the bundle is even read: nothing changes without them
  port_preflight

  local stage; stage="$(mktemp -d "$BASE/staging/bundle.XXXXXX")"
  STAGE="$stage"

  head -c "$((MAX_BUNDLE_BYTES + 1))" > "$stage/bundle.tar"
  [[ "$(stat -c %s "$stage/bundle.tar")" -le "$MAX_BUNDLE_BYTES" ]] || die "bundle too large" 2
  local members; members="$(tar -tf "$stage/bundle.tar" | LC_ALL=C sort | tr '\n' ' ')"
  [[ "$members" == "images.tar.gz manifest manifest.sig source.tar.gz " ]] \
    || die "unexpected bundle members: $members" 2
  only_regular_entries "$stage/bundle.tar" - 0 || die "bundle contains non-regular entries" 2
  tar -xf "$stage/bundle.tar" -C "$stage" --no-same-owner --no-same-permissions

  # 1) signature over the manifest
  ssh-keygen -Y verify -f "$BASE/shared/allowed_signers" -I release -n "$SIGN_NAMESPACE" \
    -s "$stage/manifest.sig" < "$stage/manifest" >/dev/null 2>&1 \
    || die "manifest signature verification FAILED" 7

  # 2) strict manifest parsing (exactly six known lines)
  local sha src_hash img_hash created new_head compat
  sha="$(sed -n 's/^sha=\([0-9a-f]\{40\}\)$/\1/p' "$stage/manifest")"
  src_hash="$(sed -n 's/^source_sha256=\([0-9a-f]\{64\}\)$/\1/p' "$stage/manifest")"
  img_hash="$(sed -n 's/^images_sha256=\([0-9a-f]\{64\}\)$/\1/p' "$stage/manifest")"
  created="$(sed -n 's/^created=\([0-9]\{10\}\)$/\1/p' "$stage/manifest")"
  new_head="$(sed -n 's/^schema_head=\([0-9A-Za-z_]\{1,32\}\)$/\1/p' "$stage/manifest")"
  compat="$(sed -n 's/^rollback_compatible=\(\([0-9A-Za-z_]\{1,32\}\(,[0-9A-Za-z_]\{1,32\}\)*\)\{0,1\}\)$/\1/p' "$stage/manifest")"
  [[ -n "$sha" && -n "$src_hash" && -n "$img_hash" && -n "$created" && -n "$new_head" ]] \
    || die "bad manifest" 2
  grep -q '^rollback_compatible=' "$stage/manifest" || die "bad manifest (no compat line)" 2
  [[ "$(wc -l < "$stage/manifest")" -eq 6 ]] || die "bad manifest (unexpected lines)" 2

  # 3) artifact integrity
  [[ "$(sha256sum "$stage/source.tar.gz" | cut -d' ' -f1)" == "$src_hash" ]] \
    || die "source archive hash mismatch" 7
  [[ "$(sha256sum "$stage/images.tar.gz" | cut -d' ' -f1)" == "$img_hash" ]] \
    || die "image archive hash mismatch" 7

  # 4) replay/downgrade protection: a validly signed but OLDER bundle is refused
  local last_created; last_created="$(read_state current_created)"; last_created="${last_created:-0}"
  [[ "$created" -ge "$last_created" ]] || die "bundle is older than the running release" 7

  # 5) schema compatibility with the rollback target (the release running right now)
  local running run_head rollback_ok=1
  running="$(read_state current_sha)"; run_head="$(read_state current_head)"
  if [[ -n "$running" && "$running" != "$sha" ]]; then
    if [[ -n "$run_head" && ( "$run_head" == "$new_head" || ",$compat," == *",$run_head,"* ) ]]; then
      rollback_ok=1
    elif [[ "$mode" == irreversible ]]; then
      rollback_ok=0
      echo "deploy: accepted IRREVERSIBLE deploy: rollback to $running will be refused" >&2
    else
      die "schema $new_head is not declared rollback-compatible with the running release (head ${run_head:-unknown}); use deploy-irreversible after reviewing the migration" 9
    fi
  fi

  # 6) unpack source safely (regular files/dirs only, no absolute or .. paths)
  only_regular_entries "$stage/source.tar.gz" z 1 || die "source archive has non-regular entries" 2
  if tar -tzf "$stage/source.tar.gz" | grep -Eq '^/|(^|/)\.\.(/|$)'; then
    die "source archive contains unsafe paths" 2
  fi
  local rel="$BASE/releases/$sha"
  rm -rf "$rel.partial"; mkdir -p "$rel.partial"
  tar -xzf "$stage/source.tar.gz" -C "$rel.partial" --no-same-owner --no-same-permissions
  rm -rf "$rel"; mv "$rel.partial" "$rel"
  # 6b) the effective compose DNS must match the guard BEFORE images are loaded, the database is
  # dumped or a container is touched (activate() repeats it right before `up`, for restores too)
  dns_config_gate "$sha" || die "release $sha is refused: its rendered DNS configuration disagrees with the guard" 11
  # 6c) ... and runtime containment must accept the release (a supervised service with a restart policy is
  # refused): found out HERE, not at the end of an activation that has already migrated the database
  if ! containment_committable "$sha"; then
    "$CONTAINMENT" commit --check --sha "$sha" --release-dir "$BASE/releases/$sha" -- "${CARGS[@]}" >&2 || true
    die "release $sha is refused: runtime containment cannot supervise it (its services with a route out, and its agents, must render restart: \"no\")" 11
  fi
  # 6d) can the release running NOW be restored under containment? A release from before runtime
  # containment renders restart: unless-stopped, which `commit` refuses: after a failed activation there would be
  # nothing to go back to. Never pretend otherwise: the operator must acknowledge it BEFORE anything changes.
  local previous_restorable=1
  if [[ -n "$running" && "$running" != "$sha" ]] && ! containment_committable "$running"; then
    previous_restorable=0
    rollback_ok=0
    if [[ "$mode" != irreversible ]]; then
      die "the running release $running predates runtime containment (its services render a restart policy) and cannot be restored under it: if this deploy fails there is NO previous release to go back to and the stack would be stopped. Use deploy-irreversible to acknowledge that (docs/deployment.md, \"First deploy with runtime containment\")" 14
    fi
    echo "deploy: accepted IRREVERSIBLE deploy: $running predates runtime containment; if $sha fails it will NOT be restored and the stack will be stopped" >&2
  fi

  # 7) immutable images: load, never build
  docker load -i "$stage/images.tar.gz" >/dev/null

  local previous="$running"

  # 8) database backup before anything is changed (skipped on the very first deploy)
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

  # 9) switch; a failed migration, start or health check restores the previous release
  export ACCEPT_SCHEMA_REVISION=""
  if ! ( set_current "$sha" && activate "$sha" ); then
    echo "deploy: $sha failed (migration, start or health check); restoring ${previous:-<none>}" >&2
    if [[ -n "$previous" && "$previous_restorable" == 0 ]]; then
      # Nothing to restore TO: the running release cannot be committed under runtime containment. Fail closed,
      # say so, and do not report a restore that did not happen.
      echo "deploy: $previous predates runtime containment and CANNOT be restored; it was NOT restored. The stack is being stopped (fail closed)." >&2
      stop_stack "$sha"
      set_current "$previous"
      manual_recovery
      exit 10
    elif [[ -n "$previous" ]]; then
      # The new release may already have migrated the database. Read the REAL revision and
      # let the previous release accept it only if this bundle's signed declaration says so.
      local db_now accept
      db_now="$(actual_db_revision "$sha")"
      if accept="$(accept_revision "$db_now" "$run_head" "$new_head" "$compat")"; then
        export ACCEPT_SCHEMA_REVISION="$accept"
        [[ -n "$accept" ]] && echo "deploy: database already at $db_now; $previous will accept it (declared compatible)" >&2
      else
        echo "deploy: database is at '${db_now:-unreadable}', which $previous may not accept" >&2
        export ACCEPT_SCHEMA_REVISION=""
      fi
      set_current "$previous"
      if ! activate "$previous"; then
        echo "deploy: RESTORE ALSO FAILED" >&2
        stop_stack "$previous"
        manual_recovery
        exit 10
      fi
      echo "$db_now" > "$(state db_head)"
      echo "deploy: restored $previous (verified: images, health, schema)" >&2
    else
      # FIRST deploy: there is nothing to go back to, and a half-started or unisolated new
      # release must not keep running. Tear it down and leave no 'current' behind.
      stop_stack "$sha"
      rm -f "$BASE/current" "$BASE/current.new"
      echo "deploy: first deploy of $sha failed; stack stopped, nothing is current" >&2
    fi
    exit 1
  fi
  printf '%s' "$compat" > "$(state "compat-$sha")"
  [[ -n "$previous" && "$previous" != "$sha" ]] && {
    echo "$previous" > "$(state previous_sha)"
    echo "$run_head" > "$(state previous_head)"
  }
  echo "$sha" > "$(state current_sha)"
  echo "$new_head" > "$(state current_head)"
  echo "$new_head" > "$(state db_head)"
  echo "$created" > "$(state current_created)"
  echo "$rollback_ok" > "$(state rollback_ok)"

  # 10) prune old releases, never current or previous
  local keep_prev; keep_prev="$(read_state previous_sha)"
  # shellcheck disable=SC2012  # directory names are 40-hex commit SHAs
  ls -1dt "$BASE"/releases/*/ 2>/dev/null | tail -n +$((KEEP_RELEASES + 1)) | while read -r d; do
    name="$(basename "$d")"
    [[ "$name" == "$sha" || "$name" == "$keep_prev" ]] && continue
    rm -rf "$d"
    docker image rm "internship-hunter-app:$name" "internship-hunter-agent:$name" \
      "internship-hunter-egress:$name" >/dev/null 2>&1 || true
  done
  echo "deployed $sha (schema $new_head; rollback_ok=$rollback_ok)"
}

STAGE=""
trap '[[ -z "$STAGE" ]] || rm -rf "$STAGE"' EXIT

main() {
  # A caller's environment must not be able to loosen the gate or redirect compose.
  local v
  for v in $(compgen -e | grep -E '^(SMOKE_|EGRESS_FORBIDDEN_TARGETS$|COMPOSE_|HUNTER_DNS$)' || true); do unset "$v"; done
  case "${SSH_ORIGINAL_COMMAND:-}" in
    deploy|deploy-irreversible|rollback) require_rootless ;;   # before anything is written
    *)                                   die "unsupported command" 2 ;;
  esac
  mkdir -p "$BASE"/{releases,state,staging,shared}
  exec 9>"$BASE/state/deploy.lock"
  flock -n 9 || die "another deploy is running" 4
  # The watchdog's right to change the stack (runtime-containment.sh, "LOCKING"): taken for the whole of this
  # deploy so that a deploy and a watchdog stop/start never overlap. It is held by the watchdog only while it is
  # ACTING, so this normally returns at once; if the watchdog is in the middle of an action, wait for it. The
  # truncating open makes the lock file's mtime the start of this deploy (the hung-deploy bound).
  exec 8>"$BASE/state/containment.action.lock"
  flock -w "$ACTION_LOCK_WAIT" 8 \
    || die "the runtime-containment watchdog is in the middle of stopping or starting the stack (waited ${ACTION_LOCK_WAIT}s); retry in a minute" 4
  case "$SSH_ORIGINAL_COMMAND" in
    deploy)              do_deploy normal ;;
    deploy-irreversible) do_deploy irreversible ;;
    rollback)            do_rollback ;;
  esac
}
main
