#!/usr/bin/env bash
# Proves a logical backup is restorable: dump the live DB, restore into a scratch database,
# compare schema version and row counts, then drop the scratch DB. Non-destructive.
# Usage: deploy/verify-restore.sh [docker compose args, e.g. -p internship-hunter --env-file .env]
set -Eeuo pipefail
COMPOSE=(docker compose "$@")
SCRATCH=hunter_restore_check
psql_in() { "${COMPOSE[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U hunter -qAt "$@"; }

dump="$(mktemp)"; trap 'rm -f "$dump"' EXIT
"${COMPOSE[@]}" exec -T postgres pg_dump -U hunter hunter | gzip > "$dump"
[[ -s "$dump" ]] || { echo "empty dump" >&2; exit 1; }

psql_in -d postgres -c "DROP DATABASE IF EXISTS $SCRATCH" -c "CREATE DATABASE $SCRATCH"
gunzip -c "$dump" | psql_in -d "$SCRATCH" >/dev/null

counts() {
  psql_in -d "$1" -c "SELECT 'alembic', version_num FROM alembic_version" \
    -c "SELECT 'profiles', count(*) FROM search_profiles" \
    -c "SELECT 'scans', count(*) FROM scans" \
    -c "SELECT 'jobs', count(*) FROM jobs" \
    -c "SELECT 'agent_runs', count(*) FROM agent_runs"
}
a="$(counts hunter)"; b="$(counts "$SCRATCH")"
psql_in -d postgres -c "DROP DATABASE $SCRATCH" >/dev/null
if [[ "$a" != "$b" ]]; then
  echo "RESTORE MISMATCH"; diff <(echo "$a") <(echo "$b") || true; exit 1
fi
echo "restore verified:"; echo "$a"
