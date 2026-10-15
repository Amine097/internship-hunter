# Backup, restore and migrations

## Migrations (Alembic)

- Revisions live in `hunter/migrations/versions/`; the `migrate` service runs
  `python -m hunter.db` → `alembic upgrade head`, then upserts profile definitions from
  `config/search_profiles.yaml` (the operator's `enabled` flag is preserved).
- Databases created by the pre-Alembic bootstrap are **stamped** `0001` then upgraded.
- Migrations are **forward-only in production**. `downgrade` is exercised in tests but a
  failed release never runs it automatically; recover data with a restore (below).
- Policy: a migration must be backward compatible with the *previous* release's code
  (add nullable columns/tables first, drop later), so a code rollback is always safe.
- Tested by `tests/test_migrations.py` on SQLite **and** PostgreSQL: empty → head, model
  drift (`compare_metadata`), legacy-stamp path, downgrade/upgrade round trip.

## Automatic pre-deploy backup

`deploy/remote-deploy.sh` runs `pg_dump | gzip` into `$BASE/backups/pre-<sha>-<ts>.sql.gz`
before changing anything and aborts (exit 8) if the dump fails or is empty. The 10 newest are
kept. Copy them off the host on your own schedule; nothing here does so.

## Verify a backup is restorable (non-destructive)

```bash
deploy/verify-restore.sh -p internship-hunter --env-file /opt/internship-hunter/shared/.env
```

Restores a fresh dump into a scratch database and compares the schema version and row counts.
Run in CI against the compose stack and run it on the server periodically.

## Restore (destructive; do by hand)

```bash
cd /opt/internship-hunter/current
export RELEASE_SHA=$(cat ../state/current_sha)
C="docker compose -p internship-hunter --env-file ../shared/.env"
$C stop api discovery scheduler telegram
gunzip -c ../backups/pre-<sha>-<ts>.sql.gz > /tmp/restore.sql        # inspect first
$C exec -T postgres psql -U hunter -d postgres -c "DROP DATABASE hunter" -c "CREATE DATABASE hunter"
$C exec -T postgres psql -v ON_ERROR_STOP=1 -U hunter -d hunter < /tmp/restore.sql
$C start api discovery scheduler telegram
```

Then roll the code back (`rollback` action) if the backup predates a schema change.
