# Backup, restore and migrations

## Migrations (Alembic) and rollback compatibility

- Revisions live in `hunter/migrations/versions/`; the `migrate` service runs
  `python -m hunter.db` → `alembic upgrade head`, then upserts profile definitions from
  `config/search_profiles.yaml` (the operator's `enabled` flag is preserved).
- Databases created by the pre-Alembic bootstrap are **stamped** `0001` then upgraded.

### The rollback problem and the policy

After release N+1 migrates the database to its head, release N (whose Alembic knows only
older revisions) would normally refuse to start: `Can't locate revision`. Two things were
wrong before: N+1 gave no way to say "my schema is still fine for N", and the failure only
showed up *during* rollback. Policy now:

1. **Expand/contract.** A migration that releases N and N+1 must both tolerate is
   *expand-only* (new tables, new nullable/defaulted columns, new indexes/constraints that
   existing rows satisfy). Contracting changes (drop/rename/alter) ship one release later,
   after nothing depends on the old shape.
2. **Declare it.** `hunter/migrations/compat.json` lists the previous heads that still work
   on this release's head. `tests/test_schema_compat.py` lints every migration between each
   listed base and head and fails on `drop_*`, `alter_column`, renames.
3. **The signed manifest carries it** (`schema_head`, `rollback_compatible`), produced by
   `deploy/build-artifacts.sh` from the source tree.
4. **Checked before anything changes.** `remote-deploy.sh deploy` compares the running
   release's head with the new manifest. Not declared compatible → refused (exit 9) *before*
   backup, load or switch. The operator may knowingly use `deploy-irreversible`; a backup is
   mandatory and `rollback` is then refused with the manual-recovery procedure below.
5. **The real database decides, not state files.** Before accepting anything, restore and
   rollback read `alembic_version` from PostgreSQL (`psql` through the running stack). The
   target release may be told to accept revision *R* only if **all** hold: *R* is what the
   database actually says; *R* is the head of the release being left; and that release's own
   **signed** `rollback_compatible` list names the target's head. Any other revision —
   including one that a stale `state/` file claims — is refused. This covers the automatic
   restore after a failed deploy (the new release may already have migrated) and an explicit
   rollback alike.
6. **Unknown revisions are never silently ignored.** `hunter.db` raises `SchemaMismatch`
   (and `/ready` returns 503) for a revision it does not know. The only exception is an
   explicit `HUNTER_ACCEPT_SCHEMA_REVISION=<that exact revision>`, which *only the deploy
   script* sets, *only* during a rollback it has verified is compatible; in that mode the
   release neither migrates nor seeds data.
7. **Rollback is verified, not assumed.** It re-activates the previous images, then checks
   running images, `/ready` (schema), and `submission_enabled=false`. If any check fails it
   re-activates the release it came from, exits 6 and prints the recovery procedure — it
   never reports success on an unverified rollback.

**Protocol baseline.** The accept protocol exists from revision `0003` onward
(`accept_protocol_since` in `compat.json`). Older releases refuse any newer schema, so they
can never be listed in `rollback_compatible_with`; `deploy/schema_info.py` (run at build and
again at signing) and `tests/test_schema_compat.py` reject such a declaration.

**The signing job recomputes this metadata** from the source archive (text parsing only,
nothing executed) and writes the signed manifest itself; a build job that reports a different
`schema_head`/`rollback_compatible` is refused (`tests/test_sign_bundle.py`).

### Migration failure and failed health check after migrating

PostgreSQL DDL is transactional, so a *failing* migration leaves the schema at the previous
revision and the previous release is restored as is (exit 1). A migration that *succeeds*
but whose release then fails its health check leaves the schema at the new head: the
previous release is restored with that exact revision explicitly accepted (only when the
bundle's signed declaration covers it; this was the reviewer's reproduced failure, now
`test_regression_restore_after_compatible_migration_and_failed_healthcheck`). For an
`irreversible` deploy nothing is accepted and the outcome is exit 10 + manual recovery. If the restore
*also* fails (e.g. non-transactional DDL left a half-applied change) the script exits 10 with
the latest backups and the procedure below. Never run `alembic downgrade` in production.

### Tests

`tests/test_migrations.py`: empty → head, model drift, legacy stamp, downgrade/upgrade round
trip, RQ-era active scans receive a task (SQLite and PostgreSQL).
`tests/test_schema_compat.py`: unknown/accepted/behind revisions, expand-only lint.
`tests/test_deploy_script.py`: N→N+1, incompatible refused, irreversible, migration failure,
failed restore, failed health check on rollback, forward/back toggling.

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
