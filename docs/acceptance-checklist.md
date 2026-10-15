# Milestone 1 acceptance checklist

Legend: **L** = executed locally on a real Docker daemon (2026-10-15, WSL2/Docker Desktop, not the
production host); **CI** = defined in GitHub Actions, *not yet executed* on GitHub; **S** = must
be done on the real server. Nothing marked S has been done.

## Code / CI
- [x] **L** `ruff check .` clean; `pytest` 149 passed on Python 3.12 with real PostgreSQL 17 + Redis 7
- [ ] **CI** same on GitHub (`lint-test`, with `CI_REQUIRE_SERVICES=1` so nothing can skip)
- [x] **L** `pip-audit` no known vulnerabilities; [ ] **CI**
- [x] **L** gitleaks (2 commits) no leaks; [ ] **CI** full history
- [x] **L** shellcheck clean on `deploy/*.sh`; [ ] **CI**
- [x] **L** hadolint clean on both Dockerfiles; [ ] **CI**
- [x] **L** `docker compose up -d --build --wait`: all services healthy, `migrate` exited 0
- [ ] **CI** `docker` job (build, up, `deploy/smoke-test.sh`, `deploy/verify-restore.sh`)

## Security regression (reproduced, then blocked)
- [x] **L** pickled job executes on default RQ (control) and is rejected by the hardened worker
- [x] **L** forged `subprocess.run` job executes without allowlist (control) and is rejected
- [x] **L** poisoned pickled *result* executes via default `return_value()` (control), inert now
- [x] **L** same attacks injected into the **live** Redis of the running stack: no code ran
- [x] **L** agent container cannot connect to Redis / Postgres / other agents / API
- [x] **L** agent env contains no `REDIS_URL`, `DATABASE_URL`, admin or Telegram secrets
- [x] **L** agent runner rejects unauthenticated and schema-violating calls
- [x] **L** Redis runs as uid 999 with `cap_drop: ALL`, read-only root, named volume

## Reliability
- [x] **L** timeout of an agent → run failed, scan `partial`, no orphan job
- [x] **L** stale queued/running scans swept; forged re-run of a finished scan is a no-op
- [x] **L** concurrent `/scan` creates one active scan (SQLite + PostgreSQL, DB-enforced)
- [x] **L** backup restores into a scratch DB with identical schema version and row counts

## Deployment script (stub Docker unless noted)
- [x] **L** bad signature / hash / members / paths / older bundle refused
- [x] **L** failed `up` and failed health check restore the previous release
- [x] **L** rollback uses loaded images, never builds or loads
- [x] **L** concurrent deploy refused; backup failure aborts before any change
- [x] **L** rootful daemon refused
- [x] **L** real signed bundles on a real (rootful, local, `HUNTER_ALLOW_ROOTFUL=1`) daemon:
      deploy #1, deploy #2 with pg_dump backup, rollback, and a deliberately broken release
      (restored automatically); running images verified to be the exact SHA tags
- [x] **L** finding from that run: compose silently ran `:dev` images when `RELEASE_SHA` did
      not reach it -> script now passes an env-file and verifies running images
- [ ] **S** rootless Docker on the production host; real deploy, health check and rollback
- [ ] **S** no inbound port 22 from the Internet; ACL limits `tag:ci` to `:22`

## Server (demo mode) — all **S**
- [ ] `ss -tlnp` shows no Postgres/Redis listener on host interfaces; API only on loopback
- [ ] Telegram from owner: `/profiles` lists 2, `/scan` queues, `/agents` shows 3 `demo` runs
- [ ] Telegram from another account or a group: no reply
- [ ] Repeated `/scan` with one real configured board: no duplicate jobs
- [ ] Container memory totals within budget; other host services unaffected

## CLI mode (only after provider terms are confirmed) — all **S**
- [ ] Each CLI logged in separately; one scan yields three `cli` runs
- [ ] Revoking one login fails only that agent (scan `partial`)
