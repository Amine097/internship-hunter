# Milestone 1 acceptance checklist

Legend: **L** = executed locally on a real Docker daemon (2026-10-15, WSL2/Docker Desktop, not
the production host); **CI** = defined in GitHub Actions, *not yet executed* on GitHub for this
revision; **S** = must be done on the real server. Nothing marked S has been done.

## Code / CI
- [x] **L** `ruff check .` clean; `pytest` **187 passed, 0 skipped** on Python 3.12.15 against
      real PostgreSQL 17 (`TEST_DATABASE_URL`, `CI_REQUIRE_SERVICES=1`)
- [ ] **CI** same on GitHub (`lint-test`; fails if the PostgreSQL service is missing)
- [x] **L** `pip-audit` no known vulnerabilities; [ ] **CI**
- [x] **L** gitleaks (full history) no leaks; [ ] **CI**
- [x] **L** shellcheck clean on `deploy/*.sh`; hadolint clean on all three Dockerfiles; [ ] **CI**
- [x] **L** `docker compose up -d --build --wait`: all services healthy, `migrate` exited 0
- [ ] **CI** `docker` job (build, up, `deploy/smoke-test.sh`, `deploy/verify-restore.sh`)

## Queue (PostgreSQL, replaces RQ/Redis)
- [x] **L** reviewer's finding reproduced: a job rejected by `HardenedJob` still invoked the
      attacker-named failure callback (`builtins.print(job, ...)`) -> RQ removed
- [x] **L** no `redis`/`rq` in code, compose, dependencies (`test_compose_invariants`)
- [x] **L** database rejects forged task kinds/states (CHECK) — unit, PostgreSQL and live stack
- [x] **L** 8 threads x 60 tasks and 4 processes x 40 tasks: every task claimed exactly once
- [x] **L** `FOR UPDATE SKIP LOCKED` does not block behind a locked row
- [x] **L** SIGKILLed worker: lease expires -> retried with back-off -> bounded at 3 attempts
      -> task and scan failed; recovered task completes on a healthy worker (attempts == 2)
- [x] **L** heartbeat keeps a slow task alive; silence is reaped; fenced-out worker cannot
      write or complete; expired worker cannot overwrite a newer result
- [x] **L** one active scan per profile under 16 concurrent enqueues (DB-enforced)

## Migrations and rollback (real daemon, signed bundles, real images + database)
- [x] **L** deploy N (schema 0003) -> deploy N+1 (additive 0004): healthy, DB at 0004
- [x] **L** rollback to N on schema 0004: succeeded only after images + `/ready` + schema were
      verified; migrate log shows the revision explicitly accepted, not ignored
- [x] **L** forward toggle back to N+1; scan accepted on the rolled-back release
- [x] **L** contracting migration without a compatibility declaration: refused (exit 9) before
      any change; running release and DB untouched
- [x] **L** failing migration: deploy fails, previous release restored automatically, DB
      revision unchanged, healthy
- [x] **L** `deploy-irreversible`: explicit, backup taken; following `rollback` refused (exit 9)
      with the manual-recovery procedure
- [x] **L** unknown Alembic revision raises `SchemaMismatch` / `/ready` 503 unless explicitly
      accepted; accepted mode neither migrates nor seeds
- [x] **L** stub-Docker suite: bad signature/hash/members/paths/symlinks/extra manifest lines,
      replay, lock, rootful refusal, backup failure, failed restore (exit 10), failed health
      check on rollback (exit 6)
- [ ] **S** rootless Docker on the production host; real deploy and rollback there

## Release signing (static checks of the workflow files)
- [x] **L** `RELEASE_SIGNING_KEY` referenced only by the `sign` job (own environment, main only);
      `build`/`verify` hold no secrets; deploy secrets only in `deploy`; all actions SHA-pinned
- [ ] **S** GitHub environments `release-signing` and `production` configured with the
      "main only" deployment-branch rule; `DEPLOY_ENABLED` unset

## Egress (real daemon)
- [x] **L** agent networks internal: direct TCP to 1.1.1.1 / 8.8.8.8 / metadata IP /
      postgres / peers / API / orchestrator / other proxies all blocked
- [x] **L** agent reaches only its own proxy; proxy refuses other hosts, IP literals,
      metadata/LAN addresses, port 22, look-alike domains and the other provider's host
- [x] **L** CONNECT to `api.anthropic.com` (claude proxy) and `api.openai.com` (codex proxy)
      succeeds — legitimate provider access preserved
- [ ] **S** provider hostname lists confirmed against the pinned CLI versions (UNVERIFIED);
      behaviour under rootless Docker (slirp4netns/pasta)

## Rootless-host isolation (run `SMOKE_EXPECT_ROOTLESS=1 deploy/smoke-test.sh` on the server)
Derived checks (also run in CI against the Docker runner, without the rootless assertion):
- [x] **L** no container mounts the Docker socket or runs privileged; daemon is rootless (**S**)
- [x] **L** the egress proxy (the only container with an outbound route) cannot reach its
      gateway/host on ssh, the Docker API, postgres or the API port
- [x] **L** only loopback-published ports; proxy refuses tailnet (100.64/10, 100.100.100.100),
      RFC1918, link-local, loopback literals and `localhost`
- [ ] **S** the same three, on the rootless production host, plus Tailscale ACL review

## Server (demo mode) — all **S**
- [ ] `ss -tlnp`: only the API on loopback; Telegram from owner works, others get no reply
- [ ] Container memory totals within budget; other host services unaffected

## CLI mode (only after provider terms are confirmed) — all **S**
- [ ] Each CLI logged in separately; one scan yields three `cli` runs
