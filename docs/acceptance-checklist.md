# Milestone 1 acceptance checklist

Mark each item only after running it. "CI" = executed by GitHub Actions; "Server" = must be done
on the real host. Items not yet executed anywhere are listed in the PR description.

## Code / CI
- [ ] `ruff check hunter tests` clean (CI)
- [ ] `pytest` green, including `tests/test_postgres.py` against the PostgreSQL service (CI)
- [ ] `pip-audit` reports no vulnerable runtime dependency (CI)
- [ ] `gitleaks` finds no secret in history (CI)
- [ ] `docker compose config -q` passes with placeholder env (CI)
- [ ] Both images build; hadolint passes (CI)
- [ ] Compose smoke test: `/health`, `/ready`, `/profiles`, scan reaches `finished` (CI)

## Server (demo mode)
- [ ] `docker compose up -d --build --wait` → all services healthy; `migrate` exited 0
- [ ] `curl 127.0.0.1:8000/health` shows `"submission_enabled":false`
- [ ] API unreachable from the LAN / public IP (only loopback + tailnet)
- [ ] `ss -tlnp` shows no Postgres/Redis listener on host interfaces
- [ ] Wrong/missing `X-Admin-Token` → 401 on every route except `/health`, `/ready`
- [ ] Telegram from the owner account: `/profiles` lists 2; `/scan` queues 2; `/agents` shows
      three `demo` runs; `/jobs` empty with empty `sources.yaml`
- [ ] Telegram from another account / a group: no reply at all
- [ ] Repeated `/scan` with one real configured board: no duplicate jobs
- [ ] `docker compose exec agent-codex env` shows no `DATABASE_URL`/`ADMIN_TOKEN`
- [ ] `docker compose exec agent-codex ls /home/hunter/.claude` does not expose claude volumes
- [ ] Redis requires password (`redis-cli ping` unauthenticated → NOAUTH)
- [ ] Container memory totals within the budget; other host services unaffected

## Server (CLI mode, only after provider terms are confirmed)
- [ ] Each of the three CLIs logged in separately; one scan yields three `cli` runs
- [ ] Revoking one agent's login fails only that agent's run (scan `partial`, honest error)

## Deployment pipeline
- [ ] Deploy of a non-main SHA is refused
- [ ] Deploy without green CI is refused
- [ ] Deploy needs environment approval
- [ ] CI key cannot get a shell (`ssh … bash` → "unsupported command")
- [ ] `rollback` restores the previous release
- [ ] No inbound port 22 from the Internet (external port scan)
