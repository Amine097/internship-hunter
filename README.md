# Internship Hunter — bootstrap 0.1.0

Private, self-hosted, **read-only** internship / part-time job discovery bootstrap.
Three agents (Claude #1, Claude #2, Codex) plan searches in parallel; each runs in its own
container behind a small HTTP planner and has **no** Redis/PostgreSQL access
(see `docs/security-architecture.md`). The discovery
worker collects only from explicitly configured, public Greenhouse and Lever APIs.
Jobs and scan traces are persisted in PostgreSQL. RQ/Redis coordinates workloads.

> **No auto-application exists in this version.** No email is sent, no CV is generated,
> and no browser automation runs. `AGENT_MODE=demo` makes deterministic local plans,
> **without contacting Claude or Codex**. `AGENT_MODE=cli` needs independent CLI logins,
> allowed provider usage, and fresh CLI smoke tests before unattended operation.

## Requirements

- Linux server with Docker Engine + Docker Compose v2, or Docker Desktop + WSL2.
- Git, Python 3.12 for local unit tests.
- GitHub CLI (`gh`) for private repository creation.
- Telegram bot from `@BotFather` + your numeric user ID (do not send secrets to agents).
- Tailscale recommended for private server access.

## Run (server / WSL2)

```bash
cp .env.example .env
# six independent values: Postgres, Redis, admin token, and one inbound token per agent:
for i in 1 2 3 4 5 6; do python3 -c 'import secrets; print(secrets.token_urlsafe(40))'; done
# Set TELEGRAM_BOT_TOKEN and TELEGRAM_ALLOWED_USER_ID; do NOT commit .env.
docker compose config -q
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8000/ready
curl -fsS -H "X-Admin-Token: $(grep '^ADMIN_TOKEN=' .env | cut -d= -f2-)" \
  http://127.0.0.1:8000/profiles
```

If `docker compose config -q` reports an unset password, first update `.env`.
Telegram: message `/profiles` and `/scan` to your bot in a **private chat**.
The `POST /scan/{id}` endpoint queues one profile by numerical ID; `/scan` in
Telegram queues **all enabled** profiles. Review `/scans`, `/jobs`, `/agents` (also available as Telegram commands).

### Add permitted real job boards

Update `config/sources.yaml` to list known Greenhouse board handles and Lever site
handles. Board identifiers are obtained from the employer's own public job board.
Config is baked into the image: redeploy (`docker compose up -d --build`) after updating. In V1 we intentionally do **not** automatically
crawl job boards, Google, LinkedIn or Workday. No fabricated jobs appear.

`/scan` verifies the three agents are invoked and tests ingestion from the list
of **explicitly configured ATS boards**. **Agent-generated queries are stored
but not yet executed against arbitrary search engines** — that's milestone 2.
Each job's normalized ATS identifier is deduplicated. Cross-ATS semantic dedup,
scoring, job-fit evaluation, CV generation, applications and dashboard are later milestones.

### Enable CLI agents after authentication checks

Run the CLI once in each *isolated* container. Do not paste credentials into
Telegram, GitHub, the .env example, or a model prompt.

```bash
docker compose run --rm --no-deps -it agent-claude-1 claude
docker compose run --rm --no-deps -it agent-claude-2 claude
docker compose run --rm --no-deps -it agent-codex codex login
```

A headless server may show an OAuth URL to open on your phone or PC.
Sessions are stored in **three different Docker volumes** and never in the repo.
Check usage rights and subscription vs. API billing before enabling unattended
use; for third-party integrations Anthropic prefers API keys. This system never
extracts or proxies OAuth session tokens, and does not rotate identities to bypass quotas.

When all three work:

```bash
# edit .env: AGENT_MODE=cli
docker compose up -d --force-recreate   # unverified: see docs/deployment.md
# /scan again in Telegram
```

`claude -p` and `codex exec` are CLI wrappers, not a guarantee that providers
support unattended third-party usage in every plan. Errors show as failed agent
runs; the orchestrator does not silently generate model results.

### Tests and CI

```bash
python3.12 -m venv .venv && . .venv/bin/activate   # CI and images use 3.12
pip install -e '.[dev]'
ruff check hunter tests
pytest -q           # set TEST_DATABASE_URL / TEST_REDIS_URL to also run the real-service tests
```

CI (`.github/workflows/ci.yaml`): lint, tests (PostgreSQL + Redis services), pip-audit,
gitleaks, shellcheck, hadolint, image builds, and a real-daemon compose smoke/isolation test
(`deploy/smoke-test.sh`). No secrets or
paid model calls. Deployment is a separate **manual** workflow over Tailscale; see
`docs/deployment.md` and `docs/acceptance-checklist.md`. Never expose SSH to the Internet.

### Create your private GitHub repository

```bash
git init -b main
git add .
git commit -m "bootstrap: private internship hunter milestone 1"
gh auth login
gh repo create internship-hunter --private --source=. --remote=origin --push
```

If your GitHub already has a repo called `internship-hunter`, use another name.

## Defaults (saved in config/search_profiles.yaml)

- `internship-summer-2027`: start **2027-07-01 through 2027-08-01**, duration **2–3 months**, Switzerland prioritized with Europe secondary.
- `part-time-europe`: available from **2026-10-14**, hours flexible, Switzerland prioritized with Europe secondary.
- Unknown durations and unknown visa conditions are not rejected merely for
  being unknown. No real application is submitted until verified permissions,
  eligibility answers and anti-duplicate safeguards exist.

## Security notes

- `.env`, volumes, account cookies and secrets must never be committed.
- Redis requires a password and uses JSON serialization with a job allowlist; agents have no Redis/DB access and cannot reach each other (`docs/security-architecture.md`).
- API is bound to `127.0.0.1:8000`, not exposed to the LAN / public Internet.
  Use SSH forwarding (`ssh -L 8000:127.0.0.1:8000 host`) or private Tailscale.
- API requires `X-Admin-Token`. Bot accepts only `TELEGRAM_ALLOWED_USER_ID` in a private chat.
- Agents have their own credentials. They cannot submit applications in V1.
- Review any source before adding it; only explicit Greenhouse and Lever handles
  are permitted. Requests do not follow HTTP redirects and have finite timeouts.
- Dependency pins use ranges in this bootstrap; produce and commit a lockfile
  before production releases. Keep images updated and audit dependencies.
- Backup and restore of PostgreSQL, account data retention, rate-limit enforcement,
  auditing and public dashboard are not implemented yet.

## Acceptance criteria

1. `docker compose up -d --build` starts all components with local credentials.
2. `/health` reports `submission_enabled: false`.
3. Telegram `/profiles` shows two saved search profiles.
4. Telegram `/scan` queues two scans, each run executes three independent
   demo planners (or authenticated CLI planners if `cli` is enabled).
5. `/agents` reports agent status and planning queries.
6. With empty `sources.yaml`, `/jobs` is empty; with a valid real source, ATS jobs
   appear with stable IDs and no duplicates upon repeated scans.
7. CI runs unit tests without secrets and never submits a candidature.

**Validation status**: unit/integration tests run against SQLite and fakeredis. Docker
startup, PostgreSQL, real Telegram, internet ATS and CLI checks have *not* been executed
(see `docs/acceptance-checklist.md`).
