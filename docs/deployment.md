# Deployment design (Tailscale, GitHub-hosted CI/CD)

Status: **designed, not yet exercised.** No secrets are configured, nothing has been deployed,
and `deploy.yaml` has never run. Treat every step below as unverified until the acceptance
checklist (`docs/acceptance-checklist.md`) has been executed on the real server.

## Principles

- SSH is **never** published to the Internet. `sshd` listens on the Tailscale interface only
  (or use Tailscale SSH); the router/firewall exposes no port 22.
- **No self-hosted runner** on the shared server. GitHub-hosted runners join the tailnet as an
  ephemeral node tagged `tag:ci` for the duration of one deploy job.
- The server holds **no GitHub credentials**. CI ships a `git archive` tarball of one verified
  commit; the server never pulls.
- The CI SSH key is a *forced command* key: it can run `deploy <sha>` or `rollback` and nothing
  else (no shell, no port forwarding, no pty).
- Developer agents (Claude Code / Codex on your workstation) get **no** access to the server,
  the deploy key, or the Docker socket. The `agent-*` containers get no Docker socket either.
- Production deploys are manual (`workflow_dispatch`), gated by a protected GitHub environment
  with required reviewers, and only accept a SHA that is on `main` with a green CI run.

## Flow

```
you -> Actions "Deploy (manual)" (input: full SHA)
     -> verify: SHA ancestor of main, green ci.yaml run for that SHA
     -> environment "production" approval
     -> runner joins tailnet (tag:ci, ephemeral, OAuth client)
     -> git archive | ssh hunter-deploy@<tailnet-host> "deploy <sha>"
     -> forced command: unpack to releases/<sha>, switch `current`, compose up --wait,
        check /ready and submission_enabled=false, prune old releases
```

Rollback: run the same forced command with `rollback` (switches to `previous`).

## One-time server setup (manual, by you)

1. Create an unprivileged user `hunter-deploy`. Preferred: give it **rootless Docker**
   (`dockerd-rootless-setuptool.sh install`) so the deploy key is not root-equivalent. Adding a
   user to the `docker` group is root-equivalent on a *shared* host and should be avoided.
2. `mkdir -p /opt/internship-hunter/{releases,shared,deploy}`; install `deploy/remote-deploy.sh`
   to `/opt/internship-hunter/deploy/` (root-owned, mode 755, **not** writable by the deploy
   user, because it is the forced command).
3. Create `/opt/internship-hunter/shared/.env` (mode 600, owner `hunter-deploy`) from
   `.env.example` with three independent long random values. Never commit it.
4. `~hunter-deploy/.ssh/authorized_keys`:
   `restrict,command="/opt/internship-hunter/deploy/remote-deploy.sh" ssh-ed25519 AAAA… ci-deploy`
5. Tailscale: tag the server `tag:hunter-prod`, create an OAuth client scoped to `tag:ci`.
   ACL (only CI → deploy SSH, nothing else):
   ```json
   {"tagOwners": {"tag:ci": ["autogroup:admin"], "tag:hunter-prod": ["autogroup:admin"]},
    "acls": [{"action": "accept", "src": ["tag:ci"], "dst": ["tag:hunter-prod:22"]}]}
   ```
6. Resource guard: the compose file caps each container (memory/CPU/pids); total budget is
   ~3.5 GB of RAM. Check against the other Docker services on the host before first start.

## GitHub configuration (manual)

| Kind | Name | Value |
|---|---|---|
| Environment | `production` | required reviewers, restrict to `main` |
| Secret (env) | `TS_OAUTH_CLIENT_ID`, `TS_OAUTH_SECRET` | Tailscale OAuth client for `tag:ci` |
| Secret (env) | `DEPLOY_SSH_KEY` | private key of the forced-command key |
| Secret (env) | `DEPLOY_KNOWN_HOSTS` | server host key line (pin it; do not TOFU) |
| Variable (env) | `DEPLOY_USER`, `DEPLOY_TAILNET_HOST` | `hunter-deploy`, MagicDNS name |

Also enable branch protection on `main` (require the `CI` checks) and secret scanning.

## Agent credentials

Each agent has its own named volume and its own container; none sees the others' volume or
the database. Log in once per container (interactive, from your own terminal):

```bash
docker compose run --rm --no-deps -it agent-claude-1 claude
docker compose run --rm --no-deps -it agent-claude-2 claude
docker compose run --rm --no-deps -it agent-codex codex login
```

Do not switch to `AGENT_MODE=cli` until each subscription's terms allow unattended CLI use
(the README flags this as unconfirmed) and the CLI flags used in `hunter/agents.py` have been
smoke-tested against the pinned CLI versions in `docker/agent.Dockerfile`.

## Known gaps

- Redis is shared by all workers: an agent container could read other queues' payloads (search
  profiles only; no secrets are enqueued). Per-agent Redis ACL users are a follow-up.
- No lockfile / digest-pinned base images yet; no Alembic migrations (`create_all` only);
  no backup/restore job; no alerting.
- Config files are baked into the image, so editing `config/*.yaml` requires a redeploy.
