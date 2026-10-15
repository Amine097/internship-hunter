# Deployment design (Tailscale, GitHub-hosted CI/CD)

Status: **designed and partly exercised, not enabled.** `deploy.yaml` is disabled until the
repository variable `DEPLOY_ENABLED` is `true`, and has never run. The server-side script has
been tested with stubbed Docker (`tests/test_deploy_script.py`) and once against a real local
Docker daemon (see "Evidence" in the PR description). No secrets are configured.

## Principles

- SSH is **never** published to the Internet; `sshd` listens on the Tailscale interface only.
- **No self-hosted runner** on the shared server. GitHub-hosted runners join the tailnet as an
  ephemeral `tag:ci` node for one job.
- The server holds **no GitHub credentials** and **never builds**. CI builds images, tags them
  by commit SHA, signs a manifest, and ships one bundle; the server verifies and loads it.
- The SSH key is a *forced command* key: `deploy` (bundle on stdin) or `rollback`, nothing else.
- **Two independent keys**: the SSH key (reaches the server) and the release-signing key
  (authorises content). The server only trusts the signing key's public half
  (`shared/allowed_signers`), so a stolen SSH key alone cannot deploy arbitrary code.
- **The signing key never meets repository code.** Jobs are split: `build` (runs repository
  code, no secrets) → `sign` (own GitHub environment `release-signing`, main only, runs
  trusted-main shell that only hashes/verifies the artifacts) → `deploy` (transport only).
  `tests/test_workflows.py` enforces which job may reference which secret.
- **Rootless Docker is mandatory** for the deploy user: the script refuses a rootful daemon
  (exit 5). A docker-group member is root-equivalent on a shared host.
- Developer agents (Claude Code/Codex on your workstation) get no server access, no deploy or
  signing key, and no Docker socket. No container mounts the Docker socket.
- Deploys are manual (`workflow_dispatch`) behind a protected `production` environment.

## Bundle and verification

`deploy/build-artifacts.sh` (no secrets) produces `source.tar.gz` (`git archive`),
`images.tar.gz` (`docker save` of `internship-hunter-{app,agent,egress}:<sha>`) and a
6-line `manifest` (sha, hashes, created, `schema_head`, `rollback_compatible`);
`deploy/sign-bundle.sh` recomputes the schema metadata from the source archive (text parsing
only), checks commit id, member types and script modes, and writes + signs the manifest
itself. `deploy/make-bundle.sh` does both locally. `remote-deploy.sh` then:

0. accepts only regular files/directories in the bundle and the source archive (no
   symlinks, hard links or devices);
1. takes the deploy lock (`flock`; a concurrent deploy exits 4) and checks rootless Docker;
2. caps the bundle size and accepts exactly the four expected members;
3. verifies the SSH signature (`ssh-keygen -Y verify`, namespace `hunter-release`);
4. parses the manifest strictly and verifies both SHA-256 hashes;
5. refuses a validly signed but **older** bundle than the running release (replay/downgrade);
6. rejects archives with absolute or `..` paths; unpacks to `releases/<sha>`;
7. `docker load`s the images (never `build`);
8. takes a `pg_dump` backup and aborts on failure, before any change;
9. (schema compatibility with the running release is checked here, before any change;
   see `docs/backup-restore.md`)
10. switches `current`, runs `compose up -d --no-build --wait`, then checks `/ready` and
   `submission_enabled == false`;
10. on **any** failure restores the previous release; on success records `current_sha` /
    `previous_sha` and prunes old releases (never current or previous).

`rollback` re-activates `previous_sha` from already-loaded images: no build, no network, no
registry. It does not downgrade the database (see `docs/backup-restore.md`).

## Flow

```
you -> Actions "Deploy (manual)" (action=deploy, ref=<full SHA>)
     -> verify: run from main, SHA ancestor of main, green ci.yaml run for that SHA
     -> build: images + signed bundle (secret RELEASE_SIGNING_KEY)
     -> environment "production" approval (required reviewers)
     -> runner joins tailnet (tag:ci) -> ssh hunter-deploy@host "deploy" < bundle.tar
```

## One-time server setup (manual, by you)

1. User `hunter-deploy` with **rootless Docker** (`dockerd-rootless-setuptool.sh install`).
2. `mkdir -p /opt/internship-hunter/{releases,state,staging,shared,backups,deploy}`; install
   `deploy/remote-deploy.sh` into `/opt/internship-hunter/deploy/` **root-owned and not
   writable by the deploy user** (it is the forced command).
3. `shared/.env` (mode 600) from `.env.example`: **five** independent random values
   (Postgres, admin, three agent tokens). Never commit it.
4. `shared/allowed_signers`: `release ssh-ed25519 AAAA…` (public half of the signing key).
   Generate with `ssh-keygen -t ed25519 -N '' -f release_signing_key`; keep the private half
   only as the GitHub secret.
5. `authorized_keys`:
   `restrict,command="/opt/internship-hunter/deploy/remote-deploy.sh" ssh-ed25519 AAAA… ci-deploy`
6. Tailscale ACL: `tag:ci` may reach only `tag:hunter-prod:22`.
   ```json
   {"tagOwners": {"tag:ci": ["autogroup:admin"], "tag:hunter-prod": ["autogroup:admin"]},
    "acls": [{"action": "accept", "src": ["tag:ci"], "dst": ["tag:hunter-prod:22"]}]}
   ```
7. Resource budget: containers are capped at ~3.2 GB total (see `compose.yaml`); check it
   against the other services on the host first.

## GitHub configuration (manual)

| Kind | Name | Value |
|---|---|---|
| Variable (repo) | `DEPLOY_ENABLED` | leave unset/`false` until the gates below pass |
| Environment | `production` | required reviewers; **deployment branches: `main` only** |
| Secret (env) | `TS_OAUTH_CLIENT_ID`, `TS_OAUTH_SECRET` | Tailscale OAuth client for `tag:ci` |
| Secret (env) | `DEPLOY_SSH_KEY`, `DEPLOY_KNOWN_HOSTS` | forced-command key; pinned host key |
| Environment | `release-signing` | **only** home of `RELEASE_SIGNING_KEY`; deployment branches: `main` only |
| Secret (env `release-signing`) | `RELEASE_SIGNING_KEY` | private signing key (not the SSH key); never a repository-level secret |
| Variable (env) | `DEPLOY_USER`, `DEPLOY_TAILNET_HOST` | `hunter-deploy`, MagicDNS name |

`workflow_dispatch` runs the workflow file of the *selected* branch; the environment's
"main only" rule is what stops a branch-edited workflow from reaching the secrets.
Also: branch protection on `main` requiring all CI jobs, and secret scanning.

## Stopping workers (routine deploys)

`docker compose` sends SIGTERM and waits `stop_grace_period: 150s` for `discovery`. A worker
that is stopping checks between the agent and ATS phases and hands the task back with
`release()` — **without consuming an attempt** — so routine deployments do not exhaust the
three retries reserved for crashes. Only a worker killed after the grace period goes through
lease expiry and spends one.

## Host isolation depends on the host (what CI cannot prove)

On a rootful Docker host every container can reach services the host listens on at the
bridge gateway address. GitHub-hosted runners are such hosts (`sshd` on `0.0.0.0:22`), so the
CI `docker` job runs `deploy/smoke-test.sh` with `SMOKE_HOST_ISOLATION=report` and prints
what is reachable. On the production host the same script **must** pass with the default
`enforce` mode and `SMOKE_EXPECT_ROOTLESS=1`; that requires rootless Docker and `sshd` bound
to the Tailscale interface only. Whether rootless Docker's slirp4netns/pasta gateway exposes
host loopback on your setup is **unverified** until that run.

## Go-live gates (all must be true before setting `DEPLOY_ENABLED`)

- [ ] CI is green on `main`, including the `docker` job (real daemon) and `lint-test`
      without skips.
- [ ] `docs/acceptance-checklist.md` server section executed on the real host.
- [ ] Rootless Docker confirmed on the host; script refusal tested once.
- [ ] `SMOKE_EXPECT_ROOTLESS=1 deploy/smoke-test.sh` passes **in enforce mode** on the host
      (the CI run only reports host exposure).
- [ ] Provider terms for unattended CLI use confirmed (otherwise stay in `AGENT_MODE=demo`).
- [ ] Backup copied off-host once and `deploy/verify-restore.sh` run on the server.
- [ ] Rollback rehearsed on the server with two real releases.

## Agent credentials

Log in once per container, interactively, from your own terminal:

```bash
docker compose run --rm --no-deps -it agent-claude-1 claude   # proxies must be running: docker compose up -d egress-claude-1
docker compose run --rm --no-deps -it agent-claude-2 claude
docker compose run --rm --no-deps -it agent-codex codex login
```

Each login lands in that agent's own named volume. Do not switch to `AGENT_MODE=cli` before
the provider terms are confirmed and the CLI flags in `hunter/agents.py` are smoke-tested.

## Known gaps

See "Threats considered and residual risk" in `docs/security-architecture.md`, plus:
no dependency lockfile, no base-image digest pinning, no off-host backup, no alerting,
and the per-release signing key has no rotation procedure yet.
