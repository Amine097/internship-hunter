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
8. **Host guard** (`## Host isolation` below): installed, applied and persisted *before* the first
   deploy. Without it every container with a route out can dial the host's Tailscale IP.

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

## Host isolation

Containers with a route out can dial the **host** through the rootless daemon's user-space NAT
(finding, root cause and layers: `docs/security-architecture.md`, "Host boundary"). CI cannot prove
this either way (GitHub runners are rootful with `sshd` on `0.0.0.0`), so the CI `docker` job runs
the check in `report` mode and the production host must pass it in `enforce` mode.

### What is in this repository, and what is not applied

| Piece | Role | Applied by this repo? |
|---|---|---|
| `deploy/host-egress-guard.sh` | prevents: iptables rules inside the **rootless daemon's own** network namespace | **No - operator procedure below** |
| `EGRESS_FORBIDDEN_TARGETS` + `docker/egress-healthcheck.sh` | detects a missing guard; makes `up --wait` fail | yes (inert while the variable is empty) |
| `deploy/check-host-isolation.sh` (via `smoke-test.sh`) | verifies, from every container with a route out | yes |
| `egress_<name>` networks | proxies cannot reach each other or discovery/telegram | yes |

The guard never touches the host's iptables/nftables/UFW, sshd, Tailscale, Gluetun or the rootful
daemon and its containers: it refuses to run as root, refuses a target namespace equal to the
host's, and enters only `$XDG_RUNTIME_DIR/dockerd-rootless/child_pid`'s namespace.

### Operator procedure (reversible; run as `hunter-deploy`, the rootless daemon's owner)

```bash
sudo -iu hunter-deploy; export XDG_RUNTIME_DIR=/run/user/$(id -u)
HOST_TS_IP=100.107.22.84                       # tailscale ip -4
GUARD=/opt/internship-hunter/deploy/host-egress-guard.sh
```

0. **Install** the script root-owned (it is a security control, the deploy user must not edit it):
   `sudo install -o root -g root -m 0755 deploy/host-egress-guard.sh "$GUARD"`. Needs `iptables`
   and `nsenter` on the host (`iptables --version` should say `nf_tables`; Docker's `DOCKER-USER`
   chain must exist, i.e. Docker uses the iptables backend; `apply` refuses otherwise).
1. **Baseline** (expect `REACHABLE`: this reproduces the finding, nothing is changed):
   ```bash
   docker network create probe-net
   probe() { docker run --rm --network probe-net busybox:1.36 nc -z -w3 "$@" && echo REACHABLE || echo blocked; }
   probe $HOST_TS_IP 22; probe $HOST_TS_IP 8000
   ```
2. **Plan** (prints the rules and the resolver exception, changes nothing). The resolver is read
   from the daemon's `/etc/resolv.conf` (slirp4netns: `10.0.2.3`); if it is not what you expect,
   or none is found, pass `--dns <ip>`:
   `"$GUARD" plan --protect $HOST_TS_IP/32`
3. **Apply** (new connections only; the stack can stay up, `down` first is cleaner):
   `"$GUARD" apply --protect $HOST_TS_IP/32 && "$GUARD" status`
4. **Check immediately**: `probe $HOST_TS_IP 22; probe $HOST_TS_IP 8000` must print `blocked`;
   `docker run --rm --network probe-net busybox:1.36 nc -z -w5 1.1.1.1 443` must succeed
   (public Internet), `... nslookup api.anthropic.com` must resolve (DNS). If DNS fails, run
   step R and re-plan with the right `--dns`.
5. **Persist** (rules live in the daemon's namespace and vanish when the daemon restarts). A
   failing `ExecStartPost` fails the unit, so the daemon is down rather than unguarded:
   ```ini
   # ~/.config/systemd/user/docker.service.d/10-hunter-egress-guard.conf
   [Service]
   ExecStartPost=/opt/internship-hunter/deploy/host-egress-guard.sh apply --wait 90 --protect 100.107.22.84/32
   ```
   `systemctl --user daemon-reload && systemctl --user restart docker` (this user's daemon only),
   then `"$GUARD" status` again. `loginctl enable-linger hunter-deploy` must already be set.
6. **Tell the proxies what must stay unreachable** in `shared/.env` (mode 600):
   `EGRESS_FORBIDDEN_TARGETS=100.107.22.84:22,100.107.22.84:8000`. From now on a proxy that can
   reach either is unhealthy, its agent does not start, and `compose up --wait` (the deploy) fails
   and rolls back. Remove the probe network: `docker network rm probe-net`.
7. **Validate** the whole stack (plan below).

**R - Roll back** (restores Docker's own rules exactly): `"$GUARD" remove`; delete the drop-in,
`systemctl --user daemon-reload && systemctl --user restart docker`. Verified in the sandbox to leave
zero `HUNTER` rules and the identical reachability matrix as before `apply`.

### Validation plan (all on the production host, in this order)

| # | Check | Expected |
|---|---|---|
| V1 | `"$GUARD" status` | `active` |
| V2 | step 4 probes | tailnet `22`/`8000` blocked; `1.1.1.1:443` and DNS work |
| V3 | `docker compose up -d --wait` | proxies healthy with `EGRESS_FORBIDDEN_TARGETS` set |
| V4 | `ADMIN_TOKEN=... SMOKE_EXPECT_ROOTLESS=1 SMOKE_PROTECTED_IPS=$HOST_TS_IP deploy/smoke-test.sh` | `SMOKE TEST PASSED`; includes `CONNECT api.anthropic.com` / `api.openai.com` = 200 (set `SMOKE_EXTERNAL=1`, the default) |
| V5 | negative control: `"$GUARD" remove`, re-run V4 | **fails** naming `egress-* reaches 100.107.22.84:22`; then `apply` again |
| V6 | `systemctl --user restart docker`; `"$GUARD" status` | `active` without manual action |
| V7 | read-only: `docker ps` of the rootful daemon, `ufw status verbose`, `ss -tlnp`, Gluetun reachable from the tailnet as before | identical to your pre-change notes |

`SMOKE_PROTECTED_IPS` is added to the host's own addresses (`tailscale ip -4`, `ip -4 addr`), each
probed on `22 8000 2375 2376 5432` plus an ephemeral canary listener, from `egress-claude-1`,
`egress-claude-2`, `egress-codex`, `discovery`, `telegram` and `api`, and on every container's
gateway. In `enforce` mode (default) a reachable target, a probe that did not run, a missing
gateway or no target at all fails; with `SMOKE_EXPECT_ROOTLESS=1` a Tailscale address must be
among the targets.

### Evidence gathered without touching any live system

Real `iptables` (nf_tables 1.8.11, WSL2 kernel 6.6) and real packets in throwaway user+network
namespaces (`tests/test_host_egress_guard_netns.py`), running the actual script:

| from a container | before | with guard |
|---|---|---|
| host tailnet IP `:22`, `:8000`; host public IP; slirp gateway `10.0.2.2` | reachable | blocked |
| a container on `docker0` -> tailnet IP | reachable | blocked |
| public `8.8.8.8:443`, DNS to the resolver | works | works |
| peer on the same bridge; daemon -> container (docker-proxy style) | works | works |

With the real `docker/egress-proxy.sh` (tinyproxy 1.11.3; the image ships Alpine 3.20's) in the
same sandbox: `CONNECT` to an allow-listed public name -> `200` before and after; `CONNECT` to an
allow-listed *name that resolves to the host's tailnet IP* -> `200` before (the hostname filter
does not protect the host) and `500` after; IP literals, other ports, other names -> `403` both ways;
the healthcheck is unhealthy before and healthy after. **Not** verified: the production host
itself, slirp4netns/pasta behaviour, Docker's iptables rule order on that host, Alpine's tinyproxy.

### Limits you accept

- Public Internet space stays open at the network level: a compromised proxy can open a socket to
  any public IP and port; only the hostname list narrows the CONNECT path.
- The guard is lost when the daemon restarts until `ExecStartPost` re-applies it; containers with
  `restart: unless-stopped` may run unguarded for the first seconds. A host address acquired later
  (DHCP) is covered after the next `apply`; the smoke test detects the drift. Established
  connections are not cut.
- IPv4/iptables only (IPv6 is rejected wholesale for new forwarded traffic; containers are
  IPv4-only). Docker's nftables mode (no `DOCKER-USER`) is refused, not worked around.

## Go-live gates (all must be true before setting `DEPLOY_ENABLED`)

- [ ] CI is green on `main`, including the `docker` job (real daemon) and `lint-test`
      without skips.
- [ ] `docs/acceptance-checklist.md` server section executed on the real host.
- [ ] Rootless Docker confirmed on the host; script refusal tested once.
- [ ] **Host guard applied and persisted** (operator procedure above) and validation V1-V7 done.
- [ ] `shared/.env` sets `EGRESS_FORBIDDEN_TARGETS` (tailnet IP on `:22` and `:8000`).
- [ ] `SMOKE_EXPECT_ROOTLESS=1 SMOKE_PROTECTED_IPS=<tailscale ip> deploy/smoke-test.sh` passes
      **in enforce mode** on the host (the CI run only reports host exposure).
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
