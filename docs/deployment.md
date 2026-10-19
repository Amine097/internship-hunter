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
10. switches `current`, runs `compose up -d --no-build --wait`, then checks that the `api`
   container publishes exactly `127.0.0.1:18000` and that `/ready` and `submission_enabled ==
   false` answer there, and finally runs the **host-isolation check in enforce mode**
   (`## Host isolation

Containers with a route out can dial the **host** through the rootless daemon's user-space NAT
(finding, root cause and layers: `docs/security-architecture.md`, "Host boundary"). CI cannot prove
this either way (GitHub runners are rootful with `sshd` on `0.0.0.0`), so the CI `docker` job runs
the check in `report` mode and the production host must pass it in `enforce` mode.

### What is in this repository, and what is not applied

| Piece | Role | Applied by this repo? |
|---|---|---|
| `deploy/host-egress-guard.sh` | **prevents**: iptables rules inside the **rootless daemon's own** network namespace; `status` verifies the FULL IPv4+IPv6 policy | **No - operator procedure below** |
| `remote-deploy.sh` isolation gate | **refuses** to deploy/roll back without the guard, runs the enforce check after `up --wait` | yes (inert until a deploy is attempted) |
| `deploy/check-host-isolation.sh` (also via `smoke-test.sh`) | **verifies**, from every container with a route out, with positive controls | yes |
| `docker/isolation-gate.sh`, `egress-proxy.sh` start check | **start gate**: api/discovery/telegram/proxies exit instead of starting while `EGRESS_FORBIDDEN_TARGETS` answers | yes (inert while the variable is empty) |
| `EGRESS_FORBIDDEN_TARGETS` + proxy healthcheck | **detects** a guard that vanished while running | yes |
| `egress_<name>` networks | proxies cannot reach each other or discovery/telegram | yes |

The guard never touches the host's iptables/nftables/UFW, sshd, Tailscale, Gluetun or the rootful
daemon and its containers: it refuses to run as root, refuses a target namespace equal to the
host's, and before entering the namespace of `$XDG_RUNTIME_DIR/dockerd-rootless/child_pid` it
proves that process is *this user's* rootless daemon (owned by the uid, a `dockerd`/`rootlesskit`
command line, a user namespace mapped to this uid and different from ours, its socket present).
`HUNTER_GUARD_PROC` (a fake `/proc` for tests) is refused unless `HUNTER_GUARD_TEST_MODE=1`.

### The deploy gate (what `remote-deploy.sh` now enforces)

For `deploy`, `deploy-irreversible` **and** `rollback`, before anything is read, loaded or changed:

| Check | Failure |
|---|---|
| `/opt/internship-hunter/deploy/host-egress-guard.sh` and `check-host-isolation.sh` exist, are executable regular files (not symlinks), root-owned, not group/world-writable, in a directory that is too | exit 11 |
| `shared/.env` sets `EGRESS_FORBIDDEN_TARGETS` to a non-empty, well-formed `ip:port` list (the last assignment wins, as in compose; the caller's environment is ignored) | exit 11 |
| optional `deploy/host-isolation.conf` (`ROOTFUL_TARGETS=ip:port,...`) is trusted | exit 11 |
| `host-egress-guard.sh status` exits 0: the **full** policy is installed and unmodified | exit 12 |
| `127.0.0.1:18000` is free, or held by this application's own running `api` (read-only `ss`) | exit 3 |

After `compose up --wait` and the health checks, `check-host-isolation.sh` runs in **enforce**
mode with `SMOKE_PROTECTED_IPS` taken from the targets (ambient `SMOKE_*` variables are removed first).
A failure is a failed activation: the previous release is restored (and gated again); a failed
*first* deploy is torn down (`compose down`, no `current`); a restore that cannot be verified either
stops the stack - an unreachable service is preferred to an exposed one.

### Operator procedure (reversible; as `hunter-deploy`, the rootless daemon's owner)

```bash
sudo -iu hunter-deploy; export XDG_RUNTIME_DIR=/run/user/$(id -u)
HOST_TS_IP=100.107.22.84                       # tailscale ip -4
D=/opt/internship-hunter/deploy; GUARD=$D/host-egress-guard.sh
```

0. **Install** (root; the deploy user must not be able to edit a security control or its directory):
   `sudo install -o root -g root -m 0755 deploy/host-egress-guard.sh deploy/check-host-isolation.sh "$D"/`
   Needs `iptables`, `ip6tables`, `nsenter`, `ss`, `python3` on the host (`iptables --version` should
   say `nf_tables`; Docker's `DOCKER-USER` chain must exist - the iptables backend; `apply` refuses
   otherwise, and also refuses without `ip6tables`).
1. **Baseline** (expect `REACHABLE`: this reproduces the finding, nothing is changed):
   ```bash
   docker network create probe-net
   probe() { docker run --rm --network probe-net busybox:1.36 nc -z -w3 "$@" && echo REACHABLE || echo blocked; }
   probe $HOST_TS_IP 22; probe $HOST_TS_IP 8000
   ```
2. **Persistent parameters** (root-owned, next to the script; `status` and the re-apply then need no
   arguments and cannot disagree with the first `apply`):
   ```bash
   printf 'PROTECT=%s/32\n' "$HOST_TS_IP" | sudo tee "$D/host-egress-guard.conf" >/dev/null
   sudo chmod 644 "$D/host-egress-guard.conf"     # DNS=<ip> is added only if auto-detection is wrong
   ```
3. **Plan** (prints the rules, the resolver exception and the host addresses; changes nothing). The
   resolver comes from the daemon's `/etc/resolv.conf` (slirp4netns: `10.0.2.3`); the protected
   host addresses are every global IPv4 address on every interface - rootful `docker0`/`br-*`
   gateways included, because rootful containers' published ports listen there - plus the host's
   default gateway: `"$GUARD" plan`
4. **Apply** (new connections only) and verify it verified itself: `"$GUARD" apply && "$GUARD" status`
5. **Check immediately**: `probe $HOST_TS_IP 22; probe $HOST_TS_IP 8000` must print `blocked`;
   `docker run --rm --network probe-net busybox:1.36 nc -z -w5 1.1.1.1 443` must succeed and
   `... nslookup api.anthropic.com` must resolve. If DNS fails: step R, then set `DNS=` in the conf.
6. **Persist** (the rules live in the daemon's namespace and vanish when the daemon restarts). A
   failing `ExecStartPost` fails the unit, so the daemon is down rather than unguarded:
   ```ini
   # ~/.config/systemd/user/docker.service.d/10-hunter-egress-guard.conf
   [Service]
   ExecStartPost=/opt/internship-hunter/deploy/host-egress-guard.sh apply --wait 90
   ```
   `systemctl --user daemon-reload && systemctl --user restart docker` (this user's daemon only),
   then `"$GUARD" status`. `loginctl enable-linger hunter-deploy` must already be set.
7. **Tell the stack what must stay unreachable** in `shared/.env` (mode 600):
   `EGRESS_FORBIDDEN_TARGETS=100.107.22.84:22,100.107.22.84:8000`. Optional, root-owned
   `"$D/host-isolation.conf"` with `ROOTFUL_TARGETS=172.17.0.2:8080,...` lists specific rootful
   container `ip:port`s to probe (nothing is scanned; only what you list). `docker network rm probe-net`.
8. **Validate** the whole stack (plan below).

**R - Roll back** (restores Docker's own rules exactly): `"$GUARD" remove`; delete the drop-in and
the conf, `systemctl --user daemon-reload && systemctl --user restart docker`. Verified in the
sandbox to leave zero `HUNTER` rules and the identical reachability matrix as before `apply`.
(Note: while the guard is removed the deploy gate refuses; that is intended.)

### Startup window (does a daemon restart start containers before the guard?)

**Finding.** Containers with `restart: unless-stopped` are restarted by the daemon itself when it
starts. An `ExecStartPost=` runs after the unit is considered started, and a `Type=notify` daemon
reports ready around when it finishes restoring containers, so **a restarted outbound-capable
container can run before the guard is re-applied** - for `discovery`, `telegram` and `api`
exactly as for the proxies. Neither `ExecStartPost` nor a healthcheck (first result after
`interval`, i.e. up to 10 s, and it only *reports*) closes that. This was reasoned from Docker's
documented behaviour and systemd's semantics; it was **not** measured on the production daemon.
`depends_on` is not honoured by restart policies either.

**Design (implemented): every service with a route out starts through a gate.**
`api`, `discovery` and `telegram` use `docker/isolation-gate.sh` as ENTRYPOINT, the proxies run
`egress-forbidden-check.sh` first. If any `EGRESS_FORBIDDEN_TARGETS` entry *connects or answers
"refused"*, the container exits non-zero **before any application code runs**, and the restart policy
retries (Docker's back-off is at most one minute) until the guard is in place. The gate sends a bare
`connect()` and no data. Tested with real packets (`tests/test_host_egress_guard_netns.py`: service
stopped before `apply`, running after, stopped again after `remove`) and with the Alpine busybox `nc`.

| In the window | Covered by |
|---|---|
| application code of api/discovery/telegram runs unguarded | **no longer possible** if the host answers on a listed target |
| a proxy serves a request unguarded | **no longer possible** (start check) |
| agents | not affected: internal networks, no route to the host |

**What the gate does not do** (accepted for `AGENT_MODE=demo`, documented): it only knows the
targets it was given - the guard is the complete policy; it checks at *start* only (a guard removed
later is caught by the proxies' healthcheck, within ~50 s, and by the next deploy's gate, not
for `discovery`/`telegram`/`api` while they run); a host that silently drops (rather than answers)
packets from the daemon would make an unguarded start look guarded for those targets.

**Stronger design (not implemented; needs a change on the production host; required before
`AGENT_MODE=cli` holds real provider credentials):** `restart: "no"` on every outbound-capable
service plus a user unit `hunter-stack.service` (`After=docker.service`, `ExecStartPre=` the guard's
`status`, `ExecStart=` `compose up -d --wait`), so that *nothing* can start until the guard is verified.

**Validation (W1, stack stopped first so nothing is exposed while the guard is off):**
`docker compose -p internship-hunter stop` → `"$GUARD" remove` → `docker compose -p internship-hunter start discovery egress-codex api`
→ each must be `Restarting`, with `isolation-gate: refusing to start` / `egress-proxy: refusing to
start` in `docker logs` and **no** worker/uvicorn/tinyproxy log lines → `"$GUARD" apply` → all `Up`
within about a minute, `docker compose -p internship-hunter start` the rest, then the smoke test.
**W2:** `systemctl --user restart docker`; `docker logs --since 2m` may show a few gate refusals
(that is the window being closed); after two minutes `docker ps` is healthy and `"$GUARD" status` is active.

### Validation plan (all on the production host, in this order)

| # | Check | Expected |
|---|---|---|
| V1 | `"$GUARD" status` | `active (pid ...)` |
| V2 | step 5 probes | tailnet `22`/`8000` blocked; `1.1.1.1:443` and DNS work |
| V3 | `docker compose up -d --wait` | proxies healthy with `EGRESS_FORBIDDEN_TARGETS` set |
| V4 | `ADMIN_TOKEN=... SMOKE_EXPECT_ROOTLESS=1 SMOKE_PROTECTED_IPS=$HOST_TS_IP deploy/smoke-test.sh` | `SMOKE TEST PASSED`; includes `CONNECT api.anthropic.com` / `api.openai.com` = 200 (`SMOKE_EXTERNAL=1`, the default), "controls verified" for every container |
| V5 | negative control: `"$GUARD" remove`, re-run V4 | **fails** naming `egress-* reaches 100.107.22.84:22 (connection OPEN)` and `... :2375 (connection REFUSED ...)`; then `apply` again |
| V6 | idempotence: run `"$GUARD" apply` twice, then `status` | still `active`; exactly two jumps per chain, no duplicated rules |
| V7 | `systemctl --user restart docker`; `"$GUARD" status` | `active` without manual action |
| V8 | W1 and W2 above | gates refuse while unguarded, services come up after `apply` |
| V9 | read-only: `docker ps` of the rootful daemon, `ufw status verbose`, `ss -tlnp`, Gluetun reachable from the tailnet as before, `ss -ltn 'sport = :18000'` shows only this application | identical to your pre-change notes |

`SMOKE_PROTECTED_IPS` is added to the host's own addresses; each is probed on `22 8000 2375 2376 5432`
plus an ephemeral canary listener, from every service that has a route out (computed from
`compose config`, never a hard-coded shortlist), together with each container's gateway, the host's
default gateway (22/80/443), `169.254.169.254:80`, Tailscale MagicDNS `100.100.100.100:53/80` and
your `ROOTFUL_TARGETS`. **A refusal counts as reaching the host** (it is an answer from the protected
side). Every container must first pass its own positive controls (the probe tool connects to a listener
in that container and recognises a refusal); a missing/broken `nc` or `python`, a failed `docker exec`,
an unknown output line, a missing or duplicated result, or an unclassifiable error fails in `enforce`
mode. With `SMOKE_EXPECT_ROOTLESS=1` a Tailscale address must be among the targets.

### Evidence and what CI can and cannot show

Real `iptables` (nf_tables 1.8.11, WSL2 kernel 6.6) and real packets in throwaway user+network
namespaces (`tests/test_host_egress_guard_netns.py`), running the actual scripts:

| from a container | before | with guard |
|---|---|---|
| host tailnet IP `:22`, `:8000`; host public IP; slirp gateway `10.0.2.2`; bridge gateway | reachable | blocked |
| a closed port on those addresses (e.g. `:2375`) | **refused** (an answer) | blocked |
| a container on `docker0` -> tailnet IP | reachable | blocked |
| public `8.8.8.8:443`, DNS to the resolver | works | works |
| peer on the same bridge; daemon -> container (docker-proxy style) | works | works |
| start gate of a service on `docker0` | stops it | lets it run |
| 9 kinds of tampering (a reject deleted, ACCEPT inserted before our jumps, a jump removed, chain flushed, ACCEPT inside the chain, INPUT chain edited, IPv6 chain flushed, INPUT jump removed, ACCEPT inserted before Docker's own jump) | - | `status` fails; `apply` repairs (the displaced Docker jump is reported, not "repaired") |

With the real `docker/egress-proxy.sh` (tinyproxy 1.11.3; the image ships Alpine 3.20's) in the same
sandbox: `CONNECT` to an allow-listed public name -> `200` before and after; to an allow-listed *name that
resolves to the host's tailnet IP* -> `200` before (the hostname filter does not protect the host) and `500`
after; IP literals, other ports, other names -> `403` both ways. The probe and gate scripts were also run
with **Alpine 3.20's own busybox `nc`** (1.36.1): `nc -vv -z` prints `Connection refused` /
`Host is unreachable` / `Network unreachable` / `Operation timed out`, and **`nc -z` alone is silent on a
refusal** - which is why the probes use `-vv` and calibrate against it.

**CI.** The `host-guard-netns` job runs those packet tests on `ubuntu-22.04` (no sudo, no AppArmor
change - this repository never relaxes either). If namespaces cannot be created there it ends with a
**warning annotation and a step summary that say the tests did not run** and list the replacement
checks (V1, V2, V4, V5, V6, V8 above); a skipped test is never reported as a pass. On Ubuntu 24.04 the
same tests skip locally unless user namespaces are allowed - the *production host* checks V1-V9 are the
authoritative evidence there. Not verified anywhere: the production host itself, slirp4netns/pasta,
Docker's rule order on that host, Alpine's tinyproxy build.

### Limits you accept

- Public Internet space stays open at the network level: a compromised proxy can open a socket to
  any public IP and port; only the hostname list narrows the CONNECT path.
- The guard is lost when the daemon restarts until `ExecStartPost` re-applies it; the start gates
  (above) keep application code from running in between, for the listed targets only.
- A host address acquired after `apply` (DHCP) makes `status` fail (`chain ... differs`) and so
  blocks the next deploy until `apply` is re-run; established connections are not cut.
- IPv4/iptables only for the allow path (IPv6 is rejected wholesale for new forwarded traffic;
  containers are IPv4-only). Docker's nftables mode (no `DOCKER-USER`) is refused, not worked around.
- The deploy gate cannot defend against root on the host, or against a Docker daemon that is
  restarted by someone else between the gate and the next container start (the start gates cover that).

## Go-live gates (all must be true before setting `DEPLOY_ENABLED`)

- [ ] CI is green on `main`, including the `docker` job (real daemon) and `lint-test`
      without skips.
- [ ] `docs/acceptance-checklist.md` server section executed on the real host.
- [ ] Rootless Docker confirmed on the host; script refusal tested once.
- [ ] **Host guard installed root-owned, applied and persisted** (operator procedure above) and
      validation **V1-V9** done on the production host, including the negative control (V5) and the
      startup-window drills (W1/W2).
- [ ] `shared/.env` sets `EGRESS_FORBIDDEN_TARGETS` (tailnet IP on `:22` and `:8000`);
      `127.0.0.1:18000` is free; the CI `host-guard-netns` job ran (not the explicit SKIP) or its
      replacement checks are recorded.
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
