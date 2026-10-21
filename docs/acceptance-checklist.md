# Milestone 1 acceptance checklist

Legend: **L** = executed locally on a real Docker daemon (2026-10-15, WSL2/Docker Desktop, not
the production host); **CI** = defined in GitHub Actions, *not yet executed* on GitHub for this
revision; **S** = must be done on the real server. Nothing marked S has been done.

## Code / CI
- [x] **L** `ruff check .` clean; `pytest` **217 passed, 0 skipped** on Python 3.12.15 against
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

## Final pre-deployment fixes (real daemon, signed bundles, real images + database)
- [x] **L** REVIEWER SCENARIO: A on 0003, B migrates to 0004 then fails its health check ->
      automatic restore of A succeeded (A told to accept exactly 0004, declared compatible);
      database at 0004, A running, `/ready` 200, state `db_head` repaired from the real DB
      (the pre-fix script exits 10 on the same scenario: `HUNTER_DEPLOY_SCRIPT` regression run)
- [x] **L** deploy of a healthy B on the already-migrated database; rollback with a corrupted
      `state/db_head` still works because the real `alembic_version` is read
- [x] **L** database tampered to an unexpected revision (0009): rollback refused (exit 9), no
      acceptance granted; irreversible deploys still end in manual recovery (stub suite)
- [x] **L** `compat.json` no longer lists releases without the accept protocol; build and
      signing both reject such a declaration
- [x] **L** signing job recomputes `schema_head`/`rollback_compatible` from the source archive
      and refuses a build manifest that disagrees; checks commit id, member types, script modes
- [x] **L** egress proxy CONNECT-only (plain HTTP to an allowed host was forwarded before:
      observed 400 from the provider; now 403)
- [x] **L** graceful shutdown releases a task without consuming an attempt
- [x] **L** PostgreSQL: expired-lease row locked by a fencing worker is skipped by the reaper;
      an expired worker loses to an in-flight reaper without writing
- [x] **L** actionlint clean on both workflows
- [ ] **CI** all of the above on GitHub for commit `2d5ac4d` and later (not yet run)

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

## Rootless-host isolation (run `SMOKE_EXPECT_ROOTLESS=1 SMOKE_PROTECTED_IPS=<tailscale ip> deploy/smoke-test.sh` on the server)
Derived checks (also run in CI against the Docker runner, in report mode, without the rootless assertion):
- [x] **L** no container mounts the Docker socket or runs privileged; daemon is rootless (**S**)
- [x] **L** `deploy/check-host-isolation.sh` logic (stubbed containers): every service with a route
      out (computed from compose) probed against every host address (all interfaces, rootful
      bridges), default gateway, metadata, MagicDNS, operator-listed rootful targets, a canary and
      each gateway; a **refusal** counts as reaching the host; fails closed on missing/broken
      `nc`/`python`, failed exec, unknown/duplicated/missing results, missing gateway, IPv6 route
- [x] **L** host guard against real iptables and real packets in throwaway namespaces
      (`tests/test_host_egress_guard_netns.py`): tailnet/host/gateway blocked (also closed ports and
      `docker0`), Internet + DNS + same-bridge + docker-proxy traffic kept, idempotent, `remove`
      restores exactly; 9 tamperings detected by `status`; start gate stops/starts a service
- [x] **L** guard in the production rootlesskit `--detach-netns` layout, real user/mount/network namespaces
      (`tests/test_host_egress_guard_detached_netns.py`): the daemon's namespace is the detached one, never
      the child's (= host's); absent / non-namespace / symlink / host / ambiguous targets and missing Docker
      chains refused before anything is changed; stale pid file, swapped namespace and killed daemon fail closed
- [ ] **S** on the production host, read-only: `readlink /proc/self/ns/net /proc/$PID/ns/net` equal, the
      detached file is `nsfs` with a different inode, `"$GUARD" plan` names that inode (docs/deployment.md)
- [x] **L** deploy script gate (stubbed docker): missing/untrusted/inactive guard, unset targets,
      failed enforce check, first-deploy teardown, rollback prerequisites, rootful daemon never used
- [x] **L** real `egress-proxy.sh` CONNECT to an allow-listed public name keeps working with the guard;
      Alpine's busybox `nc -vv -z` texts observed and the probes calibrated against them
- [x] **L** F-2 start check/healthcheck fail closed (missing/broken nc, unsupported option, silent or
      localised output, reachable/refused/odd target) - the old script FAILS these tests
- [x] **L** F-5 report mode softens only reachability; 15 kinds of defect fatal in both modes
- [x] **L** F-3/F-6 `--verify-targets`: typo, dropped packet, unreachable, refused, reachable listener;
      required rootful target; deploy gate re-verifies on every deploy and rollback
- [x] **L** F-1 CI step scripts executed with failing/skipping/passing pytest (the old `pytest | tee` stays green
      under `bash -e`: reproduced); unavailable namespaces fail the job
- [x] **L** IPv6 with real packets (host IPv6 address, IPv6 Internet, daemon namespace) blocked by the guard
- [ ] **CI** the `host-guard-netns` job is GREEN on GitHub (it fails, it does not skip, if namespaces are
      unavailable) - never run on GitHub from here
- [x] **L** only loopback-published ports; proxy refuses tailnet (100.64/10, 100.100.100.100),
      RFC1918, link-local, loopback literals and `localhost`
- [ ] **S** host guard installed + applied + persisted; `EGRESS_FORBIDDEN_TARGETS` set; validation V1-V9
      of `docs/deployment.md` ("Host isolation") including the negative control and the W1/W2 drills
- [ ] **S** smoke test passes in **enforce** mode on the rootless production host
- [ ] **S** (GitHub runner, rootful, sshd on 0.0.0.0) the proxies CAN reach the runner's address:
      CI reports it, the server must not

## Server (demo mode) — all **S**
- [ ] `ss -tlnp`: only the API on loopback; Telegram from owner works, others get no reply
- [ ] Container memory totals within budget; other host services unaffected

## CLI mode (only after provider terms are confirmed) — all **S**
- [ ] Each CLI logged in separately; one scan yields three `cli` runs

## Resource sessions (Telegram-approved reservation) - see docs/resource-sessions.md
- [x] **L** broker unit suite with a fake Docker (dependency order, snapshot/restore, restart
      policies, crash mid-stop AND mid-restore, watchdog deadline/silence, reboot recovery,
      missing/recreated container, busy probes, unlisted dependents, protected names)
- [x] **L** hostile-protocol suite: unknown ops/extra keys/names/oversize -> zero Docker calls
- [x] **L** REAL Docker with DISPOSABLE `hv-rsm-test-*` containers: order, restart policies,
      bystander untouched, helper process SIGKILLed mid-session -> watchdog restores,
      boot-recovery command, unlisted namespace dependent blocks
- [x] **L** approval flow: decline, expiry, double accept, simultaneous accepts, second
      session refused, owner-only callbacks, replay/forgery, scan failure, timeout (scans
      cancelled), broker unreachable, lost reply while stopping, controller crash + resume,
      restore failure -> single explicit alert -> `/restore`
- [x] **L** compose: broker socket only in `session-controller` (opt-in override), no Docker
      socket anywhere, agents/proxies/bot have no path to the helper
- [ ] **CI** all of the above on GitHub (RSM integration needs the runner's Docker)
- [ ] **S** installation and acceptance tests A1-A16 of docs/resource-sessions.md on the
      real host (nothing in this section has run on your server)

## Resource sessions: review fixes (9d35464 -> this commit) - what was and was NOT executed
- [x] **L** `ruff`; `pytest` **389 passed, 10 skipped** (local, Python 3.12, real PostgreSQL via
      `pgserver`); the 10 skips are the real-Docker integration tests (no Docker daemon was
      reachable in this session)
- [x] **L** REAL systemd (user manager): socket activation, sandboxed broker process state,
      `kill -9` recovery with an unchanged socket inode, restarts during live calls, connect
      before the broker runs, watchdog and boot-recovery units, corrupt-state exit code 3
- [x] **L** the production seccomp filter blocks `chown`; the Go docker CLI runs under it
- [x] **L** shellcheck (all deploy + pilot scripts) and actionlint (all workflows) clean
- [ ] **NOT RUN** `SocketUser/SocketGroup`, EACCES for an unauthorised user, docker
      supplementary group, system-manager sandbox: `deploy/rsm/pilot/pilot-test.sh` (root)
- [x] **L** (CI fix) the user-manager run above could not work on GitHub's Ubuntu 24.04
      runners (218/CAPABILITIES: AppArmor restricts the user namespace the user manager needs to
      drop the bounding set). `tests/test_rsm_systemd.py` now installs the production units
      under the SYSTEM manager as root, only in the CI job `rsm-systemd` (ephemeral runner,
      disposable users, fake docker bind-mounted inside the units, no credentials, not for fork
      PRs, AppArmor untouched). Covers the `SocketUser/SocketGroup`, EACCES and docker
      supplementary-group items above. Run locally in a disposable Ubuntu 24.04 systemd
      container: 15 passed; weakening the unit (bounding set, `~@privileged` filter,
      `NoNewPrivileges`) makes it fail. The earlier chown probe (on `/proc/self`) passed even
      without the filter (procfs refuses every chown); it now chowns a file the process owns.
      **Not yet run on GitHub.**
- [ ] **NOT RUN** real rootless Docker: namespace mapping, bind-mounted directory after broker
      restart/crash, rootless daemon started before the broker: pilot script / `rsm-pilot.yaml`
- [ ] **NOT RUN** real-Docker integration tests (`RSM_INTEGRATION=1`): network-namespace
      providers (stale/undeclared/recreated), SIGTERM-ignoring container, admin abandon
- [ ] **CI** everything above on GitHub for the new commit
