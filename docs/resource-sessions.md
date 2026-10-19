# Resource sessions: Telegram-approved reservation of server resources

Status: **foundation implemented and tested; not installed anywhere.** Nothing here has been
run on your server. The host-side commands below are a *proposal* to execute by hand, in
order, after reading the risks. `AGENT_MODE=demo` throughout; submission stays disabled.

## 1. What the user experiences

At 07:00, 13:00 and 20:00 (Europe/Zurich) Telegram shows a prompt with **Accept / Decline**.

| Answer | Result |
|---|---|
| Decline | Nothing changes. |
| No answer for 15 min | The request expires; nothing is ever launched automatically. |
| Accept | Resources are reserved (approved containers stopped), the three agents run, then the original container state is restored and you get a summary. |

`/scan [profile_id]` and `POST /scan/{id}` create the *same* kind of request (no scan starts
without an approval). `/status` shows the session, `/restore` forces restoration. Only one
session may be active (database-enforced); a second Accept is refused.

## 2. What was inspected first (existing architecture)

- Three paths started scans with no approval: the scheduler (automatic), Telegram `/scan`,
  and `POST /scan`. All three now only create an approval request.
- No compose service mounts the Docker socket or any host path; that baseline is kept and is
  asserted by tests.
- Two Docker daemons will coexist: the **existing rootful daemon** (20 production services,
  *not touched by development*) and the **rootless daemon** that runs Internship Hunter.
  They are different sockets, different image stores, different networks. The helper below
  talks to the rootful one; the application only ever talks to the helper.
- The rootless prerequisites (subuid/subgid, lingering, `dockerd-rootless-setuptool.sh`,
  slirp4netns/pasta) are **not assumed to be installed**; installing them is step 0 of
  section 8 and is independent of this milestone.

## 3. How the rootless daemon and the privileged helper interact

```
 rootless daemon (user hunter-deploy)                 host (systemd, system units)
 ┌─────────────────────────────────────────┐          ┌────────────────────────────────────┐
 │ telegram ──┐                            │          │ hunter-rsm.service  (user hunter-rsm│
 │ scheduler ─┼─▶ PostgreSQL ◀── session-controller ──▶│   + group docker)                   │
 │ api ───────┘   (approvals, state)  │    │  unix    │   5 operations, fixed policy        │
 │ agents ✗ no socket, no DB            │   socket   │ hunter-rsm-watchdog.timer (30 s)     │
 └─────────────────────────────────────────┘ /run/hunter-rsm │ hunter-rsm-recover (boot)    │
                                                       │            │ rootful docker.sock      │
                                                       │            ▼                          │
                                                       │   20 production containers            │
                                                       └────────────────────────────────────┘
```

**One narrow channel:** a Unix socket `/var/lib/hunter-rsm-ipc/rsm.sock`, bind-mounted
(as the *directory*, read-only) into exactly one container (`session-controller`, via the
opt-in `compose.rsm.yaml`). Everything else:

- **Agents, proxies, API, Telegram bot, scheduler, discovery**: no socket, no Docker socket.
  Asserted by `tests/test_compose_invariants.py`; checked live by `deploy/smoke-test.sh`.
- **The rootful Docker socket is never mounted anywhere** and `hunter-deploy` (the rootless
  user) must *not* be in the `docker` group: that would be root on the host.
  `deploy/rsm/pilot/install-pilot.sh` refuses to install if it is.
- **Telegram never talks to the helper.** The bot only moves `pending -> accepted/declined`
  in PostgreSQL after authenticating the owner. A Telegram/bot outage cannot strand a session
  because the controller, the helper's watchdog and the boot unit do not depend on it.

**Socket lifecycle (systemd socket activation).** `hunter-rsm.socket` creates, owns
(`SocketUser=hunter-rsm`, `SocketGroup=<client primary group>`) and permissions
(`SocketMode=0660`) the socket; `hunter-rsm.service` *inherits it as fd 3*. The broker never
chowns or chmods anything, so it keeps an empty capability set and a seccomp filter that
forbids both (the previous in-process `chown` was killed by that filter at startup). The
socket is activated at boot, before the rootless daemon, and survives broker restarts and
crashes: a client that connects while the broker is down is queued by the kernel until
systemd restarts it. The directory `/var/lib/hunter-rsm-ipc` is `root:<client group> 0750`
(tmpfiles.d), outside `/run` (recreated) and `/etc`, so a bind mount of it never goes stale.

Alternatives considered and rejected: (1) mounting `docker.sock` — root-equivalent for any
compromised container; (2) the helper polling PostgreSQL — would need the database reachable
from the host and gives the helper a DB credential; (3) `sudo`/ssh from a container —
bigger surface, shell semantics; (4) HTTP on host loopback — rootless networking
deliberately cannot reach host loopback (and we test that it cannot); (5) a `RuntimeDirectory`
under `/run` — recreated on every service restart, which stranded the bind mount.

**Why the socket works under rootless Docker:** container root *is* the unprivileged host
user, so the socket is `0660 hunter-rsm:<rootless user's primary group>` (the group is never
`docker`) and the broker also checks `SO_PEERCRED` uid. A non-root container user would map to a sub-uid that cannot
connect; hence `user: "0:0"` **in the override only** (still `cap_drop: ALL`, read-only
root). In rootless mode this is not host root.

## 4. The helper's security properties (requirements 1-12)

| # | Requirement | Mechanism | Evidence |
|---|---|---|---|
| 1 | Only predefined operations | `OPERATIONS` = prepare, stop_approved, restore, status, emergency_restore; request schema rejects every other key/op | `test_rsm_server.py` (17 hostile payloads, zero Docker calls) |
| 2 | No arbitrary commands/names | No field carries a name or command; docker argv is fixed, names validated | same + `test_cli_docker_*` |
| 3 | Admin allowlist | `/etc/hunter-rsm/policy.json`, root-owned, not group/world-writable or the helper refuses to start | `test_policy_file_must_be_root_owned...` |
| 4 | Durable snapshot | state written (fsync + atomic rename) before and after every Docker action | `test_helper_crash_mid_stop...` |
| 5 | Stop only approved, dependency-aware | topological order from `depends_on`; live `network_mode: container:` / compose `depends_on` discovery blocks unlisted dependents | broker tests + integration |
| 6 | Restore only what was running | snapshot taken at `prepare`; containers already stopped are never started | `test_full_session...` |
| 7 | Restart policies preserved | only `inspect/ps/stop/start` exist in code (asserted by AST test); no `update` | integration + fake |
| 8 | Survives Telegram/app/Docker/reboot failure | durable state + independent watchdog + boot unit | crash/reboot tests |
| 9 | Independent watchdog | `hunter-rsm-watchdog.timer` runs a separate process every 30 s | `test_killing_the_real_helper_process...` |
| 10 | Persist + audit | `session.json`, append-only fsync'd `audit.log` | `test_everything_is_audited_in_order` |
| 11 | No overlap / replay | helper `flock` + one active session; DB unique `lock_key`; nonce + CAS transitions | concurrency tests |
| 12 | Max duration, bounded timeouts | policy `max_session_seconds`; sum of stop timeouts validated against it | policy tests |

**Protected by code, not configuration** (a policy file listing them is rejected at load):
names matching `tailscale`, `ssh*`, `internship-hunter`, `hunter*`; and `adguard` unless the
admin sets `dns_independence_verified: true`. The application's own database, bot, scheduler
and controller are in that protected set by name and by being a different daemon entirely.

## 5. Dependency and busy-service investigation

I cannot inspect your server, so **nothing below is asserted about it** — it is the method,
and what the helper does automatically:

```bash
# which containers share another container's network namespace (the Gluetun pattern)?
docker ps -q | xargs docker inspect --format '{{.Name}} net={{.HostConfig.NetworkMode}}'
# compose dependency labels
docker ps -q | xargs docker inspect --format '{{.Name}} {{index .Config.Labels "com.docker.compose.depends_on"}}'
# restart policies (must be identical before and after a session)
docker ps -q | xargs docker inspect --format '{{.Name}} {{.HostConfig.RestartPolicy.Name}}'
```

- **Gluetun / qBittorrent:** if qBittorrent uses `network_mode: container:gluetun`, stopping
  Gluetun alone would break it, and *restarting* Gluetun leaves such a client attached to a
  dead namespace. The policy models `qbittorrent depends_on gluetun`: qBittorrent stops
  first, Gluetun last; on restore Gluetun starts first. An *unlisted* container attached to
  Gluetun makes `prepare` fail with `blocked_dependency` before anything stops.
- **Immich:** `immich_postgres` and `immich_redis` are kept **running** (protected) — stopping
  a database mid-job is the riskiest option and they are small. The example policy stops only
  `immich_machine_learning` and `immich_server`, each guarded by the `immich_activity` probe
  (`/api/jobs` active count) with `on_busy: block`.
- **Jellyfin:** guarded by `jellyfin_playback` (`/Sessions`, `NowPlayingItem`) with
  `on_busy: block`; `skip` leaves it running and proceeds with less memory.
- **Fail closed:** a probe that cannot determine activity counts as *busy*.
- **AdGuard:** stays running (protected) until you verify the host and containers do not
  depend on it for DNS, then set `dns_independence_verified` yourself.

## 6. Operational risks (read before installing)

1. **Docker-group membership is root-equivalent.** The helper's confinement is its small,
   audited code and systemd sandbox, not the group. Do not widen the operations.
2. **Restart policy `always` re-starts containers after a reboot** regardless of our state;
   `unless-stopped` containers we stopped stay down until `recover` runs. Both are handled and
   tested, but the reboot-during-session path must be rehearsed on the real host.
3. **A container recreated during a session** (e.g. an auto-updater) is restored by *name*;
   a *removed* one is reported as a restoration failure, not recreated.
4. **Stopping a service interrupts its users** (downloads pause, Jellyfin/Immich clients
   disconnect). Busy probes cover playback and Immich jobs only; qBittorrent transfers are
   *not* probed. Decide that tradeoff in the policy.
5. **VPN kill-switch behaviour:** restarting Gluetun gets a new tunnel; check your
   port-forwarding/ qBittorrent binding after a restore on the first rehearsal.
6. **Probe API keys** live in root-owned files readable by `hunter-rsm`; treat as secrets.
7. **Memory is the trigger, not a guarantee:** if stopping frees less than
   `min_available_mib`, the session is blocked and everything restored.
8. **Port clash:** the application publishes `127.0.0.1:18000`; check the rootful services do
   not already use it (`ss -tlnp`).
9. **Clock:** deadlines use the host clock; keep NTP on.
10. **Alerts are rate limited** (one restoration-failure alert per 30 min per problem, in the
    app and from the host), then a "recovered" message; a persistent problem is therefore
    quiet after the first alert. Check `/status` and `journalctl -u hunter-rsm-watchdog`.
11. **Direct Telegram message from the helper** (optional `telegram_notify`) needs the bot
    token readable by `hunter-rsm`; omit it if you prefer alerts only via the app.
12. **Unverified here:** rootless slirp4netns/pasta behaviour, your real container graph,
    and the CLI provider hosts. The acceptance tests in section 9 settle these.

## 7. Files added by this milestone

`hunter/rsm/` (helper: policy, dockerctl, store, probes, broker, server, notify, __main__),
`hunter/sessions.py`, `hunter/session_controller.py`, `hunter/rsm_client.py`, changes to
`telegram.py`/`scheduler.py`/`api.py`, migration `0004`, `compose.rsm.yaml`,
`deploy/rsm/*` (units, example policy), `tests/test_rsm_*.py`, `tests/test_sessions.py`.

## 8. Manual server installation procedure (nothing below has been executed)

Do it in a maintenance window, one step at a time, stopping at the first surprise.

**0. Baseline (read-only).**
```bash
docker ps --format '{{.Names}} {{.Status}}' | sort > ~/baseline.ps
docker ps -q | xargs docker inspect --format '{{.Name}} {{.HostConfig.RestartPolicy.Name}}' | sort > ~/baseline.restart
free -m; ss -tlnp > ~/baseline.ports
id hunter-deploy        # must NOT list the docker group
```
**1. Rootless prerequisites** (separate from this milestone; see docs/deployment.md): user
`hunter-deploy`, `/etc/subuid`+`/etc/subgid`, `loginctl enable-linger hunter-deploy`,
`dockerd-rootless-setuptool.sh install`. Confirm the **rootful daemon is untouched**:
`diff <(docker ps --format '{{.Names}} {{.Status}}' | sort) ~/baseline.ps` (uptime differs;
names must match).

**2. Helper user** (no login, no home):
```bash
sudo adduser --system --group --no-create-home --shell /usr/sbin/nologin hunter-rsm
sudo usermod -aG docker hunter-rsm
```
**3. Install the code, root-owned** (stdlib only; no pip, no venv):
```bash
sudo install -d -m 0755 -o root -g root /opt/hunter-rsm/src/hunter
sudo install -m 0644 -o root -g root hunter/__init__.py /opt/hunter-rsm/src/hunter/
sudo cp -r hunter/rsm /opt/hunter-rsm/src/hunter/ && sudo chown -R root:root /opt/hunter-rsm
sudo find /opt/hunter-rsm -type d -exec chmod 0755 {} + ; sudo find /opt/hunter-rsm -type f -exec chmod 0644 {} +
```
**4. Policy, root-owned:** copy `deploy/rsm/policy.example.json`, edit it to match
section 5's investigation, then
```bash
sudo install -d -m 0755 -o root -g root /etc/hunter-rsm
sudo install -m 0644 -o root -g root policy.json /etc/hunter-rsm/policy.json
sudo install -m 0600 -o hunter-rsm -g hunter-rsm jellyfin.key /etc/hunter-rsm/jellyfin.key
```
**5. Dry run (changes nothing):**
```bash
sudo -u hunter-rsm env PYTHONPATH=/opt/hunter-rsm/src python3 -m hunter.rsm plan
```
Compare the listing with your understanding; fix the policy until it is exactly right.

**6. Socket directory, then units.** `CLIENT_GROUP=$(id -gn hunter-deploy)` (its *primary*
group, **not** `docker`) and `CLIENT_UID=$(id -u hunter-deploy)`:
```bash
sed "s/__HUNTER_CLIENT_GROUP__/$CLIENT_GROUP/" deploy/rsm/tmpfiles-hunter-rsm.conf | sudo tee /etc/tmpfiles.d/hunter-rsm.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/hunter-rsm.conf
sed "s/__HUNTER_CLIENT_GROUP__/$CLIENT_GROUP/" deploy/rsm/hunter-rsm.socket  | sudo tee /etc/systemd/system/hunter-rsm.socket
sed "s/__HUNTER_ROOTLESS_UID__/$CLIENT_UID/"   deploy/rsm/hunter-rsm.service | sudo tee /etc/systemd/system/hunter-rsm.service
sudo install -m 0644 deploy/rsm/hunter-rsm-watchdog.service deploy/rsm/hunter-rsm-watchdog.timer deploy/rsm/hunter-rsm-recover.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hunter-rsm.socket hunter-rsm-recover.service hunter-rsm-watchdog.timer
systemctl status hunter-rsm.socket; ls -l /var/lib/hunter-rsm-ipc/
```
**7. Channel check** (as the rootless user: must work; as any other user: must fail with
`Permission denied`):
```bash
sudo -u hunter-deploy python3 -c "import socket;s=socket.socket(socket.AF_UNIX);s.connect('/var/lib/hunter-rsm-ipc/rsm.sock');s.sendall(b'{\"op\":\"status\"}\n');print(s.makefile().readline())"
sudo -u nobody python3 -c "import socket;s=socket.socket(socket.AF_UNIX);s.connect('/var/lib/hunter-rsm-ipc/rsm.sock')"   # PermissionError
```
**8. Enable in the application (opt-in):**
```bash
sudo -u hunter-deploy touch /opt/internship-hunter/shared/rsm.enabled
# then the normal manual deploy; the deploy script adds compose.rsm.yaml automatically
```
First production deployment stays `AGENT_MODE=demo`.

## 9. Exact acceptance tests (run on the server, in this order)

| # | Action | Expected |
|---|---|---|
| A1 | `python3 -m hunter.rsm plan` as hunter-rsm | lists policy containers with running state; `docker ps` unchanged |
| A2 | Start the helper with a world-writable policy copy (`--policy /tmp/p.json` as root-owned 0666) | refuses to start, error names the file |
| A3 | From inside any **agent** container: `ls /run/hunter-rsm`; `nc -U` | no such path; no socket; no Docker socket |
| A4 | Telegram: wait for / trigger the 20:00 prompt, press **Decline** | `docker ps` identical to baseline; `/status` shows declined |
| A5 | Let a prompt expire (set `APPROVAL_TTL_SECONDS=120` temporarily) | state `expired`; no container change; late press says expired |
| A6 | Press **Accept** twice quickly; then an old prompt | second press "Already handled"; exactly one session in `audit.log` |
| A7 | **Accept** with nothing playing | approved containers stop in policy order; `free -m` rises; 3 agents run (demo); containers return; `diff` of `docker ps` and restart policies vs baseline is empty; Telegram summary + "All containers restored" |
| A8 | Start Jellyfin playback, then /scan + Accept | blocked before anything stops; alert names jellyfin; baseline unchanged |
| A9 | During a session `sudo systemctl kill -s KILL hunter-rsm.service` | session continues or controller restarts it; if not restored, watchdog restores within ~60 s; `audit.log` shows `watchdog_restore` |
| A10 | During a session `docker stop` the session-controller (rootless) | controller resumes after restart; if silent > 5 min the host watchdog restores |
| A11 | During a session reboot the host (maintenance window) | after boot `hunter-rsm-recover` restores the snapshot; restart-always containers are up; originally stopped ones stay stopped |
| A12 | During a session send `/restore` | containers restored; "Emergency restore" message |
| A13 | Make a managed container fail to start (e.g. temporarily `docker rename` it) | explicit RESTORATION FAILED alert naming it; app retries; fixing it + `/restore` recovers |
| A14 | Throughout A7: `systemctl is-active tailscaled ssh`; `docker inspect -f '{{.State.StartedAt}}'` for adguard, uptime-kuma, immich_postgres | all unchanged (never stopped) |
| A15 | `sudo cat /var/lib/hunter-rsm/audit.log` | every prepare/stop/start/restore recorded, in order |
| A16 | `SMOKE_EXPECT_ROOTLESS=1 deploy/smoke-test.sh` in enforce mode | passes (host exposure checks) |

## 10. Review fixes for 9d35464 (HIGH-1/2, MEDIUM-1..4, LOW-1)

| Finding | Fix | Verified |
|---|---|---|
| HIGH-1 broker could not start: in-process `chown` killed by its own seccomp filter | systemd socket activation (`hunter-rsm.socket`), broker inherits fd 3; no chown/chmod in code (AST-tested) | **real system manager, as root** (`tests/test_rsm_systemd.py`, CI job `rsm-systemd`): activation on first connect, `NoNewPrivs=1`, `CapEff=CapBnd=0`, `Seccomp=2`, fd 3 is a socket; `SocketUser/SocketGroup/SocketMode` set by systemd; the authorised uid is served, a socket-group member with another uid gets `forbidden`, any other user `EACCES`; the filter really blocks `chown`; the Go docker CLI runs under the filter |
| HIGH-2 socket under `/run` went stale on service restart | stable root-owned dir `/var/lib/hunter-rsm-ipc` (tmpfiles.d), bind-mount of the directory `:ro` | **real systemd**: `kill -9` -> restart, socket inode unchanged; restarts during live calls lose nothing; connect before the broker runs is queued, not refused. **Not yet**: real rootless Docker namespace mapping (`pilot-test.sh`, `rsm-pilot.yaml`) |
| MEDIUM-1 scans kept running after the reservation ended | controller cancels all scans on every end cause, holds the lock until cleanup is recorded, a cancelled task is never retried, owner vs watchdog distinguished | session tests (SQLite) incl. queued/running scans, dead worker, hung worker |
| MEDIUM-2 only compose `depends_on` considered | real `NetworkMode=container:<id|name|prefix>` resolved; undeclared, stale (recreated) and ambiguous providers refused; provider recreated mid-session reported at restore | fake Docker; **real-Docker tests written (`test_rsm_docker_integration.py`) but not executed in this environment** |
| MEDIUM-3 permanent `restore_failed` | `python -m hunter.rsm admin abandon|reconcile|recover-state|show`, uid 0 only, not on the socket, audited, never deletes; alerts rate limited | unit + CLI tests; non-root refusal; real-systemd watchdog unit |
| MEDIUM-4 slow stops looked like silence | contact refreshed after every stop and at the end; policy validation `stale_contact_seconds >= slowest single stop + 60`; client deadline raised to the broker's advertised stop budget | slow-stop tests with a fake clock; client adaptation tests |
| LOW-1 corrupt state was renamed and then read as "idle" | never renamed; every call reports `state_corrupt`; last good backup kept; explicit `admin recover-state --mode backup|discard`; invalid policy exits 4 and touches nothing | unit tests, **real-systemd watchdog unit** exits 3 and acts on nothing |

## 11. Disposable-container-only pilot (Ubuntu 24.04) - minimal instructions

Purpose: prove the host mechanics without any production container in scope. The generated
policy can only name `hv-pilot-*` containers; the script creates and removes only those.

0. Prerequisites you set up yourself: a user `hunter-deploy` with **rootless Docker**
   running (`systemctl --user status docker` as that user) and *not* in the `docker` group.
   Ubuntu 24.04 restricts unprivileged user namespaces; give **only** `/usr/bin/rootlesskit` an
   AppArmor profile (see `.github/workflows/rsm-pilot.yaml` for the exact profile). Do not
   disable the restriction globally.
1. `sudo deploy/rsm/pilot/install-pilot.sh --client-user hunter-deploy`
2. `sudo deploy/rsm/pilot/pilot-test.sh --client-user hunter-deploy --require-rootless`
   (about 6 minutes; it waits for the real watchdog once).
3. Read the `PASS/FAIL/SKIP` lines. A `SKIP` means that part did **not** run.
4. `sudo deploy/rsm/pilot/uninstall-pilot.sh` removes everything it installed.

The same job runs from GitHub (manual `workflow_dispatch`: "RSM pilot (manual)") on a real
Ubuntu 24.04 runner. It is experimental and has not been run yet.

## 12. What is deliberately not done

No scheduling of memory cgroups, no per-container resource limits on existing services, no
Docker API proxy, no automatic policy discovery, no stopping of protected names, no
application submission. Changing the operation set or letting the policy be written by the
application would change the security model and needs its own review.
