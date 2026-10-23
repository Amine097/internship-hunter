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
host's, and before entering anything it proves that the process in
`$XDG_RUNTIME_DIR/dockerd-rootless/child_pid` is *this user's* rootless daemon (owned by the uid, a
`dockerd`/`rootlesskit` command line, a user namespace mapped to this uid and different from ours, its
socket present). `HUNTER_GUARD_PROC` (a fake `/proc` for tests) and `HUNTER_GUARD_TEST_NSFS_TYPE` are
refused unless `HUNTER_GUARD_TEST_MODE=1`.

#### Which network namespace is "the daemon's" (rootlesskit `--detach-netns`)

The production daemon runs rootlesskit with `--net=slirp4netns --detach-netns`. In that layout the
rootlesskit child process (`child_pid`) **stays in the host's network namespace**; the daemon's namespace is
a separate, detached one, bind-mounted at `$XDG_RUNTIME_DIR/dockerd-rootless/netns` **inside rootlesskit's
mount namespace only** (the same path on the host is not a namespace file). Entering the child's own network
namespace (`nsenter -U -n -t <pid>`) therefore lands in the host's namespace as an unprivileged user and
cannot work - and must never be made to. The guard resolves one explicit identity instead:

| layout | what is entered | target identity |
|---|---|---|
| `--detach-netns` (file at `/proc/<child>/root$XDG_RUNTIME_DIR/dockerd-rootless/netns`) | the child's user + mount namespaces, network namespace **from that file** | `net:[inode]` of the file |
| no detached file, child **not** in our network namespace | the child's user, mount and network namespaces | the child's `net:[inode]` |
| no detached file, child in the host's network namespace | **nothing - refused** (the daemon's namespace cannot be identified) | - |

Refused, before any command is sent into a namespace: the detached file is absent (child in the host
namespace), is a regular file, a symbolic link or anything but a namespace file (`nsfs`), has the host's own
identity, or the child is in a third namespace (ambiguous layout). There is no fallback from one layout to
another and none to the host namespace. Every firewall command then runs through one gate (a `/bin/sh`
that `exec`s the command only if `/proc/self/ns/net` and `/proc/self/ns/user` are exactly the verified
identities, else exit 97), the process start time and the file's identity are re-checked before each phase,
and `apply` only mutates after Docker's own `DOCKER-USER` chain and the `FORWARD` jump into it exist **in
that namespace**. A daemon that restarts (new process, new namespace) while `apply --wait` is waiting makes
it fail with `nothing was changed` instead of re-resolving; systemd then retries with a fresh resolution.
The mount namespace entered is the daemon's, so `iptables -w` takes the same `/run/xtables.lock` as Docker's
own calls. Read-only checks an operator can run to see the layout (nothing is changed):
```bash
PID=$(cat "$XDG_RUNTIME_DIR/dockerd-rootless/child_pid")
readlink /proc/self/ns/net "/proc/$PID/ns/net"                      # detach layout: the same value
stat -L -f -c %T "/proc/$PID/root$XDG_RUNTIME_DIR/dockerd-rootless/netns"   # nsfs
stat -L -c 'net:[%i]' "/proc/$PID/root$XDG_RUNTIME_DIR/dockerd-rootless/netns"   # a DIFFERENT value
"$GUARD" plan                                                       # names the target namespace
```
The systemd drop-in (step 6) needs no change: it already runs as the daemon's user with
`XDG_RUNTIME_DIR` set, after rootlesskit has created the state directory.

### DNS (which resolver each service uses, and what the guard does and does not see)

Measured on a real rootless Docker 29.9.1 (rootlesskit `--net=slirp4netns --detach-netns`, the production
layout) running this repository's real `compose.yaml` topology with the real guard
(`tests/test_dns_rootless_lab.py`). **Docker's embedded resolver (`127.0.0.11`) has two forwarding
paths, and only one of them crosses the guard:**

| container's `resolv.conf` says | who sends the upstream query | crosses the guard? |
|---|---|---|
| `ExtServers: [host(192.168.1.1)]` - no `dns:` anywhere; servers copied from the daemon's `/etc/resolv.conf` | **dockerd itself**, from its own namespace (the packets never enter the daemon's firewall; the daemon's `tap0` sees nothing) | **no.** The host's LAN resolver is reachable whatever the guard says - including with a guard whose `DNS=` names a different address |
| `ExtServers: [10.0.2.3]` - explicit `dns:` (compose, `--dns`, `daemon.json`) | the container's own namespace: container -> bridge -> `DOCKER-USER` -> slirp4netns | **yes.** Only `10.0.2.3:53` passes (guard rule `-d 10.0.2.3 ... dpt:53 RETURN`); a private LAN resolver, the bridge gateway, any other private address is rejected |
| container on `internal` networks only | nobody: SERVFAIL for every name outside the project, no direct path either | n/a |
| ad hoc container on Docker's default bridge (no `--dns`) | the container itself, straight to the daemon's upstream (`192.168.1.1`) | yes - and **rejected** (not part of this stack; use `--dns 10.0.2.3` on that one container) |
| *any* container when the **daemon** has `"dns": ["10.0.2.3"]` in `daemon.json` | as the explicit case, for every container, including the internal-only ones | yes - which is the problem: **do not configure it** (below) |

So the stack worked unchanged once the guard was applied - *through the path the guard does not police*.
That is not the policy the guard documents ("DNS only to the namespace's resolver"), it depends on what
the host's `/etc/resolv.conf` says at daemon start, and it could not be seen by any existing check. Hence:

**Per service** (computed from `compose config` by `deploy/check-dns.sh`, never a hard-coded list):

| service | networks | DNS |
|---|---|---|
| `egress-claude-1`, `egress-claude-2`, `egress-codex` | `egress_<name>` (route out) + `agent_<name>` (internal) | `dns: [${HUNTER_DNS:-10.0.2.3}]`. Resolves the allow-listed provider names for tinyproxy through the guard; resolves its agent and `discovery` by service name |
| `discovery`, `telegram` | `egress` (route out) + internal ones | same explicit resolver (ATS boards, Telegram API); service names of the networks they share |
| `api` | `edge` (route out, only to publish `127.0.0.1:18000`) + `data` | same explicit resolver: it needs no public name, but it must not have a second, unpoliced one |
| `agent-claude-1`, `agent-claude-2`, `agent-codex` | one `agent_<name>`, **internal** | **none, deliberately.** Resolve their own proxy and `discovery`, nothing else; every public name is SERVFAIL; `10.0.2.3` and `1.1.1.1` are unreachable. They reach providers only by `CONNECT` through their proxy, which resolves the name itself. |
| `postgres`, `migrate`, `scheduler`, `session-controller` | `data`, **internal** | none; same as above |

Service names resolve only between services sharing a network (`agent-claude-1` cannot resolve
`egress-codex`, `postgres`, `api`, `agent-codex`) - asserted by the check in both directions.

**Exact production configuration**

1. `host-egress-guard.conf` (root-owned, already in the procedure): `DNS=10.0.2.3`. The deploy gate now
   *requires* this line to be present and a valid IPv4 list, and passes it to `check-dns.sh` as the
   expectation (`SMOKE_DNS_EXPECT`), so the resolver the guard allows and the resolver compose gives to the
   services cannot silently diverge.
2. `shared/.env`: nothing. `compose.yaml` defaults `HUNTER_DNS` to `10.0.2.3` (slirp4netns'
   resolver). Set `HUNTER_DNS` only if the guard's `DNS=` is changed (e.g. another network driver); both must
   then change together, or the deploy gate fails: `egress-* cannot resolve ...` / `configured dns is ...`.
3. Install `deploy/check-dns.sh` root-owned next to the other gate scripts (step 0 below); the gate refuses
   to deploy without it (exit 11).
4. **Do NOT configure daemon-level DNS** (`"dns": [...]` in `~hunter-deploy/.config/docker/daemon.json`;
   an earlier revision of this document recommended it for ad hoc containers - that recommendation is
   withdrawn). `daemon.json` must not contain a `dns` key. Without it an ad hoc container on the default
   bridge has no working DNS while the guard is on - by design; give that one container `--dns 10.0.2.3`
   (step 5 does). Why, measured on the real rootless Docker 29.9.1 (`tests/test_dns_rootless_lab.py`,
   `test_daemon_level_dns_gives_agents_an_explicit_upstream_and_check_dns_refuses_it`):
   - it changes the resolver state of **every** container without a line of `compose.yaml` changing. With
     no daemon-level `dns`, an agent's `resolv.conf` says `ExtServers: [host(<daemon upstream>)]`; with it, the
     same agent says `ExtServers: [10.0.2.3]` / `Overrides: [nameservers]` - the guard-approved address,
     configured inside a container whose whole design is that it carries no resolver. Docker 29.9.1 still did
     **not** forward from the internal-only containers (every public name SERVFAIL, no packet reached the
     guard's DNS exception, the resolver and `1.1.1.1` unreachable), so this is lost defense in depth, not
     a hole measured today: the day an agent gains a route (a misconfiguration, a `docker network connect`,
     different Docker behaviour) the one resolver the guard lets through is already wired in;
   - it hands the guard's DNS exception to **every** ad hoc container on this daemon, which is the
     covert-channel budget this deployment gives only the services with a route out;
   - compose cannot show it, so a declaration-only check passes. `check-dns.sh` therefore reads the
     **runtime** `resolv.conf` of every service: an internal-only service whose `ExtServers` names anything
     other than `host(...)` (the daemon's own list, which Docker prints for every container and never uses for
     an internal-only one), or whose nameserver is not `127.0.0.11`, is a **breach in every mode** -
     `agent-codex is internal-only but Docker gave it explicit upstream resolver(s) ['10.0.2.3'] ...
     daemon-level dns (daemon.json)`. Local service discovery (`127.0.0.11` answering the agent's proxy and
     `discovery`) is still required and still checked.

**Verification** (read-only unless stated; after the guard is applied and the stack is up)
```bash
cd /opt/internship-hunter/current   # or the release directory
# V10  every service with a route out: Docker uses 10.0.2.3 from INSIDE the container, never host(...)
for s in api discovery telegram egress-claude-1 egress-claude-2 egress-codex; do
  docker compose exec -T $s grep -E '^(nameserver|# ExtServers)' /etc/resolv.conf; done   # 127.0.0.11 / [10.0.2.3]
# V11  the full check (also run by deploy/smoke-test.sh and by remote-deploy.sh in enforce mode)
SMOKE_HOST_ISOLATION=enforce deploy/check-dns.sh      # -> "ok   DNS: 6 service(s) with a route out use 10.0.2.3 ..."
# V12  negative controls, by hand: an agent resolves its proxy and nothing outside
docker compose exec -T agent-codex nslookup -timeout=3 egress-codex.        # answers
docker compose exec -T agent-codex nslookup -timeout=3 example.com.         # SERVFAIL / no answer
docker compose exec -T agent-codex nslookup -timeout=3 example.com. 10.0.2.3   # unreachable
# V13  the guard really is in the path: counters on the DNS exception grow while a proxy resolves
docker compose exec -T egress-codex nslookup example.com. >/dev/null
nsenter ... iptables -L HUNTER-EGRESS-GUARD -n -v | grep 'dpt:53'   # (namespace entry as the guard does; packets > 0)
```
Failure behaviour (each is a test): the guard without the exception (`DNS=` different) -> the stack's
external names stop resolving (SERVFAIL, `check-dns.sh` fails `cannot resolve example.com through ...`;
`report` mode only warns); `HUNTER_DNS` pointing at a private LAN resolver -> rejected by the guard, same
failure; a service with a route out but no `dns:` -> `breach ... host(...)`; an internal-only service that
resolves a public name, gets a direct answer from a resolver, or resolves a name from a network it is not on
-> `breach`, **in every mode**; an unreadable `resolv.conf`, a missing resolver tool, a failed `docker exec`,
a failed own-name control -> `defect` (unverified is never a pass).

**The raw-UDP probe has a positive control (so silence means something).** Several verdicts are "this
container got *no* answer" (an agent asking `10.0.2.3` or `1.1.1.1` directly). A probe that cannot receive an
answer at all - a broken `nslookup`, a malformed packet, a missing capability - would make every one of them
pass. So every service with a route out sends the **same raw query** to the approved resolver, where the
guard lets it through, and each probe flavour (python in the app/agent images, busybox `nslookup` in the proxy
image) must get an answer from at least one such service before the agents' silence counts:
- a service that resolves `example.com` through the approved resolver yet gets no raw answer from it ->
  `PROBE DEFECT ... the negative direct-query checks of this probe are UNVERIFIED`, **fatal in every mode**;
- no service with a route out runs a flavour the agents use -> `defect: ... its positive control is missing`;
- the network blocking the query (no guard exception: names do not resolve either) is a different class: it
  stays `cannot resolve ... through ...` (fatal in `enforce`, a warning in `report`), plus a note that the
  agents' direct-query checks are unverified because a blocked query cannot be told from a broken probe.
Real packets: `test_explicit_resolver_works_through_the_guard...` (a proxy gets the direct answer, an agent
does not) and `test_a_probe_that_cannot_receive_direct_answers_is_a_defect_not_a_pass` (the probe tool
sabotaged inside real containers).

**The rendered DNS is judged before anything starts.** `HUNTER_DNS` can come from the SSH session's
environment, from `shared/.env` or from compose's default, and a disagreement used to be found only after
`up --wait`, with the new containers already running. Now `remote-deploy.sh`:
1. removes `HUNTER_DNS` from the caller's environment (as it does `SMOKE_*`, `COMPOSE_*` and
   `EGRESS_FORBIDDEN_TARGETS`), so an SSH session cannot override what the host decides;
2. runs `check-dns.sh` in `SMOKE_DNS_CONFIG_ONLY=1` mode against `docker compose config` of the release
   (with `shared/.env` and the release env file - the effective values) and `SMOKE_DNS_EXPECT` = `DNS=` of the
   root-owned `host-egress-guard.conf`: every service with a route out must render exactly that resolver and
   no internal-only service may render any;
3. does so **right after the release is unpacked**, before images are loaded, the database is dumped or a
   container is touched (`die`, exit 11, the running release is left alone); **before `rollback` changes
   anything** (exit 11); and again in `activate()` right before `compose up`, which also covers the
   restore of a previous release;
4. so a `shared/.env` with `HUNTER_DNS=9.9.9.9` against `DNS=10.0.2.3`, a guard conf changed to `1.1.1.1` while
   compose still renders `10.0.2.3`, or a list (`compose.yaml` renders one resolver) are all refused with
   `the rendered compose DNS of <sha> disagrees with DNS=... in host-egress-guard.conf ... nothing was started`.
The post-start check (V11) remains: it proves Docker honoured the rendered value.

**CLI mode (`AGENT_MODE=cli`) is a separate requirement; this change does not enable it.** What holds today
is structural and is already tested in demo mode: agents are internal-only, so DNS gives them neither a
way out nor a tunnel. Blockers to clear before CLI mode: (1) ~~the pinned Claude/Codex CLI versions must be
run to confirm they hand the *hostname* to the proxy~~ - **done**: they do (no DNS query at all, `CONNECT
host:443`, SNI == host; CI job `cli-egress-probe`, docs/security-architecture.md "Egress"); a CLI that resolved
locally would get SERVFAIL, and the fix must never be to give agents a resolver; (2) ~~the provider allow-lists
are still the documented defaults~~ - **done**: the defaults are now exactly the hosts the pinned CLIs need
(measured), and the probe fails if a CLI upgrade needs more; (3) RSM stays off
(its DNS independence flag is unrelated to this); (4) the proxies' resolver is shared with `discovery`/`telegram`
through `10.0.2.3`, so a compromised *proxy* still has DNS as a covert channel to the public Internet (see
"Limits you accept").

**Status of the independent review's findings on this change (PR #12)**

| | finding | state |
|---|---|---|
| F-1 | daemon-level `dns` undermines the agents' defense in depth | **fixed here**: the recommendation is withdrawn and the reasons documented; the check reads the runtime resolver state of internal-only services; real-daemon test |
| F-2 | no positive control for the direct UDP probe | **fixed here**: see "The raw-UDP probe has a positive control" |
| F-3 | DNS mismatch only detected after startup | **fixed here**: see "The rendered DNS is judged before anything starts" |
| F-4 | open in the review; **not part of this patch** (no change made or implied by it) | open |
| F-5 | runtime containment after the deploy (topology/guard/DNS drift, Tailscale late, a failed prerequisite must not leave agents running) | **addressed by "Runtime containment" (this change)**; CLI mode itself stays disabled (the other blockers above remain) |

### The deploy gate (what `remote-deploy.sh` now enforces)

For `deploy`, `deploy-irreversible` **and** `rollback`, before anything is read, loaded or changed:

| Check | Failure |
|---|---|
| `/opt/internship-hunter/deploy/host-egress-guard.sh`, `check-host-isolation.sh` and `check-dns.sh` exist, are executable regular files (not symlinks), root-owned, not group/world-writable, in a directory that is too | exit 11 |
| `shared/.env` sets `EGRESS_FORBIDDEN_TARGETS` to a non-empty, well-formed `ip:port` list (the last assignment wins, as in compose; the caller's environment is ignored) | exit 11 |
| `deploy/host-isolation.conf` exists (regular file, not a symlink, root-owned, not group/world-writable) and sets `ROOTFUL_TARGETS=ip:port[,...]` with **at least one** entry | exit 11 |
| every target is **real**: each `EGRESS_FORBIDDEN_TARGETS` address is an address of this host, and every forbidden and rootful target either connects or is **refused** from the host's own namespace (safe TCP connect, no payload) - a silent timeout, `unreachable`, a typo or a moved address is rejected (`check-host-isolation.sh --verify-targets`) | exit 11 |
| `deploy/host-egress-guard.conf` (regular file, not a symlink, root-owned, not group/world-writable) sets `DNS=<ipv4>[,...]`: the resolver the guard lets containers use, which `check-dns.sh` then requires the stack to use | exit 11 |
| the **rendered** compose DNS (effective `shared/.env` values; the caller's `HUNTER_DNS` is removed) equals `DNS=` of that conf for every service with a route out and is absent for internal-only ones - checked after unpacking the release, before images are loaded or anything starts, before a rollback changes anything, and again before every `compose up` | exit 11 |
| `host-egress-guard.sh status` exits 0: the **full** policy is installed and unmodified | exit 12 |
| `deploy/runtime-containment.sh` is a root-owned executable, its watchdog has a fresh heartbeat and is **not latched** (`status --require-active`) | exit 11 / **13** |
| the release being deployed is one containment can supervise; the running release (or a rollback target) is one it can take back, else `deploy-irreversible` / refusal | exit 11 / **14** |
| `127.0.0.1:18000` is free, or held by this application's own running `api` (read-only `ss`) | exit 3 |

After `compose up --wait` and the health checks, `check-host-isolation.sh` runs in **enforce**
mode with `SMOKE_PROTECTED_IPS` taken from the targets and `SMOKE_ROOTFUL_TARGETS` from the conf
(ambient `SMOKE_*` variables are removed first), followed by `check-dns.sh` in enforce mode with
`SMOKE_DNS_EXPECT` = the guard conf's `DNS=` (see "DNS"); either failing is a failed activation. Only then
is the release **committed** to the runtime-containment watchdog (see "Runtime containment"); a refusal
there is a failed activation too, and a stack the script tears down is first recorded as `desired: stopped`.

**The forced-command boundary.** Whatever environment the SSH session arrives with, production runs
only against `/opt/internship-hunter`, with `PATH` fixed and `BASH_ENV`, `LD_PRELOAD`, `LD_LIBRARY_PATH`,
`PYTHONPATH`, `HUNTER_BASE`, `HUNTER_MAX_BUNDLE_BYTES`, `HUNTER_GUARD_*` and the schema-accept variable
removed. `HUNTER_TEST_MODE` (the test hooks) is honoured only together with a `HUNTER_BASE` outside
`/opt/internship-hunter`, so it cannot be turned on against production. `DOCKER_HOST` is pinned to the
user's own rootless socket (never `/var/run/docker.sock`); no script here ever connects to the rootful
Docker socket, and none modifies or restarts a rootful container.
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
   `sudo install -o root -g root -m 0755 deploy/host-egress-guard.sh deploy/check-host-isolation.sh deploy/check-dns.sh deploy/runtime-containment.sh "$D"/`
   Also `host-egress-guard.conf` and `host-isolation.conf` (step 2 and 7). Needs `iptables`, `ip6tables`, `nsenter`, `ss`, `python3` on the host (`iptables --version` should
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
   `docker run --rm --network probe-net --dns 10.0.2.3 busybox:1.36 nslookup api.anthropic.com` must resolve
   (**with `--dns`**: without it Docker's embedded resolver forwards from the daemon and the test would pass
   even if the guard blocked DNS - see "DNS"). If DNS fails: step R, then set `DNS=` in the conf.
6. **Persist** (the rules live in the daemon's namespace and vanish when the daemon restarts). A
   failing `ExecStartPost` fails the unit, so the daemon is down rather than unguarded:
   ```ini
   # ~/.config/systemd/user/docker.service.d/10-hunter-egress-guard.conf
   [Service]
   ExecStartPost=/opt/internship-hunter/deploy/host-egress-guard.sh apply --wait 90
   ```
   `systemctl --user daemon-reload && systemctl --user restart docker` (this user's daemon only),
   then `"$GUARD" status`. `loginctl enable-linger hunter-deploy` must already be set.
   **Also install the runtime-containment watchdog** (see "Runtime containment"): without it the deploy gate
   refuses (exit 13), and with `restart: "no"` nothing would restart the supervised services after a reboot.
7. **Tell the stack what must stay unreachable.** Two lists, both validated as *real* before every
   deploy and rollback (see "The deploy gate"):
   - `shared/.env` (mode 600): `EGRESS_FORBIDDEN_TARGETS=100.107.22.84:22,100.107.22.84:8000` - addresses
     **of this host** (sshd on the tailnet IP, Gluetun's listener). Each must connect or be refused
     from the host itself. Any stable host-owned address with a closed port also works as a liveness
     target, e.g. the rootful `docker0` gateway: **detect it, never assume `172.17.0.1`**
     (`ip -4 -o addr show docker0`, `docker network inspect bridge` by the rootful Docker admin).
   - **required**, root-owned `"$D/host-isolation.conf"` (mode 0644): `ROOTFUL_TARGETS=<ip:port>[,...]`
     naming at least one EXISTING rootful container. The operator chooses it with read-only inspection
     as the rootful Docker admin (never as `hunter-deploy`, which has no access to that socket):
     `docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' <container>`, then
     pick a **closed** TCP port on that IP (`nc -vz <ip> <port>` from the host must say *refused*) so no
     media application receives a request; a refusal still proves a probe reached it. If the container's
     IP drifts the next deploy fails (`not live from the host`): update the file. Nothing is scanned;
     only what you list is probed. `docker network rm probe-net`.
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

**What the gate does not do** (and what now does): the in-container gate only knows the targets it
was given - the guard is the complete policy - and it checks at *start* only, from the container's point
of view: a host that silently drops (rather than answers) packets, or a Tailscale address that does not
exist *yet*, makes an unguarded start look guarded. Before "Runtime containment" below, removing the guard
while the stack ran was stopped by nothing (the proxies' healthcheck only *reports* `unhealthy`; an
unhealthy container is neither stopped nor restarted). **That is closed by the "stronger design" this
section used to describe as not implemented:** every service with a route out and every agent is
`restart: "no"`, and `deploy/runtime-containment.sh` starts them - only after the guard is verified and the
protected host addresses are live - and stops them when an invariant is lost. The in-container gates remain
as a second line.

**Validation (W1, stack stopped first so nothing is exposed while the guard is off):**
`docker compose -p internship-hunter stop` → `"$GUARD" remove` → `docker compose -p internship-hunter start discovery egress-codex api`
→ each must be `Restarting`, with `isolation-gate: refusing to start` / `egress-proxy: refusing to
start` in `docker logs` and **no** worker/uvicorn/tinyproxy log lines → `"$GUARD" apply` → all `Up`
within about a minute, `docker compose -p internship-hunter start` the rest, then the smoke test.
**W2:** `systemctl --user restart docker`; `docker logs --since 2m` may show a few gate refusals
(that is the window being closed); after two minutes `docker ps` is healthy and `"$GUARD" status` is active.

### Runtime containment (F-5: the isolation stays true after the deploy)

**Threat model.** Assets: the host (its Tailscale/LAN/public addresses, sshd, the rootful containers),
the provider credentials the agents will hold in CLI mode, the other networks of the stack. Adversaries
and accidents this layer is for: a compromised agent or proxy container; an operator command that
changes the topology (`docker network connect`, `docker run --network`, a daemon-level `dns`); a guard
that is removed, flushed or goes stale (a daemon restart, a host address that appears after boot);
Tailscale that is up *after* the stack; a host resolver that changes. Not defended: a compromised
`hunter-deploy` user or root (they own the daemon and this script's state), kernel/container escapes,
and the Internet itself (a compromised proxy still reaches public hosts and has DNS as a covert channel).

**Mechanism** (one root-owned script, one systemd *user* unit, no new infrastructure):
`deploy/runtime-containment.sh watch` runs next to the rootless daemon (`deploy/systemd/hunter-containment.service`,
`Type=notify`, `WatchdogSec`, `Restart=always`). It wakes every 10 s **and** immediately on `docker events`
(network/container) and `ip monitor address route` (a host address appearing), and per cycle:

| # | invariant | on violation |
|---|---|---|
| G | `host-egress-guard.sh status` = the **full** policy, host addresses included | `status` exit **3** (the policy is intact; only the set of host addresses it names is stale - a rootful Docker bridge or an interface address came or went): **re-apply and verify first, stop nothing** (`apply` takes about a second, less than `docker stop`'s own grace period, so stopping first closes the gap no sooner); stop the set only if that repair does not hold. A repaired drift is not a flap. Exit 1 (a rule deleted or edited, a jump missing, an ACCEPT): stop the supervised set, re-apply, verify, restart (*self-healing*) |
| T | the protected host addresses (`EGRESS_FORBIDDEN_TARGETS`) are live, checked by `check-host-isolation.sh --verify-targets` | **before starting only** (Tailscale late): the set stays stopped, state `waiting`; a Tailscale that goes away while running is not a loss of isolation and stops nothing |
| N | every container of the project is attached to exactly the networks its service declares (stopped ones too: `docker network connect` works on a stopped container); no foreign container is attached to a project network; every network that must be `internal` is | stop the set, **disconnect** the unauthorised endpoint (the container is kept for forensics, never removed), **latch** |
| H | no project container with host network/pid, `privileged`, or the Docker socket; no container claiming the project that the release does not define | stop, latch |
| D | the **runtime** `resolv.conf` of every running project container: a service with a route out forwards to exactly the contract's resolver from inside the container (never `host(...)`), an internal-only one carries no upstream at all (the F-1 daemon-level `dns` case) | stop, latch (unreadable file: stop, self-healing) |
| C | the rendered compose DNS equals `DNS=` of the root-owned guard conf | stop, wait (self-healing) |
| R | the daemon's upstream resolver list (what the host's resolver change would alter) equals the one recorded at the deploy (D-5) | **warning** only: logged once, shown by `status`, a deploy re-baselines it; every service has an explicit resolver, so the host resolver is not on the policed path |
| S | root-owned helpers are regular, non-symlink, not writable by others; Docker can be inspected; the daemon is rootless | stop (self-healing) / `unverified` |
| K | supervised containers run only if the last deploy left the stack wanted (`desired: running`) | stop, latch (somebody ran `compose up` by hand) |

*Latch* = the set stays stopped, whatever the next cycles see, until an operator runs
`runtime-containment.sh reset` after investigating (a hot attachment can be removed by the attacker
afterwards; an evidence-free restart would hide it). *Self-healing* = the set comes back by itself when the
prerequisite holds again, and **three of them in 15 minutes latch** (`FLAPPING`). After the watchdog starts
the set from cold it runs the deploy gate's enforce-mode isolation and DNS checks once and re-judges
N/H/D on what really runs; a failure stops the set again and latches (`POST-START`).

**Order of a quarantine: latch, cut, stop.** (1) The intent is written to disk (`state/containment/latch`);
(2) every unauthorised endpoint is removed (`docker network disconnect -f`, instant; retried once; if it cannot
be removed and the container is ours, that container is **killed**, a foreign container is left running but
the set is stopped anyway and the latch says the endpoint is still there); (3) only then is the set stopped
(`docker stop -t 5`, then `kill`). Stop-first would keep a hot-attached route alive for the whole shutdown
(measured on a real daemon by the QA review: the route outlived the first stopped container by 3.4 s); latching
first means a watchdog that dies between (2) and (3) cannot fail open - the evidence that justified the latch
(the extra endpoint) is already gone, but the next cycle sees the latch and finishes the job. Integrity findings
are acted on **before** the slower prerequisite checks (guard status, compose render) run. An action is judged
on a **fresh** snapshot (see "Locks").

**Locks.** `state/deploy.lock` belongs to `remote-deploy.sh` alone (one deploy at a time, `flock -n`); the
watchdog never takes it, so a legitimate deploy cannot be refused because a check cycle is running (it was:
533 of 612 attempts in the QA run). The watchdog's right to *change* the stack is a second lock,
`state/containment.action.lock`: a deploy holds it for its whole duration (waiting up to 180 s for an action
in flight, then exit 4 "the watchdog is in the middle of stopping or starting the stack"); the watchdog takes
it only when a cycle has something to change, without waiting, and **re-observes after taking it** (what it
decided on may be a deploy ago); busy means `paused` (a lock older than 30 minutes is a hung deploy and does not
disable containment). A healthy cycle - almost all of them - takes no lock at all. Children (`docker`, the guard,
the checks) never inherit the lock descriptor, so a hung or orphaned child cannot keep it after the watchdog died.
`docker events` is filtered to `create,start,die,destroy,connect,disconnect`: a healthcheck run is not news (nine
10 s healthchecks used to make a 300 s poll run a cycle every ~8 s).

**The supervised set** is every service with a route out (api, discovery, telegram, the three proxies) plus
the agents: exactly the services `compose.yaml` gives `restart: "no"`, so that after a reboot or a daemon
restart **the daemon starts none of them** (the restart race of "Startup window" is closed by
construction, not by a retry loop). The watchdog starts them in two phases (proxies healthy first), with
`docker compose start` only (it cannot create, pull or build), and restarts a crashed one with a 30 s
back-off. postgres, scheduler and session-controller keep `unless-stopped`: they have no route to the host.
The deploy script commits a release to the watchdog only **after** every gate passed (`runtime-containment.sh
commit`, under its own lock, refused if a supervised service renders any restart policy but `no`), records
`desired: stopped` before it tears a stack down, and refuses to deploy or roll back (exit 13) unless the
watchdog has a fresh heartbeat and is not latched. While a deploy holds the action lock the watchdog pauses
its decisions (the deploy is replacing containers on purpose; it still heartbeats).

**Dead man.** If the watchdog is killed, hangs (systemd's `WatchdogSec`), or is stopped
(`systemctl --user stop`, shutdown), `ExecStopPost` runs `quarantine --no-latch`: the supervised set stops,
and the next instance restarts it after verifying everything. A watchdog that is *disabled* leaves the
stack stopped (nothing else starts it) and the deploy gate refuses (exit 13): the failure is loud and
safe, never silently permissive.

**Install** (root, once; before the first deploy of a release that has `restart: "no"`):
```bash
sudo install -o root -g root -m 0755 deploy/runtime-containment.sh "$D"/       # with the other helpers
# as hunter-deploy:
mkdir -p ~/.config/systemd/user && cp /opt/internship-hunter/releases/<sha>/deploy/systemd/hunter-containment.service ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now hunter-containment
"$D/runtime-containment.sh" status --require-active        # state: idle (no release committed yet), heartbeat: <10s
```
**Operate.** `runtime-containment.sh status` (state, heartbeat, latch, warning), `check` (read-only, names every
finding, exit 10/11), `journalctl --user -u hunter-containment`, `~/…/state/containment/events.log`.
After an incident: investigate (`docker inspect`, `events.log`), remove the cause, then
`runtime-containment.sh reset [--disconnect-foreign]` (refused while any N/H/D finding, a missing guard or an
unreachable protected address remains) - the watchdog restarts the set within one cycle.

*Recovery from a latch whose cause cannot be removed in place* (e.g. `NET-FLAG`: a project network was
recreated without `--internal`, and `reset` keeps refusing; `remote-deploy.sh deploy|rollback` is refused with
exit 13 while latched): as the daemon's owner, `docker compose -p internship-hunter down` (volumes are kept),
fix or recreate the network, `runtime-containment.sh reset`, then deploy. `reset` and `deploy` never run at the
same time (the action lock).

**First deploy with runtime containment.** `remote-deploy.sh` commits a release to the watchdog only if the
release renders `restart: "no"` for every service with a route out and every agent. Every release built
before this change renders `unless-stopped` and is refused (`commit --check`: exit 11). Consequently:
1. **The new release is checked before anything changes** (before images are loaded or the database is
   dumped): a release containment cannot supervise is refused with exit 11, not discovered at the end of an
   activation that has already migrated the schema.
2. **A running release that predates containment cannot be restored under it.** A normal `deploy` over it is
   refused with **exit 14** before anything changes; `deploy-irreversible` acknowledges that if the new release
   fails there is nothing to go back to. Then, on a failed activation, nothing is restored: the stack is stopped
   (fail closed, `desired: stopped` is recorded), `current` stays on the old release, the script says in so many
   words that the old release was **NOT restored**, prints the manual-recovery procedure and exits 10. It never
   prints "restored" for something it did not restore. (The same convention as an irreversible schema change.)
3. **`rollback` to such a release is refused (exit 14) before anything is touched**, naming the release that
   keeps running.
4. A first deploy with no previous release is unchanged: a failure tears down and leaves nothing current.
Plan the migration deploy for a moment when a short outage is acceptable, take the backup first (the deploy does
too), and use `deploy-irreversible`. After it, every later release is committable and the normal restore path
applies.

**What a project container must be (`SPEC`).** Docker labels are free text: `docker run --label
com.docker.compose.project=… --label com.docker.compose.service=agent-codex` yields a container the watchdog
used to treat as the agent, whatever else it carried (`--cap-add NET_ADMIN`, `seccomp=unconfined`, `-v /:/host`).
`commit` now renders, from the release's own compose files (`docker compose config`) and the image store, a
**spec** for every service and stores it in the contract (version 2; the image is pinned by *content*: the id
the tag had at commit). Every cycle each project container, running or stopped, is compared with it:

| Compared | Rule |
|---|---|
| image | `Config.Image` equals the compose reference **and** the image id equals the pinned one (a moved tag is a different container); entrypoint, command and user equal the release's (or the image's own defaults) |
| privileges | `Privileged` false; `CapAdd`/`CapDrop`, `SecurityOpt` (`no-new-privileges`, no `*=unconfined`), `ReadonlyRootfs`, devices, device cgroup rules, sysctls, `GroupAdd` equal the release's; no dangerous capability (`NET_ADMIN`, `SYS_ADMIN`, `NET_RAW`, `SYS_PTRACE`, …) even if a release asked |
| namespaces | pid/uts/userns `""`; ipc `private`/`shareable`/`none`; cgroupns `private`; cgroup parent empty; runtime = the daemon's default (`docker info`) — unless the release says otherwise |
| network | `NetworkMode` is one of the release's own networks (never host, `container:`, bridge); `ExtraHosts` (`host-gateway`) and published ports (`PortBindings`, `PublishAllPorts`) equal the release's; `VolumesFrom`/`Links` empty |
| mounts | the **effective** mount list (what `-v`, `--mount`, `--tmpfs` and image `VOLUME`s produced) equals the release's volumes/binds/tmpfs, plus anonymous volumes at destinations the *image* declares; the Docker socket never |

A difference is a latching `SPEC` finding naming it (`cap_add is ['NET_ADMIN'], the release says []`, `mounts
differ: unexpected [('bind', '/', '/host', False)]`); a running impostor is stopped with the set whether it is
supervised or not; a **stopped** impostor is caught before the watchdog can `compose start` it. Environment
variables are not compared (see residual risk 8). `commit` refuses (exit 11) a release that itself asks for
a dangerous capability, an unconfined security option, a device, the Docker socket, a host namespace,
`volumes_from`/`links`, or an image missing from the store (it cannot be pinned) — `commit --check`, which
runs before the images are loaded, skips only that last check.

*Transitions.* While a deploy holds the action lock the watchdog yields, so release B's containers are never
judged by release A's contract; once `commit` wrote B's contract they are B's containers. A rollback re-commits
A (its own spec, its own pinned ids) before the watchdog sees A's containers again. `compose up
--force-recreate` produces the same spec and is accepted. A container that vanishes between `docker ps` and
`docker inspect` makes the cycle `unverified` (nothing is changed, retried), never a finding. Left behind by a
deploy killed halfway, a stopped container of another release carrying the service label **is** a finding
(`docker rm` it, then `reset`). A contract written before this change (version 1) is *not* enforced for the
spec: a `SPEC-LEGACY` warning says so every cycle until the next deploy commits version 2.

**Failure behaviour** (each is a test in `tests/test_runtime_containment.py` against a stateful fake daemon,
and, where marked *real*, in `tests/test_runtime_containment_lab.py` on a genuine rootless Docker):
guard rule deleted / guard removed / daemon restarted (*real*: stop → repair → start, never start before a
verified guard); host address set changed (*real*: absorbed without stopping anything, three in a row do not
latch, a new *global* address is in the policy within seconds and refused to a container); hot `network connect`, foreign container on an agent network, internal flag lost, privileged /
host-network container, daemon-level `dns` after a restart (*real*); Tailscale late (*real*: nothing starts
while the targets are not live; running stacks are not stopped when they go away); an ad hoc container on
the default bridge or an unrelated network, a replica, the exited `migrate`, a service missing a network, a
changed host resolver (false positives: nothing happens, *real* for the first two); docker unreachable or
hanging (`unverified`, nothing is changed, systemd's watchdog restarts a hung script); a deploy in progress
(paused) and a hung one (acts anyway); the deploy lock never refused by a running watchdog (*real*); the hostile
endpoint cut before the first container stops, and a watchdog killed right after the cut (*real*); a release
that predates containment (*real* `docker compose` render of main's compose); a latched stack that someone starts by hand (stopped again); flapping.

**Rollback of this layer.** The watchdog never edits the host: `systemctl --user disable --now hunter-containment`
stops the supervised set (dead-man) and the deploy gate then refuses; to go back to the previous behaviour
deliberately, deploy the previous release (its `compose.yaml` has `restart: unless-stopped`), reinstall the
previous `remote-deploy.sh` (it does not know exit 13) and delete the unit. Nothing else changed on the host.

**Residual risks.** (1) Detection latency: up to 10 s for a poll-only change, but a Docker network/container
event or a host address/route change runs a cycle within about a second; a hot attachment is therefore
exploitable only inside that window. (2) The watchdog runs as `hunter-deploy`, as the daemon does: it
defends against compromised *containers* and mistakes, not against that user. (3) A stop is `docker stop`
(5 s grace): in-flight agent work is lost by design. (4) The data tier is not supervised: a compromised
data-tier container is outside this layer's model (it has no route to the host or the Internet). (5)
The runtime DNS check reads Docker's `ResolvConfPath` files (readable by the daemon's owner); a Docker that
stops writing the `ExtServers` annotation makes the OUT services `UNVERIFIED` (stop, self-healing) rather
than passing. (8) The spec does not cover the container's **environment**, its healthcheck, or who may *create* containers:
anyone who can talk to the rootless Docker socket (the `hunter-deploy` user) can also write the contract or stop
the watchdog — the spec defends against containers and operator mistakes, not against that user. A foreign
container (no project label) that mounts a project *volume* is also outside it. (6) Not verified on the production host: the unit under the real user manager, `ip monitor`
and `docker events` there, the first Tailscale-late boot. (7) `AGENT_MODE=cli` stays disabled: this layer is
the runtime-containment prerequisite for it, not the whole of it (see "CLI mode" above: the pinned CLIs must
still hand hostnames to the proxy, the allow-lists are still defaults, RSM stays off).

### Validation plan (all on the production host, in this order)

| # | Check | Expected |
|---|---|---|
| V1 | `"$GUARD" status` | `active (pid ...)` |
| V2 | step 5 probes | tailnet `22`/`8000` blocked; `1.1.1.1:443` and DNS work |
| V3 | `docker compose up -d --wait` | proxies healthy with `EGRESS_FORBIDDEN_TARGETS` set |
| V4 | `ADMIN_TOKEN=... SMOKE_EXPECT_ROOTLESS=1 SMOKE_PROTECTED_IPS=$HOST_TS_IP SMOKE_ROOTFUL_TARGETS=<ip:port from host-isolation.conf> deploy/smoke-test.sh` (`API_URL` must be the literal `http://127.0.0.1:18000`) | `SMOKE TEST PASSED`; includes `CONNECT api.anthropic.com` / `api.openai.com` = 200 (`SMOKE_EXTERNAL=1`, the default), "controls verified" for every container |
| V5 | negative control: `"$GUARD" remove`, re-run V4 | **fails** naming `egress-* reaches 100.107.22.84:22 (connection OPEN)` and `... :2375 (connection REFUSED ...)`; then `apply` again |
| V6 | idempotence: run `"$GUARD" apply` twice, then `status` | still `active`; exactly two jumps per chain, no duplicated rules |
| V7 | `systemctl --user restart docker`; `"$GUARD" status` | `active` without manual action |
| V8 | W1 and W2 above | gates refuse while unguarded, services come up after `apply` |
| V9 | read-only: `docker ps` of the rootful daemon, `ufw status verbose`, `ss -tlnp`, Gluetun reachable from the tailnet as before, `ss -ltn 'sport = :18000'` shows only this application | identical to your pre-change notes |
| V10 | per service with a route out: `grep -E '^(nameserver\|# ExtServers)' /etc/resolv.conf` | `127.0.0.11` and `ExtServers: [10.0.2.3]`, never `host(...)` ("DNS") |
| V10b | per **internal-only** service (agents, postgres, ...): the same `grep` | `127.0.0.11` and `ExtServers: [host(...)]` or no annotation - **never** an explicit address such as `[10.0.2.3]`; and `python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.config/docker/daemon.json'))).get('dns'))"` prints `None` (or the file does not exist) |
| V11 | `deploy/check-dns.sh` (enforce) | `ok   DNS: 6 service(s) with a route out use 10.0.2.3 ...` |
| V11b | `SMOKE_DNS_CONFIG_ONLY=1 SMOKE_DNS_EXPECT=10.0.2.3 deploy/check-dns.sh -p internship-hunter -f compose.yaml --env-file shared/.env ...` (what the deploy gate runs BEFORE `compose up`; starts nothing) | `ok   DNS configuration: 13 services render dns exactly as the guard allows ...` |
| V14 | `runtime-containment.sh status --require-active` as `hunter-deploy`; `systemctl --user is-active hunter-containment` | `state: ok N/9 ...`, heartbeat < 15 s; `active` |
| V15 | `docker compose ps` shows the six services with a route out and the agents with restart policy `no` (`docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' <container>` = `no`); postgres/scheduler/session-controller `unless-stopped` | as stated |
| V16 | reboot drill (maintenance window): after boot, before the watchdog, `docker ps` shows no supervised container; within ~1 min of tailscaled being up they are all running and `status` says `ok` | as stated |
| V12 | `agent-codex`: resolves `egress-codex.`; `example.com.` and `example.com. 10.0.2.3` get no answer | as stated |
| V13 | counters of `HUNTER-EGRESS-GUARD` `-d 10.0.2.3 ... dpt:53` grow while a proxy resolves | packets > 0 |

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
namespaces (`tests/test_host_egress_guard_netns.py`), running the actual scripts, in the production
`--detach-netns` layout (rootlesskit child in the host namespace, daemon namespace bind-mounted in the
child's mount namespace only):

| from a container | before | with guard |
|---|---|---|
| host tailnet IP `:22`, `:8000`; host public IP; slirp gateway `10.0.2.2`; bridge gateway | reachable | blocked |
| a closed port on those addresses (e.g. `:2375`) | **refused** (an answer) | blocked |
| a container on `docker0` -> tailnet IP | reachable | blocked |
| public `8.8.8.8:443`, DNS to the resolver | works | works |
| peer on the same bridge; daemon -> container (docker-proxy style) | works | works |
| start gate of a service on `docker0` | stops it | lets it run |
| 9 kinds of tampering (a reject deleted, ACCEPT inserted before our jumps, a jump removed, chain flushed, ACCEPT inside the chain, INPUT chain edited, IPv6 chain flushed, INPUT jump removed, ACCEPT inserted before Docker's own jump) | - | `status` fails; `apply` repairs (the displaced Docker jump is reported, not "repaired") |

With the then-current `docker/egress-proxy.sh` (tinyproxy, Alpine 3.20's 1.11.x; replaced since by
`docker/egress_proxy.py`, see docs/security-architecture.md "Egress") in the same sandbox: `CONNECT` to an
allow-listed public name -> `200` before and after; to an allow-listed *name that resolves to the host's
tailnet IP* -> `200` before (the hostname filter did not protect the host) and `500` after; IP literals,
other ports, other names -> `403` both ways. The replacement refuses such a name itself
(`403 resolve-non-global`) before the guard is even consulted. The probe and gate scripts were also run
with **Alpine 3.20's own busybox `nc`** (1.36.1): `nc -vv -z` prints `Connection refused` /
`Host is unreachable` / `Network unreachable` / `Operation timed out`, and **`nc -z` alone is silent on a
refusal** - which is why the probes use `-vv` and calibrate against it.

The same layout is exercised for its failure behaviour with real user, mount and network namespaces
(`tests/test_host_egress_guard_detached_netns.py`): the happy path and `remove`; absent, plain-file,
symlink and wrong-namespace targets and an ambiguous layout are refused with **no `nsenter` call at all**;
missing Docker chains change nothing; a namespace swapped, or a daemon killed, under a running
`apply --wait` is detected and neither namespace is touched; a stale `child_pid` is refused; after a real
restart the new namespace is unguarded until `apply` runs and never inherits anything; the gate refuses a
wrong network or user namespace (exit 97, the command is not run). In this
sandbox layout the previous guard (`main@597cf65`) stops at its host-namespace check; on the production host
the same layout was reported to fail with `Operation not permitted` from `nsenter -U -n -t <pid>`. Either way
entering the child's namespace means entering the host's, which is what the new resolution replaces.

**DNS on a real rootless daemon.** `tests/rootless_lab/lab.sh` starts a genuine rootless Docker 29.9.1 (rootlesskit
`--detach-netns` + slirp4netns) as an unprivileged user - pinned, checksummed downloads, one mapped uid, an
Alpine rootfs repacked with root ownership, nothing else different from production - and
`tests/test_dns_rootless_lab.py` runs the project's real `compose.yaml` topology on it (images replaced by
Alpine, processes by `sleep`) with the real guard and the real `check-dns.sh`: embedded DNS without `dns:` reaches
the Internet while a guard that allows *no* resolver is applied (counters on the guard: 0 packets, `host(...)`
in `resolv.conf`); the same stack with the explicit resolver is blocked by that guard and works with the right
one (counters grow); a private LAN resolver is rejected even when configured; agents and the data tier
resolve nothing outside and only their neighbours' names; the check catches an internal service given a
resolver, a runtime `docker network connect`, a changed topology and a wrong expectation; a daemon-level `dns`
puts an explicit upstream into every agent (`ExtServers: [10.0.2.3]`) which `check-dns.sh` refuses, and
gives every ad hoc container the guard's DNS exception (why it must not be configured); a probe sabotaged
inside real containers is a defect, not a pass. Opt-in locally (`HUNTER_ROOTLESS_LAB=1`, ~100 MB once), a
required CI job (`rootless-dns-lab`, ubuntu-22.04, no sudo). `tests/test_check_dns.py` covers the script's own
failure modes against a modelled resolver.

**CI.** The `host-guard-netns` job is a **mandatory security job that fails when it cannot do its
work**. It runs the packet tests on `ubuntu-22.04` (no sudo, no AppArmor change - this repository never
relaxes either); every step runs under `shell: bash` with `set -euo pipefail`, because GitHub's default
`bash -e` lets `pytest | tee` swallow a failing pytest (reproduced and covered by
`tests/test_workflows.py`, which executes the real CI step scripts with a failing, a skipping and a passing
pytest). If user+network namespaces or `iptables` are unavailable the job ends **red** with an `::error`
annotation and a `BLOCKED` step summary - there is no success-on-skip path. **This is a genuine CI
blocker to resolve, not to bypass:** a compatible runner is `ubuntu-22.04` (what the job uses);
`ubuntu-24.04` restricts unprivileged user namespaces via AppArmor and would need a per-binary profile for
`/usr/bin/unshare` (as `rsm-pilot.yaml` does for rootlesskit), which requires elevated privileges and is a
policy decision. Not verified anywhere in this repository's history: the job on GitHub's runners, the
production host, slirp4netns/pasta, Docker's rule order on that host, Alpine's tinyproxy build. The
`docker` job additionally runs `check-host-isolation.sh` against the **real images** (Alpine `nc`,
Python): in report mode only reachability is a warning; a broken or missing probe tool, a failed exec or an
incomplete result fails the job.

### Limits you accept

- Public Internet space stays open at the network level: a compromised proxy can open a socket to
  any public IP and port; the CONNECT path is narrowed by the hostname list, the pinned global address
  and the SNI check, not by the network. Inside a correctly named TLS session the proxy sees nothing
  (domain fronting by `Host` header is not detectable without terminating TLS; docs/security-architecture.md,
  "Egress").
- DNS is a covert channel for anything with a route out: `10.0.2.3` forwards arbitrary names to the host's
  resolver (and from there to the Internet), so a compromised `egress-*`, `discovery`, `telegram` or `api`
  container could tunnel data through queries. Internal-only services (the agents) cannot; the proxies'
  hostname filter does not apply to DNS. Query content is visible to the host's upstream resolver.
- The DNS behaviour above is Docker 29.9.1's (two forwarding paths, `ExtServers: [host(...)]`). It is
  tested, not guaranteed: `check-dns.sh` fails closed if the annotation disappears or changes, and
  `tests/test_dns_rootless_lab.py` must be re-run on a Docker upgrade (CI job `rootless-dns-lab`).
  Not verified: pasta (a different resolver address; `DNS=`/`HUNTER_DNS` must then change together).
- The guard is lost when the daemon restarts until `ExecStartPost` re-applies it; the start gates
  (above) keep application code from running in between, for the listed targets only.
- A host address acquired after `apply` (DHCP) makes `status` fail (`chain ... differs`) and so
  blocks the next deploy until `apply` is re-run; established connections are not cut.
- **IPv6.** Investigated, not assumed: Docker's default bridges (and every compose network here:
  `enable_ipv6` is forbidden by a test) give containers no IPv6 default route, and the check refuses to
  validate if any container has one or any outbound network enables IPv6. As defence in depth the guard
  also rejects every NEW IPv6 connection from a Docker bridge, both forwarded and to the daemon namespace
  (ICMPv6 kept), and `status` verifies those chains. Proven with **real IPv6 packets** in the sandbox
  (host's IPv6 tailnet address, IPv6 Internet, daemon namespace: reachable without the guard, blocked with
  it) - not inferred from IPv4 tests. Consequence: IPv6 egress is unavailable, by design. Not verified:
  how slirp4netns/pasta on the production host handles IPv6 for the daemon namespace itself.
  Docker's nftables mode (no `DOCKER-USER`) is refused, not worked around.
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
