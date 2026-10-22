# Security architecture (Milestone 1 hardening, round 3)

## Why there is no Redis/RQ any more

Round 2 hardened RQ with JSON serialization and a consumer-side allowlist (`HardenedJob`).
An independent reviewer then showed it could still be bypassed: RQ imports and *calls* the
callbacks named in a job (`on_failure`, `on_success`, `on_stopped`) by dotted path, and a
job that fails our argument validation is exactly what triggers the failure callback.
Reproduced here: `builtins.print(job, connection, ...)` ran for a forged job rejected by
`HardenedJob`. A framework that dispatches on names read from a shared store cannot be
made safe by checking a few of those names, so the queue was **replaced, not patched**.

The V1 work queue is now one PostgreSQL table (`tasks`). Nothing in it is executable:

- `kind` is a CHECK-constrained enum (`scan`), `scan_id` is a foreign key. There is no
  payload, function name, callback, URL or serialized object column.
- The worker's behaviour for a task is a fixed code path (`orchestrator.process_claim`).
- The database rejects forged kinds/states (`ck_tasks_kind`, `ck_tasks_state`), proven by
  `tests/test_postgres.py` and by `deploy/smoke-test.sh` on the live stack.

## Trust zones

```
 Telegram ──egress──▶ telegram ─┐
 Tailscale ─127.0.0.1▶ api ─────┼──▶ PostgreSQL  (internal "data" network)
                      scheduler ┘        ▲
 ATS boards ◀─egress── discovery worker ─┘  claims tasks: FOR UPDATE SKIP LOCKED + lease
                      └──────┬──────────┬─────────┬───────────── one internal net per agent
                    HTTP+token│          │         │
                       ┌──────▼──┐ ┌─────▼───┐ ┌───▼─────┐
 provider APIs ◀─CONNECT egress-* proxy (per agent: host allow-list, :443, pinned IP, SNI==host)
                       │ agent   │ │ agent   │ │ agent   │   untrusted runtime:
                       └─────────┘ └─────────┘ └─────────┘   no DB, no admin/Telegram secrets
```

## Rules

1. **Agents never touch the database.** Each agent container runs `hunter.agent_runner`
   (HTTP planner, bearer token, JSON). The orchestrator *calls* it and treats the reply as
   hostile data: strict schemas (`hunter/schemas.py`), ≤15 queries of ≤160 printable chars,
   ≤32 KiB, identity must match the agent called, only the exception class is stored.
2. **Agent egress is enforced by topology, not by proxy variables.** Agent networks are
   `internal` (no gateway): the only reachable address besides the orchestrator is the agent's
   own egress proxy. `HTTPS_PROXY` is merely how the CLI finds it; ignoring it yields "network
   unreachable", not a bypass. The proxy (`docker/egress_proxy.py`, non-root, Python standard
   library only) accepts exactly `CONNECT <allow-listed host>:443`, pins the connection to the
   global IPv4 address it resolved itself, and lets the tunnel carry only a TLS handshake whose
   server name (SNI) is that same host - see "Egress" below for what that does and does not
   prove. The lists are policy, kept in `compose.yaml`/`.env`. **This is an application-level
   control on what the proxy will *ask for*. It is not a network boundary for the proxy
   process** - see "Host boundary" below.
3. **Task leases and fencing** (`hunter/taskqueue.py`). A task is claimed in one short
   transaction under `FOR UPDATE SKIP LOCKED` and gets a random `lease_token` and expiry;
   a heartbeat thread renews it. Every write a worker makes to a scan's results happens in a
   transaction that first *fences* (re-validates + renews the lease, row-locking the task).
   An expired or superseded worker gets `LeaseLost` and its writes roll back; terminal updates
   are conditional on `state='running' AND lease_token=:mine`.
4. **Recovery.** `reap()` (run by every worker) returns abandoned `running` tasks to `queued`
   with back-off, up to `max_attempts` (3), then fails the task *and* the scan. Queued tasks
   nobody picks up for an hour fail instead of running stale. Agent runs are replaced on retry.
5. **At most one active scan per profile**, by a partial unique index; scan and task are
   created in one transaction, so a scan can never exist without work behind it.
6. **Least-privilege containers**: non-root, read-only root fs, `cap_drop: ALL`,
   `no-new-privileges`, memory/CPU/pid limits.
7. **Submission is disabled in code** (`SUBMISSION_ENABLED = False`).

## What an agent compromise can and cannot do

| Can | Cannot |
|---|---|
| Return bad data (rejected by schema → run marked failed) | Read or write PostgreSQL |
| Use its **own** provider login via its proxy | Reach LAN, tailnet, host, metadata service, other agents (topology) |
| Read its own `AGENT_TOKEN` (via `/proc`) | Reach the API, admin routes, Telegram token |
| Consume its CPU/memory share until limits | Reach another provider's API through its proxy |

That table assumes the proxy itself is not compromised. A bug in the proxy's request or TLS
parser is reachable by the agent; the proxy is small, memory-safe Python with strict bounds
(see "Egress"), and the following section is about what a compromised proxy could then do.

## Egress: what the agent's proxy enforces, and what it cannot see

**Threat.** In `AGENT_MODE=cli` an agent runs a real CLI with real provider credentials and
untrusted input (job postings, profiles). Assume it is prompt-injected or otherwise hostile and
tries to move data anywhere other than its provider, or to reach the host, the LAN or the tailnet.
Its only way out is `CONNECT` through its own proxy (the agent network is `internal`; it has no
route and no resolver for public names - `deploy/check-dns.sh`).

**What the pinned CLIs actually do** (measured, not assumed: `tests/cli_probe`, CI job
`cli-egress-probe`, run through `hunter.agents.run_plan` with the pinned Claude Code and Codex in a
namespace that has nothing but loopback): they send **no DNS query of their own**, only
`CONNECT <hostname>:443`, with a TLS **SNI equal to that hostname** and **no Encrypted Client
Hello**. Hosts needed: Claude Code - `api.anthropic.com`, and `platform.claude.com` to refresh
its OAuth token; Codex - `api.openai.com` (API-key login) or `chatgpt.com` + `auth.openai.com`
(ChatGPT login). Those are the defaults; the old defaults (`console.anthropic.com`, `claude.ai`,
`statsig.anthropic.com`) were not used and **lacked the token endpoint**. Without hardening Codex
also reached `github.com`/`api.github.com` (plugin and skill sync - a public write channel) and
`ab.chatgpt.com` (analytics); `hunter/agents.py` now turns those features off on every invocation.

| Vector | Enforced by | Evidence |
|---|---|---|
| `CONNECT` to an unlisted name, an IP or IPv6 literal, another port, a look-alike, the other provider | exact host match, port `443` only: `403 host`/`403 port`, nothing is dialled | `tests/test_egress_proxy.py`; smoke test, all three proxies |
| plain-HTTP forwarding, other methods | `403 method` | same |
| DNS rebinding: an allowed name whose answer is private, the host, the tailnet, metadata | the proxy resolves, refuses if **any** A record is not global unicast (`403 resolve-non-global`), then dials **that** literal address (no second lookup) - and the host guard rejects those destinations at the network layer anyway | proxy tests (resolver answers injected); guard: netns packet tests |
| **SNI swap** on a shared CDN: `CONNECT api.openai.com`, then a ClientHello for another site served by the same edge | the first ClientHello must name exactly the CONNECT host, or the tunnel is cut **before the provider receives it** (`tls-sni-mismatch`); this also stops swapping between two allow-listed names | proxy tests with real OpenSSL clients; smoke test against the real providers (`www.cloudflare.com` via each proxy is cut) |
| second ClientHello after a TLS 1.3 HelloRetryRequest naming another site | every plaintext ClientHello is checked until the real ServerHello; a third one, or one after the ServerHello, is cut | proxy tests (scripted HRR) |
| no SNI (default virtual host), Encrypted Client Hello / ESNI (hides the real name) | cut (`tls-no-sni`, `tls-ech`) | proxy tests |
| non-TLS bytes through the tunnel (another protocol to the provider's address) | the first record must be a TLS handshake | proxy tests |
| bypassing the proxy | no route: `internal` network | smoke test, `check-host-isolation.sh` |
| DNS as a channel | agents have no upstream resolver | `check-dns.sh`, `rootless-dns-lab` |
| QUIC / UDP, CONNECT-UDP | no UDP route; only HTTP/1.x `CONNECT` is parsed | topology; proxy tests |
| a redirect to another host | invisible inside TLS, but following it needs a new `CONNECT`, judged like any other | - |

**What it cannot see (and does not claim to stop).**
- **Domain fronting proper.** After the handshake everything is encrypted. If a CDN routes by the
  HTTP `Host`/`:authority` header rather than by SNI, a request inside a correctly named tunnel could
  reach another customer of that CDN. No proxy can check this without terminating TLS. Some CDNs
  reject an SNI/Host mismatch; that is the provider's control, not ours, and nothing here verifies it.
- **The provider itself.** Whatever the agent's account can do at its provider (store content, use
  provider-side tools), a hostile agent can do. That is inherent to giving it the login.
  Mitigation: dedicated accounts with the smallest plan/scope, spend limits, no organisation-admin
  keys, and the per-connection log below.
- **`chatgpt.com` is a whole web application**, not an API endpoint. It is allowed only because the
  ChatGPT login of Codex needs it. With API-key login set `EGRESS_ALLOW_OPENAI=api.openai.com`.
- Volume and timing inside allowed sessions; TLS 0-RTT early data (opaque, but only after a checked
  ClientHello, so bound to the right server).

**Why not TLS interception?** Terminating TLS would let the proxy compare `Host` with SNI and
allow-list paths. But it needs a private CA trusted by both CLIs (Node and Rust/rustls trust
stores), and it puts every provider credential and every prompt in cleartext in the proxy, which
would become the most valuable target in the system. The chosen boundary - exact host, global pinned
address, matching SNI, minimal per-agent lists - is everything that can be enforced *without* reading
the traffic.

**Who may use a proxy** is decided by topology, not by a password: each proxy sits on exactly one
agent network plus its own egress network (`tests/test_compose_invariants.py`). The orchestrator
(`discovery`) shares the agent networks but has its own route out, so a proxy gives it nothing new.
A per-agent proxy password would be held by the very agent it is meant to constrain.

**Audit trail.** Every connection is one JSON line on the proxy's stdout: host, resolved and dialled
address, SNI, number of ClientHellos and HelloRetryRequests, verdict and reason, bytes each way,
duration. No request contents, no credentials.

## Host boundary (network level, not hostname level)

Observed on the production host (Ubuntu 24.04, rootless Docker): a container on a default
bridge could open TCP connections to the host's own Tailscale IP, on `:22` (sshd) and `:8000`
(an unrelated rootful Gluetun container's published port). An `--internal` network could not.

**Root cause.** Every container on a non-internal network leaves through the rootless
daemon's user-space NAT (slirp4netns/pasta). That NAT performs the `connect()` itself, from the
*host's* network namespace, so any address the host owns is reachable. No host firewall rule
(UFW/nftables `FORWARD`) can intervene because no forwarded packet ever exists on the host.
The `--disable-host-loopback` option rootlesskit sets by default only concerns the gateway's
mapping to `127.0.0.1`, not the host's other addresses. (The cause is inferred from the two
observations above and from how these NATs work; it was not traced inside the production host.
The sandbox in `tests/netns_guard_sandbox.sh` reproduces the *topology*, not the NAT itself.)

| Component | Route out | Reaches the host before the guard? | Control that stops it |
|---|---|---|---|
| agent-* | none (`internal`) | no | topology (smoke test checks, incl. host IPs) |
| egress-* proxies | `egress_<name>` | **yes**, with *any* process in the container | host guard (network); healthcheck + smoke test detect its absence |
| discovery, telegram | `egress` | **yes** | host guard |
| api | `edge` (only to publish the loopback port) | **yes** | host guard |
| any other container on this daemon | default bridge | **yes** | host guard (covers `docker0` and every `br-*`) |

Hostname filtering does not help here for two reasons. (1) It only governs what an agent can
*ask the CONNECT handler for*; the proxy process can open any socket itself. (2) Even through
the handler, an allowed *name* that resolves to a private or host address is dialled: with the
real `egress-proxy.sh`, `CONNECT <allow-listed-name>:443` whose A record is the host's Tailscale
IP returned `200` without the guard and `500` with it (`docs/deployment.md`, evidence).

Layers, each answering a different question (`docs/deployment.md`, "Host isolation"):

1. **Prevent** - `deploy/host-egress-guard.sh`: iptables rules in the rootless daemon's own
   network namespace reject NEW connections from any Docker bridge to non-global space, to every
   address of the host (rootful bridges included), to its default gateway and to the namespace
   itself. DNS to the namespace's resolver and the public Internet pass. Operator-applied,
   reversible, never touches the host's firewall. `status` verifies the *whole* IPv4+IPv6 policy
   (chain contents, jump position, Docker's own jump) and proves the target process is this user's
   rootless daemon; any missing, extra, reordered or edited rule fails it.
2. **Refuse** - `remote-deploy.sh` will not deploy or roll back unless the root-owned guard reports
   the full policy active and `EGRESS_FORBIDDEN_TARGETS` is set, and runs the enforce-mode checks
   after `up --wait`: host reachability and DNS (failed first deploy: torn down; failed restore: stack
   stopped).
   *DNS is part of the boundary.* Docker's embedded resolver forwards names from the **daemon's**
   namespace - outside the guard - unless `dns:` is explicit, so every service with a route out names
   the one resolver the guard allows (`10.0.2.3`) and `deploy/check-dns.sh` verifies it, together with
   the facts that internal-only services (the agents) resolve nothing outside the project and that
   service names resolve only between services sharing a network (docs/deployment.md, "DNS"). The
   rendered compose DNS is compared with the guard's `DNS=` before anything starts (and the caller's
   `HUNTER_DNS` is ignored); the runtime `resolv.conf` of the internal-only services must carry no explicit
   upstream (so daemon-level `dns` in `daemon.json` is refused, and must not be configured); and the raw
   UDP probe has a positive control, so "no answer" from an agent is never the product of a broken probe.
3. **Start gate** - after a daemon restart the restart policy can start containers before the
   guard is re-applied; `api`, `discovery`, `telegram` and the proxies therefore exit at start while
   a forbidden target answers, before any application code runs.
4. **Detect at runtime** - the proxy's healthcheck *reports* unhealthy if it can reach anything listed in
   `EGRESS_FORBIDDEN_TARGETS` (e.g. `100.107.22.84:22,100.107.22.84:8000`). That only prevents agents
   from *starting* behind it and fails `compose up --wait`; an unhealthy container is not stopped or
   restarted, and nothing at all watches `discovery`/`telegram`/`api` while they run. Removing the
   guard at runtime is therefore a documented blocker for `AGENT_MODE=cli`.
5. **Verify** - `deploy/check-host-isolation.sh` dials every protected address from every container
   with a route out (computed from `compose config`) with raw TCP, including a canary listener on a
   random port. It counts an open port *and a refusal* as reaching the host, and fails closed unless
   each container first passes its own positive controls. In `report` mode (rootful CI runners) only
   reachability becomes a warning; broken tools, missing output and incomplete coverage stay fatal.
   `deploy/check-dns.sh` does the same for DNS: services with a route out use the guard-allowed resolver
   from inside the container, internal-only services resolve nothing outside and carry no explicit upstream
   resolver, names resolve only across shared networks (a leak or a wrong resolver is a breach in every
   mode); a probe that cannot receive an answer from the approved resolver is a defect in every mode.
   The proxy's start check and healthcheck use the same rule: only "unreachable", "prohibited" or
   "timed out" count as isolation, after a self-test proves `nc` works here.

Compose gives each proxy its **own** outbound network (`egress_<name>`), so a compromised proxy
cannot reach another proxy (and so another provider's allow-list) or `discovery`/`telegram`.

## Residual risks

- **Compromise of a trusted component** (api, telegram, scheduler, discovery) gives database
  access; they run first-party code only and share one database role. Per-component roles
  are future work.
- **Provider hostname lists are unverified** against the pinned CLI versions; if a CLI needs
  another host the run fails closed (visible in the proxy log), it does not widen silently.
- **A provider-owned allowed hostname is trusted**: exfiltration *to the provider* with the
  agent's own account remains possible.
- **Without the host guard the host is reachable from the proxies** (previous revisions of
  this document claimed otherwise; that claim only covered the CONNECT handler). With it, a
  compromised proxy can still open connections to any *public* IP and port: provider CDNs do
  not allow an IP allow-list, so the hostname list stays the only filter for public space.
  Residual guard limits: it is lost when the daemon restarts until re-applied (systemd
  `ExecStartPost`; restart-policy containers can run unguarded for the first seconds), a host
  address acquired after `apply` is covered only after the next `apply`, and established
  connections are not cut. See `docs/deployment.md`.
- `postgres` keeps five capabilities its entrypoint needs. Provider/CLI sandbox flags are
  unverified against the pinned CLIs.
- Clock assumption: leases are minutes long and use the workers' clocks; workers must be
  NTP-synced (they share one host in this deployment).

## Resource sessions (host helper)

A privileged host-side helper may stop an admin-approved set of containers of the *existing*
rootful daemon. It is a separate trust zone with five fixed operations, a root-owned policy
and an independent watchdog; the application reaches it only through one Unix socket that
only the session controller holds. The socket is created by systemd socket activation in a
stable root-owned directory; the broker neither chowns nor chmods. Administrative recovery
(`hunter.rsm admin`) is uid-0 only and not reachable over the socket. See
`docs/resource-sessions.md`.

## Evidence

See `docs/acceptance-checklist.md` for what was executed locally versus what exists only as CI.
