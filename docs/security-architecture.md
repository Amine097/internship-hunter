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
 provider APIs ◀─CONNECT egress-* proxy (per agent, hostname allow-list, :443 only)
                       │ agent   │ │ agent   │ │ agent   │   untrusted runtime:
                       └─────────┘ └─────────┘ └─────────┘   no DB, no admin/Telegram secrets
```

## Rules

1. **Agents never touch the database.** Each agent container runs `hunter.agent_runner`
   (HTTP planner, bearer token, JSON). The orchestrator *calls* it and treats the reply as
   hostile data: strict schemas (`hunter/schemas.py`), ≤15 queries of ≤160 printable chars,
   ≤32 KiB, identity must match the agent called, only the exception class is stored.
2. **Egress is enforced by topology, not by proxy variables.** Agent networks are `internal`
   (no gateway): the only reachable address besides the orchestrator is the agent's own
   egress proxy. `HTTPS_PROXY` is merely how the CLI finds it; ignoring it yields "network
   unreachable", not a bypass. The proxy (tinyproxy, non-root) is **CONNECT-only**: filtering
   matches the request target, and the allow patterns are `^<host>:443$`, so plain-HTTP
   forwarding (even to an allowed host), other ports, IP literals, look-alike domains and
   other providers' hosts are all refused (checked in `deploy/smoke-test.sh`). The lists are policy, kept in `compose.yaml`/`.env`.
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
| Use its **own** provider login via its proxy | Reach LAN, tailnet, host, metadata service, other agents |
| Read its own `AGENT_TOKEN` (via `/proc`) | Reach the API, admin routes, Telegram token |
| Consume its CPU/memory share until limits | Reach another provider's API through its proxy |

## Residual risks

- **Compromise of a trusted component** (api, telegram, scheduler, discovery) gives database
  access; they run first-party code only and share one database role. Per-component roles
  are future work.
- **Provider hostname lists are unverified** against the pinned CLI versions; if a CLI needs
  another host the run fails closed (visible in the proxy log), it does not widen silently.
- **A provider-owned allowed hostname is trusted**: exfiltration *to the provider* with the
  agent's own account remains possible. Rootless Docker (required for the deploy user) puts
  the proxy's outbound traffic through slirp4netns/pasta; the proxy itself refuses IP
  literals so tailnet/LAN addresses are not reachable by name or number.
- `postgres` keeps five capabilities its entrypoint needs. Provider/CLI sandbox flags are
  unverified against the pinned CLIs.
- Clock assumption: leases are minutes long and use the workers' clocks; workers must be
  NTP-synced (they share one host in this deployment).

## Evidence

See `docs/acceptance-checklist.md` for what was executed locally versus what exists only as CI.
