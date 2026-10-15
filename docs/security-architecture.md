# Security architecture (Milestone 1 hardening, round 2)

## Trust zones

```
                      ┌──────────── trusted ─────────────────────────────┐
 Telegram ──egress──▶ telegram ─┐                                         │
 Tailscale ─127.0.0.1▶ api ─────┼──▶ redis (internal net, password)       │
                      scheduler ┘        ▲                               │
                                         │ JSON jobs only, allowlisted   │
 ATS boards ◀─egress── discovery (RQ worker + orchestrator) ──▶ postgres │
                      └───────┬──────────┬───────────┬───────────────────┘
                   HTTP+token │          │           │   (one private network per agent)
                      ┌───────▼──┐ ┌─────▼────┐ ┌────▼─────┐
                      │ claude-1 │ │ claude-2 │ │  codex   │   untrusted runtime
                      │ runner   │ │ runner   │ │ runner   │   no Redis / DB / admin secrets
                      └──────────┘ └──────────┘ └──────────┘   own credential volume only
```

## Rules

1. **Agents never touch Redis or PostgreSQL.** Each agent container runs
   `hunter.agent_runner`, a tiny HTTP service. The orchestrator *calls* it
   (`POST /plan`, bearer token, JSON body) and treats the reply as hostile data.
2. **No pickle anywhere.** Every `Queue`/`Worker`/`Job` is built in `hunter/queueing.py` with
   `JSONSerializer`; the discovery worker uses `HardenedJob`.
3. **Consumer-side allowlist.** `HardenedJob` refuses anything that is not exactly
   `hunter.orchestrator.run_scan(<positive int>)`: no other function, no kwargs, no callbacks,
   no bound instance. A forged Redis entry cannot name `subprocess.run`.
4. **Strict schemas both ways** (`hunter/schemas.py`): requests to agents contain only a fixed
   set of profile fields with pattern/length limits; replies are `extra="forbid"`, ≤15 queries
   of ≤160 printable chars, ≤32 KiB, and must carry the identity of the agent that was called.
   Only the exception *class* of a failure is stored; CLI stdout/stderr never reaches the DB.
5. **Network separation.** `data` and `queue` are `internal` networks. Each agent has its own
   private network shared only with the orchestrator, so agents cannot see each other, the
   API, Redis or PostgreSQL (verified live, see below).
6. **Least privilege containers.** Non-root, read-only root fs, `cap_drop: ALL`,
   `no-new-privileges`, memory/CPU/pid limits. Redis runs as uid 999.
7. **Submission is disabled in code** (`SUBMISSION_ENABLED = False`) and no code path sends
   applications or e-mail.

## What an agent compromise can and cannot do

| Can | Cannot |
|---|---|
| Return bad data (rejected by schema → run marked failed) | Read or write Redis, PostgreSQL |
| Use its **own** provider login and the internet | Reach the other agents' volumes or runners |
| Read its own `AGENT_TOKEN` (via `/proc`) | Reach the API, admin routes, Telegram token |
| Consume its CPU/memory share until limits | Inject jobs, or execute code in the worker |

`AGENT_TOKEN` only authenticates *inbound* calls to that same runner, so its disclosure to the
CLI subprocess is not an escalation. The CLI subprocess still receives a minimal allow-listed
environment (`agents.cli_env`).

## Threats considered and residual risk

- **Compromise of a trusted component** (api, telegram, scheduler, discovery) gives Redis and,
  for most of them, the database. These run first-party code only; they still share Redis
  and its single password. Per-component Redis ACL users are future work.
- **Agent egress is open** (the CLIs need their provider APIs). A hostile agent could
  exfiltrate what it is given (search profiles) or abuse its own account. Egress filtering by
  hostname is future work.
- **Docker socket / root on the host** is out of scope of the application; see
  `docs/deployment.md` for the rootless-Docker requirement.
- **Postgres has `cap_add` for its entrypoint** (CHOWN/SETUID/SETGID/DAC_OVERRIDE/FOWNER).
- Sandbox flags of the Claude/Codex CLIs are unverified against the pinned versions.

## Evidence

| Claim | Local (real Docker daemon) | CI |
|---|---|---|
| Pickle/forged-function jobs never execute | `tests/test_queue_security.py` (control + hardened pairs), live injection via `deploy/smoke-test.sh` | same, on every PR |
| Agents cannot reach Redis/Postgres/peers | `deploy/smoke-test.sh` (live sockets), `tests/test_compose_invariants.py` | `docker` job |
| Redis starts unprivileged with real volume | stack started, uid 999, `PONG` healthcheck | `docker` job |
