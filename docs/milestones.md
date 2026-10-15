# Milestones and strict boundaries

## M1 — Bootstrap (this delivery)
- Private GitHub-ready repo, CI checks.
- Backend, read-only endpoints, scheduler, RQ queues, isolated agents.
- Search profiles, ATS public discovery with explicit allowlist.
- Telegram /profiles /status /scan, PostgreSQL persistence.
- CLI agent adapters available but default to deterministic demo mode.
- Never pretend demo results are real offers or model outputs.

## M2 — Production search
- Confirm CLI entitlement and subscription billing for each account.
- Agent-independent queries execute against permitted discovery sources.
- Full job metadata and historical observations, cross-source dedup.
- Country/visa checks; job fit scoring with uncertainty-aware policy.
- Approval/documentation of verified facts from CV / GitHub.
- Dashboard accessible only over Tailscale.

## M3 — Candidate preparation
- Resume templates (SWE, systems, DevOps, networking), factual verification.
- Long answers routed to Telegram approvals, with content/version binding.
- Reviewed permissions and rate limits for each ATS.

## M4 — Controlled applications
- Browser automation only where permitted; never bypass CAPTCHAs.
- One submitted application per canonical offer, evidence of submission.
- Submit idempotency, network failure recovery, secret isolation.
- Shadow-mode tests with fixtures first; manual roll-out by source.
- Consent and legally relevant questions require verified information.

## M5 — Deployment
- GitHub Actions CI + manual Tailscale deploy (designed in M1 hardening; see docs/deployment.md).
- Migrations with Alembic, backups/restores, alerts, dependency pinning.
- Read-only Gmail integration for reply classification only with authorization.
