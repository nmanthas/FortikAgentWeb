# Fortik MVP: six-phase roadmap

Source of truth: *Fortik Agent Kill Switch — MVP Technical Implementation Plan* (Oct 6 2026).
The plan already fixes the phase boundaries, in its "Six phases, three gates" figure. This roadmap keeps
those boundaries and only adds the task detail the plan leaves to the team. Every change from the
figure is listed under **Deviations**, with the reason.

| Phase | Plan's title | Gate |
|---|---|---|
| 1 | Foundations | demoable: decide + diary + pg proxy; agentgateway go/no-go |
| 2 | Broker and apps | demoable: Agents screen on live data |
| 3 | Coding agents | **Gate: accident demo end to end** |
| 4 | Containment | demoable: Command Center live |
| 5 | Swarms and map | **Gate: attack + kill-swarm demos** |
| 6 | Pilot-ready | **Gate: 3 design partners in observe mode** |

## Deviations from the plan figure (each needs developer sign-off)

1. **Two Postgres undo kinds land in Phase 1, not Phase 4.** These are "copy rows before risky writes" (undo #3) and "DROP → rename" (undo #4). The plan's proxy row says the Postgres proxy itself "copies rows before risky writes, rewrites DROP to a rename". Fortik must also never claim an undo it hasn't tested, so the Postgres undo executor ships with them. Phase 4 adds the other four undo kinds.
2. **Minimal ladder enforcement lands in Phase 1.** Decide "reads control state (level…)" and red actions "step the agent down", so the policy enforces the six levels and red actions step down automatically. The *authorised level API* (`PUT /v1/agents/{id}/level`, one-level step-up, roles) stays in Phase 2. Until then levels change only through the audited `fortik agent set-level` CLI.
3. **Approve/deny of held actions moves from Phase 5 to Phase 3.** The Phase 3 accident gate needs "owner approves or denies from the console", but the figure puts the approval queue in Phase 5. Phase 3 ships approve/deny and the safe-form execution. Phase 5 adds the full queue (two-approver release, expiry sweeps).
4. **Redis and NATS are deferred to the phases that first need them.** Phase 1 reads control levels from Postgres by primary key. Measured overhead: Decide p95 1.4 ms, and 6.9 ms with 8 concurrent workers. A write-through Redis cache that can go stale would risk *widening* authority, so Redis arrives with copy-cap heartbeats (Phase 4) and baselines (Phase 5). NATS arrives with console live updates (Phase 2) and the timed-suspension restore worker (Phase 3).
5. **The master prompt's suggested phase 1** included the Claude Code hook. The plan places the hook in Phase 3, and this roadmap follows the plan. The hook is small, so it can be pulled forward if the developer wants it.

6. **Manager feedback (Oct 2026) pulled three use cases into Phase 3** ([PHASE3_DESIGN.md](PHASE3_DESIGN.md)):
   - Agent-to-agent policy bypass, plus multi-level delegation chains with transitive enforcement. These come from Phase 5's "A2A + delegation chain".
   - Spawning anomalies and rate limiting. This comes from Phase 4's "copy registration + caps" and Phase 5's baselines.

   Phase 4 keeps suspend/isolate/memory/kill and the Command Center. Phase 5 keeps swarm detection, kill-swarm, the communication map and shadow agents.

7. **Phase 4 deviations** ([PHASE4_DESIGN.md](PHASE4_DESIGN.md)):
   - The Drive, Gmail and GitHub undo kinds already shipped with the Phase 2 gateways; Phase 4 adds memory staging (undo #6) and the Undo list's `undoable` / `why_not`.
   - Memory rules are **POL-901–904**, not POL-80x: the MCP rules (Phase 3) already use POL-801–804.
   - The decide aggregation now reports the yellow finding that **demands the hold** before the lowest rule id. This changes one Phase 2 report: a 48-recipient external email is now reported as POL-203 (bulk, approval required) instead of POL-202 (delayed send). The decision itself (hold) is unchanged.
   - Copy registration and caps were delivered in Phase 3 (deviation 6); Phase 4 adds suspended copies (heartbeat 423) and stopped copies on kill (410). Copy heartbeats stay in Postgres; Redis is used for counters only when configured.
   - Fleet E-Stop is single-tenant, as planned; multi-tenant fleet stop is out of scope.
   - Snapshot encryption: snapshots stay in the customer's database and rely on its at-rest encryption (documented in SECURITY.md).

8. **Phase 5 deviations** ([PHASE5_DESIGN.md](PHASE5_DESIGN.md)):
   - Live map updates use the existing authenticated **SSE** stream, not WebSocket. The map only needs server-to-client push, and the SSE stream already re-checks the viewer's session on every event.
   - A call held by the swarm breaker is **yellow with two approvers required**, not red. In this codebase red holds can only be released through a safe form, and the plan requires that "releasing any held call asks for two approvers". The swarm itself is still shown red on the map.
   - Rule ids: swarm POL-651–659, baselines POL-660–669, hidden signals POL-670–679, shadow agents POL-680–689.
   - **Attack scenario step 1** ("read flagged yellow"): a new rule, POL-113, holds a bulk read of sensitive data (estimated by a plain EXPLAIN on labelled tables) for approval. "Require approval" is one of the plan's yellow handlings. Earlier phases estimated rows only for writes.
   - **Kill-swarm demo:** the live demo drives delegations and sends through the decide API, as agentgateway and the app gateway do. The "0 emails delivered" check (delayed sends cancelled) is proven by the automated test `TestKillSwarmFullScale`, because real Gmail delivery needs the Workspace test account.
   - **Two-person rule and API tokens:** two API tokens no longer count as two people. A second token vote on a two-approver hold or a swarm release is refused unless `approvals.allow_token_pairs` is on. That setting is on only in the dev config, so the demo can play both approvers with the security and admin tokens.
   - **Breaker identity:** a Gmail SEND is "the same call" when it goes to the same recipients (sorted, lower-cased, without +tags, in any of To, Cc or Bcc, whether sent directly or from a draft). Postgres row writes (INSERT, UPDATE, DELETE, MERGE, COPY FROM) do not count toward the Max-5 breaker, because the proxy identifies them by statement shape without their values.

## Phase 1 · Foundations (this phase)

- **Goal:** the smallest secure core that every later phase plugs into, plus a demoable accident-*containment* path through a real interception point.
- **Scope:**
  - Normalized Action model with the 10 verbs.
  - Decide service: OPA embedded in Go, Rego bundle with 15+ starter rules across Postgres, Gmail/Drive, GitHub and AWS, plus control-ladder gating, hot reload and versioning.
  - Fail-closed contract, with a configurable green-read allowlist.
  - Postgres-backed control state: level reads and conditional automatic step-down.
  - Agent Diary: append-only, hash-chained, signed roots, verify and export.
  - Postgres wire-protocol proxy: pgproto3 and pg_query, simple and extended protocols, row snapshots before risky writes, rename safe form offered on DROP/TRUNCATE.
  - Postgres undo executor.
  - Internal API subset with token auth and roles.
  - Migrations, dev environment, demo script.
  - agentgateway spike: go/no-go.
- **Dependencies:** none.
- **APIs:**
  - `POST /v1/actions/decide`
  - `GET /v1/actions`, `GET /v1/actions/{id}` (explanations)
  - `GET /v1/held`, `GET /v1/agents`, `GET /v1/policy`
  - `GET /v1/diary`, `GET /v1/diary/verify`, `GET /v1/diary/export`
  - `GET /v1/undo`, `POST /v1/undo/{action_id}` (Postgres kinds)
  - `/healthz`, `/readyz`, `/metrics`
- **Database:** `agents`, `actions`, `held_actions`, `undo_handles`, `diary`, `diary_head`, `diary_roots`, plus append-only triggers.
- **Policies:**
  - System rules: POL-001…009, POL-101…112, POL-201…203, POL-211/212, POL-301…304, POL-401…404.
  - Control-ladder rules: POL-010…015.
- **Tests:**
  - OPA unit tests for every rule.
  - Go unit and integration tests against real Postgres: decide, diary, undo, API, proxy, classifier, pgundo.
  - Fail-closed tests.
  - Latency measurement.
- **Manual validation:** `scripts/demo-phase1-accident.sh`.
- **Exit criteria:** all of the above green. DROP TABLE on prod through the proxy is held, never executes, offers the rename form and steps the agent to READ_ONLY. A non-narrow staging DELETE is snapshotted, runs, and can be undone. The Diary verifies. The spike report gives a recommendation.

## Phase 2 · Broker and apps

- **Goal:** Fortik owns the credential path. An agent cannot act on Workspace, GitHub, AWS or Postgres without a Fortik-issued, short-lived, narrow credential.
- **Scope:**
  - **Authority broker v1:** `POST /v1/credentials/issue`, which checks level and access profile on every request.
  - **Secret provider:** Vault/KMS, with no secrets in Postgres.
  - **Google Workspace:** the Fortik app gateway, using a service account with domain-wide delegation. The token never leaves the gateway. It enforces recipient, share and volume rules and produces Gmail/Drive Actions.
  - **GitHub:** a GitHub App installation token scoped to listed repos and permissions, with `DELETE /installation/token` for revocation.
  - **AWS:** STS AssumeRole with a per-action-class session policy for 15 minutes, revoked by attaching a `TokenIssueTime` deny.
  - **Postgres:** per-agent roles with per-session rotated credentials replace the Phase 1 static upstream user and agent bootstrap tokens.
  - **Access profiles:** per agent per system, versioned and passed to OPA. `PUT /v1/agents/{id}/access/{system}`.
  - **Full control ladder:** `PUT /v1/agents/{id}/level`. Step-up is one level at a time with a reason and a security role. Kill is manual and security-only. Three held yellows within 10 minutes move the agent to Supervised.
  - **Identity and events:** OIDC login with RBAC. NATS for events.
  - **Console:** the React/TypeScript **Agents** screen, wired to live data.
- **Dependencies:** Phase 1. Sandbox accounts are **blocked on the developer**: a Workspace test domain, a GitHub test org/App, an AWS sandbox account with a role, and a Vault (dev) instance.
- **Database:** `access_profiles`. A credential-issuance log feeding the Diary.
- **Tests:** adapter contract tests against the real sandboxes, broker scope-generation unit tests, revocation tests, and authz tests per role.
- **Exit criteria:** credentials are issued and revoked on all four systems against the sandboxes. A level change affects the next credential in under 1 s. The Agents screen shows real agents, levels and recent actions.

## Phase 3 · Coding agents (gate: accident demo end to end)

- **Goal:** the full accident scenario with Claude Code.
- **Scope:**
  - **Claude Code hook:** a PreToolUse *local command* hook that fails closed (exit 2 when Fortik is unreachable), pushed through managed settings.
  - **MCP through agentgateway**, per the spike's conditions (or the Envoy `ext_proc` fallback):
    - mcpGuardrails for MCP routes, extAuthz for A2A/HTTP.
    - Explicit fail-closed with a 100–250 ms timeout.
    - Agent and instance headers bound to authenticated identity and client-supplied ones stripped.
    - Pinned version.
  - **Timed app suspensions:**
    - `access_overrides` table and `POST /v1/overrides`, plus `release`, `extend` and `GET`.
    - Restore worker: a NATS delayed message, with a database sweep as backup.
    - Safety checks before restore.
    - Timer chip in the console.
  - **Approvals (pulled forward):**
    - `POST /v1/held/{id}/approve|deny`.
    - When a DROP is approved, its rename safe form runs.
    - Minimal console approve/deny.
- **Tests:**
  - Hook fail-closed tests: Fortik down, timeout, non-2xx.
  - Override and restore tests, including the restore safety checks.
  - Accident acceptance test (scenario 2).
  - Timed-suspension acceptance test (scenario 4), which needs the Phase 2 adapters.
- **Exit criteria:** the accident scenario passes end to end:
  - The staging migration is snapshotted.
  - DROP on prod is held, the safe form is offered, the agent goes to Read-only, and the owner approves or denies in the console.
  - The staging delete is undone from the Undo list.

## Phase 4 · Containment (implemented, awaiting developer review)

- **Scope:**
  - **The remaining four undo kinds:** Drive permission delete, Gmail 2-minute delayed send with cancel, GitHub ref restore and PR reopen, and memory staging namespace with 10-minute promotion and snapshot restore. Plus the Undo list in the console.
  - **Agent controls:** suspend/resume (pause queued jobs, tell copies to pause), isolate, `memory/remove` and `memory/restore`.
  - **Kill (level 5):** per-system revocation, queue cancel, `pg_terminate_backend` on the agent's sessions (using the `fortik:<agent>:<instance>` application_name tag the Phase 1 proxy already sets), and stopping copies.
  - **Copies:** `instances` registration and 15 s heartbeats in Redis, copy caps, "Pause extra", and new-host flags.
  - **Snapshots:** retention and purge jobs (30 days for snapshots, 7 days for trash), plus encryption.
  - **Console:** the **Command Center**, live.
- **Tests:** memory-cut (scenario 5), runaway-copies (scenario 6) and kill tests, plus per-kind undo contract tests.

## Phase 5 · Swarms and map (gate: attack + kill-swarm demos) (implemented, awaiting developer review)

- **Scope:**
  - **A2A and delegation:** the delegation chain, and DELEGATE actions through agentgateway.
  - **Swarm detection:** action-hash breaker (Max-5), spawn-tree fan-out and depth limits, copy surge, and converging targets.
  - **Swarm actions:** a `swarms` object. Kill-swarm runs the 7 ordered steps. Release needs two approvers.
  - **Communication map:**
    - `edges` rolled up per 5 minutes.
    - Views by team, agent, swarm, external exposure and blast radius.
    - Path trace, time replay, and hidden-signal rules.
    - Live updates over WebSocket from NATS.
  - **Shadow-agent discovery:** standing credentials per system, and unknown hosts or OAuth clients. A discovered agent starts Isolated.
  - **Baselines:** 14-day hourly counts in Redis, mean + 3σ or 5× median.
  - **Approval queue:** the full queue.
- **Tests:** attack (scenario 1), kill-swarm (scenario 3) and shadow agent (scenario 7).

## Phase 6 · Pilot-ready (gate: 3 partners in observe mode)

- **Scope:**
  - **SaaS copilot connector broker:** Fortik-issued OAuth clients and vendor audit-log pulls.
  - **Observe mode:** decide and record, but don't enforce.
  - **Test suites:** a 10,000-action replay suite that blocks a merge on any class change, chaos tests (kill Redis, NATS or the gateway mid-demo), and a k6 load test at 200 actions/s with p95 under 50 ms.
  - **Hardening:** mTLS between components, Docker Compose and Helm packaging, a security review, and the deployment guide with least-privilege service accounts.
- **Exit criteria:** the plan's "Done means" and its success metrics.

## Open questions from the plan (unresolved; no irreversible decision taken)

- Which three design partners are we piloting with, and which two of the four systems matter most to each?
- Deploy model for pilots: customer VPC only, or also a Fortik-hosted single-tenant option?
- Is a 2-minute delay for yellow Gmail sends acceptable to partners?
- Approvals: build our own console UI only, or also push approvals to Slack in the MVP?
- Who owns the policy library long term: product, or each customer's security team?
