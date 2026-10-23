# Fortik — Agent Kill Switch MVP

Fortik is an **authority broker for autonomous agents**. Before a risky action touches the business, Fortik gives it:

- a policy decision,
- a containment level,
- an undo plan, and
- (from Phase 2) a short-lived credential.

Each agent call becomes a normalized **Action** and is classified **green, yellow or red** by deterministic OPA/Rego rules. Fortik then enforces that decision at the interception point and writes it to a hash-chained **Agent Diary**.

> **Status: Phase 5 of 6 implemented, awaiting developer review.** Phase 5 (swarms and the communication map) adds:
> - swarm detection (Max-5 breaker, spawn tree, copy surge, converging targets), one-click **kill-swarm** in 7 steps, and two-approver release;
> - the **communication map**: 5-minute edges, team / agent / swarm / external / blast-radius views, path trace, time replay, hidden-signal rules, live updates;
> - **shadow-agent discovery** (Postgres, GitHub, AWS, Google Workspace, unknown callers): discovered agents start ISOLATED with no owner;
> - 14-day **baselines** (above-normal volume turns green into yellow) and the full **approval queue**.
>
> See [docs/PHASE5_DESIGN.md](docs/PHASE5_DESIGN.md) and `scripts/demo-phase5.sh` (plan scenarios 1, 3 and 7).
>
> **Phase 4 (containment):**
> - suspend / resume, isolate, kill, team suspend and a single-tenant **Fleet E-Stop**, each with honest per-step results;
> - memory protection: a memory gateway, staged writes undoable for 10 minutes, memory cut, snapshots and roll-back (plan scenario 5);
> - pause / resume / cancel of queued work (Temporal, Celery on Redis, signed webhook);
> - retention and purge of undo snapshots, trash tables and memory snapshots; an Undo list that says what can still be undone;
> - the console **Command Center**, containment controls, Teams and Undo pages.
>
> See [docs/PHASE4_DESIGN.md](docs/PHASE4_DESIGN.md) and `scripts/demo-phase4.sh`.
>
> **Phase 3:**
> - the Claude Code hook (fails closed);
> - the agentgateway callout (MCP / A2A / HTTP);
> - timed app suspensions and approvals;
> - the manager's three use cases: delegation-bypass blocking, multi-level chain enforcement, spawning control with rate limits.
>
> See [docs/PHASE3_DESIGN.md](docs/PHASE3_DESIGN.md) and `scripts/demo-phase3.sh`.
>
> **Phase 2 (Broker and apps):** See [docs/ROADMAP.md](docs/ROADMAP.md) and [docs/PHASE2_DESIGN.md](docs/PHASE2_DESIGN.md).
>
> Phase 2 adds:
> - the authority broker, with AWS STS per-action credentials, GitHub App tokens and per-agent Postgres roles;
> - the agent gateway for Gmail, Drive and GitHub;
> - access profiles;
> - an encrypted secret store (or Vault);
> - the console (login, Agents, Integrations);
> - the level and agent-token APIs, and live events.
>
> Real Google, GitHub and AWS accounts are entered in the console under **Integrations**. Until then those systems fail closed.
> Not built yet: pilot hardening (Phase 6).

## Quick start (local, no Docker needed)

> **New here? Read [GETTING_STARTED.md](GETTING_STARTED.md).** It covers installing the prerequisites and running and understanding every phase, step by step.

Prerequisites: Go ≥ 1.23, Postgres ≥ 16 binaries (`initdb`, `pg_ctl`, `psql`), `opa` (for policy tests), `openssl`, `curl`, `python3`.

```bash
./scripts/dev-up.sh                                   # private Postgres on :55432, schema, seed data, dev secrets, demo agents
bin/fortik serve -config configs/fortik.dev.yaml      # API + console on :8080, agent gateway on :8090, Postgres proxy on :6432
./scripts/demo-phase1-accident.sh                     # in another terminal: end-to-end accident-containment demo
./scripts/demo-phase2.sh                              # broker, access profiles, console API, level API, live events
./scripts/demo-phase3.sh                              # Claude Code hook, approvals, suspensions, UC1/UC2/UC3
./scripts/demo-phase4.sh                              # memory staging + scenario 5, suspend/isolate/kill, team, E-Stop
./scripts/demo-phase5.sh                              # kill-swarm (41 agents), attack, shadow agent, map, approval queue
open http://127.0.0.1:8080                            # console (dev login: security@acme.com / admin@acme.com / pranav.kumar@acme.com)
make ci                                               # vet + opa fmt/test + go test -race (needs the dev cluster)
```

Agents connect to Postgres **through the proxy**: user = `agent_id`, password = the agent's Fortik token, database = an upstream alias from the config (`acme_prod`, `acme_staging`). Optionally set `application_name=fortik:<instance_id>`.

```bash
source .dev/tokens.env
PGPASSWORD=$FORTIK_AGENT_TOKEN_CLAUDE_CODE_01 psql -h 127.0.0.1 -p 6432 -U claude_code_01 -d acme_prod -c 'DROP TABLE orders'
# ERROR:  fortik: hold (red) by POL-101: irreversible DROP_TABLE on prod database (public.orders)
# DETAIL: action_id=act_01K...
# HINT:   A security approver can approve the safe form: ALTER TABLE public.orders RENAME TO fortik_trash_orders_...
```

## Layout

| Path | What it is |
|---|---|
| `cmd/fortik` | Single binary: `serve`, `migrate`, `agent`, `diary`, `token`, `keygen` |
| `internal/action` | Normalized Action model (10 verbs), validation, action hash |
| `internal/policy` | Embedded OPA engine: prepared query, hot reload, bundle versioning |
| `internal/decide` | Decide service: control state → policy → atomic persistence (action, hold, step-down, Diary); fail-closed |
| `internal/control` | Control ladder (FULL…KILLED) and control-state store |
| `internal/diary` | Append-only, hash-chained Agent Diary; verification; signed roots; export |
| `internal/pgproxy`, `internal/pgsql` | Postgres wire-protocol proxy and SQL classifier ([README](internal/pgproxy/README.md)) |
| `internal/undo`, `internal/undo/pgundo` | Undo handles (prepared before execution) and the Postgres undo executor |
| `internal/api` | Internal HTTP API (`/v1/...`) with token auth and roles |
| `policies/` | Rego bundle (`fortik.decide`), starter rules, OPA unit tests |
| `migrations/` | Versioned SQL migrations (embedded) |
| `configs/` | Dev config (no secrets) |
| `scripts/` | Dev environment and demo scripts |
| `spikes/agentgateway` | Phase 1 agentgateway go/no-go spike ([report](docs/spikes/agentgateway-spike.md)) |

## Docs

- [ROADMAP](docs/ROADMAP.md) — six phases, deviations from the plan figure, open questions
- [ARCHITECTURE](ARCHITECTURE.md) — components, request path, data model
- [SECURITY](SECURITY.md) — threat model, fail-closed behaviour, secrets, known gaps
- [DEVELOPMENT](DEVELOPMENT.md) — environment, tests, conventions
- [API](docs/API.md) — endpoints and roles
- [POLICIES](docs/POLICIES.md) — the rule catalogue and the adapter contract
