# Phase 4 design: containment

**Plan scope** ("Phase 4 · Containment"):
- Undo handles for all 6 action types.
- Suspend, isolate and memory cut.
- Copy registration and caps (done in Phase 3).
- Console: Command Center, live.

Also included, from the plan's containment table and roadmap:
- Kill (level 5).
- Cancel queued work in Temporal/Celery.
- Snapshot retention and purge.
- A single-tenant **Fleet E-Stop**. Multi-tenant fleet stop stays out of scope.

**Scenarios:**
- Plan scenario 5 (memory cut).
- Kill tests, and suspend/resume end to end.
- Per-kind undo contract tests (memory staging).

Already contracted (in the repo):
- Migration `0006_phase4.sql`.
- `control.State.Suspended` and `control.Store.SetSuspendedTx`, with Diary events `agent.suspended` and `agent.resumed`.
- Policy gate **POL-016**: a suspended agent is refused everything. KILLED takes precedence.
- Contract types in `internal/{containment,queues,memory}/types.go`.
- Config sections `memory` and `retention`.

## 1. Containment operations (`internal/containment`)

Every operation:
- runs ordered **steps**;
- records each step's honest result in `containment_ops.steps`;
- is **idempotent** (suspending a suspended agent is a no-op step);
- writes a Diary event `containment.<op>` with the actor, target, reason and steps.

Steps run in parallel across target members where it is safe.

| Op | Targets | Steps (in order) |
|---|---|---|
| `suspend` | instance, agent, team | Mark suspended (`SetSuspendedTx`; instance → status `suspended`) → revoke live credentials (`broker.RevokeAll`, per-system honest semantics) → pause queued jobs (all configured queue adapters, **paused, not cancelled**) → tell running copies to pause (instances → `suspended`; heartbeat returns `423` with `{"action":"pause"}`). Memory and state are kept. |
| `resume` | instance, agent, team | Clear the suspension → resume queues → instances `suspended` → `live` (they continue heartbeating). Credentials are issued again on request. |
| `isolate` | agent, team | Set level ISOLATED (step-down through the ladder; never loosens) → revoke live credentials → pause copies over the cap (pause-extra). Lifted by step-up (owner or security). |
| `memory_remove` | agent, team | Memory access → `none`, or `staging_only` (keep reads, writes staged and not promoted) → revoke vector-store credentials → existing memory frozen, not deleted. |
| `memory_restore` | agent, team | Optionally roll back to a clean snapshot first (`rollback_snapshot_id`) → access → `full`. |
| `cancel_queue` | agent | Cancel queued jobs, retries and schedules. **Not reversible**; jobs must be resubmitted. |
| `kill` | agent, team | Level KILLED → revoke everything → cancel queued jobs → terminate DB sessions (pgroles) → stop all copies (instances `stopped`; heartbeat 410) → memory access `none` → seal (`containment.kill` Diary event with every step). Re-enable is manual, security only. |
| `estop` | fleet | Single tenant: suspend **every** registered agent. Needs `security` plus `"confirm":"STOP ALL AGENTS"`. Records the op id so `estop_release` resumes only the agents the e-stop suspended. |

**Roles:**

| Op | Who may run it |
|---|---|
| `kill`, team ops, `estop`, `estop_release`, `cancel_queue` | `security` |
| `suspend`, `resume`, `isolate`, `memory_remove`, `memory_restore` on one agent | `security`, or that agent's owner. An owner may lift (resume, memory_restore) only a containment they imposed themselves; one imposed by security, an E-Stop, the level API or a kill needs `security`. A `rollback_snapshot_id` always needs `security`. |
| `resume` after a kill | refused (re-enable is the level API, security only) |

**Review hardening:**
- Operations on one agent are serialised by a per-agent Postgres advisory lock (team and fleet ops take each agent's lock around that agent's steps; the level API takes it too). A lock not obtained within 5 minutes → `409` and nothing recorded.
- A retried suspend repeats revocation unless an earlier op actually revoked for the current suspension.
- Resume and E-Stop release only undo what that suspension paused: copies suspended individually stay suspended, and a QUARANTINED or higher agent's queues and copies are not resumed.
- Suspended copies keep their `copy_cap` slot (POL-701/702 count live or suspended copies), so a suspended copy cannot be replaced by registering a new one.
- Owners' containment history shows only their own agents' steps.
- The level API keeps its deadline; database-only steps still complete and the op is always recorded.
- Reasons may contain newlines and tabs, up to 1000 bytes.

**Level API integration:** `PUT /v1/agents/{id}/level` to QUARANTINED or KILLED already calls `Revoker.RevokeAll`. The containment service implements that interface, so a level change to QUARANTINED runs the suspend-style steps without un-suspending, and KILLED runs the full kill steps. That way the console's level buttons and the containment buttons behave the same.

**API** (API listener, all with a reason):
- `POST /v1/containment` with a `containment.Request`.
- Convenience routes:
  - `POST /v1/agents/{id}/suspend`, `/resume`, `/isolate`, `/kill`
  - `POST /v1/agents/{id}/memory/remove`, `/memory/restore`, `/queue/cancel`
  - `POST /v1/instances/{id}/suspend`, `/resume`
  - `POST /v1/teams/{team}/suspend`, `/resume`, `/kill`
  - `POST /v1/fleet/estop`, `/release`
- `GET /v1/containment?target_type=&target_id=&limit=` returns the history with steps.

## 2. Queue control (`internal/queues`)

`queues.Adapter` has Pause, Resume and Cancel per agent. Work is attributed to an agent by a tag the customer's producers set.

| Adapter | Integration key | How |
|---|---|---|
| Temporal | `temporal` (`host_port`, `namespace`, optional TLS/API key secret) | Workflows tagged with search attribute `FortikAgentId`. Pause → signal `fortik-pause` plus a Fortik-side memo (workers using the Fortik SDK helper check it); running workflows can't be frozen generically, so the detail says so honestly. Resume → signal `fortik-resume`. Cancel → `RequestCancelWorkflowExecution` on every open workflow for the agent, plus deletion of schedules tagged with the agent. |
| Celery (Redis broker) | `celery` (`redis_url` secret, `queues`) | Messages carry header `fortik_agent_id`. Pause → atomically move the agent's messages from the queue lists to `fortik:held:<agent>:<queue>` (Lua). Resume → move them back. Cancel → delete held and queued messages, and broadcast `revoke` for their task ids through the pidbox so running workers drop them. |
| Webhook | `queue_webhook` (`url`, HMAC `secret`) | POST `{action: pause\|resume\|cancel, agent_id, reason, ts}`, signed with HMAC-SHA256 (`X-Fortik-Signature`). 2xx = done; anything else is a failed step. |

Each adapter is also an `integrations.Tester`. The schemas for the three keys are added to the Integrations screen.

Honesty rules (after review):
- Celery held lists are keyed `fortik:held:<agent>/<queue>` (agent ids never contain `/`), and resume/cancel only touch entries owned by that agent.
- A Celery pause is one-shot: messages enqueued afterwards are not held by that step (the detail says so). `queues.HoldWorker` re-holds new messages every 10 s for agents that stay suspended or are QUARANTINED or KILLED.
- Temporal workflows are signalled and cancelled per workflow chain (continue-as-new safe). Hitting the workflow or schedule cap (`queues.ErrTruncated`) is a failed step, not done.
- A configured queue integration whose secret is missing from the secret store (`ErrSecretMissing`) is a failed step; only a missing integration is "not configured: skipped". Postgres revocation likewise reports such an upstream as NOT revoked.
- A suspended agent's delayed Gmail sends stay pending (not sent, still undoable) until it is resumed.

## 3. Memory protection (`internal/memory`)

- **Store** (the customer's): an integration `memory:<name>` (Postgres connection with pgvector; admin credentials as a secret). Tables live in the customer database, schema `fortik_memory`:
  - `items`: id, namespace, content, embedding `vector`, metadata, agent_id, staged, flagged, promote_at, created_at;
  - `snapshots_<id>` tables;
  - Fortik keeps only pointers (`memory_snapshots`).
- **Gateway** (agent token, on the gateway listener):
  - `POST /gw/memory/{store}/{namespace}/items` (write = REMEMBER)
  - `POST /gw/memory/{store}/{namespace}/query` (READ; optional embedding or text)
  - `DELETE /gw/memory/{store}/{namespace}/items/{id}` (DELETE)

  Every call is decided. MCP memory tools reach the same decisions through agentgateway (system `mcp`). `data.fortik.memory.mcp_servers` lists which MCP servers are memory.
- **Staging (undo #6):**
  - Every write lands **staged** (`promote_at = now + promotion_delay`, 10 m) with an undo handle of kind `memory_staging`.
  - A promotion worker promotes due, unflagged items, unless the writer's access is `staging_only` or `none`.
  - Undo drops the staged item. `POST /v1/memory/items/{id}/flag` stops promotion.
  - Queries by the writing agent may include its own staged items; other agents see promoted items only.
- **Snapshots:**
  - Automatic every `snapshot_every` (clean = taken while no item in the namespace was flagged), or manual `POST /v1/memory/snapshots`.
  - `GET /v1/memory/snapshots?namespace=`.
  - `POST /v1/memory/snapshots/{id}/restore`, as security: the namespace is replaced by the snapshot's contents, and a pre-restore snapshot is taken first so the restore itself can be undone.
- **Access:**
  - `memory_access` per agent (default full).
  - Enricher → `input.context.memory = {access}`.
  - Rego package `fortik.memory`:

    | Rule | Effect |
    |---|---|
    | POL-901 | Access `none` → deny any memory or memory-MCP action (READ included) |
    | POL-902 | Access `staging_only` → deny DELETE on memory (reads and staged writes allowed) |
    | POL-903 | REMEMBER is yellow `allow_reduced {memory_staging: true}`: always staged, always undoable |
    | POL-904 | Memory writes carrying sensitive data labels → hold |

- **Review hardening:**
  - A snapshot is clean only if it holds no flagged and no staged (unreviewed) items; pre-restore copies are never clean. Rollback re-checks the snapshot's data and refuses an unclean one.
  - Items are keyed `(namespace, id)`. Removing an item (staging undo, drop, approved DELETE) records a tombstone; restores skip tombstoned items and say so. Existing stores are migrated on first use.
  - A staging undo is bound to the write's action id.
  - The pre-restore copy, delete and insert run in one customer-store transaction; restored staged items are held for review.
  - Writes made while the writer is not at full access are held; when access returns to full they get a fresh review window instead of being promoted at once (listed in `memory.access_changed`).
  - Removing an item expires its staging undo handle in the same transaction as the Diary event.
- **Scenario 5 test:**
  1. A support agent writes a "poisoned instruction" (staged).
  2. Security removes memory access → reads and writes are denied, and the staged item is not promoted.
  3. Roll back to the last clean snapshot.
  4. Restore access → the agent works again, and the poisoned item is gone.

## 4. Retention (`internal/retention`)

A worker runs every `retention.sweep_interval`, under an advisory lock so only one instance runs across processes. On every `postgres:*` integration, as admin, it:
- drops `fortik_undo.*` snapshot tables whose undo handle has expired (30 d) or that are orphaned and older than 30 d;
- drops `fortik_trash_*` tables older than `undo.trash_retention` (7 d), if their `pg_rename` handle is expired or used;
- purges memory snapshots past `memory.snapshot_retention`;
- marks expired undo handles `expired`.

Each purge writes a Diary event `retention.purged` with what was dropped, never the data.

Encryption: snapshot data stays in the customer's database and bucket, and relies on the customer's at-rest encryption. Fortik stores only pointers. This is documented as the MVP stance, per the plan's "customer's own bucket or database".

## 5. Undo list

`GET /v1/undo` returns per handle:
- `undoable` (bool);
- `why_not` ("already sent: NOT undoable", "expired", "already used", "no undo prepared");
- a human description of what Undo will do.

The console's **Undo** page lists every handle with an Undo button only when it's undoable, and the "NOT UNDOABLE" wording otherwise.

## 6. Console: Command Center (v2 screen) and controls

- **Command Center** (the screenshot's layout):
  - **KPI tiles:** agents discovered, high-risk agents, blocked actions today, pending approvals, active memory quarantines.
  - **Agent Radar:** agents, owner, tools, dangerous verbs, risk.
  - **Live incident / action chain:** the latest red decision and its chain of preceding actions by that agent.
  - **Action Control panel** for the selected agent: Freeze agent (suspend), Quarantine memory, Revoke token (revoke credentials), Cancel queue, Disable SEND (narrow the gmail profile to `send: none`), and **Fleet E-Stop** (typed confirmation).
  - **Agent Diary feed** (live).
  - **Architecture panel.**
- **Agent detail:**
  - Containment buttons with a reason dialog; each result shows per-step outcomes.
  - Memory panel: access mode, snapshots (restore), staged items (flag or drop).
  - Containment history.
- **Teams:** suspend or resume a team.
- **Undo page.**
- **Integrations:** Temporal, Celery, queue webhook and memory stores appear automatically from the schemas.

## 7. Ownership

| WS | Owns |
|---|---|
| E1 containment | `internal/containment`; small additions in `internal/population` (instance suspend/resume and the heartbeat 423 "pause" signal) |
| E2 queues | `internal/queues`, plus schema/tester registration additions in `internal/integrations` |
| E3 memory | `internal/memory`, `policies/fortik/memory`, the `internal/access` `memory` profile system (if needed) |
| E4 retention and undo list | `internal/retention`, `internal/undo` (descriptions, `undoable`/`why_not`) |
| E5 console | `web/console`, `internal/console` |

The lead wires `main.go`, the API list endpoint for undo, the dev config, `dev-up.sh`, `scripts/demo-phase4.sh` and the docs.
