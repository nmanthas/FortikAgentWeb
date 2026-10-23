# Phase 5 design: swarms and the communication map

**Plan scope** ("Phase 5 · Swarms and map", gate: attack + kill-swarm demos):
- swarm detection with the Max-5 breaker, spawn-tree, copy-surge and converging-target signals;
- a `swarms` object; kill-swarm in 7 ordered steps; release needs two approvers;
- the communication map: 5-minute edges; views by team, agent, swarm, external exposure and blast radius; path trace; time replay; hidden-signal rules; live updates;
- shadow-agent discovery (standing credentials per system, unknown hosts and OAuth clients; a discovered agent starts ISOLATED);
- baselines: 14-day hourly counts, mean + 3σ, or 5× the median with less than 3 days of history; an above-normal green action becomes yellow;
- the full approval queue.

**Scenarios:**
- 1 attack;
- 3 kill-swarm (41 agents; breaker trips on the 6th identical send; 0 emails delivered);
- 7 shadow agent.

Already delivered earlier and reused:
- the delegation chain and A2A DELEGATE through agentgateway (Phase 3);
- copy caps and spawn rate limits (Phase 3);
- containment steps (Phase 4).

**Already contracted** (in the repo):
- **Migration `0007_phase5.sql`:**
  - `swarms`, `swarm_members`, `swarm_breakers`, `swarm_release_votes`;
  - `edges`, `edge_rollup_state`;
  - `shadow_findings`;
  - `baseline_hourly`;
  - `held_actions.swarm_id` and `held_actions.assigned_to`;
  - containment ops `trip_breaker`, `kill_swarm`, `release_swarm`, and target `swarm`.
- **Two-approver holds:** a finding may carry `"approvals_required": n`. A hold then needs n distinct approvers: `policy.Result.ApprovalsRequired` is stored in `held_actions.approvals_required`. The approvals service already counts distinct approve votes.
- **Config:** `swarm`, `map`, `shadow` and `baseline` sections, with the plan's defaults.

## Rule ids

| Range | Package | Rules |
|---|---|---|
| POL-651–659 | `fortik.swarm` | POL-651 breaker: a call matching a tripped breaker is held as yellow with `approvals_required: 2`. POL-652: a frozen swarm refuses DELEGATE and new copies (gate). Others as needed. |
| POL-660–669 | `fortik.baseline` | POL-660: an above-normal action that would otherwise be green becomes yellow and is held (one approver) |
| POL-670–679 | `fortik.hidden` | hidden signals that the policy can see on one action (e.g. an encoded payload in a URL parameter above `map.encoded_param_min`) |
| POL-680–689 | `fortik.shadow` | calls from unknown hosts or OAuth clients, or with unknown tokens, where the policy can see them |

Policy inputs (enrichers, under `input.context`):
- `swarm = {member_of: [swarm_id], frozen: bool, breaker: {tripped: bool, swarm_id}}` for this action's hash;
- `baseline = {current, mean, stddev, median, history_days, threshold, above_normal}` for (agent, verb, current hour).

## 1. Swarms (`internal/swarm`)

**Detection** (the observer counts inside the decide transaction; a background sweep covers the rest):

1. **Action hash (Max-5).** `action.Hash()` repeated by more than `breaker_n` (5) distinct agents or copies within `breaker_window`. The match that pushes past N trips the breaker:
   - create the swarm with `detected_by = action_hash` and the earlier N plus this one as members;
   - write `swarm_breakers`;
   - hold every later matching call (POL-651, two approvers).

   In the plan's demo, the 6th identical send is held and workers 1–5 are already in the delay queue.
2. **Spawn tree.** One root's open delegations exceed `fanout_limit`, or the chain goes deeper than `depth_limit`. This creates a swarm rooted at the root agent, with every agent in its tree as a member.
3. **Copy surge.** Live copies exceed `copy_cap` (Phase 3 population signal). The swarm is that agent's copies.
4. **Converging targets.** At least `converge_n` distinct agents hit the same external domain, table or repo within `converge_window`.

A swarm's `swarm_id` is the root delegation id when the members share one, otherwise `swm_<ulid>`. Members are added as detection continues, and `member_count` is kept current. `actions.swarm_id` is set for members' actions.

**Actions** (security; a reason is always required; each is recorded as a containment op with target `swarm`, per-member steps, and a Diary event):

| Action | What it does |
|---|---|
| `trip_breaker` | Trip a breaker by hand for a swarm's action hash: hold matching calls only |
| `suspend` / `isolate` | Run the Phase 4 suspend / isolate on every member |
| `kill` | The 7 steps in order, each in parallel across members, see below |
| `release` | Needs **two distinct security approvers**. The first vote is recorded; the second releases: breakers released, freeze lifted, members resumed. It never un-kills: killed members stay KILLED until security re-enables each one through the level API. |

Kill-swarm steps:
1. **Freeze spawning:** `frozen`; POL-652 refuses DELEGATE and new copy registration.
2. **Hold every pending matching call:** pending delayed Gmail sends from members are cancelled, and queued calls are held.
3. **Revoke** every member's live credentials on every system.
4. **Cancel** queued jobs and retries.
5. **Remove memory access** for the swarm's members (frozen, not deleted).
6. **Stop all copies.** Optionally the root is kept at READ_ONLY instead of KILLED (`keep_root_read_only`, default true, as in the plan's demo).
7. **Seal a Diary bundle:** `swarm.sealed` with the swarm, the spawn tree, the brief (the root's first delegation), every held call and every step. It is exportable through `GET /v1/swarms/{id}/bundle`, signed like Diary exports.

**API** (API listener):

| Method | Path | Role |
|---|---|---|
| GET | `/v1/swarms?state=` | auditor |
| GET | `/v1/swarms/{id}` | auditor; includes members, signal, breakers, held calls, release votes |
| POST | `/v1/swarms/{id}/trip\|suspend\|isolate\|kill` | security; body `{reason}` (kill: also `keep_root_read_only`) |
| POST | `/v1/swarms/{id}/release` | security; body `{reason}`. The 1st vote returns `{released: false, votes: 1, required: 2}`, the 2nd (a different approver) releases. |
| GET | `/v1/swarms/{id}/bundle` | auditor |

The kill result has the same shape as a containment op: `{op_id, op: "kill_swarm", status, steps: [{name, agent_id, status, detail}]}`.

## 2. Communication map (`internal/commap`)

- **Nodes.** Typed ids:

  | Node | Id |
  |---|---|
  | Agent | `agent:<id>` |
  | Running copy | `instance:<id>` |
  | Human sponsor | `user:<email>` |
  | App or tool | `app:<system>` (gmail, drive, github, aws, http, shell, files) |
  | Data store | `store:postgres:<upstream>` |
  | Memory namespace | `memory:<store>/<namespace>` |
  | MCP server | `mcp:<server>` |
  | External domain | `domain:<host>` |

  Node attributes: kind, label, team, level, suspended, discovered, owner, swarm ids.
- **Edges.** A rollup worker runs every `map.rollup_interval` and folds new `actions` (and delegations, as `DELEGATE` agent→agent edges) into 5-minute windows. Each edge records verb, count, bytes, data labels, sample action ids, and worst class (green, yellow, red, or **hidden**). The worker is exactly-once through `edge_rollup_state`, and retention prunes windows older than `map.retention`.
- **Hidden signals** (MVP rules from the plan). An edge is marked `hidden` and an alert is raised (`alerts`, kind `hidden_signal`) when:
  1. a data label such as customer PII flows into a memory write;
  2. a URL parameter carries an encoded payload above `map.encoded_param_min` (also a POL-67x policy finding);
  3. one agent passes labelled data to another agent that has external egress (its http access profile allows external, or it has made external calls).
- **API:**

  | Method | Path | Role |
  |---|---|---|
  | GET | `/v1/map?view=team\|agent\|swarm\|external\|blast&id=&from=&to=` | auditor |
  | GET | `/v1/map/path?label=&dest=&from=&to=` | auditor |
  | GET | `/v1/map/live` | auditor |

  - `GET /v1/map` returns `{window: {from, to}, nodes: [...], edges: [...], clusters: [...]}`.
    - `view=swarm` collapses each active swarm into one cluster `{swarm_id, state, members}` that expands on click.
    - `view=blast&id=<agent>` returns everything the agent can reach with its current access profiles (a halo), not just what it called.
    - `from`/`to` give time replay; the default is the last hour.
  - `GET /v1/map/path` traces every hop of data with that label to that destination, using a recursive query over edges. Each hop is `{from, to, verb, window_start, action_ids}`, and the console links each one to its Diary event.
  - `GET /v1/map/live` sends live updates over **SSE**, reusing the authenticated, re-validated Phase 2 event stream. The plan says WebSocket; this is recorded as a deviation for sign-off. Events: `edge.updated` and `swarm.updated`.

## 3. Shadow-agent discovery (`internal/shadow`)

**Discoverers** each list the standing credentials of one system, through the integration configured in the console, and flag those used by software rather than a person:

| System | Discovers | Flagged as software when |
|---|---|---|
| Postgres | non-Fortik login roles on each `postgres:*` upstream | Connections in `pg_stat_activity` or recent logins come from a role that is not a person (no interactive `application_name` such as psql or pgAdmin, non-interactive client hosts). Fortik's own `fortik_a_*`, admin, read and write roles are excluded. |
| GitHub | fine-grained PATs approved for the org; app installations | the token's user agent or usage pattern, or the app isn't registered |
| AWS | IAM users with active access keys | Fortik's own principals are excluded |
| Google Workspace | OAuth grants (Admin SDK tokens.list) | the client is not native or browser-based |

Traffic findings are recorded when Fortik sees calls from unregistered agent ids, unknown instance hosts or unknown OAuth clients (gateway and hook attempts that fail authentication with a well-formed token, and Postgres proxy logins as unknown users).

**A finding** goes into `shadow_findings` (the credential's identifier only, never the secret). When it is used by software:
- a **discovered agent** is registered with `discovered=true`, no owner (`sponsor` empty) and level **ISOLATED**;
- it appears on the map;
- the finding's status becomes `flagged_for_revocation`.

This is scenario 7. Security can revoke the credential where Fortik can (for example `ALTER ROLE ... NOLOGIN` on Postgres), dismiss the finding, or register the agent properly with an owner.

**API:**

| Method | Path | Role |
|---|---|---|
| GET | `/v1/shadow?status=` | auditor |
| POST | `/v1/shadow/scan` | security |
| POST | `/v1/shadow/{id}/revoke\|dismiss\|register` | security; `register` takes `{sponsor, name, team}` |

## 4. Baselines (`internal/baseline`)

- An observer increments the hourly count per (agent, verb), in Redis when `counters.provider: redis` and in memory otherwise. `baseline_hourly` in Postgres is the durable copy and the backfill source (14 days).
- The enricher computes `input.context.baseline` against the agent's own history:
  - 14 days of hourly counts;
  - above normal when `current > mean + 3σ`, or `current > 5 × median` with less than 3 days of history;
  - never below `baseline.min_count`.
- POL-660 turns an above-normal green action into yellow, held for one approver.
- `GET /v1/agents/{id}/baseline?verb=` returns the hourly series and the thresholds (auditor), for the console.

## 5. Approval queue (`internal/approvals`)

The full queue:
- `GET /v1/approvals/queue?status=&agent_id=&swarm_id=&rule_id=&class=&assigned_to=&sort=` returns held actions, each with `votes [{approver, decision, at}]`, `approvals_required`, `expires_at`, the swarm and its group.
- `POST /v1/held/{id}/assign {assignee}` (security).
- `POST /v1/held/bulk-deny {action_ids, reason}` (security; each id is decided and recorded on its own).
- Swarm-held calls are grouped by `swarm_id`, and a 2-approver hold shows "1 of 2 approvals".
- The approve and deny routes keep working. The first of two approvers gets `{outcome: "pending", approvals: 1, approvals_required: 2}`.

## 6. Console

- **Communication Map** (v2 screen):
  - the graph, with view tabs Team, Agent, Swarm, External and Blast radius;
  - swarm clusters that expand on click;
  - a red/yellow/green/hidden edge legend;
  - node and edge details with the Diary link;
  - a path-trace panel (data label → destination);
  - a time-replay slider;
  - live updates.
- **Swarms:** a list and detail page (members, signal, spawn tree, breakers, held calls). The Kill swarm button shows each step ticking off across the members. Release shows the 2-approver progress.
- **Approval queue:** filters, assignment, bulk deny, swarm grouping, and "1 of 2 approvals".
- **Shadow agents:** findings with revoke, dismiss and register.
- **Command Center:** an active-swarms tile and a "discovered agents" tile.
- **Agent page:** a baseline chart.

## 7. Ownership

| WS | Owns |
|---|---|
| F1 swarms | `internal/swarm`, `policies/fortik/swarm`; small additions in `internal/containment` (swarm target) and `internal/gateway/google` (cancel members' pending delayed sends) |
| F2 map | `internal/commap`, `policies/fortik/hidden` |
| F3 shadow | `internal/shadow`, `policies/fortik/shadow`; small additions in the gateway, hook and pgproxy authentication-failure paths to record traffic findings |
| F4 baselines + approval queue | `internal/baseline`, `policies/fortik/baseline`, `internal/approvals` |
| F5 console | `web/console`, `internal/console` |

The lead wires `cmd/fortik/main.go`, the dev config, `dev-up.sh`, the demo scripts (`demo-phase5.sh`: scenarios 1, 3 and 7) and the docs.

## 8. Changes after the adversarial review

Four independent reviews (swarms and decide, map and hidden signals, shadow and baselines, console and wiring) confirmed 43 findings. 42 are fixed, each with a regression test; one is a documented limitation.

- **POL-113 bypasses.** Reads are now sized by the rows they read, not the rows they return. A parameterised read is bounded by the size of the table it reads. Nothing is planned over a view before the decision. A missing estimate on sensitive data now holds the read under the new rule POL-114.
- **Swarms:**
  - A Gmail SEND's breaker identity is its recipient set.
  - Postgres row writes are not counted.
  - Only registered copies count as separate actors.
  - A call matching someone else's tripped breaker is held, but its agent is not made a frozen member.
  - Automatic detection never grows a swarm that has been suspended, isolated or killed.
  - Grants carry their approval count.
  - A trip raises identical pending holds to two approvers and clears earlier release votes.
  - Two API tokens are not two people (`approvals.allow_token_pairs`).
  - A copy-surge kill kills the copied agent.
  - The hold's `approvals_required` is recorded in the Diary.
- **Map:**
  - `actions.ts` is never earlier than its writing transaction, and the rollup horizon uses the database clock, so a slow decision is never lost.
  - A new table, `edge_links` (migration 0009), records which agent's calls through a hub app went to which domain. Path traces and views no longer guess in busy windows.
  - The blast radius shows the default-open web for agents without an http profile.
  - An `action_id` Diary export is verified entry by entry.
  - A batch with more hidden-signal alerts than the cap raises one overflow alert instead of dropping the rest silently.
  - POL-671 was hardened (see POLICIES.md). Its threshold now applies to adapter summaries too.
- **Shadow agents:**
  - Superuser and replication login roles are findings; revoking them is a manual step.
  - A Google revoke re-checks every user before it reports success.
  - Floods of traffic-found agents raise one alert per interception point, and the hourly budget is read from the database.
  - Unknown-token refs are an HMAC keyed from the Diary signing key.
- **Baselines:**
  - A first-use ceiling, and a sparse-history cap, so one burst cannot pre-train a huge threshold.
  - The rule never fires at or below the busiest hour already seen.
  - Only executed calls count.
  - An above-normal action that would run reduced is held instead.
  - When Redis loses its data, the counts are reloaded before the next decision.
- **Console:**
  - The queue loads in pages of up to 500.
  - Team clusters are no longer drawn as swarms, and live swarm updates apply only in the swarm view.
  - A revoke shows "NOT revoked" when it was not revoked.
  - Filters offer only the values the server accepts.
  - Killed swarms count as active.
  - Reach edges are labelled as reach.
  - Token voters are recognised as voters.
  - The swarm member status is shown.
  - The scan toast shows the counts.
- **Known limitation:** each map rollup tick writes the touched edge rows to the Diary (`map.edges_updated`, about 270 bytes per row), which feeds the live map stream. These Diary copies are not pruned with the edges. A non-chained notify path, or Diary retention, is left for Phase 6.
