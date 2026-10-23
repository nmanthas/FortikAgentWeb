# Internal API (Phase 1)

- **Base URL:** `http://127.0.0.1:8080` in dev.
- **Authentication:** every `/v1` route needs `Authorization: Bearer <token>`. Missing or wrong token → `401`. Wrong role → `403`.
- **Request bodies:** strict JSON. Unknown fields, malformed JSON and trailing data → `400`. Bodies are capped at 1 MiB.

## Endpoints

| Method | Path | Role |
|---|---|---|
| POST | `/v1/actions/decide` | interceptor |
| GET | `/v1/actions?agent_id=&class=&decision=&limit=` | auditor |
| GET | `/v1/actions/{id}` | auditor |
| GET | `/v1/held?status=pending\|approved\|denied\|expired\|all` | auditor |
| GET | `/v1/agents` | auditor |
| GET | `/v1/policy` | auditor |
| GET | `/v1/diary?agent_id=&from=&to=&after_seq=&limit=` | auditor |
| GET | `/v1/diary/verify` | auditor |
| GET | `/v1/diary/export?agent_id=&action_id=&from=&to=` | auditor (an `agent_id` or `action_id` export is verified entry by entry; no segment root) |
| GET | `/v1/undo?agent_id=` | auditor |
| POST | `/v1/undo/{action_id}` | security |
| GET | `/healthz` | none |
| GET | `/readyz` | none |
| GET | `/metrics` | auditor |

What each endpoint does:

- **`POST /v1/actions/decide`:** takes an Action and returns a decision. Always `200` when a decision was made, including deny and hold; the caller must enforce the `decision` field.
- **`GET /v1/actions`:** recent actions, newest first, with explanations.
- **`GET /v1/actions/{id}`:** explains one decision: the matched rules, the levels before and after, the policy version, any held record, and any undo handle.
- **`GET /v1/held`:** held actions, with class, rule, reason, safe form and the level at the time of decision. Approve and deny arrive in Phase 3.
- **`GET /v1/agents`:** the agent registry and each agent's current level. Level changes arrive in Phase 2; until then use the audited CLI.
- **`GET /v1/policy`:** the loaded bundle version.
- **`GET /v1/diary`:** Diary entries in `seq` order.
- **`GET /v1/diary/verify`:** verifies the full chain and its head.
- **`GET /v1/diary/export`:** a signed, verifiable export. The export itself is written to the Diary.
- **`GET /v1/undo`:** the Undo list: handles and their statuses.
- **`POST /v1/undo/{action_id}`:** runs an undo handle. Body: `{"reason": "..."}` (required). Response codes:
  - `200`: undone.
  - `404`: nothing was prepared, so the action is NOT undoable.
  - `409`: already used, not active, or nothing left to undo.
  - `410`: the handle expired.
  - `502`: the undo failed; the handle returns to `active` with the error recorded.
- **`/healthz`, `/readyz`:** liveness, and readiness (database reachable, policy loaded).
- **`/metrics`:** Prometheus metrics.

## Decide

Example request:

```json
POST /v1/actions/decide
{
  "agent_id": "finance_agent_07",
  "instance_id": "inst_3f1c",
  "system": "gmail",
  "verb": "SEND",
  "target": {"to": ["investor@venturefund.com"], "external_domains": 1},
  "payload_summary": {"attachments": 1, "bytes": 12582912, "data_labels": ["customer_pii"], "recipients": 1},
  "reversible": false,
  "est_cost_usd": 0
}
```

Example response:

```json
{
  "action_id": "act_01K...",
  "class": "red",
  "decision": "hold",
  "rule_id": "POL-201",
  "reason": "email with sensitive data [\"customer_pii\"] to external recipients",
  "matched": [{"rule_id": "POL-201", "class": "red", "reason": "..."}, {"rule_id": "POL-202", "class": "yellow", "reason": "..."}],
  "ladder_change": {"to": "ISOLATED", "reason": "POL-201: ..."},
  "level_before": "FULL",
  "level_after": "ISOLATED",
  "held": true,
  "fail_closed": false,
  "latency_us": 1830,
  "policy_version": "sha256:3c1f..."
}
```

Response fields:

- `decision`: one of `allow`, `allow_reduced`, `hold`, `deny`.
- `reduced_form`: present when the decision is `allow_reduced`, e.g. `{"snapshot_rows": true}`, `{"delay_send_seconds": 120}`, `{"narrow_share": "domain", "record_permission": true}` or `{"record_ref": true}`. An interception point that can't honour every key in the reduced form must refuse the call.
- `fail_closed: true`: Fortik couldn't decide normally (see the fail behaviour table in ARCHITECTURE.md).

## Phase 4: containment, memory, undo list

All bodies need a `reason`. Roles: `kill`, team ops, `estop`, `release` and `queue/cancel` need **security**; `suspend`, `resume`, `isolate`, `memory/remove`, `memory/restore` on one agent need **security or the agent's owner** (sponsor). An owner may lift (`resume`, `memory/restore`) only a containment they imposed themselves; anything imposed by security, an E-Stop, the level API or a kill needs security, and so does any `rollback_snapshot_id`. Nobody can `resume` a killed agent (re-enable is `PUT /level`, security only). Reasons may be multi-line, up to 1000 bytes.

| Method | Path | Notes |
|---|---|---|
| POST | `/v1/containment` | a `containment.Request` `{op, target_type, target_id, reason, memory_mode?, rollback_snapshot_id?, confirm?}` |
| POST | `/v1/agents/{id}/suspend\|resume\|isolate\|kill` | |
| POST | `/v1/agents/{id}/memory/remove` | `{reason, memory_mode: none\|staging_only}` |
| POST | `/v1/agents/{id}/memory/restore` | `{reason, rollback_snapshot_id?}` |
| POST | `/v1/agents/{id}/queue/cancel` | NOT reversible |
| POST | `/v1/instances/{id}/suspend\|resume` | one copy |
| POST | `/v1/teams/{team}/suspend\|resume\|kill` | every agent of the business unit |
| POST | `/v1/fleet/estop` | `{reason, confirm: "STOP ALL AGENTS"}` |
| POST | `/v1/fleet/release` | `{reason, op_id?}`: resumes only agents that e-stop suspended |
| GET | `/v1/containment?target_type=&target_id=&limit=` | history with per-step results (auditor) |
| GET | `/v1/memory/stores`, `/v1/memory/snapshots?store=&namespace=` | auditor |
| POST | `/v1/memory/snapshots`, `/v1/memory/snapshots/{id}/restore` | security |
| POST | `/v1/memory/items/{store}/{namespace}/{id}/flag\|drop` | security or the writer's owner |
| GET | `/v1/agents/{id}/memory` | access mode and staged items |

Every operation answers `200` with the op: `{op_id, op, status: done|partial|failed, steps: [{name, agent_id, status: done|skipped|failed, detail}]}`. Each step's `detail` says what really happened in that system (e.g. "STS tokens not recallable", "workers must honour the fortik-pause signal").

`GET /v1/undo` now returns, per handle, `undoable`, `why_not` (e.g. "already used", "expired", "already sent: NOT undoable") and `description` (what Undo will do).

Agent gateway (agent token): `POST /gw/memory/{store}/{namespace}/items` (REMEMBER), `POST .../query` (READ), `DELETE .../items/{id}` (DELETE). Copies: a suspended copy's heartbeat answers `423 {"action":"pause"}`; a stopped one `410`.

## Phase 5: swarms, map, shadow agents, baselines, approval queue

| Method | Path | Role |
|---|---|---|
| GET | `/v1/swarms?state=`, `/v1/swarms/{id}`, `/v1/swarms/{id}/bundle` | auditor or security |
| POST | `/v1/swarms/{id}/trip\|suspend\|isolate\|kill` | security; `{reason}` (kill: `keep_root_read_only`, default true) |
| POST | `/v1/swarms/{id}/release` | security; needs **two distinct approvers**: the 1st returns `{released:false, votes:1, required:2}`. A second API-token vote after a token vote returns 409 (two-person rule) unless `approvals.allow_token_pairs` |
| GET | `/v1/map?view=team\|agent\|swarm\|external\|blast&id=&from=&to=` | auditor or security |
| GET | `/v1/map/path?label=&dest=&from=&to=` | auditor or security |
| GET | `/v1/map/live` | SSE: `edge.updated`, `swarm.updated` |
| GET | `/v1/shadow?status=&system=&kind=`, `/v1/shadow/{id}` | auditor or security |
| POST | `/v1/shadow/scan`, `/v1/shadow/{id}/revoke\|dismiss` | security; optional `{reason}`. Revoke answers 200 `{finding, outcome, revoked, detail}`, where `outcome` is `revoked`, `not_revoked` or `manual_required`. Check `revoked`: only `true` means the credential was revoked |
| POST | `/v1/shadow/{id}/register` | security; `{sponsor, name, team}` |
| GET | `/v1/agents/{id}/baseline?verb=` | auditor or security |
| GET | `/v1/approvals/queue?status=&agent_id=&swarm_id=&rule_id=&class=&assigned_to=&sort=&limit=&offset=` | auditor or security |
| POST | `/v1/held/{id}/assign` | security; `{assignee}` |
| POST | `/v1/held/bulk-deny` | security; `{action_ids, reason}` → per-id results |
| GET | `/v1/diary?action_id=` | auditor (new filter) |

`POST /v1/actions/decide` now returns `approvals_required` on a hold that needs more than one approver. An approver who voted to approve may still deny; votes are append-only, and the Diary records the withdrawal.

## Not yet implemented (planned)

| Phase | Endpoints |
|---|---|
| 2 | `/v1/credentials/issue`, `PUT /v1/agents/{id}/level`, `PUT /v1/agents/{id}/access/{system}` |
| 3 | `/v1/held/{id}/approve\|deny`, `/v1/overrides*` |
