# Internal API

Every endpoint, by the phase that added it. Base URLs in dev:
- control-plane API and console: `http://127.0.0.1:8080`;
- agent gateway: `http://127.0.0.1:8090` (agent tokens, `/gw/...`, `/v1/credentials/issue`, `/v1/instances/*`, `/v1/hook/claude-code`, `/oauth/*`).

In a pilot deployment both use TLS, and mutual TLS where configured (docs/DEPLOYMENT.md).

## Phase 1

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

## Phase 2: broker, access profiles, levels, console, integrations

| Method | Path | Role |
|---|---|---|
| POST | `/v1/credentials/issue` (gateway) | agent token. `{system, aws?…}` → short-lived credential, or `403` refusal with `rule_id`, or `503 integration_not_configured` |
| PUT | `/v1/agents/{id}/level` | `{level, reason}`. The owner may step up one level at a time, or step down; only security may set or leave `KILLED` |
| GET | `/v1/agents/{id}/access`, `/v1/agents/{id}/access/{system}/history` | auditor, security or the agent's owner |
| PUT | `/v1/agents/{id}/access/{system}` | security; the owner only to narrow |
| POST | `/v1/agents/{id}/access/{system}/revert` | security; the owner only to narrow |
| GET / PUT / DELETE | `/v1/integrations/{key}`; `GET /v1/integrations`, `/v1/integrations/schema`; `POST /v1/integrations/{key}/test` | GET auditor or security; changes security. Secret values are never returned (`{"set": true}`) |
| POST | `/auth/dev-login` (dev only, loopback only), `GET /auth/login`, `/auth/callback` (OIDC), `GET /auth/config`, `POST /auth/logout`, `GET /v1/me` | console sessions; cookie requests need the `X-Fortik-CSRF` header |
| GET | `/v1/events/stream` | SSE of Diary events (auditor) |
| GET | `/v1/agents/{id}`, `/v1/agents/{id}/stats`, `/v1/stats/summary` | auditor |

## Phase 3: hook, delegation, copies, approvals, timed suspensions

| Method | Path | Role |
|---|---|---|
| POST | `/v1/hook/claude-code` (gateway) | agent token; used by `fortik hook claude-code` (exit 0 allow, 2 block, and 2 when Fortik is unreachable) |
| POST | `/v1/agents` | security: register an agent. `POST /v1/agents/{id}/tokens` mints its token (shown once), `DELETE` revokes it. `PATCH /v1/agents/{id}` changes e.g. `copy_cap` |
| GET / PUT | `/v1/agent-types`, `/v1/agent-types/{type}` | GET auditor or security; PUT security (`expected_max_instances`, `max_agents`, `spawn_rate_per_min`, `action_rate_per_min`) |
| POST | `/v1/instances/register\|heartbeat\|stop` (gateway) | agent token. register `201 \| 403 \| 429`; heartbeat `200 \| 410 (stop) \| 423 {"action":"pause"}` |
| GET / POST | `/v1/agents/{id}/instances`, `/v1/agents/{id}/instances/pause-extra` | auditor, security or the owner; pause-extra security or the owner |
| GET | `/v1/agents/{id}/delegations?direction=&status=&limit=` | auditor |
| POST | `/v1/held/{id}/approve` `{reason, use_safe_form}`, `/v1/held/{id}/deny` `{reason}` | security (the owner too when `approvals.allow_owner_approval`). A red hold is approved only with `use_safe_form: true` (else `409`) |
| POST | `/v1/overrides` `{scope: agent\|team, scope_id, system, mode: suspended\|read_only, duration_seconds \| until_released, reason}` | security; the owner for agent scope on their own agent. `duration_seconds` is between 60 s and the configured maximum |
| POST | `/v1/overrides/{id}/release\|extend\|permanent`; `GET /v1/overrides?agent_id=&status=`, `/v1/overrides/{id}` | see internal/overrides/http.go: security, or the owner for their own agent |
| GET / POST | `/v1/alerts?status=&kind=&agent_id=`, `/v1/alerts/{id}`; `/v1/alerts/{id}/ack\|resolve` | GET auditor; ack/resolve security |

A timed suspension of a system also covers actions that **reach** it: a Claude Code shell command that runs `gh` or a git remote operation (push, fetch, pull, clone…) reaches GitHub, and the AWS CLI reaches AWS (`target.reaches`, POL-030/031). A copilot connector token reaches its upstream's systems.

## Phase 6: observe mode, pilot metrics, copilot connectors

| Method | Path | Role |
|---|---|---|
| GET | `/v1/enforcement` | auditor or security: the deployment's mode (`enforce` \| `observe`) |
| PUT | `/v1/agents/{id}/enforcement` `{mode: default\|observe\|enforce, reason}` | security; a Diary event (`enforcement.changed`). The agent's response carries `enforcement` and `effective_enforcement` |
| GET | `/v1/metrics/pilot?from=&to=` (RFC 3339; default the last 30 days) | auditor or security: the plan's five success metrics, each `{value, unit, target, met, n}` |
| GET | `/v1/connectors`, `/v1/connectors/{id}` | auditor or security (with `callback_url`, Fortik's redirect URI to register at Google/GitHub) |
| POST | `/v1/connectors` `{agent_id, name, sponsor, team, vendor, upstream: google_workspace\|github, redirect_uris, scopes, reason}` | security. Returns the client id and the **client secret once** (only its hash is stored), plus the authorize and token URLs |
| POST | `/v1/connectors/{id}/disable` `{reason}` | security: no more tokens, and every grant revoked upstream now |

**Public OAuth endpoints** (gateway; clients authenticate with their client secret, browsers with the upstream):

| Method | Path | Notes |
|---|---|---|
| GET | `/oauth/authorize?client_id=&redirect_uri=&response_type=code&state=&scope=&code_challenge=&code_challenge_method=S256` | redirect_uri must be registered (exact match; may be omitted when only one is registered); scopes are narrowed to the registration; at most 200 open authorizations per connector (`temporarily_unavailable` beyond) |
| GET | `/oauth/callback` | upstream consent → Fortik keeps the upstream grant (secret store) and redirects the client with a one-time code (2 min) |
| POST | `/oauth/token` | `grant_type=authorization_code` (code single-use: a replay revokes the grant; PKCE S256 checked) or `refresh_token` (rotated; reuse of an old one revokes the grant). **Each issue is a Fortik decision** (system `connector`, verb READ for read-only scopes, WRITE otherwise) |
| POST | `/oauth/revoke` | RFC 7009 |

**Milestone 0 (cross-agent authority, evidence, coverage):**

| Method | Path | Role |
|---|---|---|
| GET | `/v1/coverage` | auditor or security: per integration, each capability dimension (discovery, identity attribution, activity, delegation, pre-execution enforcement, credential revocation, suspension, undo, evidence integrity) with its status (`verified_live`, `verified_test`, `implemented`, `unsupported`, `not_built`), evidence and gap. Plus a class: A prevented before execution, B contained after, C observed only, D not verified. No overall score; test-only verification never earns A–C; a disconnected integration is D |
| GET | `/v1/containment/{op_id}/receipt` | auditor or security: the evidence for a containment operation, re-read now from authoritative state (level, suspension, live copies, memory access, copilot grants, open delegations). Includes the steps as reported, residual access the systems reported, linked Diary seqs, and an outcome `confirmed` \| `partially_confirmed` \| `failed` \| `unknown`. A step reporting "done" is never proof by itself |

A DELEGATE (`system a2a`) may carry `target.task_scope` `{systems: [...], verbs: [...], domains: [...]}` (POL-605). Hops record `task_scope` (narrowed) and a `correlation_id` (the root DELEGATE's action id) shared by every hop of one delegated task.

**Milestone 1, NetSuite:**

| Method | Path | Role |
|---|---|---|
| any | `/gw/netsuite/services/rest/record/v1/...`, `POST /gw/netsuite/services/rest/query/v1/suiteql` (gateway) | agent token. The same paths as NetSuite's REST web services; each call is decided (POL-1001..1009, the access profile, delegation, levels) before Fortik forwards it with its own OAuth token. `503 integration_not_configured` until the `netsuite` integration exists |
| GET | `/v1/saas/netsuite` | auditor or security: capability probes against the account, mapped-agent inventory (`complete: false`), sync state, coverage declaration |
| POST | `/v1/saas/netsuite/sync` | security: read system notes now; changes by mapped agents are recorded as observed after execution, with the rule policy would have applied |

Integration `netsuite`: `account_id`, `client_id`, `certificate_id`, `algorithm` (PS256 or ES256), `scope`, `agent_map` (`fortik_agent=entity_id`), `activity_query`, `api_base`, and secret `private_key_pem`. The access profile system `netsuite` is `{"mode","record_types","suiteql"}`.

**NetSuite QuickStart MCP (QuickStart Milestones 1–4):**

| Method | Path | Role |
|---|---|---|
| PUT / POST …/test / DELETE | `/v1/integrations/netsuite_quickstart` | security. Save (a new `personal_access_token` rotates it), live Test connection, disconnect. Disconnecting deletes Fortik's copy of the token; it does not revoke it in QuickStart |
| GET | `/v1/saas/netsuite_quickstart` | auditor or security: `state` (`not_configured`, `saved_not_tested`, `connected`, `connected_limited`, `auth_failed`, `token_expired`, `permission_denied`, `mcp_init_failed`, `tool_discovery_failed`, `unavailable`, `endpoint_not_permitted`). Also: the discovered tools with their schemas; `permission_mode` (inferred: `read_only`, `read_write`, `unverified`, `unknown`) with its basis; token expiry; sync times; `enforcement` (`agent_calls_routed: true`); `agent_endpoint`; `activity` (last 24 h: allowed, held, denied, executed, failed, pending approvals, active NetSuite suspensions, undos available, recent decisions with outcome and undo state); `known_gaps`; the coverage declaration. Never the token |
| POST | `/v1/saas/netsuite_quickstart/refresh` | security: live check and tool rediscovery now (`initialize` and `tools/list`; never a tool call) |
| POST | `/mcp/netsuite_quickstart` (gateway) | agent token (`Authorization: Bearer <Fortik agent token>`; optional `X-Fortik-Instance-Id` and `X-Fortik-Delegation`). Fortik's MCP server for QuickStart (Streamable HTTP, JSON responses, stateless: no session id).<br>• `initialize` and `ping` are answered by Fortik.<br>• `tools/list` is decided (a suspended or unprofiled agent sees nothing) and returns the discovered tools the agent's `netsuite` profile allows. Write tools say they are held.<br>• Every `tools/call` is decided before QuickStart sees it, then forwarded with Fortik's token.<br>• A refusal or hold returns `isError: true` with `_meta` `fortik/action_id`, `fortik/decision` and `fortik/executed: false`. Results carry `fortik/executed: true`, and `fortik/undo: available` when an update was snapshotted.<br>• A held yellow call runs when the agent repeats it identically after approval. |
| GET / DELETE | `/mcp/netsuite_quickstart` | GET: 405 (no server stream). DELETE: 204 |

Fortik re-checks the connection every `mcp_upstreams.check_interval` (default 30m; negative disables). It raises alerts of kind `quickstart_connection`, `quickstart_token_expiry` and `quickstart_tools_changed`, deduplicated while open. The `netsuite` access profile also takes `quickstart_tools` (optional): `["*"]` or a list of tool names (POL-1108). Undo of a QuickStart update is `POST /v1/undo/{action_id}`, as for every other undo kind (`netsuite_quickstart_record`). The agentgateway config `agentgw.mcp_server_systems` (e.g. `quickstart: netsuite`) makes a business system's timed suspensions cover an agentgateway MCP server.

Integration `netsuite_quickstart`: `name`, `tenant_label`, `endpoint_url` (default `https://my.quickstartapi.netsuite.com/mcp`; the host must be in config `mcp_upstreams.allowed_hosts`), `transport` (`streamable_http`), `auth_type` (`personal_access_token`), `token_expires_on`, and secret `personal_access_token`.

**Unified integrations: one logical integration per tenant, several transports (integration platform M1):**

A *logical integration* is one tenant of one provider, id `provider:name` (e.g. `netsuite:acme`, `netsuite:quickstart`, `github:default`). Its *connections* are the existing integrations (`/v1/integrations/{key}`), each with one `transport` (`rest_api`, `mcp`, `native`) and its own credentials, status and test. A logical integration has at most one connection per transport. A full NetSuite account's connections must all name the same `account_id`, and an account belongs to one logical integration only. A QuickStart company label is a display name, not an identity. Every integration row now carries `integration_id` and `transport`.

| Method | Path | Role |
|---|---|---|
| GET | `/v1/app-integrations` | auditor or security: `{integrations, providers}`. Each integration has its `health` (`healthy`, `degraded`, `unhealthy`, `untested`, `not_connected`), `connections`, and `transports`: per transport the provider environment offers, whether it is `available` (with the `reason` when not), its evidence (`verified`: `live`, `test`, `none`), the `connection_key` to configure, and whether that connection is `configured`. A transport is configured only when its own connection exists; another transport working says nothing about it. `providers` lists each provider's environments and transports (NetSuite: `full` with REST and the AI Connector MCP server; `quickstart` with the QuickStart MCP server and no REST, with the documented reason) |
| POST | `/v1/app-integrations` | security: `{provider, environment, name, tenant_ref, display_name}` creates a tenant before its connections (e.g. a second NetSuite account). It is kept when its last connection is removed; tenants created implicitly by configuring a connection are removed with their last connection |
| GET / PATCH / DELETE | `/v1/app-integrations/{id}` | GET: auditor or security. PATCH `{display_name}`: security. DELETE: security, only without connections (409 otherwise) |
| GET | `/v1/app-integrations/{id}/activity` | auditor or security: last 24 h of agents' calls to this tenant across its transports (`by_transport` → decision → count), pending approvals, active suspensions of the provider's systems, the 20 most recent decisions |
| DELETE | `/v1/integrations/{key}` | now returns `{deleted, notes}`: what disconnecting did upstream (e.g. whether NetSuite confirmed the OAuth revocation, or that a QuickStart PAT was not revoked) |

Connection keys: `netsuite` or `netsuite:<tenant>` (REST), `netsuite_quickstart` or `netsuite_quickstart:<tenant>` (QuickStart MCP), `netsuite_mcp:<tenant>` (a full account's AI Connector Service MCP server). The single keys belong to `netsuite:default` and `netsuite:quickstart`.

**Selecting the tenant.** REST: the header `X-Fortik-Integration: netsuite:<tenant>` on `/gw/netsuite/...`. Without it, the only NetSuite REST connection is used. With more than one, the call is refused and recorded (verb `UNKNOWN`, `target.reason` names the header); it is never routed to a guessed tenant. MCP: each tenant has its own endpoint `/mcp/netsuite/<tenant>` on the gateway (`/mcp/netsuite_quickstart` remains the QuickStart one). Every decided NetSuite action carries `target.transport`, `target.integration_id` (the tenant), `target.connection` (the key) and, for REST, `target.tenant` (the account). The `netsuite` access profile takes `integrations`: `["*"]` or tenant ids; any other tenant is refused on every transport (POL-1010).

**NetSuite MCP connections (QuickStart and the AI Connector Service):**

| Method | Path | Role |
|---|---|---|
| GET | `/v1/integrations/{key}/mcp` | auditor or security: the status described for `/v1/saas/netsuite_quickstart` above, for any NetSuite MCP connection; adds `key`, `integration_id`, `mapped_tools`, each tool's `mapped`, and for OAuth connections `oauth` (`authorized`, `authorized_at`, `authorized_by`, `access_expires_at`, `refreshed_at`, `stale`, `scope`; never a token). State `authorization_required`: configured but no NetSuite user has authorized Fortik |
| POST | `/v1/integrations/{key}/mcp/refresh` | security: live check and tool rediscovery |
| POST | `/v1/integrations/{key}/oauth/start` | security, `netsuite_mcp` only: `{authorize_url, expires_in}`. The administrator opens the URL (NetSuite login and consent; authorization code with PKCE S256, `prompt=consent`, state of 43 characters, valid 10 minutes and once) |
| GET | `/v1/oauth/netsuite/callback` | security (the console session that started it): exchanges the code (public client: `client_id` and `code_verifier`, no secret), stores the tokens in the secret store, runs a live check, and redirects to `/integrations?oauth=<key>&oauth_ok=1` or `&oauth_error=...` |
| POST | `/mcp/netsuite/<tenant>` (gateway) | agent token. The tenant's MCP endpoint; same protocol and decisions as `/mcp/netsuite_quickstart`. A tenant without an MCP connection is refused (decided as `UNKNOWN`, recorded) |

`/v1/saas/netsuite_quickstart` and `/v1/saas/netsuite_quickstart/refresh` remain and serve the QuickStart connection (or the only NetSuite MCP connection).

Integration `netsuite_mcp:<tenant>`: `account_id`, `client_id` (the integration record's client ID; a public client has no secret), `redirect_uri` (default `http://127.0.0.1:8080/v1/oauth/netsuite/callback`; must equal the integration record's redirect URI), `scope` (default `mcp`; Oracle does not document the value), `tools_path` (`all` or `suiteapp/com.netsuite.mcpstandardtools`), `api_base` (tests only), and the managed secret `oauth_tokens` (written by Fortik, never accepted from the API, deleted with the connection). The access token is refreshed one minute before it expires; NetSuite's refresh tokens are one-time use, so each refresh stores the new one. Disconnecting calls NetSuite's revoke endpoint with the refresh token and reports whether NetSuite confirmed it.

**Salesforce, ServiceNow and SAP (REST API or MCP Server, one integration per tenant):** see docs/INTEGRATIONS.md for the fields and setup of each connection type.

| Method | Path | Role |
|---|---|---|
| PUT / POST …/test / DELETE | `/v1/integrations/{salesforce,servicenow,sap}[:<tenant>]` | security. The REST connection: save, live read-only test, disconnect |
| GET | `/v1/integrations/{key}/check` | auditor or security, REST connections of these providers: `state` (`not_configured`, `saved_not_tested`, `connected`, `auth_failed`, `permission_denied`, `not_found`, `unavailable`, `endpoint_not_permitted`, `invalid_settings`), `detail`, `identity` (who the credentials act as, as the provider reported it), `capabilities` (Salesforce: API versions, objects visible/queryable and the access flags of common objects, API requests left; ServiceNow: readable tables; SAP: entity sets per OData service), `capabilities_from_current_settings`, `agent_endpoint`, `known_gaps`. Never a credential |
| any | `/gw/salesforce/services/data/vNN.N/...`, `/gw/servicenow/api/now/...`, `/gw/sap/sap/opu/odata[4]/...` (gateway) | agent token. The provider's paths; each call is decided (system `salesforce` / `servicenow` / `sap`, `target.transport: rest_api`, `operation`, `object`, `record_id`, `integration_id`) before Fortik forwards it with its own credentials. Other paths are refused (`UNKNOWN`). `X-Fortik-Integration: <provider>:<tenant>` selects the tenant when several are connected (ambiguous calls are refused). `503 integration_not_configured` until the REST connection exists |
| PUT / POST …/test / DELETE | `/v1/integrations/{salesforce_mcp,servicenow_mcp,sap_mcp}[:<tenant>]` | security. The MCP connection; `GET /v1/integrations/{key}/mcp`, `POST …/mcp/refresh` and `POST …/oauth/start` as for NetSuite MCP connections |
| GET | `/v1/oauth/mcp/callback` | the OAuth return of these MCP connections (same handler as `/v1/oauth/netsuite/callback`) |
| POST | `/mcp/{salesforce,servicenow,sap}/<tenant>` (gateway) | agent token. The tenant's MCP endpoint; every `tools/call` is decided as the provider's system. No tool is mapped yet (`policies/fortik/<provider>_mcp/data.json`): every call is refused (POL-002) until mapped |

The access profile of `salesforce`, `servicenow` and `sap` is `{"mode","objects","integrations"?,"mcp_tools"?}` and applies to both transports; timed suspensions (`/v1/overrides`) accept these systems. `GET /v1/app-integrations` lists their tenants and both transports, with the catalog's availability and evidence.

**Notifications:** the integration `notify_slack` (`PUT /v1/integrations/notify_slack` `{config: {min_severity, kinds, console_url}, secrets: {webhook_url}}`, security; `POST …/test` posts a test message) sends each security alert once to a Slack incoming webhook, naming the agent's owner. This includes the owner notification when a timed suspension is restored.

In observe mode, `POST /v1/actions/decide` returns `decision: allow` for what policy would have held, denied or reduced, with `observed: {decision, rule_id, reason, reduced_form, ladder_change}`. Refusals that are not policy opinions stay enforced: unknown or malformed actions, fail-closed outcomes, levels set by humans, timed suspensions, unregistered agents and connector checks (docs/POLICIES.md).

**CLI** (`bin/fortik <command> -h`):

| Command | Purpose |
|---|---|
| `replay build -capture F[,F…]` | build the 10,000-record corpus |
| `replay run -corpus F -policy DIR` | the replay gate; exit 1 on any class, decision, rule or step-down change |
| `certs dev -out DIR [-hosts …] [-clients …] [-days 365] [-if-absent]` | a development CA plus server and client certificates for mTLS |
| `healthz -url U [-ca F -cert F -key F]` | health probe for containers |
| `config check -config FILE` | validate a configuration without starting |
| `migrate -config F [-grant-app ROLE]` | apply migrations; grant the app role its least privileges |
