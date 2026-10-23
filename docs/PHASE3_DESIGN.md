# Phase 3 design: coding agents, delegation chains, spawning control

## Scope

Phase 3 combines the plan's Phase 3 with the manager's feedback.

**From the plan's Phase 3:**
- Claude Code hook (fail closed).
- MCP through agentgateway (A2A and HTTP egress too, per the spike).
- Timed app suspensions with automatic restore.
- Approve/deny of held actions, pulled forward from Phase 5.

**Manager's feedback (pulled forward from plan Phases 4 and 5):**

| # | Use case | Control |
|---|---|---|
| UC1 | Agent-to-agent policy bypass | Delegation tracking and transitive enforcement |
| UC2 | Spawning anomaly and rate limiting | Instance registration, copy caps, type populations, spawn-rate baselines, throttling, alerts, action rate limits |
| UC3 | Multi-level chaining | End-to-end chain tracing; every hop's permissions are evaluated for the executor's action, at any depth |

**Gate:** the accident demo runs end to end through the hook. A UC1/UC2/UC3 demo runs through agentgateway and the registration API.

Already contracted (code in the repo):
- `decide.Enricher` and `decide.Observer` extension points.
- `policy.Input.Context`, read by Rego as `input.context.*`.
- The `fortik.gates` deny-gate set.
- One-time grants (`input.context.grant`, `Result.GrantID`).
- Contract types in `internal/{delegation,alerts,population,overrides,approvals}/types.go`.
- Migration `0004_phase3.sql` and the Phase 3 config sections.

---

## 1. Delegation (UC1 and UC3)

### 1.1 Recording hops

- A hop is recorded whenever an agent delegates:
  - an A2A `message/send`, `message/stream` or `tasks/*` call through agentgateway;
  - a spawn registration with a parent instance belonging to another agent;
  - a Claude Code `Task` subagent call (channel `hook_task`, same agent; recorded for visibility only).
- The delegator's call is an Action with `system: "a2a"`, `verb: "DELEGATE"` and `target: {to_agent, task_id, channel, depth}`. It is decided like any action:
  - the delegator's level (a READ_ONLY agent may not delegate, because DELEGATE isn't READ);
  - its `a2a` access profile;
  - the depth limit;
  - **and its own upstream chain** (UC3: B delegating to C is checked against A as well).
- On allow, `delegation.Store.Open` stores the hop in `delegations` and returns an HMAC-SHA256 token. The key is the secret `delegation.signing_key_secret`, auto-created.
  - Claims: `{did, root, chain:[root..delegatee], depth, task, iat, exp}`.
  - The callout injects it into the upstream request as `X-Fortik-Delegation`.
- A hop closes when the A2A task reaches a terminal state, seen by the callout on the response, or when it expires (`token_ttl`, default 15 m).

### 1.2 Attributing an action to a chain

The **delegation enricher** builds `input.context.delegation` for every action:

1. **Token.** If the request carries a valid token (header, A2A metadata `fortik_delegation`, or the hook payload) whose last chain element is the acting agent:
   - `source: "token"`;
   - `chain` = the upstream agents (root first, excluding the executor).
   - An invalid, expired or wrong-agent token is **not ignored**: the action is denied by POL-604.
2. **Inferred.** Otherwise, if the agent has `delegation_strict` set (the default) and has open inbound hops:
   - `source: "inferred"`;
   - `chain` = the union of the upstream agents of every open inbound chain, deduplicated, i.e. the most restrictive assumption.
3. **None.** Otherwise `{present: false}`.

- Each chain element is a `HopState`: `{agent_id, registered, level, level_name, access}`. Here `access` is that agent's profile **for the action's system**, so every hop's own level and access are part of the input.
- Enrichers must stay fast: one query for the hops and one batched query for levels and profiles.

### 1.3 Policy: package `fortik.delegation` (adds to `fortik.gates.deny`)

| Rule | Denies when |
|---|---|
| POL-601 | Any upstream hop could not perform this action itself: `control.gate` or `access.gate` holds when evaluated with that hop's agent, level and access (`with input.agent as …, input.access as …`). Reason: "delegation bypass: originating agent X (hop i of n) may not …". |
| POL-602 | `depth > max_depth`, either from `input.context.delegation.depth`, or for a DELEGATE action, the target depth |
| POL-603 | A DELEGATE whose `target.to_agent` isn't allowed by the delegator's `a2a` profile (`may_delegate_to`), or whose resulting depth exceeds the profile's `max_depth` |
| POL-604 | The delegation token is invalid, expired or doesn't belong to the agent (the enricher sets `token_error`) |

The gate reuses the exact control and access logic, so "may not" means the same thing for direct and delegated actions.

### 1.4 Consequences (delegation observer, inside the decision transaction)

- **POL-601:**
  - Raise alert `delegation_bypass` (high), with the full chain, the executor, the root and the rule that refused.
  - Step down the **originating agent** (chain[0]) to `delegation.bypass_origin_level` (default SUPERVISED). This uses `control.Store.StepDownTx`, so it never loosens a level.
  - The executor isn't stepped down unless its own rules say so.
- **POL-602/603:** alert `delegation_depth` (warning).
- **DELEGATE allowed:** the observer stores the hop (`Open`) with `action_id`. The token goes back to the transport through the Outcome: `out.Extra["delegation_token"]`, never into the Diary.
- **Diary:** `delegation.opened`, `delegation.closed` and `delegation.bypass_blocked`, each with chain, root and executor.

### 1.5 New access-profile systems

- `a2a`: `{"may_delegate_to": ["agent_b", "*"], "max_depth": 3}`. No profile means the agent may not delegate (POL-020).
- `http`: `{"external": "none|allowlist|any", "allowed_domains": ["api.example.com", "*.example.org"]}`. POL-028 denies external egress outside the profile.
- `mcp`: `{"servers": {"github-mcp": ["*"], "memory": ["read_graph", "search_nodes"]}}`. POL-029 denies a server or tool not listed.

These extend the `internal/access` validation, `Widens` and the console editors.

---

## 2. Population: spawning and rate limits (UC2)

### 2.1 Registering instances

- `POST /v1/instances/register` (agent token, gateway listener)
  - Body: `{instance_id, host, parent_instance_id}`.
  - It is decided as Action `system: "agents"`, `verb: "DELEGATE"`, `target: {operation: "spawn", instance_id, host, parent_instance_id, new_host}`.
  - Allowed: `201 {instance_id, status:"live", heartbeat_interval_s}`.
  - Refused: `429` (rate) or `403` (cap or policy), with the refusal JSON. A refused instance is stored with status `refused`.
- `POST /v1/instances/heartbeat` with body `{instance_id}`. Returns 200, or 410 when the instance is paused, refused or stopped (it must stop).
- `POST /v1/instances/stop` with body `{instance_id}`.
- Instances are **live** while `last_heartbeat > now - stale_after` (45 s).
- Agents with `require_instances` set must send `instance_id` with every action: credentials, gateway calls, the proxy (`application_name=fortik:<id>`) and the hook. An unknown, paused, refused or stale instance is denied by POL-705.

### 2.2 Population context (enricher → `input.context.population`)

The fields are defined by `population.PolicyContext`: live counts per agent and per type, the type's expected max, spawns in the last minute (per type), the static spawn limit and baseline limit, and actions in the last minute against the action rate limit.

### 2.3 Spawn baseline (plan baselines, no ML)

- `spawn_stats` holds hourly counts per type over a rolling 14 days.
- The per-minute limit is derived from the hourly mean + 3σ, or 5× the median when there are fewer than 3 days of history, divided by 60. The minimum is the type's `spawn_rate_per_min` when set.
- `SpawnBaselineLimit = 0` means no baseline yet; then only the static limits apply.

### 2.4 Policy: package `fortik.population` (adds to `fortik.gates.deny`; spawn checks only apply to `system == "agents"` spawn actions)

| Rule | Denies when |
|---|---|
| POL-701 | The agent's live copies are at or above `copy_cap` (new copies get no credentials) |
| POL-702 | The type's live total is at or above `type_expected_max` (> 0) |
| POL-703 | Spawns in the last minute exceed `spawn_rate_limit` (> 0) or `spawn_baseline_limit` (> 0); throttled for `spike_cooldown` |
| POL-704 | The agent's actions in the last minute are at or above `action_rate_limit` (> 0), for any system |
| POL-705 | The agent requires instances and the instance is missing, paused, refused or stale |

**Population observer:**
- Counts spawns (`spawn_stats`) and actions, using the counters service.
- Raises alerts: `copy_cap`, `population_exceeded` and `spawn_spike` (high), deduplicated by agent or type within the window. `rate_limited` (warning) is also deduplicated.

### 2.5 Registration surges and unregistered agents

- `POST /v1/agents` (API) refuses beyond `agent_types.max_agents` for the type, with 409 and alert `agent_registration_surge`.
- An observer counts POL-015 (unregistered agent) denials per minute. Going above a threshold raises `unregistered_agent_surge`.

### 2.6 Pause extra

`POST /v1/agents/{id}/instances/pause-extra` (security or owner) pauses the newest live instances above `copy_cap`. They get 410 on the next heartbeat and refusals on every action.

### 2.7 Counters

- `population.Counters` interface: `Incr(key, window)`, `Count(key, window)` (sliding window).
- Implementations: `memory` (single process) and `redis` (plan; Lua or ZSET sliding window).
- If counters are unavailable, the enricher errors and the decision fails closed.

### 2.8 Agent types

- `GET /v1/agent-types` (auditor) and `PUT /v1/agent-types/{type}` (security).
- Diary `agent_type.changed`.

### 2.9 Alerts

- `GET /v1/alerts?status=` (auditor), `POST /v1/alerts/{id}/ack`, `POST /v1/alerts/{id}/resolve`.
- Diary `alert.raised`, `alert.acknowledged`.
- `alerts.Raiser` with `Raise` and `RaiseTx(ctx, tx, a)`.

---

## 3. Claude Code hook (plan Phase 3)

### 3.1 Client: `fortik hook claude-code` (a subcommand of the same binary)

- Reads the PreToolUse JSON from stdin.
- Env: `FORTIK_GATEWAY_URL`, `FORTIK_AGENT_TOKEN` or `FORTIK_AGENT_TOKEN_FILE`, `FORTIK_INSTANCE_ID`, and an optional `FORTIK_DELEGATION`.
- POSTs to `{gateway}/v1/hook/claude-code` with a **3 s** timeout.

Exit semantics, verified against the Claude Code docs; a hook that crashes or times out fails **open**, and only exit 2 blocks:

| Fortik says | Hook does |
|---|---|
| allow | exit 0, no stdout; Claude Code's own permission flow continues (Fortik never auto-approves) |
| allow_reduced | exit 0, and `systemMessage` notes the reduced form (e.g. the snapshot) |
| hold or deny | stderr `fortik: <decision> (<class>) by <rule>: <reason>. action_id=…`, exit **2** |
| any error | exit **2** with "Fortik unreachable: refusing (fail closed)". This covers a timeout, connection error, non-2xx, malformed response, missing token or unreadable stdin. |

- The client never prints anything else to stdout. Shell profile noise can't affect it, because the client is a Go binary, not a shell script.

### 3.2 Install

`scripts/install-claude-hook.sh` writes the `hooks.PreToolUse` entry with matcher `"*"`:
- with `--user`: `~/.claude/settings.json`;
- otherwise: managed settings (`/Library/Application Support/ClaudeCode/managed-settings.json` on macOS, `/etc/claude-code/managed-settings.json` on Linux) with `allowManagedHooksOnly: true`;
- the hook `timeout` is 30 s, well above the client's 3 s, so Claude Code never times out first.

The script prints what it changes and backs up the previous file.

### 3.3 Server: gateway `POST /v1/hook/claude-code` (agent principal)

The server maps `tool_name` and `tool_input` to an Action. Unknown tools get verb `UNKNOWN`, which policy refuses.

**`Bash` → `system: "shell"`.** The command is parsed with `mvdan.cc/sh/v3/syntax`, and every simple command (including pipelines, `&&`, subshells and `$( )`) is classified. Dynamic constructs that can't be resolved (`eval`, variable command names, `sh -c "$X"`) set `dynamic: true`, which means hold.

| Category | Examples |
|---|---|
| READ allowlist | `ls`, `cat`, `head`, `grep`, `rg`, `find` (without `-delete`/`-exec`), `git status/diff/log/show/branch`, `pwd`, `echo`, `wc`, `which`, `env` |
| destructive | `rm -r/-f`, `git reset --hard`, `git clean -fdx`, `dd`, `mkfs`, `chmod`/`chown -R`, `shred`, `truncate`, `kubectl delete`, `terraform destroy` |
| git | `git push` → operation `push`/`force_push`, plus branch |
| egress | `curl`/`wget`/`http` → domain, `uploads` (`-d`, `--data`, `-F`, `-T`, `POST`), `pipes_to_shell` (`curl … \| sh`); `scp`/`rsync`/`ssh` to remote hosts → `external_hosts` |
| database | `psql`/`mysql`/`mongo` → `db_host`; `direct_db` = the host isn't in `hook.proxy_hosts` |
| cloud | `aws <svc> <op>` → `aws_action` (e.g. `s3 rm` → `s3:DeleteObject`), `gh` |
| privilege | `sudo`, `su`, `doas` |

- Target: `{commands, operations, external_hosts, uploads, pipes_to_shell, direct_db, db_host, dynamic, git, paths}`.
- `verb` is the most dangerous verb found.

**Other tools:**
- `Write`, `Edit`, `MultiEdit`, `NotebookEdit` → `system: "files"`, `verb: "WRITE"`, `target {path, sensitive_path}`. Sensitive paths include `.env*`, `~/.ssh`, `~/.aws`, `*.pem`, `.github/workflows/`, `id_rsa`, and `/etc`.
- `Read`, `Glob`, `Grep` → `files` READ (a secrets path counts as sensitive).
- `WebFetch`, `WebSearch` → `system: "http"`, READ, `target {domain, external}`.
- `Task` → `system: "a2a"`, DELEGATE, channel `hook_task`, `to_agent` = the same agent (a subagent). This is recorded; the a2a rules allow self-delegation.
- `mcp__<server>__<tool>` → `system: "mcp"`, `target {server, tool}`; the verb comes from §4.3.

### 3.4 Policy (new rule files)

| File | Rules |
|---|---|
| `shell.rego` | POL-501 `direct_db` (DB access bypassing the Fortik proxy), red · POL-502 `pipes_to_shell`, red · POL-503 destructive filesystem or infra commands, red, or yellow-hold on paths outside the project · POL-504 privilege escalation, red · POL-505 uploads or remote copy to external hosts, yellow hold (red with sensitive paths) · POL-506 dynamic/unparseable, yellow hold · POL-507 force push to a protected branch, red · POL-508 `aws` CLI mapped onto the AWS rules |
| `files.rego` | POL-511 writing a sensitive path, red (workflows: also POL-303 semantics) · POL-512 reading credential files, yellow hold |
| `http.rego` | External READ is allowed by default unless the http profile restricts it (POL-028); uploads → POL-505 |

`rule_systems` gains `shell`, `files`, `http`, `mcp`, `a2a` and `agents`. POL-005 still holds any non-READ on systems without rules.

The DB statements an agent runs through `psql` to the **proxy** are still decided statement by statement by pgproxy (Phase 1). The hook only decides whether the shell command may run.

---

## 4. agentgateway callout (MCP, A2A, HTTP egress)

### 4.1 Service

- `internal/agentgw`: one gRPC server on `agentgw.listen`, implementing:
  - **Envoy ext_authz v3 `Authorization/Check`**, for A2A and HTTP routes.
  - **agentgateway `ext_mcp` guardrails**, for MCP routes. The bindings are copied from `spikes/agentgateway/internal/extmcp` (Apache-2.0).
- **Identity:**
  - The callout authenticates the `Authorization: Bearer <agent token>` header with the same `AgentAuth` as the gateway.
  - Client-supplied `x-fortik-agent-id` and `x-fortik-instance-id` headers are **ignored**, and the verified values are injected through header mutation (a spike condition).
  - A missing or invalid token means deny.
- **Target and server identity** come from route-set headers: `x-fortik-route-agent` and `x-fortik-route-mcp`. These are set by the generated agentgateway config, which overrides any client value; `agentgw.a2a_targets` and `agentgw.mcp_servers` map routes to names.

### 4.2 Mapping

- **A2A:** `message/send`, `message/stream` and `tasks/send*` → DELEGATE.
  - Allowed: inject `X-Fortik-Delegation` with the new hop token.
  - `tasks/get` and `tasks/cancel` → READ, or WRITE to close the hop.
  - JSON-RPC batches are denied.
- **HTTP routes:** `system: "http"`, verb READ for GET/HEAD and EXPORT for anything with a body to an external host. `target {domain, external, method}`.
- **MCP `tools/call`:**
  - `system: "mcp"`, with the verb from `policies/fortik/mcp/data.json`: `{server: {tool: verb}}`, plus name heuristics for read tools (`get_*`, `list_*`, `search*`, `read*`, `query*`, `fetch*`, `find*`).
  - Memory-server write tools (`create_entities`, `add_observations`, `create_relations`, `delete_*`, `store*`, `remember*`) → REMEMBER or DELETE.
  - Everything else is EXECUTE, which POL-005 holds until mapped.
  - `tools/list`, `resources/read`, `prompts/get` → READ.
- **Delegation propagation:** an inbound `X-Fortik-Delegation` on any request (MCP, HTTP, A2A) is verified and passed to Decide (§1.2).

### 4.3 Fail mode and config

- Every refusal returns a deny response, and an internal error also denies.
- `fortik agentgw config` generates the agentgateway YAML: routes, `extAuthz` and `mcpGuardrails` pointing at the callout, `failureMode: deny` / `failClosed`, a 250 ms `requestTimeout`, the `x-fortik-route-*` header injection, `allowPartialMessage: false`, and a pinned version comment (v1.6.0, as tested in the spike).

### 4.4 Tests

- Direct gRPC tests for both services.
- End-to-end tests with the **real agentgateway v1.6.0 binary** (`spikes/agentgateway/bin/agentgateway`), plus small Go MCP and A2A servers written in the tests. If the binary is missing, these skip with an explicit message.

---

## 5. Timed app suspensions (plan Phase 3)

- **API** (security, or the agent's owner for its own agents; team scope needs security):
  - `POST /v1/overrides` with `{scope, scope_id, system, mode, duration_seconds | until_released, reason}` → 201 Override, plus `revoke_result` per system.
  - `POST /v1/overrides/{id}/release`, `POST /v1/overrides/{id}/extend {duration_seconds}`, `POST /v1/overrides/{id}/permanent`.
  - `GET /v1/overrides?agent_id=&status=`.
- **On create:**
  - Revoke live credentials for **that system only**, using the broker adapter's `RevokeAgent`. This uses the honest semantics already implemented: the GitHub token is deleted, Google tokens are dropped from the gateway, AWS gets a deny-by-issue-time, Postgres sessions are terminated.
  - Diary `override.created`.
- **Enricher** `input.context.overrides`: the active overrides for the agent (and its team, `agents.business_unit`) for the action's system.
- **Policy** `fortik.overrides`:
  - POL-030: mode `suspended` → deny ("<system> suspended until 11:55 by <who>: <reason>").
  - POL-031: mode `read_only` and the verb isn't READ → deny.
- **Restore worker:**
  - A DB sweep every `overrides.sweep_interval`, using `FOR UPDATE SKIP LOCKED`.
  - At `expires_at` it checks: the agent isn't QUARANTINED or KILLED, no newer active override exists, and no red action happened for that agent and system during the suspension.
  - Pass: status `restored`, Diary `override.restored`, and an owner notification (alert `info`).
  - Fail: status `blocked`, the override stays in force (blocked overrides are still enforced), and alert `override_restore_blocked`.

---

## 6. Approvals (pulled forward)

- `POST /v1/held/{id}/approve` with `{reason, use_safe_form}` and `POST /v1/held/{id}/deny` with `{reason}`.
- **Role:** security. The agent's sponsor is refused unless `approvals.allow_owner_approval` is set.
- Every vote goes into `held_approvals`. `approvals_required` is honoured (1 now; swarm releases need 2 in Phase 5). A held action can only be decided while it is `pending` and unexpired.

**Approve, red, with a safe form** (`use_safe_form: true`, kind `pg_rename`):
- Fortik executes the safe form itself on the upstream as the integration admin. For a rename: `ALTER TABLE … RENAME TO fortik_trash_…`; TRUNCATE also recreates `LIKE`.
- An undo handle of kind `pg_rename` is recorded first.
- Then `outcome = approved`, plus Diary `action.approved` and `safe_form.executed`.

**Approve, red, without a safe form:** refused (409 "red actions are never run unchanged").

**Approve, yellow:**
- Create an `approval_grants` row: one use, `approvals.grant_ttl`, bound to the agent and `action_hash`.
- `outcome = approved`. The agent retries the identical action within the TTL.
- The grants enricher sets `input.context.grant` when a usable grant matches, and the grants observer marks it used in the same transaction.

**Deny:** `outcome = denied`, Diary `action.denied`.

**Expiry:** a sweep marks pending holds past `expires_at` as `expired`.

---

## 7. Console additions

- **Agents → Held tab:** Approve (with "use safe form" when one exists) and Deny buttons, each with a reason. "NOT UNDOABLE" wording is kept.
- **Approvals page:** every pending held action.
- **Agents → Suspensions:** create a suspension (system, mode, duration or until released). A timer chip, e.g. "GitHub suspended · restores at 11:55", with Release now, Extend and Make permanent.
- **Agents → Instances:** live count against the cap (e.g. "9 of 6"), the instance list, and Pause extra.
- **Agents → Delegations:** inbound and outbound hops, chains drawn as A → B → C, and blocked bypass attempts.
- **Alerts page:** open alerts by severity, with Acknowledge and Resolve, and a live toast.
- **Settings → Agent types:** expected max instances, max agents, spawn rate, action rate.
- **Access editors** for `a2a`, `http` and `mcp`.

## 8. Ownership (parallel workstreams)

| WS | Owns |
|---|---|
| D1 delegation | `internal/delegation`, `policies/fortik/delegation`, the `internal/access` additions for `a2a`/`http`/`mcp` (validate, widens) plus POL-028/029 in `policies/fortik/access` |
| D2 agentgw | `internal/agentgw` (callout, config generator, e2e with the real binary), `policies/fortik/mcp` |
| D3 hook | `internal/hook` (client, mapping, shell classifier), the gateway route `/v1/hook/claude-code` handler (in `internal/hook`), `policies/fortik/rules/{shell,files,http}.rego` and their tests, `scripts/install-claude-hook.sh` |
| D4 population | `internal/population`, `internal/alerts`, `policies/fortik/population`, the agents-API surge check (as a hook the API calls) |
| D5 overrides | `internal/overrides`, `policies/fortik/overrides` |
| D6 approvals | `internal/approvals` (API, grants enricher and observer, pg safe-form executor), the held expiry sweep |
| D7 console | `web/console`, `internal/console` |

The lead wires `cmd/fortik/main.go`, the dev config, `scripts/dev-up.sh`, the demos and the docs.

**Shared-file rules:**
- Each policy package keeps its config in its own `policies/fortik/<pkg>/data.json` (read as `data.fortik.<pkg>`). Never edit `policies/fortik/data.json` or `decide.rego`.
- `rule_systems` in `common.rego` is updated by D3 only.
