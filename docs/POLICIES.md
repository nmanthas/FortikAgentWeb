# Policy catalogue (bundle `policies/`, query `data.fortik.decide.result`)

Rules are deterministic Rego. Each rule contributes a finding, `{rule_id, class, reason, reduced_form? | hold? | ladder? | deny?}`. `fortik.decide` then aggregates the findings:

- The worst class wins.
- The deciding rule is, within that class, a yellow finding that demands a hold first (it is why the action waits for a human), then the lowest rule id. (Phase 4: before this, a bulk email held by POL-203 was reported as POL-202.)
- Reduced forms from yellow findings are merged.
- The ladder target is the most restrictive level named by any red finding.
- Control gating can turn the decision into `deny`.

Thresholds are in `policies/fortik/data.json` and can be overridden per evaluation through `input.config`.

## Control ladder gating

| Rule | Level | Effect |
|---|---|---|
| POL-015 | unregistered agent | deny |
| POL-010 | KILLED | deny everything |
| POL-016 | SUSPENDED (Phase 4: suspend, team suspend, Fleet E-Stop) | deny everything until resumed; state and memory kept, nothing to re-earn |
| POL-011 | QUARANTINED | deny everything |
| POL-012 | ISOLATED | deny anything except internal READ |
| POL-013 | READ_ONLY | deny anything except READ |
| POL-014 | SUPERVISED | every yellow → hold for a human |

## Access profiles (Phase 2, `policies/fortik/access`)

They apply only when the agent's system has an access profile (gmail, drive, github, aws, postgres). The decision is deny, with no ladder change, checked after the control gate.

| Rule | Denies when |
|---|---|
| POL-020 | No profile for the system, or the mode/send/upstream is `none` |
| POL-021 | The profile is `read_only` and the verb isn't READ |
| POL-022 | Gmail `send: internal_only` and the message goes to an external recipient |
| POL-023 | Drive `share` is `internal_only`/`none` and the share is external, anyone, or not allowed |
| POL-024 | The GitHub repo isn't in `repos`, or the operation's permission is missing |
| POL-025 | The AWS service isn't in `services`, or the action matches `denied_actions` |
| POL-026 | The Postgres upstream isn't in the profile, or it is `read_only` and the verb isn't READ |
| POL-027 | Recipients exceed `max_recipients` |

## System-independent

| Rule | Class | Effect |
|---|---|---|
| POL-001 | red | any GRANT (permission, role or IAM change) → hold, step to ISOLATED |
| POL-002 | red | unknown verb or system → deny (no step-down) |
| POL-003 | red | sensitive data sent/exported/written to an external destination on any system other than Gmail/Drive → hold, ISOLATED |
| POL-005 | yellow | non-READ action on a known system with no dedicated rules yet (mcp, a2a, http, shell, memory) → hold |
| POL-007 | yellow | Gmail/Drive DELETE (not undoable in the MVP) → hold |
| POL-008 | yellow | spend above `spend_approval_usd` (500) on systems other than AWS, or any SPEND with no cost estimate → hold |
| POL-009 | red | malformed target field (boolean field not boolean, `external_domains` not a number) → deny (no step-down) |

## Postgres (Action produced by the Fortik proxy)

| Rule | Class | Effect |
|---|---|---|
| POL-101 | red | DROP TABLE/SCHEMA/DATABASE or TRUNCATE (any env) → hold, step to `pg_destructive_ladder` (READ_ONLY); rename safe form offered |
| POL-102 | yellow | DELETE/UPDATE with non-narrow WHERE, or over `pg_snapshot_row_threshold` (100) rows → `allow_reduced {snapshot_rows}` |
| POL-103 | yellow | Same as POL-102 but a snapshot can't be prepared (multi-table, no PK for UPDATE, over `pg_snapshot_max_rows`) → hold |
| POL-104 | red | COPY TO/FROM PROGRAM or a server file, or dangerous functions (`pg_read_file`, `dblink`, `pg_terminate_backend`…) → hold, ISOLATED |
| POL-105 | yellow | COPY … TO STDOUT (bulk export) → hold |
| POL-106 | yellow | DDL, maintenance, LOCK or SELECT INTO on prod → hold (no undo for DDL) |
| POL-107 | red | ALTER TABLE … DROP COLUMN on prod → hold, READ_ONLY |
| POL-108 | yellow | DROP COLUMN outside prod → hold |
| POL-109 | yellow | DO block or CALL (can't be inspected statically) → hold |
| POL-110 | red | UNKNOWN or missing statement type → deny (no step-down) |
| POL-111 | yellow | MERGE (can update/delete many rows, no undo in the MVP) → hold |
| POL-112 | yellow | upsert (`INSERT … ON CONFLICT DO UPDATE`), an INSERT whose `on_conflict_update` flag is missing, or `COPY … FROM STDIN` on prod → hold |

## Gmail / Drive (Actions produced by the Phase 2 app gateway)

| Rule | Class | Effect |
|---|---|---|
| POL-201 | red | SEND with sensitive data labels to external recipients → hold, ISOLATED |
| POL-202 | yellow | external SEND → `allow_reduced {delay_send_seconds: 120}` (the cancel window) |
| POL-203 | yellow | SEND to more than `gmail_bulk_recipients` (25) recipients → hold |
| POL-211 | yellow | Drive "anyone" link, or external share without sensitive data → `allow_reduced {narrow_share: domain, record_permission}` |
| POL-213 | yellow | any other Drive EXPORT to an external destination → hold |
| POL-212 | red | Drive share of sensitive data with an external grantee → hold, ISOLATED |

## GitHub

| Rule | Class | Effect |
|---|---|---|
| POL-301 | red | force-push or branch delete on a protected branch → hold, ISOLATED |
| POL-302 | yellow | push or force-push to a protected-adjacent branch (`release/`, `hotfix/`, `staging`), branch delete, PR close → `allow_reduced {record_ref}` |
| POL-302 | yellow | ordinary push or PR merge to a protected branch → `allow_reduced {record_ref}` |
| POL-303 | red | workflow, secret, webhook or deploy-key changes, or a push touching `.github/workflows/` → hold, ISOLATED |
| POL-305 | yellow | workflow dispatch (runs CI with repository secrets) → hold |
| POL-304 | red | any other GitHub deletion (repository, release, tag, environment), by verb DELETE or by a `delete_*` operation name → hold, ISOLATED |

## AWS

| Rule | Class | Effect |
|---|---|---|
| POL-401 | red | non-read `iam:`, `organizations:`, `sso:` or `identitystore:` actions → hold, ISOLATED |
| POL-402 | red | DELETE of resources (by verb **or** by action name: `Delete*`, `Terminate*`, `Remove*`, `Purge*`, `Destroy*`, `Deregister*`), or backup deletion/modification → hold (not undoable in the MVP) |
| POL-401 (sts) | red | any `sts:` action except GetCallerIdentity/GetAccessKeyInfo/DecodeAuthorizationMessage (role chaining would escape the session policy) → hold, ISOLATED |
| POL-406 | yellow | SSM run-command/session, Lambda invoke and code/config update, KMS decrypt, ECS run-task/exec → hold |
| POL-405 | yellow | S3 lifecycle rules and Route 53 record changes (can delete data later or redirect traffic) → hold |
| POL-404 | red | permission/sharing changes outside IAM (`Put*Policy`, `Attach*Policy`, `*Permission`, `Authorize*`, ACLs, KMS `CreateGrant`, snapshot/AMI sharing) → hold, ISOLATED |
| POL-403 | yellow | `est_cost_usd` above `aws_spend_approval_usd` (500) → hold |

## Memory (Phase 4, `policies/fortik/memory`)

Memory actions come from the memory gateway (`/gw/memory/{store}/{namespace}/...`, system `memory`) or from MCP servers listed in `data.fortik.memory.mcp_servers`. `input.context.memory.access` is the agent's memory access mode (`full`, `staging_only`, `none`).

| Rule | Class | Effect |
|---|---|---|
| POL-901 | gate | access `none` → deny every memory or memory-MCP action, READ included |
| POL-902 | gate | access `staging_only` → deny DELETE (reads and staged writes allowed) |
| POL-903 | yellow | REMEMBER → `allow_reduced {memory_staging: true}`: always staged, promoted after `memory.promotion_delay` (10 min) unless flagged, undoable (dropped) until then |
| POL-904 | yellow | memory write carrying a sensitive data label → hold |

A gateway REMEMBER that names its store and namespace is covered here, so POL-005 does not also hold it; memory DELETE is still held by POL-005. (The MCP rules keep POL-801–804.)

Population (Phase 4 addition): POL-705 also refuses actions by a copy whose status is `suspended`.

## Phase 3: Claude Code hook, MCP, delegation, copies, timed suspensions

**Shell** (`policies/fortik/rules/shell.rego`, system `shell`; targets come from the hook's classifier, which never runs anything). The hook refuses before anything runs, so these red rules do not step the agent down: the refusal and the record are the control.

| Rule | Class | Effect |
|---|---|---|
| POL-501 | red | a database client connecting directly, not through the Fortik proxy |
| POL-502 | red | downloaded or decoded content piped into a shell or interpreter |
| POL-503 | red / yellow | destructive command on catastrophic, remote or disk targets (red); outside the project, on the project root, or unknown (yellow hold) |
| POL-504 | red | privilege escalation (sudo, su, doas) |
| POL-505 | yellow | uploads, remote copy, remote shell → hold (red with secrets) |
| POL-506 | yellow | dynamic or unclassified command → hold |
| POL-507 | red / yellow | force push or branch deletion on a protected branch, GitHub CLI repo deletion or secret changes (red); force push to an unknown branch, PR merges and workflow runs (yellow hold) |
| POL-508 | red / yellow | AWS CLI calls judged like AWS actions (red identity/deletion, yellow hold for other non-read calls) |
| POL-511 | red | writing a sensitive path (credentials, agent settings, CI workflows, shell rc files, system) |
| POL-512 | yellow | reading credential files → hold |

**MCP** (`policies/fortik/mcp`): POL-801 unmapped tool → hold; POL-802 MCP DELETE, SEND or EXPORT → hold; POL-803 the verb disagrees with the verb table → deny; POL-804 malformed MCP target → deny.

**Delegation** (`policies/fortik/delegation`; `input.context.delegation`, inferred from open inbound delegations when no token is presented):

| Rule | Effect |
|---|---|
| POL-601 | an upstream agent in the chain could not perform this action itself (the same control and access gates, evaluated as that agent, at any depth) → deny; the originating agent steps down (`delegation.bypass_origin_level`, SUPERVISED), the executor does not |
| POL-602 | the delegation is deeper than `max_depth` |
| POL-603 | a DELEGATE to an agent the delegator's a2a profile does not list, or deeper than the profile's max_depth |
| POL-604 | the presented delegation token is invalid, expired or not the agent's |
| POL-605 | the action is outside a delegated task's scope. The delegator may declare `target.task_scope` `{systems, verbs, domains}` on the DELEGATE. The scope is signed into the delegation token and stored on the hop, and a child hop's scope is the intersection with every ancestor's (it never widens; nothing in common becomes deny-all). Every scope the executor acts under must allow the action. An external action whose destination cannot be identified does not fit a domain-restricted scope (fail closed). A DELEGATE is exempt from the system and verb checks (the scope travels with it, narrowed). Always enforced, even in observe mode |

**Copies and populations** (`policies/fortik/population`):

| Rule | Effect |
|---|---|
| POL-701 | spawn: the agent's live copies (suspended included) are at or above `copy_cap`: the new copy is refused and gets no credentials |
| POL-702 | spawn: the agent type's live total is at or above `expected_max_instances` |
| POL-703 | spawn: spawns in the last minute exceed the rate or baseline limit, or the type is in its spike cooldown |
| POL-704 | actions in the last minute are at or above `action_rate_per_min` |
| POL-705 | the agent requires instances and the action's instance is missing, unregistered or stale; or the instance is paused, refused, stopped or suspended |
| POL-706 | only spawn registrations exist on system `agents` |

**Timed suspensions** (`policies/fortik/overrides`; `input.context.overrides` holds the overrides in force for the agent or its team):

| Rule | Effect |
|---|---|
| POL-030 | an override in mode `suspended` covers the action → deny until it is released or expires |
| POL-031 | an override in mode `read_only` covers the action and the verb is not a read → deny |

An override on system S covers an action when:
- the action's system is S; or
- the action **reaches** S (`target.reaches`): a Claude Code shell command that runs `gh` or a git remote operation (push, fetch, pull, clone, ls-remote, submodule, lfs, remote, send-pack, request-pull) reaches `github`, and the AWS CLI reaches `aws`; or
- the action is a copilot connector token whose upstream serves S (`target.upstream_systems`).

Reaching only ever adds overrides, never removes one. The refusal names the suspended system.

## Phase 5: swarms, baselines, hidden signals, shadow agents

| Rule | Class | Effect |
|---|---|---|
| POL-113 | yellow | bulk read of sensitive data: a SELECT from a table carrying a sensitive data label, estimated above `pg_bulk_read_rows` (5000) rows read → hold. The estimate is the rows **read** (the largest plan node, so `json_agg(…)` over the whole table counts every row). For a parameterised read it is at least the table size, unless it is a unique-key lookup, because generic plans use default selectivities. Nothing is planned over a view or other non-table relation before the decision |
| POL-114 | yellow | a SELECT of sensitive data with **no** row estimate (a function outside the safe built-ins, a view, a pipelined statement, an EXPLAIN error or timeout, a never-analysed table) → hold (fail closed: unknown size is never treated as small) |
| POL-651 | yellow | swarm breaker tripped: the same action (action hash; a Gmail SEND is identified by its recipient set) by more than `swarm.breaker_n` (5) distinct agents or registered copies in the window → every matching call is held for **two** distinct approvers. Approval grants carry their approval count, and a grant approved by fewer people than a hold needs releases nothing. A trip raises identical pending holds to two approvers. Postgres row writes are not counted |
| POL-652 | gate | a frozen (killed) swarm refuses DELEGATE, delegation to its members, and new copies |
| POL-653 | gate | a member of a frozen swarm may only READ and is issued no credentials |
| POL-659 | gate | malformed swarm context → deny (fail closed) |
| POL-660 | yellow | above-normal volume → hold. The baseline is `first_use_ceiling` (200) for a verb never used, at least that ceiling and at most 5× it while fewer than 6 hours are active, 5× the median with < 3 days of history, and mean + 3σ after that. It never fires at or below the busiest hour already seen, and only executed calls count. An *escalation* finding: green becomes a yellow hold, and a yellow that would run reduced is held instead. Dropped on anything already held, denied or red |
| POL-661 | yellow | malformed baseline context → hold (fail closed) |
| POL-671 | yellow | a URL query carries an encoded payload (base64, hex or percent-encoded) of at least `map.encoded_param_min` (256) characters → hold. The payload can be in one parameter's name or value, or split over several parameters. Parameters are split on `&` and `;`. A part is measured by its runs of encoding-alphabet characters, so an inserted `.` or `%26` does not hide it. Signature parameters of GCS, S3 and Azure signed URLs on the provider's own hosts are exempt. Adapters send only a summary (`target.encoded_params`), never the value |
| POL-680–684 | gate | a discovered agent with no owner may not reach outside, GRANT, DELEGATE, SEND, EXPORT or SPEND; while its credential is flagged for revocation it may only READ |
| POL-689 | gate | malformed shadow context → deny (fail closed) |

A hold needs as many distinct approvers as the most demanding finding asks for (`approvals_required`, default 1).

## Milestone 1: NetSuite (`policies/fortik/rules/netsuite.rego`; access gates in `fortik.access`)

The gateway produces `target.operation` (get, list, create, update, upsert, delete, transform, query; observed_change for audit records), `record_type`, `record_id`, `to_record_type`, `fields` (names only) and `query_tables`/`limit`. Lists live in `data.json` `config.netsuite`. Nothing is classified as a payment or a bank change without that evidence in the request.

| Rule | Class | Effect |
|---|---|---|
| POL-1001 | yellow | update of one record → allowed only with `record_snapshot` (the changed fields' previous values kept for undo) |
| POL-1002 | red | delete → held, never run unchanged; step down READ_ONLY |
| POL-1003 | yellow | create or transform into a payment record type → held for `payment_approvals` (2) approvers |
| POL-1004 | yellow | a write to a bank-details record type, or to a vendor/employee/customer/partner field matching a bank pattern → held |
| POL-1005 | red | create/update/delete of financial setup (accounting periods, accounts, subsidiaries, currencies, tax) → held; step down READ_ONLY |
| POL-1006 | red | malformed target → denied (fail closed) |
| POL-1007 | access | record type, or a SuiteQL table, outside the profile's `record_types`; a query whose tables cannot be identified under a restricted profile → denied |
| POL-1008 | access | SuiteQL while the profile's `suiteql` is false → denied |
| POL-1009 | yellow | upsert (PUT) → held (no verified undo) |
| POL-1010 | access | the action's tenant (`target.integration_id`, e.g. `netsuite:acme`) is not in the profile's optional `integrations` (`["*"]` or tenant ids). Applies to every transport, REST and MCP, and to Salesforce, ServiceNow and SAP as well; under a restricted profile an action naming no tenant is refused (fail closed) |

**One tenant, several transports (integration platform M1).** REST calls (`target.transport: "rest_api"`) and MCP calls (`"mcp"`, from QuickStart or a full account's AI Connector Service) are decided as the same system `netsuite` with the same access profile, suspensions, levels, delegation checks, approvals and the rules above. `policies/fortik/tests/transports_test.rego` asserts the same decision and rule for the same operation on both transports (reads, read-only writes, record types, deletes, payments, bank details, POL-1010, a transport switch for a refused tenant). The one difference is explicit and configurable: `config.netsuite.mcp_writes_require_approval` (default `true`). While it is true, an MCP update is held (POL-1120) where a REST update runs after a snapshot (POL-1001). Set to false, an MCP update whose fields Fortik can snapshot (`undo_possible`, `understood`) gets POL-1001 like REST; deletes, payments, bank details, financial setup and every other MCP write stay held.

## NetSuite MCP: QuickStart and the AI Connector Service (`policies/fortik/rules/netsuite_quickstart.rego`; mappings `policies/fortik/netsuite_quickstart/data.json`, `policies/fortik/netsuite_mcp/data.json`)

Agents call a NetSuite MCP server's tools through Fortik's endpoint (`/mcp/netsuite_quickstart`, or `/mcp/netsuite/<tenant>`, on the gateway). Each `tools/call` is decided as system `netsuite` with:
- `target.transport: "mcp"` and `target.integration` (`netsuite_quickstart` or `netsuite_mcp`), plus `target.integration_id` (the tenant);
- the tool and its mapped `operation`;
- `record_type`, `record_id` and field names (never values);
- `args_sha256`, which binds an approval to the exact arguments.

So the NetSuite rules above apply as well: POL-1002 deletes, POL-1003 payments, POL-1004 bank details, POL-1005 financial setup and POL-1010 tenants. The `netsuite` access profile and timed `netsuite` suspensions apply too. POL-1001 (snapshot-and-allow) applies to an MCP update only when `config.netsuite.mcp_writes_require_approval` is false; by default MCP writes are held instead. The AI Connector Service mapping is empty (its tools depend on the SuiteApps installed in each account and none was available to read): every AI Connector tool is `UNKNOWN` and refused (POL-002) until it is mapped. POL-1101 reasons begin "QuickStart call refused" or "NetSuite MCP call refused".

| Rule | Class | When |
|---|---|---|
| POL-1101 | red, deny | the tool is not in the server's current `tools/list`, the tool list was not verified for the current settings or token, or the arguments do not match the tool's discovered input schema |
| POL-1102 | red, deny | `set_preferences` on a protected preference (`MCP_SERVER_ENABLED`) |
| POL-1103 | yellow | any other company preference change → held for 2 approvers |
| POL-1104 | red | attachment delete → held, never run unchanged |
| POL-1105 | yellow | money movement or ledger change → held for `payment_approvals` (2) approvers: transforms or record actions whose id matches `payment_transform_patterns` (`payVendorBill`, `invoiceToCustomerPayment`, …), record actions `approve`/`void`/`unapply`, and create/update/delete of `money_record_types` (BankTransfer, VendorPayment, JournalEntry, …) |
| POL-1106 | yellow | `send_record_email` or `submit_contact_support_request` → held (external effect; a repeat sends twice; not undoable) |
| POL-1107 | yellow | a write that could not be fully understood (e.g. an update naming no fields) → held for review |
| POL-1108 | access | the tool is not in the profile's optional `quickstart_tools` |
| POL-1120 | yellow | every other QuickStart write → held for approval. The reason says whether undo will be prepared. |

- **Tools outside the mapping:** a tool missing from the mapping is verb `UNKNOWN` and is denied (POL-002).
- **Approved calls:** an approved yellow call runs only when the agent repeats the identical call, once, within `approvals.grant_ttl`. The call is decided again at that point: level, suspension, delegation, schema and policy version are all re-checked.
- **Red holds:** red holds are never released by an approval.

## Salesforce, ServiceNow, SAP (`policies/fortik/rules/saas.rego`; access gates in `fortik.access`)

REST calls (`/gw/<provider>/...`, `target.transport: "rest_api"`, `operation`, `object`, `record_id`) and MCP calls (`/mcp/<provider>/<tenant>`, `transport: "mcp"`, the mapped tool) are decided as system `salesforce`, `servicenow` or `sap`, with `target.integration_id` (the tenant). Fortik has no verified undo for these providers, so every change needs a human.

| Rule | Class | Effect |
|---|---|---|
| POL-1201 | yellow | a write (create, update, upsert, batch) → held |
| POL-1202 | red | a delete → held, never released unchanged |
| POL-1203 | yellow | an action, flow or function (EXECUTE) → held |
| POL-1205 | yellow | any other side effect (send, export, grant, …) → held |
| POL-1204 | red, deny | malformed target: no transport or no tenant |
| POL-1206 | red, deny | MCP: the tool is not in the server's current, verified tool list, or the arguments break its schema |
| POL-1211 | access | REST: the object (Salesforce object, ServiceNow table, SAP `<SERVICE>/<EntitySet>`, compared lower-case) is not in the profile's `objects`; a non-describe call naming no object under a restricted list is refused |
| POL-1212 | access | MCP: the tool is not in the profile's optional `mcp_tools` |
| POL-1213 | access | Salesforce Agent API: the Agentforce agent (BotDefinition id) is not in the profile's `agentforce_agents` (absent = none) |
| POL-1214 | yellow, hold | Salesforce Agent API: a message to an Agentforce agent (it may act inside Salesforce, where Fortik cannot see or undo it); allowed without approval only when the profile sets `agentforce_messages: "allow"`. A message that is not an EXECUTE is denied red |
| POL-1010 | access | the tenant is not in the profile's optional `integrations` (shared with NetSuite) |

POL-020 (no profile, or mode none) and POL-021 (read_only and not READ) apply as for NetSuite. Paths outside each provider's API and unmapped MCP tools are `UNKNOWN` and denied (POL-002). `policies/fortik/tests/saas_test.rego` asserts the same decision and rule for the same operation over REST and MCP.

## Phase 6: copilot connectors and observe mode

| Rule | Class | Effect |
|---|---|---|
| POL-690 | red | the copilot connector is not active (disabled): no tokens are issued (defence in depth; the broker checks first) |
| POL-691 | red | malformed connector target, or the token's verb is not READ/WRITE, or write scopes are presented as READ → deny (fail closed) |

A connector token is system `connector`, with verb READ when every scope is read-only and WRITE otherwise. A READ_ONLY agent's copilot therefore still gets read-only tokens, never write ones. The ladder, kills and timed suspensions of the upstream's systems apply through the usual gates.

**Observe mode** (`enforcement.mode: observe`, or per agent with `PUT /v1/agents/{id}/enforcement`). Policy holds, denies and reductions become `allow`, with an `observed` block recording what would have happened. No automatic step-down is applied; the would-be one is recorded.

These rules are **always enforced**, even in observe mode (`policies/fortik/observe/data.json`), because they are not policy opinions about risk:

| Group | Rules |
|---|---|
| Unknown or malformed actions | POL-002, POL-009 |
| Levels set by people and the ladder | POL-010–013, POL-016 |
| Unregistered agents | POL-015 |
| Timed suspensions | POL-030, POL-031 |
| Delegation | POL-601, POL-602, POL-604 |
| Frozen swarms and malformed contexts | POL-652, POL-653, POL-659, POL-661 |
| Discovered agents | POL-680, POL-689 |
| Copies and populations | POL-701–706 |
| MCP verb mismatch and malformed targets | POL-803, POL-804 |
| Memory cut | POL-901, POL-902 |
| Connectors | POL-690, POL-691 |
| Postgres unparseable statements | POL-110 |

A fail-closed outcome (Fortik could not decide) is never relaxed either.

**Replay gate:** `testdata/replay/corpus.jsonl.gz` (10,000 recorded inputs) is evaluated by `go test ./internal/replay` and `fortik replay run`. A change of class, decision, rule or step-down fails the build until it is reviewed.

## Adapter contract

These are the Target keys each adapter must set:

- **postgres** (built): `statement_type`, `environment`, `tables`, `schema`, `table`, `has_where`, `where_narrow`, `undo_preparable`, `volatile_where`, `on_conflict_update`, `merge_has_delete`, `dangerous_functions`, `protocol`, `statement_count`, `fingerprint`, `normalized_sql`, and `safe_form` (for DROP/TRUNCATE). `payload_summary.rows_estimate` and `payload_summary.data_labels` go in the payload summary.
- **gmail** (Phase 2): `to`, `cc`, `bcc`, `external_domains`. `payload_summary.recipients` and `payload_summary.data_labels` go in the payload summary.
- **drive** (Phase 2): a share or link maps to verb `EXPORT`, with `operation: "share"`, `share_type` (`user|group|domain|anyone`) and `external`. Drive shares deliberately map to EXPORT, not GRANT, so the plan's yellow "narrow and record permission" path applies instead of the always-red GRANT rule.
- **github** (Phase 2): `repo`, `branch`, `operation`, `protected`, `paths`. Branch names are normalised (`refs/heads/` stripped, lower-cased) and operations lower-cased before matching.
- **aws** (Phase 2): `iam_action`, `resource`, `backup`, plus `est_cost_usd`.
- **shell** (Phase 3, the Claude Code hook's classifier): `classifier` (`fortik-shell/1`), `commands`, `operations`, `external_hosts`, `external`, `uploads`, `upload_sensitive`, `pipes_to_shell`, `direct_db`, `db_host`, `dynamic`, `privilege`, `git`, `gh`, `destructive`, `aws_actions`, `paths`, `sensitive_writes`, `sensitive_reads`, `reaches`. Never the command text.
- **connector** (Phase 6): `connector_id`, `vendor`, `upstream`, `upstream_systems`, `scopes`, `write`, `grant_type`, `grant_id`, `connector_status`.
