# SaaS integration milestones (after the six MVP phases)

This rollout extends the finished MVP. It does not rebuild it.

| Milestone | Scope | Status |
|---|---|---|
| **M0** | Current-state audit; shared foundation for the three management use cases (authority laundering, swarm surge, multi-hop delegation), human approval, containment receipts, coverage reporting, the SaaS connector contract | Done 2026-10-25, awaiting review |
| **M1** | NetSuite connector | Built and tested against a LOCAL FAKE 2026-10-25; live verification blocked on a NetSuite sandbox |
| M2 | Salesforce Agentforce | After M1 approval |
| M3 | SAP | After M2 approval |
| M4 | ServiceNow, and a cross-SaaS chain | After M3 approval |

Each milestone is tested, reported, and then stops for developer approval.

**Unified multi-transport platform** (a later brief: REST API + MCP under one logical integration per tenant):

| Milestone | Scope | Status |
|---|---|---|
| **UM0** | Audit, baseline tests, gap analysis | Done 2026-10-27 |
| **UM1** | Unified integration model; NetSuite dual transport (REST + MCP per tenant); QuickStart preserved | Built and tested 2026-10-27, awaiting review (see the section at the end) |
| UM2 | One card per provider with a REST / MCP dropdown; Salesforce, ServiceNow and SAP (REST + MCP) | Built and tested 2026-10-28 (the developer asked for all four providers in one pass); live verification blocked on tenants (see the last section) |

## M0 gap analysis (2026-10-25)

### 1. Already implemented and tested (reused, not rebuilt)

- **Delegation authority:**
  - signed delegation tokens (HMAC-SHA256, domain-separated) carrying root, chain, depth, task id and expiry;
  - hops with parent ids;
  - inferred chains when no token is presented (fail closed).
  - **POL-601** evaluates every upstream agent's own level and access profile, which is the intersection of permissions: a downstream agent cannot use broader permissions for its caller's task.
  - **POL-602/603** enforce depth limits (config and per-delegator profile). **POL-604** refuses invalid, expired, revoked or misdirected tokens.
  - The origin agent steps down; the relay does not.
  - Through the real agentgateway v1.6.0: `scripts/demo-agentgateway.sh`, `TestEndToEndAgentgateway`.
- **Swarm and surge:**
  - copy caps (POL-701);
  - agent-type populations (POL-702);
  - spawn rate and baselines (POL-703), action rate (POL-704);
  - registered-instance requirement (POL-705);
  - registration-surge guard (max agents per type);
  - the Max-5 identical-action breaker, swarm objects and kill-swarm;
  - aggregated alerts and Slack notification.
- **Human in the loop:**
  - holds;
  - approve/deny by an authenticated approver role;
  - one-time grants bound to the exact action hash, so an approval never covers a different target;
  - grant expiry; revalidation at execution (the level, freeze and grant consumption are re-checked);
  - red actions approved only in a safe form;
  - two-approver holds and swarm release;
  - two API tokens are not two people.
- **SSO:** OIDC login with `role_claim` + `role_map` (group or role claim to Fortik roles), session cookies, CSRF, and security-role checks on kill, quarantine, access widening and privileged operations.
- **Evidence:** the hash-chained Diary, signed exports, containment operations with per-step results.

### 2. Implemented but not verified against real systems

- Google Workspace, GitHub and AWS adapters, the copilot connector broker, and shadow discovery for those systems: tested against local fakes only.
- OIDC against Microsoft Entra ID or Okta: no tenant was available. Both issue standard OIDC ID tokens with a groups (or roles) claim, which `role_claim`/`role_map` consumes.
  - Entra ID's group *overage* (too many groups means the claim is replaced by a link) is not handled. Use Entra app roles (`role_claim: roles`) instead.

### 3. Partially implemented (completed in M0)

- **Delegation:** there was no **task scope** (what the delegated task may do) and no **correlation id** across a chain. Added (POL-605).
- **Containment:** results were reported, not verified. Added **receipts** that re-read authoritative state.
- **Coverage:** no capability model existed. Added **per-dimension coverage** with A/B/C/D classes.

### 4. Missing

- NetSuite, Salesforce, SAP and ServiceNow connectors (M1–M4).
- IdP-side identity suspension (Entra/Okta user disable, session revocation). Not built, because no tenant exists to verify it against.
- NGINX reverse-proxy enforcement. Not built: it only enforces where traffic can be forced through it, and that must be verified per SaaS (see §14 of the brief).
- eBPF: out of scope unless approved.

### 5. Dependencies needed from the developer

- NetSuite: a **test (sandbox or developer) account** and an **administrator who can create an integration record and a role**, plus the account ID. Then we verify, in that account:
  - REST web services and SuiteQL access;
  - OAuth 2.0 client credentials (machine-to-machine);
  - the System Notes and Login Audit Trail visibility;
  - whether the account exposes its AI agent or the NetSuite AI connector (MCP) service, and through which documented interface.

  None of this is assumed until verified in the account.
- Salesforce: the Developer Edition org that already exists (`sf org login web`; **rotate the password that was pasted in chat**), with API access and an Agentforce agent.
- SAP: which SAP product and tenant (S/4HANA Cloud, SuccessFactors, Ariba, BTP Joule...); each has a different API and agent model.
- ServiceNow: a Personal Developer Instance.
- Entra ID / Okta: a test tenant, to verify SSO group mapping and identity suspension.

### 6. Must not regress

- The six phase demos (191 checks).
- The agentgateway demo (11 checks).
- The Go suite with `-race` (`make ci`); the 506 policy tests; the 182 console tests.
- The replay gate (10,000 inputs).
- The chaos, load and Compose smoke tests.

## M0 design notes

### Delegated task scope (POL-605)

- A DELEGATE may declare `target.task_scope: {systems, verbs, domains}`.
- The hop stores the scope **intersected with every ancestor's scope**, so it never widens. An empty intersection is the deny-all marker `["-"]`, never "unrestricted".
- The scope is signed into the delegation token. Every hop of one delegated task shares a `correlation_id` (the root DELEGATE's action id).
- At decision time the action must fit **every** scope the executor acts under (token and open inbound hops).
- External destinations are taken from `domain`/`host`, recipients' domains, or shell hosts. An external action whose destination can't be identified fails a domain-restricted scope.
- POL-605 complements POL-601: POL-601 limits the delegatee to what each *agent* may do; POL-605 limits it to what the *task* may do.

**Handling of incomplete delegation evidence:**

| Case | Behaviour |
|---|---|
| Missing token, open inbound hops | Chain inferred from all open hops: every origin's restrictions and every scope apply |
| Invalid, expired, revoked or misdirected token | POL-604 deny |
| Unknown or unregistered upstream agent | POL-601 deny (it has no permissions) |
| Malformed chain, scope or source | Deny (fail closed) |
| Depth over limit | POL-602/603 deny |
| Delegation through a channel Fortik does not instrument | **Not observable** |

The last case can't be inferred from unrelated audit records. It is reported as a coverage gap (`delegation_visibility`), not guessed.

### Containment receipts

`GET /v1/containment/{op_id}/receipt` re-reads the state the operation should have produced:
- the level;
- `suspended_at`;
- live copies and recent heartbeats;
- memory access mode;
- active copilot grants;
- open delegations.

It also lists the steps as reported, the residual access the systems reported (e.g. "STS tokens cannot be recalled", "tokens minted by other processes expire within 1 h"), and the linked Diary seqs.

| Outcome | Meaning |
|---|---|
| `confirmed` | Every verifiable check holds, no step failed, no residual access |
| `partially_confirmed` | The main state holds, but something failed or remains |
| `failed` | The main state does not hold, including later drift, e.g. the agent was re-enabled |
| `unknown` | Nothing re-readable (e.g. an external queue) |

### Coverage (`GET /v1/coverage`)

- Per integration, nine dimensions, each `verified_live` / `verified_test` / `implemented` / `unsupported` / `not_built`, with evidence (the test or demo) and gap/fix text.
- The class (A/B/C/D) needs **live** verification on a **connected** integration. Test-only verification and disconnected integrations are D.
- There is deliberately no single score.
- Declarations live in `internal/coverage/declarations.go`. A test refuses any verified claim without named evidence.

### SaaS connector contract (`internal/saas`)

Every SaaS connector (M1–M4) implements the same contract:
- `Health` (tenant identity);
- `Declaration` (capabilities, for coverage);
- `Inventory` (agents the documented APIs expose, with a `Complete` flag);
- `Activity` (events normalized to Fortik Actions, marked `Observed` when they arrive after execution);
- `Contain` (idempotent);
- `Verify` (an authoritative read-back for receipts).

It plugs into the existing agents registry, Decide, the Diary and receipts. It is not a parallel engine.

## M1: NetSuite (2026-10-25)

**Live status: not verified against NetSuite.** No account was available. Everything below was exercised against `internal/netsuite/fakens`, a local fake of the documented interfaces. The connector probes a real account on *Test connection* and `GET /v1/saas/netsuite`, and reports which capabilities actually work there.

### How it works

| Part | Mechanism | Class once verified live |
|---|---|---|
| Authentication | OAuth 2.0 client credentials (machine to machine) | — |
| Pre-execution enforcement | Gateway at `/gw/netsuite/...` | **A**, for agents routed through Fortik |
| Undo | Snapshot of changed fields, restored by PATCH | **B** (verified undo) |
| Post-execution detection | SuiteQL on system notes | **C/B** |
| NetSuite-side revocation | No API verified | **D** |
| Agent inventory | No verified API; mapped entities only | — |

**Authentication.**
- Fortik signs a JWT (PS256 or ES256) with the private key of a certificate uploaded to NetSuite's client-credentials setup. The header carries `kid` = certificate ID; the claims are `iss` = client ID, `scope` = `rest_webservices`, `aud` = the token endpoint, `iat` and `exp`.
- It exchanges the JWT at `https://<account>.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token` for an access token, which is cached. **Agents never receive it.**

**Pre-execution enforcement.**
- Agents call `/gw/netsuite/services/rest/record/v1/...` and `/gw/netsuite/services/rest/query/v1/suiteql`. Each request becomes an Action (operation, record type, record id and field *names*; SuiteQL tables) and goes through Decide before it is forwarded.
- Unknown endpoints are refused (POL-002).
- This prevents only what is routed through Fortik.

**Undo.**
- An update is allowed only after the previous values of the fields it changes are read and stored **encrypted in Fortik's secret store**. The undo handle holds only a pointer.
- `POST /v1/undo/{id}` PATCHes them back. It is last-writer-wins, and the result says so.

**Post-execution detection.**
- SuiteQL on the system notes (`id > cursor AND name IN (mapped entities)`), metadata only. Each change is evaluated by policy (`decide.Service.Evaluate`, no side effects) and recorded as **observed after execution** with the would-be rule.
- A would-be refusal raises a `saas_policy_violation` alert. Events are deduplicated, the cursor and last-success time are stored, and the worker runs every 5 minutes (`POST /v1/saas/netsuite/sync` runs it now).

**Revocation.**
- Fortik drops its own token and refuses gateway calls.
- **No documented API was verified** for disabling an entity's NetSuite access or revoking its tokens. The kill report and receipt say "NOT revoked in NetSuite" (so the receipt is `partially_confirmed`).

**Inventory.**
- No verified API lists NetSuite AI agents. Agents are mapped to the NetSuite entity they act as (`agent_map`), and each entity is checked.
- Inventory is reported `complete: false`.

### Policies (POL-1001..1009)

| Rule | Class | Effect |
|---|---|---|
| POL-1001 | yellow | Update: snapshot first |
| POL-1002 | red | Delete: held; step down READ_ONLY |
| POL-1003 | yellow | Payment record create or transform: held, 2 approvers |
| POL-1004 | yellow | Bank or payment details: held |
| POL-1005 | red | Financial setup changes: held |
| POL-1006 | red | Malformed target: denied |
| POL-1007 | access | Record type or SuiteQL table outside the profile: denied |
| POL-1008 | access | SuiteQL not allowed by the profile: denied |
| POL-1009 | yellow | Upsert: held (no verified undo) |

- The access profile is `{"mode":"none|read_only|read_write","record_types":[...]|["*"],"suiteql":bool}`.
- Delegation (POL-601/605), levels, overrides and swarms apply as for every system.
- Classification uses only what the request shows (record type, field names).

### To verify on a real NetSuite sandbox (open questions)

1. The token endpoint accepts the assertion as built, including `scope` as a JSON array and PS256.
2. The SuiteQL `systemnote` table and the columns `id, date, field, name, recordid, recordtypeid, role, context` exist and `name` is the entity id. The date format is parsed (otherwise ingestion time is used and recorded as such).
3. The `employee` columns `entityid`, `isinactive`.
4. REST record type names (case), and the payment and bank record types in `data.json` (`config.netsuite`). For example, `customrecord_2663_entity_bank_details` belongs to the Electronic Bank Payments SuiteApp, if installed.
5. PATCH with `null` to clear a field that was empty before the update (undo).
6. **What "the one agent" is:**
   - NetSuite's own AI feature: then it is not routed through Fortik and is only observable via system notes;
   - a customer agent using NetSuite's MCP / AI connector service: route it through agentgateway, once that endpoint is confirmed in the account;
   - a custom integration: route it through `/gw/netsuite`.
7. Whether any documented API can disable the agent's entity or role. If one exists, `Contain` can become verified.

### Reproduce

```bash
# with the server running (any port; set FORTIK_API / FORTIK_GATEWAY)
./scripts/demo-netsuite.sh                                   # LOCAL FAKE: 24 checks
FORTIK_NETSUITE_REAL=1 ./scripts/demo-netsuite.sh            # after configuring a real sandbox in the console
FORTIK_TEST_PG_URL=... go test ./internal/netsuite/...       # fake-backed tests
```

## NetSuite QuickStart MCP: QuickStart Milestone 1 (2026-10-25)

This is a separate brief from the classic NetSuite integration (M1 above): the **QuickStart MCP server** at `https://my.quickstartapi.netsuite.com/mcp`, which uses Streamable HTTP and a personal access token (PAT), sent as `Authorization: Bearer <PAT>`. No integration record, certificate, client ID or SuiteTalk REST settings are involved. Sources: Oracle, "Set up the QuickStart MCP server" and "OAuth client registrations" (read 2026-10-25).

### Gap analysis (before this milestone)

- **The agentgateway MCP path:** agentgateway calls Fortik's ext_mcp callout. `internal/agentgw/mapping.go` maps every MCP call to `system: "mcp"`, with target `{server, route, method, tool}`. That is why a NetSuite suspension does not cover an MCP server.
  - There is no mapping from an MCP server to its business system.
  - Tool arguments are not decoded.
  - The upstream credential would sit in agentgateway's own configuration, not in Fortik's secret store.
- **No client of Fortik's own:** Fortik had no MCP client, so it could neither check an upstream MCP server nor list its tools.
- **Reused:**
  - integration settings, with secrets only in the secret store (`internal/integrations`);
  - the connection-tester registry;
  - the Diary;
  - coverage declarations;
  - the Integrations console page, with forms rendered from the schema.

### What was built (Milestone 1: read-only connectivity)

- **Integration `netsuite_quickstart`.** Fields:
  - `name`;
  - `tenant_label` (required);
  - `endpoint_url` (default: the documented endpoint);
  - `transport` (`streamable_http`);
  - `auth_type` (`personal_access_token`);
  - `token_expires_on` (optional; QuickStart does not report it);
  - secret `personal_access_token`, stored only in the secret store and write-only through the API. A pasted `Bearer ` prefix is refused.
- **`internal/mcpclient`:** Fortik's Streamable HTTP MCP client. It sends `initialize` (requesting `2025-06-18`), then `notifications/initialized`, then pages through `tools/list` (cursor), then closes with `DELETE`.
  - It accepts JSON and SSE responses, `Mcp-Session-Id` and `MCP-Protocol-Version`.
  - It never follows redirects, and never calls a tool.
  - Malformed tool definitions are excluded one by one, with a reason. Duplicate names exclude every definition of that name.
  - Every failure has a kind: `auth_failed`, `token_expired` (only when the server's message says expired or revoked), `permission_denied`, `mcp_init_failed`, `tool_discovery_failed`, `unavailable`.
- **`internal/nsquickstart`:** the connection tester (Test connection), connection states and the status API. Possible states:
  - `not_configured`;
  - `saved_not_tested`, which also applies after any settings or token change;
  - `connected`;
  - `connected_limited` (no tools capability, no tools, or malformed tools excluded);
  - `auth_failed`, `token_expired`, `permission_denied`, `mcp_init_failed`, `tool_discovery_failed`, `unavailable`, `endpoint_not_permitted`.
- **Outcomes** go to `mcp_connections` (migration 0016). The token is never stored there.
  - A failed check keeps the last known tools, marked as not from the current settings.
  - Tool set changes are recorded in the Diary as `mcp.tools.changed` (added, removed, schema changed).
- **Token scope** is *inferred* from the tool list: Oracle documents the write tools as read-write-only. It is `read_only` only if every tool is in the documented read list. Any undocumented tool makes it `unverified`.
- **SSRF guard.** Configuration key `mcp_upstreams.allowed_hosts` defaults to `my.quickstartapi.netsuite.com`.
  - The host must be in that list, use https and resolve to public addresses.
  - The dialled address is checked again, which defends against DNS rebinding.
  - No proxy is used.
  - Loopback endpoints are allowed only with `mcp_upstreams.allow_loopback: true` (development fakes).
- **Disconnect** (`DELETE /v1/integrations/netsuite_quickstart`) deletes the token from the secret store and the learned state, and records `mcp.connection.forgotten`. It does **not** revoke the PAT in QuickStart; the console and the API say so and give the QuickStart path to revoke it.
- **Console:** the NetSuite QuickStart card shows:
  - the live state;
  - that agent calls are **not** routed through Fortik yet;
  - tenant, endpoint, token expiry warnings, server, inferred scope and sync times;
  - a tool list with schemas;
  - Refresh tools;
  - revoke instructions.

### Evidence

- **Local fake MCP server** (`internal/mcpclient/mcpfake`, `scripts/fakes/fakequickstart`): unit and integration tests, plus `scripts/demo-netsuite-quickstart.sh` (30 checks on 2026-10-25).
- **Real QuickStart endpoint, without an account:**
  - No token: `401 text/plain "Bearer token not found"`.
  - Invalid token: `401 "Token can't be parsed."`.
  - Protected-resource metadata advertises scopes `read-only` and `read-write`.
  - Through Fortik (`FORTIK_QS_REAL_PROBE=1`), the invalid token gives `auth_failed`, HTTP 401.
- **Not verified:** a successful connection, the real tool list and schemas, and the protocol version QuickStart negotiates. All three need a PAT (see below).

### To verify with a real QuickStart PAT (open questions)

1. The protocol version QuickStart answers. Fortik accepts `2025-11-25`, `2025-06-18` and `2025-03-26`.
2. Whether a session id is issued and whether responses are JSON or SSE. Both are supported.
3. The actual tool names and schemas for a read-only token. Compare them with Oracle's list; the console shows any undocumented ones.
4. The response for an expired or revoked PAT. The state becomes `token_expired` only if the message says so; otherwise it is `auth_failed`.
5. The response when the MCP server is disabled for the company, or the user lacks permission.

### How to supply the token (never in source code or chat)

1. In QuickStart, enable **MCP Server Enabled**: Menu > Administration > QuickStart settings > General.
2. In **Personal access tokens**, create a token named `Fortik` with the default **read-only** scope. Copy it; it is shown once.
3. In the Fortik console, open Integrations > **NetSuite QuickStart (MCP)** > Set up and enter:
   - a tenant label;
   - the token's expiration date;
   - the token itself.

   Keep the documented endpoint. Save, then **Test connection**.
4. Read-write tokens: only after Milestones 2–3 (enforcement and approvals) are verified and an administrator authorises it.

### Milestone 1 verified live (2026-10-25)

The developer configured a real QuickStart PAT. Test connection reported:
- `connected`, protocol `2025-06-18`;
- server `quickstart-mcp-server`;
- 27 tools, matching Oracle's documented lists exactly;
- scope inferred `read_write`. The token is read-write, so writes are only ever held and approved, never run unreviewed.

## NetSuite QuickStart MCP: QuickStart Milestones 2–4 (2026-10-25)

### Milestone 2: NetSuite-aware enforcement

- **Fortik's MCP endpoint:** `POST /mcp/netsuite_quickstart` on the app gateway (`internal/nsquickstart/proxy.go`).
  - Agents use it with their Fortik agent token; Fortik calls QuickStart with the PAT it holds (one reused MCP session; re-opened only on an expired session).
  - Stateless toward the agent: `initialize` and `ping` are answered locally.
  - `tools/list` is decided and filtered by the agent's `netsuite` profile: read-only agents see the 16 read tools.
- **Transport and system are separate:** every `tools/call` becomes an action with `system: netsuite`, `target.transport: mcp`, `target.integration: netsuite_quickstart`, `target.server_id` and `target.tool`.
  - It inherits the NetSuite profile, the NetSuite rules, the control level, timed suspensions, delegation, swarm and rate gates.
  - Unrelated MCP servers are not affected: a suspension of system `mcp` does not block QuickStart, and vice versa.
- **Normalization (`normalize.go`):** the versioned explicit mapping (`policies/fortik/netsuite_quickstart/data.json`, `mapping_version`) gives the verb and operation.
  - From the actual arguments it takes record type, record id and field names (subrecord and sublist fields as `parent.field`), transform and action ids, email recipient counts and domains, preference key, attachment operation, and the uploaded file's extension and size.
  - Values are never stored. `args_sha256` (canonical JSON, exact numbers) binds approvals.
  - Arguments are checked against the tool's **discovered** input schema (required, `additionalProperties: false`, top-level types, enums, bounds).
  - A tool missing from the current `tools/list`, or a tool list not verified for the current token, is refused.
  - Missing information is marked `understood: false` and held.
- **Classification, grounded in the live record model:** 80 record types. Transforms include `payVendorBill`, `invoiceToCustomerPayment` and `salesOrderToCustomerDeposit`; record actions include `approve`, `void` and `unapply`; `Vendor`/`Customer` have no bank fields. POL-1101..1108 and POL-1120 are in docs/POLICIES.md.
  - Reads: allowed under the profile.
  - Writes: held.
  - Money movement and ledger changes: two approvers.
  - Deletes and attachment deletes: red.
  - `MCP_SERVER_ENABLED`: refused.
  - Unknown tools: denied.
- **Fail closed:**
  - If Decide is unavailable, the call is refused (JSON-RPC error).
  - A reduced form the call cannot honour is refused.
  - Integration not configured: refused.
  - Upstream failures report whether the call is known not to have run (`not_executed`) or its outcome is unknown, so it is never silently retried.

### Milestone 3: approvals, suspension, containment

- **Approvals reuse the existing grant flow:**
  1. A held yellow call returns `isError: true`, "held for human approval and did NOT execute", with the action id.
  2. Security approves it in the console (Approvals) or with `POST /v1/held/{id}/approve`.
  3. The agent repeats the **identical** call within `approvals.grant_ttl`. Decide re-checks it: level, suspension, delegation, schema, policy version.
  4. The call runs **once**: the grant is consumed atomically, and a duplicate is held again.
  - Different arguments are not covered.
  - Red holds are never released by an approval.
  - Multi-approver holds need distinct approvers.
- **Timed NetSuite suspensions:** `netsuite` is now a timed-suspension system for the REST gateway and for QuickStart. It was missing; Milestone 1's REST adapter relied only on levels.
  - Console Suspensions now lists NetSuite.
  - For agentgateway routes to a QuickStart MCP server, `agentgw.mcp_server_systems` (`quickstart: netsuite`) adds `target.reaches`, so NetSuite suspensions cover them too.
- **Containment:** killing or suspending an agent, or revoking its Fortik token, stops its QuickStart calls. The agent never holds a QuickStart credential. The PAT itself is Fortik's: disconnecting removes it from Fortik, and revocation is manual in QuickStart.
- **Execution records:** every executed or failed call is a Diary event (`mcp.tool.executed` / `mcp.tool.failed`) with the action id.
- **The QuickStart card shows:**
  - the agent endpoint;
  - 24-hour allowed, held, denied, executed and failed counts;
  - pending approvals, active NetSuite suspensions, undos available;
  - recent decisions with outcome and undo state;
  - known gaps.
- **Console:** the agent Access tab now edits NetSuite profiles (mode, record types, SuiteQL, QuickStart tools).

### Milestone 4: history, undo, coverage

- **Undo** applies only where reversal is reliable: `update_record` of plain body fields (`undo_possible` in the target, shown in the hold reason).
  1. After approval and before running, Fortik calls `read_record`; the live shape is `structuredContent.record.fieldValues`.
  2. It keeps the previous values of exactly the fields being set, encrypted in the secret store.
  3. It prepares an undo handle and activates it only if the update succeeded.
  4. `POST /v1/undo/{action_id}` writes the values back with `update_record` (last writer wins; the result says so).
  - A field missing from the read, or holding a structured value, means no snapshot, so the update does not run.
  - Creates, deletes, transforms, record actions, emails, attachments and preferences have no undo and are held instead. No undo handle is ever shown for them.
- **Change history: not supported.** The live record model has no system notes and no last-modified or created fields on any of the 80 record types, only business dates (`tranDate`, `dueDate`). So changes made outside Fortik cannot be detected through QuickStart MCP. Coverage says so, and no post-execution monitoring is claimed.
  - The classic NetSuite REST integration (Milestone 1 above) reads system notes for accounts that have SuiteTalk.
- **Coverage (`/v1/coverage`, `netsuite_quickstart`):**

  | Dimension | Status |
  |---|---|
  | Identity, activity, pre-execution enforcement, suspension, evidence | `verified_live` |
  | Revocation, undo, delegation | `verified_test` |
  | Discovery | `unsupported` |

### Evidence (2026-10-25)

- **Real tenant, `scripts/verify-quickstart-live.sh` (20 checks).** Reads only; every held write was denied, so nothing ran on the tenant.
  - `tools/list` per profile: read-only 16 tools, read-write 27.
  - `get_record_model`, `list_records` (Term), `read_record` (Term) and `report_catalog` were executed through Fortik.
  - `update_record` held (POL-1120); `delete_record` held red (POL-1002); `MCP_SERVER_ENABLED` refused (POL-1102).
  - Read-only profile (POL-021), unknown tool and schema violations (POL-1101) refused.
  - A timed `netsuite` suspension refused one agent (POL-030) and not another.
  - The Diary verifies.
- **Local fake, `scripts/demo-netsuite-quickstart.sh` (48 checks).** It runs on a separate database and secret store, and refuses to run while the integration points at a real endpoint. It adds the flows that need an executed write: hold, approve, different arguments held, identical retry runs once with a snapshot, duplicate held, undo restores; `payVendorBill` needs two approvers; an approval of a red delete is refused; disconnect refuses agents.
- **Tests:** `internal/nsquickstart` (proxy, normalization, schema, undo, suspensions, levels, stale catalog, upstream failures), `internal/mcpclient`, `internal/access` (`quickstart_tools`), `internal/agentgw` (`mcp_server_systems`), and policy tests (`policies/fortik/tests/netsuite_quickstart_test.rego`).

### Follow-ups completed (2026-10-25)

- **Delegation:** `TestProxyDelegatedQuickStartWriteRefused`. A read-only agent's task delegated to a read-write agent cannot write through QuickStart, whether the token is presented or inferred; a forged token is refused (POL-604). Coverage: `verified_test`.
- **Background re-check:** `Service.Worker`, every `mcp_upstreams.check_interval` (default 30m). It raises the alerts `quickstart_connection`, `quickstart_token_expiry` (7 days before the entered date) and `quickstart_tools_changed`. Tested by `TestWorkerTickAlerts`.
- **Write verification script:** `scripts/verify-quickstart-write.sh` (gated by `QS_ALLOW_WRITE=yes`): create, update, undo, red delete and inactivate on a contact it creates. It passed against the local fake. Running it on the real tenant was blocked by the session's safety check, so the developer runs it.
- **Console:** the QuickStart card shows coverage per dimension. DEMO_GUIDE §8A presents QuickStart.

### Not verified on the real tenant

An executed write, and therefore a live undo. Run `QS_ALLOW_WRITE=yes ./scripts/verify-quickstart-write.sh`, or follow docs/QUICKSTART_TESTING.md §5.

### Reproduce

```bash
FORTIK_API=http://127.0.0.1:8080 FORTIK_GATEWAY=http://127.0.0.1:8090 ./scripts/verify-quickstart-live.sh   # real tenant, read-only + holds
# LOCAL FAKE (needs its own database and secret store; mcp_upstreams.allow_loopback: true)
FORTIK_API=... FORTIK_GATEWAY=... FORTIK_DB=... ./scripts/demo-netsuite-quickstart.sh
FORTIK_TEST_PG_URL=... go test ./internal/mcpclient/... ./internal/nsquickstart/ ./internal/access/ ./internal/agentgw/
```

## Unified multi-transport platform: UM0 audit (2026-10-27)

### Baseline before any change

`make ci` green: go vet, opa fmt, policy coverage ≥ 95%, 543/543 policy tests, `go test -race` on every package (51 with tests). The console suite at the baseline commit (4fcd5af): 190 tests in 36 files. One of them, `ApprovalQueue.test.tsx` "filters and sorts the same way in the browser", depends on wall-clock time between module load and the test body; it fails when the machine is heavily loaded (seen twice during a parallel `make ci`) and passes otherwise. It is unchanged.

### Already implemented (reused, not rebuilt)

- **NetSuite REST** (`netsuite`): `/gw/netsuite/...`, OAuth 2.0 client credentials, POL-1001..1009, snapshot and undo, system-notes sync. Tested against a local fake only.
- **NetSuite QuickStart MCP** (`netsuite_quickstart`): `/mcp/netsuite_quickstart`, PAT, POL-1101..1120, approvals with identical retry, undo, background re-check, coverage. Verified live (reads, holds, refusals).
- **One decision pipeline:** both were already decided as system `netsuite` with the same access profile, timed suspensions, levels, delegation checks (POL-601..605), approvals and Diary. A transport switch could not escape the profile, but nothing tied the two connections to one tenant.
- **Generic MCP governance** through agentgateway (system `mcp`) for other MCP servers.

### Gaps found

1. No logical integration: REST and MCP were unrelated integrations and unrelated console cards.
2. One tenant per connection type (keys `netsuite`, `netsuite_quickstart` only): no second account, and no tenant identity on actions.
3. No way to restrict an agent to a tenant.
4. A full NetSuite account's MCP server (the AI Connector Service, OAuth 2.0 authorization code + PKCE) was not supported.
5. Nothing stated which transports a provider environment offers, e.g. that QuickStart has no REST connection.
6. Disconnecting gave no feedback on upstream revocation.
7. The MCP-versus-REST difference for updates (held vs snapshot-and-allow) was implicit.
8. Other providers have one transport. No MCP connection type exists for them; the catalog now says so.

### Dependencies

- A **full NetSuite account** (sandbox) with the AI Connector Service integration record, a SuiteApp or custom tools, and a non-Administrator role holding MCP Server Connection: to verify OAuth live and to map its tools.
- The same account (or the existing M1 dependency) for **REST** with client credentials.
- QuickStart is already connected; no new dependency.

## Unified multi-transport platform: UM1 (2026-10-27)

### What was built

- **Logical integrations** (migration 0018, `internal/integrations/apps.go`): table `app_integrations` (id `provider:name`, environment, tenant reference, display name); every integration row gains `app_integration_id` and `transport`. Configuring a connection finds or creates its tenant and checks it fits (same environment; same account for a full NetSuite account; one connection per transport) **before** any secret is written. Existing rows are backfilled with the same ids `LogicalID` derives: the live QuickStart connection became the MCP transport of `netsuite:quickstart`, unchanged otherwise.
- **API:** `/v1/app-integrations` (list with providers' transport catalog, create, rename, delete, activity per transport). Disconnect returns notes on upstream revocation.
- **NetSuite transports:** REST (`netsuite[:tenant]`, unchanged protocol) and MCP: QuickStart (`netsuite_quickstart[:tenant]`, unchanged) and new `netsuite_mcp:<tenant>`, a full account's AI Connector Service with OAuth 2.0 authorization code + PKCE (public client), token refresh with one-time refresh-token rotation, and revocation on disconnect. Its tool mapping is empty on purpose: every AI Connector tool call is refused until mapped from a real account's tools.
- **Routing:** REST picks the tenant from `X-Fortik-Integration` (ambiguous → refused, never guessed); MCP has `/mcp/netsuite/<tenant>`. Each action records `transport`, `integration_id`, `connection` (and `tenant` for REST).
- **Policy:** POL-1010 (profile `integrations`), MCP rules applied to both MCP connection types, and the explicit `config.netsuite.mcp_writes_require_approval` (default true) for the one REST/MCP difference.
- **Console:** one NetSuite card per tenant with its transports, each with its own status, evidence (verified live / tested against fakes only), Set up, Test, Disconnect; unavailable transports with the reason; Authorize for OAuth; Add NetSuite tenant; NetSuite access editor gains the tenant list.

### Transport availability (as shown, with evidence)

| Tenant environment | REST API | MCP |
|---|---|---|
| NetSuite QuickStart | **Unavailable**: not part of QuickStart's documented setup for agents | QuickStart MCP server: **verified live** (reads, holds, refusals; 2026-10-25 and 2026-10-27) |
| Full NetSuite account | SuiteTalk REST + SuiteQL: tested against a local fake only | AI Connector Service: tested against a local fake only (OAuth and MCP); no tool mapped |
| Other providers | their existing connection | not implemented (shown unavailable; agentgateway governs MCP servers generically) |

### Evidence (2026-10-27)

- `make ci`: go vet, opa fmt, coverage ≥ 95%, **556/556** policy tests (543 before + 13 cross-transport), `go test -race` on all 51 packages. The run hit a full disk (ENOSPC) while linking two test binaries; those two packages (`cmd/fortik`, `internal/shadow/discoverers`) pass on their own.
- New Go tests: `internal/integrations/apps_test.go` (linking, account consistency before secrets, one account per tenant, QuickStart labels not identities, one connection per transport, implicit/explicit lifecycle, HTTP API and activity), `migrations/backfill_test.go`, `internal/nsquickstart/oauth_test.go` (authorization required, PKCE binding, one-time state, refresh rotation, refused refresh, settings changed mid-flow, stale tokens, revoke confirmed and failed, managed secret not settable, no token in DB/Diary/API), `internal/nsquickstart/crosstransport_test.go` (one gateway, REST + MCP on one tenant: same identity and system, read-only profile, suspension, kill and POL-1010 on both; unknown and ambiguous tenants refused; MCP failure leaves REST working; disconnecting MCP keeps REST and the tenant; the configured update difference).
- Console: **202/202** tests (190 before).
- Regression on the new build (alt instance, shared dev DB migrated to 0018): phase 1–6 demos 13/29/34/54/36/22, M0 41, agentgateway 11, NetSuite REST fake 24; QuickStart fake demo 48 on an isolated database; all pass.
- **Real QuickStart tenant**, `scripts/verify-quickstart-live.sh`: **27/27** (20 before + 7 new in §5b). Reads only; every held write denied. The tenant endpoint `/mcp/netsuite/quickstart` offers the same tools as `/mcp/netsuite_quickstart`; a read through it is recorded as `netsuite:quickstart` / `mcp`; a profile limited to another tenant refuses the read and `tools/list` (POL-1010); listing `netsuite:quickstart` allows it; an unknown tenant endpoint refuses the call; the integration shows REST unavailable and MCP configured.

### Known gaps

- No full NetSuite account was available: REST and the AI Connector Service (OAuth, refresh, revoke, MCP) are verified only against local fakes, and the OAuth scope value is not documented by Oracle (default `mcp`, configurable).
- No AI Connector tool is mapped, so that transport refuses every tool call until its tools are read from a real account and mapped.
- MCP updates are held by default while REST updates run after a snapshot (configurable, documented).
- Other providers have no MCP connection type yet.

### Reproduce

```bash
FORTIK_TEST_PG_URL=... go test ./internal/integrations/ ./internal/nsquickstart/ ./internal/netsuite/ ./migrations/
opa test policies/ -v | grep transport
cd web/console && npx vitest run src/api/apps.test.ts src/components/NetSuiteApps.test.tsx src/components/QuickStartPanel.test.tsx
FORTIK_API=... FORTIK_GATEWAY=... FORTIK_BIN=... ./scripts/verify-quickstart-live.sh   # real tenant, reads + holds only
```

## Unified REST API / MCP integrations: NetSuite, Salesforce, ServiceNow, SAP (2026-10-28)

### What was built

- **One card per tenant with a Connection method dropdown** (`web/console/src/components/ProviderCard.tsx`).
  - The dropdown is single-select (REST API / MCP Server) and decides which method's form is rendered inline, with that method's status, Save, Test connection and Disconnect.
  - Switching keeps unsaved edits per method and never touches the other method's saved settings or connection.
  - Auth-dependent fields appear only for the selected authentication (schema `show_when`).
  - Unavailable methods are explained; on a QuickStart account, REST (SuiteTalk) is unavailable and offers to connect a full account instead.
  - The same form components serve the Configure drawer.
- **Salesforce, ServiceNow, SAP REST** (`internal/saasrest`):
  - provider-specific authentication:
    - Salesforce: client credentials or the JWT bearer flow;
    - ServiceNow: Basic or OAuth client credentials;
    - SAP: Basic or OAuth client credentials;
  - a read-only live check with capability discovery (`GET /v1/integrations/{key}/check`, table `rest_connections`, migration 0019);
  - a URL guard (provider domains or `saas_upstreams.allowed_hosts`; addresses checked at dial time; no proxy; no redirects);
  - gateway adapters `/gw/{salesforce,servicenow,sap}/...` deciding every call (SAP CSRF handled).
- **Their MCP connections** reuse the MCP transport (`internal/nsquickstart`, now multi-provider):
  - Salesforce Hosted MCP: OAuth authorization code against My Domain;
  - ServiceNow MCP Server Console: OAuth code or client credentials;
  - SAP: a customer-managed server with a bearer token, client credentials or OAuth code;
  - endpoints `/mcp/{provider}/<tenant>`, tool mappings shipped empty, revocation on disconnect.
- **Policy:**
  - POL-1201..1206 (`policies/fortik/rules/saas.rego`);
  - access profile `{mode, objects, integrations, mcp_tools}` with POL-1211/1212, and POL-1010 extended to these systems;
  - timed suspensions for `salesforce`, `servicenow`, `sap`.
- **Tenants:** a tenant's connections must name the same org (My Domain host), instance or API host, and that identity belongs to one tenant only.
- **Fixed in passing:**
  - `cmd/fortik` registered only the QuickStart tester for MCP connections, so Test connection of a `netsuite_mcp` connection had no tester in a real server; all MCP and REST testers are now registered.
  - The tenant uniqueness index no longer treats QuickStart labels as identities.

### Evidence (2026-10-28)

- **`make ci`:** vet, opa fmt, policy coverage ≥ 95%, **570/570** policy tests, `go test -race` on all **52** packages. Run with `GOFLAGS=-p=4`: the machine's disk is nearly full.
- **Console:** **210/210** tests. Of these, `ProviderCard.test.tsx` covers:
  - one component per tenant; the dropdown options;
  - only the selected method's fields; auth-dependent fields;
  - edits kept across switches; saving only the selected method;
  - secret values never shown;
  - Test connection and Disconnect calling the selected connection;
  - validation messages; the unavailable explanation;
  - placeholders for all four providers.
- **Go:**
  - `internal/saasrest`: auth flows and failures, the URL guard (including a private address refused at dial time), stored results and staleness, disconnect, gateway reads / held writes / approval and identical retry / red deletes / paths outside the API / read-only / objects / suspension / tenants / SAP CSRF, and path mapping;
  - `internal/nsquickstart/saas_mcp_test.go`: one Salesforce tenant over REST and MCP with OAuth, the same rules on both, the tenant restriction and suspension on both, revocation, unmapped tools refused, ServiceNow client credentials, SAP bearer token, the host allowlist;
  - `internal/integrations`: tenant identity per provider.
- **Server binary end to end** (`scripts/verify-saas-connections.sh` against `scripts/fakes/fakesaas`, on an isolated database): **22/22**.
- **Regression on the new build:** phase 1–6 demos, M0, agentgateway and NetSuite REST (264 checks) and the QuickStart fake demo (48) pass. The real QuickStart tenant check passes **27/27**, reads and holds only.

### Not verified live

No Salesforce, ServiceNow or SAP tenant or credential was available (no `sf` CLI session either), so all six of their methods are tested against local fakes only, as are NetSuite's full-account REST and AI Connector methods. Their MCP tool mappings are empty: every tool is refused until mapped from a real server's tools.

### Live verification since (2026-11-04)

Salesforce REST API on the developer's Developer Edition org:
- Test connection passed (client credentials; run-as user with broad object access).
- Fortik's gateway forwarded two read-only SOQL queries (BotDefinition, BotVersion) through Decide: allowed, HTTP 200, recorded.

Not yet exercised there: writes, holds, approvals, the MCP Server method.

