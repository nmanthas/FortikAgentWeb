# NetSuite, Salesforce, ServiceNow and SAP: REST API or MCP Server

Each of these applications has **one card** on **Integrations**, per tenant (account, org, instance or system). The card has a **Connection method** dropdown:

- **REST API**: Fortik calls the provider's API with credentials it holds. Agents call Fortik's gateway (`/gw/<provider>/...`) with their Fortik token.
- **MCP Server**: Fortik connects to the provider's (or your) MCP server with credentials it holds. Agents connect to Fortik's MCP endpoint (`/mcp/<provider>/<tenant>`) with their Fortik token.

The dropdown chooses which method you are configuring:
- The card shows that method's form, its saved settings (never secret values), its status and its Save / Test connection / Disconnect buttons.
- Switching the dropdown changes nothing: the other method keeps its saved settings, credentials and connection. Unsaved edits are kept while you switch.
- A method shows **Connected** only after its own Test connection succeeded. A working MCP connection says nothing about REST, and the reverse.
- A method the provider environment does not offer shows **unavailable**, with the reason.

Both methods of a tenant share one integration (`<provider>:<tenant>`, e.g. `salesforce:default`). That means one access profile per agent and provider, one set of timed suspensions, approvals and one audit trail. Every agent call, REST or MCP, is decided by the same pipeline before it reaches the provider: identity, control level, access profile (mode, objects, tenants, MCP tools), delegation chain, suspensions, approvals.

## Status values

| Status | Meaning |
|---|---|
| Not configured | No settings saved for this method |
| Saved, not tested yet | Settings saved; run Test connection |
| Connected | The last live test of these settings succeeded |
| Connection test failed | The last test failed. The detail panel says why: Authentication failed, Permission denied, API or resource not found, Endpoint not permitted, Tool discovery failed, MCP initialization failed, Authorization required (OAuth not yet granted) |

Test connection never writes anything:
- **REST:** it requests a token and reads (Salesforce: the API versions, the objects visible and API limits; ServiceNow: one record id from each listed table; SAP: each listed service's `$metadata`).
- **MCP:** it runs `initialize` and `tools/list` and stores the tools.

## NetSuite

| Method | Connection type | Authentication | Evidence |
|---|---|---|---|
| REST API (SuiteTalk) | `netsuite[:<tenant>]` | OAuth 2.0 client credentials (M2M): integration record, certificate, private key | local fake only |
| MCP Server, QuickStart company | `netsuite_quickstart[:<tenant>]` | QuickStart personal access token | **verified live** (reads, holds, refusals) |
| MCP Server, full account | `netsuite_mcp:<tenant>` | OAuth 2.0 authorization code + PKCE (AI Connector Service integration record); **Authorize** opens NetSuite's consent screen | local fake only |

- A QuickStart company and a full NetSuite account are separate tenants. On a QuickStart card, REST API (SuiteTalk) shows **unavailable for this QuickStart account**: SuiteTalk REST is not part of QuickStart's documented setup. **Connect a full NetSuite account with SuiteTalk REST** adds a full-account tenant.
- With nothing connected, the NetSuite card offers the SuiteTalk REST form and the QuickStart MCP form; saving either creates that tenant.
- Permissions: the integration record's role (REST) or the token's QuickStart user (QuickStart) decides what Fortik can do; give it least privilege.

Details: docs/QUICKSTART_TESTING.md and docs/INTEGRATION_MILESTONES.md.

## Salesforce

**REST API** (`salesforce[:<tenant>]`):
- **My Domain URL:** e.g. `https://acme.my.salesforce.com`. Tokens come from `<My Domain>/services/oauth2/token`.
- **OAuth flow:** pick one of these.
  - `client_credentials`: a connected app or external client app with the Client Credentials Flow enabled and a run-as user. Enter the consumer key and the consumer secret.
  - `jwt_bearer`: an app with a digital certificate. Enter the consumer key, the username (pre-authorized for the app), the audience (`https://login.salesforce.com`, or `https://test.salesforce.com` for sandboxes) and the RSA private key.
- **Permissions:** the run-as user's profile and permission sets (API Enabled; least privilege). Test connection lists the objects it can query, create, update and delete.
- **Agents:** `/gw/salesforce/services/data/vNN.N/...` (sobjects, query, actions, composite). Other paths are refused.

**MCP Server** (`salesforce_mcp[:<tenant>]`):
- **URL:** a Salesforce Hosted MCP server, e.g. `https://api.salesforce.com/platform/mcp/v1/d/<mydomain>/platform/sobject-reads`.
- **Authentication:** `oauth_authorization_code` with an external client app.
  - Hosted MCP servers require an external client app with the `mcp_api` and `refresh_token` scopes and Fortik's redirect URI (`<console URL>/v1/oauth/mcp/callback`).
  - Save, then **Authorize**: a Salesforce user grants Fortik access, and tools run as that user. Disconnecting revokes the grant (`/services/oauth2/revoke`) and reports whether Salesforce confirmed it.
  - `bearer_token` is also possible.
- **Hosts:** `api.salesforce.com` and `*.my.salesforce.com` are permitted. Other hosts must be listed in `mcp_upstreams.allowed_hosts`.

**Agentforce agents (Agent API)**, on the same REST connection:
- **What it does:** agents talk to an Agentforce agent through Fortik with Salesforce's Agent API (`https://api.salesforce.com/einstein/ai-agent/v1`). Fortik decides every session start and message, then forwards it with a token it holds.
  - REST: `POST /gw/salesforce/einstein/ai-agent/v1/agents/<agentId>/sessions` (body optional: Fortik fills `externalSessionKey`, `streamingCapabilities` and `bypassUser`, and always sets `instanceConfig.endpoint` to the connection's My Domain), `POST .../sessions/<sessionId>/messages` with `{"message":{"type":"Text","text":"..."}}` (or `{"text":"..."}`), `DELETE .../sessions/<sessionId>` (optional `X-Session-End-Reason`). Streaming (`/messages/stream`) is refused.
  - MCP: `/mcp/agentforce/<tenant>` (`default` for the plain `salesforce` connection) with the tools `agentforce_list_agents`, `agentforce_send_message` (`agent_id`, `message`, optional `session_id`) and `agentforce_end_session`. Each tool call is dispatched as the equivalent gateway call, so REST and MCP get the same decisions.
- **Salesforce setup:** an External Client App with the Client Credentials Flow and a run-as user, the OAuth scopes `api`, `chatbot_api`, `sfap_api` and `refresh_token, offline_access`, and **Issue JSON Web Token (JWT)-based access tokens for named users**. No per-agent connection is needed for an External Client App: the token names the app and the URL names the agent (current Agentforce Builder offers no API connection type). The agent must be Active, of a type the Agent API supports (not "Agentforce (Default)"), with at least one topic. A session start that fails with an empty 404 usually means one of these, a missing scope or the JWT setting.
- **Fortik settings:** *Agent API URL* (default `https://api.salesforce.com`) and, optionally, a separate *Agent API consumer key and secret*; without them the REST app's credentials are used (its tokens must then be JWT-based).
- **Test connection** lists the org's agents (BotDefinition) and checks that the Agent API token is a JWT with `chatbot_api` and `sfap_api`. It never starts a session.
- **Access profile (salesforce):** `agentforce_agents` (`["*"]` or agent ids; absent = none, POL-1213) and `agentforce_messages` (`approval`, the default, holds each message under POL-1214; `allow` lets messages run, each one recorded). Messages need mode `read_write`; session start and end are reads. Listing agents over MCP reads `BotDefinition`, so `objects` must allow it.
- **Sessions** are bound to the Fortik agent that started them through Fortik: another agent cannot use them. The binding is in memory; after a Fortik restart, start a new session.
- **Approvals:** a held message runs when the agent repeats it after approval, with the same session and exactly the same text (the approval is bound to a hash of the text; the console shows its first 200 characters).
- **Tested only against a local fake** of the Agent API shapes taken from Salesforce's own client library (`@salesforce/agents`). Not yet verified against a real org.

**Native Agentforce actions do not pass through Fortik.** Fortik governs only calls made through its gateway or MCP endpoint, and Salesforce audit logs would only show them afterwards. That includes what an Agentforce agent does after it receives a message through Fortik.

## ServiceNow

**REST API** (`servicenow[:<tenant>]`):
- **Instance URL:** e.g. `https://acme.service-now.com`.
- **Authentication:** `basic` (an integration user and password) or `oauth_client_credentials` (client ID and secret; tokens from `/oauth_token.do`). The client credentials grant must be enabled on the instance; it is off by default.
- **Tables to check:** Test connection reads one record id from each (default incident, change_request, sys_user) and reports which are readable.
- **Permissions:** the user's roles and ACLs.
- **Agents:** `/gw/servicenow/api/now/...`.

**MCP Server** (`servicenow_mcp[:<tenant>]`):
- **URL:** from MCP Server Console, e.g. `https://acme.service-now.com/sncapps/mcp-server/mcp/sn_mcp_server_default`.
- **Authentication:**
  - `oauth_authorization_code`: an OAuth inbound integration for Fortik. Fortik uses the instance's `/oauth_auth.do`, `/oauth_token.do` and `/oauth_revoke.do`.
  - `oauth_client_credentials`: if the instance enables that grant.
  - `bearer_token`.
- **Hosts:** `*.service-now.com` and `*.servicenowservices.com` are permitted.

## SAP

**REST API (OData)** (`sap[:<tenant>]`):
- **Product:**
  - S/4HANA Cloud Public Edition: a communication user on a communication arrangement, e.g. SAP_COM_0008 for business partners.
  - S/4HANA Private Edition or on premise: SAP Gateway OData.
  - Another OData API.

  Endpoints and roles differ by product; Fortik does not assume one from another.
- **API base URL:** e.g. `https://my123456-api.s4hana.cloud.sap`. Hosts other than `*.s4hana.cloud.sap` and `*.s4hana.ondemand.com` must be listed in `saas_upstreams.allowed_hosts`.
- **Authentication:** `basic` (communication user) or `oauth_client_credentials` (token URL, client ID, secret, scope). Optional SAP client (`sap-client`).
- **OData services to check:** Test connection reads each service's `$metadata` and lists its entity sets.
- **Agents:** `/gw/sap/sap/opu/odata/...` and `/sap/opu/odata4/...`. For changes, Fortik fetches SAP's CSRF token itself.

**MCP Server** (`sap_mcp[:<tenant>]`): SAP publishes no native MCP endpoint for S/4HANA that Fortik could verify. This option connects an MCP server **you run or license** in front of SAP:
- name its URL explicitly and list its host in `mcp_upstreams.allowed_hosts`;
- authenticate with a bearer token, OAuth client credentials, or OAuth authorization code (with its authorization, token and optional revocation URLs).

## What each method controls

| | REST API | MCP Server |
|---|---|---|
| What policy sees | method, path, object (Salesforce object, ServiceNow table, SAP service/entity set), record id | the tool name and its mapped verb and operation |
| Reads | allowed under the access profile | allowed under the profile once the tool is mapped as a read |
| Writes, actions, other side effects | held for approval (POL-1201/1203/1205) | same rules once mapped |
| Deletes | red hold, never released unchanged (POL-1202) | same |
| Unclassified | paths outside the API: refused (POL-002) | unmapped tools: refused (POL-002) and hidden from agents |
| Undo | not available (no verified undo) | not available |

MCP tools need a mapping before agents can use them:
- `policies/fortik/<provider>_mcp/data.json` is shipped **empty**: every tool is refused until you add it with its verb (READ, WRITE, DELETE, EXECUTE) and operation, after reading the server's tools (card > MCP Server > View tools).
- The tool list must be verified for the current settings (POL-1206), and arguments must match the tool's schema.

## Access profiles

Agents need a profile per system (Agents > Access): Salesforce, ServiceNow or SAP. It applies to both methods.
- `mode`: none, read_only or read_write.
- `objects`: `["*"]` or names. POL-1211 refuses others.
- `integrations` (tenants): absent means all. POL-1010 refuses others on both methods.
- `mcp_tools`: absent means all the mode allows. POL-1212.

Timed suspensions per system (`salesforce`, `servicenow`, `sap`) stop both methods.

## Updating credentials and disconnecting

- **Replace a secret:** select the method, then on the secret field click **Replace**, enter the new value and **Save**. The status turns to "Saved, not tested yet" until you test again; MCP tool calls are refused until the tool list is verified again.
- **Disconnect:** select the method, click **Disconnect**, and confirm. Only that method's settings and credentials are deleted; the other method and the tenant remain.
  - OAuth authorization-code grants are revoked with the provider when it has a revocation URL, and the result says whether the provider confirmed it.
  - Client-credentials clients, bearer tokens and passwords stay valid at the provider: disable or rotate them there.

## Live evidence

- **Salesforce REST API, 2026-11-04 (a Developer Edition org):**
  - Test connection passed with the client credentials flow (API v62.0; 1,481 objects visible, 1,243 queryable).
  - Two read-only SOQL queries (BotDefinition, BotVersion) ran through the gateway: allowed (POL-000), forwarded, HTTP 200, and recorded under `salesforce:default` / `rest_api`.
  - Writes, holds and approvals have not been exercised on that org.

## Limitations (as built, 2026-10-28; updated 2026-11-04)

- **Not verified live:**
  - Salesforce MCP Server, ServiceNow and SAP (both methods), and the NetSuite full-account REST and AI Connector methods: tested only against local fakes of the documented APIs.
  - Salesforce REST is verified live for the connection and reads only (see above).
- **Unmapped MCP tools:** no MCP tool of Salesforce, ServiceNow, SAP or the NetSuite AI Connector is mapped yet.
- **Fortik sees only its own traffic:** agents or clients holding their own provider credentials, and native agents inside the provider (Agentforce, Now Assist), are not seen by Fortik.

## Tests

```bash
FORTIK_TEST_PG_URL=postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable \
  go test ./internal/saasrest/ ./internal/nsquickstart/ ./internal/integrations/ ./internal/access/ ./migrations/
opa test policies/ -v | grep -E 'saas|transport'
cd web/console && npx vitest run src/components/ProviderCard.test.tsx src/api/apps.test.ts src/lib/profiles.test.ts
```

- `internal/saasrest`: auth flows, failures, the URL guard, gateway enforcement, approval and identical retry, SAP CSRF.
- `internal/nsquickstart`: `saas_mcp_test.go` (one Salesforce tenant over REST and MCP, OAuth, revocation, ServiceNow client credentials, SAP bearer token) and `crosstransport_test.go` (NetSuite).
