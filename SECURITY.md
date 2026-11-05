# Security

Fortik sits on the authority path of autonomous agents. It must be **correct before fast** and **fail closed** for anything risky or unknown.

## Invariants (enforced and tested since Phase 1; still true through Phase 6)

1. **No statement reaches a protected Postgres without a decision.**
   - Every non-trivial statement goes through Decide before it is forwarded.
   - Only transaction-control statements and an allowlist of harmless session statements skip Decide: BEGIN, COMMIT, SHOW, and SET of whitelisted GUCs.
   - `SET ROLE`, `SET SESSION AUTHORIZATION` and `session_replication_role` are classified as GRANT, which is red.
2. **Red never executes.**
   - The policy holds or denies every red action.
   - The Go engine additionally rejects any bundle output that pairs red with an executing decision.
3. **Unknown fails closed:** unknown verbs and systems (POL-002), unclassified SQL (POL-110), unparseable SQL, internal errors, and reduced forms the interception point can't honour.
4. **Automatic step-down only tightens control.** It is atomic with the decision and the Diary event, and it never loosens a level.
5. **Undo is claimed only when it was prepared.**
   - The undo handle is recorded before the statement runs, and the snapshot is taken in the same transaction.
   - An action with no handle returns "NOT undoable".
   - Concurrent or repeated undo requests can't both run, because claiming is atomic.
6. **The Diary is append-only and tamper-evident.**
   - Database triggers refuse UPDATE, DELETE and TRUNCATE.
   - The app role (`fortik_app` in dev) is not the table owner, so it can't disable those triggers.
   - Byte-exact hash chaining with a gapless seq lets verification detect edited, removed or reordered rows, and tail truncation through the head row.
   - Exports and daily roots are Ed25519-signed.
7. **Refusal inside a transaction aborts it.** A partially executed migration can't be committed after Fortik refuses one of its statements.
8. **Every interception point fails closed** (Phases 2–6): the app gateway, the credential broker, the Claude Code hook (exit 2 when Fortik is unreachable), agentgateway's callout (`failureMode: deny` / `failClosed`), and copilot connector tokens. Verified by `scripts/chaos-test.sh`, `scripts/demo-agentgateway.sh` and the e2e tests.
9. **Observe mode relaxes only policy opinions** (Phase 6). Unknown or malformed actions, fail-closed outcomes, levels set by people, timed suspensions, unregistered agents, frozen swarms, copy caps, memory cuts and connector checks are always enforced (`policies/fortik/observe/data.json`).
10. **A suspension covers every path to its system:** direct calls, shell commands that reach it (`gh`, git remote operations, the AWS CLI), and copilot connector tokens for its upstream.

## Secrets

- No credential lives in the config file or in Fortik's Postgres. Configs reference secrets by name.
- Providers: `encfile` (AES-256-GCM files; the master key comes from a file outside the secret directory or `FORTIK_MASTER_KEY` from KMS), `vault`, `file` and `env`.
- Copilot connector client secrets and Fortik refresh tokens are stored only as SHA-256 hashes. Upstream refresh tokens live in the secret store.
- The Slack webhook URL (`notify_slack`) is a secret and never appears in logs or errors.
- The NetSuite QuickStart personal access token (`netsuite_quickstart`) is a secret. It is sent only as `Authorization: Bearer` to the configured MCP endpoint, and is scrubbed from server-supplied error text.
  - The endpoint's host must be in `mcp_upstreams.allowed_hosts` (default `my.quickstartapi.netsuite.com`) and resolve to public addresses. The dialled address is checked again (DNS rebinding). Redirects are not followed and no proxy is used.
  - Loopback is allowed only with `mcp_upstreams.allow_loopback` (development fakes).
  - Deleting the integration does not revoke the token in QuickStart.
  - Agents never receive it. They call Fortik's `/mcp/netsuite_quickstart` with their own Fortik agent token, and Fortik calls QuickStart with the stored token after Decide. Tool arguments are stored only as names and an argument hash. The previous values for undo are kept encrypted in the secret store, not in Postgres.
- A full NetSuite account's AI Connector Service (`netsuite_mcp:<tenant>`) uses OAuth 2.0 authorization code with PKCE (S256) as a public client: there is no client secret. The access and refresh tokens are the managed secret `integration/<key>/oauth_tokens` in the secret store; the API never accepts or returns it, and no token appears in Postgres, the Diary, logs or API replies (tested).
  - The authorization state is random (43 characters), stored only as a SHA-256-derived name in the secret store, valid 10 minutes and once; the callback requires the security role in the console session, and the code is useless without the verifier.
  - NetSuite's refresh tokens are one-time use: refreshes are serialized per connection and the rotated token is stored at once. Tokens issued for another account or client ID are never used.
  - Its token, revoke and MCP endpoints must be `https://<account>.suitetalk.api.netsuite.com` (or an allowed host), resolving to public addresses.
  - Disconnecting calls NetSuite's revoke endpoint and reports whether NetSuite confirmed the revocation; the tokens are deleted either way.
  - Each tool runs with the authorizing NetSuite user's role. Fortik cannot read or narrow that role: use a dedicated, least-privilege, non-Administrator role.
- Salesforce, ServiceNow and SAP REST credentials (consumer secrets, private keys, passwords, client secrets) are secrets in the secret store and are sent only to permitted URLs (`internal/saasrest` Guard):
  - https only;
  - the provider's own domains (`*.salesforce.com`; `*.service-now.com`, `*.servicenowservices.com`; `*.s4hana.cloud.sap`, `*.s4hana.ondemand.com`), or hosts listed in `saas_upstreams.allowed_hosts`;
  - addresses checked again at connect time (private, link-local, multicast and unspecified refused; loopback only with `saas_upstreams.allow_loopback`);
  - no proxy, no redirects followed.

  Access tokens are cached in memory only. Credentials and tokens never appear in Postgres, the Diary, logs, API replies or agents' responses (tested).
- Their MCP connections reuse the MCP transport's guard (`mcp_upstreams`):
  - `api.salesforce.com` and `*.my.salesforce.com` for Salesforce, and the ServiceNow domains, are permitted;
  - an SAP (customer-managed) MCP server must be listed.

  OAuth authorization codes use PKCE, and client secrets of confidential clients stay in the secret store.
- One tenant's credentials are never used for another: each connection has its own secrets, REST calls are routed by `X-Fortik-Integration` (ambiguous calls are refused, never guessed), MCP calls by the tenant's own endpoint, and every connection of a full NetSuite account must name the same account id.
- `FORTIK_POLICY_CAPTURE` (development only: writes every policy input to disk) is refused by `fortik serve` on any non-loopback listener.
- API and agent tokens are stored only as SHA-256 hashes, compared in constant time, and reloaded without a restart.
- Logs and Diary events carry statement types, fingerprints, normalized SQL (constants replaced with `$n`), tables and data labels. They never carry raw literals, row data, tokens or passwords.
- `.dev/` (generated dev secrets) is gitignored. Dev secrets are random per checkout and must never be reused.

## Authentication and authorization

- **People:** console login through OIDC (dev login only on loopback), session cookies with a CSRF header, and roles mapped from groups.
- **Machines:** bearer tokens with explicit roles per route: `interceptor` (decide), `auditor` (reads, Diary export, metrics), `security` (containment, undo, approvals, integrations, observe mode, connectors), `admin`.
- **Owners** (an agent's sponsor) may act only on their own agents: step up one level at a time, step down, suspend, isolate, and narrow access. They may not kill, widen access, or lift what security imposed. Every route is listed in docs/API.md with its role.
- **Two-person rules** (swarm release, two-approver holds) need two distinct people; two API tokens are not two people unless `approvals.allow_token_pairs` (dev only).
- **Agents** authenticate with their own Fortik token: at the proxy (as the password; TLS and client certificates outside localhost), the gateway, the hook and agentgateway's callout. Client-supplied identity headers are ignored.
- **Between components:** mTLS on the API, gateway, Postgres proxy and agentgateway callout (`<listener>.tls`, `client_auth: require`). A non-loopback listener refuses plaintext unless explicitly allowed.
- Every security-state change is a Diary event that records the actor.

## Known gaps, by design of the phase plan (not yet mitigated)

| Gap | Status |
|---|---|
| Agents used a static upstream DB role and long-lived bootstrap tokens | Fixed in Phase 2: a per-agent role per session (15 min); broker-issued AWS, GitHub and Google access |
| An agent holding its *own* standing credentials can bypass the broker | Mitigated: shadow-agent discovery (Phase 5) finds them for Postgres (live); GitHub, AWS and Google are tested with fakes. The onboarding checklist removes them (docs/DEPLOYMENT.md) |
| No OIDC/SSO; no level API | Fixed in Phase 2 |
| No mTLS between components | Fixed in Phase 6 (verified by the Compose smoke test) |
| Snapshot tables in `fortik_undo` and memory snapshots are not separately encrypted: they stay in the customer's own database and rely on its at-rest encryption (Fortik stores pointers only). Purge jobs exist since Phase 4 | Documented deviation (ROADMAP 7); optional envelope encryption not built |
| Temporal: a running workflow pauses only if its worker uses the `temporalsdk` helper; Celery: messages a worker already prefetched cannot be held (cancel revokes them). The containment step detail says so | Documented limitation |
| Memory restore and promotion commit in the customer's store before the Diary write (different databases); a Diary failure is retried and then reported as "applied but not recorded" | Documented limitation |
| User-defined SQL functions called from SELECT can have side effects the classifier can't see (known dangerous built-ins are caught) | Documented limitation |
| Unqualified table names are assumed to be in `public` (search_path not resolved) | Documented limitation |
| Owner or superuser can still disable Diary triggers; detection then relies on verification and exported signed roots | Operational (run as non-owner; export roots off-box) |
| The public OAuth endpoints (copilot connectors) have no per-IP rate limit. Secrets are high-entropy; open authorizations are capped at 200 per connector | Documented; put a rate-limiting proxy in front for internet exposure |
| GitHub installation tokens minted by *other* Fortik processes are not tracked for revocation; they expire within 1 h, and new requests are refused by Decide | Documented limitation (the kill report says so) |
| Real Google Workspace, GitHub and AWS paths are verified only against local fakes until test accounts exist (`scripts/acceptance-real-accounts.sh`) | Waiting for the developer's test accounts |

## Reporting

Report security issues privately to the Fortik engineering team, not in public issues.
