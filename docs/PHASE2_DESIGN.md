# Phase 2 design: authority broker and app adapters

**Goal (from the plan):** Fortik owns the credential path. An agent cannot act on Google Workspace, GitHub, AWS or Postgres without a Fortik-issued, short-lived, narrow credential, and every such action is decided first.

**Extra requirement from the developer:** test-account credentials are entered later **through the console UI**. So Phase 2 also ships an *Integrations* screen and API:

- Secrets entered there go to the secret store. They are never written to Postgres and never returned by any API.
- Each integration can be tested live from the UI.
- Until an integration is configured, every action on that system fails closed with a clear message: "integration not configured".

This document is the contract every Phase 2 workstream codes against. Go contract files are listed under **Ownership** at the end.

---

## 1. Components

```
                     ┌──────────────── fortik serve ────────────────────────────────────────────┐
 console (browser) ──► API :8080  (session cookie / bearer)   /v1/*  /auth/*  /  (embedded SPA)    │
 agents ─────────────► Gateway :8090 (agent token)            /gw/google/* /gw/github/*            │
                     │                                       /v1/credentials/issue                 │
 agents (SQL) ───────► pgproxy :6432 (agent token) ── broker.PostgresSession → per-agent role     │
                     │   all paths → decide.Service (Phase 1) → broker → adapters → real APIs      │
                     │   secrets: secrets.Store (encfile | vault | file)   events: diary tail → bus │
                     └────────────────────────────────────────────────────────────────────────────┘
```

## 2. How each system is brokered

| System | Agent-facing path | Credential | Narrowing | Revocation |
|---|---|---|---|---|
| Gmail and Drive | Gateway reverse proxy: `/gw/google/gmail/v1/...`, `/gw/google/drive/v3/...`, `/gw/google/upload/drive/v3/...` | Service account with domain-wide delegation, impersonating the agent's `workspace_user`. The token is minted per (agent, scope set) and cached until expiry. It **never leaves the gateway.** | Access profile, plus recipient, share and volume rules in policy | Stop issuing. The gateway holds the token, so it simply refuses: instant. |
| GitHub | Gateway reverse proxy of the REST API, `/gw/github/...`. Optional direct token via `/v1/credentials/issue` when the profile has `allow_direct_token`. | GitHub App installation token, scoped to profile repos ∩ request, and permissions ∩ profile | Profile repos and permissions, branch protection lookup, policy | `DELETE /installation/token` for direct tokens. Gateway tokens are dropped from cache. Tokens expire within 1 h anyway. |
| AWS | `POST /v1/credentials/issue` with `{system:"aws", aws:{service, action, resource, region, est_cost_usd}}` | STS AssumeRole, 900 s, `SourceIdentity=<agent_id>`. The session policy allows **exactly** `service:Action` on `resource` (∩ profile). | Profile mode, services and denied actions, plus policy | Inline role policy `fortik-revocations`: Deny `*` when `aws:SourceIdentity` = agent **and** `aws:TokenIssueTime` < now. STS tokens can't be recalled, so this is the plan's method. |
| Postgres | pgproxy (Phase 1) | Per-agent login role `fortik_a_<agent>` (sanitised, ≤ 63 bytes) in the upstream, `IN ROLE <read_role|write_role>` per profile. Password rotated **per session**, `VALID UNTIL now()+15min`. | Profile per upstream: `none \| read_only \| read_write`. Policy still classifies each statement. | `ALTER ROLE … NOLOGIN` and `pg_terminate_backend` on the role's sessions |

**Never** hand out long-lived keys. **Never** return Google tokens.

## 3. Request flow (gateway and broker)

1. Authenticate the agent with a bearer token. The SHA-256 is compared against the secret `agent_tokens`, the same as pgproxy. `X-Fortik-Instance-Id` is optional.
2. The adapter maps the request to an `action.Action`, filling in the system, verb, target and payload summary. An unknown endpoint gets verb `UNKNOWN`, which POL-002 denies (fail closed).
3. Pre-queries enrich the target before deciding: branch protection on GitHub, the current ref sha, and so on.
4. `decide.Service.Decide` runs. Its input now also carries `input.access`, the agent's current access profile for that system (§5).
5. Enforce the decision:
   - **`allow`:** the broker mints or fetches a credential and the request is forwarded.
   - **`allow_reduced`:** apply every reduced-form key the adapter understands, or **refuse**. The keys are:
     - `delay_send_seconds`: Gmail delayed queue, §6.
     - `narrow_share` and `record_permission`: Drive.
     - `record_ref`: GitHub.
     - `snapshot_rows`: Postgres, Phase 1.
   - **`hold` or `deny`:** return `403`. The body is `{"error":{"code":"fortik_refused","decision","class","rule_id","reason","action_id","held"}}`, plus `X-Fortik-Action-Id`.
6. Every credential issuance writes a `credential_issuances` row and a Diary event, `credential.issued` or `credential.refused`. **No secret values** go into either.

### Integration missing

- If the system's integration isn't configured or its secret is missing, `/v1/credentials/issue` and `/gw/*` return `503` with `{"error":{"code":"integration_not_configured","system":...}}`, after the decision is recorded.
- pgproxy refuses with SQLSTATE 08004 when an upstream can't be reached.

## 4. Secrets

The `secrets.Store` interface (in `internal/secrets/store.go`) extends `Provider` with `Put` and `Delete`.

| Provider | Use | Notes |
|---|---|---|
| `encfile` | Dev and pilots, **the dev default** | Each secret is stored as `<dir>/<name>.enc` with AES-256-GCM. The master key is 32 bytes, read as base64 from env `FORTIK_MASTER_KEY` or from `master_key_file`. A random nonce is used per write, and the name is bound as AAD. Writes are atomic: write to a temp file, then rename. |
| `vault` | Production | KV v2 over HTTP: `addr`, `mount` (default `secret`), `prefix` (default `fortik/`). The token comes from env `VAULT_TOKEN`. OpenBao is API-compatible. |
| `file` / `env` | Phase 1 | Read-only. `Put` returns `ErrReadOnly`. |

Secret names: `[a-zA-Z0-9_./-]`, no `..`. Integrations use `integration/<system>/<name>`.

## 5. Access profiles

- **Table:** `access_profiles`. Rows are append-only versions; the current profile is the highest `version` per (agent, system).
- **Default:** if no profile exists, policy denies with POL-020.
- **Profile JSON per system:**
  - `gmail`: `{"send":"none|internal_only|any","read":true,"max_recipients":25}`
  - `drive`: `{"mode":"none|read_only|read_write","share":"none|internal_only|any"}`
  - `github`: `{"repos":["org/repo"],"permissions":{"contents":"read|write","pull_requests":"read|write","issues":"read|write","metadata":"read"},"allow_direct_token":false}`
  - `aws`: `{"mode":"none|read_only|read_write","services":["s3","ec2"],"denied_actions":["iam:*"]}`
  - `postgres`: `{"upstreams":{"acme_prod":"read_only","acme_staging":"read_write"}}`
- **Policy input:** `input.access = {"system": "<system>", "version": N, "profile": {...}}`, or `{"system": ..., "version": 0, "profile": null}` when there is none.
- **Rego `fortik.access` gate.** It produces deny decisions without a ladder change, checked after the control gate:

| Rule | Denies when |
|---|---|
| POL-020 | No profile, or `mode`/`send`/the upstream is `none` |
| POL-021 | Mode is `read_only` and the verb isn't READ |
| POL-022 | Gmail `send` is `internal_only` and the message is external |
| POL-023 | Drive `share` is `internal_only` and the share is external or anyone, or `share` is `none` and the action is a share |
| POL-024 | The GitHub repo isn't in `repos`, or the needed permission is missing (`contents:write` for push/ref ops, `pull_requests:write` for PR ops) |
| POL-025 | The AWS service isn't in `services`, or the action matches `denied_actions` (glob) |
| POL-026 | The Postgres upstream isn't in the profile, or it is `read_only` and the verb isn't READ |
| POL-027 | Recipients exceed the profile's `max_recipients` |

- **API (role `security`, or the agent's owner as described in §8):**
  - `GET /v1/agents/{id}/access`: the current profile for every system.
  - `GET /v1/agents/{id}/access/{system}/history`
  - `PUT /v1/agents/{id}/access/{system}` with body `{"profile":{...},"reason":"..."}`: validated against the schema, writes a new version and a Diary event `access.changed` (old and new).
  - `POST /v1/agents/{id}/access/{system}/revert` with body `{"version":N,"reason":"..."}`: writes a new version copying N.
  - The next credential issued reflects the change.

## 6. Reduced forms the gateway honours

### Gmail `delay_send_seconds`

1. The raw message is encrypted with AES-256-GCM, using a data key from the secret `gateway/delayed_send_key` (auto-created if missing).
2. It is stored in `delayed_sends` with `send_at`.
3. An undo handle of kind `gmail_delayed_send` is written.
4. The gateway returns `200 {"id":"fortik-delayed-<action_id>","labelIds":["FORTIK_DELAYED"],"fortik":{"status":"delayed","send_at":...,"action_id":...}}`.
5. A worker polls every second with `FOR UPDATE SKIP LOCKED`. **Before sending it re-decides** the agent's level: anything stricter than SUPERVISED, or a QUARANTINED or KILLED agent, means the send is cancelled.
6. After sending, the handle becomes `used`/`expired` with the note "sent: not undoable".

Undo (`POST /v1/undo/{id}`) cancels the send if it hasn't gone yet. If it has, the response is `409 "already sent: NOT undoable"`.

### Drive `narrow_share` and `record_permission`

- On `permissions.create`, an `anyone` or external share is rewritten to `{type:"domain", domain:<primary domain>, role:<same>}`.
- After a 2xx, an undo handle of kind `drive_permission` is written with `{file_id, permission_id}`.
- The undo executor calls `permissions.delete`.

### GitHub `record_ref`

- Before forwarding, `GET /repos/{o}/{r}/git/ref/{ref}` reads the previous sha and an undo handle of kind `github_ref` is written with `{repo, ref, previous_sha}`.
- The undo executor does `PATCH /git/refs/{ref} {sha: previous, force: true}`.
- PR close and PR merge record `{repo, pr, previous_state}`. Undo of a close reopens the PR. A merge records the base ref instead.

## 7. Integrations

- **Table:** `integrations`. One row per system (`google_workspace`, `github`, `aws`) plus one per Postgres upstream (`postgres:<name>`). Columns: `config_json` (non-secret), `secret_fields` (the **names** of fields set, never values), `status` (`unconfigured|configured|ok|error`), `last_tested_at`, `last_error`, `updated_by`, `updated_at`.
- **Schema endpoint:** `GET /v1/integrations/schema` returns the field definitions the UI renders: `{system, title, fields:[{key,label,type:"text|textarea|password|list|select|number|bool",secret,required,help,options}]}`.

Fields per integration (**secret** marks write-only fields):

- **google_workspace:**
  - `primary_domain`*, `internal_domains` (list), `test_user`* (email for the connection test)
  - **secret:** `service_account_json`*
- **github:**
  - `api_base_url` (default `https://api.github.com`), `app_id`*, `installation_id`*
  - **secret:** `private_key_pem`*
- **aws:**
  - `region`*, `role_arn`*, `sts_endpoint` (optional, for testing), `iam_endpoint` (optional)
  - **secret:** `access_key_id`*, `secret_access_key`*, `external_id` (optional)
  - Fortik's own credentials must be able to call `sts:AssumeRole` on `role_arn` and `iam:PutRolePolicy` and `iam:GetRolePolicy` on that role (revocations are kept in one inline policy, `fortik-revoke`).
- **postgres:<name>:**
  - `host`*, `port`, `database`*, `sslmode`, `environment`* (`prod|staging|dev`), `admin_user`*, `read_role`*, `write_role`*
  - **secret:** `admin_password`*

**API:**

| Endpoint | Role | Behaviour |
|---|---|---|
| `GET /v1/integrations` | auditor | Configured integrations. Secrets appear only as `{"set": true}`. |
| `PUT /v1/integrations/{key}` | security | Body `{"config":{...},"secrets":{...}}`. An omitted secret field keeps its current value; an empty string is rejected. Validates, writes secrets to the store first and then the row, and records Diary `integration.configured` with the config, the secret field *names* and a sha256 fingerprint prefix. Never logs values. |
| `POST /v1/integrations/{key}/test` | security | Runs the system's live tester with a 15 s timeout. Updates `status`/`last_error` (sanitised) and writes Diary `integration.tested`. |
| `DELETE /v1/integrations/{key}` | security | Deletes the secrets and the row. Diary entry. |

**Testers:**
- Google: mints a DWD token for `test_user` and calls `gmail users.getProfile`.
- GitHub: creates the app JWT, calls `GET /app/installations/{id}`, mints a minimal token, then revokes it.
- AWS: AssumeRole with a read-only session policy, then `GetCallerIdentity`.
- Postgres: connects as admin, checks that `read_role`/`write_role` exist, and checks the CREATEROLE privilege.

Postgres upstreams come from the integrations table, **merged** with the YAML config (the DB wins on a key clash). An upstream with `admin_user` uses broker-managed per-agent roles. A YAML-only upstream keeps the Phase 1 static user, which is marked "legacy" in the UI.

## 8. Humans: login, roles, ownership

- **OIDC** with authorization code + PKCE, using `go-oidc` and `oauth2`.
  - Config: `auth.oidc.{issuer, client_id, client_secret_secret, redirect_url, role_claim, role_map, email_roles}`.
  - Routes: `/auth/login`, `/auth/callback`, `/auth/logout`, and `GET /v1/me` → `{email, name, roles, auth_method}`.
- **Dev login:** `auth.dev_login.enabled`, with users `[{email, roles}]`.
  - **Refused at startup unless the API listens on loopback.**
  - `POST /auth/dev-login {email}` → session. The UI shows a "DEV LOGIN" banner.
- **Sessions:** a random 32-byte id. Its SHA-256 is stored in `console_sessions` (12 h absolute, 1 h idle). The cookie is `fortik_session`: HttpOnly, SameSite=Strict, and Secure when the API isn't on loopback.
  - **CSRF:** every non-GET with a session cookie must send `X-Fortik-CSRF`, equal to the `csrf` value from `GET /v1/me`.
- **Bearer tokens** (Phase 1) still work for services.
- **The `authz.Principal` type** is shared by the API and gateway: `{Kind: "token"|"user"|"agent", Name, Email, Roles}`. `Actor()` gives `token:x`, `user:email` or `agent:id`.
- **Roles:** `admin`, `security`, `auditor`, `interceptor`, and *owner*.
  - Owner is not a role: a user is the owner of an agent when their email equals `agents.sponsor`.
  - Owners may step their own agent up one level, and may edit its access profile only to *narrow* it. Widening needs `security`.

## 9. Control ladder API

`PUT /v1/agents/{id}/level` with body `{"level":"READ_ONLY","reason":"..."}`. The reason is required.

| Change | Who may do it |
|---|---|
| Step down to any level below KILLED | `security`, or the owner |
| Step up, **exactly one level** | `security`, or the owner |
| Set KILLED, or leave KILLED | `security` only |

- Every change writes Diary `agent.level_changed` with the actor and the reason.
- **Automatic rule (Decide):** when a yellow action is held and the agent has ≥ `ladder.yellow_holds_threshold` (3) held yellow actions within `ladder.yellow_window` (10 m), it steps down to SUPERVISED, recorded under rule `LADDER-3Y`. This happens in the same transaction.
- **On a change to QUARANTINED or KILLED:** `broker.RevokeAll(agent)`, best effort, one Diary event per system recording the *actual* semantics, e.g. `aws: deny-by-issue-time attached (tokens not recallable)`.

## 10. Agent management API

- `POST /v1/agents` (security): register `{agent_id, name, type, platform, sponsor, business_unit, workspace_user, copy_cap}`.
- `PATCH /v1/agents/{id}` (security): update the same fields, except `agent_id` and level.
- `GET /v1/agents/{id}` (auditor): the agent, its level, profiles, integration readiness, recent counts by class over 24 h, and held actions.
- `POST /v1/agents/{id}/tokens` (security): returns `{"token":"agt_..."}` **once**. Only the sha256 is stored, in the `agent_tokens` secret (read-modify-write under a process lock and a version check). Diary `agent.token_issued` records the fingerprint prefix only.
- `DELETE /v1/agents/{id}/tokens` (security): revokes all of the agent's tokens.

## 11. Live events

- **Interface:** `events.Bus` with Publish and Subscribe.
  - Implementations: `memory`, and `nats` (JetStream, stream `FORTIK`, subjects `fortik.diary.<event_type>`).
  - Config: `events.{provider, url}`.
- **Diary tailer:**
  - Polls `diary` every 250 ms for `seq > last` and publishes each entry. This is the outbox pattern: the Diary is the source of truth, so nothing can be published that didn't commit.
  - Exactly one tailer per process. Consumers dedupe by seq.
- **Stream endpoint:** `GET /v1/events/stream` (auditor, SSE) sends `event: diary` with `data: {seq, ts, agent_id, event_type, data}`.
  - Supports `Last-Event-ID` for resume.
  - Heartbeats every 15 s.

## 12. Console (React + TypeScript, `web/console`)

Vite build output is embedded with `go:embed` in `internal/console` and served at `/`. The SPA falls back to `index.html`.

Screens in Phase 2:
- **Login:** OIDC button, plus dev login when enabled.
- **Agents:** the v2 screen on live data.
  - KPI row: total agents, actions today, held/pending, dangerous (red) today, agents not at FULL.
  - Table: agent, owner, actions today, level chip, action-type icons, risk (worst class over 24 h), status.
  - Detail panel tabs:
    - Overview: action mix, class counts, recent timeline.
    - Access: one editor per system, with history and revert.
    - Level: step down, step up, kill; reason required; role-gated buttons.
    - Held actions: read-only in Phase 2.
  - Live updates over SSE.
- **Integrations:** a card per system with a status chip.
  - Configure form rendered from `/v1/integrations/schema`. Secrets are write-only: shown as "••• set", with "Replace".
  - "Test connection" button, with last tested and last error.
  - Postgres upstreams can be added.
- **Agent tokens:** issue from the agent detail page; the token is shown once with a copy button.

Command Center is Phase 4 and the Communication Map is Phase 5. They appear in the nav as "coming in Phase 4/5" and are disabled.

The visual style follows the supplied v2 screenshots: light theme, white cards, Fortik shield, green/blue/amber/red class colours.

## 13. Schema additions (migration 0003)

- `agents`: add `workspace_user text`.
- `access_profiles`: `agent_id`, `system`, `version`, `profile_json`, `changed_by`, `changed_at`, `reason`. PK `(agent_id, system, version)`.
- `integrations`: `key` PK, `system`, `config_json`, `secret_fields`, `status`, `last_tested_at`, `last_error`, `updated_by`, `updated_at`.
- `credential_issuances`: `issuance_id` PK, `action_id`, `agent_id`, `instance_id`, `system`, `scope_json`, `expires_at`, `revoked_at`, `revoke_method`, `created_at`.
- `delayed_sends`: `action_id` PK, `agent_id`, `send_at`, `status` (`pending|sent|cancelled|failed`), `payload_enc` (bytea), `nonce`, `key_id`, `meta_json`, `sent_at`, `error`.
- `console_sessions`: `id_sha256` PK, `email`, `name`, `roles`, `auth_method`, `csrf`, `created_at`, `last_seen_at`, `expires_at`.
- `undo_handles.kind` allows the new kinds.

## 14. Testing without real accounts

Every adapter gets contract tests against **local fakes** that implement the subset of the real API used:
- Google: an OAuth token endpoint, Gmail send and getProfile, Drive permissions and files.
- GitHub: app installation, tokens, refs, pulls, contents, branches.
- AWS: **moto** in server mode for STS/IAM where the API shape matters, plus `httptest` fakes.

Fakes are clearly marked as fakes. **Real-sandbox verification is pending your credentials**; the phase report will say so explicitly. Once you enter credentials in the UI, the "Test connection" button and `scripts/demo-phase2.sh --live` exercise the real systems.

## 15. Ownership (parallel workstreams)

| WS | Owns | Builds |
|---|---|---|
| A | `internal/secrets`, `internal/integrations` | encfile and vault stores; integrations store, API, registry, tester interface |
| B | `internal/access`, `internal/broker`, `internal/broker/aws`, `policies/fortik/access`, decide changes (`input.access`, LADDER-3Y) | profiles, broker core, AWS STS adapter, revocation, Rego access gate and tests |
| C | `internal/gateway`, `internal/gateway/google` | gateway server, agent auth, Gmail/Drive adapter, delayed-send worker, Drive undo |
| D | `internal/gateway/github`, `internal/broker/github` | GitHub REST adapter, app JWT and installation tokens, record_ref and undo |
| E | `internal/broker/pgroles`, `internal/pgproxy` changes | per-agent upstream roles, rotation, revocation, proxy integration, upstreams from integrations |
| F | `internal/authz`, `internal/auth`, `internal/events`, `internal/api` changes | OIDC, dev login, sessions, CSRF, level API, agents/tokens API, SSE |
| G | `web/console`, `internal/console` | React app and embedding |

Contract Go files (written by the lead before the workstreams start):
- `internal/secrets/store.go`
- `internal/access/types.go`
- `internal/broker/types.go`
- `internal/gateway/types.go`
- `internal/integrations/types.go`
- `internal/authz/principal.go`
- `internal/events/types.go`
- `migrations/0003_phase2.sql`
- `internal/config/config.go` (Phase 2 sections)
