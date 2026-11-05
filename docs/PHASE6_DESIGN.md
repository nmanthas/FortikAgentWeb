# Phase 6 design: pilot-ready

**Plan scope** ("Phase 6 · Pilot-ready", gate: 3 design partners in observe mode):
- the **SaaS copilot connector broker**: copilots' Workspace and GitHub connectors use Fortik-issued OAuth clients, and the vendors' audit logs are pulled in for visibility. "Their access stops when Fortik stops issuing."
- **observe mode**: decide and record, but don't enforce;
- **test suites**:
  - a 10,000-action replay suite (any class change versus the last release blocks the merge);
  - chaos tests (kill Redis, NATS or the gateway mid-run; the hook and gateway must fail closed);
  - a k6 load test (200 actions/s, p95 Fortik overhead under 50 ms on green);
- **hardening**:
  - mTLS between components;
  - Docker Compose (pilots) and a Helm chart (Kubernetes);
  - a security review;
  - the deployment guide with least-privilege service accounts;
- **exit criteria**: the plan's "Done means" and its success metrics.

**Carried over from the Phase 5 review:** map telemetry must stop growing the Diary forever.

**Not in this phase** (needs the developer):
- running the demo scenarios against **real** Google Workspace, GitHub and AWS test accounts. The credentials are entered in the console later. This phase ships the real-account acceptance script `scripts/acceptance-real-accounts.sh`. It is marked UNTESTED until those accounts exist: today it is verified only to SKIP cleanly when an integration is not configured.
- choosing the 3 design partners.

---

## 1. Observe mode

`enforcement.mode: enforce | observe` (default `enforce`), plus a per-agent override (`agents.enforcement`: `default | observe | enforce`), set by security through `PUT /v1/agents/{id}/enforcement`.

In observe mode Fortik still evaluates every action, writes it to `actions` and the Diary, and feeds the map, baselines, swarm detection and alerts. It **does not enforce what the policy decided**:
- `hold`, `deny` and `allow_reduced` from **policy findings** become `allow`. The result keeps its class and rule, and carries `observed: {decision, reason, reduced_form, ladder_change}`, which is what would have happened.
- no held action is created, no reduced form is applied, and there is no automatic step-down. A would-be ladder change is recorded, not applied.

Observe mode never weakens these, because none of them is a policy *opinion*:
- **unknown or unclassifiable actions** (POL-002) and **fail-closed** outcomes (Fortik could not decide) are still refused. Master rule: never allow unknown actions through a protected path.
- **a level set by a human** (suspend, isolate, quarantine, kill, E-Stop) and timed suspensions are enforced. Containment is a human decision, not the classifier's.
- **unregistered agents** (POL-015) are refused.
- **revoked credentials** stay revoked.

Every change of mode is a Diary event (`enforcement.changed`), and needs the security role. The console shows an "OBSERVE" banner and marks would-be decisions.

## 2. Replay suite

- **The corpus:** `testdata/replay/corpus.jsonl.gz`, 10,000 full `policy.Input` records. Each record has its expected result as of the last release: class, decision, rule_id, approvals_required and whether a ladder change happens.
- `fortik replay build -capture F[,F…]` builds the corpus from **captured real policy inputs**. Set `FORTIK_POLICY_CAPTURE=path-{pid}.jsonl` while running the Go tests and the demo scripts, and every evaluated input is recorded. Capture is development only: `fortik serve` refuses it unless every listener is loopback. The build deduplicates the inputs, expands each one with variants (other control levels, observe mode, an unregistered agent), and selects 10,000 records round-robin across the (system, verb, class, decision, rule) strata in ID order. Every kind of decision that occurred is represented, and the selection is reproducible.
- `fortik replay run` evaluates every record with the policy bundle in the tree and reports every difference.
- `go test ./internal/replay` runs the same check in CI. **Any class change fails the build.** Decision, rule and step-down changes fail too: they are behaviour changes that must be reviewed.
- `fortik replay update` rewrites the expected results after a reviewed policy change. It prints the changes it accepts, and that diff is the review artifact.

## 3. Chaos tests

`scripts/chaos-test.sh` runs Fortik with **real** Redis (counters, baselines) and **real** NATS (events), then breaks things mid-run:

| Fault | Expected |
|---|---|
| Redis killed | Decisions that need counters fail **closed** (deny, FAIL-CLOSED); reads on the fail-open allowlist are allowed and recorded; after Redis returns, decisions recover and baselines are reloaded |
| NATS killed | Decisions continue and are recorded (the Diary is the source of truth); live events resume after NATS returns, nothing lost (outbox) |
| Fortik (gateway/hook server) killed | The Claude Code hook client blocks (exit 2); the app gateway and Postgres proxy refuse connections, and no call reaches the systems; an agentgateway route configured with `failureMode: deny` refuses |
| Postgres (Fortik's DB) killed | Every decision fails closed; recorded to the local spool and appended to the Diary when the DB returns |

Fail-path records that cannot be written to the database go to a **local append-only spool** (`fail.spool_dir`). They are appended to the Diary once the database is back (`action.decided` with `fail_closed`/`fail_open` and `recovered_from_spool: true`).

## 4. Load test

`loadtest/k6/decide.js` (k6):
- a constant arrival rate of **200 actions/s** for 2 minutes, green actions (READ) spread over 300 load-test agents (`fortik loadtest seed`);
- threshold: **p95 < 50 ms** on the HTTP round trip, plus a custom trend of the server-side `latency_us`.

The decide endpoint is exactly the gateways' in-process decision path, without the upstream API's own latency, which is what the plan's metric excludes.

## 5. mTLS between components

One TLS block per listener (`api.tls`, `gateway.tls`, `agentgw.tls`, `pgproxy.tls`):
- `{cert_file, key_file, client_ca_file, client_auth: none | request | require}`, TLS 1.2+.
- With `client_auth: require`, a client without a certificate signed by `client_ca_file` cannot connect. Bearer tokens are still required on top (defense in depth).

Clients:
- the hook client (`FORTIK_CA_FILE`, `FORTIK_CLIENT_CERT`, `FORTIK_CLIENT_KEY`);
- Fortik to Postgres (`sslmode=verify-full` in the URL);
- Redis (`rediss://`);
- NATS (`events.tls`);
- Vault (already TLS).

`fortik certs dev` writes a dev CA plus server and client certificates for local mTLS testing; pilots bring their own PKI. A non-loopback listener without TLS refuses to start unless `<listener>.tls.insecure_plaintext` is explicitly set, for example behind a TLS-terminating proxy.

## 6. SaaS copilot connector broker

Fortik is the copilot connector's **OAuth server**. The vendor's connector is configured with:
- authorize URL `https://<fortik>/oauth/authorize`;
- token URL `https://<fortik>/oauth/token`;
- a client id and secret that Fortik issued for that connector.

The flow:
1. **Registration.** Security registers a connector: `POST /v1/connectors {agent_id, name, sponsor, team, vendor, upstream: google_workspace|github, redirect_uris, scopes, reason}`. The copilot becomes a normal Fortik agent. The registered scopes are the most it can ever get. The client secret is shown once and only its hash is stored.
2. **Consent.** `/oauth/authorize` checks the client and the exact redirect URI, narrows the requested scopes to the registered ones, and redirects the user to the upstream (Google or GitHub) with **Fortik's own upstream OAuth client**. At most 200 authorizations per connector can be open at once.
3. **Code exchange.**
   - At `/oauth/callback`, Fortik exchanges the upstream code and keeps the upstream refresh token, encrypted in the secret store, never in Postgres.
   - It redirects the copilot with a one-time Fortik code (2 minutes; PKCE S256 supported).
   - `/oauth/token` (authorization_code) returns a short-lived upstream **access token** and a **Fortik refresh token** (opaque; only its hash is stored). A replayed code revokes the grant.
4. **Refresh.** Every token issue is a **decision**: system `connector`, verb READ when every scope is read-only and WRITE otherwise. GRANT would always be red. The Fortik refresh token rotates on each use, and reuse of an old one revokes the grant.
   - Agent level, timed suspensions and kill all apply.
   - Allowed: Fortik refreshes upstream and returns a new access token.
   - Refused: `invalid_grant`.
   - Kill, isolate, quarantine, a connector disable, or a timed suspension of an upstream system also **revokes the upstream grant** (Google revoke endpoint; GitHub DELETE grant), so access stops at once, not at token expiry.
5. **Visibility.** The vendors' audit logs are pulled for the connector's OAuth client:
   - Google: the Admin Reports API, `token` and `drive` activities filtered by client id;
   - GitHub: the org audit log, filtered by the OAuth app.
   
   They are recorded as observed actions (`source: vendor_audit`, decision `observed`), so they appear on the map and in the Diary.

This is exactly "their access stops when Fortik stops issuing". It is tested end to end with local fakes of the Google and GitHub OAuth and audit endpoints; real vendors are untested until accounts exist.

## 7. Success metrics

`GET /v1/metrics/pilot?from=&to=` (auditor) and a Command Center card:

| Metric (plan target) | Computed as |
|---|---|
| Risky actions handled without a kill (≥ 95%) | yellow/red decisions in the window whose agent was not KILLED in the window, out of all yellow/red |
| False-alarm rate on red (< 2% overturned) | red decisions whose hold was approved, or whose automatic step-down a human reversed within 24 h, out of all red |
| Time from red action to step-down (p50 < 1 s) | from the action's ts to its `control.level_changed` event |
| Undo success (100% of supported types) | undo runs that succeeded, out of all undo runs, per kind |
| Green overhead (p95 < 50 ms) | p95 of `latency_us` of green decisions |

In observe mode the same metrics use the would-be decisions.

## 8. Map telemetry out of the Diary

Rollup batches no longer write `map.edges_updated` into the hash-chained Diary.
- They write to `map_events` (`id bigserial`, `ts`, `payload jsonb`), which is pruned with the edges (`map.retention`).
- `/v1/map/live` reads from a poller of `map_events` and keeps the same SSE event names and ids, with Last-Event-ID resume on `map_events.id`.
- The Diary keeps the security events: hidden-signal alerts, swarms and containment.

## 9. Packaging and deployment

- `Dockerfile`: a multi-stage build (Go with cgo, needed by the pg_query SQL parser, then `distroless/base-debian12:nonroot`), running as uid 65532. Compose and Helm run it with a read-only root filesystem. The console is embedded.
- `deploy/compose/docker-compose.yml`:
  - Postgres with pgvector, Redis, NATS, a Fortik migrate job, and Fortik;
  - mTLS between Fortik and its clients using `fortik certs` output;
  - the secrets file mounted; healthchecks.
- `deploy/helm/fortik`:
  - Deployment, Service, ConfigMap and Secret references;
  - a migration Job (pre-install/upgrade hook) and a ServiceAccount;
  - NetworkPolicy, PodDisruptionBudget, a restricted security context, probes and resources.
  - Validated with `helm lint` and `helm template`.
- `docs/DEPLOYMENT.md`:
  - the pilot runbook: observe first, then enforce, per agent;
  - Fortik's own least-privilege service account per system: Google, GitHub App, AWS role, Postgres admin role, memory store;
  - network and TLS, secrets (Vault/KMS), backups and upgrades.

## 10. Rule ids and migrations

- **Migrations:**
  - `0010_phase6.sql`: `agents.enforcement`, `actions.observed`, `map_events`;
  - `0011_phase6_connectors.sql`: `connectors`, `connector_pending`, `connector_grants`, `connector_codes`, `connector_audit_seen`;
  - `0012_phase6_connector_bounds.sql`: indexes for the per-connector cap and pruning (security review);
  - `0013_phase6_notify.sql`: `alerts.notified_at`, `notify_attempts`, `notify_status`, and the `notify_slack` integration.
- **Rules** (`policies/fortik/rules/connector.rego`):
  - `POL-690`: the connector is not active (disabled);
  - `POL-691`: malformed connector target, or a verb or scope mismatch (fail closed).
- **Timed suspensions** of a system now cover actions that *reach* it (`target.reaches`, `target.upstream_systems`; POL-030/031).

## 11. Owner notifications

The plan: a restore "notifies the owner (console, plus Slack or email)".
- The console alert existed since Phase 3.
- Phase 6 adds the `notify_slack` integration (console > Integrations). `internal/notify` posts each security alert once to a Slack-compatible incoming webhook, with its severity, kind, summary, the agent and **the agent's owner** (sponsor). Examples: `override_restored`, `override_restore_blocked`, `delegation_bypass`, `swarm_detected`, `shadow_agent`.
- It has a minimum severity, an optional kind filter and an optional console link. Failed posts are retried 3 times, then recorded on the alert (`notify_status`). Alerts older than the integration are never sent.
- The webhook URL is a secret and never appears in logs or errors.
- Email (SMTP) is not built: Slack satisfies the plan's "Slack or email".
