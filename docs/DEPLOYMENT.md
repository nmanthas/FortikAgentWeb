# Deploying Fortik for a design-partner pilot

This guide is for the engineers who install Fortik in a design partner's environment and run the pilot. Fortik runs inside the customer's network (their VPC). It needs:
- its own PostgreSQL;
- Redis and NATS;
- one Fortik service (API and console, app gateway, Postgres proxy, agentgateway callout);
- the least-privileged accounts listed in §5 on each system it governs.

| Part | What it is |
|---|---|
| `Dockerfile` | The image: distroless, non-root (uid 65532), read-only root filesystem, console and policies inside |
| `deploy/compose/` | One VM with Docker Compose (recommended for pilots) |
| `deploy/helm/fortik/` | Kubernetes |
| `docs/PHASE6_DESIGN.md` | Observe mode, connectors, metrics, mTLS, chaos and load results |

---

## 1. Topology

```
 agents / Claude Code / agentgateway                   security team (browser)
        │ mutual TLS                                           │ TLS + SSO (OIDC)
        ▼                                                      ▼
 ┌───────────────────────────── Fortik ─────────────────────────────┐
 │ :8090 app gateway + hook   :6432 Postgres proxy   :9091 callout  │
 │ :8443 API + console        decide (OPA, embedded) · Diary         │
 └───────┬───────────────┬──────────────┬───────────────────────────┘
         │ private network (no published ports)
     PostgreSQL        Redis          NATS            secret store (encfile or Vault)
         │
 customer systems, through Fortik's least-privilege accounts:
 Google Workspace · GitHub · AWS · customer Postgres · memory store · job queues
```

| Port | Listener | Who calls it | TLS |
|---|---|---|---|
| 8443 | API + console | browsers (SSO), interceptors, scripts | TLS; tokens or SSO sessions |
| 8090 | app gateway, `/v1/credentials/issue`, `/v1/hook/claude-code`, `/oauth/*` (connectors) | agents, the Claude Code hook | **mutual TLS** (client certificate required) |
| 6432 | Postgres proxy | agents' database clients | **TLS required + client certificate** |
| 9091 | agentgateway ext_authz / ext_proc callout (gRPC) | agentgateway | **mutual TLS** |

Fortik refuses to serve plaintext on a non-loopback address unless `tls.insecure_plaintext` is set explicitly (for example behind a TLS-terminating sidecar).

---

## 2. Option A: Docker Compose on one VM (pilots)

Requirements:
- a Linux VM with 2 vCPU, 4 GB RAM and 20 GB disk;
- Docker with the Compose plugin, and OpenSSL;
- outbound HTTPS to the governed systems;
- inbound access to 8443/8090/6432/9091 from the agents' and users' networks only.

```bash
git clone <repo> && cd FortikAgentWeb/deploy/compose     # or unzip the release
./init.sh fortik.corp.example.com     # once: .env (random passwords, master key), TLS, bootstrap secrets
docker compose up -d                  # Postgres, Redis, NATS, migrations, Fortik
./smoke-test.sh                       # 12 checks: TLS, mTLS, observe mode, Diary, no published backends
```

`init.sh` writes these files, none of which should leave the VM:

| File | What it holds |
|---|---|
| `.env` (mode 600) | Random database, Redis and owner passwords, and `FORTIK_MASTER_KEY`, the key of the encrypted secret store. In a real pilot, keep the master key in the customer's KMS and inject it at start instead of keeping it in `.env`. |
| `tls/` | A development CA, the server certificate and client certificates (`client-hook`, `client-interceptor`, `client-agentgateway`, `client-agent`). Replace them with the customer's PKI using the same file names: `ca.crt`, `server.crt`/`server.key`, `client-*.crt`/`.key`. |
| `data/secrets/` | The encrypted secret store: API tokens (hashes), agent tokens, the Diary signing key. Later it also holds integration credentials and connector grants. |
| `tokens.env` (mode 600) | The admin, security, auditor and interceptor API tokens. Shown once; move them to a password manager. |

Containers:
- Fortik runs as the VM user that ran `init.sh`, never root, with a read-only root filesystem, no capabilities and `no-new-privileges`.
- Postgres, Redis and NATS are on an internal-only Docker network.

Day-2 commands:

```bash
docker compose logs -f fortik                    # JSON logs
docker compose pull && docker compose up -d      # upgrade (the migrate service runs first)
docker compose exec postgres pg_dump -U postgres fortik > fortik-$(date +%F).sql   # backup (Diary included)
```

---

## 3. Option B: Kubernetes (Helm)

**1. Build and push the image:**

```bash
docker build -t registry.example.com/fortik:phase6 .
docker push registry.example.com/fortik:phase6
```

**2. Create the credentials and TLS secrets.** Never put credentials in values files.

```bash
kubectl create namespace fortik
kubectl -n fortik create secret generic fortik-credentials \
  --from-literal=database-url='postgres://fortik_app:...@pg.internal:5432/fortik?sslmode=verify-full' \
  --from-literal=owner-database-url='postgres://fortik_owner:...@pg.internal:5432/fortik?sslmode=verify-full' \
  --from-literal=redis-url='rediss://:...@redis.internal:6379/0' \
  --from-literal=master-key="$(openssl rand -base64 32)"        # or vault-token with secrets.provider: vault
kubectl -n fortik create secret generic fortik-tls --type kubernetes.io/tls \
  --from-file=tls.crt=server.crt --from-file=tls.key=server.key --from-file=ca.crt=ca.crt   # or a cert-manager Certificate
```

**3. Prepare the database.** The PostgreSQL instance needs two roles, as in `deploy/compose/postgres-init.sh`:
- `fortik_owner` owns the database and runs migrations;
- `fortik_app` is a login role with nothing else: the migration job grants it exactly what `migrations/app_grants.sql.tmpl` lists.

**4. Install:**

```bash
helm install fortik deploy/helm/fortik -n fortik \
  --set image.repository=registry.example.com/fortik --set image.tag=phase6 \
  --set 'config.api.allowed_hosts={fortik.corp.example.com}'
```

The chart:
- runs `fortik migrate -grant-app fortik_app` as a pre-install/pre-upgrade job, the only place the owner credentials are used;
- creates the Deployment, Service, NetworkPolicy and ServiceAccount (no Kubernetes API token);
- adds a PodDisruptionBudget when there is more than one replica;
- refuses unsafe settings: dev login, token pairs as two approvers, and more than one replica without Redis, NATS and Vault.

Probes use `fortik healthz` over TLS.

**5. Bootstrap the secret store once.** These are the same three secrets `init.sh` creates:

```bash
kubectl -n fortik exec deploy/fortik-fortik -- fortik secrets put -if-absent -config /etc/fortik/fortik.yaml -name diary_signing_key < <(fortik keygen)
# api_tokens: JSON [{"name","sha256","roles"}] (sha256 of each token); agent_tokens: {}
```

With Vault (`config.secrets.provider: vault`), write the secrets to `secret/fortik/<name>` instead.

> **Tested:** `helm lint`, `helm template`, and `fortik config check` on the rendered configuration.
> **Not yet tested:** installing on a live cluster. Do that in the partner's staging cluster first.

---

## 4. TLS for the callers

| Caller | Setting |
|---|---|
| Claude Code hook | `FORTIK_GATEWAY_URL=https://fortik.corp.example.com:8090`, `FORTIK_CA_FILE=ca.crt`, `FORTIK_CLIENT_CERT=client-hook.crt`, `FORTIK_CLIENT_KEY=client-hook.key` (plus the agent token). Any TLS problem blocks the tool call. |
| Agents' database clients | `host=fortik... port=6432 sslmode=verify-full sslrootcert=ca.crt sslcert=client-agent.crt sslkey=client-agent.key user=<agent_id> password=<agent token>` |
| agentgateway | upstream TLS to `fortik:9091` with `client-agentgateway.crt/.key` and `ca.crt`. Generate the routes with `fortik agentgw config`. |
| Interceptors calling `/v1/actions/decide` | HTTPS to :8443 with the interceptor token. |
| Fortik → Postgres | `sslmode=verify-full` in the database URLs. |
| Fortik → Redis | `rediss://` |
| Fortik → NATS | `events.tls_ca_file`, `tls_cert_file`, `tls_key_file` when NATS is not on the private network. |

---

## 5. Fortik's own accounts on each system: least privilege

Fortik is the crown jewel: it holds the accounts below. Give it exactly this much and nothing else. Every credential goes into the secret store (console → **Integrations**), never into Postgres or config files.

### PostgreSQL (each customer database Fortik protects)

- **An admin role with CREATEROLE, not a superuser.** It may grant two existing NOLOGIN roles: a read role (SELECT grants) and a write role. Fortik uses it to create, rotate and disable per-agent login roles (`fortik_a_<agent>`), and to run undo snapshots and safe forms.
- **Extra grants:**
  - `pg_signal_backend`, so revocation ends live sessions;
  - `pg_read_all_stats`, optional, so shadow discovery sees client hosts;
  - `USAGE` on the `fortik_undo` schema.
- **Agents' own direct credentials** to that database are removed (onboarding checklist). Shadow discovery finds the ones left: standing login roles used by software, including superusers. Superusers are reported, never altered.

### Google Workspace

- **A service account with domain-wide delegation**, authorised in Admin console → Security → API controls → Domain-wide delegation for:
  - Gmail and Drive (the app gateway): `gmail.readonly`, `gmail.send`, `gmail.compose`, `gmail.modify`, `mail.google.com`, `gmail.settings.basic`, `gmail.settings.sharing`, `drive`, `drive.readonly`. Fortik requests the narrowest of these per call.
  - Shadow discovery: `admin.directory.user.readonly` and `admin.directory.user.security` (list and revoke users' OAuth grants).
  - Connector audit pulls: `admin.reports.audit.readonly`.
- **The admin user** that discovery impersonates (`admin_user`) is a dedicated account with the minimum admin role that can read users and their tokens.

### GitHub

A GitHub App installed on the organisation, with repository permissions:
- Contents: write; Pull requests: write; Metadata: read. These are the ceiling; agents get installation tokens narrowed per call to the repositories and permissions in their access profile.
- Shadow discovery adds organisation permissions: Personal access tokens (read; write to revoke) and Administration (read).

### AWS

- **An IAM user (or role) for Fortik** with only these permissions:
  - `sts:AssumeRole` and `sts:SetSourceIdentity` on the agents' role;
  - `iam:PutRolePolicy` and `iam:GetRolePolicy` on that role (for the `fortik-revocations` deny policy).
- **For shadow discovery, also:** `iam:ListUsers`, `iam:ListAccessKeys` and `iam:GetAccessKeyLastUsed`; plus `iam:UpdateAccessKey` to deactivate flagged keys.
- **The agents' role** trusts only Fortik's principal (with `sts:ExternalId` when required). Its permissions are the ceiling; Fortik narrows each session with a session policy.

### Memory store (Postgres with pgvector)

A role that owns the `fortik_memory` schema. Agents never receive memory-store credentials.

### Job queues (optional)

| Queue | What Fortik needs |
|---|---|
| Temporal | An API key with write access to the namespace (pause/resume/cancel workflows tagged `FortikAgentId`). |
| Celery | The broker URL. Fortik moves only messages tagged `fortik_agent_id`. |
| Webhook | A shared HMAC secret of at least 16 characters. |

### SaaS copilot connectors (optional, `connectors.enabled`)

- **Google:**
  - an OAuth client (type: web application) owned by Fortik in the customer's Google Cloud project;
  - its redirect URI is `<public_url>/oauth/callback`;
  - the scopes a connector may request are set per connector at registration;
  - set `connectors.google.client_id` and store the client secret under the name in `client_secret_secret`.
- **GitHub:**
  - a GitHub App with **expiring user-to-server tokens** enabled (refresh tokens); callback URL `<public_url>/oauth/callback`;
  - set `connectors.github.client_id` and `client_secret_secret`;
  - for audit pulls also set `audit_org`, `app_id`, and a token with `read:audit_log` stored under `audit_token_secret`.
- **Then register each copilot** under **Connectors** in the console. Give the vendor the Fortik client id, the secret (shown once), the authorization URL and the token URL.
- **Reachability:** `/oauth/*` must be reachable by the vendor and by users' browsers. Expose that path on a listener without client certificates, for example an ingress route on the gateway with `gateway.tls.client_auth: request`.
- **Not yet tested against the real vendors:** the full flow is tested with local fakes of the Google and GitHub endpoints.

### Fortik's own database

| Role | Used for |
|---|---|
| `fortik_owner` | Migrations only. |
| `fortik_app` | What the server connects as: least privileges, no UPDATE or DELETE on the Diary. |

The Diary is append-only: database triggers enforce it, and `fortik_app` cannot disable them.

---

## 6. Running the pilot: observe, then enforce

1. **Week 0, install.** Install with `enforcement.mode: observe` (the Compose and Helm defaults). Configure integrations and register agents and access profiles. Fortik now decides and records every action but enforces only what is never relaxed:
   - unknown or unclassifiable actions;
   - fail-closed outcomes;
   - levels and suspensions set by people;
   - identity checks;
   - copy and rate caps.
2. **Weeks 1–2, observe.** In the console:
   - observed actions carry an "observe: would hold / deny / reduce" chip, and the Diary records the would-be decision;
   - the Command Center's **Pilot success metrics** card measures the plan's targets on this deployment;
   - tune access profiles and policy data with the partner.
3. **Enforce per agent.** On the agent page, under the Level tab → **Enforcement**, set agents to *Enforce* one at a time, starting with the riskiest. This needs the security role and a reason, and is written to the Diary.
4. **Enforce the deployment.** Set `enforcement.mode: enforce` and restart. The change is recorded in the Diary as `enforcement.deployment_mode`.

Success metrics (`GET /v1/metrics/pilot`; plan targets):

| Metric | Target |
|---|---|
| Risky actions handled without a kill | ≥ 95% |
| False alarms on red | < 2% overturned |
| Red action → step-down | p50 < 1 s |
| Undo success | 100% |
| Green overhead | p95 < 50 ms |

---

## 7. Operations

### Fail behaviour

Verified by `scripts/chaos-test.sh`:

| What breaks | What happens |
|---|---|
| Redis | Decisions fail closed; only green reads on `fail.green_read_allowlist` pass. |
| NATS | Decisions continue (the Diary is the source of truth); live streams catch up. |
| Fortik | The hook blocks; the proxy and gateway refuse connections. |
| Fortik's database | Decisions fail closed and are spooled locally (`fail.spool_dir`), then added to the Diary when the database is back. |

### Backups and keys

- **Back up** Fortik's Postgres (it holds the Diary and every decision) and the secret store.
- **The master key** lives in the customer's KMS. The Diary signing key can be rotated: keep retired public keys in `diary.retired_public_keys`.
- **Verify the Diary** any time with `fortik diary verify` or `GET /v1/diary/verify`.

### Upgrades

- Every policy change passes the replay gate: `go test ./internal/replay`, or `fortik replay run` against 10,000 recorded inputs. A class change blocks the merge until it is reviewed and accepted with `fortik replay update`.
- Migrations run before the new version serves.

### Monitoring and capacity

- **Monitoring:** `GET /metrics` (Prometheus; auditor role) and JSON logs. Alert on `fortik_fail_closed_total` and on a growing fail spool.
- **Capacity:** one instance sustained 200 decisions/s with p95 under 4 ms (`scripts/loadtest.sh`, k6), far below the 50 ms target.

---

## 8. Security checklist before go-live

- [ ] Dev login disabled; console login through the customer's OIDC (`auth.oidc`), with roles mapped from groups.
- [ ] `approvals.allow_token_pairs: false`, so two-person rules need two people.
- [ ] TLS everywhere; mutual TLS on 8090, 6432 and 9091; the customer's PKI in place of the development CA.
- [ ] Postgres, Redis and NATS not reachable from outside Fortik's network.
- [ ] Master key in KMS or Vault; `.env`, `tokens.env` and client keys not on shared disks.
- [ ] Each system account matches §5 exactly; agents' standing credentials removed (re-run shadow discovery).
- [ ] `fortik diary verify` passes; a signed export has been taken and checked.
- [ ] The replay gate runs in CI for policy changes.
- [ ] `FORTIK_POLICY_CAPTURE` is unset. `fortik serve` refuses to start with it on any non-loopback listener, because it would write every policy input, including recipients, to disk.
- [ ] The app role has exactly the grants of `fortik migrate -grant-app` (migrations/app_grants.sql.tmpl), re-applied after each upgrade.
