#!/usr/bin/env bash
# Fortik local development environment (Phase 1).
#
# Creates, under ./.dev (gitignored):
#   - a private Postgres cluster on 127.0.0.1:55432 (trust auth, local only)
#   - database "fortik"   : Fortik's system of record
#       role fortik_owner : owns the schema, runs migrations
#       role fortik_app   : what `fortik serve` connects as; NOT the owner, so it
#                           cannot disable the Diary's append-only triggers
#   - databases "acme_prod" and "acme_staging": simulated CUSTOMER databases
#       role acme_agent   : upstream role the Fortik pgproxy uses
#   - .dev/secrets/*      : random dev-only secrets (never commit, never reuse)
#   - .dev/tokens.env     : the plaintext dev tokens, for demo scripts
#   (config: configs/fortik.dev.yaml, checked in, contains no secrets)
#
# Idempotent: re-running keeps existing data and secrets.
# Requires Postgres binaries (initdb/pg_ctl/psql). Set PGBIN if not on PATH.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEV="$ROOT/.dev"
PGBIN="${PGBIN:-$(dirname "$(command -v pg_ctl 2>/dev/null || echo /Library/PostgreSQL/17/bin/pg_ctl)")}"
PORT="${FORTIK_DEV_PG_PORT:-55432}"
PSQL=("$PGBIN/psql" -h 127.0.0.1 -p "$PORT" -U postgres -v ON_ERROR_STOP=1 -q)

mkdir -p "$DEV/secrets"
chmod 700 "$DEV" "$DEV/secrets"

# --- 1. Postgres cluster ------------------------------------------------------
if [ ! -f "$DEV/pg/PG_VERSION" ]; then
  echo "==> initdb $DEV/pg"
  "$PGBIN/initdb" -D "$DEV/pg" -U postgres --auth=trust -E UTF8 --locale=C >/dev/null
  cat >> "$DEV/pg/postgresql.conf" <<EOF
listen_addresses='127.0.0.1'
port=$PORT
# TCP only: every script connects to 127.0.0.1. A Unix socket under .dev
# fails when the checkout path is long (macOS limits socket paths to 103 bytes).
unix_socket_directories=''
max_connections=200
EOF
fi
if ! "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PORT" -q; then
  echo "==> starting Postgres on 127.0.0.1:$PORT"
  "$PGBIN/pg_ctl" -D "$DEV/pg" -l "$DEV/pg.log" start -w >/dev/null
fi

# --- 2. secrets (dev only; random per checkout) --------------------------------
rand() { openssl rand -hex 24; }
secret() { # name generator
  local f="$DEV/secrets/$1"
  [ -s "$f" ] || { $2 > "$f"; chmod 600 "$f"; }
}
secret acme_agent_password rand
secret fortik_app_password rand
secret diary_signing_key "openssl rand -base64 32"

if [ ! -s "$DEV/tokens.env" ]; then
  {
    echo "# Dev-only plaintext tokens. Never use outside local development."
    echo "FORTIK_TOKEN_ADMIN=adm_$(rand)"
    echo "FORTIK_TOKEN_SECURITY=sec_$(rand)"
    echo "FORTIK_TOKEN_AUDITOR=aud_$(rand)"
    echo "FORTIK_TOKEN_INTERCEPTOR=int_$(rand)"
    echo "FORTIK_AGENT_TOKEN_CLAUDE_CODE_01=agt_$(rand)"
    echo "FORTIK_AGENT_TOKEN_FINANCE_AGENT_07=agt_$(rand)"
    echo "FORTIK_AGENT_TOKEN_TEXT2SQL_AGENT_03=agt_$(rand)"
  } > "$DEV/tokens.env"
  chmod 600 "$DEV/tokens.env"
fi
# shellcheck disable=SC1091
source "$DEV/tokens.env"
sha() { printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1; }

cat > "$DEV/secrets/api_tokens" <<EOF
[
  {"name": "dev-admin",       "sha256": "$(sha "$FORTIK_TOKEN_ADMIN")",       "roles": ["admin"]},
  {"name": "dev-security",    "sha256": "$(sha "$FORTIK_TOKEN_SECURITY")",    "roles": ["security", "auditor"]},
  {"name": "dev-auditor",     "sha256": "$(sha "$FORTIK_TOKEN_AUDITOR")",     "roles": ["auditor"]},
  {"name": "dev-interceptor", "sha256": "$(sha "$FORTIK_TOKEN_INTERCEPTOR")", "roles": ["interceptor"]}
]
EOF
cat > "$DEV/secrets/agent_tokens" <<EOF
{
  "claude_code_01":   "$(sha "$FORTIK_AGENT_TOKEN_CLAUDE_CODE_01")",
  "finance_agent_07": "$(sha "$FORTIK_AGENT_TOKEN_FINANCE_AGENT_07")",
  "text2sql_agent_03": "$(sha "$FORTIK_AGENT_TOKEN_TEXT2SQL_AGENT_03")"
}
EOF
chmod 600 "$DEV/secrets/"*

# Phase 2: encrypted secret store (AES-256-GCM files). Master key stays outside the store.
if [ ! -s "$DEV/master.key" ]; then
  ( umask 077; openssl rand -base64 32 > "$DEV/master.key" )
fi
chmod 600 "$DEV/master.key"
secret fortik_broker_password rand

APP_PW="$(cat "$DEV/secrets/fortik_app_password")"
AGENT_PW="$(cat "$DEV/secrets/acme_agent_password")"

# --- 2b. authentication: customer databases require passwords ----------------------
# Fortik's own DB and the local superuser stay trust (dev only); the simulated
# customer databases use SCRAM so agents cannot bypass the proxy and rotated
# per-session passwords really expire.
HBA="$DEV/pg/pg_hba.conf"
if ! grep -q 'fortik-dev-hba' "$HBA"; then
  cat > "$HBA" <<'EOF2'
# fortik-dev-hba (written by scripts/dev-up.sh)
local all all trust
host  all postgres 127.0.0.1/32 trust
host  fortik all 127.0.0.1/32 trust
host  all all 127.0.0.1/32 scram-sha-256
host  all postgres ::1/128 trust
host  all all ::1/128 scram-sha-256
EOF2
  "$PGBIN/pg_ctl" -D "$DEV/pg" reload >/dev/null
fi

# --- 3. roles and databases ----------------------------------------------------
echo "==> roles and databases"
"${PSQL[@]}" <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fortik_owner') THEN CREATE ROLE fortik_owner LOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fortik_app')   THEN CREATE ROLE fortik_app LOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'acme_agent')   THEN CREATE ROLE acme_agent LOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'acme_read')    THEN CREATE ROLE acme_read NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fortik_broker') THEN CREATE ROLE fortik_broker LOGIN CREATEROLE; END IF;
END \$\$;
ALTER ROLE fortik_broker PASSWORD '$(cat "$DEV/secrets/fortik_broker_password")';
-- The broker grants per-agent roles membership in exactly one of these.
GRANT acme_read  TO fortik_broker WITH ADMIN TRUE, INHERIT FALSE;
GRANT acme_agent TO fortik_broker WITH ADMIN TRUE, INHERIT TRUE;   -- admin runs undo
GRANT pg_signal_backend TO fortik_broker;                         -- revocation ends sessions
GRANT pg_read_all_stats TO fortik_broker;                         -- shadow discovery sees client hosts
ALTER ROLE fortik_app PASSWORD '$APP_PW';
ALTER ROLE acme_agent PASSWORD '$AGENT_PW';
SQL
for db in fortik acme_prod acme_staging; do
  if [ "$("${PSQL[@]}" -tAc "SELECT 1 FROM pg_database WHERE datname='$db'")" != "1" ]; then
    owner=fortik_owner; [ "$db" != fortik ] && owner=acme_agent
    "${PSQL[@]}" -c "CREATE DATABASE $db OWNER $owner"
  fi
done

# --- 4. Fortik schema (as owner) + least-privilege grants for the app role ------
echo "==> migrations"
( cd "$ROOT" && go build -o bin/fortik ./cmd/fortik )
FORTIK_DATABASE_URL="postgres://fortik_owner@127.0.0.1:$PORT/fortik?sslmode=disable" \
  "$ROOT/bin/fortik" migrate -config "$ROOT/configs/fortik.dev.yaml"
"${PSQL[@]}" -d fortik <<'SQL'
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM fortik_app;
GRANT USAGE ON SCHEMA public TO fortik_app;
GRANT SELECT, INSERT, UPDATE ON agents, actions, held_actions, undo_handles TO fortik_app;
GRANT SELECT, INSERT ON diary, diary_roots TO fortik_app;          -- append-only: no UPDATE/DELETE
GRANT SELECT, UPDATE ON diary_head TO fortik_app;
GRANT SELECT ON schema_migrations TO fortik_app;
-- Phase 2
GRANT SELECT, INSERT ON access_profiles TO fortik_app;              -- append-only versions
GRANT SELECT, INSERT, UPDATE, DELETE ON integrations TO fortik_app;
GRANT SELECT, INSERT, UPDATE ON credential_issuances, delayed_sends TO fortik_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON console_sessions TO fortik_app;
-- Phase 3
GRANT SELECT, INSERT, UPDATE ON delegations, instances, alerts, access_overrides, approval_grants TO fortik_app;
GRANT SELECT, INSERT, UPDATE ON agent_types, spawn_stats TO fortik_app;
GRANT SELECT, INSERT ON held_approvals TO fortik_app;
GRANT UPDATE ON held_actions TO fortik_app;
-- Phase 4
GRANT SELECT, INSERT, UPDATE ON memory_access, memory_snapshots, containment_ops TO fortik_app;
-- Phase 5
GRANT SELECT, INSERT, UPDATE ON swarms, swarm_members, swarm_breakers, edge_rollup_state, shadow_findings TO fortik_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON swarm_release_votes, edges, baseline_hourly, edge_links TO fortik_app;
SQL

# --- 5. simulated customer databases (seeded) -----------------------------------
seed_customer_db() {
  local db="$1" orders="$2" customers="$3"
  echo "==> seeding $db ($orders orders, $customers customers)"
  PGPASSWORD="$AGENT_PW" "$PGBIN/psql" -h 127.0.0.1 -p "$PORT" -U acme_agent -d "$db" -v ON_ERROR_STOP=1 -q <<SQL
CREATE SCHEMA IF NOT EXISTS fortik_undo;
CREATE TABLE IF NOT EXISTS customers (
  id bigint PRIMARY KEY, name text NOT NULL, email text NOT NULL, phone text, country text, ltv_usd numeric(12,2));
CREATE TABLE IF NOT EXISTS orders (
  id bigserial PRIMARY KEY, customer_id bigint REFERENCES customers(id), status text NOT NULL,
  amount_usd numeric(12,2) NOT NULL, created_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (id bigserial PRIMARY KEY, msg text, at timestamptz DEFAULT now());
INSERT INTO customers
  SELECT g, 'Customer ' || g, 'customer' || g || '@example.com', '+1-555-' || lpad(g::text, 6, '0'),
         (ARRAY['US','IN','DE','GB','FR'])[1 + g % 5], (g % 997) * 3.5
  FROM generate_series(1, $customers) g ON CONFLICT DO NOTHING;
INSERT INTO orders (customer_id, status, amount_usd, created_at)
  SELECT 1 + g % $customers, (ARRAY['paid','shipped','refunded','pending'])[1 + g % 4], (g % 500) + 9.99,
         timestamptz '2023-01-01' + (g || ' hours')::interval
  FROM generate_series(1, $orders) g
  WHERE NOT EXISTS (SELECT 1 FROM orders LIMIT 1);
ANALYZE customers; ANALYZE orders;
GRANT USAGE ON SCHEMA public TO acme_read;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO acme_read;
GRANT USAGE ON SCHEMA fortik_undo TO fortik_broker;
SQL
  # As superuser: tables created by agents' own roles (e.g. a renamed trash
  # table) are not acme_agent's to grant on, so a re-run must not fail on them.
  "${PSQL[@]}" -d "$db" -qc "GRANT SELECT ON ALL TABLES IN SCHEMA public TO acme_read"
}
seed_customer_db acme_prod 5000 12480
seed_customer_db acme_staging 2000 2000

# --- 5b. encrypted secret store ----------------------------------------------------
echo "==> encrypted secret store (.dev/secrets-enc)"
# Seed only: once a secret exists it is managed by Fortik (the console/API
# rotates and revokes agent tokens), so a re-run must never overwrite it.
for n in api_tokens agent_tokens diary_signing_key; do
  "$ROOT/bin/fortik" secrets put -if-absent -config "$ROOT/configs/fortik.dev.yaml" -name "$n" < "$DEV/secrets/$n"
done

# --- 6. register demo agents -------------------------------------------------------
echo "==> registering demo agents"
"$ROOT/bin/fortik" agent register -config "$ROOT/configs/fortik.dev.yaml" -id claude_code_01 -name "Claude Code (pranav)" \
  -type claude_code -platform laptop -sponsor pranav.kumar@acme.com -team Engineering >/dev/null
"$ROOT/bin/fortik" agent register -config "$ROOT/configs/fortik.dev.yaml" -id finance_agent_07 -name "Finance agent" \
  -type langgraph -platform k8s -sponsor jane.smith@acme.com -team Finance >/dev/null
"$ROOT/bin/fortik" agent register -config "$ROOT/configs/fortik.dev.yaml" -id text2sql_agent_03 -name "Text-to-SQL agent" \
  -type text_to_sql -platform k8s -sponsor lisa.tan@acme.com -team Strategy >/dev/null

"${PSQL[@]}" -d fortik -c "UPDATE agents SET workspace_user = CASE agent_id
  WHEN 'claude_code_01' THEN 'pranav.kumar@acme.com' WHEN 'finance_agent_07' THEN 'finance-agent@acme.com'
  WHEN 'text2sql_agent_03' THEN 'lisa.tan@acme.com' ELSE workspace_user END" >/dev/null

# --- 7. Postgres upstream integrations (per-agent roles) + access profiles ----------
echo "==> integrations and access profiles"
F() { "$ROOT/bin/fortik" "$@" -config "$ROOT/configs/fortik.dev.yaml"; }
for env in prod staging; do
  F integration put -key "postgres:acme_$env" \
    -config-json "{\"host\":\"127.0.0.1\",\"port\":$PORT,\"database\":\"acme_$env\",\"sslmode\":\"disable\",\"environment\":\"$env\",\"admin_user\":\"fortik_broker\",\"read_role\":\"acme_read\",\"write_role\":\"acme_agent\"}" \
    -secrets-stdin >/dev/null < <(printf '{"admin_password":"%s"}' "$(cat "$DEV/secrets/fortik_broker_password")")
done
current() { "${PSQL[@]}" -d fortik -tAc "SELECT count(*) FROM access_profiles WHERE agent_id='$1' AND system='$2'"; }
seed() { # agent system json  (only if the agent has no profile yet: never clobber UI edits)
  [ "$(current "$1" "$2")" = "0" ] && F access set -id "$1" -system "$2" -profile "$3" -reason "dev seed" >/dev/null || true
}
seed claude_code_01   postgres '{"upstreams":{"acme_prod":"read_write","acme_staging":"read_write"}}'
seed claude_code_01   github   '{"repos":["acme/api"],"permissions":{"contents":"write","pull_requests":"write","metadata":"read"},"allow_direct_token":false}'
seed finance_agent_07 postgres '{"upstreams":{"acme_prod":"read_only"}}'
seed finance_agent_07 gmail    '{"send":"any","read":true,"max_recipients":25}'
seed finance_agent_07 drive    '{"mode":"read_write","share":"any"}'
seed text2sql_agent_03 postgres '{"upstreams":{"acme_prod":"read_only","acme_staging":"read_only"}}'
seed text2sql_agent_03 aws     '{"mode":"read_only","services":["s3"],"denied_actions":["iam:*"]}'

# Phase 3 demo agent tokens: append missing ones to tokens.env, merge hashes
# into the encrypted agent_tokens secret (never overwriting existing entries).
for v in PLANNER_AGENT_A RELAY_AGENT_B WEB_AGENT_C SWARM_WORKER; do
  grep -q "^FORTIK_AGENT_TOKEN_$v=" "$DEV/tokens.env" || echo "FORTIK_AGENT_TOKEN_$v=agt_$(rand)" >> "$DEV/tokens.env"
done
# shellcheck disable=SC1091
source "$DEV/tokens.env"
printf '{"planner_agent_a":"%s","relay_agent_b":"%s","web_agent_c":"%s","swarm_worker":"%s"}' \
  "$(sha "$FORTIK_AGENT_TOKEN_PLANNER_AGENT_A")" "$(sha "$FORTIK_AGENT_TOKEN_RELAY_AGENT_B")" \
  "$(sha "$FORTIK_AGENT_TOKEN_WEB_AGENT_C")" "$(sha "$FORTIK_AGENT_TOKEN_SWARM_WORKER")" \
  | "$ROOT/bin/fortik" secrets merge-json -config "$ROOT/configs/fortik.dev.yaml" -name agent_tokens

# --- 8. Phase 3 demo agents: delegation chains (UC1/UC3) and spawning (UC2) ----------
echo "==> Phase 3 demo agents"
for a in "planner_agent_a|Planner A (no external access)|planner" "relay_agent_b|Relay B (no external access)|relay" "web_agent_c|Web C (may browse)|web" "swarm_worker|Swarm worker|swarm_worker"; do
  IFS='|' read -r id name typ <<<"$a"
  F agent register -id "$id" -name "$name" -type "$typ" -platform langgraph -sponsor security@acme.com -team Research -copy-cap 6 >/dev/null
done
"${PSQL[@]}" -d fortik -q <<'SQL'
INSERT INTO agent_types (type, expected_max_instances, max_agents, spawn_rate_per_min, action_rate_per_min, updated_by)
VALUES ('swarm_worker', 5, 3, 10, 120, 'dev-up') ON CONFLICT (type) DO NOTHING;
UPDATE agents SET require_instances = true WHERE agent_id = 'swarm_worker';
SQL
seed planner_agent_a a2a  '{"may_delegate_to":["relay_agent_b"],"max_depth":3}'
seed planner_agent_a http '{"external":"none","allowed_domains":[]}'
seed relay_agent_b   a2a  '{"may_delegate_to":["web_agent_c"],"max_depth":3}'
seed relay_agent_b   http '{"external":"none","allowed_domains":[]}'
seed web_agent_c     http '{"external":"any","allowed_domains":[]}'
seed planner_agent_a postgres '{"upstreams":{"acme_prod":"read_only"}}'
seed web_agent_c     postgres '{"upstreams":{"acme_prod":"read_write"}}'

# --- 9. Phase 4: agent memory store (pgvector) and support agents -------------------
echo "==> Phase 4 memory store and support agents"
[ -s "$DEV/secrets/acme_memory_password" ] || rand > "$DEV/secrets/acme_memory_password"
chmod 600 "$DEV/secrets/acme_memory_password"
"${PSQL[@]}" -q <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'acme_memory_admin') THEN CREATE ROLE acme_memory_admin LOGIN; END IF;
END \$\$;
ALTER ROLE acme_memory_admin PASSWORD '$(cat "$DEV/secrets/acme_memory_password")';
SQL
if [ "$("${PSQL[@]}" -tAc "SELECT 1 FROM pg_database WHERE datname='acme_memory'")" != "1" ]; then
  "${PSQL[@]}" -c "CREATE DATABASE acme_memory OWNER acme_memory_admin" >/dev/null
fi
# pgvector needs a superuser to install; Fortik's admin role then owns schema fortik_memory.
"${PSQL[@]}" -d acme_memory -qc "CREATE EXTENSION IF NOT EXISTS vector"
F integration put -key "memory:support" \
  -config-json "{\"host\":\"127.0.0.1\",\"port\":$PORT,\"database\":\"acme_memory\",\"sslmode\":\"disable\",\"dimension\":3,\"admin_user\":\"acme_memory_admin\"}" \
  -secrets-stdin >/dev/null < <(printf '{"admin_password":"%s"}' "$(cat "$DEV/secrets/acme_memory_password")")

for v in SUPPORT_AGENT_01 SUPPORT_AGENT_02; do
  grep -q "^FORTIK_AGENT_TOKEN_$v=" "$DEV/tokens.env" || echo "FORTIK_AGENT_TOKEN_$v=agt_$(rand)" >> "$DEV/tokens.env"
done
# shellcheck disable=SC1091
source "$DEV/tokens.env"
printf '{"support_agent_01":"%s","support_agent_02":"%s"}' \
  "$(sha "$FORTIK_AGENT_TOKEN_SUPPORT_AGENT_01")" "$(sha "$FORTIK_AGENT_TOKEN_SUPPORT_AGENT_02")" \
  | "$ROOT/bin/fortik" secrets merge-json -config "$ROOT/configs/fortik.dev.yaml" -name agent_tokens
F agent register -id support_agent_01 -name "Support agent (memory)" -type support -platform langgraph \
  -sponsor pranav.kumar@acme.com -team Support -copy-cap 2 >/dev/null
F agent register -id support_agent_02 -name "Support agent 2" -type support -platform langgraph \
  -sponsor pranav.kumar@acme.com -team Support -copy-cap 2 >/dev/null
seed support_agent_01 postgres '{"upstreams":{"acme_staging":"read_only"}}'
seed support_agent_02 postgres '{"upstreams":{"acme_staging":"read_only"}}'

echo
echo "Dev environment ready."
echo "  config : configs/fortik.dev.yaml"
echo "  tokens : .dev/tokens.env   (source it for the demo scripts)"
echo "  start  : bin/fortik serve -config configs/fortik.dev.yaml"
echo "  console: http://127.0.0.1:8080  (dev login: security@acme.com, admin@acme.com, pranav.kumar@acme.com)"
