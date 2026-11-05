#!/usr/bin/env bash
# Checks a running Compose deployment (after ./init.sh and docker compose up -d):
# TLS everywhere, client certificates where required, observe mode, the Diary.
set -euo pipefail
cd "$(dirname "$0")"
set -a; source .env; source tokens.env; set +a
H="${FORTIK_PUBLIC_HOST:-localhost}"
API="https://$H:8443"; GW="https://$H:8090"
FAILED=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILED=1; }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
J() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
api() { curl -s --cacert tls/ca.crt -H "Authorization: Bearer $2" -H 'Content-Type: application/json' -X "$1" ${4:+-d "$4"} "$API$3"; }

echo "Fortik Compose smoke test against $H"
check "the API serves TLS with the deployment's CA" '[[ "$(curl -s --cacert tls/ca.crt "$API/healthz" | J "d[\"status\"]")" == ok ]]'
check "plain HTTP is not served on the API port" '! curl -s -m 3 "http://$H:8443/healthz" | grep -q ok'
check "the security token authenticates" '[[ "$(api GET "$FORTIK_TOKEN_SECURITY" /v1/me | J "\"security\" in d[\"roles\"]")" == True ]]'
check "deployment runs in observe mode" '[[ "$(api GET "$FORTIK_TOKEN_AUDITOR" /v1/enforcement | J "d[\"mode\"]")" == observe ]]'

api POST "$FORTIK_TOKEN_SECURITY" /v1/agents '{"agent_id":"smoke_agent","name":"Smoke test agent","type":"test","sponsor":"owner@example.com","business_unit":"QA"}' >/dev/null
R="$(api POST "$FORTIK_TOKEN_INTERCEPTOR" /v1/actions/decide '{"agent_id":"smoke_agent","system":"postgres","verb":"DELETE","source":"api","target":{"statement_type":"DROP_TABLE","environment":"prod","tables":["public.orders"],"upstream":"prod"}}')"
check "observe mode: a prod DROP TABLE is recorded red with what would have happened, and not enforced" \
  '[[ "$(echo "$R" | J "d[\"decision\"] + \"/\" + d[\"class\"] + \"/\" + d[\"reason\"][:19]")" == "allow/red/observe mode: would" ]]'
R="$(api POST "$FORTIK_TOKEN_INTERCEPTOR" /v1/actions/decide '{"agent_id":"smoke_agent","system":"postgres","verb":"TELEPORT","source":"api","target":{}}')"
check "observe mode still refuses an unknown action (fail closed)" '[[ "$(echo "$R" | J "d.get(\"decision\",\"error\")")" != allow ]]'

check "the gateway refuses a caller without a client certificate (mutual TLS)" '! curl -s -m 5 --cacert tls/ca.crt "$GW/healthz" >/dev/null 2>&1'
check "the gateway accepts the hook client certificate" \
  '[[ "$(curl -s -m 5 --cacert tls/ca.crt --cert tls/client-hook.crt --key tls/client-hook.key "$GW/healthz" | J "d[\"status\"]")" == ok ]]'
if command -v psql >/dev/null; then
  check "the Postgres proxy refuses a plaintext client" \
    '! PGPASSWORD=x psql "host=$H port=6432 user=smoke_agent dbname=prod sslmode=disable connect_timeout=5" -c "SELECT 1" 2>/dev/null'
  check "the Postgres proxy refuses a TLS client without a certificate" \
    '! PGPASSWORD=x psql "host=$H port=6432 user=smoke_agent dbname=prod sslmode=verify-full sslrootcert=tls/ca.crt connect_timeout=5" -c "SELECT 1" 2>/dev/null'
fi
check "the Diary chain verifies" '[[ "$(api GET "$FORTIK_TOKEN_AUDITOR" /v1/diary/verify | J "d[\"ok\"]")" == True ]]'
check "Postgres, Redis and NATS publish no ports (internal network only)" \
  '[[ -z "$(docker compose port postgres 5432 2>/dev/null)$(docker compose port redis 6379 2>/dev/null)$(docker compose port nats 4222 2>/dev/null)" ]]'
echo
if [ "$FAILED" = 0 ]; then printf '\033[32mCompose smoke test: all checks passed\033[0m\n'; else printf '\033[31mCompose smoke test: FAILURES\033[0m\n'; exit 1; fi
