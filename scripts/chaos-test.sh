#!/usr/bin/env bash
# Phase 6 chaos tests (plan: "kill Redis, NATS or the gateway mid-demo; the
# hook and gateway must fail closed"). Runs Fortik with REAL Redis (counters,
# baselines) and REAL NATS (events), breaks each dependency while traffic is
# flowing, and checks what happens:
#
#   A. healthy baseline
#   B. Redis killed      -> decisions fail CLOSED (green reads on the
#                           fail-open allowlist only); Redis back -> recovered
#   C. NATS killed       -> decisions continue and are recorded (the Diary is
#                           the source of truth); NATS back -> the live event
#                           stream delivers what happened during the outage
#   D. Fortik killed     -> the Claude Code hook BLOCKS, the Postgres proxy and
#                           the app gateway refuse connections: nothing gets
#                           through without a decision
#   E. Fortik's database killed -> decisions fail closed and are kept in the
#                           local spool; database back -> appended to the Diary
#
# Needs: ./scripts/dev-up.sh done, the dev server STOPPED (this script starts
# its own), redis-server and nats-server on PATH (brew install redis nats-server).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/.dev/tokens.env"
API=http://127.0.0.1:8080
GW=http://127.0.0.1:8090
PGBIN="${PGBIN:-$(dirname "$(command -v pg_ctl 2>/dev/null || echo /Library/PostgreSQL/17/bin/pg_ctl)")}"
REDIS_BIN="${REDIS_BIN:-$(command -v redis-server || true)}"
NATS_BIN="${NATS_BIN:-$(command -v nats-server || true)}"
REDIS_PORT=56379
NATS_PORT=54222
TMP="$(mktemp -d)"
FORTIK_PID="" REDIS_PID="" NATS_PID=""
FAILED=0
bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
say()  { printf '  \033[2m%s\033[0m\n' "$*"; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILED=1; }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
J() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
fdb() { "$PGBIN/psql" -h 127.0.0.1 -p 55432 -U postgres -d fortik -X -A -t -q -c "$1"; }
decide() { curl -s -m 10 -X POST -H "Authorization: Bearer $FORTIK_TOKEN_INTERCEPTOR" -H 'Content-Type: application/json' -d "$1" "$API/v1/actions/decide"; }
pg_read='{"agent_id":"text2sql_agent_03","system":"postgres","verb":"READ","source":"api","target":{"upstream":"acme_prod","statement_type":"SELECT","environment":"prod","tables":["public.orders"]}}'
web_read='{"agent_id":"web_agent_c","system":"http","verb":"READ","source":"agentgateway","target":{"domain":"docs.python.org","external":true,"method":"GET"}}'

cleanup() {
  for p in "$FORTIK_PID" "$REDIS_PID" "$NATS_PID"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  "$PGBIN/pg_isready" -h 127.0.0.1 -p 55432 -q || "$PGBIN/pg_ctl" -D "$ROOT/.dev/pg" -l "$ROOT/.dev/pg.log" start -w >/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

[ -x "$REDIS_BIN" ] && [ -x "$NATS_BIN" ] || { echo "chaos-test: needs redis-server and nats-server on PATH (brew install redis nats-server)"; exit 2; }
if curl -s -m 2 -o /dev/null "$API/healthz"; then echo "chaos-test: a Fortik server is already running on :8080; stop it first (Ctrl+C in its terminal)"; exit 2; fi
"$PGBIN/pg_isready" -h 127.0.0.1 -p 55432 -q || { echo "chaos-test: the dev database is not running; run ./scripts/dev-up.sh"; exit 2; }

start_redis() { "$REDIS_BIN" --port $REDIS_PORT --bind 127.0.0.1 --save "" --appendonly no --dir "$TMP" >/dev/null 2>&1 & REDIS_PID=$!; sleep 0.5; }
start_nats()  { "$NATS_BIN" -a 127.0.0.1 -p $NATS_PORT -js -sd "$TMP/nats" >/dev/null 2>&1 & NATS_PID=$!; sleep 0.8; }
start_fortik() {
  "$ROOT/bin/fortik" serve -config "$TMP/fortik.chaos.yaml" >> "$TMP/serve.log" 2>&1 & FORTIK_PID=$!
  for _ in $(seq 1 60); do curl -s -m 1 -o /dev/null "$API/healthz" && return 0; sleep 0.25; done
  echo "fortik did not start:"; tail -20 "$TMP/serve.log"; exit 1
}

# The dev config, with real Redis and NATS, a fail-open allowlist for http
# reads, and a spool directory for fail-path records.
python3 - "$ROOT/configs/fortik.dev.yaml" "$TMP/fortik.chaos.yaml" "$TMP/spool" <<'PY'
import sys, re
src, dst, spool = sys.argv[1:]
s = open(src).read()
s = re.sub(r"(?m)^counters:\n  provider: memory.*$", "counters:\n  provider: redis\n  redis_url: redis://127.0.0.1:56379/0", s)
s = re.sub(r"(?m)^events:\n  provider: memory.*$", "events:\n  provider: nats\n  url: nats://127.0.0.1:54222", s)
s = s.replace("  green_read_allowlist: []", "  green_read_allowlist:\n    - {system: http, agent: \"*\"}")
s = re.sub(r"(?m)^  spool_dir: .*$", "  spool_dir: " + spool, s)
open(dst, "w").write(s)
PY
( cd "$ROOT" && go build -o bin/fortik ./cmd/fortik )
cd "$ROOT"
start_redis; start_nats; start_fortik
# Known starting state for the two agents the checks use (other demos leave
# delegation chains open on purpose, which would rightly refuse web_agent_c).
fdb "UPDATE delegations SET status = 'closed', closed_at = now(), close_reason = 'chaos-test reset' WHERE status = 'open' AND (to_agent IN ('web_agent_c', 'text2sql_agent_03') OR from_agent IN ('web_agent_c', 'text2sql_agent_03'))" >/dev/null
for a in web_agent_c text2sql_agent_03; do
  "$ROOT/bin/fortik" agent set-level -config "$ROOT/configs/fortik.dev.yaml" -id "$a" -level FULL -reason "chaos-test reset" -actor chaos-test >/dev/null 2>&1 || true
done

bold "A. Healthy: Redis, NATS, Fortik and its database up"
check "a database read is decided (allow)" '[[ "$(decide "$pg_read" | J "d[\"decision\"]")" == allow ]]'
check "a web read is decided (allow)" '[[ "$(decide "$web_read" | J "d[\"decision\"]")" == allow ]]'

bold "B. Redis killed mid-run"
kill "$REDIS_PID"; wait "$REDIS_PID" 2>/dev/null || true; REDIS_PID=""
R="$(decide "$pg_read")"; say "database read: $(echo "$R" | J 'd["decision"] + " " + d["rule_id"] + " " + d["reason"]')"
check "decisions fail CLOSED without Redis (FAIL-CLOSED)" '[[ "$(echo "$R" | J "d[\"decision\"] + d[\"rule_id\"]")" == denyFAIL-CLOSED ]]'
R="$(decide "$web_read")"
check "only a green read on the fail-open allowlist is allowed (FAIL-OPEN-ALLOWLIST), and it is recorded" \
  '[[ "$(echo "$R" | J "d[\"decision\"] + d[\"rule_id\"]")" == allowFAIL-OPEN-ALLOWLIST && "$(fdb "SELECT count(*) FROM actions WHERE action_id = '"'"'$(echo "$R" | J "d[\"action_id\"]")'"'"' AND fail_closed")" == 1 ]]'
start_redis
sleep 1
check "Redis back (empty): decisions recover, baselines reloaded first" '[[ "$(decide "$pg_read" | J "d[\"decision\"]")" == allow ]]'

bold "C. NATS killed mid-run"
HEAD="$(fdb "SELECT COALESCE(max(seq),0) FROM diary")"
kill "$NATS_PID"; wait "$NATS_PID" 2>/dev/null || true; NATS_PID=""
R="$(decide "$pg_read")"; AID="$(echo "$R" | J 'd["action_id"]')"
check "decisions continue without NATS (allow) and are in the Diary" \
  '[[ "$(echo "$R" | J "d[\"decision\"]")" == allow && "$(fdb "SELECT count(*) FROM diary WHERE seq > $HEAD AND body_json LIKE '"'"'%$AID%'"'"'")" -ge 1 ]]'
start_nats
sleep 3
curl -s -N -m 8 -H "Authorization: Bearer $FORTIK_TOKEN_AUDITOR" -H "Last-Event-ID: $HEAD" "$API/v1/events/stream" > "$TMP/sse" 2>/dev/null || true
check "NATS back: the live stream delivers the decision made during the outage" 'grep -q "$AID" "$TMP/sse"'

bold "D. Fortik killed (gateway, Postgres proxy and hook endpoint down)"
kill "$FORTIK_PID"; wait "$FORTIK_PID" 2>/dev/null || true; FORTIK_PID=""
set +e
echo '{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"psql -h prod-db -c \"DROP TABLE orders\""},"cwd":"/tmp"}' |
  FORTIK_GATEWAY_URL="$GW" FORTIK_AGENT_TOKEN="$FORTIK_AGENT_TOKEN_CLAUDE_CODE_01" "$ROOT/bin/fortik" hook claude-code > "$TMP/hook.out" 2> "$TMP/hook.err"
HOOK_EXIT=$?
PGPASSWORD="$FORTIK_AGENT_TOKEN_TEXT2SQL_AGENT_03" "$PGBIN/psql" -h 127.0.0.1 -p 6432 -U text2sql_agent_03 -d acme_prod -c 'SELECT 1' >/dev/null 2>&1
PSQL_EXIT=$?
GW_CODE="$(curl -s -m 3 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $FORTIK_AGENT_TOKEN_FINANCE_AGENT_07" "$GW/gw/gmail/gmail/v1/users/me/messages")"
set -e
check "the Claude Code hook BLOCKS the tool call (exit 2: fail closed)" '[[ $HOOK_EXIT == 2 ]] && grep -q "fail closed" "$TMP/hook.err"'
check "the Postgres proxy refuses the connection (no path to the database)" '[[ $PSQL_EXIT != 0 ]]'
check "the app gateway refuses the call (no path to Gmail)" '[[ "$GW_CODE" == 000 ]]'
start_fortik
check "Fortik back: decisions served again" '[[ "$(decide "$pg_read" | J "d[\"decision\"]")" == allow ]]'

bold "E. Fortik's own database killed"
"$PGBIN/pg_ctl" -D "$ROOT/.dev/pg" stop -m fast -w >/dev/null
R="$(decide "$pg_read")"; AID="$(echo "$R" | J 'd["action_id"]')"
say "database read: $(echo "$R" | J 'd["decision"] + " " + d["rule_id"]')"
check "decisions fail CLOSED without the database" '[[ "$(echo "$R" | J "d[\"decision\"] + d[\"rule_id\"]")" == denyFAIL-CLOSED ]]'
check "the fail-path record is kept in the local spool" '[[ -s "$TMP/spool/fail-spool.jsonl" ]] && grep -q "$AID" "$TMP/spool/fail-spool.jsonl"'
"$PGBIN/pg_ctl" -D "$ROOT/.dev/pg" -l "$ROOT/.dev/pg.log" start -w >/dev/null
for _ in $(seq 1 30); do
  [ "$(fdb "SELECT count(*) FROM diary WHERE event_type = 'action.decided' AND body_json LIKE '%$AID%' AND body_json LIKE '%recovered_from_spool%'")" -ge 1 ] && break
  sleep 1
done
check "database back: the spooled decision is appended to the Diary (recovered_from_spool)" \
  '[[ "$(fdb "SELECT count(*) FROM diary WHERE event_type = '"'"'action.decided'"'"' AND body_json LIKE '"'"'%$AID%'"'"' AND body_json LIKE '"'"'%recovered_from_spool%'"'"'")" -ge 1 ]]'
check "the Diary chain still verifies" '"$ROOT/bin/fortik" diary verify -config "$ROOT/configs/fortik.dev.yaml" >/dev/null 2>&1'

echo
if [ "$FAILED" = 0 ]; then printf '\033[32mChaos tests: all checks passed\033[0m\n'; else printf '\033[31mChaos tests: FAILURES above\033[0m\n'; exit 1; fi
