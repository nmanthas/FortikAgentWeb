#!/usr/bin/env bash
# Phase 6 demo (pilot-ready), against the dev server
# (bin/fortik serve -config configs/fortik.dev.yaml):
#   A. observe mode: a real DROP TABLE through the Postgres proxy is recorded
#      as "would hold" and NOT enforced; back in enforce mode the same kind of
#      statement is held and the agent steps down
#   B. observe mode never lets an unknown action through
#   C. pilot success metrics (the plan's five targets)
#   D. the replay gate: 10,000 recorded inputs unchanged; a policy change that
#      flips classes is caught
#   E. SaaS copilot connector broker, end to end with a LOCAL FAKE of Google
#      OAuth: consent, code exchange, refresh, then a kill revokes the
#      upstream grant and the next refresh is refused
#   F. map telemetry is no longer written to the Diary
# Chaos, load and Compose have their own scripts (printed at the end).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/.dev/tokens.env"
API="${FORTIK_API:-http://127.0.0.1:8080}"
GW="${FORTIK_GATEWAY:-http://127.0.0.1:8090}"
PGBIN="${PGBIN:-$(dirname "$(command -v psql 2>/dev/null || echo /Library/PostgreSQL/17/bin/psql)")}"
CFG=(-config "$ROOT/configs/fortik.dev.yaml")
TMP="$(mktemp -d)"
FAKE_PID=""
cleanup() { [ -n "$FAKE_PID" ] && kill "$FAKE_PID" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT
FAILED=0
bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
say()  { printf '  \033[2m%s\033[0m\n' "$*"; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILED=1; }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
J() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
F() { "$ROOT/bin/fortik" "$@" "${CFG[@]}"; }
fdb() { "$PGBIN/psql" -h 127.0.0.1 -p 55432 -U postgres -d fortik -X -A -t -q -c "$1"; }
api() { curl -s -X "$1" -H "Authorization: Bearer $2" -H 'Content-Type: application/json' ${4:+-d "$4"} "$API$3"; }
level_of() { fdb "SELECT (ARRAY['FULL','SUPERVISED','READ_ONLY','ISOLATED','QUARANTINED','KILLED'])[level+1] FROM agents WHERE agent_id='$1'"; }
AGENT_PW="$(cat "$ROOT/.dev/secrets/acme_agent_password")"
owner_sql() { PGPASSWORD="$AGENT_PW" "$PGBIN/psql" -h 127.0.0.1 -p 55432 -U acme_agent -d acme_prod -X -A -t -q -c "$1"; }
proxy_sql() { PGPASSWORD="$FORTIK_AGENT_TOKEN_CLAUDE_CODE_01" "$PGBIN/psql" -h 127.0.0.1 -p "${FORTIK_PROXY_PORT:-6432}" -U claude_code_01 -d acme_prod -X -A -t -q -c "$1" 2>&1; }
RUN="$(date +%s)"
curl -s -m 2 -o /dev/null "$API/healthz" || { echo "start the server first: bin/fortik serve -config configs/fortik.dev.yaml"; exit 2; }

bold "0. reset: claude_code_01 at FULL, enforce mode"
F agent set-level -id claude_code_01 -level FULL -reason "phase 6 demo reset" >/dev/null
api PUT "$FORTIK_TOKEN_SECURITY" /v1/agents/claude_code_01/enforcement '{"mode":"default","reason":"phase 6 demo reset"}' >/dev/null
check "deployment is in enforce mode (dev config)" '[[ "$(api GET "$FORTIK_TOKEN_AUDITOR" /v1/enforcement | J "d[\"mode\"]")" == enforce ]]'

bold "A. Observe mode: decide and record, do not enforce"
T1="fortik_observe_demo_${RUN}_a"; T2="fortik_observe_demo_${RUN}_b"
owner_sql "CREATE TABLE $T1 (id int); CREATE TABLE $T2 (id int)"
R="$(api PUT "$FORTIK_TOKEN_SECURITY" /v1/agents/claude_code_01/enforcement '{"mode":"observe","reason":"pilot week 1: observe claude_code_01"}')"
check "security puts claude_code_01 in observe mode (recorded in the Diary)" \
  '[[ "$(echo "$R" | J "d[\"effective_enforcement\"]")" == observe && "$(fdb "SELECT count(*) FROM diary WHERE event_type = '"'"'enforcement.changed'"'"' AND agent_id = '"'"'claude_code_01'"'"' AND body_json LIKE '"'"'%pilot week 1%'"'"'")" -ge 1 ]]'
OUT="$(proxy_sql "DROP TABLE $T1")"
say "proxy: ${OUT:-DROP TABLE}"
AID="$(fdb "SELECT action_id FROM actions WHERE agent_id = 'claude_code_01' AND target->>'statement_type' = 'DROP_TABLE' ORDER BY ts DESC LIMIT 1")"
check "the DROP TABLE ran (observe mode does not enforce)" '[[ "$(owner_sql "SELECT to_regclass('"'"'public.$T1'"'"') IS NULL")" == t ]]'
check "it is recorded red, decision allow, with the would-be decision: hold + step-down" \
  '[[ "$(fdb "SELECT class || '"'"'/'"'"' || decision || '"'"'/'"'"' || observed || '"'"'/'"'"' || (decision_json->'"'"'observed'"'"'->>'"'"'decision'"'"') || '"'"'/'"'"' || (decision_json->'"'"'observed'"'"'->'"'"'ladder_change'"'"'->>'"'"'to'"'"') FROM actions WHERE action_id = '"'"'$AID'"'"'")" == "red/allow/true/hold/READ_ONLY" ]]'
check "and the agent was NOT stepped down (still FULL)" '[[ "$(level_of claude_code_01)" == FULL ]]'
api PUT "$FORTIK_TOKEN_SECURITY" /v1/agents/claude_code_01/enforcement '{"mode":"default","reason":"pilot week 2: enforce claude_code_01"}' >/dev/null
OUT="$(proxy_sql "DROP TABLE $T2" || true)"
say "proxy: $(echo "$OUT" | head -1)"
check "back in enforce mode the same statement is held red (POL-101) and nothing is dropped" \
  '[[ "$OUT" == *"hold (red) by POL-101"* && "$(owner_sql "SELECT to_regclass('"'"'public.$T2'"'"') IS NOT NULL")" == t ]]'
check "and the agent steps down to READ_ONLY" '[[ "$(level_of claude_code_01)" == READ_ONLY ]]'
F agent set-level -id claude_code_01 -level FULL -reason "phase 6 demo: restore" >/dev/null
owner_sql "DROP TABLE IF EXISTS $T2" >/dev/null

bold "B. Observe mode never lets an unknown action through"
api PUT "$FORTIK_TOKEN_SECURITY" /v1/agents/claude_code_01/enforcement '{"mode":"observe","reason":"demo B"}' >/dev/null
R="$(api POST "$FORTIK_TOKEN_INTERCEPTOR" /v1/actions/decide '{"agent_id":"claude_code_01","system":"postgres","verb":"TELEPORT","source":"api","target":{}}')"
check "an unknown verb is refused even in observe mode" '[[ "$(echo "$R" | J "d.get(\"decision\", \"refused\")")" != allow ]]'
api PUT "$FORTIK_TOKEN_SECURITY" /v1/agents/claude_code_01/enforcement '{"mode":"default","reason":"demo B done"}' >/dev/null

bold "C. Pilot success metrics (GET /v1/metrics/pilot, last 30 days)"
api GET "$FORTIK_TOKEN_AUDITOR" /v1/metrics/pilot > "$TMP/m"
python3 - "$TMP/m" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for k, label in [("risky_handled_without_kill", "Risky actions handled without a kill"), ("red_false_alarm_rate", "False alarms on red"),
                 ("red_to_step_down_p50", "Red action to step-down (p50)"), ("undo_success", "Undo success"), ("green_overhead_p95", "Green overhead (p95)")]:
    m = d[k]
    v = "no data" if m["value"] is None else (f'{m["value"]:.1f}{m["unit"]}' if m["unit"] == "%" else f'{m["value"]:.1f} {m["unit"]}')
    met = {True: "met", False: "NOT met", None: "-"}[m["met"]]
    print(f"    {label:<40} {v:>12}   target {m['target']:<10} {met:<8} (n={m['n']})")
PY
say "dev data includes the demos' deliberate kills and level resets, so some targets read 'not met' here"
check "all five metrics are reported" '[[ "$(J "len([k for k in [\"risky_handled_without_kill\",\"red_false_alarm_rate\",\"red_to_step_down_p50\",\"undo_success\",\"green_overhead_p95\"] if k in d])" < "$TMP/m")" == 5 ]]'
check "green overhead p95 is under the 50 ms target" '[[ "$(J "d[\"green_overhead_p95\"][\"met\"]" < "$TMP/m")" == True ]]'

bold "D. The replay gate: 10,000 recorded inputs must keep their results"
OUT="$("$ROOT/bin/fortik" replay run -corpus "$ROOT/testdata/replay/corpus.jsonl.gz" -policy "$ROOT/policies" 2>&1 | head -1)"
say "$OUT"
check "the policy in the tree passes the gate (0 breaking changes)" '[[ "$OUT" == *"10000 records"*"0 breaking"* ]]'
cp -R "$ROOT/policies" "$TMP/policies"
python3 - "$TMP/policies/fortik/data.json" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p))
d["config"]["sensitive_labels"] = [l for l in d["config"]["sensitive_labels"] if l != "customer_pii"]   # a careless policy edit
json.dump(d, open(p, "w"), indent=2)
PY
set +e
"$ROOT/bin/fortik" replay run -corpus "$ROOT/testdata/replay/corpus.jsonl.gz" -policy "$TMP/policies" > "$TMP/replay" 2>&1
GATE=$?
set -e
say "$(head -1 "$TMP/replay")"
check "a careless policy edit (customer_pii no longer sensitive) is caught: class changes block the merge" \
  '[[ $GATE != 0 ]] && grep -q "CLASS" "$TMP/replay"'

bold "E. SaaS copilot connector broker (with a LOCAL FAKE of Google OAuth)"
CID_UP="fortik-dev-upstream.apps.googleusercontent.com"
python3 "$ROOT/scripts/fakes/fake_google_oauth.py" 18100 "$CID_UP" local-fake-upstream-secret & FAKE_PID=$!; disown "$FAKE_PID"
sleep 0.7
COP="copilot_demo_$RUN"
api POST "$FORTIK_TOKEN_SECURITY" /v1/connectors "{\"agent_id\":\"$COP\",\"name\":\"ChatGPT workspace connector\",\"sponsor\":\"it@acme.com\",\"team\":\"IT\",\"vendor\":\"chatgpt\",\"upstream\":\"google_workspace\",\"redirect_uris\":[\"http://127.0.0.1:18101/cb\"],\"scopes\":[\"https://www.googleapis.com/auth/gmail.readonly\"],\"reason\":\"phase 6 demo\"}" > "$TMP/reg"
CLIENT="$(J 'd["connector"]["client_id"]' < "$TMP/reg")"; SECRET="$(J 'd["client_secret"]' < "$TMP/reg")"
check "security registers the copilot: a Fortik client id and a secret shown once (only its hash is stored)" \
  '[[ "$SECRET" == fcs_* && "$(fdb "SELECT count(*) FROM connectors WHERE client_id = '"'"'$CLIENT'"'"' AND client_secret_sha256 <> '"'"'$SECRET'"'"'")" == 1 ]]'
UP="$(curl -s -o /dev/null -w '%{redirect_url}' "$GW/oauth/authorize?client_id=$CLIENT&redirect_uri=http://127.0.0.1:18101/cb&response_type=code&state=s1&scope=https://www.googleapis.com/auth/gmail.readonly%20https://www.googleapis.com/auth/gmail.send")"
check "authorize sends the user to Google with FORTIK's client and only the allowed scope" \
  '[[ "$UP" == http://127.0.0.1:18100/auth* && "$UP" == *"client_id=$CID_UP"* && "$UP" != *gmail.send* ]]'
CB="$(curl -s -o /dev/null -w '%{redirect_url}' "$UP")"
BACK="$(curl -s -o /dev/null -w '%{redirect_url}' "$CB")"
CODE="$(python3 -c "import sys,urllib.parse as u; print(dict(u.parse_qsl(u.urlparse(sys.argv[1]).query)).get('code',''))" "$BACK")"
check "after consent the copilot gets a one-time Fortik code (the upstream grant stays with Fortik)" '[[ -n "$CODE" && "$BACK" == http://127.0.0.1:18101/cb* ]]'
curl -s -u "$CLIENT:$SECRET" -d grant_type=authorization_code -d "code=$CODE" -d redirect_uri=http://127.0.0.1:18101/cb "$GW/oauth/token" > "$TMP/tok"
RT="$(J 'd.get("refresh_token","")' < "$TMP/tok")"
check "the token endpoint (a Fortik decision) hands the copilot a short-lived Google access token" \
  '[[ "$(J "d.get(\"access_token\",\"\")" < "$TMP/tok")" == ya29.fake-* && "$RT" == frt_* ]]'
curl -s -u "$CLIENT:$SECRET" -d grant_type=refresh_token -d "refresh_token=$RT" "$GW/oauth/token" > "$TMP/tok2"
RT2="$(J 'd.get("refresh_token","")' < "$TMP/tok2")"
check "a refresh is decided again and rotates the Fortik refresh token" '[[ -n "$RT2" && "$RT2" != "$RT" ]]'
check "both token issues are recorded decisions (system connector)" '[[ "$(fdb "SELECT count(*) FROM actions WHERE agent_id = '"'"'$COP'"'"' AND system = '"'"'connector'"'"' AND decision = '"'"'allow'"'"'")" == 2 ]]'
api PUT "$FORTIK_TOKEN_SECURITY" "/v1/agents/$COP/level" '{"level":"KILLED","reason":"copilot reading mail it should not"}' > "$TMP/kill"
check "killing the copilot revokes its Google grant upstream at once" '[[ "$(curl -s http://127.0.0.1:18100/state | J "d[\"live_grants\"]")" == 0 ]]'
curl -s -u "$CLIENT:$SECRET" -d grant_type=refresh_token -d "refresh_token=$RT2" "$GW/oauth/token" > "$TMP/tok3"
check "the next refresh is refused: access stops when Fortik stops issuing" '[[ "$(J "d.get(\"error\",\"\")" < "$TMP/tok3")" == invalid_grant ]]'

bold "F. Map telemetry is no longer written to the Diary"
BEFORE="$(fdb "SELECT count(*) FROM diary WHERE event_type = 'map.edges_updated'")"
ME="$(fdb "SELECT COALESCE(max(id),0) FROM map_events")"
api POST "$FORTIK_TOKEN_INTERCEPTOR" /v1/actions/decide '{"agent_id":"web_agent_c","system":"http","verb":"READ","source":"agentgateway","target":{"domain":"docs.python.org","external":true,"method":"GET"}}' >/dev/null
say "waiting for the map rollup (settle 15s + rollup 10s)..."
for _ in $(seq 1 40); do [ "$(fdb "SELECT COALESCE(max(id),0) FROM map_events")" -gt "$ME" ] && break; sleep 1; done
check "a rollup batch went to map_events (pruned with the map), not to the hash-chained Diary" \
  '[[ "$(fdb "SELECT COALESCE(max(id),0) FROM map_events")" -gt "$ME" && "$(fdb "SELECT count(*) FROM diary WHERE event_type = '"'"'map.edges_updated'"'"'")" == "$BEFORE" ]]'
check "the Diary chain verifies" '[[ "$(api GET "$FORTIK_TOKEN_AUDITOR" /v1/diary/verify | J "d[\"ok\"]")" == True ]]'

bold "Also part of Phase 6 (separate scripts)"
say "scripts/chaos-test.sh       kill Redis, NATS, Fortik, its database mid-run (stop the dev server first)"
say "scripts/loadtest.sh         k6: 200 decisions/s for 2 minutes, p95 < 50 ms"
say "deploy/compose/init.sh, docker compose up -d, deploy/compose/smoke-test.sh   the pilot deployment with mTLS"
echo
if [ "$FAILED" = 0 ]; then printf '\033[32mPhase 6 demo: all checks passed\033[0m\n'; else printf '\033[31mPhase 6 demo: FAILURES above\033[0m\n'; exit 1; fi
