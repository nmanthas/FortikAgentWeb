#!/usr/bin/env bash
# QuickStart Milestones 1-4 demo: Fortik's connection to the NetSuite
# QuickStart MCP server and agents' tool calls through Fortik, against a
# running Fortik server and a LOCAL FAKE MCP server
# (scripts/fakes/fakequickstart). The fake is not NetSuite. The server's config
# must set mcp_upstreams.allow_loopback: true (development only).
#
# It REPLACES the netsuite_quickstart integration and deletes it at the end,
# so it refuses to run while that integration points at a real endpoint (use
# a separate database and secret store; for the real tenant use
# scripts/verify-quickstart-live.sh instead).
#
# FORTIK_QS_REAL_PROBE=1 adds one step against the REAL QuickStart endpoint
# with a deliberately invalid token (no account needed): it proves the path to
# Oracle's server and the failure state, nothing more.
#
#   1. not configured: no "Connected" without a live check
#   2. save: token write-only; saved, not tested; the server is not contacted
#   3. Test connection: initialize, notifications/initialized, tools/list; no tool call
#   4. tools, inferred scope, Diary; the token never in Postgres, the Diary or API replies
#   5. rotate to a read-write token: saved-not-tested until checked; refresh; Diary diff
#   6. failure states: expired token, wrong token, unavailable server
#   7. SSRF guard: another host is refused without being contacted
#   8. coverage: what is enforced and verified, per dimension
#   9. agents through Fortik: tools/list per profile; reads forwarded; writes held,
#      approved, retried once with an undo snapshot, undone; deletes red; suspension
#  10. disconnect: token and learned state removed; agents refused; revoke-in-QuickStart instruction
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/.dev/tokens.env"
API="${FORTIK_API:-http://127.0.0.1:8080}"
FPORT="${FORTIK_FAKE_QS_PORT:-18410}"
PGBIN="${PGBIN:-$(dirname "$(command -v psql 2>/dev/null || echo /Library/PostgreSQL/17/bin/psql)")}"
TMP="$(mktemp -d)"; FAKE_PID=""
cleanup() { [ -n "$FAKE_PID" ] && kill "$FAKE_PID" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT
FAILED=0
bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
say()  { printf '  \033[2m%s\033[0m\n' "$*"; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILED=1; }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
J() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
fdb() { "$PGBIN/psql" -h 127.0.0.1 -p 55432 -U postgres -d "${FORTIK_DB:-fortik}" -X -A -t -q -c "$1"; }
api() { curl -s -o "$TMP/b" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $3" -H 'Content-Type: application/json' ${4:+-d "$4"} "$API$2" > "$TMP/c"; cat "$TMP/b"; }
code() { cat "$TMP/c"; }
st() { api GET /v1/saas/netsuite_quickstart "$FORTIK_TOKEN_AUDITOR" > "$TMP/st"; }
sv() { J "$1" < "$TMP/st"; }
fake() { curl -s "http://127.0.0.1:$FPORT$1" ${2:+-H 'Content-Type: application/json' -d "$2"}; }
put() { # put <endpoint> [token]
  local body
  body="$(python3 - "$1" "${2:-}" <<'PY'
import json, sys
b = {"config": {"tenant_label": "Acme QuickStart (LOCAL FAKE)", "endpoint_url": sys.argv[1], "token_expires_on": "2026-11-24"}}
if sys.argv[2]:
    b["secrets"] = {"personal_access_token": sys.argv[2]}
print(json.dumps(b))
PY
)"
  api PUT /v1/integrations/netsuite_quickstart "$FORTIK_TOKEN_SECURITY" "$body" >/dev/null
}
# leaked <file...>: the token values appear in none of the files
leaked() { grep -qF -e "$RO" -e "$RW" "$@" 2>/dev/null; }
dbtext() { fdb "SELECT COALESCE((SELECT string_agg(i::text, E'\n') FROM integrations i),'') || COALESCE((SELECT string_agg(m::text, E'\n') FROM mcp_connections m),'') || COALESCE((SELECT string_agg(body_json, E'\n') FROM diary WHERE event_type LIKE 'integration.%' OR event_type LIKE 'mcp.%'),'')"; }
curl -s -m 2 -o /dev/null "$API/healthz" || { echo "start the server first"; exit 2; }
CUR="$(api GET /v1/integrations/netsuite_quickstart "$FORTIK_TOKEN_AUDITOR" | J 'd.get("config",{}).get("endpoint_url","")' 2>/dev/null || true)"
if [[ -n "$CUR" && "$CUR" != http://127.0.0.1:* && "$CUR" != http://localhost:* ]]; then
  echo "refusing to run: netsuite_quickstart is configured for $CUR (a real endpoint); this demo would delete it."
  echo "Run it against a server with its own database and secret store, or use scripts/verify-quickstart-live.sh."
  exit 2
fi
GW="${FORTIK_GATEWAY:-http://127.0.0.1:8090}"
api DELETE /v1/integrations/netsuite_quickstart "$FORTIK_TOKEN_SECURITY" >/dev/null || true # leftovers of an earlier run
SEQ0="$(fdb "SELECT COALESCE(max(seq),0) FROM diary")"

(cd "$ROOT" && go build -o "$TMP/fakeqs" ./scripts/fakes/fakequickstart)
"$TMP/fakeqs" -port "$FPORT" -token-out "$TMP/tokens" > "$TMP/fake.log" 2>&1 & FAKE_PID=$!; disown "$FAKE_PID"
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$FPORT" 2>/dev/null && [ -s "$TMP/tokens" ] && break; sleep 0.2; done
RO="$(sed -n 1p "$TMP/tokens")"; RW="$(sed -n 2p "$TMP/tokens")"
EP="http://127.0.0.1:$FPORT/mcp"
say "$(head -1 "$TMP/fake.log")"

bold "1. Not configured"
st
check "state not_configured (\"$(sv 'd["state_label"]')\")" '[[ "$(sv "d[\"state\"]")" == not_configured ]]'

bold "2. Save the connection (read-only token)"
put "$EP" "$RO"
check "saved ($(code)); the reply shows the token only as set=true" '[[ "$(code)" == 200 && "$(J "d[\"secrets\"][\"personal_access_token\"][\"set\"]" < "$TMP/b")" == True ]] && ! leaked "$TMP/b"'
st
check "state saved_not_tested (\"$(sv "d[\"state_label\"]")\"): saving is not connecting" '[[ "$(sv "d[\"state\"]")" == saved_not_tested ]]'
check "the MCP server was not contacted by saving" '[[ "$(fake /fake/calls | J "sum(d[\"calls\"].values())")" == 0 ]]'

bold "3. Test connection: the real MCP handshake against the (fake) server"
api POST /v1/integrations/netsuite_quickstart/test "$FORTIK_TOKEN_SECURITY" > "$TMP/test"
check "Test connection ok ($(J 'str(d["ok"]) + " " + str(d.get("duration_ms")) + " ms"' < "$TMP/test"))" '[[ "$(J "d[\"ok\"]" < "$TMP/test")" == True ]]'
fake /fake/calls > "$TMP/calls"
say "fake received: $(J 'd["calls"]' < "$TMP/calls"), authorization: $(J 'd["authorization"]' < "$TMP/calls")"
HS="$(J '"%s %s %s %s" % (d["calls"].get("initialize"), d["calls"].get("notifications/initialized"), d["calls"].get("tools/list",0) >= 2, d["calls"].get("tools/call",0))' < "$TMP/calls")"
AUTHK="$(J '",".join(sorted(d["authorization"]))' < "$TMP/calls")"
check "initialize, notifications/initialized and paged tools/list were sent; no tools/call" '[[ "$HS" == "1 1 True 0" ]]'
check "every upstream request carried Fortik's stored token (Authorization: Bearer)" '[[ "$AUTHK" == read_only_token ]]'

bold "4. Discovered tools, inferred scope, Diary, no token anywhere"
st
say "state: $(sv 'd["state_label"]') · server: $(sv 'd["server"]["name"]') $(sv 'd["server"]["version"]') · MCP $(sv 'd["server"]["protocol_version"]')"
say "tools ($(sv 'd["tool_count"]')): $(sv '", ".join(t["name"] for t in d["tools"])')"
check "Connected, with the 16 tools the server returned" '[[ "$(sv "d[\"state\"]")" == connected && "$(sv "d[\"tool_count\"]")" == 16 && "$(sv "d[\"tools_from_current_settings\"]")" == True ]]'
check "token scope inferred read_only, with its basis stated" '[[ "$(sv "d[\"permission_mode\"]")" == read_only ]] && sv "d[\"permission_basis\"]" | grep -q "inferred"'
check "token expiry tracked from the date entered ($(sv 'd["token"]["days_left"]') days left)" '[[ "$(sv "d[\"token\"][\"expires_on\"]")" == 2026-11-24 ]]'
FD="$(fdb "SELECT string_agg((body_json::json->'data'->>'first_discovery') || '/' || (body_json::json->'data'->>'system') || '/' || (body_json::json->'data'->>'transport'), ',') FROM diary WHERE seq > $SEQ0 AND event_type = 'mcp.tools.changed'")"
check "Diary: mcp.tools.changed (first discovery / system / transport: $FD)" '[[ "$FD" == "true/netsuite/mcp" ]]'
dbtext > "$TMP/db"; api GET /v1/integrations "$FORTIK_TOKEN_AUDITOR" > "$TMP/list"
check "the token is in neither Postgres (integrations, mcp_connections, Diary) nor any API reply" '! leaked "$TMP/db" "$TMP/st" "$TMP/list" "$TMP/test"'
if [ -n "${FORTIK_SERVER_LOG:-}" ]; then
  check "the token is not in the server log" '! leaked "$FORTIK_SERVER_LOG"'
fi

bold "5. Rotate to a read-write token"
fake /fake/control '{"token":"rw"}'
put "$EP" "$RW"; st
check "after rotation: saved_not_tested until checked (last check was $(sv 'd.get("last_checked_state")')); old tools marked as not current" '[[ "$(sv "d[\"state\"]")" == saved_not_tested && "$(sv "d[\"tools_from_current_settings\"]")" == False ]]'
api POST /v1/saas/netsuite_quickstart/refresh "$FORTIK_TOKEN_SECURITY" > "$TMP/r"
R="$(J '"%s %s %s" % (d["ok"], d["status"]["tool_count"], d["status"]["permission_mode"])' < "$TMP/r")"
check "Refresh tools: connected, 27 tools, scope read_write ($R)" '[[ "$R" == "True 27 read_write" ]]'
check "Diary records the 11 added write tools" '[[ "$(fdb "SELECT body_json::json->'"'data'"'->'"'added'"' FROM diary WHERE seq > '"$SEQ0"' AND event_type='"'mcp.tools.changed'"' ORDER BY seq DESC LIMIT 1" | J "len(d)")" == 11 ]]'
check "an auditor cannot run a check (403)" '[[ "$(api POST /v1/saas/netsuite_quickstart/refresh "$FORTIK_TOKEN_AUDITOR" >/dev/null; code)" == 403 ]]'

bold "6. Failure states are told apart"
fake /fake/control '{"token":"rw","expired_token":true}'
api POST /v1/saas/netsuite_quickstart/refresh "$FORTIK_TOKEN_SECURITY" > "$TMP/r"
check "expired token -> \"$(J 'd["status"]["state_label"]' < "$TMP/r")\"" '[[ "$(J "d[\"status\"][\"state\"]" < "$TMP/r")" == token_expired ]]'
R="$(J '"%s %s" % (d["status"]["tool_count"], d["status"]["tools_from_current_settings"])' < "$TMP/r")"
check "a failed check keeps the last known tools, marked as not current ($R)" '[[ "$R" == "27 False" ]]'
fake /fake/control '{"token":"ro"}'
api POST /v1/saas/netsuite_quickstart/refresh "$FORTIK_TOKEN_SECURITY" > "$TMP/r"
check "token not accepted -> \"$(J 'd["status"]["state_label"]' < "$TMP/r")\": $(J 'd["status"]["detail"][:70]' < "$TMP/r")" '[[ "$(J "d[\"status\"][\"state\"]" < "$TMP/r")" == auth_failed ]]'
fake /fake/control '{"token":"rw","init_status":503}'
api POST /v1/saas/netsuite_quickstart/refresh "$FORTIK_TOKEN_SECURITY" > "$TMP/r"
check "server answers 503 -> \"$(J 'd["status"]["state_label"]' < "$TMP/r")\"" '[[ "$(J "d[\"status\"][\"state\"]" < "$TMP/r")" == unavailable ]]'
api GET /v1/integrations/netsuite_quickstart "$FORTIK_TOKEN_AUDITOR" > "$TMP/i"
check "the integration card shows status error with the state as last error" '[[ "$(J "d[\"status\"]" < "$TMP/i")" == error ]] && J "d[\"last_error\"]" < "$TMP/i" | grep -q "^Temporarily unavailable"'
fake /fake/control '{"token":"rw"}'
leaked "$TMP/r" "$TMP/i" && fail "token in a failure reply" || pass "no failure reply contains the token"

bold "7. SSRF guard: only allowed hosts"
BEFORE="$(fake /fake/calls | J 'sum(d["calls"].values())')"
put "https://attacker.example.com/mcp"
api POST /v1/integrations/netsuite_quickstart/test "$FORTIK_TOKEN_SECURITY" > "$TMP/r"; st
check "another host is refused before any connection: \"$(sv 'd["detail"][:80]')\"" '[[ "$(sv "d[\"state\"]")" == endpoint_not_permitted && "$(sv "d[\"endpoint_permitted\"]")" == False ]]'
check "and nothing was sent (the token went nowhere)" '[[ "$(fake /fake/calls | J "sum(d[\"calls\"].values())")" == "$BEFORE" ]]'

if [ -n "${FORTIK_QS_REAL_PROBE:-}" ]; then
  bold "7b. REAL QuickStart endpoint, deliberately invalid token (no account)"
  put "https://my.quickstartapi.netsuite.com/mcp" "fortik-invalid-probe-token-$(date +%s)"
  api POST /v1/saas/netsuite_quickstart/refresh "$FORTIK_TOKEN_SECURITY" > "$TMP/r"
  say "real server: $(J 'd["status"]["state_label"] + " — " + d["status"]["detail"]' < "$TMP/r")"
  R="$(J '"%s %s %s" % (d["ok"], d["status"]["state"], d["status"].get("http_status"))' < "$TMP/r")"
  check "Oracle's server is reached over TLS and rejects the token: auth_failed, not connected ($R)" '[[ "$R" == "False auth_failed 401" ]]'
fi

bold "8. Coverage: per dimension, with evidence"
api GET /v1/coverage "$FORTIK_TOKEN_AUDITOR" > "$TMP/cov"
R="$(J '",".join(c["dimension"] + "=" + c["status"] for r in d["integrations"] if r["system"]=="netsuite_quickstart" for c in r["capabilities"])' < "$TMP/cov")"
say "$R"
check "coverage lists pre-execution enforcement and suspension as verified, discovery as unsupported" '[[ "$R" == *pre_execution_enforcement=verified_live* && "$R" == *suspension=verified_live* && "$R" == *discovery=unsupported* ]]'

bold "9. Agents call QuickStart through Fortik (LOCAL FAKE tenant)"
fake /fake/control '{"token":"rw"}'
put "$EP" "$RW"
api POST /v1/saas/netsuite_quickstart/refresh "$FORTIK_TOKEN_SECURITY" > "$TMP/r"
check "connected again with a read-write token ($(J 'd["status"]["tool_count"]' < "$TMP/r") tools)" '[[ "$(J "d[\"ok\"]" < "$TMP/r")" == True ]]'
RUN="$(date +%s)"; RA="qsd-reader-$RUN"; WA="qsd-writer-$RUN"
for a in "$RA" "$WA"; do
  api POST /v1/agents "$FORTIK_TOKEN_SECURITY" "{\"agent_id\":\"$a\",\"type\":\"erp_agent\",\"sponsor\":\"finance-ops@acme.example\"}" >/dev/null
  api PUT "/v1/agents/$a/level" "$FORTIK_TOKEN_SECURITY" '{"level":"FULL","reason":"QuickStart demo"}' >/dev/null
done
api PUT "/v1/agents/$RA/access/netsuite" "$FORTIK_TOKEN_SECURITY" '{"profile":{"mode":"read_only","record_types":["*"],"suiteql":false},"reason":"demo"}' >/dev/null
api PUT "/v1/agents/$WA/access/netsuite" "$FORTIK_TOKEN_SECURITY" '{"profile":{"mode":"read_write","record_types":["*"],"suiteql":false},"reason":"demo"}' >/dev/null
TR="$(api POST "/v1/agents/$RA/tokens" "$FORTIK_TOKEN_SECURITY" '{}' | J 'd["token"]')"
TW="$(api POST "/v1/agents/$WA/tokens" "$FORTIK_TOKEN_SECURITY" '{}' | J 'd["token"]')"
sleep 5 # agent tokens reload
mcp() { local p="${3:-}"; [ -n "$p" ] || p='{}'; curl -s -m 60 -X POST "$GW/mcp/netsuite_quickstart" -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$p}"; }
call() { mcp "$1" tools/call "{\"name\":\"$2\",\"arguments\":$3}" > "$TMP/r"; J 'd["result"]["_meta"]["fortik/decision"] + " " + str(d["result"]["_meta"]["fortik/executed"])' < "$TMP/r"; }
aid() { J 'd["result"]["_meta"]["fortik/action_id"]' < "$TMP/r"; }
NR="$(mcp "$TR" tools/list | J 'len(d["result"]["tools"])')"; NW="$(mcp "$TW" tools/list | J 'len(d["result"]["tools"])')"
check "tools/list through Fortik: the read-only agent sees $NR tools, the read-write agent $NW" '[[ "$NR" == 16 && "$NW" == 27 ]]'
D="$(call "$TR" read_record '{"recordType":"Customer","id":12}')"
check "read_record is decided and forwarded with Fortik's token: $D; the agent never sees the QuickStart token" '[[ "$D" == "allow True" ]] && ! leaked "$TMP/r"'
UPD='{"recordType":"Customer","id":12,"fieldValues":{"memo":"changed by the agent"}}'
D="$(call "$TW" update_record "$UPD")"; H="$(aid)"
check "update_record is held for approval and NOT executed: $D" '[[ "$D" == "hold False" && "$(fake /fake/toolcalls | J "d.get(\"update_record\",0)")" == 0 ]]'
api POST "/v1/held/$H/approve" "$FORTIK_TOKEN_SECURITY" '{"reason":"memo change checked","use_safe_form":false}' >/dev/null
check "security approves it ($(code))" '[[ "$(code)" == 200 ]]'
D="$(call "$TW" update_record '{"recordType":"Customer","id":12,"fieldValues":{"memo":"something else"}}')"
check "the approval covers only the exact arguments: different values are held again ($D)" '[[ "$D" == "hold False" ]]'
D="$(call "$TW" update_record "$UPD")"; RAN="$(aid)"; UNDO="$(J 'd["result"]["_meta"].get("fortik/undo","")' < "$TMP/r")"
check "the identical retry runs once ($D), after a snapshot: undo $UNDO" '[[ "$D" == "allow True" && "$UNDO" == available && "$(fake "/fake/record?type=Customer&id=12" | J "d[\"memo\"]")" == "changed by the agent" ]]'
D="$(call "$TW" update_record "$UPD")"
check "a duplicate retry is held again: the grant was used once ($D)" '[[ "$D" == "hold False" && "$(fake /fake/toolcalls | J "d.get(\"update_record\",0)")" == 1 ]]'
api POST "/v1/undo/$RAN" "$FORTIK_TOKEN_SECURITY" '{"reason":"wrong customer"}' >/dev/null
check "security undoes it ($(code)): the previous memo is written back" '[[ "$(code)" == 200 && "$(fake "/fake/record?type=Customer&id=12" | J "d[\"memo\"]")" == "LOCAL FAKE record" ]]'
check "the previous value was kept in the secret store, not in Postgres" '[[ "$(fdb "SELECT count(*) FROM undo_handles WHERE action_id='"'$RAN'"' AND handle_json::text LIKE '"'%LOCAL FAKE record%'"'")" == 0 ]]'
D="$(call "$TW" execute_record_transform '{"sourceRecordType":"VendorBill","sourceId":5,"transformId":"payVendorBill"}')"
check "payVendorBill (money movement) is held for two approvers: $D" '[[ "$D" == "hold False" ]] && grep -q "2 different approvers" "$TMP/r"'
D="$(call "$TW" set_preferences '{"preferenceKey":"MCP_SERVER_ENABLED","value":false}')"
check "changing MCP_SERVER_ENABLED is refused outright: $D" '[[ "$D" == "deny False" ]]'
D="$(call "$TW" delete_record '{"recordType":"Customer","id":12}')"; X="$(aid)"
api POST "/v1/held/$X/approve" "$FORTIK_TOKEN_SECURITY" '{"reason":"try","use_safe_form":false}' >/dev/null
check "delete_record is red ($D): an approval is refused ($(code)) and it never runs" '[[ "$D" == "hold False" && "$(code)" != 200 && "$(fake /fake/toolcalls | J "d.get(\"delete_record\",0)")" == 0 ]]'
D="$(call "$TR" brand_new_tool '{}')"; check "an unknown tool is refused: $D" '[[ "$D" == "deny False" ]]'
D="$(call "$TR" read_record '{"recordType":"Customer"}')"; check "arguments outside the discovered schema are refused: $D" '[[ "$D" == "deny False" ]]'
OV="$(api POST /v1/overrides "$FORTIK_TOKEN_SECURITY" "{\"scope\":\"agent\",\"scope_id\":\"$RA\",\"system\":\"netsuite\",\"mode\":\"suspended\",\"duration_seconds\":300,\"reason\":\"demo\"}" | J 'd["override_id"]')"
D="$(call "$TR" read_record '{"recordType":"Customer","id":12}')"
check "a timed NetSuite suspension stops the agent's QuickStart calls: $D" '[[ "$D" == "deny False" ]]'
api POST "/v1/overrides/$OV/release" "$FORTIK_TOKEN_SECURITY" '{"reason":"demo done"}' >/dev/null
st
check "the card counts the calls (allowed $(sv 'd["activity"]["allowed"]'), held $(sv 'd["activity"]["held"]'), denied $(sv 'd["activity"]["denied"]'), executed $(sv 'd["activity"]["executed"]'))" '[[ "$(sv "d[\"activity\"][\"executed\"] >= 2 and d[\"activity\"][\"held\"] >= 3")" == True ]]'

bold "10. Disconnect"
api DELETE /v1/integrations/netsuite_quickstart "$FORTIK_TOKEN_SECURITY" >/dev/null
check "deleted ($(code)); state not_configured; no stored tools or state" '[[ "$(code)" == 200 && "$(st; sv "d[\"state\"]")" == not_configured && "$(fdb "SELECT count(*) FROM mcp_connections")" == 0 ]]'
D="$(call "$TR" read_record '{"recordType":"Customer","id":12}')"
check "agents' calls are refused once disconnected: $D" '[[ "$D" == "deny False" ]]'
FG="$(fdb "SELECT count(*) FROM diary WHERE seq > $SEQ0 AND event_type = 'mcp.connection.forgotten' AND body_json::json->'data'->>'note' LIKE '%not revoked%'")"
check "Diary: mcp.connection.forgotten says the token is NOT revoked in QuickStart" '[[ "$FG" == 1 ]]'
say "$(sv 'd["revoke_instructions"]')"
check "Diary chain verifies" '"${FORTIK_BIN:-$ROOT/bin/fortik}" diary verify -config "${FORTIK_CONFIG:-$ROOT/configs/fortik.dev.yaml}" >/dev/null 2>&1 || [[ -n "${FORTIK_SKIP_VERIFY:-}" ]]'

echo
if [ "$FAILED" = 0 ]; then printf '\033[32mALL CHECKS PASSED\033[0m (LOCAL FAKE MCP server; no real QuickStart account was used)\n'; else printf '\033[31mSOME CHECKS FAILED\033[0m\n'; exit 1; fi
