#!/usr/bin/env bash
# Milestone 1 demo: NetSuite through Fortik, against the dev server and a
# LOCAL FAKE of NetSuite's REST web services (scripts/fakes/fakenetsuite).
# Nothing here touches a real NetSuite account. With a real sandbox, set
# FORTIK_NETSUITE_REAL=1 and configure the integration in the console first;
# the fake-only steps (direct changes) are then skipped.
#
#   1. connect: OAuth 2.0 client credentials (signed JWT), Test connection, capability probes
#   2. inventory: mapped agents' entities checked; no agent-inventory API claimed
#   3. pre-execution enforcement through the gateway: read, SuiteQL, snapshot-first
#      update + undo, payment (2 approvers), bank details, delete, read-only profile
#   4. authority laundering on NetSuite: a read-only agent's task delegated to a writer is refused
#   5. activity made OUTSIDE Fortik: read from system notes afterwards, evaluated, alerted
#   6. kill: what is and is NOT revoked in NetSuite; receipt; coverage stays D
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/.dev/tokens.env"
API="${FORTIK_API:-http://127.0.0.1:8080}"
GW="${FORTIK_GATEWAY:-http://127.0.0.1:8090}"
FPORT="${FORTIK_FAKE_NETSUITE_PORT:-18400}"
PGBIN="${PGBIN:-$(dirname "$(command -v psql 2>/dev/null || echo /Library/PostgreSQL/17/bin/psql)")}"
CFG=(-config "$ROOT/configs/fortik.dev.yaml")
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
fdb() { "$PGBIN/psql" -h 127.0.0.1 -p 55432 -U postgres -d fortik -X -A -t -q -c "$1"; }
api() { curl -s -o "$TMP/b" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $3" -H 'Content-Type: application/json' ${4:+-d "$4"} "$API$2" > "$TMP/c"; cat "$TMP/b"; }
code() { cat "$TMP/c"; }
level_of() { fdb "SELECT (ARRAY['FULL','SUPERVISED','READ_ONLY','ISOLATED','QUARANTINED','KILLED'])[level+1] FROM agents WHERE agent_id='$1'"; }
setlevel() { "$ROOT/bin/fortik" agent set-level "${CFG[@]}" -id "$1" -level "$2" -reason "netsuite demo" -actor demo >/dev/null 2>&1 || true; }
# ns <agent-token-var-value> METHOD PATH [json]: an agent's call through the gateway
ns() { curl -s -D "$TMP/h" -o "$TMP/b" -w '%{http_code}' -X "$2" -H "Authorization: Bearer $1" ${4:+-H 'Content-Type: application/json'} -H 'Prefer: transient' ${4:+-d "$4"} "$GW/gw/netsuite$3"; }
hdr_action() { awk -F': ' 'tolower($1)=="x-fortik-action-id"{print $2}' "$TMP/h" | tr -d '\r'; }
rule() { J 'd.get("error",{}).get("rule_id","")' < "$TMP/b" 2>/dev/null || true; }
fake() { curl -s "http://127.0.0.1:$FPORT$1" ${2:+-H 'Content-Type: application/json' -d "$2"}; }
curl -s -m 2 -o /dev/null "$API/healthz" || { echo "start the server first"; exit 2; }
REAL="${FORTIK_NETSUITE_REAL:-}"

bold "1. Connect (OAuth 2.0 client credentials, signed JWT)"
if [ -z "$REAL" ]; then
  (cd "$ROOT" && go build -o "$TMP/fakens" ./scripts/fakes/fakenetsuite)
  "$TMP/fakens" -port "$FPORT" -key-out "$TMP/ns.pem" > "$TMP/fake.log" 2>&1 & FAKE_PID=$!; disown "$FAKE_PID"
  for _ in $(seq 1 50); do nc -z 127.0.0.1 "$FPORT" 2>/dev/null && [ -s "$TMP/ns.pem" ] && break; sleep 0.2; done
  say "$(head -1 "$TMP/fake.log")"
  BODY="$(python3 - "$TMP/ns.pem" "$FPORT" <<'PY'
import json, sys
key = open(sys.argv[1]).read()
print(json.dumps({"config": {"account_id": "1234567_SB1", "client_id": "fortik-client-id", "certificate_id": "cert-123", "algorithm": "PS256",
  "api_base": "http://127.0.0.1:" + sys.argv[2], "agent_map": ["ns_order_bot=3", "ns_ap_bot=4"]}, "secrets": {"private_key_pem": key}}))
PY
)"
  api PUT /v1/integrations/netsuite "$FORTIK_TOKEN_SECURITY" "$BODY" >/dev/null
  check "security connects the (fake) account: integration saved ($(code)); the private key is stored as a secret only" '[[ "$(code)" == 200 ]] && ! grep -q "PRIVATE KEY" "$TMP/b"'
fi
api POST /v1/integrations/netsuite/test "$FORTIK_TOKEN_SECURITY" >/dev/null
check "Test connection: a token is issued and SuiteQL works ($(J 'str(d.get("ok")) + " " + str(d.get("error",""))' < "$TMP/b"))" '[[ "$(J "d.get(\"ok\")" < "$TMP/b")" == True ]]'

bold "2. Agents and inventory"
for a in ns_order_bot ns_ap_bot ns_planner; do api POST /v1/agents "$FORTIK_TOKEN_SECURITY" "{\"agent_id\":\"$a\",\"type\":\"erp_agent\",\"sponsor\":\"finance-ops@acme.com\"}" >/dev/null; setlevel $a FULL; done
api PUT /v1/agents/ns_order_bot/access/netsuite "$FORTIK_TOKEN_SECURITY" '{"profile":{"mode":"read_write","record_types":["*"],"suiteql":true},"reason":"demo"}' >/dev/null
api PUT /v1/agents/ns_ap_bot/access/netsuite "$FORTIK_TOKEN_SECURITY" '{"profile":{"mode":"read_only","record_types":["customer","vendor","vendorbill"],"suiteql":true},"reason":"demo"}' >/dev/null
api PUT /v1/agents/ns_planner/access/netsuite "$FORTIK_TOKEN_SECURITY" '{"profile":{"mode":"read_only","record_types":["*"],"suiteql":false},"reason":"demo"}' >/dev/null
api PUT /v1/agents/ns_planner/access/a2a "$FORTIK_TOKEN_SECURITY" '{"profile":{"may_delegate_to":["ns_order_bot"],"max_depth":2},"reason":"demo"}' >/dev/null
tok() { api POST "/v1/agents/$1/tokens" "$FORTIK_TOKEN_SECURITY" | J 'd["token"]'; }
T_ORDER="$(tok ns_order_bot)"; T_AP="$(tok ns_ap_bot)"
fdb "UPDATE delegations SET status='closed', closed_at=now(), close_reason='netsuite demo' WHERE status='open' AND (from_agent LIKE 'ns\_%' OR to_agent LIKE 'ns\_%')" >/dev/null
sleep 6
api GET /v1/saas/netsuite "$FORTIK_TOKEN_AUDITOR" > "$TMP/st"
J '"\n".join("    %-28s %-5s %s" % (p["name"], "ok" if p["ok"] else "NO", p["detail"][:90]) for p in d.get("probes",[]))' < "$TMP/st"
check "capability probes against the account: token, SuiteQL, system notes, mapped entities" '[[ "$(J "all(p[\"ok\"] for p in d[\"probes\"] if p[\"name\"] != \"agent_inventory_api\")" < "$TMP/st")" == True ]]'
check "agent inventory is reported as INCOMPLETE (no verified NetSuite API lists AI agents)" '[[ "$(J "d[\"inventory\"][\"complete\"]" < "$TMP/st")" == False && "$(J "len(d[\"inventory\"][\"agents\"])" < "$TMP/st")" == 2 ]]'

bold "3. Pre-execution enforcement through the Fortik gateway"
c="$(ns "$T_ORDER" GET /services/rest/record/v1/customer/101)"
check "a read is decided and forwarded with Fortik's token ($c); the agent never sees that token" '[[ "$c" == 200 ]] && grep -q "Acme Retail" "$TMP/b" && ! grep -q "fake-ns-token" "$TMP/b"'
c="$(ns "$T_ORDER" POST /services/rest/query/v1/suiteql '{"q":"SELECT id, companyname FROM customer"}')"
check "a SuiteQL query is decided and forwarded ($c)" '[[ "$c" == 200 ]] && grep -q Globex "$TMP/b"'
c="$(ns "$T_ORDER" PATCH /services/rest/record/v1/customer/101 '{"phone":"+1 555 9999"}')"; UPD="$(hdr_action)"
check "an update runs only after the changed field is snapshotted ($c, $(fdb "SELECT rule_id FROM actions WHERE action_id='$UPD'"))" '[[ "$c" == 204 && "$(fake /fake/state | J "d[\"records\"][\"customer\"][\"101\"][\"phone\"]")" == "+1 555 9999" ]]'
check "the snapshot is not in Fortik's database (only a pointer to the secret store)" '[[ "$(fdb "SELECT count(*) FROM undo_handles WHERE action_id='"'$UPD'"' AND handle_json::text LIKE '"'%555 0101%'"'")" == 0 ]]'
api POST "/v1/undo/$UPD" "$FORTIK_TOKEN_SECURITY" '{"reason":"wrong customer"}' >/dev/null
check "security undoes the update: the previous phone is restored ($(code))" '[[ "$(code)" == 200 && "$(fake /fake/state | J "d[\"records\"][\"customer\"][\"101\"][\"phone\"]")" == "+1 555 0101" ]]'
c="$(ns "$T_ORDER" POST /services/rest/record/v1/vendorPayment '{"entity":{"id":"201"},"total":1200}')"
check "a vendor payment is held before execution for 2 approvers ($c $(rule))" '[[ "$c" == 403 && "$(rule)" == POL-1003 ]]'
c="$(ns "$T_ORDER" PATCH /services/rest/record/v1/vendor/201 '{"achAccountNumber":"999000111"}')"
check "a change to a vendor's bank account number is held for approval ($c $(rule)); NetSuite unchanged" '[[ "$c" == 403 && "$(rule)" == POL-1004 && "$(fake /fake/state | J "d[\"records\"][\"vendor\"][\"201\"][\"achAccountNumber\"]")" == 000123456789 ]]'
c="$(ns "$T_AP" PATCH /services/rest/record/v1/customer/101 '{"phone":"x"}')"
check "the read-only AP bot's write is refused by its profile ($c $(rule))" '[[ "$c" == 403 && "$(rule)" == POL-021 ]]'
c="$(ns "$T_AP" GET /services/rest/record/v1/employee/3)"
check "the AP bot may not read record types outside its profile ($c $(rule))" '[[ "$c" == 403 && "$(rule)" == POL-1007 ]]'
c="$(ns "$T_ORDER" DELETE /services/rest/record/v1/customer/102)"
check "a delete is held red ($c $(rule)); the record still exists; the agent steps down to READ_ONLY" '[[ "$c" == 403 && "$(rule)" == POL-1002 && "$(fake /fake/state | J "\"102\" in d[\"records\"][\"customer\"]")" == True && "$(level_of ns_order_bot)" == READ_ONLY ]]'
setlevel ns_order_bot FULL

bold "4. Authority laundering on NetSuite"
api POST /v1/actions/decide "$FORTIK_TOKEN_INTERCEPTOR" '{"agent_id":"ns_planner","system":"a2a","verb":"DELEGATE","source":"agentgateway","target":{"to_agent":"ns_order_bot","channel":"a2a","route":"ns"}}' >/dev/null
check "ns_planner (read-only in NetSuite) delegates a task to ns_order_bot (read-write)" '[[ "$(J "d[\"decision\"]" < "$TMP/b")" == allow ]]'
c="$(ns "$T_ORDER" PATCH /services/rest/record/v1/customer/101 '{"email":"x@evil.example"}')"
check "ns_order_bot's update for the planner's task is refused ($c $(rule)): the planner's restriction is inherited" '[[ "$c" == 403 && "$(rule)" == POL-601 ]]'
fdb "UPDATE delegations SET status='closed', closed_at=now(), close_reason='netsuite demo' WHERE status='open' AND (from_agent LIKE 'ns\_%' OR to_agent LIKE 'ns\_%')" >/dev/null
setlevel ns_planner FULL

if [ -z "$REAL" ]; then
bold "5. Activity made OUTSIDE Fortik (read from system notes afterwards)"
fake /fake/direct-change '{"Entity":"4","RecordType":"customer","RecordID":"101","Field":"creditlimit"}' >/dev/null
fake /fake/direct-change '{"Entity":"3","RecordType":"customer","RecordID":"102","Field":"email"}' >/dev/null
say "simulated: the AP bot's own NetSuite login changed a customer's credit limit, bypassing Fortik"
api POST /v1/saas/netsuite/sync "$FORTIK_TOKEN_SECURITY" > "$TMP/sync" ; say "sync: $(cat "$TMP/sync")"
check "both changes are ingested; the read-only bot's write is flagged: policy would have refused it (detected, not prevented)" '[[ "$(J "d[\"events\"]" < "$TMP/sync")" -ge 2 && "$(J "d[\"violations\"]" < "$TMP/sync")" -ge 1 ]]'
check "recorded as observed after execution, with the would-be rule" '[[ "$(fdb "SELECT decision || '"' '"' || rule_id || '"' '"' || observed FROM actions WHERE agent_id='"'ns_ap_bot'"' AND source='"'vendor_audit'"' ORDER BY ts DESC LIMIT 1")" == "allow POL-021 true" ]]'
check "security is alerted (saas_policy_violation)" '[[ "$(fdb "SELECT count(*) FROM alerts WHERE kind='"'saas_policy_violation'"' AND agent_id='"'ns_ap_bot'"'")" -ge 1 ]]'
api POST /v1/saas/netsuite/sync "$FORTIK_TOKEN_SECURITY" > "$TMP/sync2"
check "a second sync finds nothing new (deduplicated, cursor kept)" '[[ "$(J "d[\"events\"]" < "$TMP/sync2")" == 0 ]]'
fi

bold "6. Kill: what stops, and what does not"
api POST /v1/agents/ns_ap_bot/kill "$FORTIK_TOKEN_SECURITY" '{"reason":"netsuite demo kill"}' > "$TMP/k"; OP="$(J 'd["op_id"]' < "$TMP/k")"
c="$(ns "$T_AP" GET /services/rest/record/v1/customer/101)"
check "every gateway call by the killed agent is refused ($c $(rule))" '[[ "$c" == 403 && "$(rule)" == POL-010 ]]'
api GET "/v1/containment/$OP/receipt" "$FORTIK_TOKEN_AUDITOR" > "$TMP/r"
say "receipt: $(J 'd["outcome"]' < "$TMP/r"); residual:"
J '"\n".join("      - " + x[:170] for x in d["residual_access"] if "netsuite" in x)' < "$TMP/r"
check "the receipt says NetSuite-side access was NOT revoked (no verified API), so it is not 'confirmed'" '[[ "$(J "d[\"outcome\"]" < "$TMP/r")" == partially_confirmed ]] && grep -q "NOT revoked" "$TMP/r"'
setlevel ns_ap_bot FULL; fdb "DELETE FROM memory_access WHERE agent_id='ns_ap_bot'" >/dev/null
api GET /v1/coverage "$FORTIK_TOKEN_AUDITOR" > "$TMP/cov"
check "coverage: NetSuite is connected but class $(J '[r["class"] for r in d["integrations"] if r["system"]=="netsuite"][0]' < "$TMP/cov") (verified only against a fake, never A/B/C)" '[[ "$(J "[r[\"class\"] for r in d[\"integrations\"] if r[\"system\"]==\"netsuite\"][0]" < "$TMP/cov")" == D ]]'

if [ -z "$REAL" ]; then
  api DELETE /v1/integrations/netsuite "$FORTIK_TOKEN_SECURITY" >/dev/null
  say "fake integration removed"
fi
api GET /v1/diary/verify "$FORTIK_TOKEN_AUDITOR" > "$TMP/v"
check "Diary chain verifies" '[[ "$(J "d[\"ok\"]" < "$TMP/v")" == True ]]'
echo
if [ "$FAILED" = 0 ]; then printf '\033[32mNetSuite demo (LOCAL FAKE): all checks passed\033[0m\n'; else printf '\033[31mNetSuite demo: FAILURES above\033[0m\n'; exit 1; fi
