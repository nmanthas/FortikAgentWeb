#!/usr/bin/env bash
# Live verification of NetSuite QuickStart through Fortik, against the REAL
# QuickStart tenant configured in the console (Integrations > NetSuite
# QuickStart (MCP), Test connection must say Connected).
#
# SAFE BY DESIGN: it only reads, and it checks that writes are held or refused.
# Every held write is DENIED at the end, so nothing is ever executed on the
# tenant. Record values are never printed (only counts and decisions).
#
#   1. tools/list through Fortik: a read-only agent sees read tools only
#   2. reads run through Fortik with Fortik's token (record model, a list, a record, reports)
#   3. writes are held for approval and do not run (update_record, delete_record)
#   4. refusals never reach QuickStart: read-only profile, unknown tool, schema, protected preference
#   5. a timed NetSuite suspension stops one agent's QuickStart calls, not another's
#   5b. one tenant (netsuite:quickstart) across endpoints: the tenant endpoint
#       /mcp/netsuite/quickstart, the tenant restriction (POL-1010), an unknown
#       tenant, and REST shown unavailable rather than configured
#   6. activity, coverage and the Diary
#
# Usage: FORTIK_API=http://127.0.0.1:8080 FORTIK_GATEWAY=http://127.0.0.1:8090 ./scripts/verify-quickstart-live.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/.dev/tokens.env"
API="${FORTIK_API:-http://127.0.0.1:8080}"
GW="${FORTIK_GATEWAY:-http://127.0.0.1:8090}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILED=0
bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
say()  { printf '  \033[2m%s\033[0m\n' "$*"; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILED=1; }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
J() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
api() { curl -s -o "$TMP/b" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $FORTIK_TOKEN_SECURITY" -H 'Content-Type: application/json' ${3:+-d "$3"} "$API$2" > "$TMP/c"; cat "$TMP/b"; }
# mcp <agent-token> <method> [params-json]: one JSON-RPC call to Fortik's QuickStart endpoint
# ($MCP_PATH, default /mcp/netsuite_quickstart)
mcp() {
  local params="${3:-}"
  [ -n "$params" ] || params='{}'
  curl -s -m 120 -X POST "$GW${MCP_PATH:-/mcp/netsuite_quickstart}" -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$params}"
}
# call <token> <tool> <args-json> -> writes the reply to $TMP/r; prints "decision executed"
call() { mcp "$1" tools/call "{\"name\":\"$2\",\"arguments\":$3}" > "$TMP/r"; J 'd["result"]["_meta"]["fortik/decision"] + " " + str(d["result"]["_meta"]["fortik/executed"])' < "$TMP/r"; }
aid() { J 'd["result"]["_meta"]["fortik/action_id"]' < "$TMP/r"; }
rule() { api GET "/v1/actions/$1" >/dev/null; J 'd.get("rule_id","")' < "$TMP/b"; }

curl -s -m 2 -o /dev/null "$API/healthz" || { echo "start the server first"; exit 2; }
api GET /v1/saas/netsuite_quickstart > "$TMP/st"
say "QuickStart: $(J 'd["state_label"] + " · " + str(d["tool_count"]) + " tools · token scope " + d["permission_mode"]' < "$TMP/st")"
if [[ "$(J 'd["state"] == "connected" and d["tools_from_current_settings"]' < "$TMP/st")" != True ]]; then
  echo "QuickStart is not connected with a current tool list: run Test connection in the console first"; exit 2
fi
HELD_IDS=()
# Fresh agents every run: a refused delete steps its agent down (POL-1002),
# and levels only step back up one at a time.
RUN="$(date +%s)"; RA="qsv-reader-$RUN"; WA="qsv-writer-$RUN"

bold "0. Test agents (read-only and read-write NetSuite profiles)"
for a in "$RA" "$WA"; do
  api POST /v1/agents "{\"agent_id\":\"$a\",\"type\":\"erp_agent\",\"sponsor\":\"${QS_VERIFY_SPONSOR:-security@example.com}\"}" >/dev/null
  api PUT "/v1/agents/$a/level" '{"level":"FULL","reason":"QuickStart live verification"}' >/dev/null
done
api PUT "/v1/agents/$RA/access/netsuite" '{"profile":{"mode":"read_only","record_types":["*"],"suiteql":false},"reason":"QuickStart live verification"}' >/dev/null
api PUT "/v1/agents/$WA/access/netsuite" '{"profile":{"mode":"read_write","record_types":["*"],"suiteql":false},"reason":"QuickStart live verification (writes are held and denied)"}' >/dev/null
R="$(api POST "/v1/agents/$RA/tokens" '{}' | J 'd["token"]')"
W="$(api POST "/v1/agents/$WA/tokens" '{}' | J 'd["token"]')"
check "agents registered with read_only and read_write profiles" '[[ -n "$R" && -n "$W" ]]'
sleep 5 # agent tokens reload

bold "1. tools/list through Fortik"
NR="$(mcp "$R" tools/list | J 'len(d["result"]["tools"])')"; NW="$(mcp "$W" tools/list | J 'len(d["result"]["tools"])')"
check "the read-only agent sees $NR tools (read tools only), the read-write agent $NW" '[[ "$NR" -lt "$NW" && "$NR" -gt 0 ]]'
check "write tools are described as held for approval" '[[ "$(mcp "$W" tools/list | J "[t[\"description\"][:20] for t in d[\"result\"][\"tools\"] if t[\"name\"]==\"update_record\"][0]")" == "[Fortik: calls to th" ]]'

bold "2. Reads run through Fortik (Fortik's QuickStart token; the agent never has it)"
D="$(call "$R" get_record_model '{}')"; check "get_record_model: $D" '[[ "$D" == "allow True" ]]'
D="$(call "$R" list_records '{"recordType":"Term","limit":1}')"; check "list_records Term (limit 1): $D" '[[ "$D" == "allow True" ]]'
# The id of one Term (as JSON); never printed.
TERM_ID="$(python3 -c '
import json, sys
d = json.load(sys.stdin)
for c in d["result"]["content"]:
    try:
        recs = json.loads(c["text"]).get("records") or []
    except Exception:
        continue
    if recs:
        print(json.dumps(recs[0]["id"]))
        break
' < "$TMP/r")"
[ -n "$TERM_ID" ] || { echo "the tenant has no Term records to read; pick another record type in this script"; exit 2; }
READ_ARGS="{\"recordType\":\"Term\",\"id\":$TERM_ID}"
D="$(call "$R" read_record "$READ_ARGS")"; check "read_record Term: $D" '[[ "$D" == "allow True" ]]'
D="$(call "$R" report_catalog '{"query":"all reports"}')"; check "report_catalog: $D" '[[ "$D" == "allow True" ]]'

bold "3. Writes are held and do not run"
D="$(call "$W" update_record "{\"recordType\":\"Term\",\"id\":$TERM_ID,\"fieldValues\":{\"name\":\"fortik-verification-never-executed\"}}")"; U="$(aid)"; HELD_IDS+=("$U")
check "update_record: $D ($(rule "$U")): held, not executed; undo would be prepared" '[[ "$D" == "hold False" ]] && grep -q "repeat exactly the same call" "$TMP/r"'
D="$(call "$W" set_preferences '{"preferenceKey":"MCP_SERVER_ENABLED","value":false}')"; P="$(aid)"
check "set_preferences MCP_SERVER_ENABLED: $D ($(rule "$P")): refused outright" '[[ "$D" == "deny False" ]]'
D="$(call "$W" delete_record "{\"recordType\":\"Term\",\"id\":$TERM_ID}")"; X="$(aid)"; HELD_IDS+=("$X")
check "delete_record: $D ($(rule "$X")): red, never released by an approval" '[[ "$D" == "hold False" ]] && grep -q "never released unchanged" "$TMP/r"'

bold "4. Refusals never reach QuickStart"
D="$(call "$R" update_record "{\"recordType\":\"Term\",\"id\":$TERM_ID,\"fieldValues\":{\"name\":\"x\"}}")"; check "read-only profile, update_record: $D ($(rule "$(aid)"))" '[[ "$D" == "deny False" ]]'
D="$(call "$R" no_such_tool '{}')"; check "unknown tool: $D ($(rule "$(aid)"))" '[[ "$D" == "deny False" ]]'
D="$(call "$R" read_record '{"recordType":"Term"}')"; check "arguments outside the tool's schema (no id): $D ($(rule "$(aid)"))" '[[ "$D" == "deny False" ]]'

bold "5. A timed NetSuite suspension (one agent)"
OV="$(api POST /v1/overrides "{\"scope\":\"agent\",\"scope_id\":\"$RA\",\"system\":\"netsuite\",\"mode\":\"suspended\",\"duration_seconds\":300,\"reason\":\"QuickStart live verification\"}" | J 'd["override_id"]')"
D="$(call "$R" get_record_model '{}')"; check "the suspended agent is refused: $D ($(rule "$(aid)"))" '[[ "$D" == "deny False" ]]'
D="$(call "$W" get_record_model '{}')"; check "another agent is not: $D" '[[ "$D" == "allow True" ]]'
api POST "/v1/overrides/$OV/release" '{"reason":"verification done"}' >/dev/null
check "released early ($(cat "$TMP/c"))" '[[ "$(cat "$TMP/c")" == 200 ]]'

bold "5b. One tenant across endpoints (netsuite:quickstart)"
NL="$(mcp "$R" tools/list | J 'len(d["result"]["tools"])')"
NT="$(MCP_PATH=/mcp/netsuite/quickstart mcp "$R" tools/list | J 'len(d["result"]["tools"])')"
check "the tenant endpoint /mcp/netsuite/quickstart offers the same $NT tools as /mcp/netsuite_quickstart" '[[ "$NT" == "$NL" && "$NT" -gt 0 ]]'
D="$(MCP_PATH=/mcp/netsuite/quickstart call "$R" read_record "$READ_ARGS")"; T="$(aid)"
api GET "/v1/actions/$T" >/dev/null
TGT="$(J 'd["target"].get("integration_id","") + " " + d["target"].get("transport","") + " " + d["target"].get("integration","")' < "$TMP/b")"
check "read_record through the tenant endpoint: $D, recorded as $TGT" '[[ "$D" == "allow True" && "$TGT" == "netsuite:quickstart mcp netsuite_quickstart" ]]'
api PUT "/v1/agents/$RA/access/netsuite" '{"profile":{"mode":"read_only","record_types":["*"],"suiteql":false,"integrations":["netsuite:other_tenant"]},"reason":"QuickStart live verification: tenant restriction"}' >/dev/null
sleep 1
D="$(call "$R" read_record "$READ_ARGS")"; check "a profile limited to another tenant refuses the read: $D ($(rule "$(aid)"))" '[[ "$D" == "deny False" && "$(rule "$(aid)")" == POL-1010 ]]'
check "and its tools/list is refused (POL-1010)" '[[ "$(mcp "$R" tools/list | J "\"POL-1010\" in d.get(\"error\", {}).get(\"message\", \"\")")" == True ]]'
api PUT "/v1/agents/$RA/access/netsuite" '{"profile":{"mode":"read_only","record_types":["*"],"suiteql":false,"integrations":["netsuite:quickstart"]},"reason":"QuickStart live verification: tenant restriction"}' >/dev/null
sleep 1
D="$(call "$R" read_record "$READ_ARGS")"; check "a profile listing netsuite:quickstart allows it: $D" '[[ "$D" == "allow True" ]]'
D="$(MCP_PATH=/mcp/netsuite/no_such_tenant call "$R" read_record "$READ_ARGS")"
check "an unknown tenant endpoint refuses the call: $D ($(rule "$(aid)"))" '[[ "$D" == "deny False" ]] && grep -q "has no MCP connection" "$TMP/r"'
api GET /v1/app-integrations/netsuite:quickstart > "$TMP/app"
TR="$(J '" ".join(t["transport"] + "=" + ("configured" if t["configured"] else ("unavailable" if not t["available"] else "not_configured")) for t in d["transports"])' < "$TMP/app")"
check "the integration shows $TR (a working MCP connection is no proof of REST)" '[[ "$TR" == "rest_api=unavailable mcp=configured" ]]'

bold "6. Activity, coverage, Diary; clean up"
for id in "${HELD_IDS[@]}"; do api POST "/v1/held/$id/deny" '{"reason":"QuickStart live verification: never execute"}' >/dev/null; done
check "every held verification write was denied (nothing ran on the tenant)" '[[ "$(api GET /v1/held?status=pending\&limit=1000 | J "len([h for h in d[\"held\"] if h.get(\"agent_id\",\"\").startswith(\"qsv-\")])")" == 0 ]]'
api GET /v1/saas/netsuite_quickstart > "$TMP/st"
say "last 24h: $(J 'str(d["activity"]["allowed"]) + " allowed, " + str(d["activity"]["held"]) + " held, " + str(d["activity"]["denied"]) + " denied, " + str(d["activity"]["executed"]) + " executed"' < "$TMP/st")"
check "the card reports agent calls as routed through Fortik" '[[ "$(J "d[\"enforcement\"][\"agent_calls_routed\"]" < "$TMP/st")" == True ]]'
for a in "$RA" "$WA"; do
  api DELETE "/v1/agents/$a/tokens" >/dev/null
  api PUT "/v1/agents/$a/level" '{"level":"KILLED","reason":"QuickStart verification agent: finished"}' >/dev/null
done
check "verification agents' tokens revoked" '[[ "$(cat "$TMP/c")" == 200 ]]'
if [ -n "${FORTIK_BIN:-}" ]; then
  check "Diary chain verifies" '"$FORTIK_BIN" diary verify -config "${FORTIK_CONFIG:-$ROOT/configs/fortik.dev.yaml}" >/dev/null 2>&1'
fi

echo
if [ "$FAILED" = 0 ]; then printf '\033[32mALL CHECKS PASSED\033[0m against the real QuickStart tenant (reads only; held writes denied, nothing executed)\n'; else printf '\033[31mSOME CHECKS FAILED\033[0m\n'; exit 1; fi
