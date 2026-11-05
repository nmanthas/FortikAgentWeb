#!/usr/bin/env bash
# End-to-end check of the Salesforce, ServiceNow and SAP connections (REST API
# and MCP Server) through a RUNNING Fortik server, against LOCAL FAKES of the
# providers (scripts/fakes/fakesaas). The fakes are not the providers: this
# proves Fortik's wiring (save, test, status, OAuth, gateway and MCP
# decisions, disconnect), never a provider's behaviour.
#
# It uses its own tenant "fortikfake" of each provider and removes it at the
# end; other tenants are untouched. The server must allow loopback upstreams:
#   saas_upstreams.allow_loopback: true and mcp_upstreams.allow_loopback: true
# Run it on a development instance (ideally with its own database).
#
# Usage: FORTIK_API=http://127.0.0.1:28080 FORTIK_GATEWAY=http://127.0.0.1:28090 ./scripts/verify-saas-connections.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/.dev/tokens.env"
API="${FORTIK_API:-http://127.0.0.1:8080}"
GW="${FORTIK_GATEWAY:-http://127.0.0.1:8090}"
P1="${FORTIK_FAKE_SF_PORT:-18501}"; P2="${FORTIK_FAKE_SN_PORT:-18502}"; P3="${FORTIK_FAKE_SAP_PORT:-18503}"
SF="http://127.0.0.1:$P1"; SN="http://127.0.0.1:$P2"; SAP="http://127.0.0.1:$P3"
TMP="$(mktemp -d)"; FAKE_PID=""
FAILED=0
bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILED=1; }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
J() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
api() { curl -s -o "$TMP/b" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $FORTIK_TOKEN_SECURITY" -H 'Content-Type: application/json' ${3:+-d "$3"} "$API$2" > "$TMP/c"; cat "$TMP/b"; }
code() { cat "$TMP/c"; }
C() { python3 -c "import json; print(json.load(open('$TMP/creds'))['$1'])"; }
state() { api GET "/v1/integrations/$1/$2" | J 'd["state"]'; }
KEYS="salesforce_mcp:fortikfake salesforce:fortikfake servicenow_mcp:fortikfake servicenow:fortikfake sap_mcp:fortikfake sap:fortikfake"
cleanup() {
  for k in $KEYS; do curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $FORTIK_TOKEN_SECURITY" "$API/v1/integrations/$k" || true; done
  if [ -n "$FAKE_PID" ]; then kill "$FAKE_PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

curl -s -m 2 -o /dev/null "$API/healthz" || { echo "start the server first"; exit 2; }
(cd "$ROOT" && go build -o "$TMP/fakesaas" ./scripts/fakes/fakesaas)
"$TMP/fakesaas" -salesforce-port "$P1" -servicenow-port "$P2" -sap-port "$P3" -secrets-out "$TMP/creds" -redirect "$API/v1/oauth/mcp/callback" > "$TMP/fake.log" 2>&1 &
FAKE_PID=$!; disown "$FAKE_PID"
for _ in $(seq 1 50); do curl -s -m 1 -o /dev/null "$SAP/fake/calls" && break; sleep 0.1; done

RUN="$(date +%s)"; AG="saasv-$RUN"
bold "0. A test agent with read-write profiles for the three systems"
api POST /v1/agents "{\"agent_id\":\"$AG\",\"type\":\"crm_agent\",\"sponsor\":\"${SAAS_VERIFY_SPONSOR:-security@example.com}\"}" >/dev/null
api PUT "/v1/agents/$AG/level" '{"level":"FULL","reason":"SaaS connection verification"}' >/dev/null
for s in salesforce servicenow sap; do
  api PUT "/v1/agents/$AG/access/$s" '{"profile":{"mode":"read_write","objects":["*"]},"reason":"SaaS connection verification"}' >/dev/null
done
T="$(api POST "/v1/agents/$AG/tokens" '{}' | J 'd["token"]')"
check "agent registered with salesforce, servicenow and sap profiles" '[[ -n "$T" ]]'
sleep 5 # agent tokens reload
gw() { curl -s -o "$TMP/g" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $T" -H "X-Fortik-Integration: $2" -H 'Content-Type: application/json' ${4:+-d "$4"} "$GW$3"; }
mcpcall() {
  curl -s -X POST "$GW/mcp/$1/fortikfake" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":{}}}"
}

bold "1. Salesforce REST API (client credentials)"
api PUT /v1/integrations/salesforce:fortikfake "{\"config\":{\"instance_url\":\"$SF\",\"client_id\":\"$(C sf_client_id)\"},\"secrets\":{\"client_secret\":\"$(C sf_client_secret)\"}}" >/dev/null
S="$(state salesforce:fortikfake check)"; check "saved; not shown as connected before a test ($S)" '[[ "$S" == saved_not_tested ]]'
api POST /v1/integrations/salesforce:fortikfake/test '{}' >/dev/null
api GET /v1/integrations/salesforce:fortikfake/check > "$TMP/sf"
check "Test connection: $(J 'd["state_label"] + " — " + d["detail"]' < "$TMP/sf")" '[[ "$(J "d[\"state\"]" < "$TMP/sf")" == connected ]]'
check "capabilities discovered ($(J 'd["capabilities"]["objects_visible"]' < "$TMP/sf") objects visible)" '[[ "$(J "d[\"capabilities\"][\"objects_visible\"]" < "$TMP/sf")" == 2 ]]'

bold "2. Salesforce MCP Server (OAuth authorization code, the same tenant)"
api PUT /v1/integrations/salesforce_mcp:fortikfake "{\"config\":{\"endpoint_url\":\"$SF/platform/mcp/v1/platform/sobject-all\",\"instance_url\":\"$SF\",\"client_id\":\"$(C sf_client_id)\",\"redirect_uri\":\"$API/v1/oauth/mcp/callback\"},\"secrets\":{\"client_secret\":\"$(C sf_client_secret)\"}}" >/dev/null
S="$(state salesforce_mcp:fortikfake mcp)"; check "saved; authorization required ($S)" '[[ "$S" == authorization_required ]]'
AU="$(api POST /v1/integrations/salesforce_mcp:fortikfake/oauth/start '{}' | J 'd["authorize_url"]')"
CB="$(curl -s -o /dev/null -w '%{redirect_url}' "$AU")"
BACK="$(curl -s -o /dev/null -w '%{redirect_url}' -H "Authorization: Bearer $FORTIK_TOKEN_SECURITY" "$CB")"
check "a user authorized Fortik (consent at the fake; back to the console with oauth_ok)" '[[ "$BACK" == *"oauth_ok=1"* ]]'
api GET /v1/integrations/salesforce_mcp:fortikfake/mcp > "$TMP/mcp"
check "MCP connected: $(J 'str(d["tool_count"])' < "$TMP/mcp") tools, $(J 'str(d["mapped_tools"])' < "$TMP/mcp") mapped" '[[ "$(J "d[\"state\"]" < "$TMP/mcp")" == connected && "$(J "d[\"mapped_tools\"]" < "$TMP/mcp")" == 0 ]]'
api GET /v1/app-integrations/salesforce:fortikfake > "$TMP/app"
check "one integration, both methods: $(J '" ".join(t["transport"] + "=" + ("configured" if t["configured"] else "not configured") for t in d["transports"])' < "$TMP/app")" '[[ "$(J "len(d[\"connections\"])" < "$TMP/app")" == 2 ]]'

bold "3. Agents through Fortik (Salesforce)"
R="$(gw GET salesforce:fortikfake /gw/salesforce/services/data/v62.0/sobjects/Account/001FAKE)"
check "REST read allowed and forwarded ($R)" '[[ "$R" == 200 ]]'
P="$(gw PATCH salesforce:fortikfake /gw/salesforce/services/data/v62.0/sobjects/Account/001FAKE '{"Name":"x"}')"
check "REST update held, not sent ($P, $(J 'd["error"]["rule_id"]' < "$TMP/g"))" '[[ "$P" == 403 && "$(J "d[\"error\"][\"rule_id\"]" < "$TMP/g")" == POL-1201 ]]'
check "no PATCH reached the fake" '[[ "$(curl -s "$SF/fake/calls" | J "len([c for c in d[\"calls\"] if c.startswith(\"PATCH\")])")" == 0 ]]'
M="$(mcpcall salesforce read_record | J 'd["result"]["_meta"]["fortik/decision"] + " " + str(d["result"]["_meta"]["fortik/executed"])')"
check "MCP tool call refused until the tool is mapped ($M)" '[[ "$M" == "deny False" ]]'

bold "4. ServiceNow (REST Basic; MCP client credentials)"
api PUT /v1/integrations/servicenow:fortikfake "{\"config\":{\"instance_url\":\"$SN\",\"username\":\"$(C sn_user)\",\"test_tables\":[\"incident\",\"change_request\"]},\"secrets\":{\"password\":\"$(C sn_password)\"}}" >/dev/null
api POST /v1/integrations/servicenow:fortikfake/test '{}' >/dev/null
api GET /v1/integrations/servicenow:fortikfake/check > "$TMP/sn"
check "REST connected; tables: $(J 'd["capabilities"]["tables"]' < "$TMP/sn")" '[[ "$(J "d[\"state\"]" < "$TMP/sn")" == connected ]]'
api PUT /v1/integrations/servicenow_mcp:fortikfake "{\"config\":{\"endpoint_url\":\"$SN/sncapps/mcp-server/mcp/sn_mcp_server_default\",\"auth_type\":\"oauth_client_credentials\",\"client_id\":\"$(C sn_mcp_client)\"},\"secrets\":{\"client_secret\":\"$(C sn_mcp_secret)\"}}" >/dev/null
api POST /v1/integrations/servicenow_mcp:fortikfake/test '{}' >/dev/null
S="$(state servicenow_mcp:fortikfake mcp)"; check "MCP connected with client credentials ($S)" '[[ "$S" == connected ]]'
R="$(gw GET servicenow:fortikfake '/gw/servicenow/api/now/table/incident?sysparm_limit=1')"
check "REST read through the gateway ($R)" '[[ "$R" == 200 ]]'

bold "5. SAP (OData Basic; customer-managed MCP with a bearer token)"
api PUT /v1/integrations/sap:fortikfake "{\"config\":{\"api_base_url\":\"$SAP\",\"username\":\"$(C sap_user)\"},\"secrets\":{\"password\":\"$(C sap_password)\"}}" >/dev/null
api POST /v1/integrations/sap:fortikfake/test '{}' >/dev/null
api GET /v1/integrations/sap:fortikfake/check > "$TMP/sap"
check "REST connected: $(J 'd["detail"]' < "$TMP/sap")" '[[ "$(J "d[\"state\"]" < "$TMP/sap")" == connected ]]'
api PUT /v1/integrations/sap_mcp:fortikfake "{\"config\":{\"endpoint_url\":\"$SAP/mcp\",\"auth_type\":\"bearer_token\"},\"secrets\":{\"access_token\":\"$(C sap_mcp_token)\"}}" >/dev/null
api POST /v1/integrations/sap_mcp:fortikfake/test '{}' >/dev/null
S="$(state sap_mcp:fortikfake mcp)"; check "MCP connected with a bearer token ($S)" '[[ "$S" == connected ]]'
api PUT /v1/integrations/sap:fortikfake "{\"config\":{\"api_base_url\":\"$SAP\",\"username\":\"$(C sap_user)\"},\"secrets\":{\"password\":\"wrong-password-0000\"}}" >/dev/null
api POST /v1/integrations/sap:fortikfake/test '{}' >/dev/null
S="$(state sap:fortikfake check)"; check "a wrong password is reported as $S" '[[ "$S" == auth_failed ]]'

bold "6. No credential in any reply; disconnect"
ALL="$(for k in $KEYS; do api GET "/v1/integrations/$k"; done; api GET /v1/integrations/salesforce:fortikfake/check; api GET /v1/integrations/salesforce_mcp:fortikfake/mcp; api GET /v1/app-integrations)"
LEAK=0; for f in sf_client_secret sn_password sn_mcp_secret sap_password sap_mcp_token; do if [[ "$ALL" == *"$(C "$f")"* ]]; then LEAK=1; fi; done
check "no secret value in any API reply" '[[ "$LEAK" == 0 ]]'
NOTE="$(api DELETE /v1/integrations/salesforce_mcp:fortikfake | J '" ".join(d.get("notes", []))')"
check "disconnecting Salesforce MCP revokes the grant: $NOTE" '[[ "$NOTE" == *"confirmed the revocation"* ]]'
S="$(state salesforce:fortikfake check)"; check "REST still connected after MCP was disconnected ($S)" '[[ "$S" == connected ]]'
for k in $KEYS; do api DELETE "/v1/integrations/$k" >/dev/null; done
N="$(api GET /v1/app-integrations | J 'len([a for a in d["integrations"] if a["integration_id"].endswith(":fortikfake")])')"
check "test tenants removed ($N left)" '[[ "$N" == 0 ]]'
api DELETE "/v1/agents/$AG/tokens" >/dev/null
api PUT "/v1/agents/$AG/level" '{"level":"KILLED","reason":"SaaS verification agent: finished"}' >/dev/null

echo
if [ "$FAILED" = 0 ]; then printf '\033[32mALL CHECKS PASSED\033[0m against LOCAL FAKES of Salesforce, ServiceNow and SAP\n'; else printf '\033[31mSOME CHECKS FAILED\033[0m\n'; exit 1; fi
