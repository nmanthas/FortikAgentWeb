#!/usr/bin/env bash
# One controlled WRITE test of NetSuite QuickStart through Fortik, against the
# real tenant configured in the console. It changes NetSuite, so it runs only
# with QS_ALLOW_WRITE=yes. It touches only a Contact it creates itself:
#
#   1. create_record Contact "Fortik / Verification - safe to delete": held, approved, run once
#   2. update_record its workEmail: held (undo prepared), approved, run once with a snapshot
#   3. undo: the previous workEmail (empty) is written back
#   4. delete_record: red, an approval is refused, it never runs
#   5. execute_record_action inactivate: held, approved, run once (the contact is left inactive)
#
# Delete the inactive contact in QuickStart afterwards if you do not want it
# kept (Fortik never runs deletes). Approvals are given with the security API
# token, so QS_VERIFY_SPONSOR must not be that identity.
#
# Usage: QS_ALLOW_WRITE=yes QS_VERIFY_SPONSOR=<email> FORTIK_API=... FORTIK_GATEWAY=... ./scripts/verify-quickstart-write.sh
set -euo pipefail
[[ "${QS_ALLOW_WRITE:-}" == yes ]] || { echo "this script changes NetSuite: set QS_ALLOW_WRITE=yes to run it"; exit 2; }
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
stop() { fail "$1"; echo; printf '\033[31mSTOPPED\033[0m: %s\n' "$1"; exit 1; }
J() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
api() { curl -s -o "$TMP/b" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $FORTIK_TOKEN_SECURITY" -H 'Content-Type: application/json' ${3:+-d "$3"} "$API$2" > "$TMP/c"; cat "$TMP/b"; }
code() { cat "$TMP/c"; }
mcp() {
  local params="${3:-}"
  [ -n "$params" ] || params='{}'
  curl -s -m 120 -X POST "$GW/mcp/netsuite_quickstart" -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$params}"
}
call() { mcp "$W" tools/call "{\"name\":\"$1\",\"arguments\":$2}" > "$TMP/r"; J 'd["result"]["_meta"]["fortik/decision"] + " " + str(d["result"]["_meta"]["fortik/executed"])' < "$TMP/r"; }
aid() { J 'd["result"]["_meta"]["fortik/action_id"]' < "$TMP/r"; }
approve() { api POST "/v1/held/$1/approve" '{"reason":"QuickStart write verification (scripts/verify-quickstart-write.sh)","use_safe_form":false}' >/dev/null; code; }
# field <name>: the value of one field of the test contact as JSON (null when empty)
field() {
  call read_record "{\"recordType\":\"Contact\",\"id\":$CID}" >/dev/null
  python3 -c '
import json, sys
d = json.load(sys.stdin)["result"]
s = d.get("structuredContent") or {}
fv = (s.get("record") or s).get("fieldValues") or {}
print(json.dumps(fv.get(sys.argv[1])))' "$1" < "$TMP/r"
}

curl -s -m 2 -o /dev/null "$API/healthz" || { echo "start the server first"; exit 2; }
api GET /v1/saas/netsuite_quickstart > "$TMP/st"
[[ "$(J 'd["state"] == "connected" and d["tools_from_current_settings"] and d["permission_mode"] == "read_write"' < "$TMP/st")" == True ]] ||
  { echo "QuickStart must be Connected with a current tool list and a read-write token"; exit 2; }

bold "0. A test agent with a read-write NetSuite profile"
WA="qsv-write-$(date +%s)"
api POST /v1/agents "{\"agent_id\":\"$WA\",\"type\":\"erp_agent\",\"sponsor\":\"${QS_VERIFY_SPONSOR:-security@example.com}\"}" >/dev/null
api PUT "/v1/agents/$WA/access/netsuite" '{"profile":{"mode":"read_write","record_types":["contact"],"suiteql":false,"quickstart_tools":["create_record","read_record","update_record","delete_record","execute_record_action"]},"reason":"QuickStart write verification: Contact only"}' >/dev/null
W="$(api POST "/v1/agents/$WA/tokens" '{}' | J 'd["token"]')"
check "agent $WA: Contact records only, five tools" '[[ -n "$W" ]]'
sleep 5

bold "1. Create a test contact (held, approved, run once)"
CREATE='{"recordType":"Contact","fieldValues":{"firstName":"Fortik","lastName":"Verification - safe to delete"}}'
D="$(call create_record "$CREATE")"; H="$(aid)"
[[ "$D" == "hold False" ]] || stop "create_record was not held ($D)"
pass "create_record held, not executed ($D)"
check "approved ($(approve "$H"))" '[[ "$(code)" == 200 ]]'
D="$(call create_record "$CREATE")"
[[ "$D" == "allow True" ]] || stop "the approved create did not run ($D): $(J 'd["result"]["content"][0]["text"][:300]' < "$TMP/r")"
CID="$(python3 -c '
import json, sys
d = json.load(sys.stdin)["result"]
cands = [d.get("structuredContent") or {}]
for c in d.get("content", []):
    try: cands.append(json.loads(c.get("text", "")))
    except Exception: pass
for c in cands:
    if not isinstance(c, dict): continue
    for o in (c, c.get("record") or {}):
        if o.get("id") not in (None, ""):
            print(json.dumps(o["id"])); sys.exit()
' < "$TMP/r")"
[[ -n "$CID" ]] || stop "could not find the new contact's id in the result (keys: $(J 'list((d["result"].get("structuredContent") or {}).keys())' < "$TMP/r"))"
pass "created once: contact id $CID"
D="$(call create_record "$CREATE")"; DUP="$(aid)"
check "repeating the create is held again (the approval was used): $D" '[[ "$D" == "hold False" ]]'
api POST "/v1/held/$DUP/deny" '{"reason":"duplicate"}' >/dev/null

bold "2. Update its workEmail (held, approved, run once after a snapshot)"
BEFORE="$(field workEmail)"; say "workEmail before: $BEFORE"
UPD="{\"recordType\":\"Contact\",\"id\":$CID,\"fieldValues\":{\"workEmail\":\"fortik-verification@example.invalid\"}}"
D="$(call update_record "$UPD")"; H="$(aid)"
check "update_record held ($D), undo will be prepared" '[[ "$D" == "hold False" ]] && grep -q "undo: the changed fields are snapshotted" "$TMP/r"'
check "approved ($(approve "$H"))" '[[ "$(code)" == 200 ]]'
D="$(call update_record "$UPD")"; RAN="$(aid)"; UNDO="$(J 'd["result"]["_meta"].get("fortik/undo","")' < "$TMP/r")"
check "the approved update ran once ($D), undo $UNDO" '[[ "$D" == "allow True" && "$UNDO" == available ]]'
AFTER="$(field workEmail)"
check "QuickStart now has workEmail $AFTER" '[[ "$AFTER" == "\"fortik-verification@example.invalid\"" ]]'

bold "3. Undo"
api POST "/v1/undo/$RAN" '{"reason":"QuickStart write verification: undo"}' >/dev/null
check "undo ran ($(code))" '[[ "$(code)" == 200 ]]'
RESTORED="$(field workEmail)"
check "workEmail is back to $RESTORED (was $BEFORE)" '[[ "$RESTORED" == "$BEFORE" ]]'

bold "4. Delete is red: never run by Fortik"
D="$(call delete_record "{\"recordType\":\"Contact\",\"id\":$CID}")"; X="$(aid)"
C="$(approve "$X")"
check "delete_record held red ($D); an approval is refused ($C); the contact still exists" '[[ "$D" == "hold False" && "$C" != 200 && "$(field firstName)" == "\"Fortik\"" ]]'
api POST "/v1/held/$X/deny" '{"reason":"verification: deletes are done in QuickStart"}' >/dev/null

bold "5. Inactivate the test contact (record action: held, approved, run once)"
# The refused delete stepped the agent down to READ_ONLY (POL-1002): a new
# agent with the same narrow profile does the clean-up.
WA2="qsv-write2-$(date +%s)"
api POST /v1/agents "{\"agent_id\":\"$WA2\",\"type\":\"erp_agent\",\"sponsor\":\"${QS_VERIFY_SPONSOR:-security@example.com}\"}" >/dev/null
api PUT "/v1/agents/$WA2/access/netsuite" '{"profile":{"mode":"read_write","record_types":["contact"],"suiteql":false,"quickstart_tools":["read_record","execute_record_action"]},"reason":"QuickStart write verification: clean-up"}' >/dev/null
W="$(api POST "/v1/agents/$WA2/tokens" '{}' | J 'd["token"]')"; sleep 5
ACT="{\"recordType\":\"Contact\",\"id\":$CID,\"actionId\":\"inactivate\"}"
D="$(call execute_record_action "$ACT")"; H="$(aid)"
check "inactivate held ($D)" '[[ "$D" == "hold False" ]]'
check "approved ($(approve "$H"))" '[[ "$(code)" == 200 ]]'
D="$(call execute_record_action "$ACT")"
check "inactivate ran once ($D); the contact is inactive: $(field isInactive)" '[[ "$D" == "allow True" && "$(field isInactive)" == true ]]'

for a in "$WA" "$WA2"; do
  api DELETE "/v1/agents/$a/tokens" >/dev/null
  api PUT "/v1/agents/$a/level" '{"level":"KILLED","reason":"QuickStart verification agent: finished"}' >/dev/null
done
echo
say "Test contact id $CID (Fortik / Verification - safe to delete) is left INACTIVE. Delete it in QuickStart if you do not want to keep it."
if [ "$FAILED" = 0 ]; then printf '\033[32mALL CHECKS PASSED\033[0m: writes ran only after approval, once each; undo restored the field\n'; else printf '\033[31mSOME CHECKS FAILED\033[0m\n'; exit 1; fi
