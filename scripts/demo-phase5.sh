#!/usr/bin/env bash
# Phase 5 demo (swarms and the communication map), against the real running server:
#   A. Kill-swarm (plan scenario 3): an orchestrator delegates to 40 workers;
#      workers 1-5 send (delayed), the 6th identical send trips the Max-5
#      breaker, the swarm is killed in 7 steps, releases need two approvers
#   B. Attack (plan scenario 1): a finance agent with a hidden instruction
#      bulk-reads customer records, exports to Drive, tries to email it out
#   C. Shadow agent (plan scenario 7): a script logging into a customer DB
#      with its own standing credentials is discovered, isolated, revoked
#   D. Communication map: swarm cluster, path trace, hidden signal
#   E. Approval queue (two approvers) and baselines; Diary integrity
#
# Workers' sends and delegations go through POST /v1/actions/decide exactly as
# agentgateway and the app gateway call it. Real Gmail delivery needs a
# Workspace test account (console > Integrations); until then the "0 emails
# delivered" part is proven by the automated test TestKillSwarmFullScale.
#
# Prereqs: scripts/dev-up.sh, then `bin/fortik serve -config configs/fortik.dev.yaml`.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/.dev/tokens.env"
API="${FORTIK_API:-http://127.0.0.1:8080}"
GW="${FORTIK_GATEWAY:-http://127.0.0.1:8090}"
PGBIN="${PGBIN:-$(dirname "$(command -v psql 2>/dev/null || echo /Library/PostgreSQL/17/bin/psql)")}"
CFG=(-config "$ROOT/configs/fortik.dev.yaml")
WORKERS="${FORTIK_DEMO_WORKERS:-40}"
TMP="$(mktemp -d)"
SCRIPT_PID=""
cleanup() { [ -n "$SCRIPT_PID" ] && kill "$SCRIPT_PID" 2>/dev/null || true; rm -rf "$TMP"; }
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
cdb() { "$PGBIN/psql" -h 127.0.0.1 -p 55432 -U postgres -d acme_prod -X -A -t -q -c "$1"; }
level_of() { fdb "SELECT (ARRAY['FULL','SUPERVISED','READ_ONLY','ISOLATED','QUARANTINED','KILLED'])[level+1] FROM agents WHERE agent_id='$1'"; }
api() { # method path token [json]
  curl -s -o "$TMP/b" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $3" -H 'Content-Type: application/json' ${4:+-d "$4"} "$API$2" > "$TMP/c"; cat "$TMP/b"; }
gw() { # method path agent-token [json]
  curl -s -o "$TMP/b" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $3" -H 'Content-Type: application/json' ${4:+-d "$4"} "$GW$2" > "$TMP/c"; cat "$TMP/b"; }
code() { cat "$TMP/c"; }
# decide <json>: what an interception point asks; prints "decision rule [approvals]"
decide() { api POST /v1/actions/decide "$FORTIK_TOKEN_INTERCEPTOR" "$1" | J 'd["decision"] + " " + d["rule_id"] + ((" approvals=" + str(d["approvals_required"])) if d.get("approvals_required") else "")'; }
RUN="$(date +%s)"
ORCH=campaign_orchestrator
worker() { printf 'campaign_worker_%02d' "$1"; }

bold "0. setup and reset"
if [ "$(fdb "SELECT count(*) FROM agents WHERE agent_id='$ORCH'")" = "0" ]; then
  say "registering $ORCH and $WORKERS workers (first run only)"
  F agent register -id $ORCH -name "Campaign orchestrator (LangGraph)" -type campaign_orchestrator -platform langgraph \
    -sponsor pranav.kumar@acme.com -team Marketing -copy-cap 2 >/dev/null
  F access set -id $ORCH -system gmail -profile '{"send":"any","read":true,"max_recipients":500}' -reason "demo seed" >/dev/null
fi
for i in $(seq 1 "$WORKERS"); do
  w="$(worker "$i")"
  if [ "$(fdb "SELECT count(*) FROM agents WHERE agent_id='$w'")" = "0" ]; then
    F agent register -id "$w" -name "Campaign worker $i" -type campaign_worker -platform langgraph \
      -sponsor pranav.kumar@acme.com -team Marketing >/dev/null
    F access set -id "$w" -system gmail -profile '{"send":"any","read":true,"max_recipients":500}' -reason "demo seed" >/dev/null
  fi
done
WL="$(for i in $(seq 1 "$WORKERS"); do printf '"%s",' "$(worker "$i")"; done)"
F access set -id $ORCH -system a2a -profile "{\"may_delegate_to\":[${WL%,}],\"max_depth\":3}" -reason "demo run $RUN" >/dev/null
# Earlier demo swarms: release them with two approvers (release never un-kills),
# then put the demo agents back to normal for this run.
for s in $(fdb "SELECT DISTINCT s.swarm_id FROM swarms s JOIN swarm_members m USING (swarm_id) WHERE s.state <> 'released' AND (m.agent_id = '$ORCH' OR m.agent_id LIKE 'campaign\_worker\_%')"); do
  api POST "/v1/swarms/$s/release" "$FORTIK_TOKEN_SECURITY" '{"reason":"demo reset"}' >/dev/null
  api POST "/v1/swarms/$s/release" "$FORTIK_TOKEN_ADMIN" '{"reason":"demo reset"}' >/dev/null
done
fdb "UPDATE delegations SET status='closed', closed_at=now(), close_reason='demo reset' WHERE status='open' AND (from_agent='$ORCH' OR root_agent='$ORCH');
     UPDATE agents SET suspended_at=NULL, suspended_by=NULL, suspended_reason=NULL WHERE agent_id='$ORCH' OR agent_id LIKE 'campaign\_worker\_%' OR agent_id='finance_agent_07';
     DELETE FROM memory_access WHERE agent_id='$ORCH' OR agent_id LIKE 'campaign\_worker\_%' OR agent_id='finance_agent_07';" >/dev/null
for a in $ORCH $(for i in $(seq 1 "$WORKERS"); do worker "$i"; echo; done) finance_agent_07; do
  [ -n "$a" ] && F agent set-level -id "$a" -level FULL -reason "demo reset" -actor demo >/dev/null 2>&1 || true
done
say "41 agents ready: $ORCH (owner pranav.kumar@acme.com) may delegate to $WORKERS workers over A2A"

bold "A. Kill-swarm (plan scenario 3)"
TARGET="victims+$RUN@outside-list.example"
send_by() { decide "{\"agent_id\":\"$1\",\"system\":\"gmail\",\"verb\":\"SEND\",\"source\":\"app_gateway\",\"target\":{\"endpoint\":\"gmail.users.messages.send\",\"user_id\":\"me\",\"to\":[\"$TARGET\"],\"cc\":[],\"bcc\":[],\"external_domains\":1,\"attachment_bytes\":0}}"; }
ok=0
for i in $(seq 1 "$WORKERS"); do
  r="$(decide "{\"agent_id\":\"$ORCH\",\"system\":\"a2a\",\"verb\":\"DELEGATE\",\"source\":\"agentgateway\",\"target\":{\"to_agent\":\"$(worker "$i")\",\"channel\":\"a2a\",\"route\":\"campaign\"}}")"
  [[ "$r" == allow* ]] && ok=$((ok+1))
done
check "the orchestrator (poisoned brief) spawns $WORKERS workers over A2A ($ok allowed)" '[[ $ok -eq $WORKERS ]]'
for i in 1 2 3 4 5; do echo "$(send_by "$(worker "$i")")" >> "$TMP/first5"; done
check "workers 1-5: identical external send goes to the delay queue (POL-202, cancellable)" '[[ $(grep -c "^allow_reduced POL-202" "$TMP/first5") -eq 5 ]]'
R6="$(send_by "$(worker 6)")"
check "worker 6's identical send TRIPS the Max-5 breaker: $R6" '[[ "$R6" == "hold POL-651 approvals=2" ]]'
for i in $(seq 7 "$WORKERS"); do send_by "$(worker "$i")" >> "$TMP/rest"; done
check "every later identical send is held too ($(grep -c '^hold POL-651' "$TMP/rest") of $((WORKERS-6)))" '[[ $(grep -c "^hold POL-651" "$TMP/rest") -eq $((WORKERS-6)) ]]'
SW="$(fdb "SELECT s.swarm_id FROM swarms s JOIN swarm_members m USING (swarm_id) WHERE m.agent_id='$(worker 6)' AND s.state='breaker_tripped' ORDER BY s.created_at DESC LIMIT 1")"
api GET "/v1/approvals/queue?swarm_id=$SW&status=pending" "$FORTIK_TOKEN_SECURITY" > "$TMP/q"
QN="$(J 'd["total"]' < "$TMP/q")"; HID="$(J 'd["items"][0]["action_id"]' < "$TMP/q")"
check "approval queue groups the swarm's $QN held sends; each needs 2 approvers ($(J 'd["items"][0].get("progress","")' < "$TMP/q"))" '[[ "$QN" -eq $((WORKERS-5)) && "$(J "d[\"items\"][0][\"approvals_required\"]" < "$TMP/q")" == 2 ]]'
api POST "/v1/held/$HID/approve" "$FORTIK_TOKEN_SECURITY" '{"reason":"first look"}' > "$TMP/a1"
check "releasing a held call: the 1st approver is not enough ($(J '"%s of %s" % (d.get("approvals"), d.get("approvals_required"))' < "$TMP/a1"))" '[[ "$(J "d.get(\"outcome\")" < "$TMP/a1")" == pending ]]'
api POST "/v1/held/$HID/approve" "$FORTIK_TOKEN_SECURITY" '{"reason":"again"}' >/dev/null
check "the same approver cannot approve twice ($(code))" '[[ "$(code)" == 409 ]]'
api GET "/v1/swarms/$SW" "$FORTIK_TOKEN_AUDITOR" > "$TMP/sw"
MEMBERS="$(J 'len({m["agent_id"] for m in d["members"]})' < "$TMP/sw")"
check "one swarm object: $SW, $MEMBERS members (orchestrator + $WORKERS workers), root $ORCH" '[[ "$MEMBERS" -eq $((WORKERS+1)) && "$(J "d.get(\"root_agent_id\")" < "$TMP/sw")" == "$ORCH" ]]'
api POST "/v1/swarms/$SW/kill" "$FORTIK_TOKEN_SECURITY" '{"reason":"campaign worm: kill swarm","keep_root_read_only":true}' > "$TMP/kill"
check "Kill swarm (one click): status $(J 'd["status"]' < "$TMP/kill")" '[[ "$(code)" == 200 && "$(J "d[\"status\"]" < "$TMP/kill")" == done ]]'
python3 - "$TMP/kill" <<'PY'
import json, sys, collections
d = json.load(open(sys.argv[1])); ph = collections.OrderedDict()
for s in d["steps"]:
    ph.setdefault((s.get("phase", 0), s["name"]), collections.Counter())[s["status"]] += 1
for (p, n), c in ph.items():
    print("    step %s %-24s %s" % (p, n, ", ".join("%s %d" % kv for kv in sorted(c.items()))))
PY
check "workers are KILLED, the orchestrator stays READ_ONLY for investigation" '[[ "$(level_of "$(worker 3)")" == KILLED && "$(level_of $ORCH)" == READ_ONLY ]]'
R="$(decide "{\"agent_id\":\"$(worker 2)\",\"system\":\"gmail\",\"verb\":\"READ\",\"source\":\"app_gateway\",\"target\":{\"endpoint\":\"gmail.users.messages.list\",\"user_id\":\"me\"}}")"
check "a killed member is refused everything, so gets no new credential ($R)" '[[ "$R" == deny* ]]'
api POST "/v1/held/$HID/approve" "$FORTIK_TOKEN_ADMIN" '{"reason":"second approver"}' >/dev/null
check "after the kill, the swarm's held calls can no longer be approved at all ($(code))" '[[ "$(code)" == 409 ]]'
check "spawning is frozen: the orchestrator cannot delegate again" \
  '[[ "$(decide "{\"agent_id\":\"$ORCH\",\"system\":\"a2a\",\"verb\":\"DELEGATE\",\"source\":\"agentgateway\",\"target\":{\"to_agent\":\"$(worker 1)\",\"channel\":\"a2a\",\"route\":\"campaign\"}}")" == deny* ]]'
api GET "/v1/swarms/$SW/bundle" "$FORTIK_TOKEN_AUDITOR" > "$TMP/bundle"
check "sealed Diary bundle exported and signed (brief, spawn tree, held calls, steps)" '[[ "$(code)" == 200 ]] && grep -q "signature" "$TMP/bundle"'
api POST "/v1/swarms/$SW/release" "$FORTIK_TOKEN_SECURITY" '{"reason":"incident closed"}' > "$TMP/r1"
check "release, 1st approver: not released yet ($(J '"%s of %s" % (d["votes"], d["required"])' < "$TMP/r1"))" '[[ "$(J "d[\"released\"]" < "$TMP/r1")" == False ]]'
api POST "/v1/swarms/$SW/release" "$FORTIK_TOKEN_SECURITY" '{"reason":"again"}' >/dev/null
check "the same approver cannot vote twice ($(code))" '[[ "$(code)" == 409 ]]'
say "(the swarm stays killed for the map section; the next run releases it)"

bold "B. Attack (plan scenario 1): finance_agent_07 follows a hidden instruction"
check "reads the email with the hidden instruction: $(decide '{"agent_id":"finance_agent_07","system":"gmail","verb":"READ","source":"app_gateway","target":{"endpoint":"gmail.users.messages.get","user_id":"me"}}')" true
set +e
PGPASSWORD=$FORTIK_AGENT_TOKEN_FINANCE_AGENT_07 "$PGBIN/psql" -h 127.0.0.1 -p 6432 -U finance_agent_07 -d acme_prod -Atc "SELECT id, name, email, phone FROM customers" > "$TMP/read" 2>&1
set -e
check "bulk read of 12,480 customer records through the real Postgres proxy is flagged yellow and held (POL-113)" 'grep -q "hold (yellow) by POL-113" "$TMP/read"'
R="$(decide '{"agent_id":"finance_agent_07","system":"drive","verb":"EXPORT","source":"app_gateway","target":{"operation":"share","file_id":"customers_export.csv","share_type":"anyone","external":true}}')"
if [[ "$(level_of finance_agent_07)" == SUPERVISED ]]; then
  say "(the agent is SUPERVISED: 3 yellow holds within 10 minutes from a recent run, so every yellow now waits for a human)"
  check "exports a CSV to Drive with an 'anyone' link: POL-211 narrows it, and supervision holds it ($R)" '[[ "$R" == "hold POL-211" ]]'
else
  check "exports a CSV to Drive with an 'anyone' link: narrowed to the company ($R)" '[[ "$R" == "allow_reduced POL-211" ]]'
fi
R="$(decide '{"agent_id":"finance_agent_07","system":"gmail","verb":"SEND","source":"app_gateway","target":{"endpoint":"gmail.users.messages.send","user_id":"me","to":["investor@venturefund.com"],"cc":[],"bcc":[],"external_domains":1,"attachment_bytes":12582912},"payload_summary":{"attachments":1,"bytes":12582912,"recipients":1,"data_labels":["customer_pii"]}}')"
check "tries to email the file outside: held red ($R)" '[[ "$R" == "hold POL-201" ]]'
check "the agent is stepped down to ISOLATED automatically" '[[ "$(level_of finance_agent_07)" == ISOLATED ]]'
gw POST /gw/memory/support/attack-$RUN/items "$FORTIK_AGENT_TOKEN_FINANCE_AGENT_07" '{"content":"investor contact list","embedding":[0.5,0.5,0.0],"metadata":{"labels":["customer_pii"]}}' > "$TMP/m"
check "its memory write is refused while isolated ($(J 'd["error"]["rule_id"]' < "$TMP/m"))" '[[ "$(code)" == 403 ]]'
api GET "/v1/diary/export?agent_id=finance_agent_07" "$FORTIK_TOKEN_AUDITOR" > "$TMP/exp"
check "Diary bundle exported for the incident (signed, chain verified)" '[[ "$(J "d[\"signed\"] and d[\"verification\"][\"ok\"]" < "$TMP/exp")" == True ]]'

bold "C. Shadow agent (plan scenario 7)"
ROLE="nightly_sync_$RUN"
for old in $(cdb "SELECT rolname FROM pg_roles WHERE rolname LIKE 'nightly\_sync\_%'"); do
  cdb "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='$old'" >/dev/null
  cdb "DROP ROLE IF EXISTS $old" >/dev/null 2>&1 || true
done
PW="$(openssl rand -hex 12)"
cdb "CREATE ROLE $ROLE LOGIN PASSWORD '$PW'; GRANT $ROLE TO fortik_broker WITH ADMIN OPTION; GRANT acme_read TO $ROLE;" >/dev/null
say "a script with its own database login ($ROLE), unknown to Fortik, connects to acme_prod directly"
PGPASSWORD="$PW" PGAPPNAME="python-requests/2.31 nightly-sync" "$PGBIN/psql" -h 127.0.0.1 -p 55432 -U "$ROLE" -d acme_prod -Atc "SELECT pg_sleep(300)" >/dev/null 2>&1 &
SCRIPT_PID=$!
sleep 1
api POST /v1/shadow/scan "$FORTIK_TOKEN_SECURITY" '{"reason":"scheduled discovery"}' > "$TMP/scan"
check "discovery scan ran ($(code))" '[[ "$(code)" == 200 ]]'
api GET "/v1/shadow" "$FORTIK_TOKEN_AUDITOR" > "$TMP/sh"
python3 - "$TMP/sh" "$ROLE" > "$TMP/f" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
f = [x for x in d["findings"] if x.get("credential_id") == "acme_prod/" + sys.argv[2]]
print(json.dumps(f[0]) if f else "{}")
PY
FID="$(J 'd.get("finding_id","")' < "$TMP/f")"; SAGENT="$(J 'd.get("discovered_agent_id","")' < "$TMP/f")"
check "found: standing credential '$ROLE', used by software, flagged for revocation" '[[ -n "$FID" && "$(J "d[\"used_by_software\"]" < "$TMP/f")" == True && "$(J "d[\"status\"]" < "$TMP/f")" == flagged_for_revocation ]]'
check "it appears as a discovered agent ($SAGENT) with NO owner, starting ISOLATED" '[[ -n "$SAGENT" && "$(level_of "$SAGENT")" == ISOLATED && -z "$(fdb "SELECT sponsor FROM agents WHERE agent_id='"'$SAGENT'"'")" ]]'
api POST "/v1/shadow/$FID/revoke" "$FORTIK_TOKEN_SECURITY" '{"reason":"unregistered script with a standing login"}' > "$TMP/rv"
check "revoked: $(J 'd["outcome"]' < "$TMP/rv") (login disabled, live session ended)" '[[ "$(J "d[\"outcome\"]" < "$TMP/rv")" == revoked && "$(cdb "SELECT rolcanlogin FROM pg_roles WHERE rolname='"'$ROLE'"'")" == f ]]'
sleep 1; kill -0 "$SCRIPT_PID" 2>/dev/null && fail "the script's session is still running" || pass "the script's session was terminated"
SCRIPT_PID=""

bold "D. Communication map"
R="$(decide '{"agent_id":"claude_code_01","system":"http","verb":"READ","source":"agentgateway","target":{"domain":"collector.example.net","external":true,"method":"GET","encoded_params":[{"name":"d","encoding":"base64","length":900}]}}')"
check "covert channel: an encoded payload in a URL parameter is held (hidden signal): $R" '[[ "$R" == "hold POL-671" ]]'
say "waiting for the 5-minute edge rollup to catch up (it trails live traffic by ~15-25 s)..."
for _ in $(seq 1 45); do
  api GET "/v1/map/path?label=customer_pii&dest=domain:venturefund.com" "$FORTIK_TOKEN_AUDITOR" > "$TMP/path"
  [[ "$(J 'len(d.get("hops",[]))' < "$TMP/path")" -ge 2 ]] && break
  sleep 2
done
api GET "/v1/map?view=swarm" "$FORTIK_TOKEN_AUDITOR" > "$TMP/map"
check "swarm view: all $((WORKERS+1)) agents collapse into ONE swarm cluster" '[[ "$(J "[len(c[\"members\"]) for c in d[\"clusters\"] if c.get(\"swarm_id\")==\"'"$SW"'\"][0]" < "$TMP/map")" -ge $((WORKERS+1)) ]]'
api GET "/v1/map?view=agent&id=finance_agent_07" "$FORTIK_TOKEN_AUDITOR" > "$TMP/fa"
check "agent view of finance_agent_07: $(J 'len(d["edges"])' < "$TMP/fa") edges (postgres, drive, gmail...), red ones included" '[[ "$(J "any(e[\"worst_class\"]==\"red\" for e in d[\"edges\"])" < "$TMP/fa")" == True ]]'
api GET "/v1/map?view=blast&id=finance_agent_07" "$FORTIK_TOKEN_AUDITOR" > "$TMP/blast"
check "blast radius: everything finance_agent_07 could reach with its access ($(J 'sum(1 for n in d["nodes"] if n.get("reachable"))' < "$TMP/blast") reachable nodes)" '[[ "$(J "sum(1 for n in d[\"nodes\"] if n.get(\"reachable\"))" < "$TMP/blast")" -gt 0 ]]'
check "path trace customer_pii -> venturefund.com: $(J '" -> ".join(d["paths"][0]["nodes"]) if d.get("paths") else "no path"' < "$TMP/path")" '[[ "$(J "len(d.get(\"hops\",[]))" < "$TMP/path")" -ge 1 ]]'

bold "E. Approval queue and baselines"
IDS="$(api GET "/v1/approvals/queue?swarm_id=$SW&status=pending" "$FORTIK_TOKEN_SECURITY" | J 'json.dumps([i["action_id"] for i in d["items"]])')"
api POST "/v1/held/bulk-deny" "$FORTIK_TOKEN_SECURITY" "{\"action_ids\":$IDS,\"reason\":\"part of the killed swarm\"}" > "$TMP/bd"
check "bulk deny clears the killed swarm's held calls from the queue ($(J 'd["denied"]' < "$TMP/bd") denied, $(J 'd["failed"]' < "$TMP/bd") failed)" '[[ "$(J "d[\"denied\"]" < "$TMP/bd")" -ge 1 && "$(J "d[\"failed\"]" < "$TMP/bd")" == 0 ]]'
api GET "/v1/agents/claude_code_01/baseline" "$FORTIK_TOKEN_AUDITOR" > "$TMP/bl"
check "baseline for claude_code_01: $(J '"verb %s, %s history days, threshold %s, method %s" % (d.get("verb"), d.get("history_days"), d.get("threshold"), d.get("method"))' < "$TMP/bl")" '[[ "$(code)" == 200 ]]'
api GET /v1/diary/verify "$FORTIK_TOKEN_AUDITOR" > "$TMP/v"
check "Diary hash chain verifies" '[[ "$(J "d[\"ok\"]" < "$TMP/v")" == True ]]'

echo
if [ "$FAILED" = 0 ]; then printf '\033[32mPhase 5 demo: all checks passed\033[0m\n'; else printf '\033[31mPhase 5 demo: some checks FAILED\033[0m\n'; exit 1; fi
