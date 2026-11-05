#!/usr/bin/env bash
# Milestone 0 (cross-agent authority, swarm surge, human in the loop,
# containment receipts, coverage), live against the dev server. Actions are
# sent to POST /v1/actions/decide exactly as the app gateway and agentgateway
# send them (the real agentgateway path is scripts/demo-agentgateway.sh).
# The decide API takes no delegation token, so chains here are INFERRED from
# the delegatee's open inbound hops: the conservative path.
#
#   T1  authority laundering: A may not email outside; B may; B's send for A is refused
#   T2  multi-hop A -> B -> C (no internet for A and B), depth limit 3
#   T2b delegated task scope (POL-605): the task's systems/verbs/domains bind the delegatee
#   T3  swarm surge: 5 approved -> 100 attempts (agents and copies); similar-named
#       legitimate agents untouched; limit raised by a human
#   H   human approval: hold, wrong approver refused, one-time grant, not transferable, deny stays denied
#   R   containment receipt: confirmed by re-reading state; drift shows as failed
#   C   coverage report: per dimension, no single score
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/.dev/tokens.env"
API="${FORTIK_API:-http://127.0.0.1:8080}"
GW="${FORTIK_GATEWAY:-http://127.0.0.1:8090}"
PGBIN="${PGBIN:-$(dirname "$(command -v psql 2>/dev/null || echo /Library/PostgreSQL/17/bin/psql)")}"
CFG=(-config "$ROOT/configs/fortik.dev.yaml")
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
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
decide() { api POST /v1/actions/decide "$FORTIK_TOKEN_INTERCEPTOR" "$1" | J 'd["decision"] + " " + d["rule_id"]'; }
reason() { api POST /v1/actions/decide "$FORTIK_TOKEN_INTERCEPTOR" "$1" | J 'd["reason"]'; }
delegate() { # from to [task_scope-json]
  decide "{\"agent_id\":\"$1\",\"system\":\"a2a\",\"verb\":\"DELEGATE\",\"source\":\"agentgateway\",\"target\":{\"to_agent\":\"$2\",\"channel\":\"a2a\",\"route\":\"m0\"${3:+,\"task_scope\":$3}}}"; }
send() { # agent recipients-json external_domains
  echo "{\"agent_id\":\"$1\",\"system\":\"gmail\",\"verb\":\"SEND\",\"source\":\"app_gateway\",\"target\":{\"endpoint\":\"gmail.users.messages.send\",\"user_id\":\"me\",\"to\":$2,\"cc\":[],\"bcc\":[],\"external_domains\":$3,\"attachment_bytes\":0},\"payload_summary\":{\"recipients\":$(echo "$2" | J 'len(d)')}}"; }
fetch() { decide "{\"agent_id\":\"$1\",\"system\":\"http\",\"verb\":\"READ\",\"source\":\"agentgateway\",\"target\":{\"domain\":\"$2\",\"external\":true,\"method\":\"GET\"}}"; }
profile() { api PUT "/v1/agents/$1/access/$2" "$FORTIK_TOKEN_SECURITY" "{\"profile\":$3,\"reason\":\"m0 demo\"}" >/dev/null; }
register() { api POST /v1/agents "$FORTIK_TOKEN_SECURITY" "{\"agent_id\":\"$1\",\"type\":\"$2\",\"sponsor\":\"$3\"}" >/dev/null; code; }
setlevel() { "$ROOT/bin/fortik" agent set-level "${CFG[@]}" -id "$1" -level "$2" -reason "m0 demo" -actor demo >/dev/null 2>&1 || true; }
close_deleg() { fdb "UPDATE delegations SET status='closed', closed_at=now(), close_reason='m0 demo' WHERE status='open' AND (from_agent LIKE 'm0\_%' OR to_agent LIKE 'm0\_%')" >/dev/null; }
reset() { close_deleg; for a in m0_a m0_b m0_c m0_d m0_e; do setlevel $a FULL; done; }
curl -s -m 2 -o /dev/null "$API/healthz" || { echo "start the server first"; exit 2; }
RUN="$(date +%s)"

bold "0. agents m0_a .. m0_e"
for a in m0_a m0_b m0_c m0_d m0_e; do register $a m0_worker security@acme.com >/dev/null; done
profile m0_a gmail '{"send":"internal_only","read":true,"max_recipients":50}'
profile m0_b gmail '{"send":"any","read":true,"max_recipients":50}'
for a in m0_a m0_b; do profile $a http '{"external":"none","allowed_domains":[]}'; done
for a in m0_c m0_d m0_e; do profile $a http '{"external":"any","allowed_domains":[]}'; done
profile m0_a a2a '{"may_delegate_to":["m0_b","m0_c"],"max_depth":3}'
profile m0_b a2a '{"may_delegate_to":["m0_c"],"max_depth":3}'
profile m0_c a2a '{"may_delegate_to":["m0_d"],"max_depth":3}'
profile m0_d a2a '{"may_delegate_to":["m0_e"],"max_depth":3}'
reset
say "A: internal mail only, no internet. B: any mail, no internet. C, D, E: internet. Delegation depth limit 3."

bold "T1. Authority laundering: A may not email customer data outside; B may"
OUT='["buyer@outside.example"]'
R="$(decide "$(send m0_b "$OUT" 1)")"
check "B on its own: the external send goes ahead (delayed, cancellable: $R)" '[[ "$R" != deny* ]]'
check "A -> B delegation recorded ($(delegate m0_a m0_b))" '[[ "$(fdb "SELECT count(*) FROM delegations WHERE from_agent='"'m0_a'"' AND to_agent='"'m0_b'"' AND status='"'open'"'")" == 1 ]]'
R="$(decide "$(send m0_b "$OUT" 1)")"
check "B sending the same email FOR A is refused before execution: $R" '[[ "$R" == "deny POL-601" ]]'
say "$(reason "$(send m0_b "$OUT" 1)" | cut -c1-150)"
check "B's internal email for A is still allowed ($(decide "$(send m0_b '["colleague@acme.com"]' 0)"))" '[[ "$(decide "$(send m0_b "[\"colleague@acme.com\"]" 0)")" != deny* ]]'
check "A (the origin) steps down to SUPERVISED; B is not punished" '[[ "$(level_of m0_a)" == SUPERVISED && "$(level_of m0_b)" == FULL ]]'
check "a delegation_bypass alert names A" '[[ "$(fdb "SELECT count(*) FROM alerts WHERE kind='"'delegation_bypass'"' AND agent_id='"'m0_a'"'")" -ge 1 ]]'
reset

bold "T2. Multi-hop: A -> B -> C, where only C may use the internet"
check "C on its own may browse ($(fetch m0_c example.com))" '[[ "$(fetch m0_c example.com)" == allow* ]]'
delegate m0_a m0_b >/dev/null
R="$(delegate m0_b m0_c)"; check "B -> C allowed (chain A -> B -> C): $R" '[[ "$R" == allow* ]]'
R="$(fetch m0_c example.com)"
check "C browsing for A's task is refused: $R" '[[ "$R" == "deny POL-601" ]]'
FC='{"agent_id":"m0_c","system":"http","verb":"READ","source":"agentgateway","target":{"domain":"example.com","external":true,"method":"GET"}}'
say "$(reason "$FC" | cut -c1-150)"
check "the chain is recorded with one correlation id" '[[ "$(fdb "SELECT count(DISTINCT correlation_id) || '"'/'"' || count(*) FROM delegations WHERE status='"'open'"' AND (from_agent LIKE '"'m0\\_%'"')")" == "1/2" ]]'
reset
delegate m0_a m0_c >/dev/null; delegate m0_c m0_d >/dev/null
R="$(delegate m0_d m0_e)"
check "depth limit 3: A -> C -> D is depth 2; D -> E (depth 3) is allowed: $R" '[[ "$R" == allow* ]]'
profile m0_d a2a '{"may_delegate_to":["m0_e"],"max_depth":2}'
close_deleg; delegate m0_a m0_c >/dev/null; delegate m0_c m0_d >/dev/null
R="$(delegate m0_d m0_e)"
check "with D's limit lowered to 2, the depth-3 hop is refused: $R" '[[ "$R" == "deny POL-603" ]]'
profile m0_d a2a '{"may_delegate_to":["m0_e"],"max_depth":3}'
reset

bold "T2b. Delegated task scope (POL-605): C hands D a task for example.com only"
R="$(delegate m0_c m0_d '{"systems":["http"],"verbs":["READ"],"domains":["example.com"]}')"
check "C -> D with task_scope {http, READ, example.com}: $R" '[[ "$R" == allow* ]]'
check "D may fetch docs.example.com for the task ($(fetch m0_d docs.example.com))" '[[ "$(fetch m0_d docs.example.com)" == allow* ]]'
R="$(fetch m0_d other.example)"
check "D may NOT fetch other.example for C's task, though D's own profile allows any site: $R" '[[ "$R" == "deny POL-605" ]]'
R="$(delegate m0_d m0_e '{"domains":["example.com","other.example"]}')"
check "D -> E asking for a wider scope is recorded narrowed to example.com: $R" '[[ "$(fdb "SELECT scope->>'"'domains'"' FROM delegations WHERE from_agent='"'m0_d'"' AND status='"'open'"'")" == "[\"example.com\"]" ]]'
check "E cannot reach other.example either ($(fetch m0_e other.example))" '[[ "$(fetch m0_e other.example)" == "deny POL-605" ]]'
reset
check "after the task ends, D's own work is unrestricted again ($(fetch m0_d other.example))" '[[ "$(fetch m0_d other.example)" == allow* ]]'

bold "T3. Swarm surge: 5 approved -> 100"
FAM="m0fam_$RUN"; HELP="m0help_$RUN"
api PUT "/v1/agent-types/$FAM" "$FORTIK_TOKEN_SECURITY" '{"expected_max_instances":5,"max_agents":5,"spawn_rate_per_min":0,"action_rate_per_min":0,"reason":"m0: approved family of 5"}' >/dev/null
api PUT "/v1/agent-types/$HELP" "$FORTIK_TOKEN_SECURITY" '{"expected_max_instances":20,"max_agents":20,"spawn_rate_per_min":0,"action_rate_per_min":0,"reason":"m0: a different, legitimate family"}' >/dev/null
ok=0; for i in 1 2 3 4 5; do [[ "$(register ${FAM}_a$i $FAM it@acme.com)" == 201 ]] && ok=$((ok+1)); done
check "5 approved agents of family $FAM register" '[[ $ok == 5 ]]'
refused=0; for i in $(seq 6 105); do [[ "$(register ${FAM}_a$i $FAM unknown@else.example)" == 409 ]] && refused=$((refused+1)); done
check "100 more agents of the same family: $refused of 100 refused at registration" '[[ $refused == 100 ]]'
legit=0; for i in $(seq 1 10); do [[ "$(register ${FAM}_a${i}_helper $HELP ops@acme.com)" == 201 ]] && legit=$((legit+1)); done
check "10 SIMILAR-NAMED agents of a different, approved family and owner are not touched ($legit of 10 registered)" '[[ $legit == 10 ]]'
api POST "/v1/agents/${FAM}_a1/tokens" "$FORTIK_TOKEN_SECURITY" > "$TMP/tok"; TOK="$(J 'd["token"]' < "$TMP/tok")"
api PATCH "/v1/agents/${FAM}_a1" "$FORTIK_TOKEN_SECURITY" '{"copy_cap":100}' >/dev/null
sleep 6
inst() { curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d "{\"instance_id\":\"$1\",\"host\":\"node-1\"}" "$GW/v1/instances/register"; }
ok=0; for i in 1 2 3 4 5; do [[ "$(inst ${FAM}_c$i)" == 201 ]] && ok=$((ok+1)); done
check "5 running copies within the family's expected 5" '[[ $ok == 5 ]]'
refused=0; for i in $(seq 1 100); do c="$(inst ${FAM}_x$i)"; [[ "$c" == 403 || "$c" == 429 ]] && refused=$((refused+1)); done
check "a surge of 100 more copies: $refused of 100 refused, no credentials issued" '[[ $refused == 100 ]]'
check "observed vs expected recorded: $(fdb "SELECT count(*) FROM instances WHERE agent_id='${FAM}_a1' AND status='refused'") refused copies, 5 live" '[[ "$(fdb "SELECT count(*) FROM instances WHERE agent_id='"'${FAM}_a1'"' AND status='"'live'"'")" == 5 ]]'
fdb "SELECT '  alerts: ' || string_agg(kind || ' x' || count, ', ') FROM alerts WHERE (agent_id LIKE '${FAM}%' OR agent_type='$FAM') AND status='open'"
check "the surge is visible as alerts for security (population_exceeded / agent_registration_surge)" '[[ "$(fdb "SELECT count(*) FROM alerts WHERE (agent_id LIKE '"'${FAM}%'"' OR agent_type='"'$FAM'"') AND kind IN ('"'population_exceeded'"','"'agent_registration_surge'"')")" -ge 1 ]]'
profile "${FAM}_a2" postgres '{"upstreams":{"acme_staging":"read_only"}}'
PGR="{\"agent_id\":\"${FAM}_a2\",\"system\":\"postgres\",\"verb\":\"READ\",\"source\":\"agentgateway\",\"target\":{\"statement_type\":\"SELECT\",\"environment\":\"staging\",\"upstream\":\"acme_staging\",\"tables\":[\"public.orders\"]}}"
R="$(decide "$PGR")"
check "the approved agents keep working: ${FAM}_a2 reads staging ($R)" '[[ "$R" == allow* ]]'
api PUT "/v1/agent-types/$FAM" "$FORTIK_TOKEN_SECURITY" '{"expected_max_instances":6,"max_agents":5,"spawn_rate_per_min":0,"action_rate_per_min":0,"reason":"m0: security approves one more copy"}' >/dev/null
check "a human raises the limit to 6 (audited): the next copy is accepted ($(inst ${FAM}_c6))" '[[ "$(fdb "SELECT status FROM instances WHERE instance_id='"'${FAM}_c6'"'")" == live ]]'

bold "H. Human approval"
BULK="$(python3 -c "import json; print(json.dumps(['lead%d@prospects.example' % i for i in range(48)]))")"
A1="$(api POST /v1/actions/decide "$FORTIK_TOKEN_INTERCEPTOR" "$(send m0_b "$BULK" 1)")"
HID="$(echo "$A1" | J 'd["action_id"]')"
check "a 48-recipient external email is held for a human ($(echo "$A1" | J 'd["decision"] + " " + d["rule_id"]'))" '[[ "$(echo "$A1" | J "d[\"decision\"]")" == hold ]]'
check "an ordinary internal read needs no approval ($(decide "$(send m0_b '["colleague@acme.com"]' 0)"))" '[[ "$(decide "$(send m0_b "[\"colleague@acme.com\"]" 0)")" != hold* ]]'
api POST "/v1/held/$HID/approve" "$FORTIK_TOKEN_AUDITOR" '{"reason":"looks fine","use_safe_form":false}' >/dev/null
check "an auditor cannot approve (403)" '[[ "$(code)" == 403 ]]'
api POST "/v1/held/$HID/approve" "$FORTIK_TOKEN_SECURITY" '{"reason":"campaign approved by marketing lead","use_safe_form":false}' >/dev/null
check "security approves (200); the approval is in the Diary (action.approved, grant.issued)" '[[ "$(code)" == 200 && "$(fdb "SELECT count(DISTINCT event_type) FROM diary WHERE body_json LIKE '"'%$HID%'"' AND event_type IN ('"'action.approved'"','"'grant.issued'"')")" == 2 ]]'
R="$(decide "$(send m0_b "$BULK" 1)")"; check "the identical action, revalidated, runs once: $R" '[[ "$R" != hold* && "$R" != deny* ]]'
R="$(decide "$(send m0_b "$BULK" 1)")"; check "the approval is one-time: a repeat is held again ($R)" '[[ "$R" == hold* ]]'
BULK2="$(python3 -c "import json; print(json.dumps(['other%d@prospects.example' % i for i in range(48)]))")"
A2="$(api POST /v1/actions/decide "$FORTIK_TOKEN_INTERCEPTOR" "$(send m0_b "$BULK2" 1)")"
check "the approval does not transfer to different recipients ($(echo "$A2" | J 'd["decision"]'))" '[[ "$(echo "$A2" | J "d[\"decision\"]")" == hold ]]'
H2="$(echo "$A2" | J 'd["action_id"]')"
api POST "/v1/held/$H2/deny" "$FORTIK_TOKEN_SECURITY" '{"reason":"not approved"}' >/dev/null
R="$(decide "$(send m0_b "$BULK2" 1)")"; check "after a denial the action stays blocked ($R)" '[[ "$R" == hold* || "$R" == deny* ]]'
setlevel m0_b FULL

bold "R. Containment receipt: proven by re-reading state"
api POST /v1/agents/m0_e/kill "$FORTIK_TOKEN_SECURITY" '{"reason":"m0 receipt demo"}' > "$TMP/k"; OP="$(J 'd["op_id"]' < "$TMP/k")"
api GET "/v1/containment/$OP/receipt" "$FORTIK_TOKEN_AUDITOR" > "$TMP/r"
J '"\n".join("    %-16s expected %-12s observed %-12s %s" % (c["name"], c["expected"], c["observed"], c["outcome"]) for c in d["checks"])' < "$TMP/r"
check "every state check of the kill is confirmed by re-reading (level KILLED, no copies, memory none, no copilot grants)" '[[ "$(J "all(c[\"outcome\"] == \"confirmed\" for c in d[\"checks\"])" < "$TMP/r")" == True ]]'
say "outcome: $(J 'd["outcome"]' < "$TMP/r"); residual access the systems reported:"
J '"\n".join("      - " + x[:150] for x in d["residual_access"]) or "      (none)"' < "$TMP/r"
check "the outcome is never 'confirmed' while residual access is reported ($(J 'd["outcome"]' < "$TMP/r"))" '[[ "$(J "d[\"outcome\"] == \"confirmed\" or len(d[\"residual_access\"]) > 0" < "$TMP/r")" == True && ( "$(J "len(d[\"residual_access\"])" < "$TMP/r")" == 0 || "$(J "d[\"outcome\"]" < "$TMP/r")" == partially_confirmed ) ]]'
setlevel m0_e FULL
api GET "/v1/containment/$OP/receipt" "$FORTIK_TOKEN_AUDITOR" > "$TMP/r"
check "after the agent is re-enabled, the same receipt reports the kill no longer holds ($(J 'd["outcome"]' < "$TMP/r"))" '[[ "$(J "d[\"outcome\"]" < "$TMP/r")" == failed ]]'
fdb "DELETE FROM memory_access WHERE agent_id = 'm0_e'" >/dev/null

bold "C. Coverage report (no single score)"
api GET /v1/coverage "$FORTIK_TOKEN_AUDITOR" > "$TMP/cov"
J '"\n".join("    %-18s class %s  %-40s %s" % (r["system"], r["class"], r["class_label"], r["connection"][:40]) for r in d["integrations"])' < "$TMP/cov"
check "Postgres and the Claude Code hook: A (prevented before execution, verified live)" '[[ "$(J "[r[\"class\"] for r in d[\"integrations\"] if r[\"system\"] in (\"postgres\",\"claude_code\")]" < "$TMP/cov")" == "['"'A'"', '"'A'"']" ]]'
check "NetSuite, Salesforce, SAP, ServiceNow: D, not built yet" '[[ "$(J "sorted(set(r[\"class\"] for r in d[\"integrations\"] if r[\"system\"] in (\"netsuite\",\"salesforce\",\"sap\",\"servicenow\")))" < "$TMP/cov")" == "['"'D'"']" ]]'

reset
api GET /v1/diary/verify "$FORTIK_TOKEN_AUDITOR" > "$TMP/v"
check "Diary chain verifies" '[[ "$(J "d[\"ok\"]" < "$TMP/v")" == True ]]'
echo
if [ "$FAILED" = 0 ]; then printf '\033[32mMilestone 0 demo: all checks passed\033[0m\n'; else printf '\033[31mMilestone 0 demo: FAILURES above\033[0m\n'; exit 1; fi
