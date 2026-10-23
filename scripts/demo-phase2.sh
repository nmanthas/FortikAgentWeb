#!/usr/bin/env bash
# Phase 2 demo: the authority broker, access profiles, integrations, console
# login and the control ladder API, against the real running server.
#
# What it shows (each step asserts its expected outcome):
#   1. Console login (dev login) gives a session + CSRF token; roles are enforced.
#   2. Integrations: Postgres upstreams configured; Google/GitHub/AWS not yet
#      (you add those test accounts in the console). Secrets are never returned.
#   3. Agents get their own short-lived Postgres login role per session, with
#      only the privileges their access profile allows.
#   4. Access profiles are enforced by policy (POL-02x) AND by the database.
#   5. Gateway / broker: actions on unconfigured systems fail closed (503),
#      bad agent tokens are rejected (401), decisions are still recorded.
#   6. Level API: owner may step up one level, not two, and cannot kill;
#      security can kill, which revokes credentials on every system.
#   7. Owners may only narrow access; widening needs security.
#   8. Live events (SSE) and the Diary chain.
#
# Prereqs: scripts/dev-up.sh and `bin/fortik serve -config configs/fortik.dev.yaml`.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/.dev/tokens.env"
PGBIN="${PGBIN:-$(dirname "$(command -v psql 2>/dev/null || echo /Library/PostgreSQL/17/bin/psql)")}"
API="${FORTIK_API:-http://127.0.0.1:8080}"
GW="${FORTIK_GATEWAY:-http://127.0.0.1:8090}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
FAILED=0
bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILED=1; }
check() { if [[ "$1" == "$2" ]]; then pass "$3 ($1)"; else fail "$3: got '$1', want '$2'"; fi; }
J() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
CFG=(-config "$ROOT/configs/fortik.dev.yaml")

# login <name> <email>: cookie jar + csrf file per user
login() {
  curl -s -c "$TMP/$1.jar" -b "$TMP/$1.jar" -H 'Content-Type: application/json' -H "Origin: $API" \
    -d "{\"email\":\"$2\"}" "$API/auth/dev-login" >/dev/null
  curl -s -b "$TMP/$1.jar" "$API/v1/me" | J 'd["csrf"]' > "$TMP/$1.csrf"
}
# as <name> <method> <path> [json] -> body (status in $TMP/code)
as() {
  curl -s -o "$TMP/body" -w '%{http_code}' -b "$TMP/$1.jar" -X "$2" -H 'Content-Type: application/json' \
    -H "X-Fortik-CSRF: $(cat "$TMP/$1.csrf")" ${4:+-d "$4"} "$API$3" > "$TMP/code"; cat "$TMP/body"
}
code() { cat "$TMP/code"; }
agent_sql() { # agent token db sql
  PGPASSWORD="$2" "$PGBIN/psql" -h 127.0.0.1 -p 6432 -U "$1" -d "$3" -X -A -t -v ON_ERROR_STOP=1 -c "$4" 2>&1
}
upstream() { "$PGBIN/psql" -h 127.0.0.1 -p 55432 -U postgres -d "$1" -X -A -t -c "$2"; }

bold "0. reset demo agents to FULL"
for a in claude_code_01 finance_agent_07 text2sql_agent_03; do
  "$ROOT/bin/fortik" agent set-level "${CFG[@]}" -id $a -level FULL -reason "demo reset" -actor demo >/dev/null 2>&1 || true
done

bold "1. console login and roles"
login sec security@acme.com; login pranav pranav.kumar@acme.com; login aud auditor@acme.com
check "$(curl -s -b "$TMP/sec.jar" "$API/v1/me" | J '",".join(sorted(d["roles"]))')" "auditor,security" "security user session"
as aud PUT /v1/agents/claude_code_01/level '{"level":"KILLED","reason":"x"}' >/dev/null
check "$(code)" "403" "auditor cannot change levels"
curl -s -o /dev/null -w '%{http_code}' -b "$TMP/sec.jar" -X PUT -H 'Content-Type: application/json' \
  -d '{"level":"SUPERVISED","reason":"no csrf"}' "$API/v1/agents/claude_code_01/level" > "$TMP/code"
check "$(code)" "403" "cookie request without CSRF header refused"

bold "2. integrations (what you will fill in from the console)"
as sec GET /v1/integrations | J '"\n".join("  %-22s %s" % (i["key"], i["status"]) for i in d["integrations"])'
as sec GET /v1/integrations >/dev/null
grep -q "$(cat "$ROOT/.dev/secrets/fortik_broker_password")" "$TMP/body" && fail "secret value returned by API" || pass "secret values are never returned"
as sec POST /v1/integrations/postgres:acme_prod/test >/dev/null
check "$(J 'd["ok"]' < "$TMP/body")" "True" "live connection test of postgres:acme_prod"
# Later phases add schemas (queues, memory stores); Phase 2's four must be there.
check "$(as sec GET /v1/integrations/schema | J '",".join(s for s in ["google_workspace","github","aws","postgres"] if s in [x["system"] for x in d["schemas"]])')" "google_workspace,github,aws,postgres" "schemas for the Integrations screen"

bold "3. per-agent Postgres roles (short-lived, least privilege)"
out=$(agent_sql text2sql_agent_03 "$FORTIK_AGENT_TOKEN_TEXT2SQL_AGENT_03" acme_prod "SELECT current_user")
[[ "$out" == fortik_a_text2sql_agent_03_* ]] && pass "agent connected upstream as its own role: $out" || fail "upstream user: $out"
check "$(upstream acme_prod "SELECT string_agg(b.rolname, ',') FROM pg_auth_members m JOIN pg_roles a ON a.oid=m.member JOIN pg_roles b ON b.oid=m.roleid WHERE a.rolname='$out'")" "acme_read" "read_only profile -> member of acme_read only"
check "$(upstream acme_prod "SELECT rolvaliduntil > now() AND rolvaliduntil < now() + interval '16 minutes' FROM pg_roles WHERE rolname='$out'")" "t" "password valid for at most 15 minutes"

bold "4. access profiles enforced (policy + database)"
out=$(agent_sql text2sql_agent_03 "$FORTIK_AGENT_TOKEN_TEXT2SQL_AGENT_03" acme_prod "INSERT INTO audit_log (msg) VALUES ('x')" || true)
echo "$out" | grep -q "POL-021\|POL-026" && pass "read_only agent's write refused by policy: $(echo "$out" | grep -o 'POL-02[0-9]' | head -1)" || fail "$out"
out=$(agent_sql finance_agent_07 "$FORTIK_AGENT_TOKEN_FINANCE_AGENT_07" acme_staging "SELECT 1" || true)
echo "$out" | grep -qiE "POL-02|08004|no access to database|refused" && pass "upstream not in profile refused at connect: $(echo "$out" | grep -o 'has no access[^(]*' | head -1)" || fail "$out"

bold "5. gateway and broker: unconfigured systems fail closed"
gw() { curl -s -o "$TMP/gw" -w '%{http_code}' -H "Authorization: Bearer $1" -H 'Content-Type: application/json' -X "$2" ${4:+-d "$4"} "$GW$3"; }
check "$(gw nope GET /gw/github/repos/acme/api)" "401" "bad agent token rejected"
check "$(gw "$FORTIK_AGENT_TOKEN_CLAUDE_CODE_01" GET /gw/github/repos/acme/api)" "503" "GitHub call before the integration is configured"
check "$(J 'd["error"]["code"]' < "$TMP/gw")" "integration_not_configured" "clear error code"
check "$(gw "$FORTIK_AGENT_TOKEN_TEXT2SQL_AGENT_03" POST /v1/credentials/issue '{"system":"aws","aws":{"service":"s3","action":"GetObject","resource":"arn:aws:s3:::acme-reports/*"}}')" "503" "AWS credential before the integration is configured"
check "$(gw "$FORTIK_AGENT_TOKEN_TEXT2SQL_AGENT_03" POST /v1/credentials/issue '{"system":"aws","aws":{"service":"iam","action":"CreateAccessKey","resource":"*"}}')" "403" "AWS IAM write refused by policy even before configuration"
r=$(J 'd["error"]["rule_id"]' < "$TMP/gw"); [[ "$r" == POL-021 || "$r" == POL-025 ]] && pass "refused by the access profile ($r: read_only mode / iam denied)" || fail "rule $r"
check "$(gw "$FORTIK_AGENT_TOKEN_FINANCE_AGENT_07" POST /gw/google/gmail/v1/users/me/messages/send '{"raw":"VG86IGludmVzdG9yQHZlbnR1cmVmdW5kLmNvbQ0KU3ViamVjdDogUTEKDQpoaQ"}')" "503" "Gmail send before the integration is configured"

bold "6. control ladder API"
"$ROOT/bin/fortik" agent set-level "${CFG[@]}" -id claude_code_01 -level READ_ONLY -reason "demo setup" -actor demo >/dev/null
as pranav PUT /v1/agents/claude_code_01/level '{"level":"FULL","reason":"jump two"}' >/dev/null
check "$(code)" "403" "owner cannot step up two levels"
as pranav PUT /v1/agents/claude_code_01/level '{"level":"SUPERVISED","reason":"reviewed the incident"}' >/dev/null
check "$(code)" "200" "owner steps own agent up one level"
as pranav PUT /v1/agents/claude_code_01/level '{"level":"KILLED","reason":"x"}' >/dev/null
check "$(code)" "403" "owner cannot kill"
as pranav PUT /v1/agents/finance_agent_07/level '{"level":"READ_ONLY","reason":"not my agent"}' >/dev/null
check "$(code)" "403" "non-owner cannot change someone else's agent"
as sec PUT /v1/agents/text2sql_agent_03/level '{"level":"KILLED","reason":"demo kill"}' > "$TMP/kill"
check "$(code)" "200" "security kills text2sql_agent_03"
python3 -c "import json; d=json.load(open('$TMP/kill')); r=d.get('revocation') or d.get('revoked') or {}; [print('    revoke %-9s %s' % (k, v)) for k, v in sorted(r.items())]"
out=$(agent_sql text2sql_agent_03 "$FORTIK_AGENT_TOKEN_TEXT2SQL_AGENT_03" acme_prod "SELECT 1" || true)
echo "$out" | grep -qiE "POL-010|08004|KILLED|current control level" && pass "killed agent can no longer connect or act" || fail "$out"

bold "7. owners may only narrow access"
as pranav PUT /v1/agents/claude_code_01/access/github '{"profile":{"repos":["acme/api","acme/infra"],"permissions":{"contents":"write","pull_requests":"write","metadata":"read"}},"reason":"widen"}' >/dev/null
check "$(code)" "403" "owner widening refused"
as pranav PUT /v1/agents/claude_code_01/access/github '{"profile":{"repos":["acme/api"],"permissions":{"contents":"read","pull_requests":"write","metadata":"read"}},"reason":"narrow to read"}' >/dev/null
check "$(code)" "200" "owner narrowing accepted (new version)"
as sec PUT /v1/agents/claude_code_01/access/github '{"profile":{"repos":["acme/api"],"permissions":{"contents":"write","pull_requests":"write","metadata":"read"}},"reason":"restore"}' >/dev/null
check "$(code)" "200" "security may widen"

bold "8. live events and Diary"
curl -s -N -m 3 -b "$TMP/sec.jar" -H 'Last-Event-ID: 0' "$API/v1/events/stream" > "$TMP/sse" || true
n=$(grep -c '^event: diary' "$TMP/sse" || true)
[[ "$n" -gt 0 ]] && pass "SSE stream delivered $n Diary events" || fail "no SSE events"
check "$(as sec GET /v1/diary/verify | J 'd["ok"]')" "True" "Diary chain intact"

"$ROOT/bin/fortik" agent set-level "${CFG[@]}" -id text2sql_agent_03 -level FULL -reason "demo cleanup" -actor demo >/dev/null 2>&1 || true
echo
if [[ $FAILED == 0 ]]; then printf '\033[32mPhase 2 demo: ALL CHECKS PASSED\033[0m\n'; else printf '\033[31mPhase 2 demo: FAILURES\033[0m\n'; exit 1; fi
