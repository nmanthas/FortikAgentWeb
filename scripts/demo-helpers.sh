# Presenter helpers for the live investor demo (docs/DEMO_GUIDE.md).
# Source from the repo root, in bash or zsh, after scripts/dev-up.sh:
#
#     cd ~/FortikAgentWeb && source scripts/demo-helpers.sh
#
# DEV ONLY: they use the dev tokens in .dev/tokens.env and the local dev
# database. They never print a token. Every helper only wraps a documented
# API call, the agent's psql through Fortik's proxy, or the real hook client.

FORTIK_ROOT="${FORTIK_ROOT:-$PWD}"
if [ ! -f "$FORTIK_ROOT/.dev/tokens.env" ]; then
  echo "demo-helpers: run from the repo root after ./scripts/dev-up.sh (.dev/tokens.env not found)" >&2
  return 1 2>/dev/null || exit 1
fi
. "$FORTIK_ROOT/.dev/tokens.env"
API="${FORTIK_API:-http://127.0.0.1:8080}"
GW="${FORTIK_GATEWAY:-http://127.0.0.1:8090}"
PSQL="$(command -v psql 2>/dev/null || echo /Library/PostgreSQL/17/bin/psql)"
FK_CFG="$FORTIK_ROOT/configs/fortik.dev.yaml"
FK_TMP="$(mktemp -d "${TMPDIR:-/tmp}/fortik-demo.XXXXXX")"

# _fk_req <base-url> <METHOD> <path> <token> [json]: pretty body, then "HTTP <code>"
_fk_req() {
  _fk_out="$FK_TMP/body"
  if [ -n "${5:-}" ]; then
    _fk_code=$(curl -s -o "$_fk_out" -w '%{http_code}' -X "$2" -H "Authorization: Bearer $4" -H 'Content-Type: application/json' -d "$5" "$1$3")
  else
    _fk_code=$(curl -s -o "$_fk_out" -w '%{http_code}' -X "$2" -H "Authorization: Bearer $4" "$1$3")
  fi
  python3 -m json.tool < "$_fk_out" 2>/dev/null || cat "$_fk_out"
  echo "HTTP $_fk_code"
}
# fk_api <METHOD> <path> <token> [json]   control-plane API (:8080)
fk_api() { _fk_req "$API" "$@"; }
# fk_gw <METHOD> <path> <agent-token> [json]   agent-facing gateway (:8090)
fk_gw() { _fk_req "$GW" "$@"; }

# _fk_agent_token <agent_id>: the agent's dev token (never printed)
_fk_agent_token() {
  _fk_var="FORTIK_AGENT_TOKEN_$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')"
  case "$_fk_var" in *[!A-Z0-9_]*) echo "bad agent id: $1" >&2; return 1 ;; esac
  eval "_fk_tok=\${$_fk_var:-}"
  [ -n "$_fk_tok" ] || { echo "no dev token for $1 (\$$_fk_var)" >&2; return 1; }
}

# fk_psql <agent_id> <database> <sql>: the agent's psql THROUGH Fortik's Postgres proxy (:6432)
fk_psql() {
  _fk_agent_token "$1" || return 1
  PGPASSWORD="$_fk_tok" "$PSQL" -h 127.0.0.1 -p 6432 -U "$1" -d "$2" -X -c "$3"
}

# fk_db <database> <sql>: the presenter's ADMIN view of the dev database. It
# bypasses Fortik on purpose, only to show what really happened.
fk_db() { "$PSQL" -h 127.0.0.1 -p 55432 -U postgres -d "$1" -X -c "$2"; }

# fk_level <agent_id>: control level and suspension
fk_level() {
  fk_db fortik "SELECT agent_id, (ARRAY['FULL','SUPERVISED','READ_ONLY','ISOLATED','QUARANTINED','KILLED'])[level+1] AS level, suspended_at IS NOT NULL AS suspended FROM agents WHERE agent_id = '$1'"
}

# fk_set_level <agent_id> <LEVEL> [reason]: audited CLI (writes a Diary entry)
fk_set_level() {
  "$FORTIK_ROOT/bin/fortik" agent set-level -config "$FK_CFG" -id "$1" -level "$2" -reason "${3:-investor demo}" -actor presenter
}

# fk_hook <agent_id> <ToolName> <tool_input-json>: run the REAL Claude Code
# PreToolUse hook client exactly as Claude Code does. Exit 0 = allowed, 2 = blocked.
fk_hook() {
  _fk_agent_token "$1" || return 1
  python3 -c 'import json, sys; print(json.dumps({"session_id": "investor-demo", "transcript_path": "/tmp/investor-demo", "cwd": sys.argv[1], "permission_mode": "default", "hook_event_name": "PreToolUse", "tool_use_id": "tu_" + sys.argv[4], "tool_name": sys.argv[2], "tool_input": json.loads(sys.argv[3])}))' \
    "$FORTIK_ROOT" "$2" "$3" "$RANDOM$RANDOM" > "$FK_TMP/event" || { echo "tool_input is not valid JSON" >&2; return 1; }
  FORTIK_GATEWAY_URL="${FK_HOOK_URL:-$GW}" FORTIK_AGENT_TOKEN="$_fk_tok" "$FORTIK_ROOT/bin/fortik" hook claude-code < "$FK_TMP/event"
  _fk_rc=$?
  case $_fk_rc in
    0) echo "-> hook exit 0: ALLOWED" ;;
    2) echo "-> hook exit 2: BLOCKED (Claude Code will not run the tool)" ;;
    *) echo "-> hook exit $_fk_rc" ;;
  esac
  return $_fk_rc
}

# fk_decide <json>: ask Decide exactly as an interception point does
# (agentgateway / app gateway), using the dev interceptor token.
fk_decide() {
  curl -s -X POST -H "Authorization: Bearer $FORTIK_TOKEN_INTERCEPTOR" -H 'Content-Type: application/json' -d "$1" "$API/v1/actions/decide" |
    python3 -c 'import json, sys
d = json.load(sys.stdin)
if "decision" in d: print("decision=%s class=%s rule=%s\nreason: %s" % (d["decision"], d.get("class"), d.get("rule_id"), d.get("reason")))
else: print(json.dumps(d, indent=2))'
}

# fk_delegate <from_agent> <to_agent>: an A2A delegation, reported the way
# agentgateway's callout reports it (agentgateway itself is not running in dev).
fk_delegate() {
  fk_decide "{\"agent_id\":\"$1\",\"system\":\"a2a\",\"verb\":\"DELEGATE\",\"source\":\"agentgateway\",\"target\":{\"to_agent\":\"$2\",\"channel\":\"a2a\",\"route\":\"demo\"}}"
}

# fk_login <name> <email>: console session (dev login) with its CSRF token
fk_login() {
  curl -s -c "$FK_TMP/$1.jar" -b "$FK_TMP/$1.jar" -H 'Content-Type: application/json' -H "Origin: $API" \
    -d "{\"email\":\"$2\"}" "$API/auth/dev-login" > /dev/null
  curl -s -b "$FK_TMP/$1.jar" "$API/v1/me" | python3 -c 'import json, sys; d = json.load(sys.stdin); open(sys.argv[1], "w").write(d["csrf"]); print("logged in:", d.get("email"), "roles:", ",".join(d.get("roles", [])))' "$FK_TMP/$1.csrf"
}
# fk_as <name> <METHOD> <path> [json]: a request as that console user
fk_as() {
  _fk_out="$FK_TMP/body"
  _fk_code=$(curl -s -o "$_fk_out" -w '%{http_code}' -b "$FK_TMP/$1.jar" -X "$2" -H 'Content-Type: application/json' \
    -H "X-Fortik-CSRF: $(cat "$FK_TMP/$1.csrf")" ${4:+-d} ${4:+"$4"} "$API$3")
  python3 -m json.tool < "$_fk_out" 2>/dev/null || cat "$_fk_out"
  echo "HTTP $_fk_code"
}

# fk_check: services up, and which dev token variables are set (values never printed)
fk_check() {
  for u in "$API/healthz" "$API/readyz" "$GW/healthz"; do
    printf '%-36s %s\n' "$u" "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$u")"
  done
  "$PSQL" -h 127.0.0.1 -p 55432 -U postgres -d fortik -X -A -t -c "SELECT 'fortik database: ' || count(*) || ' agents' FROM agents" 2>&1
  for v in FORTIK_TOKEN_ADMIN FORTIK_TOKEN_SECURITY FORTIK_TOKEN_AUDITOR FORTIK_TOKEN_INTERCEPTOR \
           FORTIK_AGENT_TOKEN_CLAUDE_CODE_01 FORTIK_AGENT_TOKEN_TEXT2SQL_AGENT_03 FORTIK_AGENT_TOKEN_FINANCE_AGENT_07 \
           FORTIK_AGENT_TOKEN_PLANNER_AGENT_A FORTIK_AGENT_TOKEN_RELAY_AGENT_B FORTIK_AGENT_TOKEN_WEB_AGENT_C \
           FORTIK_AGENT_TOKEN_SUPPORT_AGENT_01 FORTIK_AGENT_TOKEN_SUPPORT_AGENT_02; do
    eval "_fk_v=\${$v:-}"
    if [ -n "$_fk_v" ]; then printf '  %-40s set\n' "$v"; else printf '  %-40s MISSING\n' "$v"; fi
  done
}

# fk_reset: put the demo agents back to a known state (DEV DATABASE ONLY).
# Resumes suspended agents through the API, sets levels with the audited CLI,
# and closes stale delegation / instance / memory-cut records directly in the
# dev database, the same way scripts/demo-phase*.sh reset themselves.
fk_reset() {
  for a in $("$PSQL" -h 127.0.0.1 -p 55432 -U postgres -d fortik -X -A -t -c "SELECT agent_id FROM agents WHERE suspended_at IS NOT NULL AND discovered = false"); do
    curl -s -o /dev/null -X POST -H "Authorization: Bearer $FORTIK_TOKEN_SECURITY" -H 'Content-Type: application/json' \
      -d '{"reason":"investor demo reset"}' "$API/v1/agents/$a/resume"
  done
  "$PSQL" -h 127.0.0.1 -p 55432 -U postgres -d fortik -X -q -c "
    UPDATE delegations SET status = 'closed', closed_at = now(), close_reason = 'investor demo reset' WHERE status = 'open';
    UPDATE access_overrides SET status = 'released' WHERE status IN ('active', 'blocked');
    DELETE FROM memory_access WHERE agent_id IN ('support_agent_01', 'support_agent_02');" > /dev/null
  for a in claude_code_01 text2sql_agent_03 finance_agent_07 planner_agent_a relay_agent_b web_agent_c support_agent_01 support_agent_02; do
    fk_set_level "$a" FULL "investor demo reset" > /dev/null 2>&1 || echo "  could not reset $a" >&2
  done
  fk_db fortik "SELECT agent_id, (ARRAY['FULL','SUPERVISED','READ_ONLY','ISOLATED','QUARANTINED','KILLED'])[level+1] AS level, suspended_at IS NOT NULL AS suspended FROM agents WHERE agent_id IN ('claude_code_01','text2sql_agent_03','finance_agent_07','planner_agent_a','relay_agent_b','web_agent_c','support_agent_01','support_agent_02') ORDER BY agent_id"
}

echo "Fortik demo helpers loaded (API $API, gateway $GW). Try: fk_check"
