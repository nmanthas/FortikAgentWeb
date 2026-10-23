#!/usr/bin/env bash
# Phase 1 demo: the accident-containment path through the real Fortik
# Postgres proxy, real Decide service, real policy bundle and real Postgres.
#
#   1. Claude Code (agent claude_code_01) reads staging                -> green, allowed
#   2. runs a staging migration step (ALTER TABLE ... ADD COLUMN)      -> green, allowed
#   3. deletes old staging orders (non-narrow DELETE)                  -> yellow: rows snapshotted first, then allowed
#   4. runs DROP TABLE orders on PROD                                  -> red: HELD, never runs, safe rename form offered,
#                                                                         agent stepped down to READ_ONLY
#   5. tries a prod INSERT                                             -> denied (READ_ONLY)
#   6. reads prod                                                      -> still allowed (workflow not broken)
#   7. security undoes the staging delete via POST /v1/undo/{id}       -> rows restored
#   8. Diary chain verified + signed export
#
# Not in Phase 1 (by plan): approving the safe form from the console, the
# Claude Code hook itself (phase 3). Here psql stands in for Claude Code's shell.
#
# Prereqs: scripts/dev-up.sh, and `bin/fortik serve -config configs/fortik.dev.yaml` running.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/.dev/tokens.env"
PGBIN="${PGBIN:-$(dirname "$(command -v psql 2>/dev/null || echo /Library/PostgreSQL/17/bin/psql)")}"
API="${FORTIK_API:-http://127.0.0.1:8080}"
PROXY_PORT="${FORTIK_PROXY_PORT:-6432}"
FAILED=0

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILED=1; }

# psql as the agent, THROUGH the Fortik proxy (application_name carries the instance id)
agent_sql() { # db sql
  PGPASSWORD="$FORTIK_AGENT_TOKEN_CLAUDE_CODE_01" PGAPPNAME="fortik:inst_demo_01" \
    "$PGBIN/psql" -h 127.0.0.1 -p "$PROXY_PORT" -U claude_code_01 -d "$1" -X -A -t -v ON_ERROR_STOP=1 -c "$2" 2>&1
}
# direct upstream check (bypasses Fortik; only to prove what really happened)
upstream_sql() { "$PGBIN/psql" -h 127.0.0.1 -p 55432 -U postgres -d "$1" -X -A -t -c "$2"; }
api() { # method path token [json]
  curl -sS -X "$1" -H "Authorization: Bearer $3" -H 'Content-Type: application/json' ${4:+-d "$4"} "$API$2"
}

bold "0. reset: agent at FULL, staging orders intact"
"$ROOT/bin/fortik" agent set-level -config "$ROOT/configs/fortik.dev.yaml" -id claude_code_01 -level FULL \
  -reason "demo reset" -actor demo >/dev/null 2>&1 || true
upstream_sql acme_staging "ALTER TABLE orders DROP COLUMN IF EXISTS migrated_by_ticket" >/dev/null
STAGING_BEFORE=$(upstream_sql acme_staging "SELECT count(*) FROM orders")
PROD_BEFORE=$(upstream_sql acme_prod "SELECT count(*) FROM orders")
echo "  staging orders=$STAGING_BEFORE prod orders=$PROD_BEFORE"

bold "1. read staging (expect green/allow)"
out=$(agent_sql acme_staging "SELECT count(*) FROM orders WHERE status = 'paid'") && pass "read allowed: $out paid orders" || fail "read: $out"

bold "2. staging migration: ALTER TABLE orders ADD COLUMN (expect allow on staging)"
out=$(agent_sql acme_staging "ALTER TABLE orders ADD COLUMN migrated_by_ticket text") && pass "migration step allowed" || fail "$out"

bold "3. staging cleanup: DELETE old orders, non-narrow WHERE (expect yellow: snapshot first)"
out=$(agent_sql acme_staging "DELETE FROM orders WHERE created_at < '2023-01-15'") && pass "delete ran after snapshot: $out" || fail "$out"
DELETED_ID=$(api GET "/v1/actions?agent_id=claude_code_01&class=yellow&limit=1" "$FORTIK_TOKEN_AUDITOR" | python3 -c 'import json,sys; a=json.load(sys.stdin)["actions"]; print(a[0]["action_id"] if a else "")')
UNDO_STATUS=$(api GET "/v1/actions/$DELETED_ID" "$FORTIK_TOKEN_AUDITOR" | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("undo") or {}).get("status",""), d["rule_id"], d["decision"])')
[[ "$UNDO_STATUS" == "active POL-102 allow_reduced" ]] && pass "undo handle prepared before the delete ($DELETED_ID: $UNDO_STATUS)" || fail "undo handle: $UNDO_STATUS"
STAGING_AFTER=$(upstream_sql acme_staging "SELECT count(*) FROM orders")
echo "  staging orders now $STAGING_AFTER (was $STAGING_BEFORE)"

bold "4. PROD: DROP TABLE orders (expect red: held, safe form offered, step down to READ_ONLY)"
if out=$(agent_sql acme_prod "DROP TABLE orders"); then fail "DROP TABLE was NOT blocked: $out"; else
  echo "$out" | sed 's/^/  | /'
  echo "$out" | grep -q "POL-101" && pass "held by POL-101" || fail "no POL-101 in error"
  echo "$out" | grep -qE "RENAME TO \"?fortik_trash_orders_" && pass "rename-based safe form offered" || fail "no safe form in hint"
fi
[[ "$(upstream_sql acme_prod "SELECT to_regclass('public.orders') IS NOT NULL")" == "t" ]] && pass "prod orders table still exists" || fail "prod orders table is gone!"
LVL=$(api GET /v1/agents "$FORTIK_TOKEN_AUDITOR" | python3 -c 'import json,sys; print([a["level_name"] for a in json.load(sys.stdin)["agents"] if a["agent_id"]=="claude_code_01"][0])')
[[ "$LVL" == "READ_ONLY" ]] && pass "claude_code_01 stepped down to READ_ONLY" || fail "level is $LVL"

bold "5. prod INSERT after step-down (expect deny)"
if out=$(agent_sql acme_prod "INSERT INTO audit_log (msg) VALUES ('should not land')"); then fail "write allowed at READ_ONLY"; else
  echo "$out" | grep -q "POL-013" && pass "write refused by POL-013 (READ_ONLY)" || fail "$out"; fi

bold "6. prod read after step-down (expect allow: workflow keeps working)"
out=$(agent_sql acme_prod "SELECT count(*) FROM orders") && [[ "$out" == "$PROD_BEFORE" ]] && pass "read allowed, $out orders intact" || fail "$out"

bold "7. held action is visible with its reason and safe form"
api GET "/v1/held" "$FORTIK_TOKEN_AUDITOR" | python3 -c '
import json,sys
h=[x for x in json.load(sys.stdin)["held"] if x["agent_id"]=="claude_code_01"][0]
print("  rule=%s class=%s system=%s verb=%s level_at_decision=%s -> %s" % (h["rule_id"],h["class"],h["system"],h["verb"],h["level_at_decision"],h["level_after"]))
print("  reason:", h["reason"]); print("  safe form:", (h.get("safe_form") or {}).get("sql"))'

bold "8. security undoes the staging delete (POST /v1/undo/$DELETED_ID)"
api POST "/v1/undo/$DELETED_ID" "$FORTIK_TOKEN_SECURITY" '{"reason":"staging cleanup removed rows still needed by QA"}' | sed 's/^/  /'; echo
STAGING_RESTORED=$(upstream_sql acme_staging "SELECT count(*) FROM orders")
[[ "$STAGING_RESTORED" == "$STAGING_BEFORE" ]] && pass "staging orders restored: $STAGING_RESTORED" || fail "staging orders $STAGING_RESTORED != $STAGING_BEFORE"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $FORTIK_TOKEN_SECURITY" -d '{"reason":"again"}' "$API/v1/undo/$DELETED_ID")
[[ "$code" == "409" ]] && pass "second undo refused (409)" || fail "second undo returned $code"

bold "9. Diary: chain verification and signed export"
api GET /v1/diary/verify "$FORTIK_TOKEN_AUDITOR" | python3 -c 'import json,sys; r=json.load(sys.stdin); print("  ok=%s checked=%s head=%s" % (r["ok"], r["checked"], r["head_hash"][:16])); sys.exit(0 if r["ok"] else 1)' \
  && pass "diary chain intact" || fail "diary chain broken"
api GET "/v1/diary?agent_id=claude_code_01&limit=50" "$FORTIK_TOKEN_AUDITOR" | python3 -c '
import json,sys
for e in json.load(sys.stdin)["entries"][-14:]:
    d=json.loads(e["body_json"])["data"]
    print("  #%-4d %-22s %s" % (e["seq"], e["event_type"], " ".join(str(d.get(k,"")) for k in ("class","decision","rule_id","from","to") if d.get(k))))'

echo
if [[ $FAILED == 0 ]]; then printf '\033[32mPhase 1 accident-path demo: ALL CHECKS PASSED\033[0m\n'; else printf '\033[31mPhase 1 accident-path demo: FAILURES\033[0m\n'; exit 1; fi
