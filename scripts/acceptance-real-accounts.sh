#!/usr/bin/env bash
# Real-account acceptance (the plan's "Done means": the attack and accident
# scenarios against real Google Workspace, GitHub, AWS and Postgres test
# accounts). Run it against the dev server once the developer has entered
# DISPOSABLE TEST ACCOUNTS in the console (Integrations).
#
#   STATUS: UNTESTED AGAINST REAL ACCOUNTS. As of 2026-10-24 no Google,
#   GitHub or AWS test account exists for this project. What was checked:
#   every section SKIPs cleanly when its integration is not configured, and
#   each request uses the same API contracts the automated tests and the
#   demos exercise (against local fakes). Treat its first real run as the
#   real test.
#
# It uses its own agent (acceptance_agent), so the demo agents are untouched.
# Sections run only when their integration is configured AND their inputs
# are set (otherwise SKIP, which is never counted as a pass):
#
#   Google Workspace   FORTIK_ACCEPT_WORKSPACE_USER  a test user the service account may impersonate
#                      FORTIK_ACCEPT_INTERNAL_TO     an address in the same domain
#                      FORTIK_ACCEPT_EXTERNAL_TO     a test inbox OUTSIDE the domain (you check it stays empty)
#                      FORTIK_ACCEPT_DRIVE_FILE_ID   a file owned by that user
#   GitHub             FORTIK_ACCEPT_GITHUB_REPO     owner/repo where the GitHub App is installed
#   AWS                FORTIK_ACCEPT_S3_BUCKET       a bucket the Fortik role may read; needs the aws CLI
#   Postgres           always (the dev upstreams are real): ./scripts/demo-phase1-accident.sh
#
# Exit 0 only when nothing FAILed; the summary says how much was actually run.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/.dev/tokens.env"
API="${FORTIK_API:-http://127.0.0.1:8080}"
GW="${FORTIK_GATEWAY:-http://127.0.0.1:8090}"
PGBIN="${PGBIN:-$(dirname "$(command -v psql 2>/dev/null || echo /Library/PostgreSQL/17/bin/psql)")}"
CFG=(-config "$ROOT/configs/fortik.dev.yaml")
AG=acceptance_agent
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
P=0; F=0; S=0
bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
say()  { printf '  \033[2m%s\033[0m\n' "$*"; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; P=$((P+1)); }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; F=$((F+1)); }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$*"; S=$((S+1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
J() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
fdb() { "$PGBIN/psql" -h 127.0.0.1 -p 55432 -U postgres -d fortik -X -A -t -q -c "$1"; }
api() { curl -s -o "$TMP/b" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $FORTIK_TOKEN_SECURITY" -H 'Content-Type: application/json' ${3:+-d "$3"} "$API$2"; }
gw() { curl -s -D "$TMP/h" -o "$TMP/b" -w '%{http_code}' -X "$1" -H "Authorization: Bearer $AGTOK" -H 'Content-Type: application/json' ${3:+-d "$3"} "$GW$2"; }
action_id() { awk -F': ' 'tolower($1)=="x-fortik-action-id"{print $2}' "$TMP/h" | tr -d '\r'; }
configured() { api GET /v1/integrations >/dev/null; python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if any(i['key']==sys.argv[2] for i in d.get('integrations',[])) else 1)" "$TMP/b" "$1"; }
level() { "$ROOT/bin/fortik" agent set-level "${CFG[@]}" -id $AG -level "$1" -reason "acceptance: $2" -actor acceptance >/dev/null 2>&1; }
profile() { api PUT "/v1/agents/$AG/access/$1" "{\"profile\":$2,\"reason\":\"acceptance\"}" >/dev/null; }
curl -s -m 2 -o /dev/null "$API/healthz" || { echo "start the server first: bin/fortik serve -config configs/fortik.dev.yaml"; exit 2; }

bold "0. acceptance agent"
if [ "$(fdb "SELECT count(*) FROM agents WHERE agent_id='$AG'")" = 0 ]; then
  api POST /v1/agents "{\"agent_id\":\"$AG\",\"name\":\"Real-account acceptance\",\"type\":\"acceptance\",\"sponsor\":\"security@acme.com\",\"business_unit\":\"Security\"}" >/dev/null
fi
level FULL "start"
AGTOK="$(curl -s -X POST -H "Authorization: Bearer $FORTIK_TOKEN_SECURITY" "$API/v1/agents/$AG/tokens" | J 'd["token"]')"
[ -n "$AGTOK" ] || { echo "could not mint a token for $AG"; exit 2; }
sleep 6   # the gateway reloads agent tokens every few seconds
say "$AG ready (token minted, not shown)"

bold "A. Accident scenario: Postgres (real upstreams) + the Claude Code hook"
if "$ROOT/scripts/demo-phase1-accident.sh" > "$TMP/acc" 2>&1; then pass "accident path end to end ($(grep -c PASS "$TMP/acc") checks: snapshot, DROP held, READ_ONLY, undo, Diary)"; else fail "accident path: see scripts/demo-phase1-accident.sh"; fi

bold "B. Attack scenario: Google Workspace (Gmail, Drive)"
if ! configured google_workspace; then skip "google_workspace integration not configured (console > Integrations)"
elif [ -z "${FORTIK_ACCEPT_WORKSPACE_USER:-}" ] || [ -z "${FORTIK_ACCEPT_INTERNAL_TO:-}" ] || [ -z "${FORTIK_ACCEPT_EXTERNAL_TO:-}" ] || [ -z "${FORTIK_ACCEPT_DRIVE_FILE_ID:-}" ]; then
  skip "set FORTIK_ACCEPT_WORKSPACE_USER, FORTIK_ACCEPT_INTERNAL_TO, FORTIK_ACCEPT_EXTERNAL_TO, FORTIK_ACCEPT_DRIVE_FILE_ID"
else
  api PATCH "/v1/agents/$AG" "{\"workspace_user\":\"$FORTIK_ACCEPT_WORKSPACE_USER\"}" >/dev/null
  profile gmail '{"send":"any","read":true,"max_recipients":5}'
  profile drive '{"mode":"read_write","share":"any"}'
  sleep 2
  raw() { python3 -c "import base64,sys; m='To: %s\r\nSubject: Fortik acceptance %s\r\n\r\nFortik real-account acceptance test.\r\n'%(sys.argv[1],sys.argv[2]); print(base64.urlsafe_b64encode(m.encode()).decode().rstrip('='))" "$1" "$2"; }
  c="$(gw POST /gw/google/gmail/v1/users/me/messages/send "{\"raw\":\"$(raw "$FORTIK_ACCEPT_INTERNAL_TO" internal)\"}")"
  check "internal email is sent through the gateway ($c, message id from Gmail)" '[[ "$c" == 200 && "$(J "d.get(\"id\",\"\")" < "$TMP/b")" != fortik-delayed-* ]]'
  c="$(gw POST /gw/google/gmail/v1/users/me/messages/send "{\"raw\":\"$(raw "$FORTIK_ACCEPT_EXTERNAL_TO" external-undo)\"}")"; A1="$(action_id)"
  check "external email goes to the 2-minute delay queue instead of out ($c)" '[[ "$c" == 200 && "$(J "d.get(\"fortik\",{}).get(\"status\",\"\")" < "$TMP/b")" == delayed ]]'
  api POST "/v1/undo/$A1" '{"reason":"acceptance: cancel the delayed send"}' >/dev/null
  check "undo cancels it before it leaves" '[[ "$(fdb "SELECT status FROM delayed_sends WHERE action_id='"'$A1'"'")" == cancelled ]]'
  c="$(gw POST /gw/google/gmail/v1/users/me/messages/send "{\"raw\":\"$(raw "$FORTIK_ACCEPT_EXTERNAL_TO" external-kill)\"}")"; A2="$(action_id)"
  level KILLED "kill before the delayed send"
  say "waiting for the send time to pass (about 2 minutes) to prove nothing was delivered..."
  for _ in $(seq 1 180); do s="$(fdb "SELECT status FROM delayed_sends WHERE action_id='$A2'")"; [[ "$s" != pending ]] && break; sleep 1; done
  check "killing the agent cancels its pending send: status '$s' (check $FORTIK_ACCEPT_EXTERNAL_TO received no 'external-kill' mail)" '[[ "$s" == cancelled ]]'
  level FULL "after the kill check"; sleep 2
  c="$(gw POST "/gw/google/drive/v3/files/$FORTIK_ACCEPT_DRIVE_FILE_ID/permissions" '{"role":"reader","type":"anyone"}')"; A3="$(action_id)"; PERM="$(J 'd.get("id","")' < "$TMP/b" 2>/dev/null)"
  check "an 'anyone with the link' share is narrowed to the domain ($c, type $(J 'd.get("type","")' < "$TMP/b" 2>/dev/null))" '[[ "$c" == 200 && "$(J "d.get(\"type\",\"\")" < "$TMP/b")" == domain ]]'
  api POST "/v1/undo/$A3" '{"reason":"acceptance: remove the share"}' >/dev/null; uc="$(cat "$TMP/b" | J 'd.get("status","")' 2>/dev/null)"
  c="$(gw GET "/gw/google/drive/v3/files/$FORTIK_ACCEPT_DRIVE_FILE_ID/permissions")"
  check "undo deletes that permission at Google ($uc)" '[[ "$c" == 200 ]] && ! grep -q "\"$PERM\"" "$TMP/b"'
  level FULL "end of Google section"
fi

bold "C. GitHub"
if ! configured github; then skip "github integration not configured (console > Integrations)"
elif [ -z "${FORTIK_ACCEPT_GITHUB_REPO:-}" ]; then skip "set FORTIK_ACCEPT_GITHUB_REPO=owner/repo"
else
  profile github "{\"repos\":[\"$FORTIK_ACCEPT_GITHUB_REPO\"],\"permissions\":{\"contents\":\"read\",\"metadata\":\"read\"},\"allow_direct_token\":false}"
  sleep 2
  c="$(gw GET "/gw/github/repos/$FORTIK_ACCEPT_GITHUB_REPO")"
  check "repo read through the gateway with a Fortik-minted installation token ($c)" '[[ "$c" == 200 && "$(J "d.get(\"full_name\",\"\")" < "$TMP/b")" == "$FORTIK_ACCEPT_GITHUB_REPO" ]]'
  api POST /v1/overrides "{\"scope\":\"agent\",\"scope_id\":\"$AG\",\"system\":\"github\",\"mode\":\"suspended\",\"duration_seconds\":60,\"reason\":\"acceptance\"}" >/dev/null; OV="$(J 'd["override_id"]' < "$TMP/b")"
  c="$(gw GET "/gw/github/repos/$FORTIK_ACCEPT_GITHUB_REPO")"
  check "timed suspension: refused at once ($c POL-030)" '[[ "$c" == 403 ]] && grep -q POL-030 "$TMP/b"'
  api POST "/v1/overrides/$OV/release" '{"reason":"acceptance"}' >/dev/null
  check "released: works again ($(gw GET "/gw/github/repos/$FORTIK_ACCEPT_GITHUB_REPO"))" '[[ "$(cat "$TMP/b" | J "d.get(\"full_name\",\"\")")" == "$FORTIK_ACCEPT_GITHUB_REPO" ]]'
  level KILLED "kill"
  c="$(gw GET "/gw/github/repos/$FORTIK_ACCEPT_GITHUB_REPO")"
  check "killed: refused ($c), cached tokens dropped" '[[ "$c" == 403 ]]'
  level FULL "end of GitHub section"
fi

bold "D. AWS"
if ! configured aws; then skip "aws integration not configured (console > Integrations)"
elif [ -z "${FORTIK_ACCEPT_S3_BUCKET:-}" ] || ! command -v aws >/dev/null; then skip "set FORTIK_ACCEPT_S3_BUCKET and install the aws CLI"
else
  profile aws '{"mode":"read_only","services":["s3"],"denied_actions":["iam:*"]}'
  sleep 2
  c="$(gw POST /v1/credentials/issue "{\"system\":\"aws\",\"aws\":{\"service\":\"s3\",\"action\":\"ListBucket\",\"resource\":\"arn:aws:s3:::$FORTIK_ACCEPT_S3_BUCKET\"}}")"
  check "a 15-minute STS session scoped to s3:ListBucket on the bucket is issued ($c)" '[[ "$c" == 200 && -n "$(J "d[\"secret\"].get(\"session_token\",\"\")" < "$TMP/b")" ]]'
  export AWS_ACCESS_KEY_ID="$(J 'd["secret"]["access_key_id"]' < "$TMP/b")" AWS_SECRET_ACCESS_KEY="$(J 'd["secret"]["secret_access_key"]' < "$TMP/b")" AWS_SESSION_TOKEN="$(J 'd["secret"]["session_token"]' < "$TMP/b")"
  check "the session works for what it allows" 'aws s3api list-objects-v2 --bucket "$FORTIK_ACCEPT_S3_BUCKET" --max-items 1 >/dev/null 2>&1'
  check "and nothing else (s3:DeleteBucket refused by AWS)" '! aws s3api delete-bucket --bucket "$FORTIK_ACCEPT_S3_BUCKET" >/dev/null 2>&1'
  c="$(gw POST /v1/credentials/issue '{"system":"aws","aws":{"service":"iam","action":"CreateAccessKey","resource":"*"}}')"
  check "an IAM credential request is refused by policy ($c)" '[[ "$c" == 403 ]]'
  level FULL "after the IAM refusal"
  level KILLED "kill: revoke by token issue time"
  say "waiting up to 90 s for the IAM deny to propagate..."
  ok=1; for _ in $(seq 1 45); do aws s3api list-objects-v2 --bucket "$FORTIK_ACCEPT_S3_BUCKET" --max-items 1 >/dev/null 2>&1 || { ok=0; break; }; sleep 2; done
  check "killed: the already-issued STS session stops working (aws:TokenIssueTime deny)" '[[ $ok == 0 ]]'
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  level FULL "end of AWS section"
fi

bold "Summary"
check "Diary chain verifies" '[[ "$(curl -s -H "Authorization: Bearer $FORTIK_TOKEN_AUDITOR" "$API/v1/diary/verify" | J "d[\"ok\"]")" == True ]]'
echo "  $P passed, $F failed, $S skipped"
if [ "$S" -gt 0 ]; then echo "  Skipped sections are NOT accepted: configure their test accounts and run again."; fi
[ "$F" = 0 ]
