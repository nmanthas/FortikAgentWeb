#!/usr/bin/env bash
# Live demo through the REAL agentgateway (v1.6.0, the version the spike
# pinned), against the dev server (bin/fortik serve -config configs/fortik.dev.yaml).
# Up to here the live demos sent A2A and HTTP actions to POST /v1/actions/decide
# the way agentgateway's callout does; this one puts agentgateway itself in
# the path:
#
#   agent --HTTP/A2A--> agentgateway :15100 --gRPC ext_authz--> Fortik :9091
#                            |                                    (Decide)
#                            +--> upstream only if Fortik allows
#
# The upstreams (an A2A agent server and an "outside" API) are LOCAL stubs
# (scripts/fakes/agent_upstreams.py); nothing leaves the laptop.
#
#   1. identity comes from the agent's Fortik token; a spoofed x-fortik-agent-id is ignored
#   2. web_agent_c may call the outside API; planner_agent_a may not (POL-028)
#   3. UC1: planner_agent_a delegates to web_agent_c over A2A; web_agent_c acting
#      FOR planner_agent_a (its delegation token) is refused as a bypass (POL-601)
#   4. no token: refused before any upstream; Fortik's callout unreachable: refused (fail closed)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/.dev/tokens.env"
AGW_BIN="${AGENTGATEWAY_BIN:-$ROOT/spikes/agentgateway/bin/agentgateway}"
PIN_SHA="6cebe8bd57262edce23a65a376d2f5a27b97cdfef609740642edbe75e1e9c685" # internal/agentgw.AgentGatewaySHA256
API="${FORTIK_API:-http://127.0.0.1:8080}"
CALLOUT="${FORTIK_AGW_CALLOUT:-127.0.0.1:9091}"   # Fortik's agentgw.listen
PGBIN="${PGBIN:-$(dirname "$(command -v psql 2>/dev/null || echo /Library/PostgreSQL/17/bin/psql)")}"
GWPORT=15100; DEADPORT=15110; A2APORT=18201; APIPORT=18202
TMP="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; rm -rf "$TMP"; }
trap cleanup EXIT
FAILED=0
bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
say()  { printf '  \033[2m%s\033[0m\n' "$*"; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILED=1; }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
fdb() { "$PGBIN/psql" -h 127.0.0.1 -p 55432 -U postgres -d fortik -X -A -t -q -c "$1"; }
level_of() { fdb "SELECT (ARRAY['FULL','SUPERVISED','READ_ONLY','ISOLATED','QUARANTINED','KILLED'])[level+1] FROM agents WHERE agent_id='$1'"; }
seen() { python3 -c "import json,sys; L=[json.loads(l) for l in open(sys.argv[1])]; print(len(L))" "$TMP/upstream.log"; }
last() { python3 -c "import json,sys; L=[json.loads(l) for l in open(sys.argv[1])]; print(L[-1].get(sys.argv[2],'') if L else '')" "$TMP/upstream.log" "$1"; }
# get <port> <agent-token|""> [extra curl args...] -> HTTP code; body in $TMP/b
get() { local p="$1" tok="$2"; shift 2
  curl -s -m 5 -o "$TMP/b" -w '%{http_code}' -H "Host: api.partner.example" ${tok:+-H "Authorization: Bearer $tok"} "$@" "http://127.0.0.1:$p/v1/pricing" || true; }
a2a() { local tok="$1"; shift
  curl -s -m 5 -o "$TMP/b" -w '%{http_code}' -X POST -H 'Content-Type: application/json' ${tok:+-H "Authorization: Bearer $tok"} "$@" \
    -d '{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"fetch the partner pricing sheet"}],"messageId":"m-1"}}}' \
    "http://127.0.0.1:$GWPORT/a2a/web_agent_c" || true; }

curl -s -m 2 -o /dev/null "$API/healthz" || { echo "start the server first: bin/fortik serve -config configs/fortik.dev.yaml"; exit 2; }
if [ ! -x "$AGW_BIN" ]; then
  echo "agentgateway v1.6.0 not found at $AGW_BIN."
  echo "Run ./scripts/get-agentgateway.sh (downloads the pinned release and verifies its checksum), or set AGENTGATEWAY_BIN."
  exit 2
fi
HAVE_SHA="$(shasum -a 256 "$AGW_BIN" | cut -d' ' -f1)"
[ "$(uname -sm)" != "Darwin arm64" ] || [ "$HAVE_SHA" = "$PIN_SHA" ] || { echo "agentgateway checksum mismatch ($HAVE_SHA): refusing to run an unpinned binary"; exit 2; }

bold "0. setup: agentgateway v1.6.0 with a Fortik-generated config, local upstreams"
cat > "$TMP/spec.yaml" <<EOF
port: $GWPORT
callout: $CALLOUT
request_timeout: 250ms
admin_addr: 127.0.0.1:$((GWPORT+1))
stats_addr: 127.0.0.1:$((GWPORT+2))
readiness_addr: 127.0.0.1:$((GWPORT+3))
a2a:
  - name: web-agent-c
    path_prefix: /a2a/web_agent_c
    agent: web_agent_c
    backend: 127.0.0.1:$A2APORT
http:
  - name: partner-api
    domain: api.partner.example
    backend: 127.0.0.1:$APIPORT
EOF
"$ROOT/bin/fortik" agentgw config -spec "$TMP/spec.yaml" -out "$TMP/agw.yaml"
"$ROOT/bin/fortik" agentgw config -lint "$TMP/agw.yaml" >/dev/null
sed "s/^port: $GWPORT/port: $DEADPORT/; s/^callout: .*/callout: 127.0.0.1:1/; s/127.0.0.1:$((GWPORT+1))/127.0.0.1:$((DEADPORT+1))/; s/127.0.0.1:$((GWPORT+2))/127.0.0.1:$((DEADPORT+2))/; s/127.0.0.1:$((GWPORT+3))/127.0.0.1:$((DEADPORT+3))/" "$TMP/spec.yaml" > "$TMP/spec-dead.yaml"
"$ROOT/bin/fortik" agentgw config -spec "$TMP/spec-dead.yaml" -out "$TMP/agw-dead.yaml"
: > "$TMP/upstream.log"
python3 "$ROOT/scripts/fakes/agent_upstreams.py" $A2APORT $APIPORT "$TMP/upstream.log" & PIDS+=($!); disown $!
"$AGW_BIN" -f "$TMP/agw.yaml" > "$TMP/agw.log" 2>&1 & PIDS+=($!); disown $!
"$AGW_BIN" -f "$TMP/agw-dead.yaml" > "$TMP/agw-dead.log" 2>&1 & PIDS+=($!); disown $!
for _ in $(seq 1 100); do nc -z 127.0.0.1 $GWPORT 2>/dev/null && nc -z 127.0.0.1 $DEADPORT 2>/dev/null && nc -z 127.0.0.1 $APIPORT 2>/dev/null && break; sleep 0.2; done
say "agentgateway v1.6.0 on :$GWPORT (callout $CALLOUT); a second one on :$DEADPORT whose callout is unreachable"
fdb "UPDATE delegations SET status='closed', closed_at=now(), close_reason='agentgateway demo reset' WHERE status='open' AND (to_agent='web_agent_c' OR from_agent IN ('planner_agent_a','web_agent_c'))" >/dev/null
for a in planner_agent_a web_agent_c; do
  "$ROOT/bin/fortik" agent set-level -config "$ROOT/configs/fortik.dev.yaml" -id $a -level FULL -reason "agentgateway demo reset" -actor demo >/dev/null 2>&1 || true
done
check "agentgateway is in the path (config generated and linted by fortik agentgw config)" '[[ -s "$TMP/agw.yaml" ]] && nc -z 127.0.0.1 $GWPORT'

bold "1. Identity comes from the token, never from headers"
c="$(get $GWPORT "$FORTIK_AGENT_TOKEN_WEB_AGENT_C" -H 'x-fortik-agent-id: planner_agent_a')"
check "web_agent_c calls the outside API through agentgateway: allowed ($c)" '[[ "$c" == 200 ]]'
check "the API sees x-fortik-agent-id: web_agent_c (the spoofed planner_agent_a header was replaced), and no Authorization header" \
  '[[ "$(last agent_id)" == web_agent_c && "$(last authorization_seen)" == False ]]'

bold "2. Access profiles at the gateway"
n0="$(seen)"; c="$(get $GWPORT "$FORTIK_AGENT_TOKEN_PLANNER_AGENT_A")"
check "planner_agent_a (no internet) is refused by agentgateway before the API: $c $(grep -o 'POL-0[0-9]*' "$TMP/b" | head -1)" '[[ "$c" == 403 && "$(seen)" == "$n0" ]] && grep -q POL-028 "$TMP/b"'

bold "3. UC1 through agentgateway: A asks C to do what A may not"
c="$(a2a "$FORTIK_AGENT_TOKEN_PLANNER_AGENT_A")"
TOK="$(last delegation)"
check "planner_agent_a delegates to web_agent_c over A2A ($c); web_agent_c receives a signed delegation token" '[[ "$c" == 200 && -n "$TOK" && "$(last upstream)" == a2a && "$(last agent_id)" == planner_agent_a ]]'
check "the hop is recorded: planner_agent_a -> web_agent_c (open)" '[[ "$(fdb "SELECT count(*) FROM delegations WHERE from_agent='"'"'planner_agent_a'"'"' AND to_agent='"'"'web_agent_c'"'"' AND status='"'"'open'"'"'")" -ge 1 ]]'
n0="$(seen)"; c="$(get $GWPORT "$FORTIK_AGENT_TOKEN_WEB_AGENT_C" -H "X-Fortik-Delegation: $TOK")"
check "web_agent_c fetching FOR planner_agent_a is refused as a bypass: $c $(grep -o 'POL-60[0-9]' "$TMP/b" | head -1), and the API is not reached" '[[ "$c" == 403 && "$(seen)" == "$n0" ]] && grep -q POL-601 "$TMP/b"'
check "the originating agent planner_agent_a is stepped down to SUPERVISED; web_agent_c is not punished" '[[ "$(level_of planner_agent_a)" == SUPERVISED && "$(level_of web_agent_c)" == FULL ]]'
check "a forged delegation token is refused" '[[ "$(get $GWPORT "$FORTIK_AGENT_TOKEN_WEB_AGENT_C" -H "X-Fortik-Delegation: forged")" == 403 ]]'

bold "4. Fail closed"
n0="$(seen)"
check "no Fortik token: refused, nothing reaches the API" '[[ "$(get $GWPORT "")" == 401 && "$(seen)" == "$n0" ]]'
c="$(get $DEADPORT "$FORTIK_AGENT_TOKEN_WEB_AGENT_C")"
check "Fortik's callout unreachable: agentgateway refuses ($c), nothing reaches the API" '[[ "$c" -ge 400 && "$(seen)" == "$n0" ]]'

bold "reset"
fdb "UPDATE delegations SET status='closed', closed_at=now(), close_reason='agentgateway demo done' WHERE status='open' AND to_agent='web_agent_c'" >/dev/null
"$ROOT/bin/fortik" agent set-level -config "$ROOT/configs/fortik.dev.yaml" -id planner_agent_a -level FULL -reason "agentgateway demo done" -actor demo >/dev/null 2>&1 || true
say "delegations closed, planner_agent_a back to FULL"
echo
if [ "$FAILED" = 0 ]; then printf '\033[32magentgateway demo: all checks passed\033[0m\n'; else printf '\033[31magentgateway demo: FAILURES above\033[0m\n'; echo "--- agentgateway log"; tail -20 "$TMP/agw.log"; exit 1; fi
