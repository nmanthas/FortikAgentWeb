#!/usr/bin/env bash
# End-to-end re-run of the agentgateway go/no-go spike.
#   1. downloads agentgateway (if missing) and builds the Go helpers into bin/
#   2. functional probes: extAuthz variant, mcpGuardrails variant, A2A route
#   3. failure-mode probes (callout down / slow) for both hooks
#   4. latency benchmark (scripts/bench.sh)
# All processes are local (127.0.0.1) and are stopped on exit. Output lands in out/.
# Usage: scripts/run.sh [N_BENCH]
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
trap stop_all EXIT

AGW_VERSION=${AGW_VERSION:-v1.6.0}
N=${1:-2000}

section() { printf '\n==================== %s ====================\n' "$*"; }

# ---------------------------------------------------------------- setup
mkdir -p bin
if [ ! -x bin/agentgateway ]; then
  section "download agentgateway $AGW_VERSION (darwin-arm64)"
  base=https://github.com/agentgateway/agentgateway/releases/download/$AGW_VERSION
  curl -fsSL -o bin/agentgateway "$base/agentgateway-darwin-arm64"
  curl -fsSL -o bin/agentgateway.sha256 "$base/agentgateway-darwin-arm64.sha256"
  want=$(awk '{print $1}' bin/agentgateway.sha256); got=$(shasum -a 256 bin/agentgateway | awk '{print $1}')
  [ "$want" = "$got" ] || { echo "sha256 mismatch: $got != $want"; exit 1; }
  chmod +x bin/agentgateway
fi
bin/agentgateway -V
go build -o bin/ ./cmd/... || exit 1
for c in configs/*.yaml; do bin/agentgateway -f "$c" --validate-only >/dev/null || { echo "invalid $c"; exit 1; }; done

for p in 3300 8090 9001 4318 15000 15020 15021; do
  nc -z 127.0.0.1 $p 2>/dev/null && { echo "port $p already in use; stop it first"; exit 1; }
done

start_bg mcpserver "$OUT/mcpserver.log" bin/mcpserver; wait_port 127.0.0.1:8090
start_bg otlpsink "$OUT/otlpsink.log" bin/otlpsink; wait_port 127.0.0.1:4318
callout_start

upstream_calls() { curl -s 127.0.0.1:8090/stats; }

# ---------------------------------------------------------------- functional
section "A. extAuthz (Envoy ext_authz v3 gRPC) - functional"
gw_restart configs/extauthz.yaml extauthz
b=$(upstream_calls); scripts/probe.sh; echo "upstream tools/call counter: before=$b after=$(upstream_calls)  (expect +2: only the two allowed calls)"

section "A2A route through extAuthz"
for ag in agent-green-1 blocked_agent; do
  printf -- '--- message/send agent=%s: ' "$ag"
  curl -s -w ' [HTTP %{http_code}]\n' -H 'Content-Type: application/json' -H "x-fortik-agent-id: $ag" \
    -H 'x-fortik-instance-id: inst-0002' \
    -d '{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"role":"user","messageId":"m1","parts":[{"kind":"text","text":"hi"}]}}}' \
    http://127.0.0.1:3300/a2a
done

section "B. mcpGuardrails (agentgateway ext_mcp gRPC) - functional"
gw_restart configs/guardrails.yaml guardrails
b=$(upstream_calls); scripts/probe.sh; echo "upstream tools/call counter: before=$b after=$(upstream_calls)  (expect +2)"

# ---------------------------------------------------------------- failure modes
section "C. failure modes (callout DOWN)"
sed 's/failureMode: deny/failureMode: allow/' configs/extauthz.yaml > "$OUT/extauthz-failopen.yaml"
sed 's/failureMode: failClosed/failureMode: failOpen/' configs/guardrails.yaml > "$OUT/guardrails-failopen.yaml"
stop_pid callout
for v in configs/extauthz.yaml "$OUT/extauthz-failopen.yaml" configs/guardrails.yaml "$OUT/guardrails-failopen.yaml"; do
  gw_restart "$v" "failure-$(basename "$v" .yaml)"
  b=$(upstream_calls)
  echo "--- $v (callout down)"
  scripts/probe.sh | grep -A2 -E '^### (initialize|tools/call delete_everything)'
  echo "    upstream tools/call counter: before=$b after=$(upstream_calls)"
done

section "D. extAuthz timeout (requestTimeout 100ms, decide takes 300ms)"
python3 -I -c 'import sys;s=open(sys.argv[1]).read();print(s.replace("          failureMode: deny\n      backends:\n      - mcp:","          failureMode: deny\n          policies:\n            http:\n              requestTimeout: 100ms\n      backends:\n      - mcp:"),end="")' \
  configs/extauthz.yaml > "$OUT/extauthz-timeout.yaml"
callout_start -delay 300ms
gw_restart "$OUT/extauthz-timeout.yaml" timeout
for _ in 1 2 3; do
  curl -s -o /dev/null -w 'initialize -> HTTP %{http_code} in %{time_total}s\n' -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}' \
    http://127.0.0.1:3300/mcp
done
callout_start

# ---------------------------------------------------------------- latency
section "E. latency benchmark (N=$N, sequential, green tools/call)"
stop_pid agw
scripts/bench.sh "$N" 2

section "trace export sample (otlpsink)"
grep '"tools/call"' "$OUT/otlpsink.log" | head -2
grep '"ExtAuthz"\|CheckRequest' "$OUT/otlpsink.log" | head -2
echo; echo "done; logs in $OUT/"
