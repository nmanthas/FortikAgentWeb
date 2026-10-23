#!/usr/bin/env bash
# Latency benchmark: sequential allowed tools/call (green) requests.
#   direct            client -> mcpserver
#   gw-baseline       client -> agentgateway (no callout) -> mcpserver
#   gw-extauthz       client -> agentgateway -> [ext_authz gRPC callout] -> mcpserver
#   gw-mcpguardrails  client -> agentgateway -> [ext_mcp gRPC callout]  -> mcpserver
# Usage: scripts/bench.sh [N] [ROUNDS]   (run from spike root; services must be built)
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib.sh
N=${1:-2000}; ROUNDS=${2:-2}; WARM=200
RES=$OUT/bench.jsonl; : > "$RES"

stop_pid mcpserver; start_bg mcpserver "$OUT/mcpserver-bench.log" bin/mcpserver -quiet; wait_port 127.0.0.1:8090
nc -z 127.0.0.1 4318 2>/dev/null || { start_bg otlpsink "$OUT/otlpsink.log" bin/otlpsink; wait_port 127.0.0.1:4318; }
callout_start -quiet

for r in $(seq "$ROUNDS"); do
  bin/loadgen -url http://127.0.0.1:8090/mcp -n "$N" -warmup $WARM -label direct -json "$RES"
  for v in baseline extauthz guardrails; do
    gw_restart "configs/$v.yaml" "bench-$v"
    lbl=gw-$v; [ $v = guardrails ] && lbl=gw-mcpguardrails
    bin/loadgen -url http://127.0.0.1:3300/mcp -n "$N" -warmup $WARM -label "$lbl" -json "$RES"
  done
done
stop_pid agw
echo; echo "results: $RES"
