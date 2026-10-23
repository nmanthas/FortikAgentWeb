#!/usr/bin/env bash
# Functional probe: initialize -> notifications/initialized -> tools/list ->
# allowed tools/call -> denied tools/call (red tool) -> denied tools/call (blocked agent).
# Usage: scripts/probe.sh [url]
set -u
URL=${1:-http://127.0.0.1:3300/mcp}
AGENT=${AGENT:-agent-green-1}
INSTANCE=${INSTANCE:-inst-0001}
HDRS=(-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream'
      -H 'MCP-Protocol-Version: 2025-06-18' -H "x-fortik-instance-id: $INSTANCE")
TMP=$(mktemp -d)

req() { # name agent body
  local name=$1 agent=$2 body=$3
  local code
  code=$(curl -sS -o "$TMP/body" -D "$TMP/hdr" -w '%{http_code}' "${HDRS[@]}" \
    -H "x-fortik-agent-id: $agent" ${SID:+-H "Mcp-Session-Id: $SID"} -d "$body" "$URL")
  printf '### %-34s agent=%-14s HTTP %s\n' "$name" "$agent" "$code"
  grep -i -E '^(mcp-session-id|content-type|x-fortik-decision):' "$TMP/hdr" | sed 's/^/    hdr: /' | tr -d '\r'
  printf '    body: %s\n' "$(head -c 400 "$TMP/body" | tr '\n' ' ')"
}

SID=
req initialize "$AGENT" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}'
SID=$(grep -i '^mcp-session-id:' "$TMP/hdr" | awk '{print $2}' | tr -d '\r')
req notifications/initialized "$AGENT" '{"jsonrpc":"2.0","method":"notifications/initialized"}'
req tools/list "$AGENT" '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
req "tools/call echo (expect ALLOW)" "$AGENT" '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello fortik"}}}'
req "tools/call delete_everything (DENY)" "$AGENT" '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_everything","arguments":{"text":"rm -rf /"}}}'
req "tools/call echo by blocked_agent (DENY)" blocked_agent '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"echo","arguments":{"text":"i am blocked"}}}'
req "tools/call echo again (expect ALLOW)" "$AGENT" '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"echo","arguments":{"text":"still alive"}}}'
rm -rf "$TMP"
