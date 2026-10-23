# agentgateway spike (Phase 1 go/no-go)

Throwaway spike that checks whether [agentgateway](https://github.com/agentgateway/agentgateway)
can serve as Fortik's data plane: every MCP/A2A tool call goes to a Decide callout before it
runs, and is blocked if Decide says so. Findings: [`docs/spikes/agentgateway-spike.md`](../../docs/spikes/agentgateway-spike.md).

This is its own Go module (`fortik/spikes/agentgateway`). Nothing here is imported by the main module.

## Layout

| Path | What |
|---|---|
| `cmd/callout` | Stand-in for Fortik Decide. One gRPC port (127.0.0.1:9001) serves **Envoy ext_authz v3** (`extAuthz`) and **agentgateway ext_mcp** (`mcpGuardrails`). It denies `tools/call delete_everything` and any request with `x-fortik-agent-id: blocked_agent`. `-quiet` turns off logging, `-delay 300ms` adds artificial decision latency. |
| `cmd/mcpserver` | Small MCP server (streamable HTTP, JSON responses) at 127.0.0.1:8090/mcp, plus an A2A stub at `/a2a`. It logs every message and the `x-fortik-*` headers it receives. `GET /stats` returns how many `tools/call` requests reached it. |
| `cmd/loadgen` | Opens one MCP session, then sends N sequential `tools/call` requests and prints p50/p95/p99. |
| `cmd/otlpsink` | Minimal OTLP/HTTP trace receiver (127.0.0.1:4318). Prints one line per span. |
| `internal/extmcp` | Generated Go bindings for agentgateway's `ext_mcp.proto`, copied from agentgateway v1.6.0 (Apache-2.0). Only the package name is changed. |
| `configs/extauthz.yaml` | Gateway on :3300 with route-level `extAuthz` (gRPC) on both the MCP route and an A2A route. |
| `configs/guardrails.yaml` | Gateway on :3300 with `mcpGuardrails` (one processor per JSON-RPC method). |
| `configs/baseline.yaml` | Gateway with no callout, used to measure the proxy's own overhead. |
| `scripts/run.sh` | Full re-run: download, build, functional probes, failure modes, benchmark. |
| `scripts/probe.sh` | Sends initialize, tools/list, an allowed call, two denied calls, then another allowed call. |
| `scripts/bench.sh` | Latency benchmark (direct, gateway baseline, gateway + extAuthz, gateway + mcpGuardrails). |

`bin/` (downloaded agentgateway binary and built helpers) and `out/` (logs, results) are gitignored.

## Re-run

Needs macOS arm64, Go ≥ 1.24 and `curl`/`nc`. No Docker. It installs nothing system-wide.

```bash
cd spikes/agentgateway
scripts/run.sh            # everything; about 2-3 minutes. Output goes to the terminal and out/
scripts/run.sh 5000       # bigger benchmark sample
```

Ports used (all on 127.0.0.1 except the gateway bind): 3300 (gateway), 8090 (MCP server),
9001 (callout), 4318 (OTLP sink), 15000/15020/15021 (gateway admin/stats/readiness).
Port 3000 was taken on the spike machine, so the gateway uses 3300.
`run.sh` refuses to start if any of these ports is busy. It stops every process it started when it exits.

Manual poking:

```bash
source scripts/lib.sh
start_bg mcpserver out/mcpserver.log bin/mcpserver
callout_start
gw_restart configs/extauthz.yaml manual      # or configs/guardrails.yaml
scripts/probe.sh                              # default URL http://127.0.0.1:3300/mcp
tail -f out/callout.log out/mcpserver.log
stop_all
```

Download used for the spike: `agentgateway-darwin-arm64` from release v1.6.0,
sha256 `6cebe8bd57262edce23a65a376d2f5a27b97cdfef609740642edbe75e1e9c685` (matches the published `.sha256`).
