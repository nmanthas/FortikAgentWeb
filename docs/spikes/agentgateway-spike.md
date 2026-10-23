# Spike: agentgateway as Fortik's data plane (go/no-go)

- **Date:** 2026-10-06/07
- **Machine:** Apple M1 laptop, macOS 15 (Darwin 24.6.0), arm64. Docker was not used.
- **Code and re-run instructions:** [`spikes/agentgateway/`](../../spikes/agentgateway/README.md). Running `scripts/run.sh` repeats every result below.

## Recommendation: **GO-WITH-CONDITIONS**

agentgateway v1.6.0 meets all three plan criteria on this machine. Each criterion has at least one of agentgateway's two callout hooks running hands-on:

1. **Per-request blocking works.** A denied `tools/call` never reaches the upstream MCP server. Other calls in the same session keep working.
2. **Added latency is far under budget.** p95 overhead was about 0.5–0.6 ms with a trivial Decide. The budget is 50 ms.
3. **`x-fortik-agent-id` and `x-fortik-instance-id` travel end to end:** client → callout → upstream MCP server → OTel span attributes.

The conditions are listed in [Conditions for GO](#conditions-for-go). In short:

- Fail closed with a short explicit timeout.
- Bind the identity headers to authenticated identity instead of trusting what the client sends.
- Pin the agentgateway version.
- Use `mcpGuardrails` (ext_mcp) for MCP and `extAuthz` (gRPC) for A2A/HTTP.
- Re-validate on Linux/Kubernetes before production.

The Envoy fallback is not needed.

## Versions tested

| Component | Version |
|---|---|
| agentgateway | **v1.6.0** (released 2026-10-02), git `ea5608642b9d`, `build_target: aarch64-apple-darwin`, Rust 1.99.0 |
| Binary | `agentgateway-darwin-arm64` from GitHub Releases. sha256 `6cebe8bd…e1e9c685` matches the published `.sha256`. **A darwin-arm64 build is published officially** (also linux-amd64, linux-arm64, windows-amd64). |
| Go | go1.27.1 darwin/arm64 |
| Envoy protos | `github.com/envoyproxy/go-control-plane/envoy` v1.39.0 |
| gRPC | `google.golang.org/grpc` v1.84.0 |
| ext_mcp bindings | Copied from agentgateway v1.6.0 `api/ext_mcp*.pb.go` into `internal/extmcp` (Apache-2.0) |
| MCP protocol version used by clients | `2025-06-18` (streamable HTTP) |

## What agentgateway offers for callouts (research)

Sources: the config schema shipped in the repo (`schema/config.md` at v1.6.0), the Rust source (`crates/agentgateway/src/http/ext_authz.rs`, `src/mcp/guardrails/*`, `crates/protos/proto/ext_mcp.proto`), the examples (`examples/mcp-authzen`), the v1.5/v1.6 release notes, and agentgateway.dev docs.

| Hook | Protocol | Granularity | Sees body? | Can deny? | Failure mode |
|---|---|---|---|---|---|
| `policies.extAuthz` (route, gateway or backend level) | **Envoy ext_authz v3 gRPC** (`envoy.service.auth.v3.Authorization/Check`) or plain HTTP | Once per HTTP request | Yes, with `includeRequestBody` (`maxRequestBytes` default 8192, `allowPartialMessage`, `packAsBytes`) | Yes. The Envoy `DeniedHttpResponse` status, headers and body are returned to the client. | `failureMode: allow \| deny \| {denyWithStatus: N}`. **Default `deny`.** Default timeout **2 s**, configurable via `policies.http.requestTimeout`. |
| `policies.mcpGuardrails.processors[]` (`kind: remote`) | **agentgateway ext_mcp gRPC** (`agentgateway.dev.ext_mcp.ExtMcp/CheckRequest` + `CheckResponse`) | **Once per MCP JSON-RPC method call**, filtered by `methods` (`tools/call`, `tools/*`, `*/list`, `*`) with phase `request \| response \| full` | Gets the parsed method name, the JSON-RPC `params` (raw JSON), the target `service_names` (unmuxed), and the headers (allow/deny filter) | Yes. Returns `AuthorizationError`. It can also *mutate* params, set or remove upstream headers, and filter or mutate responses. | `failureMode: failClosed \| failOpen`. **Default `failClosed`.** Default timeout **10 s** (hard-coded default), configurable via `policies.http.requestTimeout`. |
| `policies.extProc` | Envoy ext_proc v3 gRPC | Per HTTP request, streaming | `requestBodyMode: none \| buffered \| bufferedPartial \| fullDuplexStreamed` | Yes (immediate response) | `failClosed \| failOpen` |
| `policies.mcpAuthorization` / `authorization` | In-process CEL (`mcp.tool.name`, `jwt.*`, `request.headers[...]`) | Per MCP call | n/a | Yes | n/a (local) |

`extProc` and in-process CEL were **not** exercised in this spike.

## Results by criterion

Legend: **PASS** = demonstrated hands-on in this spike. **UNVERIFIED** = from docs or source only, or not run.

| # | Criterion | extAuthz (gRPC) | mcpGuardrails (ext_mcp) |
|---|---|---|---|
| a | Callout can DENY a single request, and the denied call never reaches upstream | **PASS** | **PASS** |
| a′ | Other calls in the same MCP session still succeed after a deny | **PASS** | **PASS** |
| b | Callout receives the request body: MCP `tools/call` name and arguments | **PASS** (raw HTTP body, ≤ `maxRequestBytes`) | **PASS** (parsed method plus `params` JSON) |
| b′ | Body larger than the limit is handled safely | **PASS**: 70 KB body with limit 64 KB returns **413**. The callout and the upstream are not called. | Not applicable (no byte limit; the gateway's MCP buffer limit returns 413, per the v1.5 notes). Over-limit behaviour is **UNVERIFIED** for this hook. |
| c | Callout receives arbitrary headers (`x-fortik-agent-id`, `x-fortik-instance-id`) | **PASS** (gRPC sends all headers by default) | **PASS** (all headers by default; `requestHeaders.allowed/disallowed` to filter) |
| c′ | Those headers are forwarded to the upstream MCP server | **PASS** | **PASS** |
| c″ | Callout can inject a header that reaches upstream (e.g. a decision id) | **PASS** (`OkHttpResponse.headers` → `x-fortik-decision: allow-extauthz` seen upstream) | **PASS** (`header_mutation` → `x-fortik-decision: allow-mcpguardrails` seen upstream) |
| d | Callout invoked per JSON-RPC message, not just once per HTTP session | **PASS** for streamable HTTP. Each client→server message is its own POST and got its own Check: initialize, notifications/initialized, tools/list and each tools/call. JSON-RPC batch arrays are **rejected by the gateway (400)** before reaching upstream, so a batch cannot sneak a second call past a per-POST check. | **PASS**: one `CheckRequest` per method call (initialize, tools/list, each tools/call). Notifications are not sent to the hook. |
| e1 | A2A routes supported, callout applies | **PASS**: `message/send` on an `a2a: {}` route. Allowed for a green agent; 403 for `blocked_agent`. The access log shows `protocol=a2a a2a.method=…`. | Not applicable (MCP only) |
| e2 | OpenTelemetry trace export | **PASS**: OTLP/HTTP to a local sink. Spans for the request (`tools/call`, with `gen_ai.tool.name`, `mcp.method.name`, `mcp.session.id`), the callout (`ExtAuthz` / `Guardrail`), and the upstream call. Custom CEL attributes `fortik.agent_id` / `fortik.instance_id` were populated. The same `traceparent` trace id reached the callout and the upstream. | **PASS** (same) |
| f | Behaviour when the authz server is down. Configurable? | **PASS**: fails **closed** by default (403 `external authorization failed`). `failureMode: allow` fails **open**. `denyWithStatus: 503` returns 503. | **PASS**: fails **closed** by default (JSON-RPC error -32603, upstream not called), including when the callout dies mid-session. Recovers when the callout returns. `failOpen` fails **open**. |
| f′ | Slow authz server: timeout is configurable and fails closed | **PASS**: `requestTimeout: 100ms` with a 300 ms Decide returns 403 in about 103 ms. With the default and a 3 s Decide: 403 at 2.00 s. | **PASS**: `requestTimeout: 100ms` returns a JSON-RPC error in about 103 ms. With the default and a 12 s Decide: error at 10.0 s. |
| g | Latency acceptable on green actions (< 50 ms p95 Fortik overhead) | **PASS** (+0.48–0.57 ms p95) | **PASS** (+0.44–0.58 ms p95) |
| h | darwin-arm64 binary available | **PASS** | |
| i | Linux / container / Kubernetes deployment | **UNVERIFIED** (Docker not used) | |
| j | Throughput and concurrency under load | **UNVERIFIED** (only sequential, concurrency-1 tests were run) | |
| k | stdio MCP upstreams, multiplexed targets | **UNVERIFIED** for extAuthz | **UNVERIFIED**. The source and docs say `service_names` carries unmuxed names and headers are empty for stdio. |
| l | Server→client requests (sampling, elicitation) or `resources/subscribe`, `completion/complete` gated before execution | **UNVERIFIED** | **Not supported for the request phase.** The gateway logs: "methods match `resources/subscribe` … only the response phase runs for this method". The same holds for `resources/unsubscribe` and `completion/complete`. |

## Evidence

### Functional probe, extAuthz variant (`scripts/probe.sh`, from `out/run.log`)

```
### initialize                         agent=agent-green-1  HTTP 200
### notifications/initialized          agent=agent-green-1  HTTP 202
### tools/list                         agent=agent-green-1  HTTP 200
### tools/call echo (expect ALLOW)     agent=agent-green-1  HTTP 200
    body: event: message data: {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"executed echo args={\"text\":\"hello fortik\"}"}]}}
### tools/call delete_everything (DENY) agent=agent-green-1  HTTP 403
    hdr: x-fortik-decision: deny
    body: {"fortik":"deny","reason":"tool delete_everything is red"}
### tools/call echo by blocked_agent (DENY) agent=blocked_agent  HTTP 403
    body: {"fortik":"deny","reason":"agent blocked by kill switch"}
### tools/call echo again (expect ALLOW) agent=agent-green-1  HTTP 200
upstream tools/call counter: before={"tools_call_received":0} after={"tools_call_received":2}  (expect +2: only the two allowed calls)
```

What the callout received for the denied call (trimmed):

```json
{"hook":"extAuthz","jsonrpc_method":"tools/call","tool":"delete_everything","allow":false,
 "body":"{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"delete_everything\",\"arguments\":{\"text\":\"rm -rf /\"}}}",
 "headers":{":method":"POST",":path":"/mcp","mcp-session-id":"eyJ0Ijoi…","traceparent":"00-5b8025c1…-01",
            "x-fortik-agent-id":"agent-green-1","x-fortik-instance-id":"inst-0001"},"header_count":13}
```

What the upstream MCP server received for an allowed call. Denied calls produced no upstream log line.

```json
{"upstream_received":"tools/call","tool":"echo","args":"{\"text\":\"hello fortik\"}",
 "headers":{"mcp-method":"tools/call","mcp-name":"echo","mcp-protocol-version":"2025-06-18",
            "mcp-session-id":"de5c18ee…","traceparent":"00-1358388ff4464e596200976265b36746-05b27506…-01",
            "x-fortik-agent-id":"agent-green-1","x-fortik-instance-id":"inst-0001","x-fortik-decision":"allow-extauthz"}}
```

The gateway access log shows the denied call as `http.status=403 … reason=DirectResponse duration=0ms`.

### Functional probe, mcpGuardrails variant

```
### tools/call echo (expect ALLOW)     agent=agent-green-1  HTTP 200
### tools/call delete_everything (DENY) agent=agent-green-1  HTTP 200
    body: {"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"fortik: tool delete_everything is red"}],"isError":true}}
### tools/call echo by blocked_agent (DENY) agent=blocked_agent  HTTP 200
    body: {"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"fortik: agent blocked by kill switch"}],"isError":true}}
### tools/call echo again (expect ALLOW) agent=agent-green-1  HTTP 200
upstream tools/call counter: before={"tools_call_received":2} after={"tools_call_received":4}  (expect +2)
```

The two hooks report a deny differently:

- **mcpGuardrails** returns an MCP-native tool error (`isError: true`) that the agent/LLM can read. This is the better UX for a kill switch.
- **extAuthz** returns a raw HTTP 403 with a custom body. MCP client SDKs will raise this as a transport error.

The callout received this for one call:

```json
{"hook":"mcpGuardrails","method":"tools/call","service_names":["spike"],
 "params":"{\"name\":\"delete_everything\",\"arguments\":{\"text\":\"rm -rf /\"}}",
 "headers":{"x-fortik-agent-id":"agent-green-1","x-fortik-instance-id":"inst-0001","mcp-session-id":"…","traceparent":"…"}}
```

### A2A (extAuthz on an `a2a: {}` route)

```
--- message/send agent=agent-green-1: {"id":"1","jsonrpc":"2.0","result":{"kind":"message",…,"text":"a2a stub ok"…}} [HTTP 200]
--- message/send agent=blocked_agent: {"fortik":"deny","reason":"agent blocked by kill switch"} [HTTP 403]
gateway log: route=default/a2a … http.status=200 … protocol=a2a a2a.method=message/send …
```

### Failure modes

The callout was killed before each run (from `out/run.log`):

```
--- configs/extauthz.yaml            (failureMode: deny)        initialize -> HTTP 403 "external authorization failed"; upstream counter +0
--- out/extauthz-failopen.yaml       (failureMode: allow)       delete_everything -> HTTP 200 "executed delete_everything"; upstream counter +4
--- (denyWithStatus: 503)                                       tools/call -> HTTP 503 "Authorization service unavailable"
--- configs/guardrails.yaml          (failureMode: failClosed)  initialize -> {"error":{"code":-32603,"message":"mcpGuardrails checkRequest failed: upstream call failed: Connect: Connection refused"}}; upstream +0
--- out/guardrails-failopen.yaml     (failureMode: failOpen)    delete_everything -> executed; upstream counter +4
```

Callout killed mid-session with mcpGuardrails failClosed:

```
callout UP:     tools/call echo -> result "executed echo"
callout killed: tools/call echo -> {"error":{"code":-32603,"message":"mcpGuardrails checkRequest failed: … Connection refused"}}  upstream +0
callout back:   tools/call echo (same session) -> result "executed echo"
```

Slow Decide:

```
extAuthz      requestTimeout=100ms, decide=300ms -> HTTP 403 in 0.103-0.105s (x3)
extAuthz      default timeout,      decide=3s    -> HTTP 403 in 2.002s
mcpGuardrails requestTimeout=100ms, decide=300ms -> JSON-RPC error "upstream call timeout" in 0.103-0.105s (x3), upstream +0
mcpGuardrails default timeout,      decide=12s   -> JSON-RPC error in 10.004s
```

**Fail-open warning:** `failOpen` / `allow` executed `delete_everything`. Fortik must never ship those settings for the kill-switch path.

### OpenTelemetry (one `tools/call` trace, extAuthz variant)

```json
{"span":"tools/call","parent":"","trace_id":"1358388ff4464e596200976265b36746",
 "attrs":{"fortik.agent_id":"agent-green-1","fortik.instance_id":"inst-0001","gen_ai.tool.name":"echo",
          "mcp.method.name":"tools/call","mcp.target":"spike","http.response.status_code":"200"}}
{"span":"ExtAuthz","parent":"2c56bcd31628440d","trace_id":"1358388ff4464e596200976265b36746",
 "attrs":{"http.path":"/envoy.service.auth.v3.Authorization/Check","grpc.status":"0"}}
{"span":"tools/call spike_echo","parent":"2c56bcd31628440d","trace_id":"1358388ff4464e596200976265b36746"}
```

The upstream MCP server received `traceparent: 00-1358388ff4464e596200976265b36746-…`. That is the same trace, so Decide spans and tool spans can be stitched together. The mcpGuardrails variant emits a `Guardrail` span (`/agentgateway.dev.ext_mcp.ExtMcp/CheckRequest`, `mcp.method.name`).

## Latency

Setup:

- Sequential (concurrency 1) green `tools/call` requests over one MCP session, using keep-alive HTTP/1.1.
- 200 warm-up requests, then **2,000 measured requests per path, 3 rounds** (`scripts/bench.sh 2000 3`).
- Everything ran on one laptop over loopback.
- The callout logic is trivial (no I/O). The upstream answers instantly.
- Gateway access logging and 100% OTLP trace export were **on**, which is realistic.

| Path | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|
| direct → MCP server | 0.072–0.073 | 0.087–0.093 | 0.119–0.152 |
| agentgateway, no callout (baseline) | 0.269–0.274 | 0.348–0.368 | 0.483–0.501 |
| agentgateway + **extAuthz** callout | 0.440–0.449 | 0.566–0.655 | 0.718–0.886 |
| agentgateway + **mcpGuardrails** callout | 0.417–0.444 | 0.528–0.667 | 0.734–0.927 |

Ranges span the 3 rounds. Raw results are in `out/bench.jsonl` and `out/bench-final.log`.

**Added overhead versus direct, worst round:**

| | p50 | p95 | p99 |
|---|---|---|---|
| extAuthz | +0.38 ms | +0.57 ms | +0.77 ms |
| mcpGuardrails | +0.37 ms | +0.58 ms | +0.80 ms |

- The proxy itself costs about 0.2 ms. The gRPC callout hop costs about another 0.17–0.3 ms.
- Overhead is **about 1% of the 50 ms budget**. Nearly all of the budget remains for Decide's real policy evaluation (< 5 ms target), its network hop, and any state lookups.
- With an artificial 2 ms Decide delay (`time.Sleep`, which overshoots on macOS), p95 was 4.6 ms (extAuthz) and 4.8 ms (mcpGuardrails). The cost is additive, with no anomalies (`out/manual-run/bench-delay.jsonl`).
- One earlier 1,000-request round on a busy machine showed a noisy baseline (p99 4.97 ms). The 3×2,000 run above is the clean one.

**Caveats:** loopback only, single client, macOS. Production numbers (Linux pods, real network to Decide, TLS/mTLS to Decide, concurrency) are **UNVERIFIED**.

## Exact config used

`spikes/agentgateway/configs/extauthz.yaml`. The tracing and admin preamble is shared by all three configs:

```yaml
config:
  adminAddr: 127.0.0.1:15000
  statsAddr: 127.0.0.1:15020
  readinessAddr: 127.0.0.1:15021
frontendPolicies:
  tracing:
    host: 127.0.0.1:4318
    protocol: http
    randomSampling: "true"
    attributes:
      fortik.agent_id: 'request.headers["x-fortik-agent-id"]'
      fortik.instance_id: 'request.headers["x-fortik-instance-id"]'
binds:
- port: 3300
  listeners:
  - routes:
    - name: a2a
      matches:
      - path:
          pathPrefix: /a2a
      policies:
        a2a: {}
        extAuthz:
          host: 127.0.0.1:9001
          protocol:
            grpc: {}
          includeRequestBody:
            maxRequestBytes: 65536
          failureMode: deny
      backends:
      - host: 127.0.0.1:8090
    - name: mcp
      policies:
        extAuthz:
          host: 127.0.0.1:9001
          protocol:
            grpc: {}
          includeRequestBody:
            maxRequestBytes: 65536
            allowPartialMessage: false
          failureMode: deny
          # optional, used in the timeout test:
          # policies: { http: { requestTimeout: 100ms } }
      backends:
      - mcp:
          targets:
          - name: spike
            mcp:
              host: http://127.0.0.1:8090/mcp
```

`spikes/agentgateway/configs/guardrails.yaml` uses the same preamble with this route policy:

```yaml
      policies:
        mcpGuardrails:
          processors:
          - kind: remote
            host: 127.0.0.1:9001
            methods:
              "tools/call": request
              "*": request
            failureMode: failClosed
            # optional, used in the timeout test:
            # policies: { http: { requestTimeout: 100ms } }
```

Callout behaviour (`cmd/callout/main.go`):

- ext_authz deny: `CheckResponse{Status: PERMISSION_DENIED, DeniedResponse{403, body}}`
- ext_authz allow: `OkResponse{headers: x-fortik-decision}`
- ext_mcp deny: `McpRequestResult{Error{PERMISSION_DENIED, reason}}`
- ext_mcp allow: `Pass` plus `HeaderMutation`

## Risks and findings to carry forward

1. **The identity headers can be spoofed.** `x-fortik-agent-id` and `x-fortik-instance-id` are passed through exactly as the client sent them. In production the gateway must derive or overwrite them from authenticated identity. Options: `jwtAuth` plus a `requestHeaderModifier`/`transformation` that sets them from `jwt.*`, mTLS/SPIFFE, or ext_authz/ext_mcp header mutation from Decide. Inbound copies from untrusted clients must be stripped. Not tested here.
2. **Fail-open is one config line away.** Pin `failureMode: deny` / `failClosed` and an explicit `requestTimeout`; 100–250 ms is suggested. The defaults of 2 s (extAuthz) and 10 s (mcpGuardrails) would blow the latency budget during a Decide brownout. Add a config lint in CI.
3. **Body limit with extAuthz.** The default `maxRequestBytes` is 8 KB. Set it above the largest legitimate tool arguments. **Never** set `allowPartialMessage: true`: Decide would then judge truncated arguments. Over-limit requests got 413 (fail closed), which is safe but may break large legitimate calls.
4. **Decide must fail closed on unparseable input.** The spike callout's naive parser *allowed* a JSON-RPC batch array. Only the gateway's own 400 on batches prevented a bypass. A real Decide must deny anything it cannot classify. mcpGuardrails avoids this class of bug because the gateway hands Decide a parsed method and params.
5. **Gaps in coverage.**
   - mcpGuardrails cannot gate `resources/subscribe`, `resources/unsubscribe` or `completion/complete` before they run (response phase only).
   - Server→client requests (sampling, elicitation) were not examined.
   - extAuthz sees them as plain HTTP POSTs but must parse them itself.
6. **The deny UX differs between hooks.** extAuthz denies with HTTP 403, which MCP SDKs raise as a transport error and some agents may retry. mcpGuardrails denies with an MCP tool error (`isError: true`), which the agent can reason about.
7. **Release churn.** v1.4 → v1.6 shipped in about 2 months, with breaking changes in each release (see the v1.6.0 notes). `ext_mcp.proto` is agentgateway-specific; extAuthz uses the stable Envoy protocol. Pin an exact version and the binary checksum, and re-run this spike on upgrades.
8. **Session id rewriting.** The gateway issues its own `Mcp-Session-Id` (base64 JSON wrapping the upstream id). Decide sees the gateway id in headers; the upstream sees its own id. Correlate on trace id or on Fortik's instance id, not on the MCP session id.
9. **Not validated here:** Linux or Kubernetes deployment, concurrency and throughput, TLS to Decide, stdio upstreams, multiplexed targets, `extProc`, and the HTTP (non-gRPC) extAuthz mode.

## Conditions for GO

1. **For MCP routes, use `mcpGuardrails` with `methods: {"*": request}`** (or at least `tools/call`) and `failureMode: failClosed`.
   - Decide gets one call per MCP method, with parsed `params`, unmuxed tool names, and support for stdio upstreams.
   - Denies come back as MCP-native tool errors, and Decide can mutate or redact arguments.
   - **For A2A and plain HTTP tool routes, use `extAuthz` (gRPC)** with `includeRequestBody` and `failureMode: deny`.
   - Decide should serve **both** gRPC services from one process. The spike callout already does this on one port.
2. Set `policies.http.requestTimeout` (100–250 ms) on every callout. Alert on callout errors and timeouts (gateway spans `ExtAuthz`/`Guardrail` carry `grpc.status`).
3. Bind agent and instance identity at the gateway (JWT or mTLS) before Phase 2 traffic. Strip client-supplied `x-fortik-*` headers.
4. Pin agentgateway to an exact version with checksum verification.
5. Before production: repeat the benchmark on Linux in the target runtime (container or Kubernetes) with concurrency, and with real Decide latency and TLS.

## Envoy fallback (only if a condition fails)

If agentgateway were rejected, the same Decide service could be used from Envoy, with no change to Decide's ext_authz half:

- **Preferred:** use the `envoy.filters.http.ext_authz` filter with `with_request_body: {max_request_bytes: 65536, allow_partial_message: false}`, `failure_mode_allow: false`, `timeout: 0.2s`, and gRPC service → Decide.
  - This uses the exact `Authorization/Check` contract the spike callout already implements.
  - It is simpler than ext_proc for pure allow/deny.
- **Plan's fallback:** use the `envoy.filters.http.ext_proc` filter with `processing_mode: {request_header_mode: SEND, request_body_mode: BUFFERED, response_header_mode: SKIP, response_body_mode: NONE}`, `failure_mode_allow: false`, and `message_timeout: 0.2s`.
  - Decide implements `ExternalProcessor/Process`.
  - It returns `ImmediateResponse{status: 403}` to block, or `CommonResponse` (optionally with header and body mutation) to allow.
  - Use this route if Decide needs to rewrite arguments or inspect responses.
- **What Envoy lacks:** MCP awareness. There is no per-method hook, no parsing of MCP session or tool names (Decide must parse the JSON-RPC body itself and fail closed on batches or unknown shapes), no A2A awareness, and no MCP-specific spans.
- **Overhead estimate:** expected to be the same order as measured here (sub-millisecond proxy plus gRPC hop), but **UNVERIFIED**.
- **Bonus:** agentgateway itself also speaks ext_proc (`policies.extProc`), so a Decide ext_proc server would work with either proxy.

## Files

- `spikes/agentgateway/README.md`: how to re-run
- `spikes/agentgateway/scripts/{run,probe,bench,lib}.sh`
- `spikes/agentgateway/cmd/{callout,mcpserver,loadgen,otlpsink}/main.go`
- `spikes/agentgateway/configs/{extauthz,guardrails,baseline}.yaml`
- `spikes/agentgateway/internal/extmcp/`: ext_mcp proto and Go bindings copied from agentgateway v1.6.0
- `spikes/agentgateway/out/` (gitignored): `run.log`, `bench.jsonl`, `bench-final.log`, gateway, callout and upstream logs, `manual-run/`
