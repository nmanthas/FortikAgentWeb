// Phase 6 load test (plan: "k6 load test, 200 actions/s, p95 Fortik overhead
// under 50 ms for green, excluding upstream API time").
//
// POST /v1/actions/decide is exactly the decision path the gateways, the
// Postgres proxy and the hook run in-process (classify, enrich, OPA, record
// in Postgres + the hash-chained Diary), without any downstream API call:
// the Fortik overhead the plan measures.
//
//   k6 run -e TOKEN=$FORTIK_TOKEN_INTERCEPTOR loadtest/k6/decide.js
//   (scripts/loadtest.sh seeds the agents and runs it)
import http from "k6/http";
import { check } from "k6";
import { Trend, Rate } from "k6/metrics";

const API = __ENV.API || "http://127.0.0.1:8080";
const TOKEN = __ENV.TOKEN;
const AGENTS = parseInt(__ENV.AGENTS || "300", 10);
const RATE = parseInt(__ENV.RATE || "200", 10);
const DURATION = __ENV.DURATION || "2m";

// Server-side decision latency as Fortik records it (latency_us).
const serverLatency = new Trend("fortik_decision_ms", true);
const green = new Rate("green_allowed");

export const options = {
  scenarios: {
    decide: {
      executor: "constant-arrival-rate",
      rate: RATE,
      timeUnit: "1s",
      duration: DURATION,
      preAllocatedVUs: 50,
      maxVUs: 400,
    },
  },
  thresholds: {
    http_req_duration: ["p(95)<50"], // the plan's target, round trip included
    fortik_decision_ms: ["p(95)<50"],
    http_req_failed: ["rate<0.001"],
    dropped_iterations: ["count==0"], // the 200/s rate was actually sustained
    green_allowed: ["rate>0.99"],
  },
};

const domains = ["docs.python.org", "pkg.go.dev", "developer.mozilla.org", "en.wikipedia.org", "api.weather.example"];

export default function () {
  if (!TOKEN) {
    throw new Error("set -e TOKEN=<interceptor token>");
  }
  const agent = `load_agent_${String(Math.floor(Math.random() * AGENTS)).padStart(3, "0")}`;
  const body = JSON.stringify({
    agent_id: agent,
    system: "http",
    verb: "READ",
    source: "agentgateway",
    target: { domain: domains[Math.floor(Math.random() * domains.length)], external: true, method: "GET", route: "web" },
  });
  const res = http.post(`${API}/v1/actions/decide`, body, {
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    tags: { name: "decide" },
  });
  let d = {};
  try {
    d = res.json();
  } catch (e) {
    d = {};
  }
  check(res, { "status 200": (r) => r.status === 200 });
  green.add(d.class === "green" && d.decision === "allow");
  if (typeof d.latency_us === "number") {
    serverLatency.add(d.latency_us / 1000);
  }
}
