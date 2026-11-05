#!/usr/bin/env bash
# In-process latency budgets (Decide p95 < 50 ms sequential and with 8
# workers; baseline enrich/observe p99 < 2 ms), one package at a time with
# the budgets enforced. Run on an otherwise idle machine with the dev
# database up (scripts/dev-up.sh) and the Fortik server STOPPED.
# The plan's end-to-end latency gate is the k6 load test: scripts/loadtest.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export FORTIK_PERF=1
export FORTIK_TEST_PG_URL="${FORTIK_TEST_PG_URL:-postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable}"
go test -count=1 -p 1 -v -run 'TestDecideLatencyGreen' ./internal/decide | grep -E 'latency|sequential|concurrent|budget|^(ok|FAIL|---)'
go test -count=1 -p 1 -v -run 'TestObserverAndEnricherLatency' ./internal/baseline | grep -E 'enrich|flush|budget|^(ok|FAIL|---)'
echo "latency budgets: passed"
