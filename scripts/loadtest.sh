#!/usr/bin/env bash
# Phase 6 load test: registers the load-test agents (first run only), then runs
# the k6 scenario (200 actions/s for 2 minutes; p95 must stay under 50 ms).
# Needs: the dev server running (bin/fortik serve -config configs/fortik.dev.yaml)
# and k6 (brew install k6). Options: RATE=200 DURATION=2m AGENTS=300.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/.dev/tokens.env"
PGBIN="${PGBIN:-$(dirname "$(command -v psql 2>/dev/null || echo /Library/PostgreSQL/17/bin/psql)")}"
AGENTS="${AGENTS:-300}"
command -v k6 >/dev/null || { echo "loadtest: k6 is required (brew install k6)"; exit 2; }
curl -s -m 2 -o /dev/null http://127.0.0.1:8080/healthz || { echo "loadtest: start the server first"; exit 2; }
have="$("$PGBIN/psql" -h 127.0.0.1 -p 55432 -U postgres -d fortik -X -A -t -q -c "SELECT count(*) FROM agents WHERE agent_id LIKE 'load_agent_%'")"
if [ "$have" -lt "$AGENTS" ]; then
  echo "registering $AGENTS load-test agents (first run only)..."
  for i in $(seq 0 $((AGENTS - 1))); do
    printf -v id 'load_agent_%03d' "$i"
    "$ROOT/bin/fortik" agent register -config "$ROOT/configs/fortik.dev.yaml" -id "$id" -name "Load test agent $i" -type loadtest \
      -platform k6 -sponsor loadtest@acme.com -team LoadTest >/dev/null
  done
fi
k6 run -e TOKEN="$FORTIK_TOKEN_INTERCEPTOR" -e AGENTS="$AGENTS" -e RATE="${RATE:-200}" -e DURATION="${DURATION:-2m}" \
  --summary-trend-stats "avg,med,p(95),p(99),max" "$ROOT/loadtest/k6/decide.js"
