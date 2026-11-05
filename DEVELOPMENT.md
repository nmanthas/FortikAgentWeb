# Development

## Environment

`./scripts/dev-up.sh` is idempotent. It creates:

- **Dev Postgres cluster:** `.dev/pg`, listening on `127.0.0.1:55432` with trust auth, local only.
- **Fortik database** `fortik`, with two roles: `fortik_owner` runs migrations; `fortik_app` is what `serve` connects as, with least-privilege grants and no UPDATE or DELETE on the Diary.
- **Simulated customer databases** `acme_prod` and `acme_staging`, accessed through upstream role `acme_agent`. Seeded with `customers` (12,480 in prod, labelled `customer_pii`) and `orders`.
- **Random dev secrets** in `.dev/secrets`, and plaintext dev tokens in `.dev/tokens.env`.
- **Demo agents:** `claude_code_01`, `finance_agent_07`, `text2sql_agent_03`, the research trio (`planner_agent_a`, `relay_agent_b`, `web_agent_c`) and the Support team (`support_agent_01/02`). The Phase 5 demo adds the campaign swarm.

Docker isn't required for development. Pilot packaging is in `deploy/compose` and `deploy/helm/fortik` (docs/DEPLOYMENT.md).

## Everyday commands

```bash
make build            # bin/fortik
make serve            # API :8080 + pgproxy :6432 with configs/fortik.dev.yaml
make demo             # scripts/demo-phase1-accident.sh (server must be running)
make policy-test      # opa test (coverage threshold 95%)
make test-race        # all Go tests with -race (needs FORTIK_TEST_PG_URL; Makefile defaults to the dev cluster)
make bench            # policy eval benchmarks
make ci               # vet + opa fmt check + policy tests + go test -race
bin/fortik agent set-level -config configs/fortik.dev.yaml -id claude_code_01 -level FULL -reason "reset after demo"
bin/fortik diary verify -config configs/fortik.dev.yaml
```

## Tests

- **Rego:** `policies/fortik/tests/*_test.rego`, run by `opa test` and also by `go test ./internal/policy` (`TestRegoSuite`).
- **Integration tests** use real Postgres. They need `FORTIK_TEST_PG_URL` set to a superuser DSN on a disposable cluster. Each test creates and drops its own database. Without the variable, they skip with an explicit message and never pass silently.
- **Latency:** `go test -run TestDecideLatencyGreen -v ./internal/decide` prints p50, p95 and p99 for sequential and 8-worker runs. Its budgets are enforced only with `FORTIK_PERF=1`: run `scripts/perf-test.sh` on an idle machine. The plan's gate is `scripts/loadtest.sh` (k6).
- **Replay gate:** `go test ./internal/replay` (part of `make ci`) fails on any class, decision, rule or step-down change against the 10,000 recorded inputs. After a reviewed policy change, run `go run ./cmd/fortik replay update`.
- **agentgateway e2e:** `TestEndToEndAgentgateway` runs the pinned agentgateway v1.6.0 binary from `spikes/agentgateway/bin` (skipped with a message when it is absent).
- **CI:** `.github/workflows/ci.yml` runs `make ci` against pgvector Postgres, plus the console type check and tests.
- **Demos and system tests:** `scripts/demo-phase1-accident.sh`, `demo-phase2…6.sh`, `demo-agentgateway.sh`, `chaos-test.sh`, `loadtest.sh`, `perf-test.sh`, `acceptance-real-accounts.sh` (real test accounts), and `deploy/compose/smoke-test.sh`.

## Conventions

- **Security-sensitive logic is centralised.** Classification lives in `pgsql`, decisions in `policy` plus `decide`, and enforcement at the interception point. No interception point may run a protected operation on its own decision.
- **Policies:**
  - Every rule has a `POL-xxx` id and an OPA unit test.
  - Thresholds live in `policies/fortik/data.json`. They are overridable per evaluation through `input.config`.
  - Bundle changes hot-reload, and a broken bundle never replaces the running one.
- **Schema:** schema changes go in a new numbered file in `migrations/`. Never edit an applied migration.
- **Diary:** every security-state change appends a Diary event in the same transaction as the change.
- **Logging:** log summaries only. No raw SQL literals, payloads or secrets.
