package testutil

import (
	"os"
	"testing"
)

// PerfEnv turns on the strict latency budgets of the in-process latency
// tests. They measure contention, not Fortik, when `go test ./...` runs ~45
// packages in parallel against one Postgres, so by default they only log
// their numbers. scripts/perf-test.sh runs them one package at a time on an
// otherwise idle machine with the budgets enforced. The plan's latency gate
// is the k6 load test (scripts/loadtest.sh).
const PerfEnv = "FORTIK_PERF"

// PerfBudgets reports whether latency budgets are enforced, and says so in
// the test log when they are not.
func PerfBudgets(t testing.TB) bool {
	t.Helper()
	if os.Getenv(PerfEnv) == "1" {
		return true
	}
	t.Logf("latency budget not enforced (set %s=1 on an idle machine, or run scripts/perf-test.sh)", PerfEnv)
	return false
}
