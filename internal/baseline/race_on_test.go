//go:build race

package baseline_test

// raceEnabled: timing budgets are looser under the race detector.
const raceEnabled = true
