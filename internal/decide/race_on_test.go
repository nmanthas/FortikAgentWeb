//go:build race

package decide_test

// raceEnabled: timing budgets are meaningless under the race detector (~10x slower).
const raceEnabled = true
