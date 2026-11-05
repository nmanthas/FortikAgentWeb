//go:build race

package agentgw

// raceEnabled: the race detector slows the in-process callout several
// times, beyond agentgateway's production 250 ms callout budget.
const raceEnabled = true
