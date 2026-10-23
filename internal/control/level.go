// Package control holds the control ladder and the control-state store that
// Decide reads on every call (level today; overrides, swarm membership and
// copy counts are added by later phases behind the same State struct).
package control

import (
	"fmt"
	"strings"
)

// Level is the agent's position on the control ladder. Higher is more
// restricted. Step down (to a higher number) is automatic; step up is manual.
type Level int

const (
	Full        Level = 0
	Supervised  Level = 1
	ReadOnly    Level = 2
	Isolated    Level = 3
	Quarantined Level = 4
	Killed      Level = 5
)

var levelNames = [...]string{"FULL", "SUPERVISED", "READ_ONLY", "ISOLATED", "QUARANTINED", "KILLED"}

func (l Level) String() string {
	if l < Full || l > Killed {
		return fmt.Sprintf("LEVEL(%d)", int(l))
	}
	return levelNames[l]
}

// Valid reports whether l is on the ladder.
func (l Level) Valid() bool { return l >= Full && l <= Killed }

// ParseLevel accepts a ladder name (case-insensitive, "-" or "_") or digit.
func ParseLevel(s string) (Level, error) {
	n := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", "_"))
	for i, name := range levelNames {
		if n == name || n == fmt.Sprint(i) {
			return Level(i), nil
		}
	}
	return 0, fmt.Errorf("unknown control level %q", s)
}

// State is what Decide reads about an agent before evaluating policy.
type State struct {
	AgentID    string `json:"agent_id"`
	Registered bool   `json:"registered"`
	Level      Level  `json:"level"`
	LevelName  string `json:"level_name"`
	Sponsor    string `json:"sponsor,omitempty"`
	Type       string `json:"type,omitempty"`
	Team       string `json:"business_unit,omitempty"`
	Discovered bool   `json:"discovered"`
	// Suspended: every action is refused (POL-016) until Resume; unlike the
	// ladder, state and memory are kept and nothing has to be re-earned.
	Suspended       bool   `json:"suspended"`
	SuspendedReason string `json:"suspended_reason,omitempty"`
}
