package access

import (
	"encoding/json"
	"slices"
)

var _ WideningChecker = Widens

// Widens reports whether next grants anything prev did not. prev may be
// absent (nil or JSON null: no profile, which grants nothing). next must be
// a valid profile. Owners may apply a change only when this is false; any
// error must be treated as widening (callers refuse).
func Widens(system string, prev, next json.RawMessage) (bool, error) {
	nv, err := Parse(system, next)
	if err != nil {
		return true, err
	}
	var pv any
	if !isNull(prev) {
		if pv, err = Parse(system, prev); err != nil {
			return true, err
		}
	}
	switch n := nv.(type) {
	case GmailProfile:
		p, _ := pv.(GmailProfile)
		pRead := p.Read != nil && *p.Read
		pMax := 0
		if p.MaxRecipients != nil {
			pMax = *p.MaxRecipients
		}
		return rank(sendRank, n.Send) > rank(sendRank, p.Send) ||
			(*n.Read && !pRead) ||
			*n.MaxRecipients > pMax, nil
	case DriveProfile:
		p, _ := pv.(DriveProfile)
		return rank(modeRank, n.Mode) > rank(modeRank, p.Mode) ||
			rank(sendRank, n.Share) > rank(sendRank, p.Share), nil
	case GitHubProfile:
		p, _ := pv.(GitHubProfile)
		if n.AllowDirectToken && !p.AllowDirectToken {
			return true, nil
		}
		for _, r := range n.Repos {
			if !slices.Contains(p.Repos, r) {
				return true, nil
			}
		}
		for k, v := range n.Permissions {
			if rank(permRank, v) > rank(permRank, p.Permissions[k]) {
				return true, nil
			}
		}
		return false, nil
	case AWSProfile:
		p, _ := pv.(AWSProfile)
		if rank(modeRank, n.Mode) > rank(modeRank, p.Mode) {
			return true, nil
		}
		for _, s := range n.Services {
			if !slices.Contains(p.Services, s) {
				return true, nil
			}
		}
		// Dropping a denial widens (conservatively: even when another,
		// broader pattern still covers it). With no previous profile there
		// was no access at all, so denials are irrelevant to widening.
		if pv != nil {
			for _, d := range p.DeniedActions {
				if !slices.Contains(n.DeniedActions, d) {
					return true, nil
				}
			}
		}
		return false, nil
	case PostgresProfile:
		p, _ := pv.(PostgresProfile)
		for k, v := range n.Upstreams {
			if rank(modeRank, v) > rank(modeRank, p.Upstreams[k]) {
				return true, nil
			}
		}
		return false, nil
	case A2AProfile:
		p, ok := pv.(A2AProfile)
		return widensA2A(n, p, ok), nil
	case HTTPProfile:
		p, ok := pv.(HTTPProfile)
		return widensHTTP(n, p, ok), nil
	case MCPProfile:
		p, ok := pv.(MCPProfile)
		return widensMCP(n, p, ok), nil
	}
	return true, invalid("unknown system %q", system)
}

var (
	// An absent value ranks as the most restrictive (no grant).
	modeRank = map[string]int{ModeNone: 0, ModeReadOnly: 1, ModeReadWrite: 2}
	sendRank = map[string]int{SendNone: 0, SendInternalOnly: 1, SendAny: 2}
	permRank = map[string]int{PermRead: 1, PermWrite: 2}
)

func rank(m map[string]int, v string) int { return m[v] }
