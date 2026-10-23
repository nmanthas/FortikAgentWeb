package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"fortik/internal/access"
	"fortik/internal/broker"
)

// ProfileSource returns an agent's current access profile (access.Store
// satisfies it). access.ErrNotFound means "no access".
type ProfileSource interface {
	Current(ctx context.Context, agentID, system string) (access.Profile, error)
}

// Profile is the github access profile (docs/PHASE2_DESIGN.md §5):
//
//	{"repos":["org/repo"],"permissions":{"contents":"write",...},"allow_direct_token":false}
type Profile struct {
	Version          int               `json:"-"`
	Repos            []string          `json:"repos"`
	Permissions      map[string]string `json:"permissions"`
	AllowDirectToken bool              `json:"allow_direct_token"`
}

// ErrNoProfile: the agent has no github access profile, so it has no access.
// It wraps broker.ErrScopeDenied so the broker core turns it into a refusal.
var ErrNoProfile = fmt.Errorf("%w: github: agent has no github access profile (no access)", broker.ErrScopeDenied)

// LoadProfile fetches and parses the agent's github profile. Any error,
// including a missing or unparsable profile, means no access.
func LoadProfile(ctx context.Context, src ProfileSource, agentID string) (Profile, error) {
	if src == nil {
		return Profile{}, errors.New("github: no access profile source configured")
	}
	p, err := src.Current(ctx, agentID, System)
	if errors.Is(err, access.ErrNotFound) {
		return Profile{}, ErrNoProfile
	}
	if err != nil {
		return Profile{}, fmt.Errorf("github: load access profile: %w", err)
	}
	prof, err := ParseProfile(p.Profile)
	if err != nil {
		return Profile{}, err
	}
	prof.Version = p.Version
	return prof, nil
}

// ParseProfile parses and validates profile JSON with the access package's
// schema (access.Parse), so the broker and gateway read profiles exactly as
// the console validated them. JSON null is ErrNoProfile.
func ParseProfile(raw json.RawMessage) (Profile, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return Profile{}, ErrNoProfile
	}
	parsed, err := access.Parse(System, raw)
	if err != nil {
		return Profile{}, fmt.Errorf("github: %w", err)
	}
	gp, ok := parsed.(access.GitHubProfile)
	if !ok {
		return Profile{}, fmt.Errorf("%w: github: unexpected profile type", access.ErrInvalidProfile)
	}
	return Profile{Repos: gp.Repos, Permissions: gp.Permissions, AllowDirectToken: gp.AllowDirectToken}, nil
}

// HasRepo reports whether repo ("owner/name", case-insensitive, as GitHub
// treats it) is listed in the profile. No wildcards.
func (p Profile) HasRepo(repo string) bool {
	for _, r := range p.Repos {
		if strings.EqualFold(strings.TrimSpace(r), repo) {
			return true
		}
	}
	return false
}

// Allows reports whether the profile grants perm at level. metadata:read is
// implied by any other repository permission, as GitHub itself grants it
// with every repository permission.
func (p Profile) Allows(perm, level string) bool {
	if LevelCovers(p.Permissions[perm], level) {
		return true
	}
	if perm == "metadata" && level == "read" {
		for _, v := range p.Permissions {
			if levelRank(v) > 0 {
				return true
			}
		}
	}
	return false
}

// Missing returns the permissions in need the profile does not grant, as
// "perm:level" strings (empty = all granted).
func (p Profile) Missing(need map[string]string) []string {
	var out []string
	for k, v := range need {
		if !p.Allows(k, v) {
			out = append(out, k+":"+v)
		}
	}
	return out
}

var (
	ownerPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	namePattern  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

// ValidOwner and ValidName check GitHub's owner/repository name syntax.
func ValidOwner(s string) bool { return ownerPattern.MatchString(s) }
func ValidName(s string) bool  { return namePattern.MatchString(s) && s != "." && s != ".." }

// SplitRepo validates "owner/name" and returns its parts.
func SplitRepo(repo string) (owner, name string, err error) {
	owner, name, ok := strings.Cut(strings.TrimSpace(repo), "/")
	if !ok || !ValidOwner(owner) || !ValidName(name) {
		return "", "", fmt.Errorf("github: invalid repository %q (want owner/name)", repo)
	}
	return owner, name, nil
}
