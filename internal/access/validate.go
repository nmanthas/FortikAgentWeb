package access

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Per-system profile shapes (docs/PHASE2_DESIGN.md §5). Every field is
// required unless marked optional: an omitted field never silently means
// "allow" or "deny", it is a validation error. Decoding is strict (unknown
// fields, trailing data and wrong types are rejected).

// GmailProfile: {"send":"none|internal_only|any","read":true,"max_recipients":25}
type GmailProfile struct {
	Send          string `json:"send"`
	Read          *bool  `json:"read"`
	MaxRecipients *int   `json:"max_recipients"`
}

// DriveProfile: {"mode":"none|read_only|read_write","share":"none|internal_only|any"}
type DriveProfile struct {
	Mode  string `json:"mode"`
	Share string `json:"share"`
}

// GitHubProfile: {"repos":["org/repo"],"permissions":{...},"allow_direct_token":false}
// allow_direct_token is optional (default false).
type GitHubProfile struct {
	Repos            []string          `json:"repos"`
	Permissions      map[string]string `json:"permissions"`
	AllowDirectToken bool              `json:"allow_direct_token"`
}

// AWSProfile: {"mode":"none|read_only|read_write","services":["s3"],"denied_actions":["iam:*"]}
// denied_actions is optional (default none).
type AWSProfile struct {
	Mode          string   `json:"mode"`
	Services      []string `json:"services"`
	DeniedActions []string `json:"denied_actions"`
}

// PostgresProfile: {"upstreams":{"acme_prod":"read_only"}}
type PostgresProfile struct {
	Upstreams map[string]string `json:"upstreams"`
}

// Enum values.
const (
	ModeNone      = "none"
	ModeReadOnly  = "read_only"
	ModeReadWrite = "read_write"

	SendNone         = "none"
	SendInternalOnly = "internal_only"
	SendAny          = "any"

	PermRead  = "read"
	PermWrite = "write"
)

// Limits keep profiles (which are policy input on every decision) small.
const (
	maxListLen       = 256
	maxRecipientsCap = 10000
)

var (
	// GitHub owner/repo (owner: alnum and '-'; repo: alnum, '.', '_', '-').
	repoPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)
	// AWS service prefix as used in IAM actions ("s3", "ec2", "dynamodb").
	awsServicePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	// denied_actions: "service:Action" with * and ? wildcards, or "*".
	awsDeniedPattern = regexp.MustCompile(`^(?:\*|[a-z0-9*?][a-z0-9*?-]{0,63}:[a-z0-9*?]{1,128})$`)
	// Postgres upstream names (YAML keys or integration keys postgres:<name>).
	upstreamPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,62}$`)
)

var githubPermissions = map[string][]string{
	"contents":      {PermRead, PermWrite},
	"pull_requests": {PermRead, PermWrite},
	"issues":        {PermRead, PermWrite},
	"metadata":      {PermRead},
}

// KnownSystem reports whether system has access profiles.
func KnownSystem(system string) bool { return slices.Contains(Systems, system) }

// Validate checks a profile against its system's schema and returns it in
// canonical form (normalised values, sorted lists, no insignificant
// whitespace). Every error wraps ErrInvalidProfile.
func Validate(system string, raw json.RawMessage) (json.RawMessage, error) {
	v, err := Parse(system, raw)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProfile, err)
	}
	return out, nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidProfile, fmt.Sprintf(format, args...))
}

func decodeStrict(raw json.RawMessage, v any) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return invalid("profile must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("%v", err)
	}
	if dec.More() {
		return invalid("trailing data after profile")
	}
	return nil
}

// Parse decodes and validates raw into the system's typed profile
// (GmailProfile, DriveProfile, GitHubProfile, AWSProfile, PostgresProfile,
// A2AProfile, HTTPProfile or MCPProfile), normalised. Every error wraps
// ErrInvalidProfile.
func Parse(system string, raw json.RawMessage) (any, error) {
	switch system {
	case "gmail":
		var p GmailProfile
		if err := decodeStrict(raw, &p); err != nil {
			return nil, err
		}
		if err := oneOf("send", p.Send, SendNone, SendInternalOnly, SendAny); err != nil {
			return nil, err
		}
		if p.Read == nil {
			return nil, invalid("gmail: read is required")
		}
		if p.MaxRecipients == nil {
			return nil, invalid("gmail: max_recipients is required")
		}
		if *p.MaxRecipients < 0 || *p.MaxRecipients > maxRecipientsCap {
			return nil, invalid("gmail: max_recipients must be between 0 and %d", maxRecipientsCap)
		}
		return p, nil
	case "drive":
		var p DriveProfile
		if err := decodeStrict(raw, &p); err != nil {
			return nil, err
		}
		if err := oneOf("mode", p.Mode, ModeNone, ModeReadOnly, ModeReadWrite); err != nil {
			return nil, err
		}
		if err := oneOf("share", p.Share, SendNone, SendInternalOnly, SendAny); err != nil {
			return nil, err
		}
		return p, nil
	case "github":
		var p GitHubProfile
		if err := decodeStrict(raw, &p); err != nil {
			return nil, err
		}
		if p.Repos == nil {
			return nil, invalid("github: repos is required (use [] for none)")
		}
		if p.Permissions == nil {
			return nil, invalid("github: permissions is required (use {} for none)")
		}
		repos, err := normList("github: repos", p.Repos, func(s string) (string, error) {
			if !repoPattern.MatchString(s) {
				return "", invalid("github: repo %q must be owner/name", s)
			}
			// GitHub names are case-insensitive; policy compares lowercase.
			return strings.ToLower(s), nil
		})
		if err != nil {
			return nil, err
		}
		p.Repos = repos
		for k, v := range p.Permissions {
			allowed, ok := githubPermissions[k]
			if !ok {
				return nil, invalid("github: unknown permission %q (contents, pull_requests, issues, metadata)", k)
			}
			if !slices.Contains(allowed, v) {
				return nil, invalid("github: permission %s must be one of %s", k, strings.Join(allowed, "|"))
			}
		}
		return p, nil
	case "aws":
		var p AWSProfile
		if err := decodeStrict(raw, &p); err != nil {
			return nil, err
		}
		if err := oneOf("mode", p.Mode, ModeNone, ModeReadOnly, ModeReadWrite); err != nil {
			return nil, err
		}
		if p.Services == nil {
			return nil, invalid("aws: services is required (use [] for none)")
		}
		svcs, err := normList("aws: services", p.Services, func(s string) (string, error) {
			if !awsServicePattern.MatchString(s) {
				return "", invalid("aws: service %q must be an IAM service prefix such as s3 or ec2", s)
			}
			return s, nil
		})
		if err != nil {
			return nil, err
		}
		p.Services = svcs
		denied, err := normList("aws: denied_actions", p.DeniedActions, func(s string) (string, error) {
			// IAM action names are case-insensitive: stored lowercase, and
			// policy matches them against the lowercased action.
			s = strings.ToLower(s)
			if !awsDeniedPattern.MatchString(s) {
				return "", invalid("aws: denied action %q must be service:Action (wildcards * and ?) or *", s)
			}
			return s, nil
		})
		if err != nil {
			return nil, err
		}
		if denied == nil {
			denied = []string{}
		}
		p.DeniedActions = denied
		return p, nil
	case "postgres":
		var p PostgresProfile
		if err := decodeStrict(raw, &p); err != nil {
			return nil, err
		}
		if p.Upstreams == nil {
			return nil, invalid("postgres: upstreams is required (use {} for none)")
		}
		if len(p.Upstreams) > maxListLen {
			return nil, invalid("postgres: at most %d upstreams", maxListLen)
		}
		for k, v := range p.Upstreams {
			if !upstreamPattern.MatchString(k) {
				return nil, invalid("postgres: upstream name %q is invalid", k)
			}
			if err := oneOf("postgres: upstreams."+k, v, ModeNone, ModeReadOnly, ModeReadWrite); err != nil {
				return nil, err
			}
		}
		return p, nil
	case "a2a":
		return parseA2A(raw)
	case "http":
		return parseHTTP(raw)
	case "mcp":
		return parseMCP(raw)
	default:
		return nil, invalid("unknown system %q (one of %s)", system, strings.Join(Systems, ", "))
	}
}

func oneOf(field, v string, allowed ...string) error {
	if slices.Contains(allowed, v) {
		return nil
	}
	if v == "" {
		return invalid("%s is required (%s)", field, strings.Join(allowed, "|"))
	}
	return invalid("%s must be one of %s (got %q)", field, strings.Join(allowed, "|"), v)
}

// normList validates and normalises each entry, rejects duplicates after
// normalisation and returns the entries sorted.
func normList(field string, in []string, norm func(string) (string, error)) ([]string, error) {
	if in == nil {
		return nil, nil
	}
	if len(in) > maxListLen {
		return nil, invalid("%s: at most %d entries", field, maxListLen)
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		n, err := norm(strings.TrimSpace(s))
		if err != nil {
			return nil, err
		}
		if seen[n] {
			return nil, invalid("%s: duplicate entry %q", field, s)
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// isNull reports whether raw is absent or JSON null (no profile).
func isNull(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || bytes.Equal(t, []byte("null"))
}
