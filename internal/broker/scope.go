package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"

	"fortik/internal/access"
	"fortik/internal/action"
)

// Scope keys the broker passes to Adapter.Mint. Besides the request fields
// below, every scope carries the access profile the broker intersected it
// with, so the adapter can re-check it (defence in depth):
//
//	aws:    service, action, iam_action ("<service>:<Action>"), resource, region,
//	        access_profile (json.RawMessage), access_profile_version (int)
//	github: repos ([]string, lowercase), permissions (map[string]string),
//	        access_profile, access_profile_version
//
// The broker strips access_profile from the scope an adapter returns before
// recording it; adapters return only a non-secret description in Credential.Scope.
const (
	ScopeProfile        = "access_profile"
	ScopeProfileVersion = "access_profile_version"
)

var (
	// ErrInvalidRequest marks a structurally invalid issue request (HTTP 400).
	ErrInvalidRequest = errors.New("invalid credential request")
	// ErrScopeDenied is returned (wrapped) by the broker or an adapter when
	// the current access profile does not allow the requested scope, even
	// though the decision allowed it (e.g. the profile changed in between).
	ErrScopeDenied = errors.New("credential scope not allowed by the current access profile")
	// ErrMintFailed wraps an upstream failure while minting (HTTP 502).
	ErrMintFailed = errors.New("credential issuance failed upstream")
)

// NotConfiguredError reports a missing integration after the decision was
// recorded. errors.Is(err, ErrNotConfigured) holds.
type NotConfiguredError struct {
	System   string
	ActionID string
}

func (e *NotConfiguredError) Error() string {
	return ErrNotConfigured.Error() + ": " + e.System
}

func (e *NotConfiguredError) Is(target error) bool { return target == ErrNotConfigured }

// ReducedFormSupporter is implemented by adapters that can honour some
// allow_reduced forms for a credential. Without it, allow_reduced refuses.
type ReducedFormSupporter interface {
	// SupportsReducedForm reports whether every key of rf can be applied.
	SupportsReducedForm(rf map[string]any) bool
}

var (
	awsServicePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	awsActionPattern  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,127}$`)
	awsRegionPattern  = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+)+-[0-9]{1,2}$`)
	ghRepoPattern     = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)
	ghPermPattern     = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)
)

const (
	maxResourceLen = 2048
	maxRepos       = 100
	maxPermissions = 32
	maxCostUSD     = 1e9
)

// AWSVerb maps an IAM action name to Fortik's verb: Get/List/Describe/Head/
// BatchGet are READ; Delete/Terminate/Remove/Purge/Destroy/Deregister are
// DELETE; any positive cost estimate is SPEND; Put/Create/Update/Modify/
// Attach/Add/Set/Tag are WRITE; everything else is EXECUTE. Matching is
// case-insensitive (IAM action names are).
func AWSVerb(actionName string, estCostUSD float64) action.Verb {
	a := strings.ToLower(actionName)
	has := func(prefixes ...string) bool {
		for _, p := range prefixes {
			if strings.HasPrefix(a, p) {
				return true
			}
		}
		return false
	}
	switch {
	case has("get", "list", "describe", "head", "batchget"):
		return action.VerbRead
	case has("delete", "terminate", "remove", "purge", "destroy", "deregister"):
		return action.VerbDelete
	case estCostUSD > 0:
		return action.VerbSpend
	case has("put", "create", "update", "modify", "attach", "add", "set", "tag"):
		return action.VerbWrite
	default:
		return action.VerbExecute
	}
}

// MatchIAMGlob reports whether an IAM action matches a denied_actions
// pattern: case-insensitive, '*' matches any run of characters (including
// ':'), '?' exactly one. Same semantics as glob.match(p, null, a) in policy.
func MatchIAMGlob(pattern, iamAction string) bool {
	return globMatch([]rune(strings.ToLower(pattern)), []rune(strings.ToLower(iamAction)))
}

func globMatch(p, s []rune) bool {
	// Iterative wildcard matching with single-star backtracking.
	pi, si, star, mark := 0, 0, -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == s[si]):
			pi++
			si++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// CheckAWSProfile verifies that the profile allows service:actionName.
// It returns an error wrapping ErrScopeDenied otherwise.
func CheckAWSProfile(p access.AWSProfile, service, actionName string) error {
	iamAction := service + ":" + actionName
	// Role chaining and federation would mint a credential that escapes the
	// session policy: only STS lookups are ever brokered (POL-401 holds the rest).
	if strings.EqualFold(service, "sts") {
		switch strings.ToLower(actionName) {
		case "getcalleridentity", "getaccesskeyinfo", "decodeauthorizationmessage":
		default:
			return fmt.Errorf("%w: %s would mint a credential outside Fortik's session policy", ErrScopeDenied, iamAction)
		}
	}
	switch p.Mode {
	case access.ModeReadWrite:
	case access.ModeReadOnly:
		if AWSVerb(actionName, 0) != action.VerbRead {
			return fmt.Errorf("%w: profile mode read_only does not allow %s", ErrScopeDenied, iamAction)
		}
	default:
		return fmt.Errorf("%w: profile mode %q grants no AWS access", ErrScopeDenied, p.Mode)
	}
	if !slices.Contains(p.Services, strings.ToLower(service)) {
		return fmt.Errorf("%w: service %s is not in the profile", ErrScopeDenied, service)
	}
	for _, d := range p.DeniedActions {
		if MatchIAMGlob(d, iamAction) {
			return fmt.Errorf("%w: %s matches denied action %s", ErrScopeDenied, iamAction, d)
		}
	}
	return nil
}

// ProfileFromScope decodes and validates the access profile the broker put
// in a Mint scope.
func ProfileFromScope(system string, scope map[string]any) (any, error) {
	var raw json.RawMessage
	switch v := scope[ScopeProfile].(type) {
	case json.RawMessage:
		raw = v
	case []byte:
		raw = v
	case string:
		raw = json.RawMessage(v)
	default:
		return nil, fmt.Errorf("%w: scope carries no access profile", ErrScopeDenied)
	}
	p, err := access.Parse(system, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrScopeDenied, err)
	}
	return p, nil
}

// validateAWS checks the request shape (not authority: policy decides that).
func validateAWS(r *AWSRequest) error {
	switch {
	case r == nil:
		return fmt.Errorf("%w: aws request body is required", ErrInvalidRequest)
	case !awsServicePattern.MatchString(r.Service):
		return fmt.Errorf("%w: aws.service must be a lowercase IAM service prefix such as s3", ErrInvalidRequest)
	case !awsActionPattern.MatchString(r.Action):
		return fmt.Errorf("%w: aws.action must be one IAM action name such as GetObject (no wildcards)", ErrInvalidRequest)
	case r.Resource == "" || len(r.Resource) > maxResourceLen:
		return fmt.Errorf("%w: aws.resource is required (an ARN or *)", ErrInvalidRequest)
	case r.Resource != "*" && !strings.HasPrefix(r.Resource, "arn:"):
		return fmt.Errorf("%w: aws.resource must be an ARN or *", ErrInvalidRequest)
	case strings.ContainsAny(r.Resource, "\x00\"\\\n\r\t "):
		return fmt.Errorf("%w: aws.resource contains invalid characters", ErrInvalidRequest)
	case r.Region != "" && !awsRegionPattern.MatchString(r.Region):
		return fmt.Errorf("%w: aws.region is not a region name", ErrInvalidRequest)
	case math.IsNaN(r.EstCostUSD) || math.IsInf(r.EstCostUSD, 0) || r.EstCostUSD < 0 || r.EstCostUSD > maxCostUSD:
		return fmt.Errorf("%w: aws.est_cost_usd must be between 0 and %g", ErrInvalidRequest, float64(maxCostUSD))
	}
	return nil
}

// normGitHub validates the request shape and returns lowercase, sorted,
// de-duplicated repos and a copy of the permissions.
func normGitHub(r *GHRequest) ([]string, map[string]string, error) {
	if r == nil {
		return nil, nil, fmt.Errorf("%w: github request body is required", ErrInvalidRequest)
	}
	if len(r.Repos) == 0 || len(r.Repos) > maxRepos {
		return nil, nil, fmt.Errorf("%w: github.repos needs 1 to %d owner/name entries", ErrInvalidRequest, maxRepos)
	}
	if len(r.Permissions) == 0 || len(r.Permissions) > maxPermissions {
		return nil, nil, fmt.Errorf("%w: github.permissions needs 1 to %d entries", ErrInvalidRequest, maxPermissions)
	}
	seen := map[string]bool{}
	repos := make([]string, 0, len(r.Repos))
	for _, repo := range r.Repos {
		if !ghRepoPattern.MatchString(repo) {
			return nil, nil, fmt.Errorf("%w: github repo %q must be owner/name", ErrInvalidRequest, repo)
		}
		l := strings.ToLower(repo)
		if !seen[l] {
			seen[l] = true
			repos = append(repos, l)
		}
	}
	sort.Strings(repos)
	perms := make(map[string]string, len(r.Permissions))
	for k, v := range r.Permissions {
		if !ghPermPattern.MatchString(k) || (v != access.PermRead && v != access.PermWrite) {
			return nil, nil, fmt.Errorf("%w: github permission %q must be read or write", ErrInvalidRequest, k)
		}
		perms[k] = v
	}
	return repos, perms, nil
}

// intersectGitHub narrows the request to the profile: repos in the profile,
// permissions at most the profile's level. A request that intersects to
// nothing (or a profile without allow_direct_token) is refused.
func intersectGitHub(p access.GitHubProfile, repos []string, perms map[string]string) ([]string, map[string]string, error) {
	if !p.AllowDirectToken {
		return nil, nil, fmt.Errorf("%w: allow_direct_token is false", ErrScopeDenied)
	}
	var outRepos []string
	for _, r := range repos {
		if slices.Contains(p.Repos, r) {
			outRepos = append(outRepos, r)
		}
	}
	rank := map[string]int{access.PermRead: 1, access.PermWrite: 2}
	outPerms := map[string]string{}
	for k, v := range perms {
		if have, ok := p.Permissions[k]; ok && rank[v] <= rank[have] {
			outPerms[k] = v
		}
	}
	if len(outRepos) == 0 || len(outPerms) == 0 {
		return nil, nil, fmt.Errorf("%w: no requested repository/permission is within the profile", ErrScopeDenied)
	}
	return outRepos, outPerms, nil
}
