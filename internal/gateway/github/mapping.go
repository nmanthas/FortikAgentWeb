package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"fortik/internal/action"
	"fortik/internal/authz"
	ghbroker "fortik/internal/broker/github"
	"fortik/internal/gateway"
)

// Operations (target.operation) as named by policies/fortik/rules/github.rego.
const (
	OpRead           = "read"
	OpPush           = "push"
	OpForcePush      = "force_push"
	OpDeleteBranch   = "delete_branch"
	OpCreatePR       = "create_pr"
	OpClosePR        = "close_pr"
	OpMergePR        = "merge_pr"
	OpDeleteRepo     = "delete_repo"
	OpSetSecret      = "set_secret"
	OpCreateWebhook  = "create_webhook"
	OpAddDeployKey   = "add_deploy_key"
	OpRunWorkflow    = "run_workflow"
	OpDeleteRelease  = "delete_release"
	OpComment        = "comment"
	OpCollaborator   = "collaborator_grant"
	OpTeamRepoGrant  = "team_repo_grant"
	OpBranchProtect  = "branch_protection"
	OpGitObject      = "create_git_object"
	OpUnknown        = "unknown"
	verbUnknown      = action.Verb("UNKNOWN")
	gatewayPrefix    = "/gw/github"
	maxTargetPathLen = 256
)

// record kinds: which previous state Forward captures for record_ref.
const (
	recordNone  = ""
	recordRef   = "ref"   // the ref itself (push, force_push, delete_branch, create ref, contents)
	recordMerge = "merge" // the PR's base ref
	recordPR    = "pr"    // the PR state (close_pr)
)

// opState is the adapter-private part of an Op (Map → Enrich → Forward).
type opState struct {
	method   string
	upPath   string // escaped upstream path ("/repos/..."), exactly what was mapped
	rawQuery string

	owner, name, repo string // repo = lower(owner/name); "" when not repo-scoped
	operation         string
	unknown           bool

	branch            string // heads branch name (case preserved) or "refs/tags/..." for tag refs
	branchFromDefault bool   // contents API without body.branch: Enrich resolves the default branch
	pr                int
	path              string            // contents path
	ref               string            // ref for record_ref, without "refs/" ("heads/x")
	resultSHA         string            // sha the ref will point at after the action, when the request names it
	perms             map[string]string // installation-token permissions the request needs
	record            string            // record kind if the decision asks for record_ref
	needProtection    bool

	// notConfigured is set by Enrich when the integration is missing, so the
	// decision is still recorded and Forward answers 503.
	notConfigured error
}

// Map turns an agent request into an Op. It never returns an error: every
// request it cannot classify gets verb UNKNOWN, which policy denies (POL-002).
func (a *Adapter) Map(_ context.Context, p authz.Principal, r *http.Request, body []byte) (gateway.Op, error) {
	st := &opState{method: r.Method, rawQuery: r.URL.RawQuery, perms: map[string]string{}}
	act := action.Action{
		AgentID:        p.Name,
		InstanceID:     p.InstanceID,
		System:         action.SystemGitHub,
		Source:         action.SourceAppGateway,
		Target:         map[string]any{},
		PayloadSummary: action.PayloadSummary{Bytes: int64(len(body))},
	}
	verb, endpoint := classify(st, r.URL.EscapedPath(), body)
	act.Verb = verb
	act.Target["operation"] = st.operation
	act.Target["method"] = r.Method
	act.Target["endpoint"] = endpoint
	if st.repo != "" {
		act.Target["repo"] = st.repo
	}
	if st.branch != "" {
		act.Target["branch"] = st.branch
	}
	if st.path != "" {
		act.Target["paths"] = []string{st.path}
	}
	if st.pr > 0 {
		act.Target["pr"] = st.pr
	}
	if st.unknown {
		act.Target["path"] = truncate(st.upPath, maxTargetPathLen)
	}
	act.Reversible = st.record != recordNone
	return gateway.Op{Action: act, Body: body, State: st}, nil
}

// classify fills st and returns the verb and a templated endpoint for the Diary.
func classify(st *opState, escapedPath string, body []byte) (action.Verb, string) {
	unknown := func(endpoint string) (action.Verb, string) {
		st.unknown, st.operation, st.record, st.needProtection = true, OpUnknown, recordNone, false
		st.perms = map[string]string{}
		return verbUnknown, endpoint
	}
	rel := escapedPath
	if rel == gatewayPrefix {
		rel = "/"
	} else if strings.HasPrefix(rel, gatewayPrefix+"/") {
		rel = strings.TrimPrefix(rel, gatewayPrefix)
	}
	st.upPath = rel
	segs, ok := splitPath(rel)
	method := st.method
	if !ok {
		return unknown(method + " (malformed path)")
	}
	// Repository context: /repos/{owner}/{repo}/... or the team-grant path
	// /orgs/{org}/teams/{team}/repos/{owner}/{repo}.
	var rest []string
	repoScoped := false
	if len(segs) >= 3 && segs[0] == "repos" {
		if !ghbroker.ValidOwner(segs[1]) || !ghbroker.ValidName(segs[2]) {
			return unknown(method + " /repos/{invalid}")
		}
		st.owner, st.name = segs[1], segs[2]
		rest, repoScoped = segs[3:], true
	} else if len(segs) == 7 && segs[0] == "orgs" && segs[2] == "teams" && segs[4] == "repos" &&
		ghbroker.ValidOwner(segs[5]) && ghbroker.ValidName(segs[6]) {
		st.owner, st.name = segs[5], segs[6]
	}
	if st.owner != "" {
		st.repo = strings.ToLower(st.owner + "/" + st.name)
	}

	if method == http.MethodGet || method == http.MethodHead {
		st.operation = OpRead
		if repoScoped {
			st.perms = readPerms(rest)
			return action.VerbRead, method + " /repos/{owner}/{repo}" + templ(rest)
		}
		return action.VerbRead, method + " " + truncate(rel, maxTargetPathLen)
	}
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return unknown(method + " (unsupported method)")
	}
	// GitHub may merge query parameters into a write's parameters
	// (e.g. ?force=true); Fortik classifies the JSON body only, so a write
	// with a query string is refused.
	if st.rawQuery != "" {
		return unknown(method + " (query string on a write)")
	}
	fields, ok := parseObject(body)
	if !ok {
		return unknown(method + " (body is not one unambiguous JSON object)")
	}

	// Team repository grant (not under /repos).
	if !repoScoped {
		if st.repo != "" && (method == http.MethodPut || method == http.MethodDelete) {
			st.operation, st.perms = OpTeamRepoGrant, map[string]string{"administration": "write"}
			return action.VerbGrant, method + " /orgs/{org}/teams/{team}/repos/{owner}/{repo}"
		}
		return unknown(method + " " + truncate(rel, maxTargetPathLen))
	}
	at := func(i int) string {
		if i < len(rest) {
			return rest[i]
		}
		return ""
	}
	base := method + " /repos/{owner}/{repo}"
	switch {
	case len(rest) == 0 && method == http.MethodDelete:
		st.operation, st.perms = OpDeleteRepo, map[string]string{"administration": "write"}
		return action.VerbDelete, base

	case len(rest) == 2 && at(0) == "git" && at(1) == "refs" && method == http.MethodPost:
		ref, ok1 := str(fields, "ref")
		newSHA, ok2 := str(fields, "sha")
		if !ok1 || !ok2 || !validFullRef(ref) {
			return unknown(base + "/git/refs (invalid ref)")
		}
		st.operation, st.perms = OpPush, map[string]string{"contents": "write"}
		st.ref, st.resultSHA = strings.TrimPrefix(ref, "refs/"), newSHA
		if b, isHead := strings.CutPrefix(ref, "refs/heads/"); isHead {
			st.branch, st.needProtection = b, true
		} else {
			st.branch = ref
		}
		st.record = recordRef
		return action.VerbWrite, base + "/git/refs"

	case len(rest) == 2 && at(0) == "git" && (at(1) == "blobs" || at(1) == "trees" || at(1) == "commits" || at(1) == "tags") && method == http.MethodPost:
		// Unreferenced git objects (the REST way to build a commit); nothing
		// changes until a ref update, which is classified on its own.
		st.operation, st.perms = OpGitObject, map[string]string{"contents": "write"}
		return action.VerbWrite, base + "/git/" + at(1)

	case len(rest) >= 4 && at(0) == "git" && at(1) == "refs" && at(2) == "heads" && method == http.MethodPatch:
		b := strings.Join(rest[3:], "/")
		force, present, okF := boolean(fields, "force")
		newSHA, okS := str(fields, "sha")
		if !validBranch(b) || (present && !okF) || !okS {
			return unknown(base + "/git/refs/heads/{branch} (invalid body)")
		}
		st.operation = OpPush
		if force {
			st.operation = OpForcePush
		}
		st.branch, st.ref, st.needProtection, st.record = b, "heads/"+b, true, recordRef
		st.resultSHA = newSHA
		st.perms = map[string]string{"contents": "write"}
		return action.VerbWrite, base + "/git/refs/heads/{branch}"

	case len(rest) >= 4 && at(0) == "git" && at(1) == "refs" && at(2) == "heads" && method == http.MethodDelete:
		b := strings.Join(rest[3:], "/")
		if !validBranch(b) {
			return unknown(base + "/git/refs/heads/{branch} (invalid branch)")
		}
		st.operation, st.branch, st.ref, st.needProtection, st.record = OpDeleteBranch, b, "heads/"+b, true, recordRef
		st.perms = map[string]string{"contents": "write"}
		return action.VerbDelete, base + "/git/refs/heads/{branch}"

	case len(rest) >= 4 && at(0) == "git" && at(1) == "refs" && at(2) == "tags" && method == http.MethodDelete:
		st.operation, st.branch = OpDeleteRelease, "refs/tags/"+strings.Join(rest[3:], "/")
		st.perms = map[string]string{"contents": "write"}
		return action.VerbDelete, base + "/git/refs/tags/{tag}"

	case len(rest) >= 2 && at(0) == "contents" && (method == http.MethodPut || method == http.MethodDelete):
		path := strings.Join(rest[1:], "/")
		b, present, okB := strOpt(fields, "branch")
		if !okB || (present && !validBranch(b)) {
			return unknown(base + "/contents/{path} (invalid branch)")
		}
		st.operation, st.path, st.needProtection, st.record = OpPush, path, true, recordRef
		st.perms = map[string]string{"contents": "write"}
		if strings.HasPrefix(path, ".github/workflows/") {
			st.perms["workflows"] = "write"
		}
		if present {
			st.branch, st.ref = b, "heads/"+b
		} else {
			st.branchFromDefault = true
		}
		return action.VerbWrite, base + "/contents/{path}"

	case len(rest) == 1 && at(0) == "pulls" && method == http.MethodPost:
		b, ok := str(fields, "base")
		if !ok || !validBranch(b) {
			return unknown(base + "/pulls (invalid base)")
		}
		st.operation, st.branch = OpCreatePR, b
		st.perms = map[string]string{"pull_requests": "write"}
		return action.VerbWrite, base + "/pulls"

	case len(rest) == 2 && at(0) == "pulls" && method == http.MethodPatch:
		n, okN := prNumber(at(1))
		state, okS := str(fields, "state")
		if !okN || !okS || state != "closed" || !onlyKeys(fields, "state", "title", "body") {
			return unknown(base + "/pulls/{number}")
		}
		st.operation, st.pr, st.record = OpClosePR, n, recordPR
		st.perms = map[string]string{"pull_requests": "write"}
		return action.VerbWrite, base + "/pulls/{number}"

	case len(rest) == 3 && at(0) == "pulls" && at(2) == "merge" && method == http.MethodPut:
		n, okN := prNumber(at(1))
		if !okN {
			return unknown(base + "/pulls/{number}/merge")
		}
		st.operation, st.pr, st.needProtection, st.record = OpMergePR, n, true, recordMerge
		st.perms = map[string]string{"contents": "write", "pull_requests": "write"}
		return action.VerbWrite, base + "/pulls/{number}/merge"

	case len(rest) == 2 && at(0) == "collaborators" && (method == http.MethodPut || method == http.MethodDelete):
		st.operation, st.perms = OpCollaborator, map[string]string{"administration": "write"}
		return action.VerbGrant, base + "/collaborators/{username}"

	case len(rest) >= 3 && at(0) == "branches":
		i := indexOf(rest, "protection", 2)
		if i < 0 {
			return unknown(base + "/branches/{branch}/...")
		}
		st.operation, st.branch = OpBranchProtect, strings.Join(rest[1:i], "/")
		st.perms = map[string]string{"administration": "write"}
		return action.VerbGrant, base + "/branches/{branch}/protection" + templ(rest[i+1:])

	case len(rest) == 3 && at(0) == "actions" && at(1) == "secrets" && method == http.MethodPut:
		st.operation, st.perms = OpSetSecret, map[string]string{"secrets": "write"}
		return action.VerbWrite, base + "/actions/secrets/{name}"

	case len(rest) == 1 && at(0) == "hooks" && method == http.MethodPost:
		st.operation, st.perms = OpCreateWebhook, map[string]string{"repository_hooks": "write"}
		return action.VerbWrite, base + "/hooks"

	case len(rest) == 1 && at(0) == "keys" && method == http.MethodPost:
		st.operation, st.perms = OpAddDeployKey, map[string]string{"administration": "write"}
		return action.VerbWrite, base + "/keys"

	case len(rest) == 4 && at(0) == "actions" && at(1) == "workflows" && at(3) == "dispatches" && method == http.MethodPost:
		ref, present, okR := strOpt(fields, "ref")
		if !okR {
			return unknown(base + "/actions/workflows/{id}/dispatches")
		}
		if present {
			st.branch = strings.TrimPrefix(ref, "refs/heads/")
		}
		st.operation, st.perms = OpRunWorkflow, map[string]string{"actions": "write"}
		return action.VerbExecute, base + "/actions/workflows/{id}/dispatches"

	case method == http.MethodDelete && at(0) == "releases" && (len(rest) == 2 || (len(rest) == 3 && at(1) == "assets")):
		st.operation, st.perms = OpDeleteRelease, map[string]string{"contents": "write"}
		return action.VerbDelete, base + "/releases" + templ(rest[1:])

	case len(rest) == 3 && (at(0) == "issues" || at(0) == "pulls") && at(2) == "comments" && method == http.MethodPost:
		n, okN := prNumber(at(1))
		if !okN {
			return unknown(base + "/" + at(0) + "/{number}/comments")
		}
		st.operation, st.pr = OpComment, n
		st.perms = map[string]string{commentPerm(at(0)): "write"}
		return action.VerbWrite, base + "/" + at(0) + "/{number}/comments"

	case len(rest) == 3 && (at(0) == "issues" || at(0) == "pulls") && at(1) == "comments" && method == http.MethodPatch:
		st.operation = OpComment
		st.perms = map[string]string{commentPerm(at(0)): "write"}
		return action.VerbWrite, base + "/" + at(0) + "/comments/{id}"
	}
	return unknown(base + templ(rest))
}

func commentPerm(kind string) string {
	if kind == "pulls" {
		return "pull_requests"
	}
	return "issues"
}

// readPerms is the narrowest installation permission a repository GET needs.
// Anything unrecognised gets metadata:read only, so GitHub itself refuses
// reads beyond it.
func readPerms(rest []string) map[string]string {
	if len(rest) == 0 {
		return map[string]string{"metadata": "read"}
	}
	switch rest[0] {
	case "pulls":
		return map[string]string{"pull_requests": "read"}
	case "issues":
		return map[string]string{"issues": "read"}
	case "contents", "git", "branches", "commits", "compare", "tarball", "zipball", "readme", "tags", "releases":
		return map[string]string{"contents": "read"}
	}
	return map[string]string{"metadata": "read"}
}

// templ renders path segments for the Diary without identifiers (numbers,
// names, file paths): resource words are kept, everything else is "{…}".
func templ(rest []string) string {
	var b strings.Builder
	for i, s := range rest {
		if i >= 6 {
			b.WriteString("/…")
			break
		}
		b.WriteByte('/')
		if resourceWords[s] {
			b.WriteString(s)
		} else {
			b.WriteString("{…}")
		}
	}
	return b.String()
}

var resourceWords = map[string]bool{
	"git": true, "refs": true, "ref": true, "heads": true, "tags": true, "contents": true, "pulls": true, "issues": true,
	"comments": true, "merge": true, "branches": true, "protection": true, "commits": true, "compare": true, "releases": true,
	"assets": true, "collaborators": true, "hooks": true, "keys": true, "actions": true, "secrets": true, "workflows": true,
	"dispatches": true, "runs": true, "readme": true, "tarball": true, "zipball": true, "reviews": true, "labels": true,
	"files": true, "trees": true, "blobs": true, "statuses": true, "status": true, "check-runs": true, "environments": true,
	"variables": true, "deployments": true, "forks": true, "rulesets": true,
}

// splitPath splits an escaped path into decoded segments. It rejects
// anything that could be parsed differently by GitHub than by Fortik: empty
// segments, "." and "..", encoded slashes, backslashes, control characters
// and invalid escapes.
func splitPath(escaped string) ([]string, bool) {
	if !strings.HasPrefix(escaped, "/") {
		return nil, false
	}
	trimmed := strings.TrimPrefix(escaped, "/")
	if trimmed == "" {
		return nil, true
	}
	parts := strings.Split(trimmed, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s, err := url.PathUnescape(p)
		if err != nil || s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\") {
			return nil, false
		}
		for _, r := range s {
			if unicode.IsControl(r) {
				return nil, false
			}
		}
		out = append(out, s)
	}
	return out, true
}

// parseObject parses a request body as one JSON object, keeping raw values by
// exact key. It rejects duplicate keys, including case-insensitive
// duplicates: Go's decoder matches fields case-insensitively and GitHub
// exactly, so {"force":true,"Force":false} must never classify as a plain
// push. An empty body is an empty object.
func parseObject(body []byte) (map[string]json.RawMessage, bool) {
	out := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(body)) == 0 {
		return out, true
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false
	}
	seen := map[string]bool{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, false
		}
		k, ok := kt.(string)
		if !ok {
			return nil, false
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, false
		}
		fold := strings.ToLower(k)
		if seen[fold] {
			return nil, false
		}
		seen[fold] = true
		out[k] = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, false // trailing data
	}
	return out, true
}

// str returns a required string field.
func str(m map[string]json.RawMessage, k string) (string, bool) {
	v, present, ok := strOpt(m, k)
	return v, present && ok && v != ""
}

// strOpt returns an optional string field; ok is false if present but not a string.
func strOpt(m map[string]json.RawMessage, k string) (val string, present, ok bool) {
	raw, present := m[k]
	if !present || string(raw) == "null" {
		return "", false, true
	}
	if err := json.Unmarshal(raw, &val); err != nil {
		return "", true, false
	}
	return val, true, true
}

// boolean returns an optional boolean field; ok is false if present but not a bool.
func boolean(m map[string]json.RawMessage, k string) (val, present, ok bool) {
	raw, present := m[k]
	if !present || string(raw) == "null" {
		return false, false, true
	}
	if err := json.Unmarshal(raw, &val); err != nil {
		return false, true, false
	}
	return val, true, true
}

func onlyKeys(m map[string]json.RawMessage, allowed ...string) bool {
	for k := range m {
		ok := false
		for _, a := range allowed {
			if k == a {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func prNumber(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil && n > 0 && strconv.Itoa(n) == s
}

func indexOf(s []string, v string, from int) int {
	for i := from; i < len(s); i++ {
		if s[i] == v {
			return i
		}
	}
	return -1
}

// validBranch accepts git branch names Fortik can reason about.
func validBranch(b string) bool {
	if b == "" || len(b) > 255 || strings.HasPrefix(b, "/") || strings.HasSuffix(b, "/") || strings.HasSuffix(b, ".lock") ||
		strings.HasPrefix(b, "refs/") || strings.Contains(b, "..") || strings.Contains(b, "//") || strings.Contains(b, "@{") {
		return false
	}
	for _, r := range b {
		if unicode.IsControl(r) || r == ' ' || r == '~' || r == '^' || r == ':' || r == '?' || r == '*' || r == '[' || r == '\\' {
			return false
		}
	}
	return true
}

// validFullRef accepts refs/heads/<branch> and refs/tags/<tag>.
func validFullRef(ref string) bool {
	if b, ok := strings.CutPrefix(ref, "refs/heads/"); ok {
		return validBranch(b)
	}
	if t, ok := strings.CutPrefix(ref, "refs/tags/"); ok {
		return validBranch(t)
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
