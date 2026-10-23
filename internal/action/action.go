// Package action defines the normalized Action that every interception point
// (agentgateway, app gateway, Postgres proxy, coding-agent hook) must produce
// before Fortik decides anything. Field names follow the MVP plan's Action
// schema exactly; adapters must not invent parallel classification concepts.
package action

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

// Verb is a normalized business verb. Every adapter maps its API calls to one.
type Verb string

const (
	VerbRead     Verb = "READ"
	VerbWrite    Verb = "WRITE"
	VerbSend     Verb = "SEND"
	VerbSpend    Verb = "SPEND"
	VerbExecute  Verb = "EXECUTE"
	VerbDelete   Verb = "DELETE"
	VerbExport   Verb = "EXPORT"
	VerbGrant    Verb = "GRANT"    // permission or IAM change
	VerbDelegate Verb = "DELEGATE" // spawn or call another agent
	VerbRemember Verb = "REMEMBER" // long-term memory write
)

var knownVerbs = map[Verb]bool{
	VerbRead: true, VerbWrite: true, VerbSend: true, VerbSpend: true, VerbExecute: true,
	VerbDelete: true, VerbExport: true, VerbGrant: true, VerbDelegate: true, VerbRemember: true,
}

// KnownVerb reports whether v is one of the ten normalized verbs.
func KnownVerb(v Verb) bool { return knownVerbs[v] }

// Verbs returns all normalized verbs in a stable order.
func Verbs() []Verb {
	out := make([]Verb, 0, len(knownVerbs))
	for v := range knownVerbs {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Systems Fortik knows how to reason about. An unknown system is classified
// by the policy's fail-closed default rule, never silently allowed.
const (
	SystemGmail    = "gmail"
	SystemDrive    = "drive"
	SystemGitHub   = "github"
	SystemAWS      = "aws"
	SystemPostgres = "postgres"
	SystemMemory   = "memory"
	SystemMCP      = "mcp"
	SystemA2A      = "a2a"
	SystemHTTP     = "http"
	SystemShell    = "shell"
)

// Source identifies which interception point produced the Action.
const (
	SourcePGProxy      = "pgproxy"
	SourceAppGateway   = "app_gateway"
	SourceAgentGateway = "agentgateway"
	SourceHook         = "hook"
	SourceAPI          = "api"
)

// PayloadSummary describes the payload without carrying its contents.
// Fortik records summaries and data labels, never the private payload itself.
type PayloadSummary struct {
	Attachments  int      `json:"attachments,omitempty"`
	Bytes        int64    `json:"bytes,omitempty"`
	DataLabels   []string `json:"data_labels,omitempty"`
	Rows         *int64   `json:"rows,omitempty"`          // exact row count when known
	RowsEstimate *int64   `json:"rows_estimate,omitempty"` // planner estimate when exact is unknown
	Recipients   int      `json:"recipients,omitempty"`
}

// Action is one side-effecting (or reading) call an agent wants to make.
type Action struct {
	ActionID       string         `json:"action_id"`
	AgentID        string         `json:"agent_id"`
	InstanceID     string         `json:"instance_id,omitempty"`
	Sponsor        string         `json:"sponsor,omitempty"`
	System         string         `json:"system"`
	Verb           Verb           `json:"verb"`
	Target         map[string]any `json:"target"`
	PayloadSummary PayloadSummary `json:"payload_summary"`
	Reversible     bool           `json:"reversible"`
	EstCostUSD     float64        `json:"est_cost_usd"`
	Chain          []string       `json:"chain,omitempty"`
	TS             time.Time      `json:"ts"`
	Source         string         `json:"source,omitempty"`
}

var (
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)
	systemPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	verbPattern   = regexp.MustCompile(`^[A-Za-z_]{1,32}$`)
)

// ErrInvalid wraps every validation failure so callers can map it to 400.
var ErrInvalid = errors.New("invalid action")

// Validate checks structural validity. An unknown verb is NOT a validation
// error: it is a classification input that the policy fails closed on. A
// structurally broken Action (no agent, no system) is rejected outright.
func (a *Action) Validate() error {
	if a.AgentID == "" || !idPattern.MatchString(a.AgentID) {
		return fmt.Errorf("%w: agent_id is required and must match %s", ErrInvalid, idPattern)
	}
	if a.InstanceID != "" && !idPattern.MatchString(a.InstanceID) {
		return fmt.Errorf("%w: instance_id must match %s", ErrInvalid, idPattern)
	}
	if a.System == "" || !systemPattern.MatchString(a.System) {
		return fmt.Errorf("%w: system is required and must match %s", ErrInvalid, systemPattern)
	}
	if !verbPattern.MatchString(string(a.Verb)) {
		return fmt.Errorf("%w: verb is required and must match %s (unknown well-formed verbs reach policy and fail closed)", ErrInvalid, verbPattern)
	}
	if a.ActionID != "" && !idPattern.MatchString(a.ActionID) {
		return fmt.Errorf("%w: action_id must match %s", ErrInvalid, idPattern)
	}
	if len(a.Chain) > 64 {
		return fmt.Errorf("%w: chain longer than 64 entries", ErrInvalid)
	}
	if a.EstCostUSD < 0 {
		return fmt.Errorf("%w: est_cost_usd must be >= 0", ErrInvalid)
	}
	if a.Source != "" && !knownSources[a.Source] {
		return fmt.Errorf("%w: unknown source %q", ErrInvalid, a.Source)
	}
	if len(a.PayloadSummary.DataLabels) > 64 {
		return fmt.Errorf("%w: more than 64 data labels", ErrInvalid)
	}
	// Target is free-form adapter data: bound it and reject NUL bytes, which
	// Postgres cannot store (a write failure must never become a way to
	// dodge recording or step-down).
	// Check the JSON form (what will be stored), so typed in-process
	// containers (map[string]string, structs, RawMessage) are covered too.
	var generic any
	if b, err := json.Marshal(a.Target); err != nil {
		return fmt.Errorf("%w: target is not JSON-encodable: %v", ErrInvalid, err)
	} else if err := json.Unmarshal(b, &generic); err != nil {
		return fmt.Errorf("%w: target: %v", ErrInvalid, err)
	}
	if err := checkValue(generic, 0); err != nil {
		return fmt.Errorf("%w: target: %v", ErrInvalid, err)
	}
	for _, s := range append(append([]string{}, a.Chain...), a.PayloadSummary.DataLabels...) {
		if strings.ContainsRune(s, 0) || len(s) > 512 {
			return fmt.Errorf("%w: chain/data_labels entries must be <= 512 bytes without NUL", ErrInvalid)
		}
	}
	if b, err := json.Marshal(a.Target); err != nil || len(b) > maxTargetBytes {
		return fmt.Errorf("%w: target must be valid JSON of at most %d bytes", ErrInvalid, maxTargetBytes)
	}
	return nil
}

const maxTargetBytes = 64 << 10

var knownSources = map[string]bool{
	SourcePGProxy: true, SourceAppGateway: true, SourceAgentGateway: true, SourceHook: true, SourceAPI: true,
}

func checkValue(v any, depth int) error {
	if depth > 8 {
		return errors.New("nested deeper than 8 levels")
	}
	switch t := v.(type) {
	case string:
		if strings.ContainsRune(t, 0) {
			return errors.New("string contains a NUL byte")
		}
	case map[string]any:
		for k, x := range t {
			if strings.ContainsRune(k, 0) {
				return errors.New("key contains a NUL byte")
			}
			if err := checkValue(x, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, x := range t {
			if err := checkValue(x, depth+1); err != nil {
				return err
			}
		}
	case []string:
		for _, x := range t {
			if strings.ContainsRune(x, 0) {
				return errors.New("string contains a NUL byte")
			}
		}
	}
	return nil
}

// Normalize fills server-owned fields. Fortik's clock is authoritative for ts;
// a client-supplied ts is kept only in Target["client_ts"] for forensics.
func (a *Action) Normalize(now time.Time) {
	if a.ActionID == "" {
		a.ActionID = NewID("act")
	}
	if !a.TS.IsZero() && a.Target != nil {
		a.Target["client_ts"] = a.TS.UTC().Format(time.RFC3339Nano)
	}
	a.TS = now.UTC()
	if a.Target == nil {
		a.Target = map[string]any{}
	}
	a.Verb = Verb(strings.ToUpper(string(a.Verb)))
	labels := a.PayloadSummary.DataLabels
	if len(labels) > 0 {
		seen := map[string]bool{}
		out := labels[:0]
		for _, l := range labels {
			l = strings.ToLower(strings.TrimSpace(l))
			if l != "" && !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
		sort.Strings(out)
		a.PayloadSummary.DataLabels = out
	}
}

// Hash is SHA256(verb + target + schema), the identity used by swarm
// detection to recognise "the same action" across agents and copies (and by
// approval grants). Volatile target keys (client timestamps) are excluded,
// and a Gmail SEND is identified by who receives it: the recipients as one
// sorted, de-duplicated, lower-cased set without +tags, so reordering them,
// moving one between To, Cc and Bcc, or sending through a draft (each with
// its own draft id) or users/<own address> is still the same call.
func (a *Action) Hash() string {
	t := make(map[string]any, len(a.Target))
	for k, v := range a.Target {
		if k == "client_ts" {
			continue
		}
		t[k] = v
	}
	if a.System == SystemGmail && a.Verb == VerbSend {
		canonicalSend(t)
	}
	tb, _ := json.Marshal(t) // map keys are marshalled sorted
	h := sha256.New()
	h.Write([]byte(a.Verb))
	h.Write([]byte{0})
	h.Write([]byte(a.System))
	h.Write([]byte{0})
	h.Write(tb)
	return hex.EncodeToString(h.Sum(nil))
}

// canonicalSend rewrites a Gmail SEND target to its recipient identity.
func canonicalSend(t map[string]any) {
	if _, ok := t["recipients_unknown"]; ok {
		delete(t, "draft_id")
		delete(t, "endpoint")
		delete(t, "user_id")
		return
	}
	set := map[string]bool{}
	for _, k := range []string{"to", "cc", "bcc"} {
		for _, r := range stringsOf(t[k]) {
			if r = canonicalAddress(r); r != "" {
				set[r] = true
			}
		}
		delete(t, k)
	}
	rs := make([]string, 0, len(set))
	for r := range set {
		rs = append(rs, r)
	}
	sort.Strings(rs)
	t["recipients"] = rs
	delete(t, "draft_id")
	delete(t, "endpoint")
	delete(t, "user_id")
}

func stringsOf(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// canonicalAddress lower-cases an address and drops a +tag from the local
// part (user+x@d and user@d reach the same mailbox at common providers).
func canonicalAddress(r string) string {
	r = strings.ToLower(strings.TrimSpace(r))
	local, domain, ok := strings.Cut(r, "@")
	if !ok {
		return r
	}
	if i := strings.IndexByte(local, '+'); i > 0 {
		local = local[:i]
	}
	return local + "@" + domain
}

// NewID returns a sortable unique id with a type prefix, e.g. act_01J9....
func NewID(prefix string) string {
	return prefix + "_" + ulid.MustNew(ulid.Now(), rand.Reader).String()
}
