package agentgw

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"fortik/internal/action"
	"fortik/internal/commap"
)

// Channel names a delegation hop created through agentgateway.
const ChannelA2A = "a2a"

// A2AMetadataKey is where an A2A client may carry its delegation token
// (params.metadata or params.message.metadata) instead of the header.
const A2AMetadataKey = "fortik_delegation"

// mapped is a request expressed in Fortik's model, plus what the transport
// must do around the decision.
type mapped struct {
	System string
	Verb   action.Verb
	Target map[string]any
	Bytes  int64

	// NoDecide marks protocol plumbing that is allowed for an authenticated
	// agent without a decision (MCP initialize and ping only).
	NoDecide bool
	// Malformed is set when the request could not be classified; it is still
	// decided (as UNKNOWN, recorded and denied) and always refused.
	Malformed string
	// Delegate: an A2A call that hands work to another agent. On allow the
	// observer issues a token that the callout injects upstream.
	Delegate bool
	// MetaToken is a delegation token found in A2A params metadata.
	MetaToken string
	// RPCID is the JSON-RPC id (echoed in a JSON-RPC refusal body).
	RPCID json.RawMessage
}

func unknown(system, reason string, target map[string]any) mapped {
	if target == nil {
		target = map[string]any{}
	}
	target["reason"] = reason
	return mapped{System: system, Verb: "UNKNOWN", Target: target, Malformed: reason}
}

var (
	methodPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_/.-]{0,63}$`)
	errBatch      = errors.New("JSON-RPC batch requests are not allowed")
)

type rpcEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// parseRPC parses one JSON-RPC 2.0 request. Batches, duplicate keys anywhere
// in the document (a parser-differential smuggling vector), unknown envelope
// fields and trailing data are errors.
func parseRPC(body []byte) (rpcEnvelope, error) {
	var env rpcEnvelope
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return env, errors.New("empty body")
	}
	if trimmed[0] == '[' {
		return env, errBatch
	}
	if trimmed[0] != '{' {
		return env, errors.New("body is not a JSON object")
	}
	if err := checkJSON(trimmed); err != nil {
		return env, err
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return env, fmt.Errorf("invalid JSON-RPC envelope: %w", err)
	}
	if env.JSONRPC != "2.0" {
		return env, errors.New(`jsonrpc must be "2.0"`)
	}
	if !methodPattern.MatchString(env.Method) {
		return env, errors.New("invalid JSON-RPC method")
	}
	if len(env.Params) > 0 && env.Params[0] != '{' && string(env.Params) != "null" {
		return env, errors.New("JSON-RPC params must be an object")
	}
	return env, nil
}

// checkJSON verifies body is exactly one JSON value with no duplicate object
// keys at any depth (bounded nesting).
func checkJSON(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := checkValueTokens(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func checkValueTokens(dec *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nested too deeply")
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return fmt.Errorf("invalid JSON: %w", err)
			}
			k, _ := kt.(string)
			// encoding/json matches keys to struct fields case-insensitively
			// (Unicode simple folding) with last-wins, while upstreams match
			// exactly. Reject keys that collide under folding so Fortik and
			// the upstream can never read different members.
			fk := foldKey(k)
			if seen[fk] {
				return fmt.Errorf("duplicate JSON key %q (case-insensitive)", truncate(k, 64))
			}
			seen[fk] = true
			if err := checkValueTokens(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := checkValueTokens(dec, depth+1); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil { // closing delimiter
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

// foldKey canonicalises k so that keys equal under strings.EqualFold (the
// rule encoding/json uses for field matching) map to the same string.
func foldKey(k string) string {
	var b strings.Builder
	for _, r := range k {
		m := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < m {
				m = f
			}
		}
		b.WriteRune(m)
	}
	return b.String()
}

// --- A2A ---------------------------------------------------------------------

type a2aParams struct {
	ID        json.RawMessage `json:"id"`     // tasks/* (and legacy tasks/send)
	TaskID    json.RawMessage `json:"taskId"` // pushNotificationConfig
	Message   *a2aMessage     `json:"message"`
	Metadata  json.RawMessage `json:"metadata"`
	SessionID json.RawMessage `json:"sessionId"`
}

type a2aMessage struct {
	TaskID    json.RawMessage `json:"taskId"`
	ContextID json.RawMessage `json:"contextId"`
	Metadata  json.RawMessage `json:"metadata"`
}

// a2aVerbs maps A2A JSON-RPC methods. DELEGATE methods hand work to the
// target agent; everything not listed is UNKNOWN (denied).
var a2aVerbs = map[string]action.Verb{
	"message/send":                        action.VerbDelegate,
	"message/stream":                      action.VerbDelegate,
	"tasks/send":                          action.VerbDelegate,
	"tasks/sendSubscribe":                 action.VerbDelegate,
	"tasks/get":                           action.VerbRead,
	"tasks/resubscribe":                   action.VerbRead,
	"tasks/pushNotificationConfig/get":    action.VerbRead,
	"tasks/pushNotificationConfig/list":   action.VerbRead,
	"agent/getAuthenticatedExtendedCard":  action.VerbRead,
	"tasks/cancel":                        action.VerbWrite,
	"tasks/pushNotificationConfig/set":    action.VerbWrite,
	"tasks/pushNotificationConfig/delete": action.VerbWrite,
}

// mapA2A maps one HTTP request on an A2A route to the target agent toAgent.
func mapA2A(httpMethod, path, route, toAgent string, body []byte) mapped {
	base := func() map[string]any {
		return map[string]any{"to_agent": toAgent, "route": route, "channel": ChannelA2A}
	}
	switch httpMethod {
	case "GET", "HEAD":
		if strings.HasSuffix(path, "/.well-known/agent.json") || strings.HasSuffix(path, "/.well-known/agent-card.json") {
			t := base()
			t["operation"] = "agent_card"
			return mapped{System: action.SystemA2A, Verb: action.VerbRead, Target: t}
		}
		t := base()
		t["http_method"] = httpMethod
		return unknown(action.SystemA2A, "unsupported A2A GET request", t)
	case "POST":
	default:
		t := base()
		t["http_method"] = httpMethod
		return unknown(action.SystemA2A, "unsupported A2A HTTP method", t)
	}
	env, err := parseRPC(body)
	if err != nil {
		t := base()
		if errors.Is(err, errBatch) {
			return unknown(action.SystemA2A, "batch", t)
		}
		return unknown(action.SystemA2A, "malformed A2A request: "+err.Error(), t)
	}
	t := base()
	t["method"] = env.Method
	verb, ok := a2aVerbs[env.Method]
	if !ok {
		m := unknown(action.SystemA2A, "unknown A2A method", t)
		m.RPCID = env.ID
		return m
	}
	var p a2aParams
	if len(env.Params) > 0 && string(env.Params) != "null" {
		if err := json.Unmarshal(env.Params, &p); err != nil {
			m := unknown(action.SystemA2A, "malformed A2A params", t)
			m.RPCID = env.ID
			return m
		}
	}
	m := mapped{System: action.SystemA2A, Verb: verb, Target: t, Bytes: int64(len(body)), RPCID: env.ID}
	fail := func(reason string) mapped {
		u := unknown(action.SystemA2A, reason, t)
		u.RPCID = env.ID
		return u
	}

	var taskID, contextID string
	var metaTokens []string
	if tok, err := metaToken(p.Metadata); err != nil {
		return fail("malformed A2A metadata")
	} else if tok != "" {
		metaTokens = append(metaTokens, tok)
	}
	switch env.Method {
	case "message/send", "message/stream":
		if p.Message == nil {
			return fail("A2A message is missing")
		}
		if taskID, err = optString(p.Message.TaskID); err != nil {
			return fail("malformed A2A message.taskId")
		}
		if contextID, err = optString(p.Message.ContextID); err != nil {
			return fail("malformed A2A message.contextId")
		}
		if tok, err := metaToken(p.Message.Metadata); err != nil {
			return fail("malformed A2A message metadata")
		} else if tok != "" {
			metaTokens = append(metaTokens, tok)
		}
	case "tasks/send", "tasks/sendSubscribe":
		if taskID, err = optString(p.ID); err != nil {
			return fail("malformed A2A task id")
		}
		if p.Message != nil {
			if tok, err := metaToken(p.Message.Metadata); err != nil {
				return fail("malformed A2A message metadata")
			} else if tok != "" {
				metaTokens = append(metaTokens, tok)
			}
		}
	case "tasks/get", "tasks/cancel", "tasks/resubscribe":
		if taskID, err = optString(p.ID); err != nil || taskID == "" {
			return fail("A2A task id is missing or malformed")
		}
	case "tasks/pushNotificationConfig/get", "tasks/pushNotificationConfig/list",
		"tasks/pushNotificationConfig/set", "tasks/pushNotificationConfig/delete":
		id, err1 := optString(p.TaskID)
		alt, err2 := optString(p.ID)
		if err1 != nil || err2 != nil {
			return fail("malformed A2A task id")
		}
		taskID = id
		if taskID == "" {
			taskID = alt
		}
	}
	for _, tok := range metaTokens[min(1, len(metaTokens)):] {
		if tok != metaTokens[0] {
			return fail("conflicting delegation tokens in A2A metadata")
		}
	}
	if len(metaTokens) > 0 {
		m.MetaToken = metaTokens[0]
	}
	if taskID != "" {
		t["task_id"] = taskID
	}
	if contextID != "" {
		t["context_id"] = contextID
	}
	switch env.Method {
	case "tasks/cancel":
		t["operation"] = "cancel"
	case "tasks/get":
		t["operation"] = "get"
	}
	if verb == action.VerbDelegate {
		m.Delegate = true
	}
	return m
}

// optString reads an optional JSON string id: absent/null is "", anything
// other than a bounded printable string is an error.
func optString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", errors.New("not a string")
	}
	if len(s) > 256 || !printable(s) {
		return "", errors.New("id too long or not printable")
	}
	return s, nil
}

// metaToken extracts metadata.fortik_delegation (absent = "").
func metaToken(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var md map[string]json.RawMessage
	if err := json.Unmarshal(raw, &md); err != nil {
		return "", err
	}
	v, ok := md[A2AMetadataKey]
	if !ok {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", errors.New("fortik_delegation is not a string")
	}
	return s, nil
}

func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// --- MCP ---------------------------------------------------------------------

// mcpReadMethods are MCP methods that only read. resources/subscribe,
// resources/unsubscribe and completion/complete are listed for completeness:
// agentgateway v1.6.0 only runs the response phase for them, so they are not
// gated before execution (docs/spikes/agentgateway-spike.md, finding 5).
var mcpReadMethods = map[string]bool{
	"tools/list":               true,
	"resources/list":           true,
	"resources/templates/list": true,
	"resources/read":           true,
	"resources/subscribe":      true,
	"resources/unsubscribe":    true,
	"prompts/list":             true,
	"prompts/get":              true,
	"completion/complete":      true,
	"logging/setLevel":         true,
}

// mcpNoDecide are allowed for an authenticated agent without a decision:
// session setup and liveness carry no tool call and no data. Notifications
// are never sent to the guardrail by agentgateway (and carry no request).
func mcpNoDecide(method string) bool {
	return method == "initialize" || method == "ping" || strings.HasPrefix(method, "notifications/")
}

type mcpCallParams struct {
	Name      *string         `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	URI       *string         `json:"uri"`
}

// mapMCP maps one MCP method call on server (ext_mcp gives the parsed
// method and the raw params).
func mapMCP(verbs *ToolVerbs, server, route, method string, params []byte) mapped {
	t := map[string]any{"server": server, "route": route, "method": method}
	if !methodPattern.MatchString(method) {
		delete(t, "method")
		return unknown(action.SystemMCP, "invalid MCP method", t)
	}
	if mcpNoDecide(method) {
		return mapped{System: action.SystemMCP, Verb: action.VerbRead, Target: t, NoDecide: true}
	}
	var p mcpCallParams
	if len(bytes.TrimSpace(params)) > 0 {
		if err := checkJSON(params); err != nil {
			return unknown(action.SystemMCP, "malformed MCP params: "+err.Error(), t)
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return unknown(action.SystemMCP, "malformed MCP params", t)
		}
	}
	switch {
	case method == "tools/call":
		if p.Name == nil {
			return unknown(action.SystemMCP, "tools/call without a tool name", t)
		}
		verb, source := verbs.Verb(server, *p.Name)
		if verb == "UNKNOWN" {
			return unknown(action.SystemMCP, "invalid MCP tool name", t)
		}
		t["tool"] = *p.Name
		t["verb_source"] = source
		return mapped{System: action.SystemMCP, Verb: verb, Target: t, Bytes: int64(len(params))}
	case mcpReadMethods[method]:
		if method == "resources/read" && p.URI != nil {
			t["resource"] = truncate(*p.URI, 256)
		}
		if method == "prompts/get" && p.Name != nil {
			t["prompt"] = truncate(*p.Name, 128)
		}
		return mapped{System: action.SystemMCP, Verb: action.VerbRead, Target: t, Bytes: int64(len(params))}
	default:
		return unknown(action.SystemMCP, "unknown MCP method", t)
	}
}

// --- HTTP egress ---------------------------------------------------------------

// hostMatcher decides whether a domain is inside the company
// (config.AgentGWConfig.InternalHosts: exact names, or "*.example.com" /
// ".example.com" for a domain and its subdomains).
type hostMatcher struct {
	exact    map[string]bool
	suffixes []string
}

func newHostMatcher(hosts []string) hostMatcher {
	m := hostMatcher{exact: map[string]bool{}}
	for _, h := range hosts {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		switch {
		case h == "":
		case strings.HasPrefix(h, "*."):
			m.suffixes = append(m.suffixes, h[1:])
		case strings.HasPrefix(h, "."):
			m.suffixes = append(m.suffixes, h)
		default:
			m.exact[h] = true
		}
	}
	return m
}

func (m hostMatcher) internal(domain string) bool {
	if m.exact[domain] {
		return true
	}
	for _, s := range m.suffixes {
		if strings.HasSuffix(domain, s) || domain == s[1:] {
			return true
		}
	}
	return false
}

var hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*$`)

// normalizeHost turns an :authority into a lowercase host without port.
func normalizeHost(authority string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(authority))
	if h == "" {
		return "", errors.New("missing :authority")
	}
	if strings.ContainsAny(h, "@/\\ ") {
		return "", errors.New("malformed :authority")
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.Trim(h, "[]"), ".")
	if ip := net.ParseIP(h); ip != nil {
		return ip.String(), nil
	}
	if len(h) > 253 || !hostnamePattern.MatchString(h) {
		return "", errors.New("malformed host name")
	}
	return h, nil
}

// mapHTTP maps an HTTP egress request. READ for GET/HEAD/OPTIONS without a
// body; EXPORT for anything carrying data (a body, or a non-read method) to
// an external host; DELETE for DELETE; WRITE for other internal changes.
func mapHTTP(hm hostMatcher, routeDomain, route, method, authority, path string, hasBody bool, bodyLen int64) mapped {
	t := map[string]any{"route": route, "method": method}
	domain, err := normalizeHost(authority)
	if err != nil {
		return unknown(action.SystemHTTP, err.Error(), t)
	}
	t["domain"] = domain
	if routeDomain != "" && domain != routeDomain {
		return unknown(action.SystemHTTP, "request host does not match the route's domain", t)
	}
	external := !hm.internal(domain)
	t["external"] = external
	p, q, _ := strings.Cut(path, "?")
	if p != "" {
		t["path"] = truncate(p, 256)
	}
	// The query itself is not stored (it may be the exfiltrated data); only
	// a summary of encoded-looking parameters, for POL-671.
	if ps := commap.SummarizeRawQuery(q); len(ps) > 0 {
		t["encoded_params"] = ps
	}
	read := method == "GET" || method == "HEAD" || method == "OPTIONS"
	var verb action.Verb
	switch {
	case !methodPattern.MatchString(method):
		return unknown(action.SystemHTTP, "invalid HTTP method", t)
	case external && hasBody:
		verb = action.VerbExport
	case read:
		verb = action.VerbRead
	case method == "DELETE":
		verb = action.VerbDelete
	case external:
		verb = action.VerbExport
	default:
		verb = action.VerbWrite
	}
	return mapped{System: action.SystemHTTP, Verb: verb, Target: t, Bytes: bodyLen}
}
