// Package mcpclient is Fortik's own client for upstream MCP servers over the
// Streamable HTTP transport. Fortik uses it to check a connection and to
// discover the server's tools (initialize, notifications/initialized,
// tools/list); it never calls a tool.
//
// It is deliberately small: one session per Discover call, no server-sent
// requests, no GET stream. Every failure is an *Error whose Kind says which
// step failed, so the console can tell an expired token from an unreachable
// server.
package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

// RequestedVersion is the protocol version Fortik asks for; Supported are
// the versions it accepts from the server (the negotiated version must be
// one of them).
const RequestedVersion = "2025-06-18"

var Supported = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

// Limits on what one discovery reads.
const (
	MaxBody     = 4 << 20 // bytes of one response
	MaxPages    = 50      // tools/list pages
	MaxTools    = 1000
	MaxDescLen  = 8 << 10
	MaxInstrLen = 4 << 10
)

// Error kinds, in the order a discovery can fail.
const (
	KindUnavailable     = "unavailable"           // network error, timeout, 408/429/5xx
	KindAuthFailed      = "auth_failed"           // 401
	KindTokenExpired    = "token_expired"         // 401 whose message says expired or revoked
	KindPermission      = "permission_denied"     // 403
	KindInitFailed      = "mcp_init_failed"       // initialize refused, malformed or unsupported version
	KindDiscoveryFailed = "tool_discovery_failed" // tools/list refused or malformed
	KindCallFailed      = "tool_call_failed"      // tools/call answered with a protocol error or malformed result
	KindSessionExpired  = "session_expired"       // 404 for a known session: the request was not processed
)

// Error is a failed step. Detail never contains the token.
type Error struct {
	Kind       string
	Step       string // initialize | initialized | tools/list
	HTTPStatus int    // 0 when no HTTP response was received
	Detail     string
}

func (e *Error) Error() string {
	s := e.Kind + " (" + e.Step
	if e.HTTPStatus != 0 {
		s += ", HTTP " + strconv.Itoa(e.HTTPStatus)
	}
	return s + "): " + e.Detail
}

// Client talks to one MCP endpoint with one bearer token.
type Client struct {
	HTTP          *http.Client // must not follow redirects (see NoRedirects)
	Endpoint      string
	Token         string
	ClientName    string
	ClientVersion string
}

// NoRedirects is the CheckRedirect for clients that carry bearer tokens: a
// redirect is reported, never followed.
func NoRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Tool is one discovered tool, as the server described it. Annotations are
// the server's own hints: recorded, never trusted for policy.
type Tool struct {
	Name         string          `json:"name"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"input_schema"`
	OutputSchema json.RawMessage `json:"output_schema,omitempty"`
	Annotations  json.RawMessage `json:"annotations,omitempty"`
}

// Rejected is a tool entry Fortik refused to record, with the reason.
type Rejected struct {
	Name   string `json:"name,omitempty"`
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

// Discovery is the result of one successful initialize + tools/list.
type Discovery struct {
	ProtocolVersion string          `json:"protocol_version"`
	ServerName      string          `json:"server_name"`
	ServerVersion   string          `json:"server_version"`
	Instructions    string          `json:"instructions,omitempty"`
	Capabilities    json.RawMessage `json:"capabilities"`
	HasTools        bool            `json:"has_tools_capability"`
	SessionID       bool            `json:"session_id_issued"`
	Tools           []Tool          `json:"tools"`
	Rejected        []Rejected      `json:"rejected,omitempty"`
	Pages           int             `json:"pages"`
	Duration        time.Duration   `json:"-"`
}

type session struct {
	c       *Client
	id      string // Mcp-Session-Id
	version string // negotiated protocol version
	nextID  atomic.Int64
}

// Discover opens a session, lists every tool and closes the session. It
// performs no tool call.
func (c *Client) Discover(ctx context.Context) (*Discovery, error) {
	start := time.Now()
	s := &session{c: c}
	d, err := s.initialize(ctx)
	if err != nil {
		return nil, err
	}
	defer s.close()
	if err := s.notify(ctx, "notifications/initialized"); err != nil {
		return nil, err
	}
	if err := s.listTools(ctx, d); err != nil {
		return nil, err
	}
	d.Duration = time.Since(start)
	return d, nil
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func (s *session) initialize(ctx context.Context) (*Discovery, error) {
	const step = "initialize"
	params := map[string]any{
		"protocolVersion": RequestedVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": nonEmpty(s.c.ClientName, "fortik"), "version": nonEmpty(s.c.ClientVersion, "dev")},
	}
	raw, hdr, err := s.call(ctx, step, KindInitFailed, "initialize", params)
	if err != nil {
		return nil, err
	}
	s.id = hdr.Get("Mcp-Session-Id")
	if s.id != "" && !validSessionID(s.id) {
		return nil, &Error{Kind: KindInitFailed, Step: step, Detail: "server issued an invalid Mcp-Session-Id (must be visible ASCII)"}
	}
	var res struct {
		ProtocolVersion string          `json:"protocolVersion"`
		Capabilities    json.RawMessage `json:"capabilities"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
		Instructions string `json:"instructions"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, &Error{Kind: KindInitFailed, Step: step, Detail: "initialize result is not the expected object"}
	}
	if res.ProtocolVersion == "" {
		return nil, &Error{Kind: KindInitFailed, Step: step, Detail: "initialize result has no protocolVersion"}
	}
	if !slices.Contains(Supported, res.ProtocolVersion) {
		s.id = "" // the session is unusable; nothing to close politely
		return nil, &Error{Kind: KindInitFailed, Step: step, Detail: fmt.Sprintf("server answered protocol version %q; Fortik supports %s", clip(res.ProtocolVersion, 40), strings.Join(Supported, ", "))}
	}
	s.version = res.ProtocolVersion
	caps := map[string]json.RawMessage{}
	if len(res.Capabilities) > 0 && string(res.Capabilities) != "null" {
		if err := json.Unmarshal(res.Capabilities, &caps); err != nil {
			return nil, &Error{Kind: KindInitFailed, Step: step, Detail: "initialize capabilities is not an object"}
		}
	}
	_, hasTools := caps["tools"]
	capsJSON := res.Capabilities
	if len(capsJSON) == 0 || string(capsJSON) == "null" {
		capsJSON = json.RawMessage("{}")
	}
	return &Discovery{
		ProtocolVersion: res.ProtocolVersion,
		ServerName:      clip(res.ServerInfo.Name, 200),
		ServerVersion:   clip(res.ServerInfo.Version, 100),
		Instructions:    clip(res.Instructions, MaxInstrLen),
		Capabilities:    capsJSON,
		HasTools:        hasTools,
		SessionID:       s.id != "",
	}, nil
}

var toolName = regexp.MustCompile(`^[A-Za-z0-9_.\-/]{1,128}$`)

func (s *session) listTools(ctx context.Context, d *Discovery) error {
	const step = "tools/list"
	seen := map[string]int{} // name -> index in d.Tools, -1 once rejected as a duplicate
	firstIndex := map[string]int{}
	cursor := ""
	index := 0
	for page := 1; ; page++ {
		if page > MaxPages {
			return &Error{Kind: KindDiscoveryFailed, Step: step, Detail: fmt.Sprintf("more than %d pages of tools", MaxPages)}
		}
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		raw, _, err := s.call(ctx, step, KindDiscoveryFailed, "tools/list", params)
		if err != nil {
			return err
		}
		var res struct {
			Tools      *[]json.RawMessage `json:"tools"`
			NextCursor string             `json:"nextCursor"`
		}
		if err := json.Unmarshal(raw, &res); err != nil || res.Tools == nil {
			return &Error{Kind: KindDiscoveryFailed, Step: step, Detail: "tools/list result has no tools array"}
		}
		d.Pages = page
		for _, t := range *res.Tools {
			if index >= MaxTools {
				return &Error{Kind: KindDiscoveryFailed, Step: step, Detail: fmt.Sprintf("more than %d tools", MaxTools)}
			}
			tool, reason := parseTool(t)
			switch {
			case reason != "":
				d.Rejected = append(d.Rejected, Rejected{Name: tool.Name, Index: index, Reason: reason})
			default:
				if at, dup := seen[tool.Name]; dup {
					// Two definitions of one name: neither can be trusted.
					if at >= 0 {
						d.Rejected = append(d.Rejected, Rejected{Name: tool.Name, Index: firstIndex[tool.Name], Reason: "duplicate tool name: every definition of it is excluded"})
						d.Tools[at].Name = ""
						seen[tool.Name] = -1
					}
					d.Rejected = append(d.Rejected, Rejected{Name: tool.Name, Index: index, Reason: "duplicate tool name: every definition of it is excluded"})
				} else {
					seen[tool.Name] = len(d.Tools)
					firstIndex[tool.Name] = index
					d.Tools = append(d.Tools, tool)
				}
			}
			index++
		}
		if res.NextCursor == "" {
			break
		}
		if res.NextCursor == cursor {
			return &Error{Kind: KindDiscoveryFailed, Step: step, Detail: "tools/list returned the same cursor twice"}
		}
		cursor = res.NextCursor
	}
	d.Tools = slices.DeleteFunc(d.Tools, func(t Tool) bool { return t.Name == "" })
	slices.SortFunc(d.Tools, func(a, b Tool) int { return strings.Compare(a.Name, b.Name) })
	return nil
}

// parseTool validates one tool definition. The returned reason is "" when
// the tool is usable.
func parseTool(raw json.RawMessage) (Tool, string) {
	var t struct {
		Name         *string         `json:"name"`
		Title        string          `json:"title"`
		Description  string          `json:"description"`
		InputSchema  json.RawMessage `json:"inputSchema"`
		OutputSchema json.RawMessage `json:"outputSchema"`
		Annotations  json.RawMessage `json:"annotations"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return Tool{}, "not a tool object"
	}
	if t.Name == nil || *t.Name == "" {
		return Tool{}, "missing name"
	}
	out := Tool{Name: *t.Name}
	if !toolName.MatchString(*t.Name) {
		out.Name = clip(printable(*t.Name), 64)
		return out, "name must be 1-128 characters of letters, digits and _ . - /"
	}
	if r := objectSchema(t.InputSchema); r != "" {
		return out, "inputSchema " + r
	}
	if len(t.OutputSchema) > 0 && string(t.OutputSchema) != "null" {
		if r := objectSchema(t.OutputSchema); r != "" {
			return out, "outputSchema " + r
		}
		out.OutputSchema = compact(t.OutputSchema)
	}
	if len(t.Annotations) > 0 && string(t.Annotations) != "null" {
		var a map[string]any
		if json.Unmarshal(t.Annotations, &a) != nil {
			return out, "annotations must be an object"
		}
		out.Annotations = compact(t.Annotations)
	}
	out.InputSchema = compact(t.InputSchema)
	out.Title = clip(t.Title, 200)
	out.Description = clip(t.Description, MaxDescLen)
	return out, ""
}

// objectSchema checks a JSON Schema for tool arguments: an object whose type
// is "object" (MCP requires it).
func objectSchema(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return "is missing"
	}
	var s map[string]json.RawMessage
	if json.Unmarshal(raw, &s) != nil {
		return "must be a JSON object"
	}
	var typ string
	if json.Unmarshal(s["type"], &typ) != nil || typ != "object" {
		return `must have "type": "object"`
	}
	if p, ok := s["properties"]; ok && string(p) != "null" {
		var props map[string]json.RawMessage
		if json.Unmarshal(p, &props) != nil {
			return "properties must be an object"
		}
	}
	return ""
}

func compact(raw json.RawMessage) json.RawMessage {
	var b bytes.Buffer
	if json.Compact(&b, raw) != nil {
		return raw
	}
	return b.Bytes()
}

// call sends one JSON-RPC request and returns its result. failKind is the
// error kind of a JSON-RPC error or malformed answer at this step.
func (s *session) call(ctx context.Context, step, failKind, method string, params any) (json.RawMessage, http.Header, error) {
	id := int(s.nextID.Add(1))
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	resp, err := s.post(ctx, step, body)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if e := s.statusError(step, failKind, resp); e != nil {
		return nil, nil, e
	}
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	var msg *rpcMessage
	switch ct {
	case "application/json":
		msg, err = findJSON(io.LimitReader(resp.Body, MaxBody+1), id)
	case "text/event-stream":
		msg, err = findSSE(io.LimitReader(resp.Body, MaxBody+1), id)
	default:
		return nil, nil, &Error{Kind: failKind, Step: step, HTTPStatus: resp.StatusCode, Detail: fmt.Sprintf("unexpected Content-Type %q (want application/json or text/event-stream)", clip(ct, 60))}
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, &Error{Kind: KindUnavailable, Step: step, HTTPStatus: resp.StatusCode, Detail: "timed out reading the response"}
		}
		return nil, nil, &Error{Kind: failKind, Step: step, HTTPStatus: resp.StatusCode, Detail: s.scrub(err.Error())}
	}
	if msg.Error != nil {
		return nil, nil, &Error{Kind: failKind, Step: step, HTTPStatus: resp.StatusCode,
			Detail: fmt.Sprintf("JSON-RPC error %d: %s", msg.Error.Code, s.scrub(clip(printable(msg.Error.Message), 300)))}
	}
	if len(msg.Result) == 0 || msg.Result[0] != '{' {
		return nil, nil, &Error{Kind: failKind, Step: step, HTTPStatus: resp.StatusCode, Detail: "response has no result object"}
	}
	return msg.Result, resp.Header, nil
}

// notify sends a JSON-RPC notification; the server must accept it with 202
// (or any 2xx).
func (s *session) notify(ctx context.Context, method string) error {
	const step = "initialized"
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method})
	resp, err := s.post(ctx, step, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return s.statusError(step, KindInitFailed, resp)
}

func (s *session) post(ctx context.Context, step string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, &Error{Kind: KindInitFailed, Step: step, Detail: "invalid endpoint URL"}
	}
	s.headers(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := s.c.HTTP.Do(req)
	if err != nil {
		return nil, &Error{Kind: KindUnavailable, Step: step, Detail: s.scrub(transportDetail(ctx, err))}
	}
	return resp, nil
}

func (s *session) headers(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+s.c.Token)
	if s.id != "" {
		req.Header.Set("Mcp-Session-Id", s.id)
	}
	if s.version != "" {
		req.Header.Set("MCP-Protocol-Version", s.version)
	}
}

// close ends the session (DELETE with the session id); best effort, a server
// may answer 405.
func (s *session) close() {
	if s.id == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.c.Endpoint, nil)
	if err != nil {
		return
	}
	s.headers(req)
	if resp, err := s.c.HTTP.Do(req); err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
	}
}

// statusError maps a non-2xx answer to an error kind.
func (s *session) statusError(step, failKind string, resp *http.Response) error {
	code := resp.StatusCode
	if code >= 200 && code < 300 {
		return nil
	}
	snippet := s.bodySnippet(resp)
	e := &Error{Step: step, HTTPStatus: code}
	switch {
	case code == http.StatusUnauthorized:
		desc := bearerParam(resp.Header.Get("WWW-Authenticate"), "error_description")
		e.Kind, e.Detail = KindAuthFailed, "the server rejected the token"
		if msg := strings.TrimSpace(desc + " " + snippet); msg != "" {
			e.Detail += ": " + clip(msg, 300)
			l := strings.ToLower(msg)
			if strings.Contains(l, "expired") || strings.Contains(l, "revoked") {
				e.Kind = KindTokenExpired
			}
		}
	case code == http.StatusForbidden:
		e.Kind, e.Detail = KindPermission, "the server refused access"
		if snippet != "" {
			e.Detail += ": " + snippet
		}
	case code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500:
		e.Kind, e.Detail = KindUnavailable, "the server is unavailable"
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			e.Detail += " (Retry-After: " + clip(printable(ra), 40) + ")"
		}
		if snippet != "" {
			e.Detail += ": " + snippet
		}
	case code >= 300 && code < 400:
		e.Kind, e.Detail = failKind, "the server answered with a redirect, which Fortik does not follow (check the endpoint URL)"
	default:
		e.Kind, e.Detail = failKind, "the server refused the request"
		if code == http.StatusNotFound && step != "initialize" && s.id != "" {
			// Streamable HTTP: 404 for a session id means the session is
			// gone and the request was not processed (safe to re-open).
			e.Kind, e.Detail = KindSessionExpired, "the server no longer knows the session"
		}
		if snippet != "" {
			e.Detail += ": " + snippet
		}
	}
	return e
}

// bodySnippet is a short, printable, token-free excerpt of an error body
// (HTML error pages are summarised, not quoted).
func (s *session) bodySnippet(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if ct == "text/html" || bytes.HasPrefix(bytes.TrimSpace(b), []byte("<")) {
		return "HTML error page"
	}
	if ct == "application/json" {
		var m rpcMessage
		if json.Unmarshal(b, &m) == nil && m.Error != nil {
			return s.scrub(clip(fmt.Sprintf("JSON-RPC error %d: %s", m.Error.Code, printable(m.Error.Message)), 300))
		}
	}
	return s.scrub(clip(printable(strings.TrimSpace(string(b))), 300))
}

// scrub removes the token from text that came from the server or the
// transport.
func (s *session) scrub(text string) string {
	if t := s.c.Token; len(t) >= 4 {
		text = strings.ReplaceAll(text, t, "[redacted]")
	}
	return text
}

func transportDetail(ctx context.Context, err error) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return "timed out connecting to the server"
	}
	var ue interface{ Unwrap() error }
	if errors.As(err, &ue) {
		if inner := ue.Unwrap(); inner != nil {
			return "could not reach the server: " + clip(inner.Error(), 300)
		}
	}
	return "could not reach the server: " + clip(err.Error(), 300)
}

// findJSON reads a JSON response: one message, or a batch array of them.
func findJSON(r io.Reader, id int) (*rpcMessage, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if len(b) > MaxBody {
		return nil, fmt.Errorf("response larger than %d bytes", MaxBody)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '[' {
		var batch []rpcMessage
		if err := json.Unmarshal(b, &batch); err != nil {
			return nil, errors.New("response is not valid JSON-RPC")
		}
		for i := range batch {
			if matches(&batch[i], id) {
				return &batch[i], nil
			}
		}
		return nil, errors.New("response does not answer the request")
	}
	var m rpcMessage
	if err := json.Unmarshal(b, &m); err != nil || m.JSONRPC != "2.0" {
		return nil, errors.New("response is not valid JSON-RPC")
	}
	if !matches(&m, id) {
		return nil, errors.New("response does not answer the request")
	}
	return &m, nil
}

// findSSE reads an event stream until the message answering id arrives.
// Notifications and server requests before it are skipped.
func findSSE(r io.Reader, id int) (*rpcMessage, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), MaxBody)
	var data strings.Builder
	total := 0
	flush := func() (*rpcMessage, bool) {
		defer data.Reset()
		if data.Len() == 0 {
			return nil, false
		}
		var m rpcMessage
		if json.Unmarshal([]byte(data.String()), &m) != nil {
			return nil, false
		}
		return &m, matches(&m, id)
	}
	for sc.Scan() {
		line := sc.Text()
		total += len(line) + 1
		if total > MaxBody {
			return nil, fmt.Errorf("event stream larger than %d bytes", MaxBody)
		}
		if line == "" {
			if m, ok := flush(); ok {
				return m, nil
			}
			continue
		}
		if v, ok := strings.CutPrefix(line, "data:"); ok {
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(v, " "))
		}
	}
	if m, ok := flush(); ok {
		return m, nil
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading event stream: %w", err)
	}
	return nil, errors.New("event stream ended without answering the request")
}

func matches(m *rpcMessage, id int) bool {
	if m.Method != "" || (m.Result == nil && m.Error == nil) {
		return false
	}
	var got int
	return json.Unmarshal(m.ID, &got) == nil && got == id
}

// bearerParam extracts one auth-param from a Bearer WWW-Authenticate header.
func bearerParam(h, name string) string {
	i := strings.Index(strings.ToLower(h), name+"=")
	if i < 0 {
		return ""
	}
	v := h[i+len(name)+1:]
	if strings.HasPrefix(v, `"`) {
		if j := strings.IndexByte(v[1:], '"'); j >= 0 {
			return printable(v[1 : j+1])
		}
		return ""
	}
	if j := strings.IndexAny(v, ", "); j >= 0 {
		v = v[:j]
	}
	return printable(v)
}

func validSessionID(s string) bool {
	if len(s) > 512 {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "..."
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
