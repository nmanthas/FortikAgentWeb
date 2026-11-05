package mcpclient

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Session is an open MCP session used for tool calls. It is safe for
// concurrent use; Close ends it on the server (best effort).
type Session struct {
	s        *session
	Opened   time.Time
	Protocol string
}

// Open initializes a session (initialize + notifications/initialized).
func (c *Client) Open(ctx context.Context) (*Session, error) {
	s := &session{c: c}
	d, err := s.initialize(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.notify(ctx, "notifications/initialized"); err != nil {
		s.close()
		return nil, err
	}
	return &Session{s: s, Opened: time.Now(), Protocol: d.ProtocolVersion}, nil
}

// ToolResult is the result object of one tools/call, as the server sent it.
// IsError is the server's own "the tool failed" flag (a tool-level error, not
// a protocol error).
type ToolResult struct {
	Raw     json.RawMessage
	IsError bool
}

// CallTool sends tools/call once. It never retries: a tool call may have
// external effects. A KindSessionExpired error means the server did not
// process the request (the caller may re-open the session and call again);
// every other error leaves the outcome unknown for non-idempotent tools.
func (x *Session) CallTool(ctx context.Context, name string, args json.RawMessage) (*ToolResult, error) {
	if len(args) == 0 || string(args) == "null" {
		args = json.RawMessage("{}")
	}
	params := map[string]any{"name": name, "arguments": args}
	raw, _, err := x.s.call(ctx, "tools/call", KindCallFailed, "tools/call", params)
	if err != nil {
		return nil, err
	}
	var res struct {
		Content *json.RawMessage `json:"content"`
		IsError bool             `json:"isError"`
	}
	if err := json.Unmarshal(raw, &res); err != nil || res.Content == nil {
		return nil, &Error{Kind: KindCallFailed, Step: "tools/call", Detail: "tools/call result has no content"}
	}
	return &ToolResult{Raw: raw, IsError: res.IsError}, nil
}

// Close ends the session on the server (DELETE; best effort).
func (x *Session) Close() { x.s.close() }

// Expired reports whether err says the session is gone (re-open and retry
// is safe: the server did not process the request).
func Expired(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Kind == KindSessionExpired
}
